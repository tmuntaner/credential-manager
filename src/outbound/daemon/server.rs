use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use log::{error, info, warn};
use tokio::sync::{broadcast, mpsc};

use crate::domain::models::secret::SafeSecret;
use crate::domain::models::user_interaction::UserNotice;
use crate::domain::ports::notifier::Notifier;
use crate::domain::ports::secret_wrapper::{SecretWrapper, WrapError};
use crate::outbound::daemon::peer_cred::{
    bind_secure_socket, verify_peer_connection, PeerCredError, PeerIdentity,
};
use crate::outbound::daemon::protocol::{read_frame, write_frame, IpcRequest, IpcResponse};
use crate::outbound::yubikey::{HmacSecretDeriver, YubikeyWrapper};

pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// The trait to manage wrapped secrets within the daemon.
#[async_trait(?Send)]
pub trait DaemonKeyCache: SecretWrapper {
    /// Clears the cached secrets from the daemon's memory.
    fn clear_key(&self) -> Result<(), WrapError>;

    /// Returns whether the daemon has the secret in memory.
    fn has_key(&self) -> Result<bool, WrapError>;
}

#[async_trait(?Send)]
impl<D: HmacSecretDeriver> DaemonKeyCache for YubikeyWrapper<D> {
    fn clear_key(&self) -> Result<(), WrapError> {
        self.clear_cached_key()
    }

    fn has_key(&self) -> Result<bool, WrapError> {
        self.has_cached_key()
    }
}

/// Disable core dumps if possible to protect the secrets within memory.
pub fn disable_core_dumps() {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }
}

/// A daemon session that manages the cached secrets.
pub struct DaemonSession<W, N> {
    wrapper: Arc<W>,
    notifier: Arc<N>,
    idle_timeout: Duration,
    last_activity: Mutex<Option<Instant>>,
    notify_on_decrypt: bool,
}

impl<W: DaemonKeyCache, N: Notifier> DaemonSession<W, N> {
    pub fn new(
        wrapper: Arc<W>,
        notifier: Arc<N>,
        idle_timeout: Duration,
        notify_on_decrypt: bool,
    ) -> Self {
        Self {
            wrapper,
            notifier,
            idle_timeout,
            last_activity: Mutex::new(None),
            notify_on_decrypt,
        }
    }

    /// Checks if the session is over the idle timeout. If it is, clear the secrets from meory.
    pub fn check_and_expire_if_idle(&self) -> Result<bool, WrapError> {
        let mut guard = self.last_activity.lock().unwrap();

        if let Some(last) = *guard {
            if last.elapsed() >= self.idle_timeout {
                self.wrapper.clear_key()?;
                *guard = None;
                info!("daemon session expired due to inactivity. Secrets cleared.");

                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Locks the session and clears the secret in the memory.
    pub fn lock(&self) -> Result<(), WrapError> {
        self.wrapper.clear_key()?;

        let mut guard = self.last_activity.lock().unwrap();
        *guard = None;

        info!("daemon session locked. Secrets cleared.");
        Ok(())
    }

    fn touch_activity(&self) {
        let mut guard = self.last_activity.lock().unwrap();
        *guard = Some(Instant::now());
    }

    /// Processes an incoming request and returns its response.
    pub async fn handle_request(
        &self,
        request: IpcRequest,
        peer: &PeerIdentity,
    ) -> (IpcResponse, bool) {
        match request {
            IpcRequest::Wrap { aad, plaintext } => {
                // Check if the cache was expired. If so, return an error.
                if let Err(e) = self.check_and_expire_if_idle() {
                    return (
                        IpcResponse::Error {
                            message: e.to_string(),
                        },
                        false,
                    );
                }

                // wrap the secret
                let safe_secret = SafeSecret::new(plaintext);
                match self.wrapper.wrap(&aad, &safe_secret).await {
                    Ok(wrapped) => {
                        self.touch_activity();
                        (
                            IpcResponse::Success {
                                value: wrapped.into_inner(),
                            },
                            false,
                        )
                    }
                    Err(e) => (
                        IpcResponse::Error {
                            message: e.to_string(),
                        },
                        false,
                    ),
                }
            }
            IpcRequest::Unwrap { aad, ciphertext } => {
                // Check if the cache was expired. If so, return an error.
                if let Err(e) = self.check_and_expire_if_idle() {
                    return (
                        IpcResponse::Error {
                            message: e.to_string(),
                        },
                        false,
                    );
                }

                // unwrap the secret.
                let safe_secret = SafeSecret::new(ciphertext);
                match self.wrapper.unwrap(&aad, &safe_secret).await {
                    Ok(unwrapped) => {
                        self.touch_activity();

                        if self.notify_on_decrypt {
                            let notice = UserNotice::info(format!(
                                "c9s secret decrypted for PID {} ({})",
                                peer.pid, peer.binary_name
                            ));
                            if let Err(e) = self.notifier.notify(&notice).await {
                                warn!("failed to send decryption desktop notification: {}", e);
                            }
                        }

                        (
                            IpcResponse::Success {
                                value: unwrapped.into_inner(),
                            },
                            false,
                        )
                    }
                    Err(e) => (
                        IpcResponse::Error {
                            message: e.to_string(),
                        },
                        false,
                    ),
                }
            }
            IpcRequest::Status => {
                // Check if the cache was expired. If so, return an error.
                if let Err(e) = self.check_and_expire_if_idle() {
                    return (
                        IpcResponse::Error {
                            message: e.to_string(),
                        },
                        false,
                    );
                }

                // see if there is a secret in the cache.
                // if it's there, then it's considered unlocked.
                let is_cached = self.wrapper.has_key().unwrap_or(false);
                if is_cached {
                    let guard = self.last_activity.lock().unwrap();
                    let remaining =
                        guard.map(|t| self.idle_timeout.saturating_sub(t.elapsed()).as_secs());
                    (
                        IpcResponse::Status {
                            is_locked: false,
                            remaining_ttl_seconds: remaining,
                        },
                        false,
                    )
                } else {
                    (
                        IpcResponse::Status {
                            is_locked: true,
                            remaining_ttl_seconds: None,
                        },
                        false,
                    )
                }
            }
            IpcRequest::Lock => {
                // try to lock and clear the memory.
                if let Err(e) = self.lock() {
                    (
                        IpcResponse::Error {
                            message: e.to_string(),
                        },
                        false,
                    )
                } else {
                    (IpcResponse::Locked, false)
                }
            }
            IpcRequest::Stop => {
                // try to lock and clear the data.
                // we don't care if it fails because we'll stop the daemon.
                let _ = self.lock();
                (IpcResponse::Stopped, true)
            }
        }
    }
}

/// Verifies a connected peer. Called on every request.
pub type PeerVerifier =
    Arc<dyn Fn(&tokio::net::UnixStream) -> Result<PeerIdentity, PeerCredError> + Send + Sync>;

/// The IPC background daemon for c9s.
pub struct DaemonServer<W, N> {
    socket_path: PathBuf,
    session: Arc<DaemonSession<W, N>>,
    verifier: PeerVerifier,
}

impl<W: DaemonKeyCache + 'static, N: Notifier + 'static> DaemonServer<W, N> {
    pub fn new(
        socket_path: impl Into<PathBuf>,
        wrapper: Arc<W>,
        notifier: Arc<N>,
        idle_timeout: Duration,
        notify_on_decrypt: bool,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            session: Arc::new(DaemonSession::new(
                wrapper,
                notifier,
                idle_timeout,
                notify_on_decrypt,
            )),
            verifier: Arc::new(verify_peer_connection),
        }
    }

    /// Replaces the peer verification.
    pub fn with_verifier(mut self, verifier: PeerVerifier) -> Self {
        self.verifier = verifier;
        self
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn session(&self) -> Arc<DaemonSession<W, N>> {
        self.session.clone()
    }

    /// Runs the daemon server loop.
    pub async fn run(&self) -> Result<(), std::io::Error> {
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        self.run_with_shutdown(shutdown_tx, shutdown_rx).await
    }

    /// Runs the daemon server loop with a shutdown broadcast channel.
    pub async fn run_with_shutdown(
        &self,
        shutdown_tx: broadcast::Sender<()>,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<(), std::io::Error> {
        // creates a locking channel
        let (lock_tx, lock_rx) = mpsc::unbounded_channel();

        // on linux, watch zbus for session events
        #[cfg(target_os = "linux")]
        crate::outbound::daemon::session_events::spawn(lock_tx.clone());

        self.run_with_events(shutdown_tx, shutdown_rx, lock_rx, lock_tx)
            .await
    }

    /// Runs the server loop.
    /// An event for shutdown can stop the loop.
    /// An event for lock can lock the daemon and clear secrets from memory.
    async fn run_with_events(
        &self,
        shutdown_tx: broadcast::Sender<()>,
        mut shutdown_rx: broadcast::Receiver<()>,
        mut lock_rx: mpsc::UnboundedReceiver<()>,
        lock_tx: mpsc::UnboundedSender<()>,
    ) -> Result<(), std::io::Error> {
        // before we start, disable core dumps to protect the secrets within memory.
        disable_core_dumps();

        // start the listener at the socket path.
        let listener = bind_secure_socket(&self.socket_path).await?;
        info!("daemon listening on {}", self.socket_path.display());

        let session = self.session.clone();
        let socket_path = self.socket_path.clone();

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("daemon received shutdown signal");
                    break;
                }
                Some(()) = lock_rx.recv() => {
                    if let Err(e) = session.lock() {
                        error!("failed to lock on session event: {}", e);
                    }
                }
                accept_res = listener.accept() => {
                    // incoming request
                    match accept_res {
                        Ok((mut stream, _)) => {
                            // before we do anything, verify the connection to be sure we
                            // should be communicating with it.
                            if let Err(err) = (self.verifier)(&stream) {
                                warn!("peer verification failed: {}", err);
                                let err_resp = IpcResponse::Error {
                                    message: format!("Access denied: {}", err),
                                };
                                let _ = write_frame(&mut stream, &err_resp).await;
                                continue;
                            }

                            // read and handle the request.
                            while let Ok(req) = read_frame::<_, IpcRequest>(&mut stream).await {
                                // apply session lock events that arrived while connected.
                                while let Ok(()) = lock_rx.try_recv() {
                                    let _ = session.lock();
                                }

                                // Verify Again!
                                // The peer could have exec'd as another program since the last frame.
                                let peer = match (self.verifier)(&stream) {
                                    Ok(id) => id,
                                    Err(err) => {
                                        warn!("peer verification failed: {}", err);
                                        let err_resp = IpcResponse::Error {
                                            message: format!("Access denied: {}", err),
                                        };
                                        let _ = write_frame(&mut stream, &err_resp).await;
                                        break;
                                    }
                                };

                                // handle the request
                                let (resp, should_stop) = session.handle_request(req, &peer).await;

                                // write the response back.
                                if write_frame(&mut stream, &resp).await.is_err() {
                                    break;
                                }

                                // if the response says we shold stop the daemon, do it.
                                if should_stop {
                                    let _ = shutdown_tx.send(());
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            error!("listener accept error: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        // Clean the socket on shutdown
        let _ = std::fs::remove_file(&socket_path);
        let _ = self.session.lock();
        drop(lock_tx);
        info!("daemon stopped and socket removed.");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::daemon::peer_cred::verify_peer_connection_in_tests;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::UnixStream;

    struct TestKeyCache {
        has_key: Mutex<bool>,
        clear_calls: AtomicUsize,
    }

    impl TestKeyCache {
        fn new() -> Self {
            Self {
                has_key: Mutex::new(false),
                clear_calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait(?Send)]
    impl SecretWrapper for TestKeyCache {
        async fn wrap(&self, _aad: &[u8], plaintext: &SafeSecret) -> Result<SafeSecret, WrapError> {
            *self.has_key.lock().unwrap() = true;
            Ok(SafeSecret::new(format!(
                "wrapped:{}",
                plaintext.expose_secret()
            )))
        }

        async fn unwrap(
            &self,
            _aad: &[u8],
            ciphertext: &SafeSecret,
        ) -> Result<SafeSecret, WrapError> {
            *self.has_key.lock().unwrap() = true;
            let raw = ciphertext.expose_secret();
            if let Some(stripped) = raw.strip_prefix("wrapped:") {
                Ok(SafeSecret::new(stripped))
            } else {
                Err(WrapError::Corrupt)
            }
        }
    }

    #[async_trait(?Send)]
    impl DaemonKeyCache for TestKeyCache {
        fn clear_key(&self) -> Result<(), WrapError> {
            *self.has_key.lock().unwrap() = false;
            self.clear_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn has_key(&self) -> Result<bool, WrapError> {
            Ok(*self.has_key.lock().unwrap())
        }
    }

    struct MockNotifier {
        notified: AtomicUsize,
    }

    #[async_trait(?Send)]
    impl Notifier for MockNotifier {
        async fn notify(
            &self,
            _notice: &UserNotice,
        ) -> Result<(), crate::domain::ports::notifier::NotifyError> {
            self.notified.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn server_wrap_unwrap_lifecycle() {
        let temp_dir = tempfile::tempdir().unwrap();
        let sock_path = temp_dir.path().join("server.sock");

        let wrapper = Arc::new(TestKeyCache::new());
        let notifier = Arc::new(MockNotifier {
            notified: AtomicUsize::new(0),
        });
        let server = DaemonServer::new(
            &sock_path,
            wrapper.clone(),
            notifier.clone(),
            Duration::from_secs(60),
            true,
        )
        .with_verifier(Arc::new(verify_peer_connection_in_tests));

        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let srv_shutdown_tx = shutdown_tx.clone();

        let srv_handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                server
                    .run_with_shutdown(srv_shutdown_tx, shutdown_rx)
                    .await
                    .unwrap();
            });
        });

        // Wait for socket to appear
        for _ in 0..50 {
            if sock_path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let mut client = UnixStream::connect(&sock_path).await.unwrap();

        // 1. Initial status: is_locked = true
        write_frame(&mut client, &IpcRequest::Status).await.unwrap();
        let resp: IpcResponse = read_frame(&mut client).await.unwrap();
        assert_eq!(
            resp,
            IpcResponse::Status {
                is_locked: true,
                remaining_ttl_seconds: None
            }
        );

        // 2. Wrap request
        let wrap_req = IpcRequest::Wrap {
            aad: b"test-aad".to_vec(),
            plaintext: "my-secret".to_string(),
        };
        write_frame(&mut client, &wrap_req).await.unwrap();
        let resp: IpcResponse = read_frame(&mut client).await.unwrap();
        assert_eq!(
            resp,
            IpcResponse::Success {
                value: "wrapped:my-secret".to_string()
            }
        );

        // 3. Status after wrap: is_locked = false
        write_frame(&mut client, &IpcRequest::Status).await.unwrap();
        let resp: IpcResponse = read_frame(&mut client).await.unwrap();
        if let IpcResponse::Status {
            is_locked,
            remaining_ttl_seconds,
        } = resp
        {
            assert!(!is_locked);
            assert!(remaining_ttl_seconds.is_some());
        } else {
            panic!("unexpected response {:?}", resp);
        }

        // 4. Unwrap request
        let unwrap_req = IpcRequest::Unwrap {
            aad: b"test-aad".to_vec(),
            ciphertext: "wrapped:my-secret".to_string(),
        };
        write_frame(&mut client, &unwrap_req).await.unwrap();
        let resp: IpcResponse = read_frame(&mut client).await.unwrap();
        assert_eq!(
            resp,
            IpcResponse::Success {
                value: "my-secret".to_string()
            }
        );
        assert_eq!(notifier.notified.load(Ordering::SeqCst), 1);

        // 5. Lock command
        write_frame(&mut client, &IpcRequest::Lock).await.unwrap();
        let resp: IpcResponse = read_frame(&mut client).await.unwrap();
        assert_eq!(resp, IpcResponse::Locked);
        assert_eq!(wrapper.clear_calls.load(Ordering::SeqCst), 1);

        // 6. Stop command
        write_frame(&mut client, &IpcRequest::Stop).await.unwrap();
        let resp: IpcResponse = read_frame(&mut client).await.unwrap();
        assert_eq!(resp, IpcResponse::Stopped);

        let _ = srv_handle.join();
        assert!(!sock_path.exists());
    }

    #[tokio::test]
    async fn idle_timeout_expires_session() {
        let wrapper = Arc::new(TestKeyCache::new());
        let notifier = Arc::new(MockNotifier {
            notified: AtomicUsize::new(0),
        });
        let session =
            DaemonSession::new(wrapper.clone(), notifier, Duration::from_millis(50), false);

        let peer = PeerIdentity {
            pid: std::process::id(),
            uid: unsafe { libc::getuid() },
            exe_path: PathBuf::from("/bin/c9s"),
            binary_name: "c9s".to_string(),
        };

        // Initially locked
        let (resp, _) = session.handle_request(IpcRequest::Status, &peer).await;
        assert_eq!(
            resp,
            IpcResponse::Status {
                is_locked: true,
                remaining_ttl_seconds: None
            }
        );

        // Wrap unlocks
        let (resp, _) = session
            .handle_request(
                IpcRequest::Wrap {
                    aad: b"aad".to_vec(),
                    plaintext: "secret".to_string(),
                },
                &peer,
            )
            .await;
        assert_eq!(
            resp,
            IpcResponse::Success {
                value: "wrapped:secret".to_string()
            }
        );

        // Immediately check status: not locked
        let (resp, _) = session.handle_request(IpcRequest::Status, &peer).await;
        if let IpcResponse::Status {
            is_locked,
            remaining_ttl_seconds,
        } = resp
        {
            assert!(!is_locked);
            assert!(remaining_ttl_seconds.is_some());
        } else {
            panic!("unexpected response {:?}", resp);
        }

        // Wait past idle timeout
        tokio::time::sleep(Duration::from_millis(70)).await;

        // Status check should now show locked
        let (resp, _) = session.handle_request(IpcRequest::Status, &peer).await;
        assert_eq!(
            resp,
            IpcResponse::Status {
                is_locked: true,
                remaining_ttl_seconds: None
            }
        );
        assert_eq!(wrapper.clear_calls.load(Ordering::SeqCst), 1);
    }

    fn test_server(
        sock_path: &Path,
        wrapper: Arc<TestKeyCache>,
    ) -> DaemonServer<TestKeyCache, MockNotifier> {
        let notifier = Arc::new(MockNotifier {
            notified: AtomicUsize::new(0),
        });
        DaemonServer::new(sock_path, wrapper, notifier, Duration::from_secs(60), false)
            .with_verifier(Arc::new(verify_peer_connection_in_tests))
    }

    async fn wait_for_socket(sock_path: &Path) {
        for _ in 0..50 {
            if sock_path.exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn each_request_is_verified_again() {
        use std::sync::atomic::AtomicBool;

        let temp_dir = tempfile::tempdir().unwrap();
        let sock_path = temp_dir.path().join("verify.sock");
        let wrapper = Arc::new(TestKeyCache::new());

        let allow = Arc::new(AtomicBool::new(true));
        let allow_in_verifier = allow.clone();
        let server = test_server(&sock_path, wrapper).with_verifier(Arc::new(move |stream| {
            if allow_in_verifier.load(Ordering::SeqCst) {
                verify_peer_connection_in_tests(stream)
            } else {
                Err(PeerCredError::PeerTraced)
            }
        }));

        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let srv_shutdown_tx = shutdown_tx.clone();
        let srv_handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                server
                    .run_with_shutdown(srv_shutdown_tx, shutdown_rx)
                    .await
                    .unwrap();
            });
        });
        wait_for_socket(&sock_path).await;

        let mut client = UnixStream::connect(&sock_path).await.unwrap();

        write_frame(&mut client, &IpcRequest::Status).await.unwrap();
        let resp: IpcResponse = read_frame(&mut client).await.unwrap();
        assert!(matches!(resp, IpcResponse::Status { .. }));

        // the peer turns bad after the connection was accepted.
        allow.store(false, Ordering::SeqCst);
        write_frame(&mut client, &IpcRequest::Status).await.unwrap();
        let resp: IpcResponse = read_frame(&mut client).await.unwrap();
        match resp {
            IpcResponse::Error { message } => assert!(message.contains("Access denied")),
            other => panic!("unexpected response {:?}", other),
        }

        let _ = shutdown_tx.send(());
        let _ = srv_handle.join();
    }

    #[tokio::test]
    async fn lock_event_clears_the_key() {
        let temp_dir = tempfile::tempdir().unwrap();
        let sock_path = temp_dir.path().join("lock.sock");
        let wrapper = Arc::new(TestKeyCache::new());
        *wrapper.has_key.lock().unwrap() = true;
        let server = test_server(&sock_path, wrapper.clone());

        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let (lock_tx, lock_rx) = mpsc::unbounded_channel();
        let srv_shutdown_tx = shutdown_tx.clone();
        let srv_lock_tx = lock_tx.clone();
        let srv_handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                server
                    .run_with_events(srv_shutdown_tx, shutdown_rx, lock_rx, srv_lock_tx)
                    .await
                    .unwrap();
            });
        });
        wait_for_socket(&sock_path).await;

        lock_tx.send(()).unwrap();
        for _ in 0..100 {
            if !wrapper.has_key().unwrap() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(!wrapper.has_key().unwrap());
        assert!(wrapper.clear_calls.load(Ordering::SeqCst) >= 1);

        let _ = shutdown_tx.send(());
        let _ = srv_handle.join();
    }
}
