use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use log::{debug, info};
use tokio::net::UnixStream;

use crate::domain::models::secret::SafeSecret;
use crate::domain::ports::secret_wrapper::{SecretWrapper, WrapError};
use crate::outbound::daemon::protocol::{read_frame, write_frame, IpcRequest, IpcResponse};

/// Sends a request to the daemon at the `socket_path`, returning the response.
pub async fn send_request(
    socket_path: &Path,
    request: &IpcRequest,
) -> Result<IpcResponse, std::io::Error> {
    // connect to the socket
    let mut stream = UnixStream::connect(socket_path).await?;

    // write the request
    write_frame(&mut stream, request).await?;

    // read and return the response
    read_frame(&mut stream).await
}

/// Spawns a new background daemon.
pub fn try_spawn_daemon(socket_path: &Path) -> Result<(), std::io::Error> {
    // get the path of the current binary.
    // we need it to call the daemon run command
    if let Ok(exe) = std::env::current_exe() {
        // build a new run command
        let mut cmd = std::process::Command::new(exe);
        cmd.arg("daemon").arg("run");

        // set the socket string
        if let Some(sock_str) = socket_path.to_str() {
            cmd.env("C9S_DAEMON_SOCKET", sock_str);
        }

        // set the stdio handles
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());

        // spawn the process
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            unsafe {
                cmd.pre_exec(|| {
                    libc::setsid();
                    Ok(())
                });
            }
        }

        cmd.spawn()?;
    }
    Ok(())
}

// convert an IPC error to a WrapError
fn map_ipc_error(msg: &str) -> WrapError {
    match msg {
        "secret payload is not wrapped" => WrapError::NotWrapped,
        "wrapped secret payload is corrupt" => WrapError::Corrupt,
        "YubiKey device is not present" => WrapError::DeviceNotPresent,
        "operation was cancelled or timed out" => WrapError::Cancelled,
        other => WrapError::Failed(Box::new(std::io::Error::other(other.to_string()))),
    }
}

/// Client adapter for the driven [`SecretWrapper`] port.
pub struct DaemonSecretWrapper {
    socket_path: PathBuf,
    fallback: Option<Box<dyn SecretWrapper>>,
    auto_spawn: bool,
}

impl DaemonSecretWrapper {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            fallback: None,
            auto_spawn: false,
        }
    }

    pub fn with_fallback(mut self, fallback: Box<dyn SecretWrapper>) -> Self {
        self.fallback = Some(fallback);
        self
    }

    pub fn with_auto_spawn(mut self, auto_spawn: bool) -> Self {
        self.auto_spawn = auto_spawn;
        self
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    async fn connect_or_spawn(&self) -> Result<UnixStream, std::io::Error> {
        // try to connect to the socket
        // if we cannot connect, but auto_spawn is true, try to spawn the daemon
        match UnixStream::connect(&self.socket_path).await {
            Ok(stream) => Ok(stream),
            Err(e) if self.auto_spawn => {
                debug!("daemon socket not ready, attempting auto-spawn: {}", e);

                if try_spawn_daemon(&self.socket_path).is_ok() {
                    // Poll for the socket to connect
                    for _ in 0..20 {
                        tokio::time::sleep(Duration::from_millis(15)).await;
                        if let Ok(stream) = UnixStream::connect(&self.socket_path).await {
                            return Ok(stream);
                        }
                    }
                }
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    async fn execute_ipc(&self, request: &IpcRequest) -> Result<String, WrapError> {
        // connect to the socket
        let mut stream = self
            .connect_or_spawn()
            .await
            .map_err(|e| WrapError::Failed(Box::new(e)))?;

        // write the request
        write_frame(&mut stream, request)
            .await
            .map_err(|e| WrapError::Failed(Box::new(e)))?;

        // read the response
        let response: IpcResponse = read_frame(&mut stream)
            .await
            .map_err(|e| WrapError::Failed(Box::new(e)))?;

        match response {
            IpcResponse::Success { value } => Ok(value),
            IpcResponse::Error { message } => Err(map_ipc_error(&message)),
            other => Err(WrapError::Failed(Box::new(std::io::Error::other(format!(
                "unexpected daemon response: {:?}",
                other
            ))))),
        }
    }
}

#[async_trait(?Send)]
impl SecretWrapper for DaemonSecretWrapper {
    async fn wrap(&self, aad: &[u8], plaintext: &SafeSecret) -> Result<SafeSecret, WrapError> {
        // create a request to wrap a secret
        let req = IpcRequest::Wrap {
            aad: aad.to_vec(),
            plaintext: plaintext.expose_secret().to_string(),
        };

        // try to send the secret wrapping request to the daemon with IPC
        match self.execute_ipc(&req).await {
            Ok(val) => Ok(SafeSecret::new(val)),
            Err(err) => {
                // if it fails, fall back to doing it inside the process instead of the daemon
                if let Some(ref fallback) = self.fallback {
                    info!(
                        "daemon wrap unavailable, falling back to local wrapper: {}",
                        err
                    );
                    fallback.wrap(aad, plaintext).await
                } else {
                    Err(err)
                }
            }
        }
    }

    async fn unwrap(&self, aad: &[u8], ciphertext: &SafeSecret) -> Result<SafeSecret, WrapError> {
        // create the request to unwrap a secret
        let req = IpcRequest::Unwrap {
            aad: aad.to_vec(),
            ciphertext: ciphertext.expose_secret().to_string(),
        };

        // try to send the secret unwrapping request to the daemon with IPC
        match self.execute_ipc(&req).await {
            Ok(val) => Ok(SafeSecret::new(val)),
            Err(err) => {
                // if it fails, fall back to doing it inside the process instead of the daemon
                if let Some(ref fallback) = self.fallback {
                    info!(
                        "daemon unwrap unavailable, falling back to local wrapper: {}",
                        err
                    );
                    fallback.unwrap(aad, ciphertext).await
                } else {
                    Err(err)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ports::secret_wrapper::MockSecretWrapper;

    #[test]
    fn maps_all_expected_error_messages() {
        assert!(matches!(
            map_ipc_error("secret payload is not wrapped"),
            WrapError::NotWrapped
        ));
        assert!(matches!(
            map_ipc_error("wrapped secret payload is corrupt"),
            WrapError::Corrupt
        ));
        assert!(matches!(
            map_ipc_error("YubiKey device is not present"),
            WrapError::DeviceNotPresent
        ));
        assert!(matches!(
            map_ipc_error("operation was cancelled or timed out"),
            WrapError::Cancelled
        ));

        let generic = map_ipc_error("some connection fault");
        assert!(matches!(generic, WrapError::Failed(_)));
        assert!(generic.to_string().contains("some connection fault"));
    }

    #[tokio::test]
    async fn unreachable_daemon_falls_back_to_local_wrapper() {
        let temp_dir = tempfile::tempdir().unwrap();
        let sock_path = temp_dir.path().join("non_existent.sock");

        let mut mock_fallback = MockSecretWrapper::new();
        mock_fallback.expect_wrap().times(1).returning(|_aad, pt| {
            Ok(SafeSecret::new(format!(
                "fallback-wrapped:{}",
                pt.expose_secret()
            )))
        });
        mock_fallback
            .expect_unwrap()
            .times(1)
            .returning(|_aad, ct| {
                Ok(SafeSecret::new(format!(
                    "fallback-unwrapped:{}",
                    ct.expose_secret()
                )))
            });

        let client = DaemonSecretWrapper::new(&sock_path).with_fallback(Box::new(mock_fallback));

        let aad = b"test-aad";
        let pt = SafeSecret::new("my-secret");
        let wrapped = client.wrap(aad, &pt).await.unwrap();
        assert_eq!(wrapped.expose_secret(), "fallback-wrapped:my-secret");

        let unwrapped = client.unwrap(aad, &wrapped).await.unwrap();
        assert_eq!(
            unwrapped.expose_secret(),
            "fallback-unwrapped:fallback-wrapped:my-secret"
        );
    }

    #[tokio::test]
    async fn unreachable_daemon_without_fallback_returns_failed_error() {
        let temp_dir = tempfile::tempdir().unwrap();
        let sock_path = temp_dir.path().join("non_existent.sock");

        let client = DaemonSecretWrapper::new(&sock_path);

        let aad = b"test-aad";
        let pt = SafeSecret::new("my-secret");
        let res = client.wrap(aad, &pt).await;

        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), WrapError::Failed(_)));
    }

    struct TestDeriver {
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait(?Send)]
    impl crate::outbound::yubikey::HmacSecretDeriver for std::sync::Arc<TestDeriver> {
        async fn derive(
            &self,
            _rp_id: &str,
            _credential_id: &[u8],
            _salt: &[u8; 32],
        ) -> Result<[u8; 32], WrapError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok([0x77; 32])
        }
    }

    struct DummyNotifier;

    #[async_trait(?Send)]
    impl crate::domain::ports::notifier::Notifier for DummyNotifier {
        async fn notify(
            &self,
            _notice: &crate::domain::models::user_interaction::UserNotice,
        ) -> Result<(), crate::domain::ports::notifier::NotifyError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn end_to_end_daemon_session_preservation_and_lock() {
        use crate::outbound::daemon::server::DaemonServer;
        use crate::outbound::yubikey::YubikeyWrapper;
        use std::sync::atomic::Ordering;

        let temp_dir = tempfile::tempdir().unwrap();
        let sock_path = temp_dir.path().join("e2e_daemon.sock");

        let deriver = std::sync::Arc::new(TestDeriver {
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let yk_wrapper =
            YubikeyWrapper::with_deriver("example.com", vec![1, 2], [0u8; 32], deriver.clone());

        let server = DaemonServer::new(
            &sock_path,
            std::sync::Arc::new(yk_wrapper),
            std::sync::Arc::new(DummyNotifier),
            Duration::from_secs(300),
            false,
        )
        .with_verifier(std::sync::Arc::new(
            crate::outbound::daemon::peer_cred::verify_peer_connection_in_tests,
        ));

        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let srv_tx = shutdown_tx.clone();

        let srv_handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                server.run_with_shutdown(srv_tx, shutdown_rx).await.unwrap();
            });
        });

        for _ in 0..50 {
            if sock_path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let client = DaemonSecretWrapper::new(&sock_path);
        let aad = b"e2e-aad";
        let secret1 = SafeSecret::new("e2e-secret-1");
        let secret2 = SafeSecret::new("e2e-secret-2");

        // 1. First operation: wraps secret, triggers initial hardware key derivation
        let wrapped1 = client.wrap(aad, &secret1).await.unwrap();
        assert_eq!(deriver.calls.load(Ordering::SeqCst), 1);

        // 2. Second operation: unwrap uses the cached key in daemon memory WITHOUT calling deriver
        let unwrapped1 = client.unwrap(aad, &wrapped1).await.unwrap();
        assert_eq!(unwrapped1.expose_secret(), "e2e-secret-1");
        assert_eq!(deriver.calls.load(Ordering::SeqCst), 1);

        // 3. Third operation: wrap second secret also uses cached key
        let wrapped2 = client.wrap(aad, &secret2).await.unwrap();
        let unwrapped2 = client.unwrap(aad, &wrapped2).await.unwrap();
        assert_eq!(unwrapped2.expose_secret(), "e2e-secret-2");
        assert_eq!(deriver.calls.load(Ordering::SeqCst), 1);

        // 4. Send Lock request over IPC
        let lock_resp = send_request(&sock_path, &IpcRequest::Lock).await.unwrap();
        assert_eq!(lock_resp, IpcResponse::Locked);

        // 5. Operation after lock requires key derivation again
        let _ = client.unwrap(aad, &wrapped1).await.unwrap();
        assert_eq!(deriver.calls.load(Ordering::SeqCst), 2);

        // 6. Stop daemon
        let stop_resp = send_request(&sock_path, &IpcRequest::Stop).await.unwrap();
        assert_eq!(stop_resp, IpcResponse::Stopped);
        let _ = srv_handle.join();
    }
}
