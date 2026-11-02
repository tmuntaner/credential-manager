use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PeerCredError {
    #[error("failed to query socket peer credentials: {0}")]
    SocketQueryFailed(#[source] std::io::Error),

    #[error("caller UID {peer_uid} does not match daemon UID {expected_uid}")]
    UidMismatch { peer_uid: u32, expected_uid: u32 },

    #[error("failed to inspect peer process executable: {0}")]
    ExeLookupFailed(#[source] std::io::Error),

    #[error("unauthorized calling binary: {path}")]
    UnauthorizedBinary { path: PathBuf },

    #[error("peer process has exited")]
    PeerExited,

    #[error("peer process is being traced")]
    PeerTraced,

    #[error("peer process environment contains {var}")]
    PeerEnvTampered { var: String },

    #[error("failed to inspect peer process state: {0}")]
    PeerInspectionFailed(#[source] std::io::Error),

    #[error("peer verification is unsupported on this platform")]
    UnsupportedPlatform,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCredentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    pub pid: u32,
    pub uid: u32,
    pub exe_path: PathBuf,
    pub binary_name: String,
}

/// Retrieves the peer credentials from the connected stream.
#[cfg(target_os = "linux")]
pub fn get_peer_credentials(
    stream: &tokio::net::UnixStream,
) -> Result<PeerCredentials, PeerCredError> {
    use std::os::fd::AsRawFd;

    // get the raw file descriptor
    let fd = stream.as_raw_fd();
    let mut ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = size_of::<libc::ucred>() as libc::socklen_t;

    // get the socket options from libc.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    // if the return is 0, it failed.
    if ret != 0 {
        return Err(PeerCredError::SocketQueryFailed(
            std::io::Error::last_os_error(),
        ));
    }

    Ok(PeerCredentials {
        pid: ucred.pid as u32,
        uid: ucred.uid,
        gid: ucred.gid,
    })
}

/// Retrieves peer credentials from a connected Unix stream on macOS.
#[cfg(target_os = "macos")]
pub fn get_peer_credentials(
    stream: &tokio::net::UnixStream,
) -> Result<PeerCredentials, PeerCredError> {
    use std::os::fd::AsRawFd;

    let fd = stream.as_raw_fd();

    // 1. Query xucred for UID/GID
    let mut xucred: libc::xucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::xucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            0, // SOL_LOCAL
            libc::LOCAL_PEERCRED,
            &mut xucred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(PeerCredError::SocketQueryFailed(
            std::io::Error::last_os_error(),
        ));
    }

    // 2. Query LOCAL_PEERPID for PID (0x002 on Darwin)
    const LOCAL_PEERPID: libc::c_int = 0x002;
    let mut pid: libc::pid_t = 0;
    let mut pid_len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let ret_pid = unsafe {
        libc::getsockopt(
            fd,
            0, // SOL_LOCAL
            LOCAL_PEERPID,
            &mut pid as *mut _ as *mut libc::c_void,
            &mut pid_len,
        )
    };
    if ret_pid != 0 {
        return Err(PeerCredError::SocketQueryFailed(
            std::io::Error::last_os_error(),
        ));
    }

    Ok(PeerCredentials {
        pid: pid as u32,
        uid: xucred.cr_uid,
        gid: if xucred.cr_ngroups > 0 {
            xucred.cr_groups[0]
        } else {
            0
        },
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn get_peer_credentials(
    _stream: &tokio::net::UnixStream,
) -> Result<PeerCredentials, PeerCredError> {
    Err(PeerCredError::UnsupportedPlatform)
}

/// Gets the filesystem executable path from the PID.
#[cfg(target_os = "linux")]
pub fn get_peer_exe_path(pid: u32) -> Result<PathBuf, PeerCredError> {
    // create the link path for proc
    let link_path = format!("/proc/{}/exe", pid);

    // read the proc link to find the executable path
    let exe_path = std::fs::read_link(&link_path).map_err(PeerCredError::ExeLookupFailed)?;

    Ok(exe_path)
}

/// Resolves the filesystem executable path of a process on macOS.
#[cfg(target_os = "macos")]
pub fn get_peer_exe_path(pid: u32) -> Result<PathBuf, PeerCredError> {
    let mut buf = vec![0u8; 4096];
    let ret = unsafe {
        libc::proc_pidpath(
            pid as libc::c_int,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len() as u32,
        )
    };
    if ret <= 0 {
        return Err(PeerCredError::ExeLookupFailed(
            std::io::Error::last_os_error(),
        ));
    }
    let cstr = std::ffi::CStr::from_bytes_until_nul(&buf).map_err(|e| {
        PeerCredError::ExeLookupFailed(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    })?;
    let path_str = cstr.to_str().map_err(|e| {
        PeerCredError::ExeLookupFailed(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    })?;
    Ok(PathBuf::from(path_str))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn get_peer_exe_path(_pid: u32) -> Result<PathBuf, PeerCredError> {
    Err(PeerCredError::UnsupportedPlatform)
}

/// Whether both paths are the same file (same device and inode).
fn is_same_file(a: &Path, b: &Path) -> Result<bool, std::io::Error> {
    use std::os::unix::fs::MetadataExt;

    let a = std::fs::metadata(a)?;
    let b = std::fs::metadata(b)?;
    Ok(a.dev() == b.dev() && a.ino() == b.ino())
}

/// Whether the peer process is the same executable file as this process.
///
/// On Linux the `/proc/<pid>/exe` link holds even when the binary was deleted or replaced on disk.
/// A renamed or copied binary is a different file and does not match.
fn is_same_executable(pid: u32, peer_exe_path: &Path) -> Result<bool, PeerCredError> {
    #[cfg(target_os = "linux")]
    let (peer, own) = {
        let _ = peer_exe_path;
        (
            PathBuf::from(format!("/proc/{}/exe", pid)),
            PathBuf::from("/proc/self/exe"),
        )
    };

    #[cfg(not(target_os = "linux"))]
    let (peer, own) = {
        let _ = pid;
        (
            peer_exe_path.to_path_buf(),
            std::env::current_exe().map_err(PeerCredError::ExeLookupFailed)?,
        )
    };

    is_same_file(&peer, &own).map_err(PeerCredError::ExeLookupFailed)
}

/// `SO_PEERPIDFD`, added in Linux 6.5. Defined locally in case `libc` lacks it.
#[cfg(target_os = "linux")]
const SO_PEERPIDFD: libc::c_int = 77;

/// Forbidden environment variables that allow a process to inject code into a binary.
const FORBIDDEN_ENV_VARS: &[&[u8]] = &[b"LD_PRELOAD", b"LD_LIBRARY_PATH", b"LD_AUDIT"];

/// Fetches a pidfd for the peer. This stays tied to a process, even if its PID was reused.
/// Returns `None` for kernels older than 6.5.
#[cfg(target_os = "linux")]
fn get_peer_pidfd(
    stream: &tokio::net::UnixStream,
) -> Result<Option<std::os::fd::OwnedFd>, PeerCredError> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    // gets the pidfd
    let mut pidfd: libc::c_int = -1;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_PEERPIDFD,
            &mut pidfd as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    // if it's unsuccessful, return an error.
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOPROTOOPT) {
            return Ok(None);
        }
        return Err(PeerCredError::SocketQueryFailed(err));
    }

    Ok(Some(unsafe { OwnedFd::from_raw_fd(pidfd) }))
}

/// Parses the `Pid:` line of `/proc/self/fdinfo/<pidfd>`.
#[cfg(target_os = "linux")]
fn parse_fdinfo_pid(fdinfo: &[u8]) -> Option<i64> {
    fdinfo
        .split(|b| *b == b'\n')
        .find_map(|line| line.strip_prefix(b"Pid:"))
        .and_then(|rest| std::str::from_utf8(rest).ok())
        .and_then(|rest| rest.trim().parse().ok())
}

/// Resolves the PID that a pidfd points to.
/// A pidfd of a dead process has no PID.
#[cfg(target_os = "linux")]
fn pid_from_pidfd(pidfd: &std::os::fd::OwnedFd) -> Result<u32, PeerCredError> {
    use std::os::fd::AsRawFd;

    // gets the fdinfo from proc
    let fdinfo = std::fs::read(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))
        .map_err(PeerCredError::PeerInspectionFailed)?;

    // handle the fdinfo
    match parse_fdinfo_pid(&fdinfo) {
        Some(pid) if pid > 0 => Ok(pid as u32),
        Some(_) => Err(PeerCredError::PeerExited),
        None => Err(PeerCredError::PeerInspectionFailed(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "no Pid in pidfd fdinfo",
        ))),
    }
}

/// Confirms the pidfd process still exists.
#[cfg(target_os = "linux")]
fn ensure_pidfd_alive(pidfd: &std::os::fd::OwnedFd) -> Result<(), PeerCredError> {
    use std::os::fd::AsRawFd;

    // send a signal to the process referred to by the pidfd.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            0,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if ret == 0 {
        return Ok(());
    }

    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ESRCH) {
        Err(PeerCredError::PeerExited)
    } else {
        Err(PeerCredError::PeerInspectionFailed(err))
    }
}

/// Reads the `TracerPid` from the contents of `/proc/<pid>/status`.
#[cfg(target_os = "linux")]
fn parse_tracer_pid(status: &[u8]) -> Option<u32> {
    status
        .split(|b| *b == b'\n')
        .find_map(|line| line.strip_prefix(b"TracerPid:"))
        .and_then(|rest| std::str::from_utf8(rest).ok())
        .and_then(|rest| rest.trim().parse().ok())
}

/// Finds a forbidden variable in the contents of `/proc/<pid>/environ` (NUL separated entries).
#[cfg(target_os = "linux")]
fn find_forbidden_env(environ: &[u8], forbidden: &[&[u8]]) -> Option<String> {
    environ.split(|b| *b == 0).find_map(|entry| {
        let name = entry.split(|b| *b == b'=').next().unwrap_or_default();
        forbidden
            .contains(&name)
            .then(|| String::from_utf8_lossy(name).into_owned())
    })
}

/// Rejects peers that are being traced or that were started with library injection variables.
/// An unreadable `status` or `environ` is a denial.
#[cfg(target_os = "linux")]
fn check_peer_hygiene(pid: u32, forbidden_env: &[&[u8]]) -> Result<(), PeerCredError> {
    let status = std::fs::read(format!("/proc/{}/status", pid))
        .map_err(PeerCredError::PeerInspectionFailed)?;
    match parse_tracer_pid(&status) {
        Some(0) => {}
        Some(_) => return Err(PeerCredError::PeerTraced),
        None => {
            return Err(PeerCredError::PeerInspectionFailed(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "no TracerPid in status",
            )))
        }
    }

    let environ = std::fs::read(format!("/proc/{}/environ", pid))
        .map_err(PeerCredError::PeerInspectionFailed)?;
    if let Some(var) = find_forbidden_env(&environ, forbidden_env) {
        return Err(PeerCredError::PeerEnvTampered { var });
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn check_peer_hygiene(_pid: u32, _forbidden_env: &[&[u8]]) -> Result<(), PeerCredError> {
    // macOS has no equivalent of the Linux checks.
    Ok(())
}

/// Verify that the connected peer should actually connect to the daemon.
///
/// This runs for every request, so a peer that `exec`s something else after connecting is caught.
pub fn verify_peer_connection(
    stream: &tokio::net::UnixStream,
) -> Result<PeerIdentity, PeerCredError> {
    verify_peer_with(stream, Some(FORBIDDEN_ENV_VARS))
}

/// Like [`verify_peer_connection`], which uses [`FORBIDDEN_ENV_VARS`], with the given forbidden
/// environment variables. `None` skips the hygiene checks.
fn verify_peer_with(
    stream: &tokio::net::UnixStream,
    forbidden_env: Option<&[&[u8]]>,
) -> Result<PeerIdentity, PeerCredError> {
    let creds = get_peer_credentials(stream)?;

    // get the user id
    let expected_uid = unsafe { libc::getuid() };
    if creds.uid != expected_uid {
        return Err(PeerCredError::UidMismatch {
            peer_uid: creds.uid,
            expected_uid,
        });
    }

    // On Linux, prefer the pidfd: it pins the process the peer connected as, so a reused PID
    // is not mistaken for it. Older kernels fall back to the PID from `SO_PEERCRED`.
    #[cfg(target_os = "linux")]
    let pidfd = get_peer_pidfd(stream)?;
    #[cfg(target_os = "linux")]
    let pid = match &pidfd {
        Some(fd) => pid_from_pidfd(fd)?,
        None => creds.pid,
    };
    #[cfg(not(target_os = "linux"))]
    let pid = creds.pid;

    // get the binary name
    let exe_path = get_peer_exe_path(pid)?;
    let binary_name = exe_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    // Only allow an executable by the same binary as the daemon. The attacker can
    // control the file name, so it's better to be safe.
    if !is_same_executable(pid, &exe_path)? {
        return Err(PeerCredError::UnauthorizedBinary { path: exe_path });
    }

    if let Some(forbidden_env) = forbidden_env {
        check_peer_hygiene(pid, forbidden_env)?;
    }

    // the peer must still be alive after all the checks, otherwise they described something else.
    #[cfg(target_os = "linux")]
    if let Some(fd) = &pidfd {
        ensure_pidfd_alive(fd)?;
    }

    Ok(PeerIdentity {
        pid,
        uid: creds.uid,
        exe_path,
        binary_name,
    })
}

/// Verification for tests that connect to a server in the same process: `cargo test` sets
/// `LD_LIBRARY_PATH` for the test binary, and the server makes the process non-dumpable, which
/// makes its `/proc` files unreadable. Hygiene is tested with child processes instead.
#[cfg(test)]
pub fn verify_peer_connection_in_tests(
    stream: &tokio::net::UnixStream,
) -> Result<PeerIdentity, PeerCredError> {
    verify_peer_with(stream, None)
}

/// Gets the standard socket location.
pub fn default_socket_path() -> PathBuf {
    // get the environment variable path if set.
    if let Some(custom) = std::env::var_os("C9S_DAEMON_SOCKET") {
        return PathBuf::from(custom);
    }

    // if there is a runtime directory, add its path to c9s.sock to create the path.
    if let Some(runtime_dir) = dirs::runtime_dir() {
        return runtime_dir.join("c9s.sock");
    }

    // build a path from the home's local directory
    let local_share = dirs::data_local_dir().unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_default()
            .join(".local")
            .join("share")
    });

    local_share.join("c9s").join("run").join("c9s.sock")
}

/// Ensures the parent directory exists for the socket 0700 permissions.
pub fn ensure_socket_dir(socket_path: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Binds to a domain socket with 0600 permissions.
pub async fn bind_secure_socket(
    socket_path: &Path,
) -> Result<tokio::net::UnixListener, std::io::Error> {
    ensure_socket_dir(socket_path)?;

    // See if the socket file exists already
    if socket_path.exists() {
        // Try a connection against the socket to see if anything is listening already.
        // Return an error if something is already listening there.
        match tokio::net::UnixStream::connect(socket_path).await {
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!(
                        "another daemon is already listening on {}",
                        socket_path.display()
                    ),
                ));
            }
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => {
                // It should be a stale socket file left over from a crashed process. Clean it up!
                let _ = std::fs::remove_file(socket_path);
            }
            Err(_) => {
                let _ = std::fs::remove_file(socket_path);
            }
        }
    }

    // start listening to the socket.
    let listener = tokio::net::UnixListener::bind(socket_path)?;
    std::fs::set_permissions(socket_path, Permissions::from_mode(0o600))?;

    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn peer_credentials_from_connected_socket_pair() {
        let (tokio_a, _tokio_b) = tokio::net::UnixStream::pair().unwrap();

        let creds = get_peer_credentials(&tokio_a).unwrap();
        assert_eq!(creds.pid, std::process::id());
        assert_eq!(creds.uid, unsafe { libc::getuid() });
    }

    #[tokio::test]
    async fn peer_verification_succeeds_for_current_process() {
        let (tokio_a, _tokio_b) = tokio::net::UnixStream::pair().unwrap();

        let identity = verify_peer_connection_in_tests(&tokio_a).unwrap();
        assert_eq!(identity.pid, std::process::id());
        assert_eq!(identity.uid, unsafe { libc::getuid() });
        assert!(!identity.binary_name.is_empty());
    }

    #[test]
    fn copied_binary_with_c9s_name_is_not_the_same_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let copy = temp_dir.path().join("c9s");
        std::fs::copy(std::env::current_exe().unwrap(), &copy).unwrap();

        assert!(!is_same_file(&copy, &std::env::current_exe().unwrap()).unwrap());
    }

    #[test]
    fn hard_link_and_same_path_are_the_same_file() {
        let exe = std::env::current_exe().unwrap();
        assert!(is_same_file(&exe, &exe).unwrap());

        let temp_dir = tempfile::tempdir().unwrap();
        let link = temp_dir.path().join("link");
        if std::fs::hard_link(&exe, &link).is_ok() {
            assert!(is_same_file(&link, &exe).unwrap());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tracer_pid_is_parsed_from_status() {
        assert_eq!(
            parse_tracer_pid(b"Name:\tc9s\nTracerPid:\t0\nUid:\t1000\n"),
            Some(0)
        );
        assert_eq!(
            parse_tracer_pid(b"Name:\tc9s\nTracerPid:\t4242\n"),
            Some(4242)
        );
        assert_eq!(parse_tracer_pid(b"Name:\tc9s\n"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forbidden_env_is_detected_in_environ() {
        assert_eq!(
            find_forbidden_env(b"PATH=/bin\0HOME=/root\0", FORBIDDEN_ENV_VARS),
            None
        );
        assert_eq!(
            find_forbidden_env(b"PATH=/bin\0LD_PRELOAD=/tmp/x.so\0", FORBIDDEN_ENV_VARS),
            Some("LD_PRELOAD".to_string())
        );
        assert_eq!(
            find_forbidden_env(b"LD_LIBRARY_PATH=/tmp\0", FORBIDDEN_ENV_VARS),
            Some("LD_LIBRARY_PATH".to_string())
        );
        assert_eq!(
            find_forbidden_env(b"LD_AUDIT=a\0", FORBIDDEN_ENV_VARS),
            Some("LD_AUDIT".to_string())
        );
        // a value that merely mentions the name, or a longer name, is fine
        assert_eq!(
            find_forbidden_env(b"X=LD_PRELOAD\0LD_PRELOAD_X=1\0", FORBIDDEN_ENV_VARS),
            None
        );
    }

    #[cfg(target_os = "linux")]
    fn sleeping_child(preload: bool) -> std::process::Child {
        let mut cmd = std::process::Command::new("sleep");
        cmd.arg("30").env_remove("LD_LIBRARY_PATH");
        if preload {
            cmd.env("LD_PRELOAD", "/dev/null");
        }
        cmd.spawn().unwrap()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn hygiene_of_real_processes() {
        let mut clean = sleeping_child(false);
        let mut preloaded = sleeping_child(true);
        // wait until both executed `sleep`; before that they show the environment of the fork.
        std::thread::sleep(std::time::Duration::from_millis(200));

        assert!(check_peer_hygiene(clean.id(), FORBIDDEN_ENV_VARS).is_ok());
        assert!(matches!(
            check_peer_hygiene(preloaded.id(), FORBIDDEN_ENV_VARS),
            Err(PeerCredError::PeerEnvTampered { var }) if var == "LD_PRELOAD"
        ));

        clean.kill().unwrap();
        preloaded.kill().unwrap();
        let _ = clean.wait();
        let _ = preloaded.wait();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pid_is_parsed_from_fdinfo() {
        assert_eq!(
            parse_fdinfo_pid(b"pos:\t0\nflags:\t02\nPid:\t1234\nNSpid:\t1234\n"),
            Some(1234)
        );
        assert_eq!(parse_fdinfo_pid(b"Pid:\t-1\n"), Some(-1));
        assert_eq!(parse_fdinfo_pid(b"pos:\t0\n"), None);
    }

    #[tokio::test]
    async fn default_socket_path_is_deterministic() {
        let path = default_socket_path();
        assert!(path.to_string_lossy().contains("c9s.sock"));
    }

    #[tokio::test]
    async fn bind_and_permissions_work() {
        let temp_dir = tempfile::tempdir().unwrap();
        let sock_path = temp_dir.path().join("test.sock");

        let listener = bind_secure_socket(&sock_path).await.unwrap();
        assert!(sock_path.exists());

        let metadata = std::fs::metadata(&sock_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        drop(listener);
    }

    #[tokio::test]
    async fn bind_detects_already_running_daemon() {
        let temp_dir = tempfile::tempdir().unwrap();
        let sock_path = temp_dir.path().join("active.sock");

        let _listener = bind_secure_socket(&sock_path).await.unwrap();

        // Second bind attempt should fail with AddrInUse
        let second_bind = bind_secure_socket(&sock_path).await;
        assert!(second_bind.is_err());
        assert_eq!(
            second_bind.unwrap_err().kind(),
            std::io::ErrorKind::AddrInUse
        );
    }

    #[tokio::test]
    async fn bind_cleans_up_stale_socket() {
        let temp_dir = tempfile::tempdir().unwrap();
        let sock_path = temp_dir.path().join("stale.sock");

        // Create socket then drop listener without deleting file
        let listener = bind_secure_socket(&sock_path).await.unwrap();
        drop(listener);

        // File still exists but nobody listening
        assert!(sock_path.exists());

        // Rebinding should detect stale socket, clean it up, and succeed
        let new_listener = bind_secure_socket(&sock_path).await.unwrap();
        assert!(sock_path.exists());
        drop(new_listener);
    }
}
