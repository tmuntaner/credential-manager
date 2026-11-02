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

/// Verify that the connected peer should actually connect to the daemon.
pub fn verify_peer_connection(
    stream: &tokio::net::UnixStream,
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

    // get the binary name
    let exe_path = get_peer_exe_path(creds.pid)?;
    let binary_name = exe_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    // Only allow an executable by the same binary as the daemon. The attacker can
    // control the file name, so it's better to be safe.
    if !is_same_executable(creds.pid, &exe_path)? {
        return Err(PeerCredError::UnauthorizedBinary { path: exe_path });
    }

    Ok(PeerIdentity {
        pid: creds.pid,
        uid: creds.uid,
        exe_path,
        binary_name,
    })
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

        let identity = verify_peer_connection(&tokio_a).unwrap();
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
