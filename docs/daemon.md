# Background Daemon

To prevent the user from needing to touch their security key too often,
`c9s` has a background daemon that keeps secrets in memory.
The background daemon acts as a secret wrapper and is meant to preserve user ergonomics and general security.

## Credential Encryption

The daemon follows the same [credential encryption](./credential_encryption.md) process as the normal `c9s` binary.
It's using the same code, it just spawns as another process to aid later `c9s` calls.

## Communication with c9s

`c9s` and the daemon communicates with each other with IPC.
It's important to note here that it will never transfer the encryption key over IPC.
It will only send requested secrets.

### Peer Verification

Every request is verified, not only the connection.
A process that connects and then `exec`s another program is caught on its next request.
Unauthorized peers receive an "Access denied" response.

1. The UIDs must match:
    - **Linux**: Queries `SO_PEERCRED` to retrieve the caller's PID, UID, and GID directly from the kernel.
    - **macOS**: Queries `LOCAL_PEERCRED` for UID/GID and `LOCAL_PEERPID` for caller PID.
    - It only allows connections from matched UIDs. It will abort connections for everything else immediately.
2. The caller must be the same binary file as the daemon:
    - It resolves the caller's executable using `/proc/<pid>/exe` on Linux or `proc_pidpath()` on macOS,
      and compares device and inode with the daemon's own executable.
    - It will deny connections from other executables with an access-denied error.
3. The caller must still be the process that connected (Linux 6.5+):
    - It fetches a pidfd with `SO_PEERPIDFD`, resolves the PID through it, and confirms the process is alive
      after the checks, so a reused PID is not mistaken for the caller.
    - On older kernels, it falls back to the PID from `SO_PEERCRED`.
4. The caller must not be traced or tampered with (Linux only):
    - `TracerPid` in `/proc/<pid>/status` must be 0.
    - `/proc/<pid>/environ` must not contain `LD_PRELOAD`, `LD_LIBRARY_PATH` or `LD_AUDIT`.
    - If these files can't be read, the caller is denied.
    - A client that was denied falls back to a local touch of the security key.
5. Core dumps are disabled (Linux Only):
    - On startup, the daemon disables ptrace dumping with `prctl(PR_SET_DUMPABLE, 0)`. This prevents unauthorized inspections of memory by unprivileged debuggers or crash loggers.

### Threat model

The daemon protects against other users and non-malicious local processes.
It doesn't protect against malware running as the same user.

For example, malware can run `c9s` itself, or inject code into a genuine `c9s` binary,
and obtain secrets without a security key touch.

The above checks increase the defense, but they can't close the malware gap on Linux.
If you can't accept that, set `daemon.enabled = false`, and every decryption needs a touch.

### Idle Daemon

The daemon keeps an idle 15-minute timer in the background, which when reached,
will lock the daemon, clearing secrets from memory.
Every interaction from `c9s` resets that timer, allowing a user to have an extended session without needing to unlock.

### Locking

When the daemon locks, it clears the secrets from memory.
It achieves this with zeroize, to securely zero the key in memory so we safely evict it from memory.

**Linux Only:**
The daemon locks when the desktop session locks or when the system suspends.
It listens to systemd-logind on the system bus, where it watches for the `Lock` signal of the session and `PrepareForSleep`.
If the bus is not available, it logs a warning and keeps running.
