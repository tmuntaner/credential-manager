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

### Kernel Enforced Protections

1. The UIDs must match:
    - **Linux**: Queries `SO_PEERCRED` to retrieve the caller's PID, UID, and GID directly from the kernel.
    - **macOS**: Queries `LOCAL_PEERCRED` for UID/GID and `LOCAL_PEERPID` for caller PID.
    - It only allows connections from matched UIDs. It will abort connections for everything else immediately.
2. The caller must be using the same binary path:
    - It resolves caller's executable using `/proc/<pid>/exe` on Linux or `proc_pidpath()` on macOS.
    - It will deny connections from other executables with an access-denied error.
3. Core dumps are disabled (Linux Only):
    - On startup, the daemon disables ptrace dumping with `prctl(PR_SET_DUMPABLE, 0)`. This prevents unauthorized inspections of memory by unprivileged debuggers or crash loggers. 

### Idle Daemon

The daemon keeps an idle 15-minute timer in the background, which when reached,
will lock the daemon, clearing secrets from memory.
Every interaction from `c9s` resets that timer, allowing a user to have an extended session without needing to unlock.

### Locking

When the daemon locks, it clears the secrets from memory.
It achieves this with zeroize, to securely zero the key in memory so we safely evict it from memory.
