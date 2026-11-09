use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use clap::Parser;

use crate::app::CliApplication;
use c9s::domain::models::settings::AppConfig;
use c9s::domain::ports::notifier::Notifier;
use c9s::domain::ports::user_interaction::UserInteraction;
use c9s::outbound::daemon::client::send_request;
use c9s::outbound::daemon::peer_cred::default_socket_path;
use c9s::outbound::daemon::protocol::{IpcRequest, IpcResponse};
use c9s::outbound::daemon::server::{DaemonServer, DEFAULT_IDLE_TIMEOUT};

use crate::utils::parse_ttl;

#[derive(Parser)]
pub struct Daemon {
    #[clap(subcommand)]
    sub_command: DaemonSubCommands,
}

#[derive(Parser)]
enum DaemonSubCommands {
    /// Runs the daemon as a background process.
    Run(DaemonRun),
    /// Shows the status of the daemon.
    Status(DaemonStatus),
    /// Clears the secrets from the daemon's memory.
    Lock(DaemonLock),
    /// Gracefully stops the daemon
    Stop(DaemonStop),
}

#[derive(Parser)]
pub struct DaemonRun {
    /// The socket's path.
    #[clap(long)]
    socket: Option<PathBuf>,

    /// The timeout before the daemon clears its memory.
    #[clap(long, value_parser = parse_ttl)]
    idle_timeout: Option<Duration>,

    /// Turn off desktop notifications when the daemon decrypts secrets.
    #[clap(long)]
    no_notify: bool,
}

#[derive(Parser)]
pub struct DaemonStatus {
    /// The socket's path.
    #[clap(long)]
    socket: Option<PathBuf>,
}

#[derive(Parser)]
pub struct DaemonLock {
    /// The socket's path.
    #[clap(long)]
    socket: Option<PathBuf>,
}

#[derive(Parser)]
pub struct DaemonStop {
    /// The socket's path.
    #[clap(long)]
    socket: Option<PathBuf>,
}

impl Daemon {
    pub async fn run(self, application: &CliApplication) -> Result<()> {
        let settings = application.config().clone();
        match self.sub_command {
            DaemonSubCommands::Run(cmd) => {
                let interaction = Arc::new(application.interaction());
                let notifier = Arc::new(application.notifier());
                cmd.run(&settings, interaction, notifier).await
            }
            DaemonSubCommands::Status(cmd) => cmd.run(&settings).await,
            DaemonSubCommands::Lock(cmd) => cmd.run(&settings).await,
            DaemonSubCommands::Stop(cmd) => cmd.run(&settings).await,
        }
    }
}

impl DaemonRun {
    pub async fn run<U: UserInteraction + 'static, N: Notifier + 'static>(
        self,
        settings: &AppConfig,
        interaction: Arc<U>,
        notifier: Arc<N>,
    ) -> Result<()> {
        let yk = settings.yubikey_config().ok_or_else(|| {
            anyhow!("The security key is not configured. Run `c9s config yubikey` first.")
        })?;

        #[cfg(target_os = "windows")]
        {
            let _ = (yk, interaction, notifier);
            return Err(anyhow!("YubiKey wrapping is not supported on Windows"));
        }

        #[cfg(not(target_os = "windows"))]
        {
            // get the security key's credential id
            let credential_id = yk.credential_id().to_vec();

            // get the salt
            let salt = *yk.salt();

            // create the security key wrapper
            let wrapper = c9s::outbound::yubikey::YubikeyWrapper::new(
                yk.rp_id(),
                credential_id,
                salt,
                interaction,
                notifier.clone(),
            );

            // get the socket's path
            let socket_path = self
                .socket
                .or_else(|| {
                    settings
                        .daemon_config()
                        .and_then(|d| d.socket_path().cloned())
                })
                .unwrap_or_else(default_socket_path);

            // get the idle timeout for the daemon
            let idle_timeout = self
                .idle_timeout
                .or_else(|| {
                    settings
                        .daemon_config()
                        .map(|d| Duration::from_secs(d.idle_timeout_minutes() * 60))
                })
                .unwrap_or(DEFAULT_IDLE_TIMEOUT);

            // figure out if we should notify the user on decrypting a secret.
            let notify_on_decrypt = if self.no_notify {
                false
            } else {
                settings
                    .daemon_config()
                    .map(|d| d.notify_on_decrypt())
                    .unwrap_or(true)
            };

            // create the daemon server
            let server = DaemonServer::new(
                socket_path,
                Arc::new(wrapper),
                notifier,
                idle_timeout,
                notify_on_decrypt,
            );

            // run the daemon
            server
                .run()
                .await
                .map_err(|e| anyhow!("daemon server error: {}", e))
        }
    }
}

impl DaemonStatus {
    pub async fn run(self, settings: &AppConfig) -> Result<()> {
        // get the socket's path
        let socket_path = self
            .socket
            .or_else(|| {
                settings
                    .daemon_config()
                    .and_then(|d| d.socket_path().cloned())
            })
            .unwrap_or_else(default_socket_path);

        // send a status request to the daemon
        match send_request(&socket_path, &IpcRequest::Status).await {
            Ok(IpcResponse::Status {
                is_locked,
                remaining_ttl_seconds,
            }) => {
                // the daemon is running, give the status
                println!("Daemon: running ({})", socket_path.display());

                if is_locked {
                    println!("Session: locked (no key cached)");
                } else {
                    println!("Session: unlocked (key cached in memory)");
                    if let Some(ttl) = remaining_ttl_seconds {
                        println!("Idle TTL remaining: {}s", ttl);
                    }
                }

                Ok(())
            }
            Ok(other) => Err(anyhow!("unexpected response: {:?}", other)),
            Err(e)
            // check if it's not running
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.kind() == std::io::ErrorKind::ConnectionRefused =>
            {
                println!("Daemon: not running");
                Ok(())
            }
            Err(e) => Err(anyhow!("failed to query daemon status: {}", e)),
        }
    }
}

impl DaemonLock {
    pub async fn run(self, settings: &AppConfig) -> Result<()> {
        // get the socket's path
        let socket_path = self
            .socket
            .or_else(|| {
                settings
                    .daemon_config()
                    .and_then(|d| d.socket_path().cloned())
            })
            .unwrap_or_else(default_socket_path);

        // send a lock request to the daemon
        match send_request(&socket_path, &IpcRequest::Lock).await {
            Ok(IpcResponse::Locked) => {
                println!("Session locked and secrets cleared.");
                Ok(())
            }
            Ok(IpcResponse::Error { message }) => Err(anyhow!("daemon error: {}", message)),
            Ok(other) => Err(anyhow!("unexpected response: {:?}", other)),
            Err(e)
            // check if the daemon is running
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.kind() == std::io::ErrorKind::ConnectionRefused =>
            {
                println!("Daemon is not running.");
                Ok(())
            }
            Err(e) => Err(anyhow!("failed to lock daemon: {}", e)),
        }
    }
}

impl DaemonStop {
    pub async fn run(self, settings: &AppConfig) -> Result<()> {
        // get the socket's path
        let socket_path = self
            .socket
            .or_else(|| {
                settings
                    .daemon_config()
                    .and_then(|d| d.socket_path().cloned())
            })
            .unwrap_or_else(default_socket_path);

        // send the stop request to the daemon
        match send_request(&socket_path, &IpcRequest::Stop).await {
            Ok(IpcResponse::Stopped) => {
                println!("Daemon stopped.");
                Ok(())
            }
            Ok(IpcResponse::Error { message }) => Err(anyhow!("daemon error: {}", message)),
            Ok(other) => Err(anyhow!("unexpected response: {:?}", other)),
            Err(e)
            // check if the daemon is running
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.kind() == std::io::ErrorKind::ConnectionRefused =>
            {
                println!("Daemon is not running.");
                Ok(())
            }
            Err(e) => Err(anyhow!("failed to stop daemon: {}", e)),
        }
    }
}
