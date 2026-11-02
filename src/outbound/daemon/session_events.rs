//! Lock events from systemd-logind, so the daemon drops its secrets when the session locks or the
//! machine suspends.

use futures::stream::BoxStream;
use futures::StreamExt;
use log::{debug, warn};
use tokio::sync::mpsc::UnboundedSender;

use zbus::{Connection, OwnedObjectPath, Proxy};

const LOGIN1: &str = "org.freedesktop.login1";

/// Spawns a new task that sends on `lock_tx` when a user locks their session or the system
/// is about to sleep.
pub fn spawn(lock_tx: UnboundedSender<()>) {
    tokio::spawn(async move {
        if let Err(err) = listen(lock_tx).await {
            warn!("session lock events unavailable: {}", err);
        }
    });
}

async fn listen(lock_tx: UnboundedSender<()>) -> zbus::Result<()> {
    // connect to zbus and the login manager
    let conn = Connection::system().await?;
    let manager = Proxy::new(
        &conn,
        LOGIN1,
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
    )
    .await?;

    // receive sleep events
    let sleep: BoxStream<'_, ()> = manager
        .receive_signal("PrepareForSleep")
        .await?
        .filter_map(|msg| async move { msg.body().deserialize::<bool>().ok().filter(|b| *b) })
        .map(|_| ())
        .boxed();
    let mut events = vec![sleep];

    // Build a session proxy for the current processes login session.
    // Note: a login session may not exist depending on the runtime environment.
    let session: zbus::Result<OwnedObjectPath> = manager
        .call("GetSessionByPID", &(std::process::id(),))
        .await;
    let session_proxy = match session {
        Ok(path) => Some(Proxy::new(&conn, LOGIN1, path, "org.freedesktop.login1.Session").await?),
        Err(err) => {
            warn!(
                "no logind session for the daemon, session lock is not watched: {}",
                err
            );
            None
        }
    };

    // if there is a session proxy, watch it for locks
    if let Some(proxy) = &session_proxy {
        events.push(proxy.receive_signal("Lock").await?.map(|_| ()).boxed());
    }

    // dispatch events
    let mut events = futures::stream::select_all(events);
    while events.next().await.is_some() {
        debug!("session lock or suspend event received");
        if lock_tx.send(()).is_err() {
            break;
        }
    }

    Ok(())
}
