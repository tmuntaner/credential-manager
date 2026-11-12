use crate::inbound::app::Shell;
use crate::outbound::prompts::Bridge;
use c9s::app::prompts::{WindowInteraction, WindowNotifier};
use c9s::app::settings::{enroll_security_key, SetupError, DEFAULT_RP_ID};
use c9s::domain::models::settings::YubikeyConfig;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::Arc;

/// Enrolls a security key for a rp_id, blocking until the user is done.
/// It runs on its own thread and asks its questions through the bridge.
pub type Enroller = Arc<dyn Fn(&str, Bridge) -> Result<YubikeyConfig, SetupError> + Send + Sync>;

/// The enroller that uses the real security key.
fn real_enroller() -> Enroller {
    Arc::new(|rp_id, bridge| {
        // The enrolling future is not `Send`, so it gets a runtime of its own on this thread.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| SetupError::general(format!("Could not start enrolling: {e}.")))?;

        let result = runtime.block_on(enroll_security_key(
            rp_id,
            Arc::new(WindowInteraction::new(bridge.clone())),
            Arc::new(WindowNotifier::new(bridge.clone())),
        ));

        // The "touch your key" notice stays until it is cleared.
        bridge.clear_notices();
        result
    })
}

/// The enrolling of a security key: started on its own thread, taken in when it is done.
pub struct Enrolling {
    pub enroller: Enroller,
    /// The result of the enrolling that is in progress.
    pending: Option<Receiver<Result<YubikeyConfig, SetupError>>>,
}

impl Enrolling {
    pub fn new() -> Self {
        Self {
            enroller: real_enroller(),
            pending: None,
        }
    }

    /// Replaces how a security key is enrolled.
    pub fn set_enroller(&mut self, enroller: Enroller) {
        self.enroller = enroller;
    }

    pub fn is_running(&self) -> bool {
        self.pending.is_some()
    }

    /// Starts enrolling a security key on its own thread.
    pub fn start(&mut self, shell: &mut Shell, bridge: &Bridge) {
        if self.is_running() {
            return;
        }

        let (sender, receiver) = mpsc::channel();
        let enroller = self.enroller.clone();
        let bridge = bridge.clone();
        let ctx = shell.ctx.clone();
        let spawned = std::thread::Builder::new()
            .name("enroll-security-key".into())
            .spawn(move || {
                let _ = sender.send(enroller(DEFAULT_RP_ID, bridge));
                ctx.request_repaint();
            });

        match spawned {
            Ok(_) => {
                self.pending = Some(receiver);
                shell.say("Enrolling the security key. Follow the instructions on the screen.");
            }
            Err(e) => shell.fail(format!("Could not start enrolling: {e}.")),
        }
    }

    /// The result of the enrolling, once it is done. Called every frame.
    pub fn poll(&mut self) -> Option<Result<YubikeyConfig, SetupError>> {
        let receiver = self.pending.as_ref()?;
        let result = match receiver.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return None,
            Err(TryRecvError::Disconnected) => Err(SetupError::general(
                "Enrolling the security key stopped unexpectedly.",
            )),
        };
        self.pending = None;

        Some(result)
    }
}

impl Default for Enrolling {
    fn default() -> Self {
        Self::new()
    }
}
