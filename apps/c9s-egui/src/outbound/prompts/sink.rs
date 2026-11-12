use c9s::app::prompts::{PromptSink, UiEvent};
use eframe::egui::Context;
use std::sync::mpsc::Sender;

/// Queues an event for the next frame.
pub struct ChannelSink {
    events: Sender<UiEvent>,
    ctx: Context,
}

impl ChannelSink {
    pub fn new(events: Sender<UiEvent>, ctx: Context) -> Self {
        Self { events, ctx }
    }
}

impl PromptSink for ChannelSink {
    fn emit(&self, event: UiEvent) {
        if self.events.send(event).is_ok() {
            self.ctx.request_repaint();
        }
    }
}
