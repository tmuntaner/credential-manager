use crate::core::ui::field::input_id;
use c9s::app::prompts::PromptRequest;
use eframe::egui::text_edit::TextEditState;
use eframe::egui::Context;
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PromptField {
    Secret,
}

/// A question on screen, and what was typed so far.
pub struct OpenQuestion {
    pub request: PromptRequest,
    pub secret: String,
    pub choice: usize,
    pub first_frame: bool,
}

impl OpenQuestion {
    pub fn new(request: PromptRequest) -> Self {
        Self {
            request,
            secret: String::new(),
            choice: 0,
            first_frame: true,
        }
    }

    /// Clears what was typed and frees it from memory.
    pub fn wipe(&mut self, ctx: &Context) {
        self.secret.zeroize();
        ctx.data_mut(|d| d.remove::<TextEditState>(input_id(PromptField::Secret)));
    }
}

impl Drop for OpenQuestion {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret_request() -> PromptRequest {
        PromptRequest::Secret {
            id: 1,
            title: "t".into(),
            description: None,
            label: "Password".into(),
            error: None,
            kind: Default::default(),
        }
    }

    #[test]
    fn wiping_forgets_what_was_typed() {
        let mut open = OpenQuestion::new(secret_request());
        open.secret.push_str("hunter2");

        open.wipe(&Context::default());

        assert!(open.secret.is_empty());
    }
}
