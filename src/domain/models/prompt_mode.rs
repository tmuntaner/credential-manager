/// How c9s approaches auto input
#[derive(PartialEq, Eq, Debug, Clone, Copy, Default)]
pub enum PromptMode {
    /// Uses a popup when possible, and a terminal when not.
    #[default]
    Auto,
    /// Only use a popup.
    Gui,
    /// Only use a terminal.
    Terminal,
}
