use super::focus::{Focus, FocusTarget};
use super::nav::Route;
use super::status::Status;
use eframe::egui::Context;

pub struct Shell<'a> {
    pub ctx: &'a Context,
    route: &'a mut Route,
    focus: &'a mut Focus,
    status: &'a mut Status,
}

impl<'a> Shell<'a> {
    pub(crate) fn new(
        ctx: &'a Context,
        route: &'a mut Route,
        focus: &'a mut Focus,
        status: &'a mut Status,
    ) -> Self {
        Self {
            ctx,
            route,
            focus,
            status,
        }
    }

    /// The route the user is on.
    pub fn route(&self) -> Route {
        *self.route
    }

    /// Adds a message to the status line.
    pub fn say(&mut self, message: impl Into<String>) {
        self.status.say(message);
    }

    /// Adds an error to the status line.
    pub fn fail(&mut self, message: impl Into<String>) {
        self.status.fail(message);
    }

    /// Give the focus to a widget.
    pub fn focus(&mut self, target: FocusTarget) {
        self.focus.set(target);
    }

    /// Goes to another route. The focus should stay on its button in the nav bar.
    pub fn go(&mut self, route: Route) {
        *self.route = route;
        self.focus.set(FocusTarget::Nav(route));
        self.status.say(route.name());
    }
}
