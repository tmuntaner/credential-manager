use crate::app::status::Status;
use crate::app::{nav, style, Focus, Route, Shell, SidebarState};
use crate::prompts::{self, Bridge, Prompts};
use crate::settings;
use c9s::outbound::config::config_store::ConfigFileAdapter;
use eframe::egui::{CentralPanel, Context, Panel, RichText, ScrollArea, Ui};

/// What action happened in the window.
pub enum Event {
    Go(Route),
    Settings(settings::SettingsAction),
}

pub struct C9sApp {
    route: Route,
    focus: Focus,
    status: Status,
    settings: settings::SettingsState,
    bridge: Bridge,
    prompts: Prompts,
}

impl C9sApp {
    pub fn new(ctx: Context, store: ConfigFileAdapter) -> Self {
        // apply the styles
        style::apply(&ctx);

        // get the prompts
        let (bridge, prompts) = prompts::connect(ctx);

        // create the settings state
        let settings = settings::SettingsState::new(store, bridge.clone());

        let route = if settings.is_set_up() {
            Route::Credentials
        } else {
            // A first run starts on the checklist.
            Route::Setup
        };

        Self {
            route,
            focus: Focus::default(),
            status: Status::default(),
            settings,
            bridge,
            prompts,
        }
    }

    /// Replaces how a security key is enrolled (for tests).
    pub fn set_enroller(&mut self, enroller: settings::Enroller) {
        self.settings.set_enroller(enroller);
    }

    /// The prompt bridge which asks the user questions.
    pub fn bridge(&self) -> Bridge {
        self.bridge.clone()
    }

    /// Draws one frame.
    pub fn show(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();

        // if the viewport is closed, tell the bridge to cancel everything
        if ctx.input(|i| i.viewport().close_requested()) {
            self.bridge.cancel_all();
        }

        let mut event = None;

        Panel::top("header").show(ui, |ui| {
            // create the header text
            ui.add_space(6.0);
            ui.label(RichText::new("Credential Manager").size(24.0).strong());
            ui.add_space(6.0);
            ui.add_space(6.0);
        });

        // build the navigation sidebar
        let pending = self.settings.pending_sections();
        let sidebar = SidebarState {
            setup: !self.settings.is_set_up(),
            pending: &pending,
        };
        Panel::left("nav")
            .resizable(false)
            .default_size(200.0)
            .show(ui, |ui| {
                ui.add_space(6.0);
                if let Some(route) = nav::sidebar(ui, self.route, &mut self.focus, sidebar) {
                    event = Some(Event::Go(route));
                }
            });

        Panel::bottom("footer").show(ui, |ui| self.footer(ui));

        // draw the main screen
        CentralPanel::default().show(ui, |ui| {
            ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                if let Some(drawn) = self.screen(ui) {
                    event = Some(drawn);
                }
            });
        });

        // if there is an event, apply it.
        if let Some(event) = event {
            self.apply(&ctx, event);
        }

        let mut shell = Shell::new(&ctx, &mut self.route, &mut self.focus, &mut self.status);

        self.settings.poll(&mut shell);

        // don't open a dialog if a prompt is showing.
        if !self.prompts.is_showing() {
            self.settings.dialog(&mut shell);
        }

        if let Some(message) = self.prompts.ui(&ctx) {
            self.status.say(message);
        }
    }

    /// Draws the footer.
    fn footer(&self, ui: &mut Ui) {
        ui.add_space(4.0);
        self.status.ui(ui);

        ui.label(RichText::new("Built in Rust with egui.").weak());
        ui.add_space(4.0);
    }

    /// Draws the screen for a route.
    fn screen(&mut self, ui: &mut Ui) -> Option<Event> {
        let route = self.route;

        self.settings
            .ui(ui, route, &mut self.focus)
            .map(Event::Settings)
    }

    /// Applies an event to the window.
    fn apply(&mut self, ctx: &Context, event: Event) {
        let mut shell = Shell::new(ctx, &mut self.route, &mut self.focus, &mut self.status);
        match event {
            Event::Go(route) => shell.go(route),
            Event::Settings(action) => self.settings.update(&mut shell, action),
        }
    }
}

impl eframe::App for C9sApp {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        self.show(ui);
    }
}
