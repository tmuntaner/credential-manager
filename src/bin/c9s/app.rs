use c9s::domain::models::settings::AppConfig;
use c9s::domain::ports::notifier::Notifier;
use c9s::domain::ports::user_interaction::UserInteraction;
use c9s::domain::services::settings_editor::SettingsService;
use std::sync::Arc;

#[derive(Clone)]
pub struct CliApplication {
    config: AppConfig,
    settings: SettingsService,
    interaction: Arc<dyn UserInteraction + Send + Sync>,
    notifier: Arc<dyn Notifier + Send + Sync>,
}

impl CliApplication {
    pub fn new(
        config: AppConfig,
        settings: SettingsService,
        interaction: Arc<dyn UserInteraction + Send + Sync>,
        notifier: Arc<dyn Notifier + Send + Sync>,
    ) -> Self {
        Self {
            config,
            settings,
            interaction,
            notifier,
        }
    }

    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    pub fn settings_service(&self) -> &SettingsService {
        &self.settings
    }

    pub fn interaction(&self) -> Arc<dyn UserInteraction + Send + Sync> {
        self.interaction.clone()
    }

    pub fn notifier(&self) -> Arc<dyn Notifier + Send + Sync> {
        self.notifier.clone()
    }
}
