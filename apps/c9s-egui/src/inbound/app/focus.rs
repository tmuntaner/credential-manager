use super::nav::{Route, Section};
use c9s::app::settings::AwsAppKey;
use eframe::egui::Response;

/// A widget that the user can focus on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FocusTarget {
    /// A navigation bar button.
    Nav(Route),
    /// A button for finishing the onboarding process.
    FinishOnBoarding,
    /// A button to add something
    Add(Section),
    /// The Edit button for an identity provider with the name of the provider.
    Idp(String),
    /// The Edit button for an AWS app with the name of the app.
    AwsApp(AwsAppKey),
    /// The Edit button for a Rancher with the name of the cluster.
    Rancher(String),
}

#[derive(Default)]
pub struct Focus(Option<FocusTarget>);

impl Focus {
    pub fn set(&mut self, target: FocusTarget) {
        self.0 = Some(target);
    }

    /// If the focus is the same as the `FocusTarget`, set its value to None and return true
    fn take(&mut self, target: &FocusTarget) -> bool {
        // sees if the Focus's target exists and if it's the same value, set the Focus's target to None and return true
        if self.0.as_ref() == Some(target) {
            self.0 = None;
            return true;
        }

        false
    }

    /// If the target is the value of the Focus's target, have it request focus.
    pub fn apply(&mut self, target: FocusTarget, response: &Response) {
        if self.take(&target) {
            response.request_focus();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use c9s::app::settings::AwsAppType;

    #[test]
    fn the_focus_goes_to_the_target_once() {
        let mut focus = Focus::default();
        focus.set(FocusTarget::Idp("work".into()));

        assert!(!focus.take(&FocusTarget::Idp("lab".into())));
        assert!(!focus.take(&FocusTarget::Add(Section::Idp)));
        assert!(focus.take(&FocusTarget::Idp("work".into())));
        assert!(!focus.take(&FocusTarget::Idp("work".into())));
    }

    #[test]
    fn a_later_target_replaces_the_earlier() {
        let mut focus = Focus::default();
        focus.set(FocusTarget::Nav(Route::Setup));
        focus.set(FocusTarget::AwsApp(AwsAppKey {
            app_url: "https://a".into(),
            kind: AwsAppType::Aws,
        }));

        assert!(!focus.take(&FocusTarget::Nav(Route::Setup)));
        assert!(focus.take(&FocusTarget::AwsApp(AwsAppKey {
            app_url: "https://a".into(),
            kind: AwsAppType::Aws,
        })));
    }

    #[test]
    fn the_same_url_of_another_kind_is_another_target() {
        let key = |kind| {
            FocusTarget::AwsApp(AwsAppKey {
                app_url: "https://a".into(),
                kind,
            })
        };
        let mut focus = Focus::default();
        focus.set(key(AwsAppType::AwsSso));

        assert!(!focus.take(&key(AwsAppType::Aws)));
        assert!(focus.take(&key(AwsAppType::AwsSso)));
    }
}
