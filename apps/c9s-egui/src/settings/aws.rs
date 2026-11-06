//! AWS accounts: the AWS applications in the identity provider, with Edit and Remove.

use super::dialogs::{Removal, RemoveDialog};
use super::{signs_in_with, SettingsAction};
use crate::app::{Focus, FocusTarget, Section};
use crate::ui::card::{card, card_button, card_header};
use c9s::app::settings::{AwsAppKey, AwsAppKind, AwsAppSummary, SettingsView};
use eframe::egui::Ui;

pub fn ui(ui: &mut Ui, view: &SettingsView, focus: &mut Focus) -> Option<SettingsAction> {
    card_header(
        ui,
        "AWS accounts",
        "The AWS tiles in your identity provider. Each one gives access to one or more AWS accounts.",
    );

    let mut action = None;

    if view.aws_apps.is_empty() {
        ui.label("No AWS account yet.");
    }

    for app in &view.aws_apps {
        if let Some(a) = app_entry(ui, app, focus) {
            action = Some(a);
        }
        ui.add_space(8.0);
    }

    let add = ui.button("Add AWS account");
    focus.apply(FocusTarget::Add(Section::Aws), &add);
    if add.clicked() {
        action = Some(SettingsAction::AddAws);
    }

    action
}

fn app_entry(ui: &mut Ui, app: &AwsAppSummary, focus: &mut Focus) -> Option<SettingsAction> {
    let title = aws_title(app);
    let key = AwsAppKey {
        app_url: app.app_url.clone(),
        kind: app.kind,
    };

    let details = [
        app.app_url.clone(),
        signs_in_with(&app.idp, app.username.as_deref(), app.mfa),
    ];

    card(ui, &title, &[], &details, |ui| {
        let edit = card_button(ui, "Edit", &app.app_url);
        focus.apply(FocusTarget::AwsApp(key.clone()), &edit);
        if edit.clicked() {
            return Some(SettingsAction::EditAws(app.clone()));
        }

        if card_button(ui, "Remove", &app.app_url).clicked() {
            return Some(SettingsAction::Remove(RemoveDialog::new(
                Removal::AwsApp(key.clone()),
                "Remove this AWS account?",
                format!("c9s will no longer use {title} at {}.", app.app_url),
                "AWS account removed.",
            )));
        }
        None
    })
}

fn aws_title(app: &AwsAppSummary) -> String {
    let kind = match app.kind {
        AwsAppKind::Aws => "AWS with IAM roles",
        AwsAppKind::AwsSso => "AWS IAM Identity Center",
    };
    match &app.region {
        Some(region) => format!("{kind} ({region})"),
        None => kind.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_aws_app_is_titled_by_kind_and_region() {
        let mut app = AwsAppSummary {
            app_url: "https://a".into(),
            kind: AwsAppKind::Aws,
            region: None,
            idp: "work".into(),
            username: None,
            mfa: None,
        };
        assert_eq!(aws_title(&app), "AWS with IAM roles");
        app.kind = AwsAppKind::AwsSso;
        app.region = Some("eu-west-1".into());
        assert_eq!(aws_title(&app), "AWS IAM Identity Center (eu-west-1)");
    }
}
