use super::errors::{FieldKey, FormErrors};
use super::field::{finish_field, hint, INPUT_WIDTH};
use c9s::app::settings::MfaChoice;
use eframe::egui::{ComboBox, Response, RichText, Ui};

/// A select of list of `options`.
pub fn select<K: FieldKey, T: PartialEq + Clone>(
    ui: &mut Ui,
    errors: &mut FormErrors<K>,
    field: K,
    label: &str,
    hint_text: Option<&str>,
    value: &mut T,
    options: &[(T, String)],
) -> Response {
    let label = ui.label(RichText::new(label).strong());

    let hint = hint_text.map(|text| hint(ui, text));

    let selected = options
        .iter()
        .find(|(v, _)| v == value)
        .map(|(_, text)| text.clone())
        .unwrap_or_default();

    let response = ComboBox::from_id_salt(("field", field))
        .width(INPUT_WIDTH.min(ui.available_width()))
        .selected_text(selected)
        .show_ui(ui, |ui| {
            for (option, text) in options {
                ui.selectable_value(value, option.clone(), text);
            }
        })
        .response;

    finish_field(ui, &response, &label, hint.as_ref(), errors, field);

    response
}

/// The MFA options.
pub fn mfa_options(security_key: bool) -> Vec<(MfaChoice, String)> {
    let mut options = vec![
        (MfaChoice::Ask, "Ask me every time".to_string()),
        (
            MfaChoice::Totp,
            "Code from an authenticator app".to_string(),
        ),
    ];

    if security_key {
        options.push((MfaChoice::SecurityKey, "Security key (YubiKey)".to_string()));
    }

    options
}

pub fn mfa_override_options(security_key: bool) -> Vec<(Option<MfaChoice>, String)> {
    let mut options = vec![(None, "Same as the identity provider".to_string())];

    options.extend(
        mfa_options(security_key)
            .into_iter()
            .filter(|(choice, _)| *choice != MfaChoice::Ask)
            .map(|(choice, text)| (Some(choice), text)),
    );

    options
}

pub fn mfa_label(choice: MfaChoice) -> &'static str {
    match choice {
        MfaChoice::Ask => "Ask every time",
        MfaChoice::Totp => "Code from an authenticator app",
        MfaChoice::SecurityKey => "Security key (YubiKey)",
    }
}

/// The identity providers an app can use. An app always names one.
pub fn idp_options(names: &[String], current: &str) -> Vec<(String, String)> {
    let mut options: Vec<(String, String)> = names
        .iter()
        .map(|name| (name.clone(), name.clone()))
        .collect();

    // An entry may have one that is missing. Keep it, so an edit does not silently change it.
    if !current.is_empty() && !names.iter().any(|n| n == current) {
        options.push((current.to_string(), format!("{current} (missing)")));
    }

    options
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values<T: Clone>(options: &[(T, String)]) -> Vec<T> {
        options.iter().map(|(v, _)| v.clone()).collect()
    }

    #[test]
    fn a_security_key_is_offered_only_where_it_works() {
        assert_eq!(
            values(&mfa_options(true)),
            [MfaChoice::Ask, MfaChoice::Totp, MfaChoice::SecurityKey]
        );
        assert_eq!(
            values(&mfa_options(false)),
            [MfaChoice::Ask, MfaChoice::Totp]
        );
    }

    #[test]
    fn an_override_starts_with_the_choice_of_the_idp_and_never_asks() {
        let options = values(&mfa_override_options(true));
        assert_eq!(
            options,
            [None, Some(MfaChoice::Totp), Some(MfaChoice::SecurityKey)]
        );
        assert_eq!(
            values(&mfa_override_options(false)),
            [None, Some(MfaChoice::Totp)]
        );
    }

    #[test]
    fn every_idp_is_an_option_and_there_is_no_default_entry() {
        let names = ["work".to_string(), "lab".to_string()];

        assert_eq!(values(&idp_options(&names, "work")), ["work", "lab"]);
        assert!(idp_options(&[], "").is_empty());
    }

    #[test]
    fn an_idp_that_is_gone_is_kept_and_marked() {
        let names = ["work".to_string()];

        let options = idp_options(&names, "old");

        assert_eq!(
            options.last().unwrap(),
            &("old".to_string(), "old (missing)".to_string())
        );
        // One that is there is not listed twice.
        assert_eq!(idp_options(&names, "work").len(), 1);
    }
}
