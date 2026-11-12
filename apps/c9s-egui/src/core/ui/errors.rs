use super::a11y;
use c9s::app::settings::{Field, SetupError};
use eframe::egui::{Color32, Response, RichText, Ui};
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;

pub trait FieldKey: Copy + Eq + Hash + Debug {}
impl<T: Copy + Eq + Hash + Debug> FieldKey for T {}

/// The errors of a form.
#[derive(Debug)]
pub struct FormErrors<K: FieldKey = Field> {
    /// the errors for the forms fields:
    fields: HashMap<K, String>,
    /// The general error for the form.
    general: Option<String>,
    /// The field which we should focus on for the next frame. It should be the first one with an error.
    focus: Option<K>,
}

impl<K: FieldKey> Default for FormErrors<K> {
    fn default() -> Self {
        Self {
            fields: HashMap::new(),
            general: None,
            focus: None,
        }
    }
}

impl<K: FieldKey> FormErrors<K> {
    /// Set a general error message, e.g., "Wrong password, try again",
    pub fn general(message: impl Into<String>) -> Self {
        Self {
            general: Some(message.into()),
            ..Self::default()
        }
    }

    /// Clear the errors
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// Set an error message for a field.
    pub fn of(&self, field: K) -> Option<&str> {
        self.fields.get(&field).map(String::as_str)
    }

    /// Generate a short summary of the errors for the status line.
    pub fn summary(&self) -> String {
        match (self.fields.len(), &self.general) {
            (0, Some(general)) => general.clone(),
            (1, _) => "1 problem to fix.".to_string(),
            (n, _) => format!("{n} problems to fix."),
        }
    }

    /// True for the field which should take the focus.
    pub fn take_focus(&mut self, field: K) -> bool {
        if self.focus == Some(field) {
            self.focus = None;
            return true;
        }

        false
    }
}

impl FormErrors<Field> {
    /// Sets an error for a form. Errors which cannot be placed in a field are added to the general.
    pub fn set(&mut self, error: SetupError, known: &[Field]) {
        self.clear();

        let mut unplaced = Vec::new();

        for field in error.fields {
            if known.contains(&field.field) {
                self.fields.insert(field.field, field.message);
            } else {
                unplaced.push(field.message);
            }
        }

        self.focus = known.iter().copied().find(|f| self.fields.contains_key(f));
        let general: Vec<String> = error.message.into_iter().chain(unplaced).collect();
        self.general = (!general.is_empty()).then(|| general.join(" "));
    }

    /// Shows an error in the form and returns the status line.
    pub fn fail(&mut self, error: SetupError, known: &[Field]) -> String {
        self.set(error, known);
        self.summary()
    }
}

pub fn error_color(ui: &Ui) -> Color32 {
    ui.visuals().error_fg_color
}

pub fn error_label(ui: &mut Ui, message: &str) -> Response {
    ui.label(
        RichText::new(format!("Error: {message}"))
            .color(error_color(ui))
            .strong(),
    )
}

pub fn general_error<K: FieldKey>(ui: &mut Ui, errors: &FormErrors<K>) {
    if let Some(message) = &errors.general {
        let label = error_label(ui, message);
        a11y::live(ui, &label);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN: [Field; 3] = [Field::IdpName, Field::IdpUrl, Field::IdpUsername];

    fn failing(fields: &[(Field, &str)], message: Option<&str>) -> SetupError {
        let mut error = SetupError::default();
        for (field, text) in fields {
            error.fields.extend(SetupError::field(*field, *text).fields);
        }
        error.message = message.map(str::to_string);
        error
    }

    #[test]
    fn an_error_is_put_under_its_field_and_the_first_gets_the_focus() {
        let mut errors = FormErrors::default();
        let error = failing(&[(Field::IdpUsername, "b"), (Field::IdpUrl, "a")], None);

        errors.set(error, &KNOWN);

        assert_eq!(errors.of(Field::IdpUrl), Some("a"));
        assert_eq!(errors.of(Field::IdpUsername), Some("b"));
        assert_eq!(errors.of(Field::IdpName), None);
        // The first in the order of the form, not of the error.
        assert!(!errors.take_focus(Field::IdpUsername));
        assert!(errors.take_focus(Field::IdpUrl));
        assert!(!errors.take_focus(Field::IdpUrl), "the focus moves once");
    }

    #[test]
    fn an_error_for_a_field_the_form_lacks_is_not_lost() {
        let mut errors = FormErrors::default();
        let error = failing(&[(Field::AwsRegion, "region")], Some("general"));

        errors.set(error, &KNOWN);

        assert_eq!(errors.of(Field::AwsRegion), None);
        assert_eq!(errors.general.as_deref(), Some("general region"));
        assert_eq!(errors.summary(), "general region");
    }

    #[test]
    fn the_summary_counts_the_problems() {
        let mut errors = FormErrors::default();
        assert_eq!(
            errors.fail(failing(&[(Field::IdpName, "x")], None), &KNOWN),
            "1 problem to fix."
        );
        assert_eq!(
            errors.fail(
                failing(&[(Field::IdpName, "x"), (Field::IdpUrl, "y")], None),
                &KNOWN
            ),
            "2 problems to fix."
        );
    }

    #[test]
    fn setting_again_replaces_what_was_there() {
        let mut errors = FormErrors::default();
        errors.set(failing(&[(Field::IdpName, "x")], Some("old")), &KNOWN);

        errors.set(failing(&[(Field::IdpUrl, "y")], None), &KNOWN);

        assert_eq!(errors.of(Field::IdpName), None);
        assert_eq!(errors.general, None);
    }

    #[test]
    fn a_general_error_has_no_field() {
        let errors = FormErrors::<Field>::general("Wrong password");
        assert_eq!(errors.summary(), "Wrong password");
        assert_eq!(errors.of(Field::IdpName), None);
    }
}
