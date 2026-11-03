use super::a11y;
use super::errors::{error_label, FieldKey, FormErrors};
use eframe::egui::{Id, Key, Response, RichText, TextEdit, Ui};

/// The widest an input can get.
pub const INPUT_WIDTH: f32 = 520.0;

/// The options for a text field.
#[derive(Default, Clone, Copy)]
pub struct TextOptions<'a> {
    pub hint: Option<&'a str>,
    pub placeholder: Option<&'a str>,
    pub password: bool,
    /// Take the focus. Set it on the first field, on the first frame of a dialog only.
    pub autofocus: bool,
}

/// The id of an input `field`.
pub fn input_id<K: FieldKey>(field: K) -> Id {
    Id::unique(("field", field))
}

pub fn hint(ui: &mut Ui, text: &str) -> Response {
    ui.label(RichText::new(text).weak())
}

/// Names and describes `input` in the accessibility tree, and shows its error.
pub fn finish_field<K: FieldKey>(
    ui: &mut Ui,
    input: &Response,
    label: &Response,
    hint: Option<&Response>,
    errors: &mut FormErrors<K>,
    field: K,
) {
    let error = errors.of(field).map(|message| error_label(ui, message));

    a11y::describe_input(ui.ctx(), input, label, hint, error.as_ref());

    if errors.take_focus(field) {
        input.request_focus();
    }

    ui.add_space(8.0);
}

/// A one line text field.
pub fn text_field<K: FieldKey>(
    ui: &mut Ui,
    errors: &mut FormErrors<K>,
    field: K,
    label: &str,
    value: &mut String,
    options: TextOptions,
) -> Response {
    let label = ui.label(RichText::new(label).strong());

    let hint = options.hint.map(|text| self::hint(ui, text));

    let mut edit = TextEdit::singleline(value)
        .id(input_id(field))
        .desired_width(INPUT_WIDTH.min(ui.available_width()))
        .password(options.password);

    if let Some(placeholder) = options.placeholder {
        edit = edit.hint_text(placeholder);
    }

    let input = ui.add(edit);

    if options.autofocus {
        input.request_focus();
    }

    finish_field(ui, &input, &label, hint.as_ref(), errors, field);

    input
}

/// Whether Enter was pressed in `input` so we can submit it.
pub fn submitted(input: &Response) -> bool {
    input.lost_focus() && input.ctx.input(|i| i.key_pressed(Key::Enter))
}

/// A fixed field which the user cannot change.
pub fn fixed_field(ui: &mut Ui, label: &str, value: &str, hint_text: &str) {
    ui.label(RichText::new(label).strong());

    ui.label(value);

    hint(ui, hint_text);

    ui.add_space(8.0);
}
