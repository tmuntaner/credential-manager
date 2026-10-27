/// The GPG error for a canceled dialog.
const GPG_ERR_CANCELED: u32 = 99;

/// The GPG error for a confirmation when the user answered with "no".
const GPG_ERR_NOT_CONFIRMED: u32 = 114;

/// The GPG error for when the user canceled the full operation.
const GPG_ERR_FULLY_CANCELED: u32 = 198;

/// One line sent by the pinentry program.
#[derive(Debug, PartialEq, Eq)]
pub enum Line<'a> {
    /// The command succeeded.
    Ok,
    /// The command failed.
    Err { code: u32, message: &'a str },
    /// Percent-encoded data, still to be decoded with [`decode_into`].
    Data(&'a [u8]),
    /// Status and comment lines, which carry nothing we need.
    Ignored,
    /// The server asks for more data.
    Inquire,
    /// Anything else.
    Unknown,
}

/// What an `ERR` code means to us.
#[derive(Debug, PartialEq, Eq)]
pub enum ErrKind {
    /// The user closed the dialog.
    Cancelled,
    /// The user answered a confirmation with "no".
    NotConfirmed,
    /// Any other failure.
    Other,
}

impl ErrKind {
    /// Classifies a code, ignoring the part that says which GPG component raised it.
    pub fn of(code: u32) -> Self {
        match code & 0xFFFF {
            GPG_ERR_CANCELED | GPG_ERR_FULLY_CANCELED => Self::Cancelled,
            GPG_ERR_NOT_CONFIRMED => Self::NotConfirmed,
            _ => Self::Other,
        }
    }
}

/// Parses a line of assuan output
pub fn parse_line(line: &[u8]) -> Line<'_> {
    // check if the line is "Ok"
    if line == b"OK" || line.starts_with(b"OK ") {
        return Line::Ok;
    }

    // check if the line is data
    if let Some(data) = line.strip_prefix(b"D ") {
        return Line::Data(data);
    }

    // check if the line is an error
    if let Some(rest) = line.strip_prefix(b"ERR ") {
        let rest = std::str::from_utf8(rest).unwrap_or_default();
        let (code, message) = rest.split_once(' ').unwrap_or((rest, ""));
        return match code.parse() {
            Ok(code) => Line::Err { code, message },
            Err(_) => Line::Unknown,
        };
    }

    // informational output from the server that can be ignored
    if line == b"S" || line.starts_with(b"S ") || line.starts_with(b"#") {
        return Line::Ignored;
    }

    // check if the line is an "INQUIRE"
    if line.starts_with(b"INQUIRE") {
        return Line::Inquire;
    }
    Line::Unknown
}

/// Builds an assuan command
pub fn command(name: &str, argument: &str) -> String {
    let mut line = String::with_capacity(name.len() + argument.len() + 2);
    line.push_str(name);
    line.push(' ');
    for c in argument.chars() {
        match c {
            '%' => line.push_str("%25"),
            '\r' => line.push_str("%0D"),
            '\n' => line.push_str("%0A"),
            c => line.push(c),
        }
    }
    line.push('\n');
    line
}

/// Decode the data
pub fn decode_into(data: &[u8], out: &mut Vec<u8>) {
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'%' {
            if let Some(byte) = data.get(i + 1..i + 3).and_then(hex_byte) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(data[i]);
        i += 1;
    }
}

fn hex_byte(hex: &[u8]) -> Option<u8> {
    let [high, low] = hex else {
        return None;
    };
    let digit = |b: u8| (b as char).to_digit(16);
    Some((digit(*high)? * 16 + digit(*low)?) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        decode_into(data, &mut out);
        out
    }

    #[test]
    fn parses_the_kinds_of_line() {
        assert_eq!(parse_line(b"OK"), Line::Ok);
        assert_eq!(parse_line(b"OK Pleased to meet you"), Line::Ok);
        assert_eq!(parse_line(b"D hunter 2"), Line::Data(b"hunter 2"));
        assert_eq!(
            parse_line(b"ERR 83886179 Operation cancelled <Pinentry>"),
            Line::Err {
                code: 83886179,
                message: "Operation cancelled <Pinentry>"
            }
        );
        assert_eq!(parse_line(b"S PASSWORD_FROM_CACHE"), Line::Ignored);
        assert_eq!(parse_line(b"# comment"), Line::Ignored);
        assert_eq!(parse_line(b"INQUIRE QUALITY"), Line::Inquire);
        assert_eq!(parse_line(b"OKAY"), Line::Unknown);
        assert_eq!(parse_line(b"ERR nope"), Line::Unknown);
    }

    #[test]
    fn malformed_server_lines_are_not_trusted() {
        // a code that does not fit, a missing code and bytes that are not UTF-8
        assert_eq!(parse_line(b"ERR 99999999999999999999 x"), Line::Unknown);
        assert_eq!(parse_line(b"ERR "), Line::Unknown);
        assert_eq!(parse_line(b"ERR \xff\xfe"), Line::Unknown);
        // data needs the space, and the reply must start the line
        assert_eq!(parse_line(b"D"), Line::Unknown);
        assert_eq!(parse_line(b" OK"), Line::Unknown);
        assert_eq!(parse_line(b""), Line::Unknown);
    }

    #[test]
    fn a_command_is_always_a_single_line() {
        let line = command("SETDESC", "a\r\nBYE\n%0ABYE");

        assert_eq!(line.matches('\n').count(), 1);
        assert!(line.ends_with('\n'));
        assert!(!line.contains('\r'));
    }

    #[test]
    fn maps_error_codes_regardless_of_their_source() {
        assert_eq!(ErrKind::of(83886179), ErrKind::Cancelled);
        assert_eq!(ErrKind::of(83886194), ErrKind::NotConfirmed);
        assert_eq!(ErrKind::of(99), ErrKind::Cancelled);
        assert_eq!(ErrKind::of(83886278), ErrKind::Cancelled);
        assert_eq!(ErrKind::of(83886142), ErrKind::Other);
    }

    #[test]
    fn escapes_what_would_break_the_line() {
        assert_eq!(
            command("SETDESC", "Wrong PIN\r\n100% sure"),
            "SETDESC Wrong PIN%0D%0A100%25 sure\n"
        );
    }

    #[test]
    fn escaping_and_decoding_round_trip() {
        let text = "a%b\nc d+é\r";
        let line = command("D", text);
        let data = line.strip_prefix("D ").unwrap().trim_end_matches('\n');

        assert_eq!(decode(data.as_bytes()), text.as_bytes());
    }

    #[test]
    fn decodes_escapes_and_keeps_everything_else() {
        assert_eq!(decode(b"a%25b%0Ac+d"), b"a%b\nc+d");
        assert_eq!(decode(b"%c3%A9"), "é".as_bytes());
        assert_eq!(decode(b"50%"), b"50%");
        assert_eq!(decode(b"%zz%4"), b"%zz%4");
    }
}
