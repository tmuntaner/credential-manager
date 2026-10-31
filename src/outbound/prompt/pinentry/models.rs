use zeroize::Zeroizing;

/// Tells a pinentry that draws on the terminal which one to use.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct TtyOptions {
    /// Path of the terminal device, e.g. `/dev/pts/3`.
    pub ttyname: Option<String>,
    /// The `TERM` of the terminal.
    pub ttytype: Option<String>,
    /// The locale character type of the terminal, e.g. `en_US.UTF-8`.
    pub lc_ctype: Option<String>,
}

/// The result of one command.
pub enum Reply {
    /// The command succeeded, with the data of the reply.
    Ok(Zeroizing<Vec<u8>>),
    /// The command failed.
    Err {
        /// The Assuan error code.
        code: u32,
        /// The message of the error.
        message: String,
    },
}
