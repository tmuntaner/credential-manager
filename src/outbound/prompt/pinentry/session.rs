use crate::outbound::prompt::pinentry::assuan;
use crate::outbound::prompt::pinentry::assuan::Line;
use crate::outbound::prompt::pinentry::error::PinentryError;
use crate::outbound::prompt::pinentry::models::{Reply, TtyOptions};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{ChildStdin, ChildStdout};
use zeroize::Zeroizing;

/// A conversation with a running pinentry.
pub struct Session {
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl Session {
    pub fn new(stdin: ChildStdin, stdout: ChildStdout) -> Self {
        Self { stdin, stdout }
    }

    /// Waits for a greeting from the pinentry program.
    /// Without a greeting, it didn't start yet.
    pub async fn start(&mut self) -> Result<(), PinentryError> {
        match self.reply().await {
            Ok(Reply::Ok(_)) => Ok(()),
            Ok(Reply::Err { message, .. }) => Err(PinentryError::NotStarted(message)),
            Err(e) => Err(PinentryError::NotStarted(e.to_string())),
        }
    }

    /// Sets the tty options.
    pub async fn options(&mut self, tty: Option<&TtyOptions>) -> Result<(), PinentryError> {
        // set the no-grab option for the pinentry programs that support it.
        self.send("OPTION", "no-grab").await?;

        // if there are no options, just return early
        let Some(tty) = tty else {
            return Ok(());
        };

        // send the options to the pinentry program
        for (name, value) in [
            ("ttyname", &tty.ttyname),
            ("ttytype", &tty.ttytype),
            ("lc-ctype", &tty.lc_ctype),
        ] {
            if let Some(value) = value {
                self.send("OPTION", &format!("{name}={value}")).await?;
            }
        }
        Ok(())
    }

    /// Sends a set command to the pinentry program.
    pub async fn set(&mut self, name: &str, argument: &str) -> Result<(), PinentryError> {
        match self.send(name, argument).await? {
            Reply::Ok(_) => Ok(()),
            Reply::Err { message, .. } => Err(PinentryError::Command(message)),
        }
    }

    /// sends a command to the pinentry program.
    pub async fn send(&mut self, name: &str, argument: &str) -> Result<Reply, PinentryError> {
        let line = if argument.is_empty() {
            // if there is no argument, ensure there is a line ending afterward to end it.
            format!("{name}\n")
        } else {
            assuan::command(name, argument)
        };

        log::debug!("pinentry <- {name}");
        self.stdin.write_all(line.as_bytes()).await?;
        self.stdin.flush().await?;
        self.reply().await
    }

    /// Sends a goodbye message.
    /// We don't care about errors because we already sent a message and recieved the result.
    pub async fn bye(&mut self) {
        let _ = self.send("BYE", "").await;
    }

    /// Reads the incoming lines up to `OK` and `ERR`, which both end the reply.
    /// The data is collected in the reply stream.
    async fn reply(&mut self) -> Result<Reply, PinentryError> {
        let mut data = Zeroizing::new(Vec::new());

        loop {
            let line = self.read_line().await?;

            match assuan::parse_line(&line) {
                Line::Ok => return Ok(Reply::Ok(data)),
                Line::Err { code, message } => {
                    log::debug!("pinentry -> ERR {code} {message}");
                    return Ok(Reply::Err {
                        code,
                        message: message.to_string(),
                    });
                }
                Line::Data(chunk) => assuan::decode_into(chunk, &mut data),
                Line::Ignored => {}
                Line::Inquire => {
                    return Err(PinentryError::Protocol("an inquiry".to_string()));
                }
                Line::Unknown => {
                    return Err(PinentryError::Protocol(
                        String::from_utf8_lossy(&line).into_owned(),
                    ));
                }
            }
        }
    }

    /// Reads one line from the pinentry program.
    async fn read_line(&mut self) -> Result<Zeroizing<Vec<u8>>, PinentryError> {
        let mut line = Zeroizing::new(Vec::new());

        loop {
            match self.stdout.read_u8().await {
                Ok(b'\n') => break,
                Ok(byte) => line.push(byte),
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    return Err(PinentryError::Exited(String::new()))
                }
                Err(e) => return Err(e.into()),
            }
        }

        if line.last() == Some(&b'\r') {
            line.pop();
        }

        Ok(line)
    }
}
