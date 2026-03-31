use std::future::Future;
use std::pin::Pin;

use tokio_util::sync::CancellationToken;

use super::{AuthBackend, AuthOutcome};
use crate::logging::syslog_debug;

/// Password authentication backend using pam_conv.
///
/// Stores the PAM handle address as usize to allow sending across threads.
/// SAFETY: The raw pointer is valid for the duration of block_on() in lib.rs,
/// and authenticate() is always awaited within that block_on() call.
pub struct PasswordBackend {
    pam_addr: usize,
    debug: bool,
}

// SAFETY: We guarantee the Pam handle outlives all uses of PasswordBackend
// because it lives on the stack in pam_sm_authenticate and block_on() doesn't
// return until all tasks complete.
unsafe impl Send for PasswordBackend {}
unsafe impl Sync for PasswordBackend {}

impl PasswordBackend {
    /// Create a new password backend.
    ///
    /// SAFETY: The caller must ensure `pamh` outlives this backend.
    /// This is guaranteed by the block_on() pattern in lib.rs.
    pub unsafe fn new(pamh: &pamsm::Pam, debug: bool) -> Self {
        Self {
            pam_addr: pamh as *const pamsm::Pam as usize,
            debug,
        }
    }

    async fn do_authenticate(&self, cancel: CancellationToken) -> AuthOutcome {
        let pam_addr = self.pam_addr;
        let debug = self.debug;

        let (tx, rx) = tokio::sync::oneshot::channel();

        // Spawn an OS thread for the blocking pam_conv call.
        // We use std::thread::spawn (not tokio::spawn_blocking) because
        // pam_conv may block indefinitely waiting for user input, and we
        // don't want to tie up the tokio blocking thread pool.
        std::thread::spawn(move || {
            syslog_debug(debug, "password: calling pam_conv");

            // SAFETY: pam_addr was created from a valid &Pam reference in new(),
            // and pamh lives on the stack for the duration of block_on() in lib.rs.
            let pamh = unsafe { &*(pam_addr as *const pamsm::Pam) };

            use pamsm::PamLibExt;
            let result = pamh.conv(
                Some("Password: "),
                pamsm::PamMsgStyle::PROMPT_ECHO_OFF,
            );

            let outcome = match result {
                Ok(Some(password_cstr)) => {
                    let pwd = password_cstr.to_str().unwrap_or("").to_string();
                    if pwd.is_empty() {
                        syslog_debug(debug, "password: pam_conv returned empty string");
                        AuthOutcome::Failed
                    } else {
                        syslog_debug(debug, "password: pam_conv returned password");
                        AuthOutcome::Success {
                            password: Some(pwd),
                        }
                    }
                }
                Ok(None) => {
                    syslog_debug(debug, "password: pam_conv returned Ok(None)");
                    AuthOutcome::Failed
                }
                Err(e) => {
                    syslog_debug(debug, &format!("password: pam_conv error: {:?}", e));
                    AuthOutcome::Failed
                }
            };

            let _ = tx.send(outcome);
        });

        // Wait for either password input or cancellation
        tokio::select! {
            _ = cancel.cancelled() => {
                syslog_debug(self.debug, "password: cancelled");
                AuthOutcome::Failed
            }
            result = rx => {
                match result {
                    Ok(outcome) => outcome,
                    Err(_) => {
                        syslog_debug(self.debug, "password: channel recv error (thread panicked?)");
                        AuthOutcome::Failed
                    }
                }
            }
        }
    }
}

impl AuthBackend for PasswordBackend {
    fn name(&self) -> &str {
        "password"
    }

    fn authenticate<'a>(
        &'a self,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = AuthOutcome> + Send + 'a>> {
        Box::pin(self.do_authenticate(cancel))
    }

    fn cancel<'a>(&'a self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }
}
