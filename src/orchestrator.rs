use std::ffi::CString;
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};
use pamsm::{Pam, PamError, PamLibExt};
use tokio_util::sync::CancellationToken;

use crate::backend::{AuthBackend, AuthOutcome};
use crate::backend::fprint::FprintBackend;
use crate::backend::password::PasswordBackend;
use crate::config::ModuleConfig;
use crate::logging::debug_log;

/// Main authentication entry point called from lib.rs within block_on().
pub async fn run_auth(pamh: &Pam, config: &ModuleConfig) -> PamError {
    // Get the username
    let user = match pamh.get_user(None) {
        Ok(Some(u)) => match u.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return PamError::USER_UNKNOWN,
        },
        _ => return PamError::USER_UNKNOWN,
    };

    debug_log!(pamh, config, "pam_parallel_auth: authenticating user '{}'", user);

    // Build list of active backends based on config.modules
    let mut backends: Vec<Box<dyn AuthBackend>> = Vec::new();

    if config.modules.contains(&"fprint".to_string()) {
        match FprintBackend::new(&user, config).await {
            Ok(fb) => {
                debug_log!(pamh, config, "pam_parallel_auth: fprint backend ready");
                backends.push(Box::new(fb));
            }
            Err(reason) => {
                debug_log!(pamh, config, "pam_parallel_auth: fprint unavailable: {}", reason);
            }
        }
    }

    if config.modules.contains(&"pass".to_string()) {
        // SAFETY: pamh lives on the caller's stack and block_on() won't return
        // until this future completes, so the raw pointer remains valid.
        let pb = unsafe { PasswordBackend::new(pamh, config.debug) };
        backends.push(Box::new(pb));
        debug_log!(pamh, config, "pam_parallel_auth: password backend ready");
    }

    if backends.is_empty() {
        debug_log!(pamh, config, "pam_parallel_auth: no backends available");
        return PamError::AUTH_ERR;
    }

    // Single backend: run directly
    if backends.len() == 1 {
        let backend = &backends[0];
        debug_log!(pamh, config, "pam_parallel_auth: single backend mode ({})", backend.name());
        let cancel = CancellationToken::new();
        let outcome = backend.authenticate(cancel).await;
        return handle_outcome(pamh, &outcome, config);
    }

    // Multiple backends: race them
    debug_log!(pamh, config, "pam_parallel_auth: racing {} backends", backends.len());
    race_backends(pamh, &backends, config).await
}

/// Race multiple backends using FuturesUnordered. First success wins.
async fn race_backends(
    pamh: &Pam,
    backends: &[Box<dyn AuthBackend>],
    config: &ModuleConfig,
) -> PamError {
    let cancel = CancellationToken::new();
    let timeout_duration = Duration::from_secs(config.timeout_secs);

    let futures: FuturesUnordered<_> = backends
        .iter()
        .enumerate()
        .map(|(i, backend)| {
            let cancel = cancel.clone();
            async move {
                let outcome = backend.authenticate(cancel).await;
                (i, outcome)
            }
        })
        .collect();

    tokio::pin!(futures);

    let result = tokio::time::timeout(timeout_duration, async {
        while let Some((idx, outcome)) = futures.next().await {
            let name = backends[idx].name();
            match &outcome {
                AuthOutcome::Success { .. } => {
                    debug_log!(pamh, config, "pam_parallel_auth: {} succeeded", name);
                    cancel.cancel();
                    // Drain remaining futures to allow cleanup (VerifyStop etc.)
                    drain_remaining(&mut futures).await;
                    return handle_outcome(pamh, &outcome, config);
                }
                AuthOutcome::Failed => {
                    debug_log!(pamh, config, "pam_parallel_auth: {} failed", name);
                }
                AuthOutcome::Unavailable(reason) => {
                    debug_log!(pamh, config, "pam_parallel_auth: {} unavailable: {}", name, reason);
                }
            }
        }
        debug_log!(pamh, config, "pam_parallel_auth: all backends failed");
        PamError::AUTH_ERR
    })
    .await;

    match result {
        Ok(pam_err) => pam_err,
        Err(_) => {
            debug_log!(pamh, config, "pam_parallel_auth: timeout after {}s", config.timeout_secs);
            cancel.cancel();
            drain_remaining(&mut futures).await;
            PamError::AUTH_ERR
        }
    }
}

/// Drain remaining futures after cancellation to allow cleanup.
async fn drain_remaining<S: futures_util::Stream + Unpin>(stream: &mut S) {
    let _ = tokio::time::timeout(Duration::from_millis(200), async {
        while stream.next().await.is_some() {}
    })
    .await;
}

/// Convert an AuthOutcome to a PamError, storing password in PAM_AUTHTOK if needed.
///
/// Return values:
/// - Fingerprint success → PAM_SUCCESS (auth complete, skip downstream modules)
/// - Password entered → PAM_IGNORE (AUTHTOK stored, let pam_unix verify)
/// - Failed → PAM_AUTH_ERR
/// - Unavailable → PAM_AUTHINFO_UNAVAIL
fn handle_outcome(pamh: &Pam, outcome: &AuthOutcome, config: &ModuleConfig) -> PamError {
    match outcome {
        AuthOutcome::Success { password } => {
            if let Some(pwd) = password {
                // Password entered: store in PAM_AUTHTOK for pam_unix to verify.
                // Return IGNORE so the PAM stack continues to the next module.
                let cstr = match CString::new(pwd.as_str()) {
                    Ok(c) => c,
                    Err(_) => {
                        debug_log!(pamh, config, "pam_parallel_auth: password contains null byte");
                        return PamError::SYSTEM_ERR;
                    }
                };
                if let Err(e) = pamh.set_authtok(&cstr) {
                    debug_log!(pamh, config, "pam_parallel_auth: set_authtok failed: {:?}", e);
                    return PamError::SYSTEM_ERR;
                }
                debug_log!(pamh, config, "pam_parallel_auth: password stored in PAM_AUTHTOK, deferring to pam_unix");
                PamError::IGNORE
            } else {
                // Fingerprint success: auth is complete, no password needed.
                debug_log!(pamh, config, "pam_parallel_auth: fingerprint auth succeeded");
                PamError::SUCCESS
            }
        }
        AuthOutcome::Failed => PamError::AUTH_ERR,
        AuthOutcome::Unavailable(_) => PamError::AUTHINFO_UNAVAIL,
    }
}
