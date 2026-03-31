pub mod fprint;
pub mod password;

use std::future::Future;
use std::pin::Pin;

use tokio_util::sync::CancellationToken;

/// Result of an authentication attempt from a backend.
pub enum AuthOutcome {
    /// Authentication succeeded.
    /// For password backend, contains the entered password.
    /// For fingerprint backend, password is None.
    Success { password: Option<String> },
    /// Authentication failed (wrong fingerprint, empty password, etc.)
    Failed,
    /// Backend is unavailable (no reader, no enrolled fingers, etc.)
    /// This is not an error — the orchestrator simply skips this backend.
    Unavailable(String),
}

/// Trait for authentication backends.
///
/// To add a new backend (e.g., YubiKey, smartcard):
/// 1. Create a new module file (e.g., `backend/yubikey.rs`)
/// 2. Implement `AuthBackend` for your type
/// 3. Register it in the orchestrator's backend builder
#[allow(dead_code)]
pub trait AuthBackend: Send + Sync {
    /// Human-readable name for logging (e.g., "fprint", "password")
    fn name(&self) -> &str;

    /// Run the authentication attempt.
    /// Must respect the cancellation token and return promptly when cancelled.
    fn authenticate<'a>(
        &'a self,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = AuthOutcome> + Send + 'a>>;

    /// Cancel/cleanup: called when another backend won the race.
    fn cancel<'a>(&'a self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}
