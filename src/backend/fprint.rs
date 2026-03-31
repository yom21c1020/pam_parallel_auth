use futures_util::StreamExt;
use tokio_util::sync::CancellationToken;
use zbus::message::Type as MessageType;
use zbus::{Connection, MatchRule, MessageStream};
use zbus::zvariant::OwnedObjectPath;

use std::future::Future;
use std::pin::Pin;

use super::{AuthBackend, AuthOutcome};
use crate::config::ModuleConfig;
use crate::dbus_helpers;
use crate::logging::syslog_debug;

pub struct FprintBackend {
    device_path: OwnedObjectPath,
    connection: Connection,
    username: String,
    debug: bool,
}

impl FprintBackend {
    /// Create a new fprint backend. Returns Err(reason) if fingerprint auth
    /// is not available (no device, no enrolled fingers, lid closed, etc.)
    pub async fn new(username: &str, config: &ModuleConfig) -> Result<Self, String> {
        // Check lid state unless enable_closed_lid is set
        if !config.enable_closed_lid {
            match dbus_helpers::is_lid_closed().await {
                Ok(true) => return Err("lid is closed".to_string()),
                Ok(false) => {}
                Err(_) => {} // Can't check lid state, proceed anyway
            }
        }

        let connection = Connection::system()
            .await
            .map_err(|e| format!("D-Bus connection failed: {e}"))?;

        // Get default fingerprint device
        let reply = connection
            .call_method(
                Some("net.reactivated.Fprint"),
                "/net/reactivated/Fprint/Manager",
                Some("net.reactivated.Fprint.Manager"),
                "GetDefaultDevice",
                &(),
            )
            .await
            .map_err(|e| format!("no fprint device: {e}"))?;

        let device_path: OwnedObjectPath = reply
            .body()
            .deserialize()
            .map_err(|e| format!("bad device path: {e}"))?;

        syslog_debug(config.debug, &format!("fprint: device path = {}", device_path));

        // Check if user has enrolled fingers
        let enrolled = connection
            .call_method(
                Some("net.reactivated.Fprint"),
                &device_path,
                Some("net.reactivated.Fprint.Device"),
                "ListEnrolledFingers",
                &(username,),
            )
            .await;

        match enrolled {
            Ok(reply) => {
                let fingers: Vec<String> = reply.body().deserialize().unwrap_or_default();
                if fingers.is_empty() {
                    return Err("no enrolled fingers".to_string());
                }
                syslog_debug(config.debug, &format!("fprint: enrolled fingers: {:?}", fingers));
            }
            Err(e) => return Err(format!("cannot list enrolled fingers: {e}")),
        }

        Ok(Self {
            device_path,
            connection,
            username: username.to_string(),
            debug: config.debug,
        })
    }

    async fn do_authenticate(&self, cancel: CancellationToken) -> AuthOutcome {
        // Claim the device
        syslog_debug(self.debug, "fprint: claiming device");
        if let Err(e) = self
            .connection
            .call_method(
                Some("net.reactivated.Fprint"),
                &self.device_path,
                Some("net.reactivated.Fprint.Device"),
                "Claim",
                &(&self.username,),
            )
            .await
        {
            syslog_debug(self.debug, &format!("fprint: claim failed: {e}"));
            return AuthOutcome::Unavailable(format!("claim failed: {e}"));
        }
        syslog_debug(self.debug, "fprint: device claimed");

        // Subscribe to VerifyStatus signal BEFORE calling VerifyStart.
        // Don't filter by sender — zbus local matching may fail to resolve
        // the well-known name to the unique bus name.
        let rule = MatchRule::builder()
            .msg_type(MessageType::Signal)
            .path(self.device_path.as_str())
            .unwrap()
            .interface("net.reactivated.Fprint.Device")
            .unwrap()
            .member("VerifyStatus")
            .unwrap()
            .build();

        syslog_debug(self.debug, "fprint: subscribing to VerifyStatus signal");
        let mut stream = match MessageStream::for_match_rule(rule, &self.connection, None).await {
            Ok(stream) => stream,
            Err(e) => {
                syslog_debug(self.debug, &format!("fprint: signal subscription failed: {e}"));
                self.release().await;
                return AuthOutcome::Failed;
            }
        };
        syslog_debug(self.debug, "fprint: signal subscription ready");

        // Start verification
        syslog_debug(self.debug, "fprint: calling VerifyStart");
        if let Err(e) = self
            .connection
            .call_method(
                Some("net.reactivated.Fprint"),
                &self.device_path,
                Some("net.reactivated.Fprint.Device"),
                "VerifyStart",
                &("any",),
            )
            .await
        {
            syslog_debug(self.debug, &format!("fprint: VerifyStart failed: {e}"));
            self.release().await;
            return AuthOutcome::Failed;
        }
        syslog_debug(self.debug, "fprint: VerifyStart succeeded, waiting for finger...");

        // Wait for VerifyStatus signal or cancellation
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    syslog_debug(self.debug, "fprint: cancelled");
                    self.stop_and_release().await;
                    return AuthOutcome::Failed;
                }
                msg = stream.next() => {
                    match msg {
                        Some(Ok(msg)) => {
                            let body = msg.body();
                            if let Ok((result, done)) = body.deserialize::<(String, bool)>() {
                                syslog_debug(self.debug, &format!("fprint: VerifyStatus signal: result={}, done={}", result, done));
                                match result.as_str() {
                                    "verify-match" => {
                                        self.stop_and_release().await;
                                        return AuthOutcome::Success { password: None };
                                    }
                                    "verify-no-match" => {
                                        self.stop_and_release().await;
                                        return AuthOutcome::Failed;
                                    }
                                    "verify-retry-scan"
                                    | "verify-swipe-too-short"
                                    | "verify-finger-not-centered"
                                    | "verify-remove-and-retry" => {
                                        continue;
                                    }
                                    _ => {
                                        syslog_debug(self.debug, &format!("fprint: unknown status '{}', treating as failure", result));
                                        self.stop_and_release().await;
                                        return AuthOutcome::Failed;
                                    }
                                }
                            } else {
                                syslog_debug(self.debug, "fprint: failed to deserialize VerifyStatus body");
                            }
                        }
                        Some(Err(e)) => {
                            syslog_debug(self.debug, &format!("fprint: stream error: {e}"));
                            self.stop_and_release().await;
                            return AuthOutcome::Failed;
                        }
                        None => {
                            syslog_debug(self.debug, "fprint: stream ended unexpectedly");
                            self.stop_and_release().await;
                            return AuthOutcome::Failed;
                        }
                    }
                }
            }
        }
    }

    async fn stop_and_release(&self) {
        syslog_debug(self.debug, "fprint: stopping and releasing device");
        let _ = self
            .connection
            .call_method(
                Some("net.reactivated.Fprint"),
                &self.device_path,
                Some("net.reactivated.Fprint.Device"),
                "VerifyStop",
                &(),
            )
            .await;
        self.release().await;
    }

    async fn release(&self) {
        let _ = self
            .connection
            .call_method(
                Some("net.reactivated.Fprint"),
                &self.device_path,
                Some("net.reactivated.Fprint.Device"),
                "Release",
                &(),
            )
            .await;
    }
}

impl AuthBackend for FprintBackend {
    fn name(&self) -> &str {
        "fprint"
    }

    fn authenticate<'a>(
        &'a self,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = AuthOutcome> + Send + 'a>> {
        Box::pin(self.do_authenticate(cancel))
    }

    fn cancel<'a>(&'a self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(self.stop_and_release())
    }
}
