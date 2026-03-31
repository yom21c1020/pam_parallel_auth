mod backend;
mod config;
mod dbus_helpers;
mod logging;
mod orchestrator;

use std::time::Duration;

use pamsm::{pam_module, Pam, PamError, PamFlags, PamServiceModule};

use config::ModuleConfig;

struct PamParallelAuth;

impl PamServiceModule for PamParallelAuth {
    fn authenticate(pamh: Pam, _flags: PamFlags, args: Vec<String>) -> PamError {
        let config = ModuleConfig::from_pam_args(&args);

        // Create a tokio runtime for this authentication call.
        // A new runtime per call is the safest approach for a cdylib.
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(_) => return PamError::SYSTEM_ERR,
        };

        let result = rt.block_on(async {
            orchestrator::run_auth(&pamh, &config).await
        });

        // Shut down the runtime with a timeout to clean up any lingering
        // blocking threads (e.g., pam_conv waiting for input after fprint won).
        rt.shutdown_timeout(Duration::from_millis(500));

        result
    }
}

pam_module!(PamParallelAuth);
