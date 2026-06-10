/// PAM module configuration parsed from module arguments.
pub struct ModuleConfig {
    pub debug: bool,
    pub enable_closed_lid: bool,
    pub modules: Vec<String>,
    pub timeout_secs: u64,
    pub max_tries: u32,
}

impl ModuleConfig {
    pub fn from_pam_args(args: &[String]) -> Self {
        let mut config = Self {
            debug: false,
            enable_closed_lid: false,
            modules: vec!["fprint".to_string(), "pass".to_string()],
            timeout_secs: 60,
            max_tries: 3,
        };

        for arg in args {
            match arg.as_str() {
                "debug" => config.debug = true,
                "enable_closed_lid" => config.enable_closed_lid = true,
                _ if arg.starts_with("modules=") => {
                    let val = &arg["modules=".len()..];
                    config.modules = val.split(',').map(|s| s.trim().to_string()).collect();
                }
                _ if arg.starts_with("timeout=") => {
                    let val = &arg["timeout=".len()..];
                    if let Ok(t) = val.parse::<u64>() {
                        config.timeout_secs = t;
                    }
                }
                _ if arg.starts_with("max_tries=") => {
                    let val = &arg["max_tries=".len()..];
                    if let Ok(t) = val.parse::<u32>() {
                        if t >= 1 {
                            config.max_tries = t;
                        }
                    }
                }
                _ => {}
            }
        }

        config
    }
}
