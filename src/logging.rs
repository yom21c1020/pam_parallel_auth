/// Log a debug message to syslog via PAM, only when debug=true.
macro_rules! debug_log {
    ($pamh:expr, $config:expr, $($arg:tt)*) => {
        if $config.debug {
            $crate::logging::pam_syslog($pamh, &format!($($arg)*));
        }
    };
}

pub(crate) use debug_log;

/// Write a message to syslog through PAM's logging facility.
pub fn pam_syslog(pamh: &pamsm::Pam, msg: &str) {
    use pamsm::PamLibExt;
    let _ = pamh.syslog(pamsm::LogLvl::DEBUG, msg);
}

/// Write directly to syslog (for use in backends without PAM handle access).
/// Only logs when debug flag is true.
pub fn syslog_debug(debug: bool, msg: &str) {
    if !debug {
        return;
    }
    use std::ffi::CString;
    let tag = CString::new("pam_parallel_auth").unwrap();
    let cmsg = CString::new(msg).unwrap_or_else(|_| CString::new("(invalid msg)").unwrap());
    unsafe {
        libc::openlog(tag.as_ptr(), libc::LOG_PID, libc::LOG_AUTHPRIV);
        libc::syslog(libc::LOG_DEBUG, b"%s\0".as_ptr() as *const _, cmsg.as_ptr());
        libc::closelog();
    }
}
