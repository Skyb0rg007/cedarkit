//! `cedarkit-pam-helper SERVICE USER [CONFDIR]`: authenticates USER with PAM,
//! using SERVICE's configuration from CONFDIR, by default `/etc/pam.d`.
//!
//! `cedarkitd` runs it as root for each attempt, so that PAM modules run
//! outside the daemon, as polkit runs `polkit-agent-helper-1`. It writes
//! PAM's messages to stdout as JSON lines, each an `org.cedarkit.Agent` step
//! (`{"prompt": …}`, `{"info": …}`, `{"error": …}`), reads the answer to each
//! prompt from stdin as a JSON string, and ends with `{"success": …}`.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::io::{self, BufRead, Write};
use std::process::ExitCode;
use std::ptr;

use cedarkit_agent_protocol::Step;

/// libpam's interface, as far as this helper needs it.
mod ffi {
    use std::ffi::{c_char, c_int, c_void};

    pub const PAM_SUCCESS: c_int = 0;
    pub const PAM_BUF_ERR: c_int = 5;
    pub const PAM_CONV_ERR: c_int = 19;

    pub const PAM_PROMPT_ECHO_OFF: c_int = 1;
    pub const PAM_PROMPT_ECHO_ON: c_int = 2;
    pub const PAM_ERROR_MSG: c_int = 3;
    pub const PAM_TEXT_INFO: c_int = 4;

    pub const PAM_USER: c_int = 2;
    pub const PAM_RUSER: c_int = 8;

    #[repr(C)]
    pub struct PamHandle {
        _private: [u8; 0],
    }

    #[repr(C)]
    pub struct PamMessage {
        pub msg_style: c_int,
        pub msg: *const c_char,
    }

    #[repr(C)]
    pub struct PamResponse {
        pub resp: *mut c_char,
        pub resp_retcode: c_int,
    }

    pub type Conversation = extern "C" fn(
        num_msg: c_int,
        msg: *mut *const PamMessage,
        resp: *mut *mut PamResponse,
        appdata_ptr: *mut c_void,
    ) -> c_int;

    #[repr(C)]
    pub struct PamConv {
        pub conv: Conversation,
        pub appdata_ptr: *mut c_void,
    }

    #[link(name = "pam")]
    unsafe extern "C" {
        pub fn pam_start(
            service_name: *const c_char,
            user: *const c_char,
            pam_conversation: *const PamConv,
            pamh: *mut *mut PamHandle,
        ) -> c_int;
        pub fn pam_start_confdir(
            service_name: *const c_char,
            user: *const c_char,
            pam_conversation: *const PamConv,
            confdir: *const c_char,
            pamh: *mut *mut PamHandle,
        ) -> c_int;
        pub fn pam_end(pamh: *mut PamHandle, pam_status: c_int) -> c_int;
        pub fn pam_authenticate(pamh: *mut PamHandle, flags: c_int) -> c_int;
        pub fn pam_acct_mgmt(pamh: *mut PamHandle, flags: c_int) -> c_int;
        pub fn pam_set_item(pamh: *mut PamHandle, item_type: c_int, item: *const c_void) -> c_int;
        pub fn pam_get_item(
            pamh: *const PamHandle,
            item_type: c_int,
            item: *mut *const c_void,
        ) -> c_int;
        pub fn pam_strerror(pamh: *mut PamHandle, errnum: c_int) -> *const c_char;
    }
}

fn send(step: &Step) -> io::Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, step)?;
    out.write_all(b"\n")?;
    out.flush()
}

/// Reads the answer to a prompt.
fn answer() -> io::Result<String> {
    let mut line = String::new();
    if io::stdin().lock().read_line(&mut line)? == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    serde_json::from_str(&line).map_err(io::Error::other)
}

/// Passes PAM's messages on, and the answers back.
extern "C" fn conversation(
    num_msg: c_int,
    msg: *mut *const ffi::PamMessage,
    resp: *mut *mut ffi::PamResponse,
    _appdata: *mut c_void,
) -> c_int {
    let Ok(count) = usize::try_from(num_msg) else {
        return ffi::PAM_CONV_ERR;
    };
    // PAM frees the responses, so they must come from its allocator.
    let responses =
        unsafe { libc::calloc(count, size_of::<ffi::PamResponse>()) } as *mut ffi::PamResponse;
    if responses.is_null() {
        return ffi::PAM_BUF_ERR;
    }

    let free = |filled: usize| unsafe {
        for i in 0..filled {
            let r = &mut *responses.add(i);
            if !r.resp.is_null() {
                libc::free(r.resp.cast());
            }
        }
        libc::free(responses.cast());
    };

    for i in 0..count {
        // Linux-PAM passes an array of pointers to messages.
        let message = unsafe { &**msg.add(i) };
        let text = if message.msg.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(message.msg) }
                .to_string_lossy()
                .into_owned()
        };
        let result = match message.msg_style {
            ffi::PAM_PROMPT_ECHO_OFF | ffi::PAM_PROMPT_ECHO_ON => {
                let echo = message.msg_style == ffi::PAM_PROMPT_ECHO_ON;
                send(&Step::prompt(text, echo))
                    .and_then(|()| answer())
                    .and_then(|a| CString::new(a).map_err(io::Error::other))
                    .map(|a| unsafe {
                        (*responses.add(i)).resp = libc::strdup(a.as_ptr());
                    })
            }
            ffi::PAM_ERROR_MSG => send(&Step::error(text)),
            ffi::PAM_TEXT_INFO => send(&Step::info(text)),
            _ => Err(io::ErrorKind::Unsupported.into()),
        };
        if result.is_err() {
            free(count);
            return ffi::PAM_CONV_ERR;
        }
    }

    unsafe { *resp = responses };
    ffi::PAM_SUCCESS
}

/// Authenticates `user`, checking their account is usable too.
fn authenticate(service: &CStr, user: &CStr, confdir: Option<&CStr>) -> Result<(), String> {
    let conv = ffi::PamConv {
        conv: conversation,
        appdata_ptr: ptr::null_mut(),
    };
    let mut handle = ptr::null_mut();
    let rc = unsafe {
        match confdir {
            Some(dir) => ffi::pam_start_confdir(
                service.as_ptr(),
                user.as_ptr(),
                &conv,
                dir.as_ptr(),
                &mut handle,
            ),
            None => ffi::pam_start(service.as_ptr(), user.as_ptr(), &conv, &mut handle),
        }
    };
    if rc != ffi::PAM_SUCCESS {
        return Err(format!("pam_start failed: {rc}"));
    }
    let error = |rc| unsafe {
        CStr::from_ptr(ffi::pam_strerror(handle, rc))
            .to_string_lossy()
            .into_owned()
    };

    let result = (|| {
        let rc = unsafe { ffi::pam_set_item(handle, ffi::PAM_RUSER, user.as_ptr().cast()) };
        if rc != ffi::PAM_SUCCESS {
            return Err((rc, error(rc)));
        }
        let rc = unsafe { ffi::pam_authenticate(handle, 0) };
        if rc != ffi::PAM_SUCCESS {
            return Err((rc, error(rc)));
        }
        let rc = unsafe { ffi::pam_acct_mgmt(handle, 0) };
        if rc != ffi::PAM_SUCCESS {
            return Err((rc, error(rc)));
        }
        // A module may have changed who's authenticating.
        let mut item: *const c_void = ptr::null();
        let rc = unsafe { ffi::pam_get_item(handle, ffi::PAM_USER, &mut item) };
        if rc != ffi::PAM_SUCCESS || item.is_null() {
            return Err((rc, "PAM didn't say who authenticated".into()));
        }
        if unsafe { CStr::from_ptr(item as *const c_char) } != user {
            return Err((rc, "PAM authenticated a different user".into()));
        }
        Ok(())
    })();

    let rc = match &result {
        Ok(()) => ffi::PAM_SUCCESS,
        Err((rc, _)) => *rc,
    };
    unsafe { ffi::pam_end(handle, rc) };
    result.map_err(|(_, msg)| msg)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let (service, user, confdir) = match args.as_slice() {
        [_, service, user] => (service, user, None),
        [_, service, user, confdir] => (service, user, Some(confdir)),
        _ => {
            eprintln!("usage: cedarkit-pam-helper SERVICE USER [CONFDIR]");
            return ExitCode::FAILURE;
        }
    };
    // Answers come from cedarkitd, never from a person at a terminal.
    if unsafe { libc::isatty(libc::STDIN_FILENO) } == 1 {
        eprintln!("cedarkit-pam-helper is run by cedarkitd");
        return ExitCode::FAILURE;
    }
    let (Ok(service), Ok(user)) = (CString::new(service.as_str()), CString::new(user.as_str()))
    else {
        return ExitCode::FAILURE;
    };
    let Ok(confdir) = confdir.map(|d| CString::new(d.as_str())).transpose() else {
        return ExitCode::FAILURE;
    };

    let success = match authenticate(&service, &user, confdir.as_deref()) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("cedarkit-pam-helper: {}: {e}", user.to_string_lossy());
            false
        }
    };
    match send(&Step::done(success)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
