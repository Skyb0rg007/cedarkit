//! The authentication dialog, after GNOME Shell's polkit agent.
//!
//! As there:
//! - the user authenticates as one identity: themselves if they're listed,
//!   otherwise root, otherwise the first listed;
//! - the dialog opens on PAM's first message, not when the request arrives;
//! - PAM's prompts, errors and information are shown as they come;
//! - after a failure, it says so, and starts again, until the user succeeds
//!   or cancels;
//! - for an account without a password, it opens straight away, with
//!   nothing to type, and PAM starts only once the user confirms.

use std::cell::Cell;
use std::path::Path;
use std::rc::Rc;
use std::time::Duration;

use adw::prelude::*;
use anyhow::Context as _;
use cedarkit_agent_protocol::{AgentProxy, Identity, Request, Step};
use futures_util::{FutureExt, StreamExt, pin_mut, select};
use gtk::{gdk, gio, glib};

const TITLE: &str = "Authentication Required";
const FAILED: &str = "Sorry, that didn’t work. Please try again.";

/// Where AccountsService keeps users' pictures.
const ICONS: &str = "/var/lib/AccountsService/icons";

/// What the user did.
enum UiEvent {
    Submit(String),
    Cancel,
}

/// How a request ended.
enum End {
    Authenticated,
    /// The user cancelled.
    Dismissed,
    /// cedarkitd cancelled.
    Cancelled,
}

/// Asks the user to authenticate for `request`, until they do, they give up,
/// or cedarkitd cancels the request.
pub async fn authenticate(
    socket: &Path,
    request: &Request,
    cancelled: async_channel::Receiver<()>,
) {
    let Some(identity) = choose(&request.identities) else {
        tracing::warn!(cookie = request.cookie, "no identity to authenticate as");
        dismiss(socket, &request.cookie).await;
        return;
    };
    if request.identities.len() > 1 {
        tracing::debug!(
            "{} identities could authenticate; only considering {}",
            request.identities.len(),
            identity.name
        );
    }

    let ui = Dialog::new(request, identity);
    let end = converse(socket, request, identity, &ui, &cancelled).await;
    ui.close();
    match end {
        Ok(End::Authenticated) => tracing::info!(action = request.action, "authenticated"),
        Ok(End::Cancelled) => tracing::debug!(cookie = request.cookie, "cancelled by cedarkitd"),
        Ok(End::Dismissed) => dismiss(socket, &request.cookie).await,
        Err(e) => {
            tracing::warn!("authentication failed: {e:#}");
            dismiss(socket, &request.cookie).await;
        }
    }
}

/// The identity to authenticate as, as GNOME Shell chooses it.
fn choose(identities: &[Identity]) -> Option<&Identity> {
    let me = nix::unistd::getuid().as_raw();
    identities
        .iter()
        .find(|i| i.uid == me)
        .or_else(|| identities.iter().find(|i| i.uid == 0))
        .or(identities.first())
}

/// Tells cedarkitd the user gave up.
async fn dismiss(socket: &Path, cookie: &str) {
    let result = async {
        let mut conn = zlink::smol::unix::connect(socket).await?;
        conn.dismiss(cookie).await??;
        anyhow::Ok(())
    };
    if let Err(e) = result.await {
        tracing::warn!("can't dismiss the request: {e:#}");
    }
}

/// Whether the account has no password, according to AccountsService, as
/// GNOME Shell decides.
async fn passwordless(uid: u32) -> bool {
    const ACCOUNTS: &str = "org.freedesktop.Accounts";
    // AccountsService's UserPasswordMode: regular, set at login, none.
    const NONE: i32 = 2;
    let result = async {
        let bus = gio::bus_get_future(gio::BusType::System).await?;
        let call = |path: &str, interface: &str, method: &str, args: glib::Variant, ty: &str| {
            bus.call_future(
                Some(ACCOUNTS),
                path,
                interface,
                method,
                Some(&args),
                Some(glib::VariantTy::new(ty).expect("valid type")),
                gio::DBusCallFlags::NONE,
                1000,
            )
        };
        let reply = call(
            "/org/freedesktop/Accounts",
            ACCOUNTS,
            "FindUserById",
            (i64::from(uid),).to_variant(),
            "(o)",
        )
        .await?;
        let path = reply.child_value(0).str().unwrap_or_default().to_owned();
        let reply = call(
            &path,
            "org.freedesktop.DBus.Properties",
            "Get",
            ("org.freedesktop.Accounts.User", "PasswordMode").to_variant(),
            "(v)",
        )
        .await?;
        let mode = reply
            .child_value(0)
            .as_variant()
            .and_then(|v| v.get::<i32>());
        anyhow::Ok(mode == Some(NONE))
    };
    result.await.unwrap_or_else(|e| {
        tracing::debug!(uid, "can't ask AccountsService about the password: {e:#}");
        false
    })
}

/// Waits for the user to answer, or the request to end.
async fn wait(ui: &Dialog, cancelled: &async_channel::Receiver<()>) -> Result<String, End> {
    select! {
        event = ui.events.recv().fuse() => match event {
            Ok(UiEvent::Submit(text)) => Ok(text),
            Ok(UiEvent::Cancel) | Err(_) => Err(End::Dismissed),
        },
        _ = cancelled.recv().fuse() => Err(End::Cancelled),
    }
}

/// Relays the conversation between PAM, through cedarkitd, and the user.
async fn converse(
    socket: &Path,
    request: &Request,
    identity: &Identity,
    ui: &Dialog,
    cancelled: &async_channel::Receiver<()>,
) -> anyhow::Result<End> {
    let mut conn = zlink::smol::unix::connect(socket)
        .await
        .with_context(|| format!("connecting to {}", socket.display()))?;
    let cookie = &request.cookie;
    let confirm = passwordless(identity.uid).await;
    // The answer to PAM's last prompt, if this call gives one.
    let mut answer: Option<String> = None;

    loop {
        if answer.is_none() && confirm {
            ui.confirm();
            match wait(ui, cancelled).await {
                Ok(_) => ui.working(),
                Err(end) => return Ok(end),
            }
        }
        // One call, which replies with PAM's messages up to its next prompt,
        // or the result.
        let last: Step = {
            let steps = match &answer {
                None => conn.authenticate(cookie, identity.uid).await?.boxed_local(),
                Some(answer) => conn.respond(cookie, answer).await?.boxed_local(),
            };
            pin_mut!(steps);
            loop {
                let step = select! {
                    step = steps.next().fuse() => step,
                    event = ui.events.recv().fuse() => match event {
                        Ok(UiEvent::Cancel) | Err(_) => return Ok(End::Dismissed),
                        Ok(UiEvent::Submit(_)) => continue,
                    },
                    _ = cancelled.recv().fuse() => return Ok(End::Cancelled),
                };
                let step = step.context("cedarkitd ended the conversation")???;
                ui.show(&step);
                if step.is_last() {
                    break step;
                }
            }
        };

        match last.success {
            Some(true) => return Ok(End::Authenticated),
            Some(false) => {
                ui.failed();
                answer = None;
            }
            // A prompt: wait for the user's answer.
            None => match wait(ui, cancelled).await {
                Ok(text) => {
                    ui.working();
                    answer = Some(text);
                }
                Err(end) => return Ok(end),
            },
        }
    }
}

/// The user's real name, from the account database.
fn real_name(identity: &Identity) -> String {
    nix::unistd::User::from_uid(identity.uid.into())
        .ok()
        .flatten()
        .and_then(|u| {
            let gecos = u.gecos.to_string_lossy().into_owned();
            let name = gecos
                .split(',')
                .next()
                .unwrap_or_default()
                .trim()
                .to_owned();
            (!name.is_empty()).then_some(name)
        })
        .unwrap_or_else(|| identity.name.clone())
}

/// A shake, like GNOME Shell's `wiggle()`, for a failed attempt.
const CSS: &str = "
@keyframes cedarkit-wiggle {
  0%   { margin-left: 0;    margin-right: 0; }
  20%  { margin-left: 0;    margin-right: 12px; }
  40%  { margin-left: 12px; margin-right: 0; }
  60%  { margin-left: 0;    margin-right: 8px; }
  80%  { margin-left: 4px;  margin-right: 0; }
  100% { margin-left: 0;    margin-right: 0; }
}
.cedarkit-wiggle { animation: cedarkit-wiggle 400ms ease-out; }
";

fn load_css() {
    thread_local! {
        static LOADED: Cell<bool> = const { Cell::new(false) };
    }
    if LOADED.replace(true) {
        return;
    }
    let provider = gtk::CssProvider::new();
    provider.load_from_string(CSS);
    if let Some(display) = gdk::Display::default() {
        gtk::style_context_add_provider_for_display(
            &display,
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }
}

/// The dialog's widgets.
struct Dialog {
    dialog: adw::Dialog,
    entries: gtk::Stack,
    /// For prompts whose answer is hidden.
    password: gtk::PasswordEntry,
    /// For prompts whose answer may be shown.
    text: gtk::Entry,
    /// Which of the two is in use.
    echo: Rc<Cell<bool>>,
    /// Whether the user only has to confirm, with nothing to type.
    confirming: Rc<Cell<bool>>,
    authenticate: gtk::Button,
    message: gtk::Label,
    /// Whether `message` shows an error.
    error_shown: Cell<bool>,
    opened: Cell<bool>,
    /// Set once the dialog is closed, so that closing isn't taken as the
    /// user cancelling.
    closed: Rc<Cell<bool>>,
    events: async_channel::Receiver<UiEvent>,
}

impl Dialog {
    fn new(request: &Request, identity: &Identity) -> Self {
        load_css();
        let (tx, events) = async_channel::unbounded();

        let content = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(18)
            .margin_top(24)
            .margin_bottom(24)
            .margin_start(24)
            .margin_end(24)
            .build();

        let title = gtk::Label::builder()
            .label(TITLE)
            .wrap(true)
            .justify(gtk::Justification::Center)
            .css_classes(["title-2"])
            .build();
        let description = gtk::Label::builder()
            .label(&request.message)
            .wrap(true)
            .justify(gtk::Justification::Center)
            .build();
        content.append(&title);
        content.append(&description);

        // The user, with their picture and real name. Root is "Administrator",
        // in the warning colour.
        let name = real_name(identity);
        let user = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(6)
            .halign(gtk::Align::Center)
            .build();
        let avatar = adw::Avatar::new(96, Some(&name), true);
        if let Ok(picture) = gdk::Texture::from_filename(format!("{ICONS}/{}", identity.name)) {
            avatar.set_custom_image(Some(&picture));
        }
        let label = gtk::Label::builder().css_classes(["heading"]).build();
        if identity.uid == 0 {
            label.set_label("Administrator");
            label.add_css_class("warning");
        } else {
            label.set_label(&name);
        }
        user.append(&avatar);
        user.append(&label);
        content.append(&user);

        // The entry appears with PAM's first prompt. Its space is reserved,
        // so that the dialog doesn't change size.
        let password = gtk::PasswordEntry::builder()
            .show_peek_icon(true)
            .activates_default(true)
            .build();
        let text = gtk::Entry::builder().activates_default(true).build();
        let entries = gtk::Stack::new();
        entries.add_named(&gtk::Box::new(gtk::Orientation::Vertical, 0), Some("none"));
        entries.add_named(&password, Some("password"));
        entries.add_named(&text, Some("text"));
        entries.set_visible_child_name("none");
        content.append(&entries);

        // PAM's error or information, whichever came last.
        let message = gtk::Label::builder()
            .label(" ")
            .wrap(true)
            .justify(gtk::Justification::Center)
            .build();
        content.append(&message);

        let buttons = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(12)
            .homogeneous(true)
            .margin_top(6)
            .build();
        let cancel = gtk::Button::builder()
            .label("Cancel")
            .css_classes(["pill"])
            .build();
        let authenticate = gtk::Button::builder()
            .label("Authenticate")
            .css_classes(["pill", "suggested-action"])
            .sensitive(false)
            .build();
        buttons.append(&cancel);
        buttons.append(&authenticate);
        content.append(&buttons);

        let dialog = adw::Dialog::builder()
            .title(TITLE)
            .content_width(400)
            .child(&content)
            .default_widget(&authenticate)
            .build();

        let echo = Rc::new(Cell::new(false));
        let confirming = Rc::new(Cell::new(false));
        let closed = Rc::new(Cell::new(false));

        // Authenticate is only active with something to send.
        for editable in [password.upcast_ref::<gtk::Editable>(), text.upcast_ref()] {
            let button = authenticate.clone();
            editable.connect_changed(move |e| button.set_sensitive(!e.text().is_empty()));
        }
        {
            let (tx, echo, confirming, password, text) = (
                tx.clone(),
                echo.clone(),
                confirming.clone(),
                password.clone(),
                text.clone(),
            );
            authenticate.connect_clicked(move |_| {
                if confirming.replace(false) {
                    let _ = tx.try_send(UiEvent::Submit(String::new()));
                    return;
                }
                let entry: gtk::Editable = if echo.get() {
                    text.clone().upcast()
                } else {
                    password.clone().upcast()
                };
                if entry.is_editable() && !entry.text().is_empty() {
                    let _ = tx.try_send(UiEvent::Submit(entry.text().into()));
                }
            });
        }
        {
            let tx = tx.clone();
            cancel.connect_clicked(move |_| {
                let _ = tx.try_send(UiEvent::Cancel);
            });
        }
        {
            // Escape, or the window being closed.
            let (tx, closed) = (tx.clone(), closed.clone());
            dialog.connect_closed(move |_| {
                if !closed.replace(true) {
                    let _ = tx.try_send(UiEvent::Cancel);
                }
            });
        }

        Self {
            dialog,
            entries,
            password,
            text,
            echo,
            confirming,
            authenticate,
            message,
            error_shown: Cell::new(false),
            opened: Cell::new(false),
            closed,
            events,
        }
    }

    fn ensure_open(&self) {
        if !self.opened.replace(true) {
            self.dialog.present(None::<&gtk::Widget>);
        }
    }

    fn entry(&self) -> gtk::Widget {
        if self.echo.get() {
            self.text.clone().upcast()
        } else {
            self.password.clone().upcast()
        }
    }

    fn clear(&self) {
        self.password.set_text("");
        self.text.set_text("");
    }

    /// Shows a message from PAM.
    fn show(&self, step: &Step) {
        if let Some(prompt) = &step.prompt {
            self.prompt(&prompt.text, prompt.echo);
        }
        if let Some(text) = &step.error {
            self.clear();
            self.show_message(text, true);
            self.ensure_open();
        }
        if let Some(text) = &step.info {
            self.clear();
            self.show_message(text, false);
            self.ensure_open();
        }
    }

    fn show_message(&self, text: &str, error: bool) {
        self.message.set_label(text);
        self.error_shown.set(error);
        if error {
            self.message.remove_css_class("dim-label");
            self.message.add_css_class("error");
        } else {
            self.message.remove_css_class("error");
            self.message.add_css_class("dim-label");
        }
    }

    fn hide_message(&self) {
        self.message.set_label(" ");
        self.error_shown.set(false);
    }

    /// Asks the user to confirm, with nothing to type.
    fn confirm(&self) {
        self.confirming.set(true);
        self.entries.set_visible_child_name("none");
        self.authenticate.set_sensitive(true);
        self.ensure_open();
        self.authenticate.grab_focus();
    }

    fn prompt(&self, text: &str, echo: bool) {
        self.confirming.set(false);
        let placeholder = if text == "Password:" || text == "Password: " {
            "Password".to_owned()
        } else {
            text.trim_end().trim_end_matches(':').trim().to_owned()
        };
        self.echo.set(echo);
        self.entries
            .set_visible_child_name(if echo { "text" } else { "password" });
        self.password.set_placeholder_text(Some(&placeholder));
        self.text.set_placeholder_text(Some(&placeholder));
        self.clear();
        let entry = self.entry();
        entry.set_sensitive(true);
        self.authenticate.set_sensitive(false);
        self.ensure_open();
        entry.grab_focus();
    }

    /// The answer is being checked.
    fn working(&self) {
        self.password.set_sensitive(false);
        self.text.set_sensitive(false);
        self.authenticate.set_sensitive(false);
        self.hide_message();
    }

    /// The attempt failed; another starts straight away.
    fn failed(&self) {
        if !self.error_shown.get() {
            self.show_message(FAILED, true);
        }
        self.clear();
        let entry = self.entry();
        entry.remove_css_class("cedarkit-wiggle");
        entry.add_css_class("cedarkit-wiggle");
        glib::timeout_add_local_once(Duration::from_millis(400), move || {
            entry.remove_css_class("cedarkit-wiggle");
        });
    }

    fn close(&self) {
        if !self.closed.replace(true) {
            self.dialog.force_close();
        }
    }
}
