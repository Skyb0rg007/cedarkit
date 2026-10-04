//! Ending a check early, while it waits for the user to authenticate: when
//! its caller cancels it or goes away, or the process it's for exits. The
//! agent's dialog then closes.

use std::collections::HashMap;
use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex};

use cedarkit_core::ProcessId;
use futures_util::StreamExt;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::oneshot;
use zbus::fdo;
use zbus::names::UniqueName;

/// The checks that can be cancelled with `CancelCheckAuthorization`, by
/// caller and cancellation id, as in polkit.
#[derive(Default)]
pub struct Cancellations {
    pending: Mutex<HashMap<(String, String), oneshot::Sender<()>>>,
}

/// A check registered for cancellation, unregistered when dropped.
pub struct Registration {
    cancellations: Arc<Cancellations>,
    key: (String, String),
    pub cancelled: oneshot::Receiver<()>,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.cancellations.lock().remove(&self.key);
    }
}

impl Cancellations {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(String, String), oneshot::Sender<()>>> {
        self.pending
            .lock()
            .expect("the cancellations' lock isn't poisoned")
    }

    /// Registers `caller`'s check with cancellation id `id`.
    pub fn register(self: &Arc<Self>, caller: &str, id: &str) -> fdo::Result<Registration> {
        let key = (caller.to_owned(), id.to_owned());
        let mut pending = self.lock();
        if pending.contains_key(&key) {
            return Err(fdo::Error::InvalidArgs(format!(
                "cancellation id {id:?} is already in use"
            )));
        }
        let (tx, cancelled) = oneshot::channel();
        pending.insert(key.clone(), tx);
        Ok(Registration {
            cancellations: self.clone(),
            key,
            cancelled,
        })
    }

    /// Cancels `caller`'s check with cancellation id `id`.
    pub fn cancel(&self, caller: &str, id: &str) -> fdo::Result<()> {
        let tx = self
            .lock()
            .remove(&(caller.to_owned(), id.to_owned()))
            .ok_or_else(|| {
                fdo::Error::InvalidArgs(format!("no check with cancellation id {id:?}"))
            })?;
        let _ = tx.send(());
        Ok(())
    }
}

/// Resolves when `name` leaves the bus.
pub async fn name_vanished(conn: &zbus::Connection, name: &UniqueName<'_>) {
    let result = async {
        let dbus = fdo::DBusProxy::new(conn).await?;
        let mut changes = dbus
            .receive_name_owner_changed_with_args(&[(0, name.as_str())])
            .await?;
        // Subscribed before asking, so that leaving in between isn't missed.
        if !dbus.name_has_owner(name.clone().into()).await? {
            return zbus::Result::Ok(());
        }
        while let Some(change) = changes.next().await {
            if change.args()?.new_owner().is_none() {
                return Ok(());
            }
        }
        Ok(())
    };
    if let Err(e) = result.await {
        tracing::warn!(%name, "can't watch the caller: {e}");
        std::future::pending::<()>().await;
    }
}

/// Resolves when `process` exits.
pub async fn process_exited(process: ProcessId) {
    // SAFETY: pidfd_open takes a pid and flags, and returns a new fd.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, process.pid as libc::pid_t, 0) };
    if fd < 0 {
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => return,
            _ => {
                tracing::warn!(pid = process.pid, "can't watch the process");
                return std::future::pending().await;
            }
        }
    }
    // SAFETY: the fd was just opened, and nothing else owns it.
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    // The pid may have been reused since the check began.
    if crate::process(process.pid, Some(0)).ok().map(|p| p.id) != Some(process) {
        return;
    }
    // A pidfd becomes readable when its process exits.
    match AsyncFd::with_interest(fd, Interest::READABLE) {
        Ok(fd) => {
            let _ = fd.readable().await;
        }
        Err(e) => {
            tracing::warn!(pid = process.pid, "can't watch the process: {e}");
            std::future::pending::<()>().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn notices_exits() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let process = crate::process(child.id(), Some(0)).unwrap().id;
        let watch = tokio::spawn(process_exited(process));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!watch.is_finished());

        child.kill().unwrap();
        tokio::time::timeout(Duration::from_secs(5), watch)
            .await
            .expect("the exit is noticed")
            .unwrap();
        child.wait().unwrap();
        // Once it's gone, straight away.
        tokio::time::timeout(Duration::from_secs(1), process_exited(process))
            .await
            .expect("an exited process is noticed");
    }

    #[tokio::test]
    async fn cancelling_by_id() {
        let cancellations = Arc::new(Cancellations::default());
        let mut registration = cancellations.register(":1.1", "a").unwrap();
        assert!(cancellations.register(":1.1", "a").is_err(), "in use");
        // Ids are the caller's own.
        assert!(cancellations.register(":1.2", "a").is_ok());
        assert!(cancellations.cancel(":1.2", "b").is_err());

        cancellations.cancel(":1.1", "a").unwrap();
        assert!((&mut registration.cancelled).await.is_ok());
        drop(registration);
        assert!(cancellations.register(":1.1", "a").is_ok(), "free again");
    }
}
