//! polkit's rule for when two processes count as one for a temporary
//! authorization (`subject_equal_for_authz` in polkit 127 and later): so
//! that, say, consecutive commands run from the same terminal share one.

use std::fs;
use std::os::unix::fs::MetadataExt;

use cedarkit_core::ProcessId;

/// What the rule looks at in a process.
#[derive(Debug, PartialEq, Eq)]
struct Info {
    uid: u32,
    ppid: u32,
    /// The controlling terminal's device number, 0 for none.
    tty: u64,
    /// The cgroup's inode number.
    cgroup: u64,
    start_time: u64,
}

/// A process's details, if it's still the same process.
fn info(process: ProcessId) -> Option<Info> {
    let stat = fs::read_to_string(format!("/proc/{}/stat", process.pid)).ok()?;
    // The fields after the command name start with the state (field 3).
    let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    let ppid = fields.get(1)?.parse().ok()?;
    let tty = fields.get(4)?.parse::<i64>().ok()? as u64;
    let start_time = fields.get(19)?.parse().ok()?;
    if start_time != process.start_time {
        return None;
    }
    let status = fs::read_to_string(format!("/proc/{}/status", process.pid)).ok()?;
    let uid = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    let cgroup = fs::read_to_string(format!("/proc/{}/cgroup", process.pid)).ok()?;
    let path = cgroup.lines().find_map(|l| l.strip_prefix("0::"))?;
    let cgroup = fs::metadata(format!("/sys/fs/cgroup{path}")).ok()?.ino();
    Some(Info {
        uid,
        ppid,
        tty,
        cgroup,
        start_time,
    })
}

/// The parent of a process, identified by its start time.
fn parent(info: &Info) -> Option<(ProcessId, Info)> {
    let stat = fs::read_to_string(format!("/proc/{}/stat", info.ppid)).ok()?;
    let start_time = stat
        .rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()?;
    let id = ProcessId {
        pid: info.ppid,
        start_time,
    };
    Some((id, self::info(id)?))
}

/// The wall-clock time the system booted, in nanoseconds since the epoch:
/// the realtime clock less the boot-time clock that process start times are
/// measured by. More precise than `/proc/stat`'s `btime`, which polkit uses,
/// and which is truncated to whole seconds.
fn boot_time_ns() -> Option<i128> {
    let now = |clock| {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: ts is a valid timespec to write to.
        (unsafe { libc::clock_gettime(clock, &mut ts) } == 0)
            .then(|| ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128)
    };
    Some(now(libc::CLOCK_REALTIME)? - now(libc::CLOCK_BOOTTIME)?)
}

/// What polkit records about a process when it remembers an
/// authentication for it, to recognize its siblings later, even once it has
/// exited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Family {
    uid: u32,
    parent: ProcessId,
    tty: u64,
    cgroup: u64,
    start_time: u64,
}

/// A running process's family, if it has a parent other than init.
pub fn family(process: ProcessId) -> Option<Family> {
    let info = info(process)?;
    if info.ppid <= 1 {
        return None;
    }
    let (parent, _) = parent(&info)?;
    Some(Family {
        uid: info.uid,
        parent,
        tty: info.tty,
        cgroup: info.cgroup,
        start_time: info.start_time,
    })
}

/// Whether running process `b` is a sibling of the process `a` was recorded
/// for, so that they may share a temporary authorization: as the same user,
/// a child of the same parent (still running, and not init), all in the
/// same cgroup, and with the same controlling pseudo-terminal, which is
/// older than both of them, so that it wasn't reopened with the same number
/// in between.
pub fn siblings(a: &Family, b: ProcessId) -> bool {
    (|| {
        let b = family(b)?;
        if a.uid != b.uid || a.parent != b.parent {
            return None;
        }
        let parent = info(a.parent)?;
        if a.cgroup != b.cgroup || a.cgroup != parent.cgroup || a.cgroup == 0 {
            return None;
        }
        if a.tty != b.tty || a.tty != parent.tty || a.tty == 0 {
            return None;
        }
        // Unix98 pseudo-terminals, /dev/pts/N.
        let major = (a.tty >> 8) & 0xfff;
        if !(136..=143).contains(&major) {
            return None;
        }
        let minor = ((a.tty & 0xfff0_0000) >> 12) | (a.tty & 0xff);
        let tty = fs::metadata(format!("/dev/pts/{minor}")).ok()?;

        // Compare the terminal's last change, at the latest its creation,
        // with the processes' start times, in clock ticks since boot.
        let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        let boot = boot_time_ns()?;
        let changed = tty.ctime() as i128 * 1_000_000_000 + tty.ctime_nsec() as i128;
        if ticks <= 0 || changed < boot {
            return None;
        }
        let created = (changed - boot) * ticks as i128 / 1_000_000_000;
        if (a.start_time as i128) < created || (b.start_time as i128) < created {
            return None;
        }
        // The parent must still be the same process at the end.
        info(a.parent).map(|_| ())
    })()
    .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> ProcessId {
        crate::state::process(std::process::id(), Some(0))
            .unwrap()
            .id
    }

    #[test]
    fn a_process_is_not_its_own_parents_sibling() {
        let me = me();
        // Without a cgroup filesystem, as in a build sandbox, nothing is.
        let (Some(family), Some(parent)) = (family(me), info(me).and_then(|i| parent(&i))) else {
            return;
        };
        assert!(!siblings(&family, parent.0));
    }

    #[test]
    fn gone_processes_have_no_family() {
        let me = me();
        let gone = ProcessId {
            start_time: me.start_time + 1,
            ..me
        };
        assert!(family(gone).is_none());
    }

    /// Two children of this process share a terminal only if it has one,
    /// which test runners often don't give; so this checks the rule's
    /// answer agrees with what's there.
    #[test]
    fn children_of_one_parent() {
        let spawn = || {
            std::process::Command::new("sleep")
                .arg("5")
                .spawn()
                .unwrap()
        };
        let (mut a, mut b) = (spawn(), spawn());
        let id = |c: &std::process::Child| crate::state::process(c.id(), Some(0)).unwrap().id;
        let (ia, ib) = (id(&a), id(&b));
        let has_pts = info(ia).is_some_and(|i| (136..=143).contains(&((i.tty >> 8) & 0xfff)));
        let Some(fa) = family(ia) else {
            return;
        };
        assert_eq!(siblings(&fa, ib), has_pts);
        // Once recorded, it holds after the first has exited.
        a.kill().unwrap();
        a.wait().unwrap();
        assert_eq!(siblings(&fa, ib), has_pts);
        b.kill().unwrap();
        b.wait().unwrap();
        assert!(!siblings(&fa, ib));
    }
}
