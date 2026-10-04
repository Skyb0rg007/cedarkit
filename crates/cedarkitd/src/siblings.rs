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

/// Whether `a` and `b` are siblings that may share a temporary
/// authorization: both still running, as the same user, children of the
/// same parent (not init), all in the same cgroup, and with the same
/// controlling pseudo-terminal, which is older than both of them, so that it
/// wasn't reopened with the same number in between.
pub fn siblings(a: ProcessId, b: ProcessId) -> bool {
    (|| {
        let (ia, ib) = (info(a)?, info(b)?);
        if ia.uid != ib.uid || ia.ppid != ib.ppid || ia.ppid <= 1 {
            return None;
        }
        let (parent_id, parent) = parent(&ia)?;
        if ia.cgroup != ib.cgroup || ia.cgroup != parent.cgroup || ia.cgroup == 0 {
            return None;
        }
        if ia.tty != ib.tty || ia.tty != parent.tty || ia.tty == 0 {
            return None;
        }
        // Unix98 pseudo-terminals, /dev/pts/N.
        let major = (ia.tty >> 8) & 0xfff;
        if !(136..=143).contains(&major) {
            return None;
        }
        let minor = ((ia.tty & 0xfff0_0000) >> 12) | (ia.tty & 0xff);
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
        if (ia.start_time as i128) < created || (ib.start_time as i128) < created {
            return None;
        }
        // The parent must still be the same process at the end.
        (info(parent_id).is_some()).then_some(())
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
        let parent = parent(&info(me).unwrap()).unwrap().0;
        assert!(!siblings(me, parent));
    }

    #[test]
    fn gone_processes_are_not_siblings() {
        let me = me();
        let gone = ProcessId {
            start_time: me.start_time + 1,
            ..me
        };
        assert!(!siblings(me, gone));
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
        assert_eq!(siblings(ia, ib), has_pts);
        a.kill().unwrap();
        b.kill().unwrap();
        a.wait().unwrap();
        b.wait().unwrap();
        assert!(!siblings(ia, ib));
    }
}
