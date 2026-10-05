//! Last steps before exec: stop privilege gain, drop capabilities, and install
//! a seccomp filter. Same order as runc, and seccomp goes last so the
//! syscalls the earlier steps use aren't filtered.

use std::mem;

use libc::{c_int, c_ulong, sock_filter};
use nix::errno::Errno;

use crate::container::Error;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("capsule's seccomp filter only knows x86_64's arch id and syscall numbers");

// Capability numbers from <linux/capability.h>.
const CAP_CHOWN: u32 = 0;
const CAP_DAC_OVERRIDE: u32 = 1;
const CAP_FOWNER: u32 = 3;
const CAP_FSETID: u32 = 4;
const CAP_KILL: u32 = 5;
const CAP_SETGID: u32 = 6;
const CAP_SETUID: u32 = 7;
const CAP_SETPCAP: u32 = 8;
const CAP_NET_BIND_SERVICE: u32 = 10;
const CAP_NET_RAW: u32 = 13;
const CAP_SYS_CHROOT: u32 = 18;
const CAP_MKNOD: u32 = 27;
const CAP_AUDIT_WRITE: u32 = 29;
const CAP_SETFCAP: u32 = 31;

/// Docker's default set: enough for ordinary root-in-a-container work (owning
/// files, switching users, binding low ports) but nothing that reaches the
/// kernel or host, like CAP_SYS_ADMIN, CAP_NET_ADMIN or CAP_SYS_MODULE.
const KEPT_CAPS: &[u32] = &[
    CAP_CHOWN,
    CAP_DAC_OVERRIDE,
    CAP_FOWNER,
    CAP_FSETID,
    CAP_KILL,
    CAP_SETGID,
    CAP_SETUID,
    CAP_SETPCAP,
    CAP_NET_BIND_SERVICE,
    CAP_NET_RAW,
    CAP_SYS_CHROOT,
    CAP_MKNOD,
    CAP_AUDIT_WRITE,
    CAP_SETFCAP,
];

/// Highest capability number worth probing; the kernel's real last cap is
/// lower, and dropping past it fails with EINVAL.
const MAX_CAP: u32 = 63;

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// `struct __user_cap_header_struct`, which libc doesn't cover.
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: c_int,
}

/// `struct __user_cap_data_struct`, which libc doesn't cover. Version 3 takes
/// two of these: the low and high 32 bits of each 64-bit set.
#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE, from <linux/audit.h>.
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

/// Syscall numbers with this bit set are the x32 ABI: a second syscall table
/// on x86_64 that a per-number deny-list would otherwise miss.
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// Syscalls that fail with EPERM inside the container.
const DENIED_SYSCALLS: &[libc::c_long] = &[
    // Changing the kernel or machine-wide state.
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_reboot,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_acct,
    libc::SYS_settimeofday,
    libc::SYS_clock_settime,
    libc::SYS_clock_adjtime,
    libc::SYS_adjtimex,
    libc::SYS_syslog,
    libc::SYS_iopl,
    libc::SYS_ioperm,
    libc::SYS_quotactl,
    libc::SYS_lookup_dcookie,
    // Rearranging or escaping the container's view of the system.
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_open_tree,
    libc::SYS_move_mount,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_fspick,
    libc::SYS_mount_setattr,
    libc::SYS_open_by_handle_at,
    libc::SYS_name_to_handle_at,
    // Large kernel attack surface, or reading other processes' memory.
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_kcmp,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_uselib,
];

/// Lock the process down. Must be the last thing before exec.
pub fn harden() -> Result<(), Error> {
    // setuid binaries and file capabilities can no longer grant privileges,
    // and it lets an unprivileged process install a seccomp filter.
    prctl(libc::PR_SET_NO_NEW_PRIVS, 1, "setting no_new_privs")?;
    drop_capabilities()?;
    install_seccomp()
}

fn cap_mask(caps: &[u32]) -> u64 {
    caps.iter().fold(0, |mask, cap| mask | 1 << cap)
}

fn drop_capabilities() -> Result<(), Error> {
    let kept = cap_mask(KEPT_CAPS);

    // The bounding set limits what exec can ever grant, including to uid 0.
    for cap in 0..=MAX_CAP {
        if kept & (1 << cap) != 0 {
            continue;
        }
        match prctl(libc::PR_CAPBSET_DROP, cap as c_ulong, "dropping capability") {
            Ok(()) => {}
            // Past the kernel's last capability.
            Err(Error::Security {
                source: Errno::EINVAL,
                ..
            }) => break,
            Err(e) => return Err(e),
        }
    }

    // SAFETY: PR_CAP_AMBIENT_CLEAR_ALL takes no pointers.
    let cleared = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as c_ulong,
            0 as c_ulong,
            0 as c_ulong,
            0 as c_ulong,
        )
    };
    check(cleared, "clearing ambient capabilities")?;

    let header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0, // this thread
    };
    let half = |shift: u32| {
        let bits = (kept >> shift) as u32;
        CapData {
            effective: bits,
            permitted: bits,
            inheritable: bits,
        }
    };
    let data = [half(0), half(32)];
    // SAFETY: header and data are valid, correctly laid out for version 3,
    // and live for the duration of the call.
    let ret = unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) };
    check(ret as c_int, "setting capabilities")
}

/// Classic BPF program run by the kernel on every syscall, over a
/// `struct seccomp_data`.
fn filter() -> Vec<sock_filter> {
    let stmt = |code: u32, k: u32| sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |code: u32, k: u32, jt: u8, jf: u8| sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    };
    let load = |offset: usize| stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, offset as u32);
    let ret = |action: u32| stmt(libc::BPF_RET | libc::BPF_K, action);
    let kill = libc::SECCOMP_RET_KILL_PROCESS;

    let nr = mem::offset_of!(libc::seccomp_data, nr);
    let arch = mem::offset_of!(libc::seccomp_data, arch);

    let mut prog = vec![
        // Syscall numbers mean different things on other architectures.
        load(arch),
        jump(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            AUDIT_ARCH_X86_64,
            1,
            0,
        ),
        ret(kill),
        load(nr),
        jump(
            libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K,
            X32_SYSCALL_BIT,
            0,
            1,
        ),
        ret(kill),
    ];

    // Each denied number jumps forward to the shared ERRNO return at the end.
    // Jump offsets are a u8, which bounds the list's length.
    let count = DENIED_SYSCALLS.len();
    assert!(count < 256, "deny-list too long for 8-bit jump offsets");
    for (i, &syscall) in DENIED_SYSCALLS.iter().enumerate() {
        let to_errno = (count - i) as u8;
        prog.push(jump(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            syscall as u32,
            to_errno,
            0,
        ));
    }
    prog.push(ret(libc::SECCOMP_RET_ALLOW));
    prog.push(ret(libc::SECCOMP_RET_ERRNO | libc::EPERM as u32));
    prog
}

fn install_seccomp() -> Result<(), Error> {
    let mut prog = filter();
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_mut_ptr(),
    };
    // SAFETY: fprog points at `prog`, which outlives the call; the kernel
    // copies the program.
    let ret = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER as c_ulong,
            &fprog as *const libc::sock_fprog,
        )
    };
    check(ret, "installing seccomp filter")
}

fn prctl(option: c_int, arg: c_ulong, op: &'static str) -> Result<(), Error> {
    // SAFETY: the options used here take only integer arguments.
    let ret = unsafe { libc::prctl(option, arg, 0 as c_ulong, 0 as c_ulong, 0 as c_ulong) };
    check(ret, op)
}

fn check(ret: c_int, op: &'static str) -> Result<(), Error> {
    if ret < 0 {
        return Err(Error::Security {
            op,
            source: Errno::last(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kept_caps_match_dockers_default() {
        // The CapEff a default Docker container shows in /proc/self/status.
        assert_eq!(cap_mask(KEPT_CAPS), 0xa804_25fb);
    }

    /// Just enough of a classic BPF interpreter to run `filter()`.
    fn run(prog: &[sock_filter], nr: u32, arch: u32) -> u32 {
        let mut data = [0u8; mem::size_of::<libc::seccomp_data>()];
        let nr_at = mem::offset_of!(libc::seccomp_data, nr);
        let arch_at = mem::offset_of!(libc::seccomp_data, arch);
        data[nr_at..nr_at + 4].copy_from_slice(&nr.to_ne_bytes());
        data[arch_at..arch_at + 4].copy_from_slice(&arch.to_ne_bytes());

        let mut acc = 0u32;
        let mut pc = 0;
        loop {
            let ins = prog[pc];
            let code = ins.code as u32;
            pc += 1;
            if code == libc::BPF_LD | libc::BPF_W | libc::BPF_ABS {
                let at = ins.k as usize;
                acc = u32::from_ne_bytes(data[at..at + 4].try_into().unwrap());
            } else if code == libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K {
                pc += if acc == ins.k { ins.jt } else { ins.jf } as usize;
            } else if code == libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K {
                pc += if acc >= ins.k { ins.jt } else { ins.jf } as usize;
            } else if code == libc::BPF_RET | libc::BPF_K {
                return ins.k;
            } else {
                panic!("unexpected BPF instruction {code:#x}");
            }
        }
    }

    const EPERM: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;

    #[test]
    fn denied_syscalls_get_eperm() {
        let prog = filter();
        for &syscall in DENIED_SYSCALLS {
            assert_eq!(
                run(&prog, syscall as u32, AUDIT_ARCH_X86_64),
                EPERM,
                "syscall {syscall}"
            );
        }
    }

    #[test]
    fn ordinary_syscalls_are_allowed() {
        let prog = filter();
        for syscall in [
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_execve,
            libc::SYS_clone,
            libc::SYS_exit_group,
        ] {
            assert_eq!(
                run(&prog, syscall as u32, AUDIT_ARCH_X86_64),
                libc::SECCOMP_RET_ALLOW,
                "syscall {syscall}"
            );
        }
    }

    #[test]
    fn foreign_arch_is_killed() {
        const AUDIT_ARCH_I386: u32 = 0x4000_0003;
        assert_eq!(
            run(&filter(), libc::SYS_read as u32, AUDIT_ARCH_I386),
            libc::SECCOMP_RET_KILL_PROCESS
        );
    }

    #[test]
    fn x32_syscalls_are_killed() {
        assert_eq!(
            run(
                &filter(),
                X32_SYSCALL_BIT | libc::SYS_read as u32,
                AUDIT_ARCH_X86_64
            ),
            libc::SECCOMP_RET_KILL_PROCESS
        );
    }
}
