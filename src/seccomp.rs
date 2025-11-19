use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use rustix::ioctl;

const SECCOMP_IOCTL_NOTIF_RECV: ioctl::Opcode =
    ioctl::opcode::read_write::<libc::seccomp_notif>(b'!', 0);
const SECCOMP_IOCTL_NOTIF_SEND: ioctl::Opcode =
    ioctl::opcode::read_write::<libc::seccomp_notif_resp>(b'!', 1);
const SECCOMP_IOCTL_NOTIF_ADDFD: ioctl::Opcode =
    ioctl::opcode::write::<libc::seccomp_notif_addfd>(b'!', 3);

pub(crate) fn check_struct_sizes() -> anyhow::Result<()> {
    let mut sizes = libc::seccomp_notif_sizes {
        seccomp_notif: 0,
        seccomp_notif_resp: 0,
        seccomp_data: 0,
    };
    if unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_GET_NOTIF_SIZES,
            0,
            &mut sizes,
        )
    } == -1
    {
        return Err(std::io::Error::last_os_error().into());
    }

    if sizes.seccomp_notif as usize != size_of::<libc::seccomp_notif>() {
        anyhow::bail!(
            "seccomp_notif size is {} (expected {})",
            sizes.seccomp_notif,
            size_of::<libc::seccomp_notif>()
        );
    }

    Ok(())
}

pub(crate) fn register() -> std::io::Result<OwnedFd> {
    rustix::thread::set_no_new_privs(true)?;

    // struct seccomp_data {
    //     int   nr;                   // System call number
    //     __u32 arch;                 // AUDIT_ARCH_* value
    //     __u64 instruction_pointer;  // CPU instruction ptr
    //     __u64 args[6];              // Up to 6 syscall args
    // };

    use libc::*;

    fn bpf(code: __u32, k: __u32) -> sock_filter {
        sock_filter {
            code: code as __u16,
            jt: 0,
            jf: 0,
            k,
        }
    }

    let mut filter = [
        // 0: load nr
        bpf(BPF_LD | BPF_ABS | BPF_W, 0),
        // 1: if nr != bind, continue
        sock_filter {
            code: (BPF_JMP | BPF_JEQ | BPF_K) as u16,
            jt: 0,
            jf: 5, // 7 - 1
            k: SYS_bind as u32,
        },
        // 2: load args[2].lo
        bpf(BPF_LD | BPF_ABS | BPF_W, 4 * 4 + 2 * 8),
        // 3: if args[2].lo != sizeof(sockaddr_in), continue
        sock_filter {
            code: (BPF_JMP | BPF_JEQ | BPF_K) as u16,
            jt: 0,
            jf: 3, // 7 - 3
            k: size_of::<libc::sockaddr_in>() as u32,
        },
        // 4: load args[2].hi
        bpf(BPF_LD | BPF_ABS | BPF_W, 4 * 4 + 2 * 8 + 4),
        // 5: if args[2].hi != 0, continue
        sock_filter {
            code: (BPF_JMP | BPF_JEQ | BPF_K) as u16,
            jt: 0,
            jf: 1, // 7 - 5
            k: 0,
        },
        // 6: intercept syscall
        bpf(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        // 7: ignore syscall
        bpf(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    ];

    let prog = sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };

    let fd = unsafe {
        match syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog,
        ) {
            -1 => return Err(std::io::Error::last_os_error()),
            fd => OwnedFd::from_raw_fd(fd.try_into().unwrap()),
        }
    };

    Ok(fd)
}

pub(crate) fn recv(
    seccomp: BorrowedFd,
    sock: BorrowedFd,
    port: u16,
) -> anyhow::Result<()> {
    let mut notif = libc::seccomp_notif {
        id: 0,
        pid: 0,
        flags: 0,
        data: libc::seccomp_data {
            nr: 0,
            arch: 0,
            instruction_pointer: 0,
            args: [0; 6],
        },
    };
    let recv_ioctl: ioctl::Updater<SECCOMP_IOCTL_NOTIF_RECV, _> =
        unsafe { ioctl::Updater::new(&mut notif) };
    unsafe { ioctl::ioctl(seccomp, recv_ioctl)? };

    let [fd, bind_addr, len, ..] = notif.data.args;
    assert!(len as usize == size_of::<libc::sockaddr_in>());

    let mut addr = libc::sockaddr_in {
        sin_family: 0,
        sin_port: 0,
        sin_addr: libc::in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };

    let local_iov = libc::iovec {
        iov_base: &mut addr as *mut libc::sockaddr_in as *mut libc::c_void,
        iov_len: size_of::<libc::sockaddr_in>(),
    };
    let remote_iov = libc::iovec {
        iov_base: bind_addr as *mut libc::c_void,
        iov_len: size_of::<libc::sockaddr_in>(),
    };

    match unsafe {
        libc::process_vm_readv(
            notif.pid.try_into()?,
            &local_iov,
            1,
            &remote_iov,
            1,
            0,
        )
    } {
        -1 => return Err(std::io::Error::last_os_error().into()),
        len if len as usize == size_of::<libc::sockaddr_in>() => (),
        _ => unreachable!(),
    }

    let notif_resp = if addr.sin_family == libc::AF_INET as u16
        && libc::ntohs(addr.sin_port) == port
    {
        let notif_addfd = libc::seccomp_notif_addfd {
            id: notif.id,
            flags: libc::SECCOMP_ADDFD_FLAG_SETFD as u32,
            srcfd: sock.as_raw_fd().try_into()?,
            newfd: fd.try_into()?,
            newfd_flags: 0,
        };

        let addfd_ioctl: ioctl::Setter<SECCOMP_IOCTL_NOTIF_ADDFD, _> =
            unsafe { ioctl::Setter::new(notif_addfd) };
        unsafe { ioctl::ioctl(seccomp, addfd_ioctl)? };

        libc::seccomp_notif_resp {
            id: notif.id,
            val: 0,
            error: 0,
            flags: 0,
        }
    } else {
        libc::seccomp_notif_resp {
            id: notif.id,
            val: 0,
            error: 0,
            flags: libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
        }
    };

    let send_ioctl: ioctl::Setter<SECCOMP_IOCTL_NOTIF_SEND, _> =
        unsafe { ioctl::Setter::new(notif_resp) };
    unsafe { ioctl::ioctl(seccomp, send_ioctl)? };

    Ok(())
}
