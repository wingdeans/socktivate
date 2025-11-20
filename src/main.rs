mod config;
mod seccomp;

use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::time::Instant;

use rustix::event;
use rustix::event::{PollFd, PollFlags};
use rustix::net;
use rustix::process;
use rustix::time;

#[derive(Debug)]
struct ErrBuf {
    buf: [Option<(anyhow::Error, Instant)>; 4],
    idx: u8,
}

impl ErrBuf {
    fn new() -> Self {
        ErrBuf {
            buf: [const { None }; 4],
            idx: 0,
        }
    }

    fn push(
        &mut self,
        e: Option<(anyhow::Error, Instant)>,
    ) -> Option<(anyhow::Error, Instant)> {
        let curr = &mut self.buf[self.idx as usize];
        let el = curr.take();
        *curr = e;
        self.idx = (self.idx + 1) % self.buf.len() as u8;
        el
    }
}

#[derive(Debug)]
enum State {
    Stopped,
    NeedSeccompFd {
        ipc: OwnedFd,
        ipc_in: PollFlags,
    },
    NeedSeccompNotify {
        seccomp: OwnedFd,
        seccomp_in: PollFlags,
    },
    Started {
        timer: OwnedFd,
        timer_in: PollFlags,
    },
    Idle {
        sock_in: PollFlags,
        timer: OwnedFd,
        timer_in: PollFlags,
    },
}

#[derive(Debug)]
struct Endpoint {
    // Endpoint configuration
    port: u16,
    cmd: Vec<String>,
    // Common fds
    sock: Option<OwnedFd>,
    pidfd: Option<(OwnedFd, PollFlags)>,
    // Error ringbuf
    errs: ErrBuf,
    // State
    state: State,
}

const TIMEOUT_STARTED: event::Secs = 60;
const TIMEOUT_IDLE: event::Secs = 5 * 60;

fn timerfd(seconds: event::Secs) -> anyhow::Result<OwnedFd> {
    let timer = time::timerfd_create(
        time::TimerfdClockId::Monotonic,
        time::TimerfdFlags::CLOEXEC,
    )?;
    time::timerfd_settime(
        &timer,
        time::TimerfdTimerFlags::empty(),
        &time::Itimerspec {
            it_interval: time::Timespec::default(),
            it_value: time::Timespec {
                tv_sec: seconds,
                tv_nsec: 0,
            },
        },
    )?;

    Ok(timer)
}

fn signalfd() -> anyhow::Result<OwnedFd> {
    unsafe {
        let mut mask = std::mem::MaybeUninit::zeroed().assume_init();

        if libc::sigemptyset(&mut mask) == -1 {
            return Err(std::io::Error::last_os_error().into());
        }
        if libc::sigaddset(&mut mask, libc::SIGTERM) == -1 {
            return Err(std::io::Error::last_os_error().into());
        }

        // Rust resets the signal mask when spawning child processes
        // so it is not necessary to do manually after fork
        if libc::sigprocmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) == -1
        {
            return Err(std::io::Error::last_os_error().into());
        }

        match libc::signalfd(-1, &mask, libc::SFD_CLOEXEC) {
            -1 => Err(std::io::Error::last_os_error().into()),
            fd => Ok(OwnedFd::from_raw_fd(fd)),
        }
    }
}

fn update_endpoint(e: &mut Endpoint) -> anyhow::Result<()> {
    // Stop endpoint if child process stopped
    if let Some((pidfd, pidfd_in)) = &e.pidfd
        && pidfd_in.contains(PollFlags::IN)
    {
        process::waitid(
            process::WaitId::PidFd(pidfd.as_fd()),
            process::WaitIdOptions::EXITED,
        )?;
        e.pidfd = None;
        e.state = State::Stopped;
        return Ok(());
    }

    match &e.state {
        State::Stopped => {
            // Set up IPC
            let (ipc_self, ipc_child) = net::socketpair(
                net::AddressFamily::UNIX,
                net::SocketType::DGRAM,
                net::SocketFlags::empty(),
                None,
            )?;

            // Configure child process
            let mut cmd = std::process::Command::new(&e.cmd[0]);
            cmd.args(&e.cmd[1..]);

            let pre_exec = move || {
                // Send seccomp fd over IPC
                let mut buf = [std::mem::MaybeUninit::uninit();
                    rustix::cmsg_space!(ScmRights(1))];
                let mut anc_buf = net::SendAncillaryBuffer::new(&mut buf);

                let seccomp_owned = seccomp::register()?;
                let rights = [seccomp_owned.as_fd()];
                anc_buf.push(net::SendAncillaryMessage::ScmRights(&rights));
                // It isn't portable to send ancillary data with no
                // data over a unix datagram socket, but it works on
                // Linux (see unix(7): Ancillary messages).
                net::sendmsg(
                    &ipc_child,
                    &[],
                    &mut anc_buf,
                    net::SendFlags::empty(),
                )?;
                Ok(())
            };

            // Start child process, open pidfd
            unsafe { cmd.pre_exec(pre_exec) };
            let child = cmd.spawn()?;

            let pidfd = process::pidfd_open(
                process::Pid::from_child(&child),
                process::PidfdFlags::empty(),
            )?;

            // Wait for seccomp fd over IPC
            e.state = State::NeedSeccompFd {
                ipc: ipc_self,
                ipc_in: PollFlags::empty(),
            };
            e.pidfd = Some((pidfd, PollFlags::empty()));
        }
        State::NeedSeccompFd { ipc, ipc_in } => {
            assert!(ipc_in.contains(PollFlags::IN));

            // Receive seccomp fd over IPC
            let mut buf = [std::mem::MaybeUninit::uninit();
                rustix::cmsg_space!(ScmRights(1))];
            let mut anc_buf = net::RecvAncillaryBuffer::new(&mut buf);
            net::recvmsg(
                ipc,
                &mut [],
                &mut anc_buf,
                net::RecvFlags::CMSG_CLOEXEC,
            )?;

            // Extract seccomp fd
            let mut anc_iter = anc_buf.drain();
            let Some(net::RecvAncillaryMessage::ScmRights(mut rights_iter)) =
                anc_iter.next()
            else {
                unreachable!();
            };
            assert!(anc_iter.next().is_none());

            let Some(seccomp) = rights_iter.next() else {
                unreachable!();
            };

            // Wait for seccomp notify on seccomp fd
            e.state = State::NeedSeccompNotify {
                seccomp,
                seccomp_in: PollFlags::empty(),
            };
        }
        State::NeedSeccompNotify {
            seccomp,
            seccomp_in,
        } => {
            assert!(seccomp_in.contains(PollFlags::IN));

            seccomp::recv(
                seccomp.as_fd(),
                e.sock.as_ref().unwrap().as_fd(),
                e.port,
            )?;

            e.state = State::Started {
                timer: timerfd(TIMEOUT_STARTED)?,
                timer_in: PollFlags::empty(),
            };
        }
        State::Started { timer: _, timer_in } => {
            assert!(timer_in.contains(PollFlags::IN));

            e.state = State::Idle {
                sock_in: PollFlags::empty(),
                timer: timerfd(TIMEOUT_IDLE)?,
                timer_in: PollFlags::empty(),
            };
        }
        State::Idle {
            sock_in,
            timer: _,
            timer_in,
        } => {
            e.state = if sock_in.contains(PollFlags::IN) {
                State::Started {
                    timer: timerfd(TIMEOUT_STARTED)?,
                    timer_in: PollFlags::empty(),
                }
            } else if timer_in.contains(PollFlags::IN) {
                let (pidfd, _) = e.pidfd.as_ref().unwrap();
                process::pidfd_send_signal(pidfd, process::Signal::TERM)?;
                State::Stopped
            } else {
                unreachable!()
            }
        }
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let config = match &std::env::args().collect::<Vec<_>>()[..] {
        [_] => anyhow::bail!("no config file provided"),
        [_, config_path] => config::read_config(config_path)?,
        _ => anyhow::bail!("too many arguments"),
    };

    let mut endpoints = Vec::with_capacity(config.len());
    for e in config.into_iter() {
        if e.cmd.is_empty() {
            anyhow::bail!("endpoint command for {} is empty", e.addr);
        }

        let sock = net::socket_with(
            net::AddressFamily::INET,
            net::SocketType::STREAM,
            net::SocketFlags::CLOEXEC,
            None,
        )?;
        net::sockopt::set_socket_reuseaddr(&sock, true)?;
        net::bind(&sock, &e.addr)?;
        net::listen(&sock, 0)?;

        endpoints.push(Endpoint {
            port: e.addr.port(),
            cmd: e.cmd,
            sock: Some(sock),
            pidfd: None,
            errs: ErrBuf::new(),
            state: State::Stopped,
        })
    }

    seccomp::check_struct_sizes()?;

    let sfd = signalfd()?;

    loop {
        // Construct poll fd list based on each endpoint state
        let mut fds: Vec<PollFd> = Vec::new();
        let mut flags: Vec<(usize, Option<&mut PollFlags>)> = Vec::new();
        for (i, e) in endpoints.iter_mut().enumerate() {
            let Some(sock) = &mut e.sock else {
                continue;
            };

            if let Some((pidfd, pidfd_in)) = &mut e.pidfd {
                fds.push(PollFd::new(pidfd, PollFlags::IN));
                flags.push((i, Some(pidfd_in)));
            }

            match &mut e.state {
                State::Stopped => {
                    fds.push(PollFd::new(sock, PollFlags::IN));
                    flags.push((i, None));
                }
                State::NeedSeccompFd { ipc, ipc_in } => {
                    fds.push(PollFd::new(ipc, PollFlags::IN));
                    flags.push((i, Some(ipc_in)));
                }
                State::NeedSeccompNotify {
                    seccomp,
                    seccomp_in,
                } => {
                    fds.push(PollFd::new(seccomp, PollFlags::IN));
                    flags.push((i, Some(seccomp_in)));
                }
                State::Started { timer, timer_in } => {
                    fds.push(PollFd::new(timer, PollFlags::IN));
                    flags.push((i, Some(timer_in)));
                }
                State::Idle {
                    sock_in,
                    timer,
                    timer_in,
                } => {
                    fds.extend([
                        PollFd::new(sock, PollFlags::IN),
                        PollFd::new(timer, PollFlags::IN),
                    ]);
                    flags.extend([(i, Some(sock_in)), (i, Some(timer_in))]);
                }
            }
        }
        fds.push(PollFd::new(&sfd, PollFlags::IN)); // signalfd is last, unpaired

        // Write endpoints/fds with events
        let cnt = event::poll(&mut fds, None)?;

        // Handle signalfd (SIGINT) separately
        if let Some(sfd) = fds.pop()
            && sfd.revents().contains(PollFlags::IN)
        {
            break;
        }

        let mut indices: Vec<usize> = Vec::new();
        for ((i, flag), fd) in flags
            .into_iter()
            .zip(&fds)
            .filter(|(_, fd)| !fd.revents().is_empty())
            .take(cnt)
        {
            if let Some(f) = flag {
                *f = fd.revents();
            }
            if indices.last() != Some(&i) {
                indices.push(i);
            }
        }

        // Update endpoints that have events
        for i in indices {
            let e = &mut endpoints[i];
            if let Err(curr_err) = update_endpoint(e) {
                let now = Instant::now();
                if let Some((first_err, first_time)) =
                    e.errs.push(Some((curr_err, now)))
                {
                    let timeframe = now - first_time;
                    if timeframe > std::time::Duration::new(5, 0) {
                        continue;
                    }

                    eprintln!(
                        concat!(
                            "Received 5 errors in {} ms. ",
                            "Disabling endpoint on port {}\n",
                            "  with command: {:?}\n",
                            "  with errors:"
                        ),
                        timeframe.as_millis(),
                        e.port,
                        e.cmd,
                    );
                    while let Some((err, t)) = e.errs.push(None) {
                        eprintln!(
                            "    {:?} ms: {}",
                            (t - first_time).as_millis(),
                            err
                        );
                    }
                    eprintln!("  with first error: {:?}", first_err);
                    e.sock = None;
                    break;
                }
            }
        }
    }

    Ok(())
}
