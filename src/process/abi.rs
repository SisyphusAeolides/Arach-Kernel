//! Process execution personalities.
//!
//! Arach's native services use the Aether syscall numbering.  Linux user
//! space uses the x86-64 Linux syscall ABI, which is a separate contract even
//! when both personalities execute System V AMD64 code.  Keeping the
//! personality in immutable launch metadata prevents a Linux image from
//! being dispatched through the native table by accident.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExecutionAbi {
    ArachNative = 0,
    LinuxX86_64 = 1,
}

impl ExecutionAbi {
    pub const fn is_linux(self) -> bool {
        matches!(self, Self::LinuxX86_64)
    }
}

/// Linux x86-64 syscall numbers needed by the initial COSMIC userspace
/// bring-up.  The list is deliberately explicit: an unlisted syscall is not
/// silently treated as a native Aether syscall.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxSyscall {
    Read,
    Write,
    Writev,
    Open,
    Close,
    Stat,
    Fstat,
    Poll,
    Pipe,
    Lseek,
    Mmap,
    Mprotect,
    Munmap,
    Brk,
    RtSigaction,
    RtSigprocmask,
    RtSigreturn,
    Kill,
    Ioctl,
    Dup,
    Dup2,
    Dup3,
    Pipe2,
    Nanosleep,
    Getpid,
    Getppid,
    Uname,
    Getuid,
    Getgid,
    Geteuid,
    Getegid,
    ArchPrctl,
    Clone,
    Fork,
    Vfork,
    Execve,
    Exit,
    Wait4,
    Fcntl,
    Ftruncate,
    Mkdir,
    MkdirAt,
    Socket,
    Connect,
    Accept,
    Accept4,
    Sendto,
    Recvfrom,
    Sendmsg,
    Recvmsg,
    Shutdown,
    Bind,
    Listen,
    Getsockname,
    Getpeername,
    Socketpair,
    Setsockopt,
    Getsockopt,
    EpollWait,
    EpollCreate1,
    EpollCtl,
    EpollPwait,
    Eventfd2,
    TimerfdCreate,
    TimerfdSettime,
    TimerfdGettime,
    ClockGettime,
    ClockNanosleep,
    Futex,
    SetTidAddress,
    SetRobustList,
    GetRobustList,
    OpenAt,
    UnlinkAt,
    Ppoll,
    Unshare,
    InotifyInit1,
    InotifyAddWatch,
    InotifyRmWatch,
    Getrandom,
    MemfdCreate,
    Prlimit64,
    Gettid,
    ExitGroup,
    Tgkill,
    Rseq,
    InitModule,
    DeleteModule,
    FinitModule,
    Syslog,
}

impl LinuxSyscall {
    /// Decode the stable x86-64 Linux syscall number table.
    pub const fn from_number(number: usize) -> Option<Self> {
        match number {
            0 => Some(Self::Read),
            1 => Some(Self::Write),
            20 => Some(Self::Writev),
            2 => Some(Self::Open),
            3 => Some(Self::Close),
            4 => Some(Self::Stat),
            5 => Some(Self::Fstat),
            7 => Some(Self::Poll),
            22 => Some(Self::Pipe),
            8 => Some(Self::Lseek),
            9 => Some(Self::Mmap),
            10 => Some(Self::Mprotect),
            11 => Some(Self::Munmap),
            12 => Some(Self::Brk),
            13 => Some(Self::RtSigaction),
            14 => Some(Self::RtSigprocmask),
            15 => Some(Self::RtSigreturn),
            62 => Some(Self::Kill),
            16 => Some(Self::Ioctl),
            32 => Some(Self::Dup),
            33 => Some(Self::Dup2),
            35 => Some(Self::Nanosleep),
            39 => Some(Self::Getpid),
            63 => Some(Self::Uname),
            102 => Some(Self::Getuid),
            104 => Some(Self::Getgid),
            107 => Some(Self::Geteuid),
            108 => Some(Self::Getegid),
            110 => Some(Self::Getppid),
            158 => Some(Self::ArchPrctl),
            41 => Some(Self::Socket),
            42 => Some(Self::Connect),
            43 => Some(Self::Accept),
            44 => Some(Self::Sendto),
            45 => Some(Self::Recvfrom),
            46 => Some(Self::Sendmsg),
            47 => Some(Self::Recvmsg),
            48 => Some(Self::Shutdown),
            49 => Some(Self::Bind),
            50 => Some(Self::Listen),
            51 => Some(Self::Getsockname),
            52 => Some(Self::Getpeername),
            53 => Some(Self::Socketpair),
            54 => Some(Self::Setsockopt),
            55 => Some(Self::Getsockopt),
            56 => Some(Self::Clone),
            57 => Some(Self::Fork),
            58 => Some(Self::Vfork),
            59 => Some(Self::Execve),
            60 => Some(Self::Exit),
            61 => Some(Self::Wait4),
            72 => Some(Self::Fcntl),
            77 => Some(Self::Ftruncate),
            83 => Some(Self::Mkdir),
            202 => Some(Self::Futex),
            218 => Some(Self::SetTidAddress),
            228 => Some(Self::ClockGettime),
            230 => Some(Self::ClockNanosleep),
            231 => Some(Self::ExitGroup),
            234 => Some(Self::Tgkill),
            232 => Some(Self::EpollWait),
            233 => Some(Self::EpollCtl),
            257 => Some(Self::OpenAt),
            258 => Some(Self::MkdirAt),
            263 => Some(Self::UnlinkAt),
            271 => Some(Self::Ppoll),
            272 => Some(Self::Unshare),
            273 => Some(Self::SetRobustList),
            274 => Some(Self::GetRobustList),
            281 => Some(Self::EpollPwait),
            283 => Some(Self::TimerfdCreate),
            286 => Some(Self::TimerfdSettime),
            287 => Some(Self::TimerfdGettime),
            288 => Some(Self::Accept4),
            290 => Some(Self::Eventfd2),
            291 => Some(Self::EpollCreate1),
            292 => Some(Self::Dup3),
            293 => Some(Self::Pipe2),
            294 => Some(Self::InotifyInit1),
            254 => Some(Self::InotifyAddWatch),
            255 => Some(Self::InotifyRmWatch),
            302 => Some(Self::Prlimit64),
            318 => Some(Self::Getrandom),
            319 => Some(Self::MemfdCreate),
            334 => Some(Self::Rseq),
            186 => Some(Self::Gettid),
            103 => Some(Self::Syslog),
            175 => Some(Self::InitModule),
            176 => Some(Self::DeleteModule),
            313 => Some(Self::FinitModule),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_and_linux_personalities_are_distinct() {
        assert!(!ExecutionAbi::ArachNative.is_linux());
        assert!(ExecutionAbi::LinuxX86_64.is_linux());
        assert_ne!(ExecutionAbi::ArachNative, ExecutionAbi::LinuxX86_64);
    }

    #[test]
    fn decodes_the_syscalls_needed_by_the_first_cosmic_boundary() {
        assert_eq!(LinuxSyscall::from_number(1), Some(LinuxSyscall::Write));
        assert_eq!(LinuxSyscall::from_number(9), Some(LinuxSyscall::Mmap));
        assert_eq!(LinuxSyscall::from_number(16), Some(LinuxSyscall::Ioctl));
        assert_eq!(LinuxSyscall::from_number(0), Some(LinuxSyscall::Read));
        assert_eq!(LinuxSyscall::from_number(3), Some(LinuxSyscall::Close));
        assert_eq!(LinuxSyscall::from_number(39), Some(LinuxSyscall::Getpid));
        assert_eq!(LinuxSyscall::from_number(110), Some(LinuxSyscall::Getppid));
        assert_eq!(
            LinuxSyscall::from_number(158),
            Some(LinuxSyscall::ArchPrctl)
        );
        assert_eq!(LinuxSyscall::from_number(202), Some(LinuxSyscall::Futex));
        assert_eq!(LinuxSyscall::from_number(62), Some(LinuxSyscall::Kill));
        assert_eq!(LinuxSyscall::from_number(234), Some(LinuxSyscall::Tgkill));
        assert_eq!(
            LinuxSyscall::from_number(273),
            Some(LinuxSyscall::SetRobustList)
        );
        assert_eq!(
            LinuxSyscall::from_number(274),
            Some(LinuxSyscall::GetRobustList)
        );
        assert_eq!(LinuxSyscall::from_number(257), Some(LinuxSyscall::OpenAt));
        assert_eq!(
            LinuxSyscall::from_number(294),
            Some(LinuxSyscall::InotifyInit1)
        );
        assert_eq!(LinuxSyscall::from_number(290), Some(LinuxSyscall::Eventfd2));
        assert_eq!(
            LinuxSyscall::from_number(283),
            Some(LinuxSyscall::TimerfdCreate)
        );
        assert_eq!(
            LinuxSyscall::from_number(286),
            Some(LinuxSyscall::TimerfdSettime)
        );
        assert_eq!(
            LinuxSyscall::from_number(287),
            Some(LinuxSyscall::TimerfdGettime)
        );
        assert_eq!(LinuxSyscall::from_number(7), Some(LinuxSyscall::Poll));
        assert_eq!(LinuxSyscall::from_number(22), Some(LinuxSyscall::Pipe));
        assert_eq!(LinuxSyscall::from_number(41), Some(LinuxSyscall::Socket));
        assert_eq!(LinuxSyscall::from_number(42), Some(LinuxSyscall::Connect));
        assert_eq!(LinuxSyscall::from_number(43), Some(LinuxSyscall::Accept));
        assert_eq!(LinuxSyscall::from_number(44), Some(LinuxSyscall::Sendto));
        assert_eq!(LinuxSyscall::from_number(45), Some(LinuxSyscall::Recvfrom));
        assert_eq!(LinuxSyscall::from_number(46), Some(LinuxSyscall::Sendmsg));
        assert_eq!(LinuxSyscall::from_number(47), Some(LinuxSyscall::Recvmsg));
        assert_eq!(LinuxSyscall::from_number(48), Some(LinuxSyscall::Shutdown));
        assert_eq!(LinuxSyscall::from_number(49), Some(LinuxSyscall::Bind));
        assert_eq!(LinuxSyscall::from_number(50), Some(LinuxSyscall::Listen));
        assert_eq!(
            LinuxSyscall::from_number(51),
            Some(LinuxSyscall::Getsockname)
        );
        assert_eq!(
            LinuxSyscall::from_number(52),
            Some(LinuxSyscall::Getpeername)
        );
        assert_eq!(
            LinuxSyscall::from_number(53),
            Some(LinuxSyscall::Socketpair)
        );
        assert_eq!(
            LinuxSyscall::from_number(54),
            Some(LinuxSyscall::Setsockopt)
        );
        assert_eq!(
            LinuxSyscall::from_number(55),
            Some(LinuxSyscall::Getsockopt)
        );
        assert_eq!(LinuxSyscall::from_number(292), Some(LinuxSyscall::Dup3));
        assert_eq!(LinuxSyscall::from_number(293), Some(LinuxSyscall::Pipe2));
        assert_eq!(LinuxSyscall::from_number(77), Some(LinuxSyscall::Ftruncate));
        assert_eq!(
            LinuxSyscall::from_number(319),
            Some(LinuxSyscall::MemfdCreate)
        );
        assert_eq!(LinuxSyscall::from_number(288), Some(LinuxSyscall::Accept4));
        assert_eq!(
            LinuxSyscall::from_number(232),
            Some(LinuxSyscall::EpollWait)
        );
        assert_eq!(LinuxSyscall::from_number(233), Some(LinuxSyscall::EpollCtl));
        assert_eq!(LinuxSyscall::from_number(83), Some(LinuxSyscall::Mkdir));
        assert_eq!(LinuxSyscall::from_number(258), Some(LinuxSyscall::MkdirAt));
        assert_eq!(
            LinuxSyscall::from_number(281),
            Some(LinuxSyscall::EpollPwait)
        );
        assert_eq!(
            LinuxSyscall::from_number(291),
            Some(LinuxSyscall::EpollCreate1)
        );
        assert_eq!(
            LinuxSyscall::from_number(318),
            Some(LinuxSyscall::Getrandom)
        );
        assert_eq!(LinuxSyscall::from_number(999), None);
    }
}
