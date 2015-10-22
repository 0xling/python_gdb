# encoding:utf-8
__author__ = 'ling'

from ctypes import *


class user_regs_struct(Structure):
    _fields_ = [
        ("ebx", c_uint),
        ("ecx", c_uint),
        ("edx", c_uint),
        ("esi", c_uint),
        ("edi", c_uint),
        ("ebp", c_uint),
        ("eax", c_uint),
        ("xds", c_uint),
        ("xes", c_uint),
        ("xfs", c_uint),
        ("xgs", c_uint),
        ("orig_eax", c_uint),
        ("eip", c_uint),
        ("xcs", c_uint),
        ("eflags", c_uint),
        ("esp", c_uint),
        ("xss", c_uint),
    ]


PTRACE_TRACEME = 0
PTRACE_PEEKTEXT = 1
PTRACE_PEEKDATA = 2
PTRACE_PEEKUSER = 3
PTRACE_POKETEXT = 4
PTRACE_POKEDATA = 5
PTRACE_POKEUSER = 6
PTRACE_CONT = 7
PTRACE_KILL = 8
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_GETFPREGS = 14
PTRACE_SETFPREGS = 15
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_GETFPXREGS = 18
PTRACE_SETFPXREGS = 19
PTRACE_SYSCALL = 24
PTRACE_SETOPTIONS = 0x4200
PTRACE_GETEVENTMSG = 0x4201
PTRACE_GETSIGINFO = 0x4202
PTRACE_SETSIGINFO = 0x4203
PTRACE_GETREGSET = 0x4204
PTRACE_SETREGSET = 0x4205
PTRACE_SEIZE = 0x4206
PTRACE_INTERRUPT = 0x4207
PTRACE_LISTEN = 0x4208
PTRACE_PEEKSIGINFO = 0x4209

PTRACE_O_TRACESYSGOOD = 0x00000001
PTRACE_O_TRACEFORK = 0x00000002
PTRACE_O_TRACEVFORK = 0x00000004
PTRACE_O_TRACECLONE = 0x00000008
PTRACE_O_TRACEEXEC = 0x00000010
PTRACE_O_TRACEVFORKDONE = 0x00000020
PTRACE_O_TRACEEXIT = 0x00000040

# Wait extended result codes for the above trace options
PTRACE_EVENT_FORK = 1
PTRACE_EVENT_VFORK = 2
PTRACE_EVENT_CLONE = 3
PTRACE_EVENT_EXEC = 4
PTRACE_EVENT_VFORK_DONE = 5
PTRACE_EVENT_EXIT = 6

#define self
PTRACE_EVENT_SINGLE_STEP = 7

SIGHUP = 0x1
SIGINT = 0x2
SIGQUIT = 0x3
SIGILL = 0x4
SIGTRAP = 0x5
SIGABRT = 0x6
SIGBUS = 0x7
SIGFPE = 0x8
SIGKILL = 0x9
SIGUSR1 = 0xa
SIGSEGV = 0xb
SIGUSR2 = 0xc
SIGPIPE = 0xd
SIGALRM = 0xe
SIGTERM = 0xf
SIGCHLD = 0x11
SIGCONT = 0x12
SIGSTOP = 0x13
SIGTSTP = 0x14
SIGTTIN = 0x15
SIGTTOU = 0x16
SIGURG = 0x17
SIGXCPU = 0x18
SIGXFSZ = 0x19
SIGVTALRM = 0x1a
SIGPROF = 0x1b
SIGWINCH = 0x1c
SIGPOLL = 0x1d
SIGPWR = 0x1e
SIGSYS = 0x1f
SIGRTMIN = 0x22
SIGRTMAX = 0x40

SIGNAMES = {1: 'SIGHUP', 2: 'SIGINT', 3: 'SIGQUIT', 4: 'SIGILL', 5: 'SIGTRAP', 6: 'SIGABRT', 7: 'SIGBUS', 8: 'SIGFPE', \
            9: 'SIGKILL', 10: 'SIGUSR1', 11: 'SIGSEGV', 12: 'SIGUSR2', 13: 'SIGPIPE', 14: 'SIGALRM', 15: 'SIGTERM', \
            17: 'SIGCHLD', 18: 'SIGCONT', 19: 'SIGSTOP', 20: 'SIGTSTP', 21: 'SIGTTIN', 22: 'SIGTTOU', 23: 'SIGURG', \
            24: 'SIGXCPU', 25: 'SIGXFSZ', 26: 'SIGVTALRM', 27: 'SIGPROF', 28: 'SIGWINCH', 29: 'SIGPOLL', 30: 'SIGPWR', \
            31: 'SIGSYS'}

#From /usr/include/asm-generic/siginfo.h
pid_t = c_int
uid_t = c_ushort
clock_t = c_uint


class _sifields_sigfault_t(Union):
    _fields_ = (
        ("_addr", c_void_p),
    )


class _sifields_sigchld_t(Structure):
    _fields_ = (
        ("pid", pid_t),
        ("uid", uid_t),
        ("status", c_int),
        ("utime", clock_t),
        ("stime", clock_t),
    )


class _sifields_t(Union):
    _fields_ = (
        ("pad", c_char * (128 - 3 * sizeof(c_int))),
        ("_sigchld", _sifields_sigchld_t),
        ("_sigfault", _sifields_sigfault_t),
        #        ("_kill", _sifields_kill_t),
        #        ("_timer", _sifields_timer_t),
        #        ("_rt", _sifields_rt_t),
        #        ("_sigpoll", _sifields_sigpoll_t),
    )


class siginfo(Structure):
    _fields_ = (
        ("si_signo", c_int),
        ("si_errno", c_int),
        ("si_code", c_int),
        ("_sifields", _sifields_t)
    )
    _anonymous_ = ("_sifields",)
