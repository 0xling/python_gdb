# encoding:utf-8
__author__ = 'ling'

import datetime
from os import waitpid, WIFSTOPPED, WIFEXITED, WIFSIGNALED, WEXITSTATUS, WTERMSIG, WSTOPSIG
import sys
import platform

from termcolor import colored
from zio import *

from defines import *
from breakpoint import *
from linux_struct import *
from cpuinfo import *
from libc import *


def stdout(s, color=None, on_color=None, attrs=None):
    if not color:
        sys.stdout.write(s)
    else:
        sys.stdout.write(colored(s, color, on_color, attrs))
    sys.stdout.flush()


def log(s, color=None, on_color=None, attrs=None, new_line=True, timestamp=False, f=sys.stderr):
    if timestamp is True:
        now = datetime.datetime.now().strftime('[%Y-%m-%d_%H:%M:%S]')
    elif timestamp is False:
        now = None
    elif timestamp:
        now = timestamp
    if not color:
        s = str(s)
    else:
        s = colored(str(s), color, on_color, attrs)
    if now:
        f.write(now)
        f.write(' ')
    f.write(s)
    if new_line:
        f.write('\n')
    f.flush()


# only support Linux os
def check_support():
    if platform.architecture()[1] == 'ELF':
        return True
    return False


'''
def disable_stdout_buffering():
    # Appending to gc.garbage is a way to stop an object from being
    # destroyed.  If the old sys.stdout is ever collected, it will
    # close() stdout, which is not good.
    gc.garbage.append(sys.stdout)
    sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
'''

if not check_support():
    raise Exception('pygdb only support Linux os')

if sys.version[0] != "2":
    raise Exception('pygdb only support python2')


class pygdb:
    def __init__(self):
        self._log = lambda msg: sys.stderr.write("PYGDB_LOG> " + msg + "\n")
        # self._log = lambda msg: msg
        self.pid = 0
        # self.regs = user_regs_struct()

        self.single_step_flag = False
        self.trace_sys_call_flag = False

        self.signal_handle_mode = {SIGTRAP: True}

        self.callbacks = {}

        self._restore_breakpoint = None

        self.breakpoints = {}
        self.event_handles = {}
        self.regs = None

        if CPU_64BITS:
            self.bit = 64
            self.byte = 8
        else:
            self.bit = 32
            self.byte = 4

    def load(self, path):
        self._log('path=%s' % path)
        pid = libc_fork()
        if pid == 0:  # child process
            # Then this will give output in the correct order:
            # disable_stdout_buffering()
            self.ptrace(PTRACE_TRACEME, 0, 0, 0)
            libc_execl(path, path, 0)
        else:  # parent
            self.pid = pid
            self._log('pid=%d' % pid)
            (pid, status) = waitpid(self.pid, 0)
            return self.pid

    def attach(self, pid):
        self._log('attach pid=%d' % pid)
        self.ptrace(PTRACE_ATTACH, pid, 0, 0)
        self.pid = pid

    def read(self, address, length):
        self._log('read addr=%x length=%d' % (address, length))
        return self.read_process_memory(address, length)

    # todo
    def read_process_memory(self, address, length):
        self._log('read_process_memory addr=%x length=%d' % (address, length))
        data = ''

        byte = self.byte
        for i in range((length + byte - 1) / byte):
            value = self.ptrace(PTRACE_PEEKDATA, self.pid, address + i * byte, 0)
            self._log('peek:addr=%x value=%x' % (address + i * byte, value))
            if byte == 8:
                data += l64(value)
            else:
                data += l32(value)
        data = data[0:length]
        return data

    def write(self, address, data, length=0):
        self._log('write address=%x data=' % address + repr(data))
        self.write_process_memory(address, data, length)

    # todo
    def print_vmmap(self):
        f = open('/proc/'+str(self.pid)+'/maps', 'rb')
        d = f.read()
        f.close()
        self._log(d)

    # todo
    def write_process_memory(self, address, data, length=0):
        self._log('write_process_memory address=%x data=' % address + repr(data))
        if length == 0:
            length = len(data)

        if length == 0:
            return

        byte = self.byte
        if length % byte:
            data2 = data + self.read_process_memory(address + length, byte - length % byte)

        for i in range(len(data2) / byte):
            if byte == 4:
                self._log('poke:*%08x=%08x' % (address + i * byte, l32(data2[i * byte:i * byte + byte])))
                self.ptrace(PTRACE_POKEDATA, self.pid, address + i * byte, l32(data2[i * byte:i * byte + byte]))
            else:
                self._log('poke:*%08x=%08x' % (address + i * byte, l64(data2[i * byte:i * byte + byte])))
                self.ptrace(PTRACE_POKEDATA, self.pid, address + i * byte, l64(data2[i * byte:i * byte + byte]))

    def run(self):
        self._log('run')
        '''
        if self.pid != 0:
            self._log('')
        '''

        self.set_options(self.pid, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK \
                         | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEVFORKDONE \
                         | PTRACE_O_TRACEEXIT)
        self.debug_event_loop()

    def debug_event_loop(self):
        # continue
        if self.single_step_flag:
            self.ptrace(PTRACE_SINGLESTEP, self.pid, 0, 0)
        elif self.trace_sys_call_flag:
            self.ptrace(PTRACE_SYSCALL, self.pid, 0, 0)
        else:
            self.ptrace(PTRACE_CONT, self.pid, 0, 0)

        while True:
            self.debug_event_iteration()

    def event_handle_process_exit(self, status):
        code = WEXITSTATUS(status)
        self._log('process exited with code:%d' % (code))
        exit(0)

    def event_handle_process_kill(self, status):
        signum = WTERMSIG(status)
        self._log('process killed by a signal:%d' % (signum))
        exit(0)

    def event_handle_process_unknown_status(self, status):
        self._log('unknown process status:%r' % status)
        # raise ProcessError(self, "Unknown process status: %r" % status)
        exit(0)

    def event_handle_process_ptrace_event(self, status):
        event = self.WPTRACEEVENT(status)
        self._log('ptrace event:%d' % event)

    def event_handle_breakpoint(self):
        signum = 0

        if CPU_64BITS:
            bp_addr = self.regs.rip - 1
        else:
            bp_addr = self.regs.eip - 1

        self.write(bp_addr, self.breakpoints[bp_addr].original_byte, 1)

        if CPU_64BITS:
            self.regs.rip = bp_addr
        else:
            self.regs.eip = bp_addr

        self.set_regs(self.regs)

        self._log('handle breakpoint:%08x' % bp_addr)
        if (self.breakpoints.has_key(bp_addr)) & (self.breakpoints[bp_addr].handler is not None):
            signum = self.breakpoints[bp_addr].handler(self)

        if self.breakpoints[bp_addr].restore:
            self.single_step(True)
            self._restore_breakpoint = self.breakpoints[bp_addr]
        else:
            self.breakpoints[bp_addr] = None

        return signum

    def event_handle_single_step(self):
        self.single_step_flag = False
        self._log('handle single step')
        if self._restore_breakpoint is not None:
            # restore breakpoint
            bp = self._restore_breakpoint
            self.bp_set(bp.address, bp.description, bp.restore, bp.handler)
            self._restore_breakpoint = None

        elif (self.event_handles.has_key(PTRACE_EVENT_SINGLE_STEP)) & (
                    self.event_handles[PTRACE_EVENT_SINGLE_STEP] is not None):
            self.event_handles[PTRACE_EVENT_SINGLE_STEP](self)
        return 0

    def event_handle_sigtrap(self):
        self._log('handle sigtrap')
        self.regs = self.get_regs()
        if self.single_step_flag:
            return self.event_handle_single_step()
        if CPU_64BITS:
            if (self.regs.rip - 1) in self.breakpoints.keys():
                return self.event_handle_breakpoint()
        else:
            if (self.regs.eip - 1) in self.breakpoints.keys():
                return self.event_handle_breakpoint()
        return 0

    def event_handle_process_signal(self, status):
        signum = WSTOPSIG(status)
        self._log('signum:%d, %s' % (signum, self.signalName(signum)))

        self.regs = self.get_regs()

        if CPU_64BITS:
            self._log('rip=%08x' % self.regs.rip)
        else:
            self._log('eip=%08x' % self.regs.eip)

        if signum == SIGTRAP:
            return self.event_handle_sigtrap()

        if self.callbacks.has_key(signum):
            return self.callbacks[signum](self)

        if signum == SIGSEGV:
            self.print_vmmap()

        # ret
        if self.signal_handle_mode.has_key(signum):
            ignore = self.signal_handle_mode[signum]
            if ignore:
                return 0
        else:
            return signum

    def bp_del(self, address):
        self._log('bp_del addr=%x' % address)
        if self.breakpoints.has_key(address) & self.breakpoints[address] is not None:
            self.write(address, self.breakpoints[address].original_byte)
            self.breakpoints[address] = None

    def bp_del_all(self):
        self._log('bp_del_all')
        for key in self.breakpoints.keys():
            bp = self.breakpoints[key]
            if bp is not None:
                self.bp_del(bp)

        self.breakpoints = {}

    def signalName(self, signum):
        self._log('signalName:%d' % signum)
        try:
            return SIGNAMES[signum]
        except KeyError:
            return "signal<%s>" % signum

    def set_signal_handle_mode(self, signum, ignore=True):
        self._log('set_signal_handle_mode:signum=%d' % signum)
        self.signal_handle_mode[signum] = ignore

    def debug_event_iteration(self):
        (pid, status) = waitpid(self.pid, 0)
        signum = 0

        self._log('status:%r' % (status))

        # Process exited?
        if WIFEXITED(status):
            self.event_handle_process_exit(status)

        # Process killed by a signal?
        elif WIFSIGNALED(status):
            self.event_handle_process_kill(status)

        # Invalid process status?
        elif not WIFSTOPPED(status):
            self.event_handle_process_unknown_status(status)

        # Ptrace event?
        elif self.WPTRACEEVENT(status):
            self.event_handle_process_ptrace_event(status)

        else:
            signum = self.event_handle_process_signal(status)

        # continue
        if self.single_step_flag:
            self.ptrace(PTRACE_SINGLESTEP, self.pid, 0, signum)
        elif self.trace_sys_call_flag:
            self.ptrace(PTRACE_SYSCALL, self.pid, 0, signum)
        else:
            self.ptrace(PTRACE_CONT, self.pid, 0, signum)

    def ptrace(self, command, pid, arg1, arg2):
        self._log('ptrace command=%d' % command)
        peek_commands = [PTRACE_PEEKDATA, PTRACE_PEEKSIGINFO, PTRACE_PEEKTEXT, PTRACE_PEEKUSER]
        if command in peek_commands:
            data = libc_ptrace(command, pid, arg1, arg2)
            '''
            if data == -1:
                self._log('ptrace error1')
                _perror()
                return None
            '''
            return data

        if libc_ptrace(command, pid, arg1, arg2) == -1:
            self._log('ptrace error2:%d' % command)
            libc_perror()

    def detach(self, signum=0):
        self._log('detach')
        self.ptrace(PTRACE_DETACH, self.pid, 0, signum)
        self.pid = 0

    def kill(self):
        self._log('kill')
        self.ptrace(PTRACE_KILL, self.pid, 0, 0)

    '''
    def peek(self, addr):
        return self.ptrace(PTRACE_PEEKTEXT, self.pid, addr, 0)

    def poke(self, address, word):
        self.ptrace(PTRACE_POKETEXT, self.pid, address, word)
    '''

    '''
    def get_siginfo(self):
        info = siginfo()
        self.ptrace(PTRACE_GETSIGINFO, self.pid, 0, addressof(info))
        return info

    def set_siginfo(self, info):
        self.ptrace(PTRACE_SETSIGINFO, self.pid, 0, addressof(info))
    '''

    '''
    def ptrace_getfpregs(pid):
        fpregs = user_fpregs_struct()
        ptrace(PTRACE_GETFPREGS, pid, 0, addressof(fpregs))
        return fpregs

    def ptrace_setfpregs(self, pid, fpregs):
        ptrace(PTRACE_SETFPREGS, pid, 0, addressof(fpregs))

    def ptrace_getfpxregs(self, pid):
        fpxregs = user_fpxregs_struct()
        self.ptrace(PTRACE_GETFPXREGS, pid, 0, addressof(fpxregs))
        return fpxregs

    def ptrace_setfpxregs(self, pid, fpxregs):
        self.ptrace(PTRACE_SETFPXREGS, pid, 0, addressof(fpxregs))
    '''

    def get_regs(self):
        self._log('get regs')
        regs = user_regs_struct()
        self.ptrace(PTRACE_GETREGS, self.pid, 0, addressof(regs))
        return regs

    def bp_set(self, address, description="", restore=True, handler=None):
        self._log('bp_set address=%x' % address)
        # print hex(address)
        original_byte = self.read(address, 1)
        # print HEX(original_byte)
        self.write(address, '\xcc')
        # now_byte = self.read(address, 4)
        # print HEX(now_byte)
        self.breakpoints[address] = breakpoint(address, original_byte, description, restore, handler)

    def set_regs(self, regs):
        self._log('set_regs')
        self.ptrace(PTRACE_SETREGS, self.pid, 0, addressof(regs))

    def WPTRACEEVENT(self, status):
        return status >> 16

    def set_options(self, pid, options):
        self.ptrace(PTRACE_SETOPTIONS, pid, 0, options)

    def get_eventmsg(self):
        new_pid = pid_t()
        self.ptrace(PTRACE_GETEVENTMSG, self.pid, 0, addressof(new_pid))
        return new_pid.value

    def single_step(self, enable):
        self.single_step_flag = enable

    def trace_sys_call(self, enable):
        self.trace_sys_call_flag = enable

    def follow_fork(self, mode):
        pass

    def follow_exec(self, mode):
        pass

    def bp_del_hw(self, address):
        pass

    def bp_del_hw_all(self):
        pass

    def bp_del_mem_all(self):
        pass

    def bp_is_ours(self, address_to_check):
        pass

    def bp_is_ours_mem(self, address_to_check):
        pass

    def bp_set_hw(self, address, length, condition, restore=True, handler=None):
        pass

    def dbg_print_all_debug_registers(self):
        pass

    def dbg_print_all_guarded_pages(self):
        pass

    def exception_handler_guard_page(self):
        pass

    '''
    def func_resolve(self, dll, function):
        pass
    '''

    def get_attr(self, attribute):
        if not hasattr(self, attribute):
            return None

        return getattr(self, attribute)

    def hide_debugger(self):
        pass

    def set_attr(self, attribute, value):
        if hasattr(self, attribute):
            setattr(self, attribute, value)

    def set_callback(self, signum, callback_func=None):
        self.callbacks[signum] = callback_func

    def set_event_handle(self, event_code, handler=None):
        self.event_handles[event_code] = handler
