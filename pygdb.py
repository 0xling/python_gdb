# encoding:utf-8
__author__ = 'ling'

from ctypes import *
from os import waitpid, WIFSTOPPED, WIFEXITED, WIFSIGNALED, WEXITSTATUS, WTERMSIG, WSTOPSIG
import sys
from zio import *
from defines import *
from breakpoint import *


libc = CDLL('libc.so.6')

_fork = libc.fork
_execl = libc.execl
_ptrace = libc.ptrace
_errno = libc.errno
_perror = libc.perror


class pygdb:
    def __init__(self):
        self._log = lambda msg: sys.stderr.write("PYGDB_LOG> " + msg + "\n")
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


    def load(self, path):
        pid = _fork()
        if pid == 0:  # child process
            self.ptrace(PTRACE_TRACEME, 0, 0, 0)
            _execl(path, path, 0)
        else:  # parent
            self.pid = pid
            self._log('pid=%d' % pid)
            (pid, status) = waitpid(self.pid, 0)
            return self.pid

    def attach(self, pid):
        self.ptrace(PTRACE_ATTACH, pid, 0, 0)
        self.pid = pid

    def read(self, address, length):
        return self.read_process_memory(address, length)

    #todo
    def read_process_memory(self, address, length):
        # to modify
        offset = address & 0x3
        align_addr = address & 0xfffffffc
        align_length = length + offset
        data = ''
        for i in range((align_length + 3) / 4):
            value = self.ptrace(PTRACE_PEEKTEXT, self.pid, align_addr, 0)
            data += l32(value)

        data = data[offset:offset + length]

        return data


    def write(self, address, data, length=0):
        self.write_process_memory(address, data, length)

    #todo
    def write_process_memory(self, address, data, length=0):
        if length == 0:
            length = len(data)

        if length == 0:
            return

        offset = address & 0x3
        align_addr = address & 0xfffffffc
        align_length = length + offset

        #print align_length

        if offset != 0:
            value = self.read_process_memory(align_addr, offset)
            data = value + data

        if align_length & 0x3:
            value = self.read_process_memory(align_addr + align_length, (4 - (align_length & 3)))
            data += value
            align_length += 4 - (align_length & 3)

        #print 'data:' + HEX(data) + ':' + hex(align_length)
        for i in range(align_length / 4):
            self._log('poke:*%08x=%08x'%(align_addr+i*4, l32(data[i*4:i*4+4])))
            self.ptrace(PTRACE_POKETEXT, self.pid, align_addr + i * 4, l32(data[i * 4:i * 4 + 4]))

    def run(self):
        if self.pid != 0:
            self._log('')


        self.set_options(self.pid, PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK\
                                   |PTRACE_O_TRACECLONE|PTRACE_O_TRACEEXEC|PTRACE_O_TRACEVFORKDONE\
                                   |PTRACE_O_TRACEEXIT)
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
        bp_addr = self.regs.eip - 1

        self.write(bp_addr, self.breakpoints[bp_addr].original_byte, 1)

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
            #resotre breakpoint
            bp = self._restore_breakpoint
            self.bp_set(bp.address, bp.description, bp.restore, bp.handler)
            self._restore_breakpoint = None

        elif (self.event_handles.has_key(PTRACE_EVENT_SINGLE_STEP)) & (
                self.event_handles[PTRACE_EVENT_SINGLE_STEP] is not None):
            self.event_handles[PTRACE_EVENT_SINGLE_STEP](self)
        return 0


    def event_handle_sigtrap(self):
        self.regs = self.get_regs()
        if self.single_step_flag:
            return self.event_handle_single_step()
        if (self.regs.eip - 1) in self.breakpoints.keys():
            return self.event_handle_breakpoint()


    def event_handle_process_signal(self, status):
        signum = WSTOPSIG(status)
        self._log('signum:%d, %s' % (signum, self.signalName(signum)))

        self.regs = self.get_regs()

        self._log('eip=%08x' % self.regs.eip)

        if signum == SIGTRAP:
            return self.event_handle_sigtrap()

        if self.callbacks.has_key(signum):
            return self.callbacks[signum](self)

        #ret
        if self.signal_handle_mode.has_key(signum):
            ignore = self.signal_handle_mode[signum]
            if ignore:
                return 0
        else:
            return signum

    def bp_del(self, address):
        if self.breakpoints.has_key(address) & self.breakpoints[address] is not None:
            self.write(address, self.breakpoints[address].original_byte)
            self.breakpoints[address] = None

    def bp_del_all(self, address):
        for key in self.breakpoints.keys():
            bp = self.breakpoints[key]
            if bp is not None:
                self.bp_del(address)

        self.breakpoints = {}

    def signalName(self, signum):
        try:
            return SIGNAMES[signum]
        except KeyError:
            return "signal<%s>" % signum

    def set_signal_handle_mode(self, signum, ignore=True):
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
        peek_commands = [PTRACE_PEEKDATA, PTRACE_PEEKSIGINFO, PTRACE_PEEKTEXT, PTRACE_PEEKUSER]
        if command in peek_commands:
            data = _ptrace(command, pid, arg1, arg2)
            '''
            if data == -1:
                self._log('ptrace error1')
                _perror()
                return None
            '''
            return data

        if _ptrace(command, pid, arg1, arg2) == -1:
            self._log('ptrace error2:%d' % command)
            _perror()

    def detach(self, signum=0):
        self.ptrace(PTRACE_DETACH, self.pid, 0, signum)
        self.pid = 0

    def kill(self):
        self.ptrace(PTRACE_KILL, self.pid, 0, 0)

    '''
    def peek(self, addr):
        return self.ptrace(PTRACE_PEEKTEXT, self.pid, addr, 0)

    def poke(self, address, word):
        self.ptrace(PTRACE_POKETEXT, self.pid, address, word)
    '''

    def get_siginfo(self):
        info = siginfo()
        self.ptrace(PTRACE_GETSIGINFO, self.pid, 0, addressof(info))
        return info

    def set_siginfo(self, info):
        self.ptrace(PTRACE_SETSIGINFO, self.pid, 0, addressof(info))

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
        regs = user_regs_struct()
        self.ptrace(PTRACE_GETREGS, self.pid, 0, addressof(regs))
        return regs

    def bp_set(self, address, description="", restore=True, handler=None):
        #print hex(address)
        original_byte = self.read(address, 1)
        #print HEX(original_byte)
        self.write(address, '\xcc')
        #now_byte = self.read(address, 4)
        #print HEX(now_byte)
        self.breakpoints[address] = breakpoint(address, original_byte, description, restore, handler)

    def set_regs(self, regs):
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


