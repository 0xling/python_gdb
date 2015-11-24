#!/usr/bin/python2 -u
# encoding:utf-8
import os
import socket

__author__ = 'ling'

from os import waitpid, WIFSTOPPED, WIFEXITED, WIFSIGNALED, WEXITSTATUS, WTERMSIG, WSTOPSIG
import sys
from zio import *
from breakpoint import *
from linux_struct import *
from cpuinfo import *
from libc import *
from strace import *

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO
from utils import *

import logging
# 创建一个logger
logger = logging.getLogger('pygdb')
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def add_console_logger(level=logging.DEBUG):
    ch = logging.StreamHandler()
    ch.setLevel(level)
    # 定义handler的输出格式
    ch.setFormatter(formatter)
    # 给logger添加handler
    logger.addHandler(ch)


def add_file_logger(file, level=logging.DEBUG):
    fh = logging.FileHandler(file)
    fh.setLevel(level)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

from ptrace.debugger.backtrace import getBacktrace


add_file_logger('pygdb.log')
#add_console_logger()

if not check_support():
    raise Exception('pygdb only support Linux os')

if sys.version[0] != "2":
    raise Exception('pygdb only support python2')


class pygdb:
    def __init__(self):
        self.pid = 0

        self.single_step_flag = False
        self.trace_sys_call_flag = False

        self.signal_handle_mode = {SIGTRAP: True}  # 字典，表示是否忽视该信号。如果忽视该信号，该信号将不会发送给被调试进程。

        self.callbacks = {}  # 字典，对应每个信号 有个对应的处理函数。 处理函数的返回值为返回给被调试程序的信号值。如果忽视该信号，返回0.

        self._restore_breakpoint = None  # 全局的一个标记，用于记录需要恢复的断点。
        # 断点的实现是将该地址改写为\xcc，如果需要恢复断点，那么需要将该地址改写为原来字节，
        # 同时单步运行，然后再次将该地址重写为\xcc，
        # 这里用_restore_braekpoint 临时记录下该断点。

        self.breakpoints = {}  # 所有的断点，以断点地址作为key值。
        self.event_handles = {}  # 对应事件的handler。
        # 共有6个事件，其中主要有EXEC和FORK事件。

        # 这里，还对event_hanles做了扩展，将单步断点等的处理函数也添加到event_handles中，但是在ptrace中并没有单步事件的说法。
        self.regs = None  # 寄存器，每次断下之后，都会读取寄存器放入到self.regs中。

        if CPU_64BITS:
            self.bit = 64
            self.byte = 8
        else:
            self.bit = 32
            self.byte = 4

        self.trace_fork = True
        self.trace_exec = True
        self.trace_clone = True

        self.enter_sys_call = False

    #####################################################################################
    # some operation of start/close debug
    # load a pe file
    def load(self, target):
        logger.debug('target=%s' % target)
        args = split_command_line(target)
        #print args
        command = args[0]
        pid = libc_fork()
        if pid == 0:  # child process
            self._ptrace(PTRACE_TRACEME, 0, 0, 0)
            os.execv(command, args)
        else:  # parent
            (pid, status) = waitpid(self.pid, 0)
            self.pid = pid
            logger.debug('pid=%d' % pid)
            return self.pid

    # attach a running process
    def attach(self, pid):
        logger.debug('attach pid=%d' % pid)
        self._ptrace(PTRACE_ATTACH, pid, 0, 0)
        self.pid = pid

    # detach a debugged process
    def detach(self, signum=0):
        logger.debug('detached')
        self._ptrace(PTRACE_DETACH, self.pid, 0, signum)
        self.pid = 0

    # kill the debugged process
    def kill(self):
        logger.debug('killed')
        self._ptrace(PTRACE_KILL, self.pid, 0, 0)

    #################################################################################
    # about the stdout
    # redir the stdout to a network port
    def redir_stdout(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))

        fd = sock.makefile('w')
        sys.stdout = fd
        sys.stdin = fd
        sys.stderr = fd

    #################################################################################
    # about the memory and regs operation
    def read(self, address, length):
        logger.debug('read addr=%x length=%d' % (address, length))
        return self._read_process_memory(address, length)

    # todo
    def _read_process_memory(self, address, length):
        # self._log('read_process_memory addr=%x length=%d' % (address, length))
        data = ''

        byte = self.byte
        for i in range((length + byte - 1) / byte):
            value = self._ptrace(PTRACE_PEEKDATA, self.pid, address + i * byte, 0)
            # self._log('peek:addr=%x value=%x' % (address + i * byte, value))
            if byte == 8:
                data += l64(value)
            else:
                data += l32(value)
        data = data[0:length]
        return data

    def write(self, address, data, length=0):
        logger.debug('write address=%x data=' % address + repr(data))
        self._write_process_memory(address, data, length)

    # todo
    def _write_process_memory(self, address, data, length=0):
        if length == 0:
            length = len(data)

        if length == 0:
            return

        tmp_data = data
        byte = self.byte
        if length % byte:
            tmp_data += self._read_process_memory(address + length, byte - length % byte)

        for i in range(len(tmp_data) / byte):
            if byte == 4:
                self._ptrace(PTRACE_POKEDATA, self.pid, address + i * byte, l32(tmp_data[i * byte:i * byte + byte]))
            else:
                self._ptrace(PTRACE_POKEDATA, self.pid, address + i * byte, l64(tmp_data[i * byte:i * byte + byte]))

    def get_regs(self):
        regs = user_regs_struct()
        self._ptrace(PTRACE_GETREGS, self.pid, 0, addressof(regs))
        return regs

    def set_regs(self, regs):
        self._ptrace(PTRACE_SETREGS, self.pid, 0, addressof(regs))

    ########################################################################
    # about the /proc operation
    # todo
    def print_vmmap(self):
        maps_file_path = '/proc/' + str(self.pid) + '/maps'
        f = open(maps_file_path, 'rb')
        d = f.read()
        f.close()

    ##############################################################################
    # about the breakpoint
    def bp_del(self, address):
        logger.debug('bp_del address=%x' % address)
        if (address in self.breakpoints.keys()) & (self.breakpoints[address] is not None):
            self.write(address, self.breakpoints[address].original_byte)
            self.breakpoints[address] = None

    def bp_del_all(self):
        logger.debug('bp_del_all')
        for key in self.breakpoints.keys():
            bp = self.breakpoints[key]
            if bp is not None:
                self.bp_del(bp)

        self.breakpoints = {}

    def bp_set(self, address, description="", restore=True, handler=None):
        logger.debug('bp_set address=%x' % address)
        original_byte = self.read(address, 1)
        self.write(address, '\xcc')
        self.breakpoints[address] = breakpoint(address, original_byte, description, restore, handler)

    #################################################################################
    def set_signal_handle_mode(self, signum, ignore=True):
        self.signal_handle_mode[signum] = ignore

    def set_options(self, pid, options):
        self._ptrace(PTRACE_SETOPTIONS, pid, 0, options)

    def set_callback(self, signum, callback_func=None):
        self.callbacks[signum] = callback_func

    def set_event_handle(self, event_code, handler=None):
        self.event_handles[event_code] = handler

    def single_step(self, enable):
        self.single_step_flag = enable

    def trace_sys_call(self, enable):
        self.trace_sys_call_flag = enable

    # True: trace child
    def follow_fork(self, mode):
        self.trace_fork = mode

    # True: trace parent
    def follow_exec(self, mode):
        self.trace_exec = mode

    def follow_clone(self, mode):
        self.trace_clone = mode

    ##########################################################################
    # about the debug event loop

    '''
        run(self):
        _debug_event_loop(self):
            _debug_event_iteration()
                #only exit
                _event_handle_process_exit(status)
                #only exit
                _event_handle_process_kill(status)
                #only exit
                _event_handle_process_unknown_status(status)
                #ptrace event
                _event_handle_process_ptrace_event(status)
                #signal event
                _event_handle_process_signal(status)
                    _event_handle_sigtrap()
                        _event_handle_single_step()
                        _event_handle_breakpoint()
                            self.breakpoints[bp_addr].handler
                    self.callbacks[signum](self)
    '''

    def run(self):
        options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | \
                  PTRACE_O_TRACEEXEC | PTRACE_O_TRACEVFORKDONE | PTRACE_O_TRACEEXIT

        self.set_options(self.pid, options)
        self._debug_event_loop()

    def _debug_event_loop(self):
        # continue
        if self.single_step_flag:
            self._ptrace(PTRACE_SINGLESTEP, self.pid, 0, 0)
        elif self.trace_sys_call_flag:
            self._ptrace(PTRACE_SYSCALL, self.pid, 0, 0)
        else:
            self._ptrace(PTRACE_CONT, self.pid, 0, 0)

        while True:
            self._debug_event_iteration()

    def _event_handle_process_exit(self, status):
        code = WEXITSTATUS(status)
        logger.debug('process exited with code:%d' % code)
        exit(0)

    def _event_handle_process_kill(self, status):
        signum = WTERMSIG(status)
        logger.debug('process killed by a signal:%d' % signum)
        exit(0)

    def _event_handle_process_unknown_status(self, status):
        logger.debug('unknown process status:%r' % status)
        exit(0)

    def _event_handle_process_ptrace_event(self, status):
        event = self.WPTRACEEVENT(status)
        logger.debug('ptrace event:%d-%s' % (event, event_name(event)))

        if event in self.event_handles.keys():
            self.event_handles[event](self)

        if event == PTRACE_EVENT_FORK:
            new_pid = pid_t()
            self._ptrace(PTRACE_GETEVENTMSG, self.pid, 0, addressof(new_pid))
            print 'fork a child child:%d' % new_pid.value
            if self.trace_fork:
                self.pid = new_pid.value
            else:
                logger.info('fork a child process:%d' % new_pid.value)

        elif event == PTRACE_EVENT_VFORK:
            logger.info('vfork event not support')
        elif event == PTRACE_EVENT_CLONE:
            new_pid = pid_t()
            self._ptrace(PTRACE_GETEVENTMSG, self.pid, 0, addressof(new_pid))
            print 'clone a child child:%d' % new_pid.value
            if self.trace_clone:
                self.pid = new_pid.value
            else:
                logger.info('clone a chile process:%d' % new_pid)
        elif event == PTRACE_EVENT_EXEC:
            logger.info('exec event not support')
        elif event == PTRACE_EVENT_VFORK_DONE:
            logger.info('vfork event not support')
        elif event == PTRACE_EVENT_EXIT:
            pass

    def _event_handle_breakpoint(self):
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

        logger.debug('handle breakpoint:%08x' % bp_addr)
        if (bp_addr in self.breakpoints.keys()) & (self.breakpoints[bp_addr].handler is not None):
            signum = self.breakpoints[bp_addr].handler(self)

        if self.breakpoints[bp_addr].restore:
            self.single_step(True)
            self._restore_breakpoint = self.breakpoints[bp_addr]
        else:
            self.breakpoints[bp_addr] = None

        return signum

    def _event_handle_sys_call(self):
        if CPU_64BITS:
            cur_pc = self.regs.rip - 2
            sys_name = SYSCALL_NAMES[self.regs.orig_rax]
            arg0 = self.regs.rdi
            arg1 = self.regs.rsi
            arg2 = self.regs.rdx
        else:
            cur_pc = self.regs.eip - 2
            sys_name = SYSCALL_NAMES[self.regs.orig_eax]
            arg0 = self.regs.ebx
            arg1 = self.regs.ecx
            arg2 = self.regs.edx

        if sys_call_handlers.has_key(sys_name):
            sys_call_handlers[sys_name](self, cur_pc, sys_name, arg0, arg1, arg2, self.enter_sys_call)
        else:
            default_sys_call_handler(self, cur_pc, sys_name, arg0, arg1, arg2, self.enter_sys_call)
        if self.enter_sys_call:
            self.enter_sys_call = False
        else:
            self.enter_sys_call = True
        return 0

    def _event_handle_single_step(self):
        self.single_step_flag = False
        logger.debug('handle single step')
        if self._restore_breakpoint is not None:
            # restore breakpoint
            bp = self._restore_breakpoint
            self.bp_set(bp.address, bp.description, bp.restore, bp.handler)
            self._restore_breakpoint = None

        elif (PTRACE_EVENT_SINGLE_STEP in self.event_handles.keys()) & \
                (self.event_handles[PTRACE_EVENT_SINGLE_STEP] is not None):
            self.event_handles[PTRACE_EVENT_SINGLE_STEP](self)
        return 0

    def _event_handle_sigtrap(self):
        logger.debug('handle sigtrap')
        self.regs = self.get_regs()

        if self.single_step_flag:
            return self._event_handle_single_step()

        if CPU_64BITS:
            if (self.regs.rip - 1) in self.breakpoints.keys():
                return self._event_handle_breakpoint()
        else:
            if (self.regs.eip - 1) in self.breakpoints.keys():
                return self._event_handle_breakpoint()
        return 0

    def _event_handle_process_signal(self, status):
        signum = WSTOPSIG(status)
        logger.debug('signum:%d, %s' % (signum, signal_name(signum)))

        self.regs = self.get_regs()

        if CPU_64BITS:
            #print 'rip='+hex(self.regs.rip)
            logger.debug('rip=%08x' % self.regs.rip)
        else:
            logger.debug('eip=%08x' % self.regs.eip)

        if signum == SIGTRAP:
            return self._event_handle_sigtrap()


        if self.trace_sys_call_flag: # status=34175=0x857f why???
            return self._event_handle_sys_call()

        if signum in self.callbacks.keys():
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

    def _debug_event_iteration(self):
        (pid, status) = waitpid(self.pid, 0)
        signum = 0

        print 'status:%r' %status
        logger.debug('status:%r' % status)

        # Process exited?
        if WIFEXITED(status):
            self._event_handle_process_exit(status)

        # Process killed by a signal?
        elif WIFSIGNALED(status):
            self._event_handle_process_kill(status)

        # Invalid process status?
        elif not WIFSTOPPED(status):
            self._event_handle_process_unknown_status(status)

        # Ptrace event?
        elif self.WPTRACEEVENT(status):
            self._event_handle_process_ptrace_event(status)

        else:
            signum = self._event_handle_process_signal(status)

        # continue
        if self.single_step_flag:
            self._ptrace(PTRACE_SINGLESTEP, self.pid, 0, signum)
        elif self.trace_sys_call_flag:
            self._ptrace(PTRACE_SYSCALL, self.pid, 0, signum)
        else:
            self._ptrace(PTRACE_CONT, self.pid, 0, signum)

    def WPTRACEEVENT(self, status):
        return status >> 16

    #################################################################
    def _ptrace(self, command, pid, arg1, arg2):
        # logger.debug('ptrace command=%d' % command)
        peek_commands = [PTRACE_PEEKDATA, PTRACE_PEEKSIGINFO, PTRACE_PEEKTEXT, PTRACE_PEEKUSER]
        if command in peek_commands:
            data = libc_ptrace(command, pid, arg1, arg2)
            # need to handle the error
            # to do
            return data

        if libc_ptrace(command, pid, arg1, arg2) == -1:
            logger.debug('ptrace error2:%d' % command)
            libc_perror()

    '''
    def get_eventmsg(self):
        new_pid = pid_t()
        self.ptrace(PTRACE_GETEVENTMSG, self.pid, 0, addressof(new_pid))
        return new_pid.value
    '''

    '''
    def getBacktrace(self, max_args=6, max_depth=20):
        pass
    '''
    '''

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

    '''
    def func_resolve(self, dll, function):
        pass
    '''

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
