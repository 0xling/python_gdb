__author__ = 'ling'

from cpuinfo import *
from zio import *

if CPU_64BITS:
    from linux_syscall64 import *
else:
    from linux_syscall32 import *

def get_retval(dbg):
    if CPU_64BITS:
        return dbg.regs.rip
    else:
        return dbg.regs.eip

def write_handler(dbg, cur_pc, sys_name, arg0, arg1, arg2, isafter):
    if isafter:
        length = arg2
        if arg2 > 0x20:
            length = 0x20
        data = dbg.read(arg1, length)
        print sys_name + ':' + hex(cur_pc) + ':' + data


def read_handler(dbg, cur_pc, sys_name, arg0, arg1, arg2, isafter):
    if isafter:
        length = get_retval(dbg)
        if length > 0x20:
            length = 0x20
        data = dbg.read(arg1, length)
        print str(dbg.pid)+':'+sys_name + ':' + hex(cur_pc) + ':' + hex(arg1) + ":" + data

def read_str(dbg, addr):
    string = ''
    for i in range(8):
        data = dbg.read(addr+i*8, 8)
        if '\x00' in data:
            string += data.split('\x00')[0]
            return string
        else:
            string += data
    return string


def open_handler(dbg, cur_pc, sys_name, arg0, arg1, arg2, isafter):
    if isafter:
        file_name = read_str(dbg, arg0)
        retval = get_retval(dbg)
        print str(dbg.pid)+':'+sys_name + ':' + file_name +':' + hex(retval)

def stat_handler(dbg, cur_pc, sys_name, arg0, arg1, arg2, isafter):
    if isafter:
        file_name = read_str(dbg, arg0)
        print str(dbg.pid)+':'+sys_name + ':' + file_name

def access_handler(dbg, cur_pc, sys_name, arg0, arg1, arg2, isafter):
    if isafter:
        file_name = read_str(dbg, arg0)
        print str(dbg.pid)+':'+sys_name + ':' + file_name

def brk_handler(dbg, cur_pc, sys_name, arg0, arg1, arg2, isafter):
    if isafter:
        retval = get_retval(dbg)
        print str(dbg.pid)+':'+sys_name + ':' + hex(retval)

def mmap_handler(dbg, cur_pc, sys_name, arg0, arg1, arg2, isafter):
    if isafter:
        retval = get_retval(dbg)
        print str(dbg.pid)+':'+sys_name + ':' + hex(retval) + ':' + hex(arg1)

def exit_handler(dbg, cur_pc, sys_name, arg0, arg1, arg2, isafter):
    if not isafter:
        print str(dbg.pid)+':'+sys_name + ':' + hex(cur_pc)

def exit_group_handler(dbg, cur_pc, sys_name, arg0, arg1, arg2, isafter):
    if not isafter:
        print str(dbg.pid)+':'+sys_name + ':' + hex(cur_pc)

def default_sys_call_handler(dbg, cur_pc, sys_name, arg0, arg1, arg2, isafter):
    if isafter:
        print str(dbg.pid)+':'+sys_name + ':' + hex(cur_pc) + ':' + hex(arg0) + ':' + hex(arg1) + ":" + hex(arg2)

def close_handler(dbg, cur_pc, sys_name, arg0, arg1, arg2, isafter):
    if isafter:
        print str(dbg.pid)+':'+sys_name + ':' + hex(cur_pc) + ':' + hex(arg0)


sys_call_handlers = {'write': write_handler, 'read': read_handler, 'exit': exit_handler, 'exit_group': exit_group_handler,
                     'open': open_handler, 'access': access_handler}
sys_call_handlers['brk'] = brk_handler
sys_call_handlers['stat'] = stat_handler
sys_call_handlers['mmap'] = mmap_handler
sys_call_handlers['close'] = close_handler
