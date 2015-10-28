# encoding:utf-8
__author__ = 'ling'

from ctypes import *

libc = cdll.LoadLibrary('libc.so.6')

libc_fork = libc.fork
libc_execl = libc.execl

libc_ptrace = libc.ptrace
libc_ptrace.restype = c_long
libc_ptrace.argtypes = [c_int, c_int, c_long, c_long]

libc_errno = libc.errno
libc_perror = libc.perror
