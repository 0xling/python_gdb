# encoding:utf-8
__author__ = 'ling'

from ctypes import *

libc = cdll.LoadLibrary('libc.so.6')

_fork = libc.fork
_execl = libc.execl

_ptrace = libc.ptrace
_ptrace.restype = c_long
_ptrace.argtypes = [c_int, c_int, c_long, c_long]

_errno = libc.errno
_perror = libc.perror
