import platform
from defines import *

__author__ = 'ling'


def split_command_line(command_line):  # this piece of code comes from pexcept, thanks very much!

    '''This splits a command line into a list of arguments. It splits arguments
    on spaces, but handles embedded quotes, doublequotes, and escaped
    characters. It's impossible to do this with a regular expression, so I
    wrote a little state machine to parse the command line. '''

    arg_list = []
    arg = ''

    # Constants to name the states we can be in.
    state_basic = 0
    state_esc = 1
    state_singlequote = 2
    state_doublequote = 3
    # The state when consuming whitespace between commands.
    state_whitespace = 4
    state = state_basic

    for c in command_line:
        if state == state_basic or state == state_whitespace:
            if c == '\\':
                # Escape the next character
                state = state_esc
            elif c == r"'":
                # Handle single quote
                state = state_singlequote
            elif c == r'"':
                # Handle double quote
                state = state_doublequote
            elif c.isspace():
                # Add arg to arg_list if we aren't in the middle of whitespace.
                if state == state_whitespace:
                    # Do nothing.
                    None
                else:
                    arg_list.append(arg)
                    arg = ''
                    state = state_whitespace
            else:
                arg = arg + c
                state = state_basic
        elif state == state_esc:
            arg = arg + c
            state = state_basic
        elif state == state_singlequote:
            if c == r"'":
                state = state_basic
            else:
                arg = arg + c
        elif state == state_doublequote:
            if c == r'"':
                state = state_basic
            else:
                arg = arg + c

    if arg != '':
        arg_list.append(arg)
    return arg_list


# only support Linux os
def check_support():
    if platform.architecture()[1] == 'ELF':
        return True
    return False


def signal_name(signum):
    try:
        return SIGNAMES[signum]
    except KeyError:
        return "signal<%s>" % signum


def event_name(event):
    try:
        return EVENTS[event]
    except KeyError:
        return u'event<{0:s}>'.format(event)


def ptrace_cmd_name(command):
    ptrace_cmd_dict = {0: 'PTRACE_TRACEME', 1: 'PTRACE_PEEKTEXT', 2: 'PTRACE_PEEKDATA', 3: 'PTRACE_PEEKUSER',
                       4: 'PTRACE_POKETEXT', 5: 'PTRACE_POKEDATA', 6: 'PTRACE_POKEUSER', 7: 'PTRACE_CONT',
                       8: 'PTRACE_KILL', 9: 'PTRACE_SINGLESTEP', 12: 'PTRACE_GETREGS', 13: 'PTRACE_SETREGS',
                       14: 'PTRACE_GETFPREGS', 15: 'PTRACE_SETFPREGS', 16: 'PTRACE_ATTACH', 17: 'PTRACE_DETACH',
                       18: 'PTRACE_GETFPXREGS', 19: 'PTRACE_SETFPXREGS', 24: 'PTRACE_SYSCALL',
                       0x4200: 'PTRACE_SETOPTIONS', 0x4201: 'PTRACE_GETEVENTMSG', 0x4202: 'PTRACE_GETSIGINFO',
                       0x4203: 'PTRACE_SETSIGINFO', 0x4204: 'PTRACE_GETREGSET', 0x4205: 'PTRACE_SETREGSET',
                       0x4206: 'PTRACE_SEIZE', 0x4207: 'PTRACE_INTERRUPT', 0x4208: 'PTRACE_LISTEN',
                       0x4209: 'PTRACE_PEEKSIGINFO'}

    return ptrace_cmd_dict[command]
