from os import environ
from sys import stderr, stdout, platform
from const import ANSIColor


def color_supported():
    """
    Does the console support colored output
    :return: True or False
    """
    supported_platform = platform != 'Pocket PC' and (platform != 'win32' or 'ANSICON' in environ)
    is_a_tty = hasattr(stdout, 'isatty') and stdout.isatty()
    return supported_platform and is_a_tty


def eprintc(message: str, color: ANSIColor = None, warn=False, fail=False, important=False, one_line=False):
    """
    Print message to stderr (with or without color support) and optionally exit with error code. Header (example
    'Header: message' is colored if colon is present, otherwise the entire line.
    colored, otherwise the entire line.
    :param message: message to print
    :param color: ANSI color to highlight message with
    :param warn: highlight text in yellow
    :param fail: highlight text in red
    :param important: highlight text in magenta
    :param one_line: rewrite output on same line
    """
    end_char = '\r' if one_line else '\n'
    if not color_supported():
        if fail:
            stderr.write("ERROR: %s%s" % (message, end_char))
            exit(-1)
        elif warn:
            stderr.write("WARN: %s%s" % message, end_char)
        else:
            stderr.write(message + end_char)
    else:
        if ':' in message and not fail:
            message = '%s' + message + end_char
            message = message.replace(': ', ':%s ')
        elif fail:
            message = '%sERROR: ' + message + end_char
            message = message.replace(': ', ':%s ')
        elif warn:
            message = '%sWARN: ' + message + end_char
            message = message.replace(': ', ':%s ')
        else:
            message = '%s' + message + '%s' + end_char
        if important:
            stderr.write(message % (ANSIColor.MAGENTA, ANSIColor.ENDC))
        elif warn:
            stderr.write(message % (ANSIColor.YELLOW, ANSIColor.ENDC))
        elif fail:
            stderr.write(message % (ANSIColor.RED, ANSIColor.ENDC))
            exit(-1)
        else:
            stderr.write(message % (color, ANSIColor.ENDC))