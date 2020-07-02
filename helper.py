from os import environ
from sys import stderr, stdout, platform
from const import ENCODING, ANSIColor, \
    MONOGRAMS, DIGRAMS, TRIGRAMS,  HEXAGRAMS, \
    NGRAM_CHAR_LEN, NGRAMS_DECRYPT_MAPPING


def color_supported() -> bool:
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
            stderr.write("WARN: %s%s" % (message, end_char))
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


def deduce_ngram_type(char: str) -> str:
    """
    Deduce ngram type from character
    :param char: first character from encrypted message
    :return: one of ['tri', 'di', 'mono']
    """
    if char in MONOGRAMS:
        return 'mono'
    elif char in DIGRAMS:
        return 'di'
    elif char in TRIGRAMS:
        return 'tri'
    elif char in HEXAGRAMS:
        return 'hex'
    else:
        raise ValueError("invalid message for decryption")


def translate_ngrams_to_hexagrams(encrypted, ngram_type: str, as_bytes: bool = True):
    """
    Translate monograms, digrams and trigrams to hexagrams for intermediate mapping before decrypt
    :param encrypted: monograms, digrams or trigrams as bytes
    :param ngram_type: 'mono' or 'di' or 'tri'
    :return: hexagrams as bytes
    """
    char_len = NGRAM_CHAR_LEN[ngram_type]
    translated = ''
    if type(encrypted) is bytes:
        encrypted = encrypted.decode(ENCODING)
    for ngram_grouping in [encrypted[y - char_len: y]
                           for y in range(char_len, len(encrypted) + char_len, char_len)]:
        translated += NGRAMS_DECRYPT_MAPPING[ngram_type][ngram_grouping]
    return bytes(translated, ENCODING) if as_bytes else translated
