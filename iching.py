#!/usr/bin/env python3

from argparse import ArgumentParser, ArgumentTypeError
from base64 import b16encode, b16decode, b32encode, b32decode, b64encode, b64decode
import random
from os import environ
from sys import stderr, stdout, platform

ENCODING = 'utf-8'

# King Wen hexagram order
HEXAGRAMS = '䷀䷁䷂䷃䷄䷅䷆䷇䷈䷉䷊䷋䷌䷍䷎䷏䷐䷑䷒䷓䷔䷕䷖䷗䷘䷙䷚䷛䷜䷝䷞䷟' \
            '䷠䷡䷢䷣䷤䷥䷦䷧䷨䷩䷪䷫䷬䷭䷮䷯䷰䷱䷲䷳䷴䷵䷶䷷䷸䷹䷺䷻䷼䷽䷾䷿'

B16 = 16
B32 = 32
B64 = 64
DEFAULT_BASE_CHARSET = {
    B16: '0123456789ABCDEF',
    B32: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
    B64: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
}


class ANSIColors:
    HEADER = '\033[95m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


parser = ArgumentParser(description='Hide messages in I Ching hexagrams')
parser.add_argument('-b', '--base', help='target base [16, 32, 64]', type=int, default=64)
parser.add_argument('-s', '--shuffle', help='shuffle base index table', nargs='?', const=True, default=False)
parser.add_argument('-e', '--encrypt', help='encrypt message')
parser.add_argument('-d', '--decrypt', help='decrypt message')
parser.add_argument('-k', '--key', help='key for decryption', default=None)
parser.add_argument('-oh', '--offset-hexagrams', help='offset hexagram slice for base [16, 32]',
                    nargs='?', const=True, default=False)
ns = parser.parse_args()


def decrypt(encrypted, base, decryption_key=None, hexagram_offset=0):
    try:
        hexagrams_slice = HEXAGRAMS[hexagram_offset: hexagram_offset + base]
        mapping = dict(zip(hexagrams_slice, decryption_key if decryption_key else DEFAULT_BASE_CHARSET[base]))
        decrypted = encrypted.decode(ENCODING)
        for hexagram in set(decrypted):
            decrypted = decrypted.replace(hexagram, mapping[hexagram])
        if decryption_key:
            decrypted = decrypted.translate(str.maketrans(DEFAULT_BASE_CHARSET[base], decryption_key))
        if base == B16:
            return b16decode(decrypted).decode(ENCODING)
        elif base == B32:
            decrypted += '=' * ((8 - (len(decrypted) % 8)) % 8)
            return b32decode(decrypted).decode(ENCODING)
        elif base == B64:
            decrypted += '=' * ((4 - len(decrypted) % 4) % 4)
            return b64decode(decrypted).decode(ENCODING)
    except KeyError:
        printerr_fail("Invalid offset or key")


def encrypt(secret, base, shuffle=False, offset_hexagrams=False):
    encryption_key = DEFAULT_BASE_CHARSET[base]
    if shuffle:
        encryption_key = ''.join(random.sample(DEFAULT_BASE_CHARSET[base], base))
    hexagram_offset = 0
    if offset_hexagrams:
        hexagram_offset = random.randint(0, B64 - base)
    hexagrams_slice = HEXAGRAMS[hexagram_offset: hexagram_offset + base]
    if base == B16:
        encrypted = b16encode(secret).decode(ENCODING)
    elif base == B32:
        encrypted = b32encode(secret).decode(ENCODING).replace('=', '')
    elif base == B64:
        encrypted = b64encode(secret).decode(ENCODING).replace('=', '')
    if shuffle:
        encrypted = encrypted.translate(str.maketrans(encryption_key, DEFAULT_BASE_CHARSET[base]))
    mapping = dict(zip(encryption_key, hexagrams_slice))
    for letter in set(encrypted):
        encrypted = encrypted.replace(letter, mapping[letter])
    return encrypted, encryption_key, hexagram_offset


def color_supported():
    plat = platform
    supported_platform = plat != 'Pocket PC' and (plat != 'win32' or 'ANSICON' in environ)
    is_a_tty = hasattr(stdout, 'isatty') and stdout.isatty()
    return supported_platform and is_a_tty


def printerr_fail(message):
    if not color_supported():
        stderr.write("ERROR: %s\n" % message)
    else:
        message = '%sERROR: ' + message + '\n'
        message = message.replace(': ', ':%s ')
        stderr.write(message % (ANSIColors.FAIL, ANSIColors.ENDC))
    exit(1)


def printerr_important(message):
    if not color_supported():
        stderr.write(message + "\n")
    else:
        message = '%s' + message + '\n'
        message = message.replace(': ', ':%s ')
        stderr.write(message % (ANSIColors.HEADER, ANSIColors.ENDC))


def validate_args():
    try:
        if not ns.encrypt and not ns.decrypt:
            parser.print_help(stderr)
        elif ns.encrypt and ns.decrypt:
            raise ArgumentTypeError("Can't encode and decode simultaneously")
        bases = DEFAULT_BASE_CHARSET.keys()
        if ns.base not in bases:
            raise ArgumentTypeError('Base must be one of %s' % set(bases))
        if ns.offset_hexagrams and ns.base == B64:
            raise ArgumentTypeError('Base64 can\'t be offset')
    except ArgumentTypeError as ate:
        printerr_fail(str(ate))


if __name__ == "__main__":
    validate_args()
    if ns.encrypt:
        data, key, offset = encrypt(bytes(ns.encrypt, ENCODING), ns.base, ns.shuffle, ns.offset_hexagrams)
        if ns.shuffle:
            printerr_important('Key: %s' % key)
        if ns.offset_hexagrams:
            printerr_important('Hexagram Offset: %s' % offset)
        print(data)
    elif ns.decrypt:
        print(decrypt(bytes(ns.decrypt, ENCODING), ns.base, ns.key, int(ns.offset_hexagrams)))
