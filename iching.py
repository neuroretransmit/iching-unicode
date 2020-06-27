#!/usr/bin/env python3

from argparse import ArgumentParser, ArgumentTypeError
from base64 import b16encode, b16decode, b32encode, b32decode, b64encode, b64decode
import random
from sys import stderr

# King Wen hexagram order
HEXAGRAMS = '䷀䷁䷂䷃䷄䷅䷆䷇䷈䷉䷊䷋䷌䷍䷎䷏䷐䷑䷒䷓䷔䷕䷖䷗䷘䷙䷚䷛䷜䷝䷞䷟' \
            '䷠䷡䷢䷣䷤䷥䷦䷧䷨䷩䷪䷫䷬䷭䷮䷯䷰䷱䷲䷳䷴䷵䷶䷷䷸䷹䷺䷻䷼䷽䷾䷿'

DEFAULT_BASE_CHARSET = {
    16: '0123456789ABCDEF',
    32: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
    64: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
}

parser = ArgumentParser(description='Hide messages in I Ching hexagrams')
parser.add_argument('-b', '--base', help='target base [16, 32, 64]', type=int, default=64)
parser.add_argument('-s', '--shuffle', help='shuffle base index table', nargs='?', const=True, default=False)
parser.add_argument('-e', '--encrypt', help='encrypt message')
parser.add_argument('-d', '--decrypt', help='decrypt message')
parser.add_argument('-k', '--key', help='key for decryption', default=None)
ns = parser.parse_args()


def decrypt(encrypted, base, decryption_key):
    try:
        # TODO: Pick random offset to slice at
        hexagrams_slice = HEXAGRAMS[:base]
        mapping = dict(zip(hexagrams_slice, decryption_key if decryption_key else DEFAULT_BASE_CHARSET[base]))
        decrypted = encrypted.decode('utf-8')
        for hexagram in set(decrypted):
            decrypted = decrypted.replace(hexagram, mapping[hexagram])
        if decryption_key:
            decrypted = decrypted.translate(str.maketrans(DEFAULT_BASE_CHARSET[base], decryption_key))
        if base == 16:
            return b16decode(decrypted).decode('utf-8')
        elif base == 32:
            decrypted += '=' * ((8 - (len(decrypted) % 8)) % 8)
            return b32decode(decrypted).decode('utf-8')
        elif base == 64:
            decrypted += '=' * ((4 - len(decrypted) % 4) % 4)
            return b64decode(decrypted).decode('utf-8')
    except ValueError:
        stderr.write("Invalid key length or base selection")


def encrypt(secret, base, shuffle):
    encryption_key = DEFAULT_BASE_CHARSET[base]
    if shuffle:
        encryption_key = ''.join(random.sample(DEFAULT_BASE_CHARSET[base], base))
    # TODO: Pick random offset to slice at
    hexagrams_slice = HEXAGRAMS[:base]
    if base == 16:
        encrypted = b16encode(secret).decode('utf-8')
    elif base == 32:
        encrypted = b32encode(secret).decode('utf-8').replace('=', '')
    elif base == 64:
        encrypted = b64encode(secret).decode('utf-8').replace('=', '')
    if shuffle:
        encrypted = encrypted.translate(str.maketrans(encryption_key, DEFAULT_BASE_CHARSET[base]))
    mapping = dict(zip(encryption_key, hexagrams_slice))
    for letter in set(encrypted):
        encrypted = encrypted.replace(letter, mapping[letter])
    return encrypted, encryption_key


def validate_and_commit_args():
    if not ns.encrypt and not ns.decrypt:
        parser.print_help(stderr)
    elif ns.encrypt and ns.decrypt:
        stderr.write("ERROR: Can't encode and decode simultaneously\n")
    bases = DEFAULT_BASE_CHARSET.keys()
    if ns.base not in bases:
        raise ArgumentTypeError('base must be one of %s' % bases)


if __name__ == "__main__":
    validate_and_commit_args()
    if ns.encrypt:
        data, key = encrypt(bytes(ns.encrypt, 'utf-8'), ns.base, ns.shuffle)
        if ns.shuffle:
            stderr.write("KEY: %s\n" % key)
        print(data)
    elif ns.decrypt:
        print(decrypt(bytes(ns.decrypt, 'utf-8'), ns.base, ns.key))
