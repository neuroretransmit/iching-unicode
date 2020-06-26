#!/usr/bin/env python3

import argparse
import base64
import random
import sys


# King Wen order
HEXAGRAMS = '䷀䷁䷂䷃䷄䷅䷆䷇䷈䷉䷊䷋䷌䷍䷎䷏' \
            '䷐䷑䷒䷓䷔䷕䷖䷗䷘䷙䷚䷛䷜䷝䷞䷟' \
            '䷠䷡䷢䷣䷤䷥䷦䷧䷨䷩䷪䷫䷬䷭䷮䷯' \
            '䷰䷱䷲䷳䷴䷵䷶䷷䷸䷹䷺䷻䷼䷽䷾䷿'

DEFAULT_BASE_IDX_TABLE = {
    16: '0123456789ABCDEF',
    32: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
    64: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
}

# Copied in case of shifts
BASE_IDX_TABLE = DEFAULT_BASE_IDX_TABLE.copy()

parser = argparse.ArgumentParser(description='Hide messages in I Ching hexagrams')
parser.add_argument('-b', '--base', help='target base [16, 32, 64, 84]', type=int, default=64)
parser.add_argument('-s', '--shuffle', help='shuffle base index table', nargs='?', const=True, default=False)
parser.add_argument('-e', '--encrypt', help='encrypt message')
parser.add_argument('-d', '--decrypt', help='decrypt message')
parser.add_argument('-k', '--key', help='key for decryption', default=None)
ns = parser.parse_args()


def decrypt(data):
    try:
        # TODO: Pick random offset to slice at
        iching_slice = HEXAGRAMS[:ns.base]
        mapping = dict(zip(iching_slice, ns.key if ns.key else DEFAULT_BASE_IDX_TABLE[ns.base]))
        data = data.decode('utf-8')
        for k, v in mapping.items():
            data = data.replace(k, v)
        if ns.key:
            data = data.translate(str.maketrans(DEFAULT_BASE_IDX_TABLE[ns.base], ns.key))
        if ns.base == 16:
            return base64.b16decode(data).decode('utf-8')
        elif ns.base == 32:
            data += '=' * ((8 - (len(data) % 8)) % 8)
            return base64.b32decode(data).decode('utf-8')
        elif ns.base == 64:
            data += '=' * ((4 - len(data) % 4) % 4)
            return base64.b64decode(data).decode('utf-8')
    except ValueError:
        sys.stderr.write("Invalid key length or base selection")


def encrypt(data):
    # TODO: Pick random offset to slice at
    iching_slice = HEXAGRAMS[:ns.base]
    if ns.base == 16:
        data = base64.b16encode(data)
    elif ns.base == 32:
        data = base64.b32encode(data)
    elif ns.base == 64:
        data = base64.b64encode(data)
    if ns.shuffle:
        data = bytes(data)
        trans = data.maketrans(
            bytes(BASE_IDX_TABLE[ns.base], 'utf-8'),
            bytes(DEFAULT_BASE_IDX_TABLE[ns.base], 'utf-8'))
        data = data.translate(trans)
    mapping = dict(zip(iching_slice, BASE_IDX_TABLE[ns.base]))
    # Decode from byte-string and remove padding
    data = data.decode('utf-8').replace('=', '')
    for k, v in mapping.items():
        data = data.replace(v, k)
    return data


def validate_and_commit_args():
    if not ns.encrypt and not ns.decrypt:
        parser.print_help(sys.stderr)
    elif ns.encrypt and ns.decrypt:
        print("ERROR: Can't encode and decode simultaneously")
    bases = set(BASE_IDX_TABLE.keys())
    if ns.base not in bases:
        raise argparse.ArgumentTypeError('base must be one of %s' % bases)
    if ns.shuffle:
        alphabet = BASE_IDX_TABLE[ns.base]
        BASE_IDX_TABLE[ns.base] = ''.join(random.sample(alphabet, ns.base))
        sys.stderr.write("KEY: %s\n" % BASE_IDX_TABLE[ns.base])


if __name__ == "__main__":
    validate_and_commit_args()
    if ns.encrypt:
        print(encrypt(bytes(ns.encrypt, 'utf-8')))
    elif ns.decrypt:
        print(decrypt(bytes(ns.decrypt, 'utf-8')))
