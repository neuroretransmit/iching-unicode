#!/usr/bin/env python3

import random
from argparse import ArgumentParser
from base64 import b16encode, b16decode, b32encode, b32decode, b64encode, b64decode
from sys import stderr

from const import *
from output import eprintc

# ===================================================== ARGUMENTS ======================================================
parser = ArgumentParser(description='Hide messages in I Ching ngrams')
# Encrypt args
parser.add_argument('-e', '--encrypt', help='encrypt message')
# TODO: parser.add_argument('-ef', '--encrypt-file', help='encrypt file')
parser.add_argument('-g', '--ngrams', help='ngram style {\'mono\', \'di\', \'tri\', \'hex\'}', default='hex')
parser.add_argument('-sb', '--shuffle-base', help='shuffle base charset order', nargs='?', const=True, default=False)
parser.add_argument('-sh', '--shuffle-hexagrams', help='shuffle hexagram order',
                    nargs='?', const=True, default=False)
# Decrypt args
parser.add_argument('-d', '--decrypt', help='decrypt message')
# TODO: parser.add_argument('-df', '--decrypt-file', help='decrypt file')
parser.add_argument('-bk', '--base-key', help='base key for decryption', default=None)
parser.add_argument('-hk', '--hexagram-key', help='hexagram key for decryption', default=None)
# Shared args
parser.add_argument('-b', '--base', help='target base {16, 32, 64}', type=int, default=64)
parser.add_argument('-oh', '--offset-hexagrams', help='offset hexagram slice for base {16, 32}',
                    nargs='?', const=True, default=False)
ns = parser.parse_args()


def validate_args():
    """
    Validate command line arguments
    """
    if not ns.encrypt and not ns.decrypt:
        parser.print_help(stderr)
    elif ns.encrypt and ns.decrypt:
        parser.error("can't encrypt and decrypt simultaneously")
    if ns.decrypt and ns.ngrams != 'hex':
        eprintc('-g can be omitted during decryption', warn=True)
    bases = BASE_DEFAULT_CHARSETS.keys()
    if ns.base not in bases:
        parser.error('base must be one of %s' % set(bases))
    if ns.offset_hexagrams and ns.base == B64:
        parser.error('base64 can\'t be offset')
    ngrams = NGRAMS_ENCRYPT_MAPPING.keys()
    if ns.ngrams and ns.ngrams.lower() not in ngrams:
        parser.error('ngrams must be one of %s' % set(ngrams))


# ================================================= HELPER FUNCTIONS ===================================================


def deduce_ngram_type(char: str) -> str:
    """
    Deduce ngram type from character
    :param char: first character from encrypted message
    :return: one of ['tri', 'di', 'mono']
    """
    if char in TRIGRAMS:
        return 'tri'
    elif char in DIGRAMS:
        return 'di'
    elif char in MONOGRAMS:
        return 'mono'
    elif char in HEXAGRAMS:
        return 'hex'
    else:
        raise ValueError("invalid message for decryption")


def translate_ngrams_to_hexagrams(encrypted: bytes, ngram_type: str) -> bytes:
    """
    Translate monograms, digrams and trigrams to hexagrams for intermediate mapping before decrypt
    :param encrypted: monograms, digrams or trigrams as bytes
    :param ngram_type: 'mono' or 'di' or 'tri'
    :return: hexagrams as bytes
    """
    char_len = NGRAM_CHAR_LEN[ngram_type]
    translated = ''
    decoded = encrypted.decode(ENCODING)
    for ngram_grouping in [decoded[y - char_len: y]
                           for y in range(char_len, len(decoded) + char_len, char_len)]:
        translated += NGRAMS_DECRYPT_MAPPING[ngram_type][ngram_grouping]
    return bytes(translated, ENCODING)


# TODO: Return bytes for file encryption
def decrypt(encrypted: bytes, base: int = 64, base_key: str = None, hexagram_offset: int = 0, hexagram_key: str = None)\
        -> str:
    """
    Decrypt encrypted byte stream using different base systems. Optionally, provide the base index key and hexagram
    offset if encrypted with them. If a hexagram key is supplied, the offset may be omitted.
    :param encrypted: encrypted bytes
    :param base: target base system
    :param base_key: index key for base system
    :param hexagram_offset: shift to use when slicing hexagrams for base16/base32, can be omitted if hexagram key
    supplied
    :param hexagram_key: index key for hexagrams
    :return: decrypted message
    """
    try:
        ngram_type = deduce_ngram_type(encrypted.decode(ENCODING)[0])
        if ngram_type != 'hex':
            encrypted = translate_ngrams_to_hexagrams(encrypted, ngram_type)
        hexagram_key = HEXAGRAMS[hexagram_offset: hexagram_offset + base] if not hexagram_key else hexagram_key
        mapping = dict(zip(hexagram_key, base_key if base_key else BASE_DEFAULT_CHARSETS[base]))
        decrypted = encrypted.decode(ENCODING)
        for hexagram in set(decrypted):
            decrypted = decrypted.replace(hexagram, mapping[hexagram])
        if base_key:
            decrypted = decrypted.translate(str.maketrans(BASE_DEFAULT_CHARSETS[base], base_key))
        if base == B16:
            return b16decode(decrypted).decode(ENCODING)
        elif base == B32:
            decrypted += '=' * ((8 - (len(decrypted) % 8)) % 8)
            return b32decode(decrypted).decode(ENCODING)
        elif base == B64:
            decrypted += '=' * ((4 - len(decrypted) % 4) % 4)
            return b64decode(decrypted).decode(ENCODING)
    except KeyError:
        eprintc("Invalid offset or key", fail=True)
    except ValueError as ve:
        eprintc(str(ve), fail=True)


# TODO: Return bytes for file encryption
def encrypt(secret: bytes, base: int = 64, shuffle_base: bool = False, offset_hexagrams: bool = False,
            shuffle_hexagrams: bool = False, ngrams: str = 'hex') -> str:
    """
    Encrypt bytes using different base systems and I Ching ngrams. Optionally, shuffle the base index key, hexagram
    index key or shift the hexagrams slice for base16/base32.
    :param secret: secret bytes
    :param base: target base system
    :param shuffle_base: shuffle index key
    :param offset_hexagrams: randomly shift where hexagrams are sliced
    :param shuffle_hexagrams: randomize hexagram slice
    :param ngrams: style of ngram to be used ['mono', 'di', 'tri', 'hex']
    :return: encrypted unicode hexagrams
    """
    base_key = BASE_DEFAULT_CHARSETS[base]
    if shuffle_base:
        base_key = ''.join(random.sample(BASE_DEFAULT_CHARSETS[base], base))
    hexagram_offset = 0
    if offset_hexagrams:
        hexagram_offset = random.randint(0, B64 - base)
    hexagram_key = HEXAGRAMS[hexagram_offset: hexagram_offset + base]
    if shuffle_hexagrams:
        hexagram_key = ''.join(random.sample(hexagram_key, base))
    if base == B16:
        encrypted = b16encode(secret).decode(ENCODING)
    elif base == B32:
        encrypted = b32encode(secret).decode(ENCODING).replace('=', '')
    elif base == B64:
        encrypted = b64encode(secret).decode(ENCODING).replace('=', '')
    if shuffle_base:
        encrypted = encrypted.translate(str.maketrans(base_key, BASE_DEFAULT_CHARSETS[base]))
    mapping = dict(zip(base_key, hexagram_key))
    for letter in set(encrypted):
        encrypted = encrypted.replace(letter,
                                      mapping[letter] if ngrams == 'hex' else
                                      NGRAMS_ENCRYPT_MAPPING[ngrams][mapping[letter]])
    return encrypted, base_key, hexagram_offset, hexagram_key


if __name__ == "__main__":
    validate_args()
    if ns.encrypt:
        data, base_key, hexagram_offset, hexagram_key = encrypt(
            secret=bytes(ns.encrypt, ENCODING),
            base=ns.base,
            shuffle_base=ns.shuffle_base,
            offset_hexagrams=ns.offset_hexagrams,
            shuffle_hexagrams=ns.shuffle_hexagrams,
            ngrams=ns.ngrams)
        if ns.shuffle_base:
            eprintc('Base%d Key: %s' % (ns.base, base_key), important=True)
        if ns.offset_hexagrams and not ns.shuffle_hexagrams:
            eprintc('Hexagram Offset: %s' % hexagram_offset, important=True)
        if ns.shuffle_hexagrams:
            eprintc('Hexagram Key: %s' % hexagram_key, important=True)
        print(data)
    elif ns.decrypt:
        print(decrypt(
            encrypted=bytes(ns.decrypt, ENCODING),
            base=ns.base,
            base_key=ns.base_key,
            hexagram_offset=int(ns.offset_hexagrams),
            hexagram_key=ns.hexagram_key))
