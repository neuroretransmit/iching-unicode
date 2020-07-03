#!/usr/bin/env python3

import random
from argparse import ArgumentParser, Namespace
from base64 import b16encode, b16decode, b32encode, b32decode, b64encode, b64decode
from sys import stderr

from const import ENCODING, \
    B16, B32, B64, BASE_DEFAULT_CHARSETS, \
    NGRAMS_ENCRYPT_MAPPING, HEXAGRAMS
from helper import eprintc, deduce_ngram_type, translate_ngrams_to_hexagrams


# TODO: Return bytes for file encryption
def decrypt(encrypted: bytes, base: int = 64, base_key: str = None, hexagram_offset: int = 0, hexagram_key: str = None) \
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
    def validate_args(parser: ArgumentParser, argparse_namespace: Namespace):
        """
        Validate command line arguments
        """
        if not argparse_namespace.encrypt and not argparse_namespace.decrypt:
            parser.print_help(stderr)
        elif argparse_namespace.encrypt and argparse_namespace.decrypt:
            parser.error("can't encrypt and decrypt simultaneously")
        if argparse_namespace.decrypt and argparse_namespace.ngrams != 'hex':
            eprintc('-g can be omitted during decryption', warn=True)
        bases = BASE_DEFAULT_CHARSETS.keys()
        if argparse_namespace.base not in bases:
            parser.error('base must be one of %s' % set(bases))
        if argparse_namespace.offset_hexagrams and argparse_namespace.base == B64:
            parser.error('base64 can\'t be offset')
        ngrams = NGRAMS_ENCRYPT_MAPPING.keys()
        if argparse_namespace.ngrams and argparse_namespace.ngrams.lower() not in ngrams:
            parser.error('ngrams must be one of %s' % set(ngrams))

    def setup_argparse():
        parser = ArgumentParser(description='Hide messages in I Ching ngrams')
        # Encrypt args
        parser.add_argument('-e', '--encrypt', help='encrypt message')
        # TODO: parser.add_argument('-ef', '--encrypt-file', help='encrypt file')
        parser.add_argument('-g', '--ngrams', help='ngram style {\'mono\', \'di\', \'tri\', \'hex\'}', default='hex')
        parser.add_argument('-sb', '--shuffle-base', help='shuffle base charset order', nargs='?', const=True,
                            default=False)
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
        return parser, parser.parse_args()

    def main():
        parser, argparse_namespace = setup_argparse()
        validate_args(parser, argparse_namespace)
        if argparse_namespace.encrypt:
            data, base_key, hexagram_offset, hexagram_key = encrypt(
                secret=bytes(argparse_namespace.encrypt, ENCODING),
                base=argparse_namespace.base,
                shuffle_base=argparse_namespace.shuffle_base,
                offset_hexagrams=argparse_namespace.offset_hexagrams,
                shuffle_hexagrams=argparse_namespace.shuffle_hexagrams,
                ngrams=argparse_namespace.ngrams)
            if argparse_namespace.shuffle_base:
                eprintc('Base%d Key: %s' % (argparse_namespace.base, base_key), important=True)
            if argparse_namespace.offset_hexagrams and not argparse_namespace.shuffle_hexagrams:
                eprintc('Hexagram Offset: %s' % hexagram_offset, important=True)
            if argparse_namespace.shuffle_hexagrams:
                eprintc('Hexagram Key: %s' % hexagram_key, important=True)
            print(data)
        elif argparse_namespace.decrypt:
            print(decrypt(
                encrypted=bytes(argparse_namespace.decrypt, ENCODING),
                base=argparse_namespace.base,
                base_key=argparse_namespace.base_key,
                hexagram_offset=int(argparse_namespace.offset_hexagrams),
                hexagram_key=argparse_namespace.hexagram_key))
    main()
