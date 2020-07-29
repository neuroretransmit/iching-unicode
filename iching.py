#!/usr/bin/env python3

import lzma
import random
from argparse import ArgumentParser, Namespace
from base64 import b16encode, b16decode, b32encode, b32decode, b64encode, b64decode
from sys import stderr

from const import ENCODING, \
    B16, B32, B64, BASE_DEFAULT_CHARSETS, \
    NGRAMS_ENCRYPT_MAPPING, HEXAGRAMS
from helper import eprintc, deduce_ngram_type, translate_ngrams_to_hexagrams

# Containerless compression (shorter messages lose larger fingerprint from container)
COMPRESSION_FORMAT = lzma.FORMAT_RAW
# Required filter with use of lzma.FORMAT_RAW
COMPRESSION_FILTER = [{'id': lzma.FILTER_LZMA2}]

# Functor for handling decoding and stripping padding where necessary
ENCODER = {
    B16: lambda x: b16encode(x).decode(ENCODING),
    B32: lambda x: b32encode(x).decode(ENCODING).replace('=', ''),
    B64: lambda x: b64encode(x).decode(ENCODING).replace('=', '')
}

# Functor for handling decoding and padding when necessary
DECODER = {
    B16: lambda x: lzma.decompress(b16decode(x),
                                   format=COMPRESSION_FORMAT, filters=COMPRESSION_FILTER).decode(ENCODING),
    B32: lambda x: lzma.decompress(b32decode(x + '=' * ((8 - (len(x) % 8)) % 8)),
                                   format=COMPRESSION_FORMAT, filters=COMPRESSION_FILTER).decode(ENCODING),
    B64: lambda x: lzma.decompress(b64decode(x + '=' * ((4 - len(x) % 4) % 4)),
                                   format=COMPRESSION_FORMAT, filters=COMPRESSION_FILTER).decode(ENCODING)
}


def decrypt(encrypted: bytes, base: int = 64, base_key: str = None, hexagram_offset: int = 0,
            hexagram_key: str = None) -> bytes:
    """
    Decrypt encrypted byte stream using different base systems. Optionally, provide the base index key and hexagram
    offset if encrypted with them. If a hexagram key is supplied, the offset may be omitted.
    :param encrypted: encrypted bytes
    :param base: target base system
    :param base_key: index key for base system
    :param hexagram_offset: shift to use when slicing hexagrams for base16/base32, can be omitted if hexagram key
    supplied
    :param hexagram_key: index key for hexagrams
    :return: decrypted bytes
    """
    try:
        ngram_type = deduce_ngram_type(encrypted.decode(ENCODING)[0])
        if ngram_type != 'hex':
            encrypted = translate_ngrams_to_hexagrams(encrypted, ngram_type)
        hexagram_key = HEXAGRAMS[hexagram_offset: hexagram_offset + base] if not hexagram_key else hexagram_key
        mapping = dict(zip(hexagram_key, base_key if base_key else BASE_DEFAULT_CHARSETS[base]))
        decrypted = encrypted.decode(ENCODING).strip()
        for hexagram in set(decrypted):
            decrypted = decrypted.replace(hexagram, mapping[hexagram])
        if base_key:
            decrypted = decrypted.translate(str.maketrans(BASE_DEFAULT_CHARSETS[base], base_key))
        return DECODER[base](decrypted)
    except KeyError:
        eprintc("Invalid offset or key", fail=True)
    except ValueError as ve:
        eprintc(str(ve), fail=True)


def encrypt(secret: bytes, base: int = 64, shuffle_base: bool = False, offset_hexagrams: bool = False,
            shuffle_hexagrams: bool = False, ngrams: str = 'hex') -> bytes:
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
    secret = lzma.compress(secret, format=COMPRESSION_FORMAT, filters=COMPRESSION_FILTER)
    base_key = BASE_DEFAULT_CHARSETS[base]
    if shuffle_base:
        base_key = ''.join(random.sample(BASE_DEFAULT_CHARSETS[base], base))
    hexagram_offset = 0
    if offset_hexagrams:
        hexagram_offset = random.randint(0, B64 - base)
    hexagram_key = HEXAGRAMS[hexagram_offset: hexagram_offset + base]
    if shuffle_hexagrams:
        hexagram_key = ''.join(random.sample(hexagram_key, base))
    encrypted = ENCODER[base](secret)
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
        if not argparse_namespace.encrypt and not argparse_namespace.decrypt \
                and not argparse_namespace.encrypt_file and not argparse_namespace.decrypt_file:
            parser.print_help(stderr)
        elif argparse_namespace.encrypt and argparse_namespace.decrypt:
            parser.error("can't encrypt and decrypt simultaneously")
        elif argparse_namespace.encrypt_file and argparse_namespace.encrypt:
            parser.error("can't encrypt file and message simultaneously")
        elif argparse_namespace.encrypt_file and argparse_namespace.decrypt_file:
            parser.error("can't encrypt and decrypt file and message simultaneously")
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
        parser.add_argument('-ef', '--encrypt-file', help='encrypt file')
        parser.add_argument('-g', '--ngrams', help='ngram style {\'mono\', \'di\', \'tri\', \'hex\'}', default='hex')
        parser.add_argument('-sb', '--shuffle-base', help='shuffle base charset order', nargs='?', const=True,
                            default=False)
        parser.add_argument('-sh', '--shuffle-hexagrams', help='shuffle hexagram order',
                            nargs='?', const=True, default=False)
        # Decrypt args
        parser.add_argument('-d', '--decrypt', help='decrypt message')
        parser.add_argument('-df', '--decrypt-file', help='decrypt file')
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
        if argparse_namespace.encrypt or argparse_namespace.encrypt_file:
            if argparse_namespace.encrypt_file:
                with open(argparse_namespace.encrypt_file, "rb") as file:
                    data = file.read()
            data, base_key, hexagram_offset, hexagram_key = encrypt(
                secret=bytes(argparse_namespace.encrypt, ENCODING) if argparse_namespace.encrypt else data,
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
        elif argparse_namespace.decrypt or argparse_namespace.decrypt_file:
            if argparse_namespace.decrypt_file:
                with open(argparse_namespace.decrypt_file, "rb") as file:
                    data = file.read()
            print(decrypt(
                encrypted=bytes(argparse_namespace.decrypt, ENCODING) if argparse_namespace.decrypt else data,
                base=argparse_namespace.base,
                base_key=argparse_namespace.base_key,
                hexagram_offset=int(argparse_namespace.offset_hexagrams),
                hexagram_key=argparse_namespace.hexagram_key))


    main()
