#!/usr/bin/env python3

import random
from argparse import ArgumentParser, ArgumentTypeError
from base64 import b16encode, b16decode, b32encode, b32decode, b64encode, b64decode
from os import environ
from sys import stderr, stdout, platform

# ===================================================== CONSTANTS ======================================================
ENCODING = 'utf-8'


class ANSIColor:
    MAGENTA = '\033[95m'
    RED = '\033[91m'
    ENDC = '\033[0m'


B16 = 16
B32 = 32
B64 = 64
DEFAULT_BASE_CHARSET = {
    B16: '0123456789ABCDEF',
    B32: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
    B64: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
}

MONOGRAMS = '⚊⚋'
DIGRAMS = '⚌⚍⚎⚏'
TRIGRAMS = '☰☱☲☳☴☵☶☷'
HEXAGRAMS = '䷀䷁䷂䷃䷄䷅䷆䷇䷈䷉䷊䷋䷌䷍䷎䷏䷐䷑䷒䷓䷔䷕䷖䷗䷘䷙䷚䷛䷜䷝䷞䷟' \
            '䷠䷡䷢䷣䷤䷥䷦䷧䷨䷩䷪䷫䷬䷭䷮䷯䷰䷱䷲䷳䷴䷵䷶䷷䷸䷹䷺䷻䷼䷽䷾䷿'
DIGRAM_TO_MONOGRAM_MAPPING = {'⚌': '⚊⚊', '⚍': '⚋⚊', '⚎': '⚊⚋', '⚏': '⚋⚋'}
HEXAGRAM_TO_TRIGRAM_MAPPING = {
    '䷀': '☰☰', '䷁': '☷☷', '䷂': '☵☳', '䷃': '☶☵', '䷄': '☵☰', '䷅': '☰☵', '䷆': '☷☵', '䷇': '☵☷',
    '䷈': '☴☰', '䷉': '☰☱', '䷊': '☷☰', '䷋': '☰☷', '䷌': '☰☲', '䷍': '☲☰', '䷎': '☷☶', '䷏': '☳☷',
    '䷐': '☱☳', '䷑': '☶☴', '䷒': '☷☱', '䷓': '☴☷', '䷔': '☲☳', '䷕': '☶☲', '䷖': '☶☷', '䷗': '☷☳',
    '䷘': '☰☳', '䷙': '☶☰', '䷚': '☶☳', '䷛': '☱☴', '䷜': '☵☵', '䷝': '☲☲', '䷞': '☱☶', '䷟': '☳☴',
    '䷠': '☰☶', '䷡': '☳☰', '䷢': '☲☷', '䷣': '☷☲', '䷤': '☴☲', '䷥': '☲☱', '䷦': '☵☶', '䷧': '☳☵',
    '䷨': '☶☱', '䷩': '☴☳', '䷪': '☱☰', '䷫': '☰☴', '䷬': '☱☷', '䷭': '☷☴', '䷮': '☱☵', '䷯': '☵☴',
    '䷰': '☱☲', '䷱': '☲☴', '䷲': '☳☳', '䷳': '☶☶', '䷴': '☴☶', '䷵': '☳☱', '䷶': '☳☲', '䷷': '☲☶',
    '䷸': '☴☴', '䷹': '☱☱', '䷺': '☴☵', '䷻': '☵☱', '䷼': '☴☱', '䷽': '☳☶', '䷾': '☵☲', '䷿': '☲☵'
}
TRIGRAM_TO_HEXAGRAM_MAPPING = {v: k for k, v in HEXAGRAM_TO_TRIGRAM_MAPPING.items()}
HEXAGRAM_TO_DIGRAM_MAPPING = {
    '䷀': '⚌⚌⚌', '䷁': '⚏⚏⚏', '䷂': '⚍⚏⚍', '䷃': '⚎⚏⚎', '䷄': '⚍⚍⚌', '䷅': '⚌⚎⚎', '䷆': '⚏⚏⚎', '䷇': '⚍⚏⚏',
    '䷈': '⚌⚍⚌', '䷉': '⚌⚎⚌', '䷊': '⚏⚍⚌', '䷋': '⚌⚎⚏', '䷌': '⚌⚌⚍', '䷍': '⚎⚌⚌', '䷎': '⚏⚍⚏', '䷏': '⚏⚎⚏',
    '䷐': '⚍⚎⚍', '䷑': '⚎⚍⚎', '䷒': '⚏⚏⚌', '䷓': '⚌⚏⚏', '䷔': '⚎⚎⚍', '䷕': '⚎⚍⚍', '䷖': '⚎⚏⚏', '䷗': '⚏⚏⚍',
    '䷘': '⚌⚎⚍', '䷙': '⚎⚍⚌', '䷚': '⚎⚏⚍', '䷛': '⚍⚌⚎', '䷜': '⚍⚏⚎', '䷝': '⚎⚌⚍', '䷞': '⚍⚌⚏', '䷟': '⚏⚌⚎',
    '䷠': '⚌⚌⚏', '䷡': '⚏⚌⚌', '䷢': '⚎⚎⚏', '䷣': '⚏⚍⚍', '䷤': '⚌⚍⚍', '䷥': '⚎⚎⚌', '䷦': '⚍⚍⚏', '䷧': '⚏⚎⚎',
    '䷨': '⚎⚏⚌', '䷩': '⚌⚏⚍', '䷪': '⚍⚌⚌', '䷫': '⚌⚌⚎', '䷬': '⚍⚎⚏', '䷭': '⚏⚍⚎', '䷮': '⚍⚎⚎', '䷯': '⚍⚍⚎',
    '䷰': '⚍⚌⚍', '䷱': '⚎⚌⚎', '䷲': '⚏⚎⚍', '䷳': '⚎⚍⚏', '䷴': '⚌⚍⚏', '䷵': '⚏⚎⚌', '䷶': '⚏⚌⚍', '䷷': '⚎⚌⚏',
    '䷸': '⚌⚍⚎', '䷹': '⚍⚎⚌', '䷺': '⚌⚏⚎', '䷻': '⚍⚏⚌', '䷼': '⚌⚏⚌', '䷽': '⚏⚌⚏', '䷾': '⚍⚍⚍', '䷿': '⚎⚎⚎'
}
DIGRAM_TO_HEXAGRAM_MAPPING = {v: k for k, v in HEXAGRAM_TO_DIGRAM_MAPPING.items()}
HEXAGRAM_TO_MONOGRAM_MAPPING = {k: ''.join(DIGRAM_TO_MONOGRAM_MAPPING[c] for c in v)
                                for k, v in HEXAGRAM_TO_DIGRAM_MAPPING.items()}
MONOGRAM_TO_HEXAGRAM_MAPPING = {v: k for k, v in HEXAGRAM_TO_MONOGRAM_MAPPING.items()}
NGRAMS_ENCRYPT_MAPPING = {
    'mono': HEXAGRAM_TO_MONOGRAM_MAPPING,
    'di': HEXAGRAM_TO_DIGRAM_MAPPING,
    'tri': HEXAGRAM_TO_TRIGRAM_MAPPING,
    'hex': None
}
NGRAMS_DECRYPT_MAPPING = {
    'mono': MONOGRAM_TO_HEXAGRAM_MAPPING,
    'di': DIGRAM_TO_HEXAGRAM_MAPPING,
    'tri': TRIGRAM_TO_HEXAGRAM_MAPPING,
    'hex': None
}
NGRAM_CHAR_LEN = {
    'mono': 6,
    'di': 3,
    'tri': 2,
    'hex': 1
}

# ===================================================== ARGUMENTS ======================================================
parser = ArgumentParser(description='Hide messages in I Ching ngrams')
parser.add_argument('-b', '--base', help='target base [16, 32, 64]', type=int, default=64)
parser.add_argument('-sb', '--shuffle-base', help='shuffle base charset order', nargs='?', const=True, default=False)
parser.add_argument('-e', '--encrypt', help='encrypt message')
parser.add_argument('-d', '--decrypt', help='decrypt message')
parser.add_argument('-bk', '--base-key', help='base key for decryption', default=None)
parser.add_argument('-oh', '--offset-hexagrams', help='offset hexagram slice for base [16, 32]',
                    nargs='?', const=True, default=False)
parser.add_argument('-sh', '--shuffle-hexagrams', help='shuffle hexagram order',
                    nargs='?', const=True, default=False)
parser.add_argument('-hk', '--hexagram-key', help='hexagram key for decryption', default=None)
parser.add_argument('-g', '--grams', help='ngram style [\'mono\', \'di\', \'tri\', \'hex\']', default='hex')
ns = parser.parse_args()


def validate_args():
    """
    Validate command line arguments
    """
    try:
        if not ns.encrypt and not ns.decrypt:
            parser.print_help(stderr)
        elif ns.encrypt and ns.decrypt:
            raise ArgumentTypeError("can't encrypt and decrypt simultaneously")
        bases = DEFAULT_BASE_CHARSET.keys()
        if ns.base not in bases:
            raise ArgumentTypeError('base must be one of %s' % set(bases))
        if ns.offset_hexagrams and ns.base == B64:
            raise ArgumentTypeError('Base64 can\'t be offset')
        ngrams = NGRAMS_ENCRYPT_MAPPING.keys()
        if ns.grams and ns.grams.lower() not in ngrams:
            raise ArgumentTypeError('ngrams must be one of %s' % set(ngrams))
    except ArgumentTypeError as ate:
        eprintc(str(ate), fail=True)


# ================================================= HELPER FUNCTIONS ===================================================
def color_supported():
    """
    Does the console support colored output
    :return: True or False
    """
    supported_platform = platform != 'Pocket PC' and (platform != 'win32' or 'ANSICON' in environ)
    is_a_tty = hasattr(stdout, 'isatty') and stdout.isatty()
    return supported_platform and is_a_tty


def eprintc(message: str, color: ANSIColor = None, fail=False, important=False):
    """
    Print message to stderr (with or without color support) and optionally exit with error code. Header (example
    'Header: message' is colored if colon is present, otherwise the entire line.
    colored, otherwise the entire line.
    :param message: message to print
    :param color: ANSI color to highlight message with
    :param fail: highlight text in red
    :param important: highlight text in magenta
    """
    if not color_supported():
        if fail:
            stderr.write("ERROR: %s\n" % message)
            exit(-1)
        else:
            stderr.write(message + "\n")
    else:
        if ':' in message and not fail:
            message = '%s' + message + '\n'
            message = message.replace(': ', ':%s ')
        elif fail:
            message = '%sERROR: ' + message + '\n'
            message = message.replace(': ', ':%s ')
            stderr.write(message % (ANSIColor.RED, ANSIColor.ENDC))
            exit(-1)
        else:
            message = '%s' + message + '%s\n'
        if important:
            stderr.write(message % (ANSIColor.MAGENTA, ANSIColor.ENDC))
        else:
            stderr.write(message % (color, ANSIColor.ENDC))


def deduce_ngram_type(char: str):
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
        raise ArgumentTypeError("invalid message for decryption")


def translate_ngrams_to_hexagrams(encrypted: bytes, ngram_type: str):
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


# ================================================== ENCRYPT/DECRYPT ===================================================
# TODO: Reduce keyspace to used characters and hexagrams
def decrypt(encrypted: bytes, base: int = 64, base_key: str = None, hexagram_offset: int = 0, hexagram_key: str = None):
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
        mapping = dict(zip(hexagram_key, base_key if base_key else DEFAULT_BASE_CHARSET[base]))
        decrypted = encrypted.decode(ENCODING)
        for hexagram in set(decrypted):
            decrypted = decrypted.replace(hexagram, mapping[hexagram])
        if base_key:
            decrypted = decrypted.translate(str.maketrans(DEFAULT_BASE_CHARSET[base], base_key))
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
    except ArgumentTypeError as ate:
        eprintc(str(ate), fail=True)


# TODO: Reduce keyspace to used characters and hexagrams
def encrypt(secret: bytes, base: int = 64, shuffle_base: bool = False, offset_hexagrams: bool = False,
            shuffle_hexagrams: bool = False, ngrams: str = 'hex'):
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
    base_key = DEFAULT_BASE_CHARSET[base]
    if shuffle_base:
        base_key = ''.join(random.sample(DEFAULT_BASE_CHARSET[base], base))
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
        encrypted = encrypted.translate(str.maketrans(base_key, DEFAULT_BASE_CHARSET[base]))
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
            ngrams=ns.grams)
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
