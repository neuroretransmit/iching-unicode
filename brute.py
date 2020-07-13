#!/usr/bin/env python3

# TODO: Thread

import binascii
import base64 as b64
from itertools import permutations
import time
from functools import reduce

from argparse import ArgumentParser
from const import B16, B32, B64, BASE_DEFAULT_CHARSETS, \
    MONOGRAMS, DIGRAMS, TRIGRAMS, HEXAGRAMS
from helper import eprintc, \
    deduce_ngram_type, translate_ngrams_to_hexagrams


def deduce_bases(message: str) -> list:
    """
    Deduce base numbering system and return set of viable bases
    :param message: encrypted message
    :return: set of viable bases
    """
    msg_len = len(message)
    unique_chars = set(message)
    unique_chars_len = len(unique_chars)
    viable_bases = []
    if msg_len < B16:
        eprintc('unable to determine base, choosing all', warn=True)
        viable_bases = list(BASE_DEFAULT_CHARSETS.keys())
    if msg_len >= B16 >= unique_chars_len:
        viable_bases.append(B16)
    if msg_len < B32 and unique_chars_len > B16:
        viable_bases = [B32, B64]
    if msg_len < B64 and unique_chars_len > B32:
        viable_bases = [B64]
    else:
        if msg_len >= B16 >= unique_chars_len:
            viable_bases.append(B16)
        if msg_len >= B32 >= unique_chars_len:
            viable_bases.append(B32)
        if msg_len >= B64 >= unique_chars_len:
            viable_bases.append(B64)
    eprintc('Bases: bases %s' % viable_bases, important=True)
    return viable_bases


def validate_ngrams(ngrams: str):
    """
    Validate encrypted message character set
    :param ngrams:
    """
    for c in ngrams:
        if c not in MONOGRAMS and c not in DIGRAMS and c not in TRIGRAMS and c not in HEXAGRAMS:
            eprintc('invalid message', fail=True)


def validate_base_key(base_key: str):
    """
    Deduce viable base character sets
    :param base_key: known
    :return: set of viable character sets
    """
    viable_charsets = []
    for v in BASE_DEFAULT_CHARSETS.values():
        for c in base_key:
            if c not in v:
                break
        replaced = v
        for c1 in base_key:
            replaced = replaced.replace(c1, '')
        if replaced != '':
            viable_charsets.append(replaced)
    if len(viable_charsets) == 0:
        eprintc('invalid base key', fail=True)
    return viable_charsets


def validate_args():
    """
    Validate command line arguments
    :return: viable base charsets
    """
    if not ns.message:
        parser.error('must supply message to decrypt')
    validate_ngrams(ns.message)
    if ns.base_key and not ns.hexagram_key \
            or ns.hexagram_key and not ns.base_key:
        eprintc('known mappings require both base key and hexagram key', fail=True)
    elif (ns.base_key and ns.hexagram_key) and (len(ns.base_key) != len(ns.hexagram_key)):
        eprintc('known mappings requires both base key and hexagram key of equal length', fail=True)
    if ns.hexagram_key:
        validate_ngrams(ns.hexagram_key)


def attempt_decode(base: int, permutation: str, encoding: str):
    """
    Attempt to decode replaced permutation
    :param base: base number to decode in
    :param permutation: permuted replacement
    :param encoding: target character encoding
    """
    if base == B16:
        decoded = b64.b16decode(permutation).decode(encoding)
    elif base == B32:
        permutation += '=' * ((8 - (len(permutation) % 8)) % 8)
        decoded = b64.b32decode(permutation).decode(encoding)
    elif base == B64:
        permutation += '=' * ((4 - (len(permutation) % 4)) % 4)
        decoded = b64.b64decode(permutation).decode(encoding)
    return decoded


def permute_bases_charsets(bases: list, viable_base_charsets: list) -> list:
    """
    Reduce bases charsets by removing known keys
    :param bases: bases to target
    :param viable_base_charsets: base charsets to target
    :return:
    """
    base_charset_partials = set()
    bases_permutations = []
    for base, viable_charset in zip(bases, viable_base_charsets):
        if viable_charset == '':
            bases.remove(base)
            viable_base_charsets.remove(viable_charset)
            eprintc('key longer than base, removing base%d' % base, warn=True)
            continue
        if len(viable_charset) != base:
            replaced = BASE_DEFAULT_CHARSETS[base]
            for c1 in viable_charset:
                for c2 in BASE_DEFAULT_CHARSETS[base]:
                    if c1 != c2:
                        replaced = replaced.replace(c2, '')
            base_charset_partials.add(replaced)
    for base, partial, viable_base_charset in zip(bases, base_charset_partials, viable_base_charsets):
        if len(partial) > 1:
            partial_permutations = permutations(partial)
            full_permutations = []
            for permutation in partial_permutations:
                full_permutations.append(viable_base_charset + permutation)
            bases_permutations += permutations(partial)
        elif len(partial) == 1:
            bases_permutations += [viable_base_charset + partial]
    return bases_permutations \
        if len(bases_permutations) != 0 else [permutations(b) for b in viable_base_charsets]


def permute_hexagrams(known: str):
    hexagrams_permutations = []
    if known == HEXAGRAMS:
        hexagrams_permutations = permutations(HEXAGRAMS)
    else:
        partial = ''.join(c for c in HEXAGRAMS if c not in known)
        partial_permutations = permutations(partial)
        for permutation in partial_permutations:
            hexagrams_permutations.append(known + ''.join(permutation))
    return hexagrams_permutations


# O(scary)
# TODO: Write keys for each permutation, add date to file
def attack(message: str, base_key: str, hexagram_charset: str):
    """
    Attack the encrypted message
    :param message: encrypted message
    :param viable_base_charsets: set of viable bases
    :param hexagram_charset: character set for hexagrams
    """
    bases = deduce_bases(message)
    if base_key:
        viable_base_charsets = validate_base_key(base_key)
    else:
        viable_base_charsets = set(BASE_DEFAULT_CHARSETS[b] for b in BASE_DEFAULT_CHARSETS.keys())
    bases_permutations = permute_bases_charsets(bases, viable_base_charsets)
    hexagrams_permutations = permute_hexagrams(hexagram_charset)
    average = 0
    i = 0
    found = False
    for hexagram_permutation in hexagrams_permutations:
        base_offset = 0
        for base_permutations in bases_permutations:
            base = bases[base_offset]
            for base_charset_permutation in base_permutations:
                start = time.time()
                mapping = dict(zip(list(hexagram_permutation), list(base_charset_permutation)))
                permutation = message
                for b, viable_charset in mapping.items():
                    permutation = permutation.replace(b, viable_charset)
                try:
                    stop = time.time()
                    # TODO: Adjust calculation for partial known mapping
                    base_multiplier = reduce(lambda b1, b2: b1 * b2, [b ** b for b in bases[base_offset:]])
                    average += (stop - start) * base_multiplier
                    i += 1
                    days_left = (average / i) // (24 * 3600)
                    eprintc('Days Left: %s' % days_left, important=True, one_line=True)
                    # TODO: Enable encoding target
                    decoded = attempt_decode(base, permutation, 'utf-8')
                    eprintc('\nFound: ' + decoded, important=True)
                    found = True
                    break
                except binascii.Error:
                    continue
                except UnicodeDecodeError:
                    continue
                except ValueError:
                    continue
            if found:
                break
            base_offset += 1
        if found:
            break


if __name__ == '__main__':
    parser = ArgumentParser(description='Attack message encoded in I Ching ngrams')
    parser.add_argument('-m', '--message', help='encrypted message', required=True)
    parser.add_argument('-bk', '--base-key', help='base key or partial if known for decryption', default=None)
    parser.add_argument('-hk', '--hexagram-key', help='hexagram key or partial if known for decryption', default=None)
    # TODO: parser.add_argument('-oh', '--offset-hexagrams', help='offset hexagram slice if known for base {16, 32}',
    #                    nargs='?', const=True, default=False)
    # TODO: parser.add_argument('-te', '--target-encoding', help='character encoding to target')
    ns = parser.parse_args()
    viable_base_charsets = validate_args()
    message = translate_ngrams_to_hexagrams(ns.message, deduce_ngram_type(ns.message[0]), as_bytes=False)
    attack(message, ns.base_key if ns.base_key else None, HEXAGRAMS if not ns.hexagram_key else ns.hexagram_key)
