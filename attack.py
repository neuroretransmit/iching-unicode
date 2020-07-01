#!/usr/bin/env python3

import binascii
import base64 as b64
from itertools import permutations
import time
from functools import reduce

from argparse import ArgumentParser
from const import B16, B32, B64, BASE_DEFAULT_CHARSETS, \
    MONOGRAMS, DIGRAMS, TRIGRAMS, HEXAGRAMS
from output import eprintc

parser = ArgumentParser(description='Attack message encoded in I Ching ngrams')
parser.add_argument('-m', '--message', help='encrypted message', required=True)
# TODO: parser.add_argument('-bk', '--base-key', help='base key if known for decryption', default=None)
# TODO: parser.add_argument('-hk', '--hexagram-key', help='hexagram key if known for decryption', default=None)
# TODO: parser.add_argument('-oh', '--offset-hexagrams', help='offset hexagram slice if known for base {16, 32}',
#                    nargs='?', const=True, default=False)
# TODO: parser.add_argument('-te', '--target-encoding', help='character encoding to target')
ns = parser.parse_args()


def deduce_bases(message: str) -> list:
    """
    Deduce base numbering system and return set of viable bases
    :param message: encrypted message
    :return: set of viable bases
    """
    msg_len = len(message)
    unique_chars = set(message)
    viable_bases = []
    if msg_len < B16:
        eprintc('unable to determine base, choosing all', warn=True)
        viable_bases = [B16, B32, B64]
    else:
        if msg_len >= B16 >= unique_chars:
            viable_bases.append(B16)
        if msg_len >= B32 >= unique_chars:
            viable_bases.append(B32)
        if msg_len >= B64 >= unique_chars:
            viable_bases.append(B64)
    eprintc('using bases %s' % viable_bases, warn=True)
    return viable_bases


def deduce_ngrams(char: str) -> str:
    """
    Deduce ngram type and return ngram alphabet
    :param char:
    :return: ngram alphabet
    """
    if char in MONOGRAMS:
        return MONOGRAMS
    elif char in DIGRAMS:
        return DIGRAMS
    elif char in TRIGRAMS:
        return TRIGRAMS
    elif char in HEXAGRAMS:
        return HEXAGRAMS


def validate_args():
    """
    Validate command line arguments
    """
    if not ns.message:
        parser.error('must supply message to decrypt')
    for c in ns.message:
        if c not in MONOGRAMS and c not in DIGRAMS and c not in TRIGRAMS and c not in HEXAGRAMS:
            eprintc('invalid message', fail=True)


# O(scary)
def attack(message: str, bases: list, ngram_alphabet: str):
    base_alphabets = set(BASE_DEFAULT_CHARSETS[b] for b in bases)
    bases_permutations = [permutations(b) for b in base_alphabets]
    ngrams_permutations = permutations(ngram_alphabet)
    average = 0
    i = 0
    for rp in ngrams_permutations:
        base_offset = 0
        for bp in bases_permutations:
            base = bases[base_offset]
            for ap in bp:
                start = time.time()
                mapping = dict(zip(list(rp), list(ap)))
                permutation = message
                for k, v in mapping.items():
                    permutation = permutation.replace(k, v)
                try:
                    stop = time.time()
                    # TODO: Adjust calculation for partial known mapping
                    base_multiplier = reduce(lambda b1, b2: b1 * b2, [b ** b for b in bases[base_offset:]])
                    average += (stop - start) * base_multiplier
                    i += 1
                    days_left = (average / i) // (24 * 3600)
                    eprintc('Days Left: %s' % days_left, important=True, one_line=True)
                    # TODO: Enable encoding target
                    if base == B16:
                        b64.b16decode(permutation).decode('utf-8')
                    elif base == B32:
                        b64.b32decode(permutation).decode('utf-8')
                    elif base == B64:
                        b64.b64decode(permutation).decode('utf-8')
                    with open('permutations.txt', 'a') as f:
                        f.write(permutation + '\n')
                except binascii.Error:
                    continue
                except UnicodeDecodeError:
                    continue
                except ValueError:
                    continue
            base_offset += 1


if __name__ == '__main__':
    validate_args()
    bases, ngram_alphabet = deduce_bases(ns.message), deduce_ngrams(ns.message[0])
    attack(ns.message, bases, ngram_alphabet)

