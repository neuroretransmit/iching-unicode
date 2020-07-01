#!/usr/bin/env python

import unittest
from base64 import b16encode, b32encode, b64encode

from const import B16, B32, B64, ENCODING, \
    BASE_DEFAULT_CHARSETS, \
    HEXAGRAMS, DIGRAM_TO_MONOGRAM_MAPPING, HEXAGRAM_TO_TRIGRAM_MAPPING, NGRAMS_ENCRYPT_MAPPING
from iching import encrypt, decrypt

TEST_MESSAGE = bytes('Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus tincidunt congue ipsum,\
sit amet sodales est. Etiam vel purus nisl. In dapibus euismod sem a ultrices. Fusce cursus tincidunt dolor, vel\
ultricies arcu. Ut consequat est metus, ac lacinia ante posuere sit amet. Phasellus tincidunt sagittis imperdiet.\
Quisque vel nunc eros. Etiam malesuada sed leo vitae vestibulum. Phasellus dapibus, dui ut volutpat lobortis, arcu\
nunc accumsan nulla, quis ultrices odio elit ut lectus. Suspendisse egestas vitae ipsum vel suscipit. Sed mollis\
ligula nisl, iaculis maximus tellus pulvinar id. Nam et mollis sem.', ENCODING)


def encode_and_translate(base, encryption_key):
    if base == B16:
        message = b16encode(TEST_MESSAGE).decode(ENCODING)
    elif base == B32:
        message = b32encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
    elif base == B64:
        message = b64encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
    return message.translate(str.maketrans(encryption_key, BASE_DEFAULT_CHARSETS[base]))


class BaseTest:
    def test_encrypt(self):
        raise NotImplementedError

    def test_encrypt_keyed(self):
        raise NotImplementedError

    def test_encrypt_offset(self):
        raise NotImplementedError

    def test_encrypt_random_hexagrams(self):
        raise NotImplementedError

    def test_encrypt_keyed_offset(self):
        raise NotImplementedError

    def test_encrypt_offset_random_hexagrams(self):
        raise NotImplementedError

    def test_encrypt_keyed_offset_random_hexagrams(self):
        raise NotImplementedError

    def test_decrypt(self):
        raise NotImplementedError

    def test_decrypt_keyed(self):
        raise NotImplementedError

    def test_decrypt_offset(self):
        raise NotImplementedError

    def test_decrypt_keyed_offset(self):
        raise NotImplementedError

    def test_decrypt_random_hexagrams(self):
        raise NotImplementedError

    def test_decrypt_offset_random_hexagrams(self):
        raise NotImplementedError

    def test_decrypt_keyed_offset_random_hexagrams(self):
        raise NotImplementedError


class TestMappings(unittest.TestCase):
    """
    Test that all mappings have unique values and that all keys have been enumerated
    """

    def test_digram_to_monogram(self):
        self.assertEqual(4, len(set(DIGRAM_TO_MONOGRAM_MAPPING.keys())))
        self.assertEqual(4, len(set(DIGRAM_TO_MONOGRAM_MAPPING.values())))

    def test_hexagram_to_trigram(self):
        self.assertEqual(64, len(set(HEXAGRAM_TO_TRIGRAM_MAPPING.keys())))
        self.assertEqual(64, len(set(HEXAGRAM_TO_TRIGRAM_MAPPING.values())))

    def test_hexagram_to_digram(self):
        self.assertEqual(64, len(set(HEXAGRAM_TO_TRIGRAM_MAPPING.keys())))
        self.assertEqual(64, len(set(HEXAGRAM_TO_TRIGRAM_MAPPING.values())))


class HexagramB16MessageEncryptionTests(unittest.TestCase, BaseTest):
    """
    Test using hexagrams and base16
    """

    def test_encrypt(self):
        actual, _, _, _ = encrypt(TEST_MESSAGE, B16)
        expected = b16encode(TEST_MESSAGE).decode(ENCODING)
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B16], HEXAGRAMS[:B16]))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed(self):
        actual, encryption_key, _, _ = encrypt(TEST_MESSAGE, B16, shuffle_base=True)
        hexagrams_slice = HEXAGRAMS[:B16]
        expected = encode_and_translate(B16, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_offset(self):
        actual, _, offset, _ = encrypt(TEST_MESSAGE, B16, offset_hexagrams=True)
        expected = b16encode(TEST_MESSAGE).decode(ENCODING)
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B16], HEXAGRAMS[offset: offset + B16]))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_random_hexagrams(self):
        actual, _, _, hexagram_key = encrypt(TEST_MESSAGE, B16, shuffle_hexagrams=True)
        expected = b16encode(TEST_MESSAGE).decode(ENCODING)
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B16], hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed_offset(self):
        actual, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B16, shuffle_base=True, offset_hexagrams=True)
        hexagrams_slice = HEXAGRAMS[offset: offset + B16]
        expected = encode_and_translate(B16, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_offset_random_hexagrams(self):
        actual, _, _, hexagram_key = encrypt(TEST_MESSAGE, B16, offset_hexagrams=True, shuffle_hexagrams=True)
        expected = b16encode(TEST_MESSAGE).decode(ENCODING)
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B16], hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed_offset_random_hexagrams(self):
        actual, encryption_key, _, hexagram_key = encrypt(TEST_MESSAGE, B16,
                                                          shuffle_base=True, offset_hexagrams=True,
                                                          shuffle_hexagrams=True)
        expected = encode_and_translate(B16, encryption_key)
        mapping = dict(zip(encryption_key, hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_decrypt(self):
        encrypted, _, _, _ = encrypt(TEST_MESSAGE, B16)
        actual = decrypt(bytes(encrypted, ENCODING), B16)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_keyed(self):
        encrypted, encryption_key, _, _ = encrypt(TEST_MESSAGE, B16, shuffle_base=True)
        decrypted = decrypt(bytes(encrypted, ENCODING), B16, encryption_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_offset(self):
        encrypted, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B16, offset_hexagrams=True)
        decrypted = decrypt(bytes(encrypted, ENCODING), B16, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_keyed_offset(self):
        encrypted, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B16, shuffle_base=True, offset_hexagrams=True)
        decrypted = decrypt(bytes(encrypted, ENCODING), B16, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_random_hexagrams(self):
        encrypted, _, _, hexagram_key = encrypt(TEST_MESSAGE, B16, shuffle_hexagrams=True)
        actual = decrypt(bytes(encrypted, ENCODING), B16, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_offset_random_hexagrams(self):
        encrypted, _, _, hexagram_key = encrypt(TEST_MESSAGE, B16, offset_hexagrams=True, shuffle_hexagrams=True)
        actual = decrypt(bytes(encrypted, ENCODING), B16, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_keyed_offset_random_hexagrams(self):
        encrypted, encryption_key, _, hexagram_key = encrypt(TEST_MESSAGE, B16,
                                                             shuffle_base=True, offset_hexagrams=True,
                                                             shuffle_hexagrams=True)
        actual = decrypt(bytes(encrypted, ENCODING), B16, base_key=encryption_key, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)


class HexagramB32MessageEncryptionTests(unittest.TestCase, BaseTest):
    """
    Test using hexagrams and base32
    """

    def test_encrypt(self):
        actual, _, _, _ = encrypt(TEST_MESSAGE, B32)
        expected = b32encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B32], HEXAGRAMS[:B32]))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed(self):
        actual, encryption_key, _, _ = encrypt(TEST_MESSAGE, B32, shuffle_base=True)
        hexagrams_slice = HEXAGRAMS[:B32]
        expected = encode_and_translate(B32, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_offset(self):
        actual, _, offset, _ = encrypt(TEST_MESSAGE, B32, offset_hexagrams=True)
        expected = b32encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B32], HEXAGRAMS[offset: offset + B32]))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_random_hexagrams(self):
        actual, _, _, hexagram_key = encrypt(TEST_MESSAGE, B32, shuffle_hexagrams=True)
        expected = b32encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B32], hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed_offset(self):
        actual, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B32, shuffle_base=True, offset_hexagrams=True)
        hexagrams_slice = HEXAGRAMS[offset: offset + B32]
        expected = encode_and_translate(B32, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_offset_random_hexagrams(self):
        actual, _, _, hexagram_key = encrypt(TEST_MESSAGE, B32, offset_hexagrams=True, shuffle_hexagrams=True)
        expected = b32encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B32], hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed_offset_random_hexagrams(self):
        actual, encryption_key, _, hexagram_key = encrypt(TEST_MESSAGE, B32,
                                                          shuffle_base=True, offset_hexagrams=True,
                                                          shuffle_hexagrams=True)
        expected = encode_and_translate(B32, encryption_key)
        mapping = dict(zip(encryption_key, hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_decrypt(self):
        encrypted, _, _, _ = encrypt(TEST_MESSAGE, B32)
        decrypted = decrypt(bytes(encrypted, ENCODING), B32)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_keyed(self):
        encrypted, encryption_key, _, _ = encrypt(TEST_MESSAGE, B32, shuffle_base=True)
        decrypted = decrypt(bytes(encrypted, ENCODING), B32, encryption_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_offset(self):
        encrypted, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B32, offset_hexagrams=True)
        decrypted = decrypt(bytes(encrypted, ENCODING), B32, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_keyed_offset(self):
        encrypted, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B32, shuffle_base=True, offset_hexagrams=True)
        decrypted = decrypt(bytes(encrypted, ENCODING), B32, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_random_hexagrams(self):
        encrypted, _, _, hexagram_key = encrypt(TEST_MESSAGE, B32, shuffle_hexagrams=True)
        actual = decrypt(bytes(encrypted, ENCODING), B32, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_offset_random_hexagrams(self):
        encrypted, _, _, hexagram_key = encrypt(TEST_MESSAGE, B32, offset_hexagrams=True, shuffle_hexagrams=True)
        actual = decrypt(bytes(encrypted, ENCODING), B32, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_keyed_offset_random_hexagrams(self):
        encrypted, encryption_key, _, hexagram_key = encrypt(TEST_MESSAGE, B32,
                                                             shuffle_base=True, offset_hexagrams=True,
                                                             shuffle_hexagrams=True)
        actual = decrypt(bytes(encrypted, ENCODING), B32, base_key=encryption_key, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)


class HexagramB64MessageEncryptionTests(unittest.TestCase, BaseTest):
    def test_encrypt(self):
        actual, _, _, _ = encrypt(TEST_MESSAGE, B64)
        expected = b64encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B64], HEXAGRAMS))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed(self):
        actual, encryption_key, _, _ = encrypt(TEST_MESSAGE, B64, shuffle_base=True)
        hexagrams_slice = HEXAGRAMS[:B64]
        expected = encode_and_translate(B64, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    @unittest.skip("Can't offset hexagrams for base64")
    def test_encrypt_offset(self):
        raise NotImplementedError

    def test_encrypt_random_hexagrams(self):
        actual, _, _, hexagram_key = encrypt(TEST_MESSAGE, B64, shuffle_hexagrams=True)
        expected = b64encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B64], hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    @unittest.skip("Can't offset hexagrams for base64")
    def test_encrypt_keyed_offset(self):
        raise NotImplementedError

    @unittest.skip("Can't offset hexagrams for base64")
    def test_encrypt_offset_random_hexagrams(self):
        raise NotImplementedError

    @unittest.skip("Can't offset hexagrams for base64")
    def test_encrypt_keyed_offset_random_hexagrams(self):
        raise NotImplementedError

    def test_decrypt(self):
        encrypted, _, _, _ = encrypt(TEST_MESSAGE, B64)
        decrypted = decrypt(bytes(encrypted, ENCODING), B64)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_keyed(self):
        encrypted, encryption_key, _, _ = encrypt(TEST_MESSAGE, B64, shuffle_base=True)
        decrypted = decrypt(bytes(encrypted, ENCODING), B64, encryption_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    @unittest.skip("Can't offset hexagrams for base64")
    def test_decrypt_offset(self):
        raise NotImplementedError

    @unittest.skip("Can't offset hexagrams for base64")
    def test_decrypt_keyed_offset(self):
        raise NotImplementedError

    def test_decrypt_random_hexagrams(self):
        encrypted, _, _, hexagram_key = encrypt(TEST_MESSAGE, B64, shuffle_hexagrams=True)
        actual = decrypt(bytes(encrypted, ENCODING), B64, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    @unittest.skip("Can't offset hexagrams for base64")
    def test_decrypt_offset_random_hexagrams(self):
        raise NotImplementedError

    @unittest.skip("Can't offset hexagrams for base64")
    def test_decrypt_keyed_offset_random_hexagrams(self):
        raise NotImplementedError


class MonogramB16MessageEncryptionTests(BaseTest, unittest.TestCase):
    """
    Test using monograms and base16
    """

    NGRAMS = 'mono'

    def test_encrypt(self):
        actual, _, _, _ = encrypt(TEST_MESSAGE, B16, ngrams=self.NGRAMS)
        expected = b16encode(TEST_MESSAGE).decode(ENCODING)
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B16], HEXAGRAMS[:B16]))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed(self):
        actual, encryption_key, _, _ = encrypt(TEST_MESSAGE, B16, shuffle_base=True, ngrams=self.NGRAMS)
        hexagrams_slice = HEXAGRAMS[:B16]
        expected = encode_and_translate(B16, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_offset(self):
        actual, _, offset, _ = encrypt(TEST_MESSAGE, B16, offset_hexagrams=True, ngrams=self.NGRAMS)
        expected = b16encode(TEST_MESSAGE).decode(ENCODING)
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B16], HEXAGRAMS[offset: offset + B16]))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_random_hexagrams(self):
        actual, _, _, hexagram_key = encrypt(TEST_MESSAGE, B16, shuffle_hexagrams=True, ngrams=self.NGRAMS)
        expected = b16encode(TEST_MESSAGE).decode(ENCODING)
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B16], hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed_offset(self):
        actual, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B16, shuffle_base=True, offset_hexagrams=True,
                                                    ngrams=self.NGRAMS)
        hexagrams_slice = HEXAGRAMS[offset: offset + B16]
        expected = encode_and_translate(B16, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_offset_random_hexagrams(self):
        actual, _, _, hexagram_key = encrypt(TEST_MESSAGE, B16, offset_hexagrams=True, shuffle_hexagrams=True,
                                             ngrams=self.NGRAMS)
        expected = b16encode(TEST_MESSAGE).decode(ENCODING)
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B16], hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed_offset_random_hexagrams(self):
        actual, encryption_key, _, hexagram_key = encrypt(TEST_MESSAGE, B16,
                                                          shuffle_base=True, offset_hexagrams=True,
                                                          shuffle_hexagrams=True, ngrams=self.NGRAMS)
        expected = encode_and_translate(B16, encryption_key)
        mapping = dict(zip(encryption_key, hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_decrypt(self):
        encrypted, _, _, _ = encrypt(TEST_MESSAGE, B16, ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B16)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_keyed(self):
        encrypted, encryption_key, _, _ = encrypt(TEST_MESSAGE, B16, shuffle_base=True, ngrams=self.NGRAMS)
        decrypted = decrypt(bytes(encrypted, ENCODING), B16, encryption_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_offset(self):
        encrypted, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B16, offset_hexagrams=True, ngrams=self.NGRAMS)
        decrypted = decrypt(bytes(encrypted, ENCODING), B16, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_keyed_offset(self):
        encrypted, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B16, shuffle_base=True, offset_hexagrams=True,
                                                       ngrams=self.NGRAMS)
        decrypted = decrypt(bytes(encrypted, ENCODING), B16, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_random_hexagrams(self):
        encrypted, _, _, hexagram_key = encrypt(TEST_MESSAGE, B16, shuffle_hexagrams=True, ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B16, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_offset_random_hexagrams(self):
        encrypted, _, _, hexagram_key = encrypt(TEST_MESSAGE, B16, offset_hexagrams=True, shuffle_hexagrams=True,
                                                ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B16, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_keyed_offset_random_hexagrams(self):
        encrypted, encryption_key, _, hexagram_key = encrypt(TEST_MESSAGE, B16,
                                                             shuffle_base=True, offset_hexagrams=True,
                                                             shuffle_hexagrams=True, ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B16, base_key=encryption_key, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)


class MonogramB32MessageEncryptionTests(BaseTest, unittest.TestCase):
    """
    Test using monograms and base32
    """

    NGRAMS = 'mono'

    def test_encrypt(self):
        actual, _, _, _ = encrypt(TEST_MESSAGE, B32, ngrams=self.NGRAMS)
        expected = b32encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B32], HEXAGRAMS[:B32]))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed(self):
        actual, encryption_key, _, _ = encrypt(TEST_MESSAGE, B32, shuffle_base=True, ngrams=self.NGRAMS)
        hexagrams_slice = HEXAGRAMS[:B32]
        expected = encode_and_translate(B32, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_offset(self):
        actual, _, offset, _ = encrypt(TEST_MESSAGE, B32, offset_hexagrams=True, ngrams=self.NGRAMS)
        expected = b32encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B32], HEXAGRAMS[offset: offset + B32]))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_random_hexagrams(self):
        actual, _, _, hexagram_key = encrypt(TEST_MESSAGE, B32, shuffle_hexagrams=True, ngrams=self.NGRAMS)
        expected = b32encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B32], hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed_offset(self):
        actual, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B32, shuffle_base=True, offset_hexagrams=True,
                                                    ngrams=self.NGRAMS)
        hexagrams_slice = HEXAGRAMS[offset: offset + B32]
        expected = encode_and_translate(B32, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_offset_random_hexagrams(self):
        actual, _, _, hexagram_key = encrypt(TEST_MESSAGE, B32, offset_hexagrams=True, shuffle_hexagrams=True,
                                             ngrams=self.NGRAMS)
        expected = b32encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B32], hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed_offset_random_hexagrams(self):
        actual, encryption_key, _, hexagram_key = encrypt(TEST_MESSAGE, B32,
                                                          shuffle_base=True, offset_hexagrams=True,
                                                          shuffle_hexagrams=True, ngrams=self.NGRAMS)
        expected = encode_and_translate(B32, encryption_key)
        mapping = dict(zip(encryption_key, hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_decrypt(self):
        encrypted, _, _, _ = encrypt(TEST_MESSAGE, B32, ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B32)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_keyed(self):
        encrypted, encryption_key, _, _ = encrypt(TEST_MESSAGE, B32, shuffle_base=True, ngrams=self.NGRAMS)
        decrypted = decrypt(bytes(encrypted, ENCODING), B32, encryption_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_offset(self):
        encrypted, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B32, offset_hexagrams=True, ngrams=self.NGRAMS)
        decrypted = decrypt(bytes(encrypted, ENCODING), B32, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_keyed_offset(self):
        encrypted, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B32, shuffle_base=True, offset_hexagrams=True,
                                                       ngrams=self.NGRAMS)
        decrypted = decrypt(bytes(encrypted, ENCODING), B32, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_random_hexagrams(self):
        encrypted, _, _, hexagram_key = encrypt(TEST_MESSAGE, B32, shuffle_hexagrams=True, ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B32, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_offset_random_hexagrams(self):
        encrypted, _, _, hexagram_key = encrypt(TEST_MESSAGE, B32, offset_hexagrams=True, shuffle_hexagrams=True,
                                                ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B32, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_keyed_offset_random_hexagrams(self):
        encrypted, encryption_key, _, hexagram_key = encrypt(TEST_MESSAGE, B32,
                                                             shuffle_base=True, offset_hexagrams=True,
                                                             shuffle_hexagrams=True, ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B32, base_key=encryption_key, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)


class MonogramB64MessageEncryptionTests(BaseTest, unittest.TestCase):
    """
    Test using monograms and base64
    """

    NGRAMS = 'mono'

    def test_encrypt(self):
        actual, _, _, _ = encrypt(TEST_MESSAGE, B64, ngrams=self.NGRAMS)
        expected = b64encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B64], HEXAGRAMS[:B64]))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed(self):
        actual, encryption_key, _, _ = encrypt(TEST_MESSAGE, B64, shuffle_base=True, ngrams=self.NGRAMS)
        hexagrams_slice = HEXAGRAMS[:B64]
        expected = encode_and_translate(B64, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_offset(self):
        actual, _, offset, _ = encrypt(TEST_MESSAGE, B64, offset_hexagrams=True, ngrams=self.NGRAMS)
        expected = b64encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B64], HEXAGRAMS[offset: offset + B64]))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_random_hexagrams(self):
        actual, _, _, hexagram_key = encrypt(TEST_MESSAGE, B64, shuffle_hexagrams=True, ngrams=self.NGRAMS)
        expected = b64encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B64], hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed_offset(self):
        actual, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B64, shuffle_base=True, offset_hexagrams=True,
                                                    ngrams=self.NGRAMS)
        hexagrams_slice = HEXAGRAMS[offset: offset + B64]
        expected = encode_and_translate(B64, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    @unittest.skip("Can't offset hexagrams for base64")
    def test_encrypt_offset_random_hexagrams(self):
        raise NotImplementedError

    @unittest.skip("Can't offset hexagrams for base64")
    def test_encrypt_keyed_offset_random_hexagrams(self):
        raise NotImplementedError

    def test_decrypt(self):
        encrypted, _, _, _ = encrypt(TEST_MESSAGE, B64, ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B64)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_keyed(self):
        encrypted, encryption_key, _, _ = encrypt(TEST_MESSAGE, B64, shuffle_base=True, ngrams=self.NGRAMS)
        decrypted = decrypt(bytes(encrypted, ENCODING), B64, encryption_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    @unittest.skip("Can't offset hexagrams for base64")
    def test_decrypt_offset(self):
        raise NotImplementedError

    @unittest.skip("Can't offset hexagrams for base64")
    def test_decrypt_keyed_offset(self):
        raise NotImplementedError

    def test_decrypt_random_hexagrams(self):
        encrypted, _, _, hexagram_key = encrypt(TEST_MESSAGE, B64, shuffle_hexagrams=True, ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B64, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    @unittest.skip("Can't offset hexagrams for base64")
    def test_decrypt_offset_random_hexagrams(self):
        raise NotImplementedError

    @unittest.skip("Can't offset hexagrams for base64")
    def test_decrypt_keyed_offset_random_hexagrams(self):
        raise NotImplementedError


class DigramB16MessageEncryptionTests(BaseTest, unittest.TestCase):
    """
    Test using digrams and base16
    """

    NGRAMS = 'di'

    def test_encrypt(self):
        actual, _, _, _ = encrypt(TEST_MESSAGE, B16, ngrams=self.NGRAMS)
        expected = b16encode(TEST_MESSAGE).decode(ENCODING)
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B16], HEXAGRAMS[:B16]))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed(self):
        actual, encryption_key, _, _ = encrypt(TEST_MESSAGE, B16, shuffle_base=True, ngrams=self.NGRAMS)
        hexagrams_slice = HEXAGRAMS[:B16]
        expected = encode_and_translate(B16, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_offset(self):
        actual, _, offset, _ = encrypt(TEST_MESSAGE, B16, offset_hexagrams=True, ngrams=self.NGRAMS)
        expected = b16encode(TEST_MESSAGE).decode(ENCODING)
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B16], HEXAGRAMS[offset: offset + B16]))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_random_hexagrams(self):
        actual, _, _, hexagram_key = encrypt(TEST_MESSAGE, B16, shuffle_hexagrams=True, ngrams=self.NGRAMS)
        expected = b16encode(TEST_MESSAGE).decode(ENCODING)
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B16], hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed_offset(self):
        actual, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B16, shuffle_base=True, offset_hexagrams=True,
                                                    ngrams=self.NGRAMS)
        hexagrams_slice = HEXAGRAMS[offset: offset + B16]
        expected = encode_and_translate(B16, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_offset_random_hexagrams(self):
        actual, _, _, hexagram_key = encrypt(TEST_MESSAGE, B16, offset_hexagrams=True, shuffle_hexagrams=True,
                                             ngrams=self.NGRAMS)
        expected = b16encode(TEST_MESSAGE).decode(ENCODING)
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B16], hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed_offset_random_hexagrams(self):
        actual, encryption_key, _, hexagram_key = encrypt(TEST_MESSAGE, B16,
                                                          shuffle_base=True, offset_hexagrams=True,
                                                          shuffle_hexagrams=True, ngrams=self.NGRAMS)
        expected = encode_and_translate(B16, encryption_key)
        mapping = dict(zip(encryption_key, hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_decrypt(self):
        encrypted, _, _, _ = encrypt(TEST_MESSAGE, B16, ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B16)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_keyed(self):
        encrypted, encryption_key, _, _ = encrypt(TEST_MESSAGE, B16, shuffle_base=True, ngrams=self.NGRAMS)
        decrypted = decrypt(bytes(encrypted, ENCODING), B16, encryption_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_offset(self):
        encrypted, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B16, offset_hexagrams=True, ngrams=self.NGRAMS)
        decrypted = decrypt(bytes(encrypted, ENCODING), B16, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_keyed_offset(self):
        encrypted, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B16, shuffle_base=True, offset_hexagrams=True,
                                                       ngrams=self.NGRAMS)
        decrypted = decrypt(bytes(encrypted, ENCODING), B16, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_random_hexagrams(self):
        encrypted, _, _, hexagram_key = encrypt(TEST_MESSAGE, B16, shuffle_hexagrams=True, ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B16, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_offset_random_hexagrams(self):
        encrypted, _, _, hexagram_key = encrypt(TEST_MESSAGE, B16, offset_hexagrams=True, shuffle_hexagrams=True,
                                                ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B16, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_keyed_offset_random_hexagrams(self):
        encrypted, encryption_key, _, hexagram_key = encrypt(TEST_MESSAGE, B16,
                                                             shuffle_base=True, offset_hexagrams=True,
                                                             shuffle_hexagrams=True, ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B16, base_key=encryption_key, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)


class DigramB32MessageEncryptionTests(BaseTest, unittest.TestCase):
    """
    Test using digrams and base32
    """

    NGRAMS = 'di'

    def test_encrypt(self):
        actual, _, _, _ = encrypt(TEST_MESSAGE, B32, ngrams=self.NGRAMS)
        expected = b32encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B32], HEXAGRAMS[:B32]))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed(self):
        actual, encryption_key, _, _ = encrypt(TEST_MESSAGE, B32, shuffle_base=True, ngrams=self.NGRAMS)
        hexagrams_slice = HEXAGRAMS[:B32]
        expected = encode_and_translate(B32, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_offset(self):
        actual, _, offset, _ = encrypt(TEST_MESSAGE, B32, offset_hexagrams=True, ngrams=self.NGRAMS)
        expected = b32encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B32], HEXAGRAMS[offset: offset + B32]))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_random_hexagrams(self):
        actual, _, _, hexagram_key = encrypt(TEST_MESSAGE, B32, shuffle_hexagrams=True, ngrams=self.NGRAMS)
        expected = b32encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B32], hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed_offset(self):
        actual, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B32, shuffle_base=True, offset_hexagrams=True,
                                                    ngrams=self.NGRAMS)
        hexagrams_slice = HEXAGRAMS[offset: offset + B32]
        expected = encode_and_translate(B32, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_offset_random_hexagrams(self):
        actual, _, _, hexagram_key = encrypt(TEST_MESSAGE, B32, offset_hexagrams=True, shuffle_hexagrams=True,
                                             ngrams=self.NGRAMS)
        expected = b32encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B32], hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed_offset_random_hexagrams(self):
        actual, encryption_key, _, hexagram_key = encrypt(TEST_MESSAGE, B32,
                                                          shuffle_base=True, offset_hexagrams=True,
                                                          shuffle_hexagrams=True, ngrams=self.NGRAMS)
        expected = encode_and_translate(B32, encryption_key)
        mapping = dict(zip(encryption_key, hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_decrypt(self):
        encrypted, _, _, _ = encrypt(TEST_MESSAGE, B32, ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B32)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_keyed(self):
        encrypted, encryption_key, _, _ = encrypt(TEST_MESSAGE, B32, shuffle_base=True, ngrams=self.NGRAMS)
        decrypted = decrypt(bytes(encrypted, ENCODING), B32, encryption_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_offset(self):
        encrypted, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B32, offset_hexagrams=True, ngrams=self.NGRAMS)
        decrypted = decrypt(bytes(encrypted, ENCODING), B32, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_keyed_offset(self):
        encrypted, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B32, shuffle_base=True, offset_hexagrams=True,
                                                       ngrams=self.NGRAMS)
        decrypted = decrypt(bytes(encrypted, ENCODING), B32, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_random_hexagrams(self):
        encrypted, _, _, hexagram_key = encrypt(TEST_MESSAGE, B32, shuffle_hexagrams=True, ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B32, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_offset_random_hexagrams(self):
        encrypted, _, _, hexagram_key = encrypt(TEST_MESSAGE, B32, offset_hexagrams=True, shuffle_hexagrams=True,
                                                ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B32, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_keyed_offset_random_hexagrams(self):
        encrypted, encryption_key, _, hexagram_key = encrypt(TEST_MESSAGE, B32,
                                                             shuffle_base=True, offset_hexagrams=True,
                                                             shuffle_hexagrams=True, ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B32, base_key=encryption_key, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)


class DigramB64MessageEncryptionTests(BaseTest, unittest.TestCase):
    """
    Test using digrams and base64
    """

    NGRAMS = 'di'

    def test_encrypt(self):
        actual, _, _, _ = encrypt(TEST_MESSAGE, B64, ngrams=self.NGRAMS)
        expected = b64encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B64], HEXAGRAMS[:B64]))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed(self):
        actual, encryption_key, _, _ = encrypt(TEST_MESSAGE, B64, shuffle_base=True, ngrams=self.NGRAMS)
        hexagrams_slice = HEXAGRAMS[:B64]
        expected = encode_and_translate(B64, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_offset(self):
        actual, _, offset, _ = encrypt(TEST_MESSAGE, B64, offset_hexagrams=True, ngrams=self.NGRAMS)
        expected = b64encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B64], HEXAGRAMS[offset: offset + B64]))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_random_hexagrams(self):
        actual, _, _, hexagram_key = encrypt(TEST_MESSAGE, B64, shuffle_hexagrams=True, ngrams=self.NGRAMS)
        expected = b64encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B64], hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed_offset(self):
        actual, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B64, shuffle_base=True, offset_hexagrams=True,
                                                    ngrams=self.NGRAMS)
        hexagrams_slice = HEXAGRAMS[offset: offset + B64]
        expected = encode_and_translate(B64, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    @unittest.skip("Can't offset hexagrams for base64")
    def test_encrypt_offset_random_hexagrams(self):
        raise NotImplementedError

    @unittest.skip("Can't offset hexagrams for base64")
    def test_encrypt_keyed_offset_random_hexagrams(self):
        raise NotImplementedError

    def test_decrypt(self):
        encrypted, _, _, _ = encrypt(TEST_MESSAGE, B64, ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B64)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_keyed(self):
        encrypted, encryption_key, _, _ = encrypt(TEST_MESSAGE, B64, shuffle_base=True, ngrams=self.NGRAMS)
        decrypted = decrypt(bytes(encrypted, ENCODING), B64, encryption_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    @unittest.skip("Can't offset hexagrams for base64")
    def test_decrypt_offset(self):
        raise NotImplementedError

    @unittest.skip("Can't offset hexagrams for base64")
    def test_decrypt_keyed_offset(self):
        raise NotImplementedError

    def test_decrypt_random_hexagrams(self):
        encrypted, _, _, hexagram_key = encrypt(TEST_MESSAGE, B64, shuffle_hexagrams=True, ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B64, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    @unittest.skip("Can't offset hexagrams for base64")
    def test_decrypt_offset_random_hexagrams(self):
        raise NotImplementedError

    @unittest.skip("Can't offset hexagrams for base64")
    def test_decrypt_keyed_offset_random_hexagrams(self):
        raise NotImplementedError


class TrigramB16MessageEncryptionTests(BaseTest, unittest.TestCase):
    """
    Test using trigrams and base16
    """

    NGRAMS = 'tri'

    def test_encrypt(self):
        actual, _, _, _ = encrypt(TEST_MESSAGE, B16, ngrams=self.NGRAMS)
        expected = b16encode(TEST_MESSAGE).decode(ENCODING)
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B16], HEXAGRAMS[:B16]))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed(self):
        actual, encryption_key, _, _ = encrypt(TEST_MESSAGE, B16, shuffle_base=True, ngrams=self.NGRAMS)
        hexagrams_slice = HEXAGRAMS[:B16]
        expected = encode_and_translate(B16, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_offset(self):
        actual, _, offset, _ = encrypt(TEST_MESSAGE, B16, offset_hexagrams=True, ngrams=self.NGRAMS)
        expected = b16encode(TEST_MESSAGE).decode(ENCODING)
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B16], HEXAGRAMS[offset: offset + B16]))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_random_hexagrams(self):
        actual, _, _, hexagram_key = encrypt(TEST_MESSAGE, B16, shuffle_hexagrams=True, ngrams=self.NGRAMS)
        expected = b16encode(TEST_MESSAGE).decode(ENCODING)
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B16], hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed_offset(self):
        actual, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B16, shuffle_base=True, offset_hexagrams=True,
                                                    ngrams=self.NGRAMS)
        hexagrams_slice = HEXAGRAMS[offset: offset + B16]
        expected = encode_and_translate(B16, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_offset_random_hexagrams(self):
        actual, _, _, hexagram_key = encrypt(TEST_MESSAGE, B16, offset_hexagrams=True, shuffle_hexagrams=True,
                                             ngrams=self.NGRAMS)
        expected = b16encode(TEST_MESSAGE).decode(ENCODING)
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B16], hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed_offset_random_hexagrams(self):
        actual, encryption_key, _, hexagram_key = encrypt(TEST_MESSAGE, B16,
                                                          shuffle_base=True, offset_hexagrams=True,
                                                          shuffle_hexagrams=True, ngrams=self.NGRAMS)
        expected = encode_and_translate(B16, encryption_key)
        mapping = dict(zip(encryption_key, hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_decrypt(self):
        encrypted, _, _, _ = encrypt(TEST_MESSAGE, B16, ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B16)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_keyed(self):
        encrypted, encryption_key, _, _ = encrypt(TEST_MESSAGE, B16, shuffle_base=True, ngrams=self.NGRAMS)
        decrypted = decrypt(bytes(encrypted, ENCODING), B16, encryption_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_offset(self):
        encrypted, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B16, offset_hexagrams=True, ngrams=self.NGRAMS)
        decrypted = decrypt(bytes(encrypted, ENCODING), B16, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_keyed_offset(self):
        encrypted, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B16, shuffle_base=True, offset_hexagrams=True,
                                                       ngrams=self.NGRAMS)
        decrypted = decrypt(bytes(encrypted, ENCODING), B16, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_random_hexagrams(self):
        encrypted, _, _, hexagram_key = encrypt(TEST_MESSAGE, B16, shuffle_hexagrams=True, ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B16, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_offset_random_hexagrams(self):
        encrypted, _, _, hexagram_key = encrypt(TEST_MESSAGE, B16, offset_hexagrams=True, shuffle_hexagrams=True,
                                                ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B16, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_keyed_offset_random_hexagrams(self):
        encrypted, encryption_key, _, hexagram_key = encrypt(TEST_MESSAGE, B16,
                                                             shuffle_base=True, offset_hexagrams=True,
                                                             shuffle_hexagrams=True, ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B16, base_key=encryption_key, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)


class TrigramB32MessageEncryptionTests(BaseTest, unittest.TestCase):
    """
    Test using trigrams and base32
    """

    NGRAMS = 'tri'

    def test_encrypt(self):
        actual, _, _, _ = encrypt(TEST_MESSAGE, B32, ngrams=self.NGRAMS)
        expected = b32encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B32], HEXAGRAMS[:B32]))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed(self):
        actual, encryption_key, _, _ = encrypt(TEST_MESSAGE, B32, shuffle_base=True, ngrams=self.NGRAMS)
        hexagrams_slice = HEXAGRAMS[:B32]
        expected = encode_and_translate(B32, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_offset(self):
        actual, _, offset, _ = encrypt(TEST_MESSAGE, B32, offset_hexagrams=True, ngrams=self.NGRAMS)
        expected = b32encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B32], HEXAGRAMS[offset: offset + B32]))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_random_hexagrams(self):
        actual, _, _, hexagram_key = encrypt(TEST_MESSAGE, B32, shuffle_hexagrams=True, ngrams=self.NGRAMS)
        expected = b32encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B32], hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed_offset(self):
        actual, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B32, shuffle_base=True, offset_hexagrams=True,
                                                    ngrams=self.NGRAMS)
        hexagrams_slice = HEXAGRAMS[offset: offset + B32]
        expected = encode_and_translate(B32, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_offset_random_hexagrams(self):
        actual, _, _, hexagram_key = encrypt(TEST_MESSAGE, B32, offset_hexagrams=True, shuffle_hexagrams=True,
                                             ngrams=self.NGRAMS)
        expected = b32encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B32], hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed_offset_random_hexagrams(self):
        actual, encryption_key, _, hexagram_key = encrypt(TEST_MESSAGE, B32,
                                                          shuffle_base=True, offset_hexagrams=True,
                                                          shuffle_hexagrams=True, ngrams=self.NGRAMS)
        expected = encode_and_translate(B32, encryption_key)
        mapping = dict(zip(encryption_key, hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_decrypt(self):
        encrypted, _, _, _ = encrypt(TEST_MESSAGE, B32, ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B32)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_keyed(self):
        encrypted, encryption_key, _, _ = encrypt(TEST_MESSAGE, B32, shuffle_base=True, ngrams=self.NGRAMS)
        decrypted = decrypt(bytes(encrypted, ENCODING), B32, encryption_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_offset(self):
        encrypted, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B32, offset_hexagrams=True, ngrams=self.NGRAMS)
        decrypted = decrypt(bytes(encrypted, ENCODING), B32, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_keyed_offset(self):
        encrypted, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B32, shuffle_base=True, offset_hexagrams=True,
                                                       ngrams=self.NGRAMS)
        decrypted = decrypt(bytes(encrypted, ENCODING), B32, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_random_hexagrams(self):
        encrypted, _, _, hexagram_key = encrypt(TEST_MESSAGE, B32, shuffle_hexagrams=True, ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B32, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_offset_random_hexagrams(self):
        encrypted, _, _, hexagram_key = encrypt(TEST_MESSAGE, B32, offset_hexagrams=True, shuffle_hexagrams=True,
                                                ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B32, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_keyed_offset_random_hexagrams(self):
        encrypted, encryption_key, _, hexagram_key = encrypt(TEST_MESSAGE, B32,
                                                             shuffle_base=True, offset_hexagrams=True,
                                                             shuffle_hexagrams=True, ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B32, base_key=encryption_key, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)


class TrigramB64MessageEncryptionTests(BaseTest, unittest.TestCase):
    """
    Test using trigrams and base64
    """

    NGRAMS = 'tri'

    def test_encrypt(self):
        actual, _, _, _ = encrypt(TEST_MESSAGE, B64, ngrams=self.NGRAMS)
        expected = b64encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B64], HEXAGRAMS[:B64]))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed(self):
        actual, encryption_key, _, _ = encrypt(TEST_MESSAGE, B64, shuffle_base=True, ngrams=self.NGRAMS)
        hexagrams_slice = HEXAGRAMS[:B64]
        expected = encode_and_translate(B64, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_offset(self):
        actual, _, offset, _ = encrypt(TEST_MESSAGE, B64, offset_hexagrams=True, ngrams=self.NGRAMS)
        expected = b64encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B64], HEXAGRAMS[offset: offset + B64]))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_random_hexagrams(self):
        actual, _, _, hexagram_key = encrypt(TEST_MESSAGE, B64, shuffle_hexagrams=True, ngrams=self.NGRAMS)
        expected = b64encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(BASE_DEFAULT_CHARSETS[B64], hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed_offset(self):
        actual, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B64, shuffle_base=True, offset_hexagrams=True,
                                                    ngrams=self.NGRAMS)
        hexagrams_slice = HEXAGRAMS[offset: offset + B64]
        expected = encode_and_translate(B64, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, NGRAMS_ENCRYPT_MAPPING[self.NGRAMS][mapping[letter]])
        self.assertEqual(actual, expected)

    @unittest.skip("Can't offset hexagrams for base64")
    def test_encrypt_offset_random_hexagrams(self):
        raise NotImplementedError

    @unittest.skip("Can't offset hexagrams for base64")
    def test_encrypt_keyed_offset_random_hexagrams(self):
        raise NotImplementedError

    def test_decrypt(self):
        encrypted, _, _, _ = encrypt(TEST_MESSAGE, B64, ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B64)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_keyed(self):
        encrypted, encryption_key, _, _ = encrypt(TEST_MESSAGE, B64, shuffle_base=True, ngrams=self.NGRAMS)
        decrypted = decrypt(bytes(encrypted, ENCODING), B64, encryption_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    @unittest.skip("Can't offset hexagrams for base64")
    def test_decrypt_offset(self):
        raise NotImplementedError

    @unittest.skip("Can't offset hexagrams for base64")
    def test_decrypt_keyed_offset(self):
        raise NotImplementedError

    def test_decrypt_random_hexagrams(self):
        encrypted, _, _, hexagram_key = encrypt(TEST_MESSAGE, B64, shuffle_hexagrams=True, ngrams=self.NGRAMS)
        actual = decrypt(bytes(encrypted, ENCODING), B64, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    @unittest.skip("Can't offset hexagrams for base64")
    def test_decrypt_offset_random_hexagrams(self):
        raise NotImplementedError

    @unittest.skip("Can't offset hexagrams for base64")
    def test_decrypt_keyed_offset_random_hexagrams(self):
        raise NotImplementedError


if __name__ == '__main__':
    unittest.main()
