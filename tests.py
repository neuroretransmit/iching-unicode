#!/usr/bin/env python

from base64 import b16encode, b32encode, b64encode
import unittest

from iching import encrypt, decrypt, B16, B32, B64, ENCODING, DEFAULT_BASE_CHARSET, HEXAGRAMS

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
    return message.translate(str.maketrans(encryption_key, DEFAULT_BASE_CHARSET[base]))


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


class B16MessageEncryptionTests(unittest.TestCase, BaseTest):
    def test_encrypt(self):
        actual, _, _, _ = encrypt(TEST_MESSAGE, B16)
        expected = b16encode(TEST_MESSAGE).decode(ENCODING)
        mapping = dict(zip(DEFAULT_BASE_CHARSET[B16], HEXAGRAMS[:B16]))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed(self):
        actual, encryption_key, _, _ = encrypt(TEST_MESSAGE, B16, shuffle=True)
        hexagrams_slice = HEXAGRAMS[:B16]
        expected = encode_and_translate(B16, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_offset(self):
        actual, _, offset, _ = encrypt(TEST_MESSAGE, B16, offset_hexagrams=True)
        expected = b16encode(TEST_MESSAGE).decode(ENCODING)
        mapping = dict(zip(DEFAULT_BASE_CHARSET[B16], HEXAGRAMS[offset: offset + B16]))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_random_hexagrams(self):
        actual, _, _, hexagram_key = encrypt(TEST_MESSAGE, B16, randomize_hexagrams=True)
        expected = b16encode(TEST_MESSAGE).decode(ENCODING)
        mapping = dict(zip(DEFAULT_BASE_CHARSET[B16], hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed_offset(self):
        actual, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B16, shuffle=True, offset_hexagrams=True)
        hexagrams_slice = HEXAGRAMS[offset: offset + B16]
        expected = encode_and_translate(B16, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_offset_random_hexagrams(self):
        actual, _, _, hexagram_key = encrypt(TEST_MESSAGE, B16, offset_hexagrams=True, randomize_hexagrams=True)
        expected = b16encode(TEST_MESSAGE).decode(ENCODING)
        mapping = dict(zip(DEFAULT_BASE_CHARSET[B16], hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed_offset_random_hexagrams(self):
        actual, encryption_key, _, hexagram_key = encrypt(TEST_MESSAGE, B16,
                                                          shuffle=True, offset_hexagrams=True, randomize_hexagrams=True)
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
        encrypted, encryption_key, _, _ = encrypt(TEST_MESSAGE, B16, shuffle=True)
        decrypted = decrypt(bytes(encrypted, ENCODING), B16, encryption_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_offset(self):
        encrypted, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B16, offset_hexagrams=True)
        decrypted = decrypt(bytes(encrypted, ENCODING), B16, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_keyed_offset(self):
        encrypted, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B16, shuffle=True, offset_hexagrams=True)
        decrypted = decrypt(bytes(encrypted, ENCODING), B16, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_random_hexagrams(self):
        encrypted, _, _, hexagram_key = encrypt(TEST_MESSAGE, B16, randomize_hexagrams=True)
        actual = decrypt(bytes(encrypted, ENCODING), B16, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_offset_random_hexagrams(self):
        encrypted, _, _, hexagram_key = encrypt(TEST_MESSAGE, B16, offset_hexagrams=True, randomize_hexagrams=True)
        actual = decrypt(bytes(encrypted, ENCODING), B16, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_keyed_offset_random_hexagrams(self):
        encrypted, encryption_key, _, hexagram_key = encrypt(TEST_MESSAGE, B16,
                                                             shuffle=True, offset_hexagrams=True,
                                                             randomize_hexagrams=True)
        actual = decrypt(bytes(encrypted, ENCODING), B16, decryption_key=encryption_key, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)


class B32MessageEncryptionTests(unittest.TestCase, BaseTest):
    def test_encrypt(self):
        actual, _, _, _ = encrypt(TEST_MESSAGE, B32)
        expected = b32encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(DEFAULT_BASE_CHARSET[B32], HEXAGRAMS[:B32]))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed(self):
        actual, encryption_key, _, _ = encrypt(TEST_MESSAGE, B32, shuffle=True)
        hexagrams_slice = HEXAGRAMS[:B32]
        expected = encode_and_translate(B32, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_offset(self):
        actual, _, offset, _ = encrypt(TEST_MESSAGE, B32, offset_hexagrams=True)
        expected = b32encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(DEFAULT_BASE_CHARSET[B32], HEXAGRAMS[offset: offset + B32]))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_random_hexagrams(self):
        actual, _, _, hexagram_key = encrypt(TEST_MESSAGE, B32, randomize_hexagrams=True)
        expected = b32encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(DEFAULT_BASE_CHARSET[B32], hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed_offset(self):
        actual, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B32, shuffle=True, offset_hexagrams=True)
        hexagrams_slice = HEXAGRAMS[offset: offset + B32]
        expected = encode_and_translate(B32, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_offset_random_hexagrams(self):
        actual, _, _, hexagram_key = encrypt(TEST_MESSAGE, B32, offset_hexagrams=True, randomize_hexagrams=True)
        expected = b32encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(DEFAULT_BASE_CHARSET[B32], hexagram_key))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed_offset_random_hexagrams(self):
        actual, encryption_key, _, hexagram_key = encrypt(TEST_MESSAGE, B32,
                                                          shuffle=True, offset_hexagrams=True, randomize_hexagrams=True)
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
        encrypted, encryption_key, _, _ = encrypt(TEST_MESSAGE, B32, shuffle=True)
        decrypted = decrypt(bytes(encrypted, ENCODING), B32, encryption_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_offset(self):
        encrypted, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B32, offset_hexagrams=True)
        decrypted = decrypt(bytes(encrypted, ENCODING), B32, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_keyed_offset(self):
        encrypted, encryption_key, offset, _ = encrypt(TEST_MESSAGE, B32, shuffle=True, offset_hexagrams=True)
        decrypted = decrypt(bytes(encrypted, ENCODING), B32, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_random_hexagrams(self):
        encrypted, _, _, hexagram_key = encrypt(TEST_MESSAGE, B32, randomize_hexagrams=True)
        actual = decrypt(bytes(encrypted, ENCODING), B32, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_offset_random_hexagrams(self):
        encrypted, _, _, hexagram_key = encrypt(TEST_MESSAGE, B32, offset_hexagrams=True, randomize_hexagrams=True)
        actual = decrypt(bytes(encrypted, ENCODING), B32, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_keyed_offset_random_hexagrams(self):
        encrypted, encryption_key, _, hexagram_key = encrypt(TEST_MESSAGE, B32,
                                                             shuffle=True, offset_hexagrams=True,
                                                             randomize_hexagrams=True)
        actual = decrypt(bytes(encrypted, ENCODING), B32, decryption_key=encryption_key, hexagram_key=hexagram_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)


class B64MessageEncryptionTests(unittest.TestCase, BaseTest):
    def test_encrypt(self):
        actual, _, _, _ = encrypt(TEST_MESSAGE, B64)
        expected = b64encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(DEFAULT_BASE_CHARSET[B64], HEXAGRAMS))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed(self):
        actual, encryption_key, _, _ = encrypt(TEST_MESSAGE, B64, shuffle=True)
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
        actual, _, _, hexagram_key = encrypt(TEST_MESSAGE, B64, randomize_hexagrams=True)
        expected = b64encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(DEFAULT_BASE_CHARSET[B64], hexagram_key))
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
        encrypted, encryption_key, _, _ = encrypt(TEST_MESSAGE, B64, shuffle=True)
        decrypted = decrypt(bytes(encrypted, ENCODING), B64, encryption_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    @unittest.skip("Can't offset hexagrams for base64")
    def test_decrypt_offset(self):
        raise NotImplementedError

    @unittest.skip("Can't offset hexagrams for base64")
    def test_decrypt_keyed_offset(self):
        raise NotImplementedError

    def test_decrypt_random_hexagrams(self):
        encrypted, _, _, hexagram_key = encrypt(TEST_MESSAGE, B64, randomize_hexagrams=True)
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
