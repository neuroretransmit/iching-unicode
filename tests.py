from base64 import b16encode, b32encode, b64encode
import unittest

from iching import encrypt, decrypt, ENCODING, DEFAULT_BASE_CHARSET, HEXAGRAMS

TEST_MESSAGE = bytes('test', ENCODING)


def encode_and_translate(base, encryption_key):
    if base == 16:
        message = b16encode(TEST_MESSAGE).decode(ENCODING)
    elif base == 32:
        message = b32encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
    elif base == 64:
        message = b64encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
    return message.translate(str.maketrans(encryption_key, DEFAULT_BASE_CHARSET[base]))


class BaseTest:
    def test_encrypt(self):
        raise NotImplementedError

    def test_encrypt_keyed(self):
        raise NotImplementedError

    def test_decrypt(self):
        raise NotImplementedError

    def test_decrypt_keyed(self):
        raise NotImplementedError

    def test_decrypt_offset(self):
        raise NotImplementedError

    def test_decrypt_keyed_offset(self):
        raise NotImplementedError


class B16MessageEncryptionTests(unittest.TestCase, BaseTest):
    BASE = 16

    def test_encrypt(self):
        actual, _, _ = encrypt(TEST_MESSAGE, self.BASE, False)
        expected = b16encode(TEST_MESSAGE).decode(ENCODING)
        mapping = dict(zip(DEFAULT_BASE_CHARSET[self.BASE], HEXAGRAMS[:self.BASE]))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed(self):
        actual, encryption_key, _ = encrypt(TEST_MESSAGE, self.BASE, True)
        hexagrams_slice = HEXAGRAMS[:self.BASE]
        expected = encode_and_translate(self.BASE, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_decrypt(self):
        encrypted, _, _ = encrypt(TEST_MESSAGE, self.BASE, False)
        actual = decrypt(bytes(encrypted, ENCODING), self.BASE, None)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_keyed(self):
        encrypted, encryption_key, _ = encrypt(TEST_MESSAGE, self.BASE, True)
        decrypted = decrypt(bytes(encrypted, ENCODING), self.BASE, encryption_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_offset(self):
        encrypted, encryption_key, offset = encrypt(TEST_MESSAGE, self.BASE, False, True)
        decrypted = decrypt(bytes(encrypted, ENCODING), self.BASE, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_keyed_offset(self):
        encrypted, encryption_key, offset = encrypt(TEST_MESSAGE, self.BASE, True, True)
        decrypted = decrypt(bytes(encrypted, ENCODING), self.BASE, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)


class B32MessageEncryptionTests(unittest.TestCase, BaseTest):
    BASE = 32

    def test_encrypt(self):
        actual, _, _ = encrypt(TEST_MESSAGE, self.BASE, False)
        expected = b32encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(DEFAULT_BASE_CHARSET[self.BASE], HEXAGRAMS[:self.BASE]))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed(self):
        actual, encryption_key, _ = encrypt(TEST_MESSAGE, self.BASE, True)
        hexagrams_slice = HEXAGRAMS[:self.BASE]
        expected = encode_and_translate(self.BASE, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_decrypt(self):
        encrypted, _, _ = encrypt(TEST_MESSAGE, self.BASE, False)
        decrypted = decrypt(bytes(encrypted, ENCODING), self.BASE, None)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_keyed(self):
        encrypted, encryption_key, _ = encrypt(TEST_MESSAGE, self.BASE, True)
        decrypted = decrypt(bytes(encrypted, ENCODING), self.BASE, encryption_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_offset(self):
        encrypted, encryption_key, offset = encrypt(TEST_MESSAGE, self.BASE, False, True)
        decrypted = decrypt(bytes(encrypted, ENCODING), self.BASE, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_keyed_offset(self):
        encrypted, encryption_key, offset = encrypt(TEST_MESSAGE, self.BASE, True, True)
        decrypted = decrypt(bytes(encrypted, ENCODING), self.BASE, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)


class B64MessageEncryptionTests(unittest.TestCase, BaseTest):
    BASE = 64

    def test_encrypt(self):
        actual, _, _ = encrypt(TEST_MESSAGE, self.BASE, False)
        expected = b64encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(DEFAULT_BASE_CHARSET[self.BASE], HEXAGRAMS))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed(self):
        actual, encryption_key, _ = encrypt(TEST_MESSAGE, self.BASE, True)
        hexagrams_slice = HEXAGRAMS[:self.BASE]
        expected = encode_and_translate(self.BASE, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_decrypt(self):
        encrypted, _, _ = encrypt(TEST_MESSAGE, self.BASE, False)
        decrypted = decrypt(bytes(encrypted, ENCODING), self.BASE, None)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_keyed(self):
        encrypted, encryption_key, _ = encrypt(TEST_MESSAGE, self.BASE, True)
        decrypted = decrypt(bytes(encrypted, ENCODING), self.BASE, encryption_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    @unittest.skip("Can't offset hexagrams for base64")
    def test_decrypt_offset(self):
        raise NotImplementedError

    @unittest.skip("Can't offset hexagrams for base64")
    def test_decrypt_keyed_offset(self):
        raise NotImplementedError


if __name__ == '__main__':
    unittest.main()
