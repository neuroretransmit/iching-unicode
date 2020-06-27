from base64 import b16encode, b32encode, b64encode
import unittest

from iching import encrypt, decrypt, DEFAULT_BASE_CHARSET, HEXAGRAMS

TEST_MESSAGE = bytes('test', 'utf-8')


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
    def test_encrypt(self):
        actual, _, _ = encrypt(TEST_MESSAGE, 16, False)
        expected = b16encode(TEST_MESSAGE).decode('utf-8')
        mapping = dict(zip(DEFAULT_BASE_CHARSET[16], HEXAGRAMS[:16]))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed(self):
        actual, encryption_key, _ = encrypt(TEST_MESSAGE, 16, True)
        iching_slice = HEXAGRAMS[:16]
        expected = b16encode(TEST_MESSAGE)
        expected = bytes(expected)
        trans = expected.maketrans(bytes(encryption_key, 'utf-8'), bytes(DEFAULT_BASE_CHARSET[16], 'utf-8'))
        expected = expected.translate(trans)
        mapping = dict(zip(encryption_key, iching_slice))
        expected = expected.decode('utf-8').replace('=', '')
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_decrypt(self):
        encrypted, _, _ = encrypt(TEST_MESSAGE, 16, False)
        actual = decrypt(bytes(encrypted, 'utf-8'), 16, None)
        self.assertEqual(TEST_MESSAGE.decode('utf-8'), actual)

    def test_decrypt_keyed(self):
        encrypted, encryption_key, _ = encrypt(TEST_MESSAGE, 16, True)
        decrypted = decrypt(bytes(encrypted, 'utf-8'), 16, encryption_key)
        self.assertEqual(TEST_MESSAGE.decode('utf-8'), decrypted)

    def test_decrypt_offset(self):
        encrypted, encryption_key, offset = encrypt(TEST_MESSAGE, 16, False, True)
        decrypted = decrypt(bytes(encrypted, 'utf-8'), 16, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode('utf-8'), decrypted)

    def test_decrypt_keyed_offset(self):
        encrypted, encryption_key, offset = encrypt(TEST_MESSAGE, 16, True, True)
        decrypted = decrypt(bytes(encrypted, 'utf-8'), 16, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode('utf-8'), decrypted)


class B32MessageEncryptionTests(unittest.TestCase, BaseTest):
    def test_encrypt(self):
        actual, _, _ = encrypt(TEST_MESSAGE, 32, False)
        expected = b32encode(TEST_MESSAGE).decode('utf-8').replace('=', '')
        mapping = dict(zip(DEFAULT_BASE_CHARSET[32], HEXAGRAMS[:32]))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed(self):
        actual, encryption_key, _ = encrypt(TEST_MESSAGE, 32, True)
        iching_slice = HEXAGRAMS[:32]
        expected = b32encode(TEST_MESSAGE)
        expected = bytes(expected)
        trans = expected.maketrans(bytes(encryption_key, 'utf-8'), bytes(DEFAULT_BASE_CHARSET[32], 'utf-8'))
        expected = expected.translate(trans)
        mapping = dict(zip(encryption_key, iching_slice))
        expected = expected.decode('utf-8').replace('=', '')
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_decrypt(self):
        encrypted, _, _ = encrypt(TEST_MESSAGE, 32, False)
        decrypted = decrypt(bytes(encrypted, 'utf-8'), 32, None)
        self.assertEqual(TEST_MESSAGE.decode('utf-8'), decrypted)

    def test_decrypt_keyed(self):
        encrypted, encryption_key, _ = encrypt(TEST_MESSAGE, 32, True)
        decrypted = decrypt(bytes(encrypted, 'utf-8'), 32, encryption_key)
        self.assertEqual(TEST_MESSAGE.decode('utf-8'), decrypted)

    def test_decrypt_offset(self):
        encrypted, encryption_key, offset = encrypt(TEST_MESSAGE, 32, False, True)
        decrypted = decrypt(bytes(encrypted, 'utf-8'), 32, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode('utf-8'), decrypted)

    def test_decrypt_keyed_offset(self):
        encrypted, encryption_key, offset = encrypt(TEST_MESSAGE, 32, True, True)
        decrypted = decrypt(bytes(encrypted, 'utf-8'), 32, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode('utf-8'), decrypted)


class B64MessageEncryptionTests(unittest.TestCase, BaseTest):
    def test_encrypt(self):
        actual, _, _ = encrypt(TEST_MESSAGE, 64, False)
        expected = b64encode(TEST_MESSAGE).decode('utf-8').replace('=', '')
        mapping = dict(zip(DEFAULT_BASE_CHARSET[64], HEXAGRAMS))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed(self):
        actual, encryption_key, _ = encrypt(TEST_MESSAGE, 64, True)
        iching_slice = HEXAGRAMS[:64]
        expected = b64encode(TEST_MESSAGE)
        expected = bytes(expected)
        trans = expected.maketrans(bytes(encryption_key, 'utf-8'), bytes(DEFAULT_BASE_CHARSET[64], 'utf-8'))
        expected = expected.translate(trans)
        mapping = dict(zip(encryption_key, iching_slice))
        expected = expected.decode('utf-8').replace('=', '')
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_decrypt(self):
        encrypted, _, _ = encrypt(TEST_MESSAGE, 64, False)
        decrypted = decrypt(bytes(encrypted, 'utf-8'), 64, None)
        self.assertEqual(TEST_MESSAGE.decode('utf-8'), decrypted)

    def test_decrypt_keyed(self):
        encrypted, encryption_key, _ = encrypt(TEST_MESSAGE, 64, True)
        decrypted = decrypt(bytes(encrypted, 'utf-8'), 64, encryption_key)
        self.assertEqual(TEST_MESSAGE.decode('utf-8'), decrypted)

    @unittest.skip("Can't offset hexagrams for base64")
    def test_decrypt_offset(self):
        raise NotImplementedError

    @unittest.skip("Can't offset hexagrams for base64")
    def test_decrypt_keyed_offset(self):
        raise NotImplementedError


if __name__ == '__main__':
    unittest.main()
