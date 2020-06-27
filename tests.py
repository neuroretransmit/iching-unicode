from base64 import b16encode, b32encode, b64encode
import unittest

from iching import encrypt, decrypt, ENCODING, DEFAULT_BASE_CHARSET, HEXAGRAMS

TEST_MESSAGE = bytes('Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus tincidunt congue ipsum,\
sit amet sodales est. Etiam vel purus nisl. In dapibus euismod sem a ultrices. Fusce cursus tincidunt dolor, vel\
ultricies arcu. Ut consequat est metus, ac lacinia ante posuere sit amet. Phasellus tincidunt sagittis imperdiet.\
Quisque vel nunc eros. Etiam malesuada sed leo vitae vestibulum. Phasellus dapibus, dui ut volutpat lobortis, arcu\
nunc accumsan nulla, quis ultrices odio elit ut lectus. Suspendisse egestas vitae ipsum vel suscipit. Sed mollis\
ligula nisl, iaculis maximus tellus pulvinar id. Nam et mollis sem.', ENCODING)


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
        actual, _, _ = encrypt(TEST_MESSAGE, self.BASE)
        expected = b16encode(TEST_MESSAGE).decode(ENCODING)
        mapping = dict(zip(DEFAULT_BASE_CHARSET[self.BASE], HEXAGRAMS[:self.BASE]))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed(self):
        actual, encryption_key, _ = encrypt(TEST_MESSAGE, self.BASE, shuffle=True)
        hexagrams_slice = HEXAGRAMS[:self.BASE]
        expected = encode_and_translate(self.BASE, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_decrypt(self):
        encrypted, _, _ = encrypt(TEST_MESSAGE, self.BASE)
        actual = decrypt(bytes(encrypted, ENCODING), self.BASE)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), actual)

    def test_decrypt_keyed(self):
        encrypted, encryption_key, _ = encrypt(TEST_MESSAGE, self.BASE, shuffle=True)
        decrypted = decrypt(bytes(encrypted, ENCODING), self.BASE, encryption_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_offset(self):
        encrypted, encryption_key, offset = encrypt(TEST_MESSAGE, self.BASE, offset_hexagrams=True)
        decrypted = decrypt(bytes(encrypted, ENCODING), self.BASE, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_keyed_offset(self):
        encrypted, encryption_key, offset = encrypt(TEST_MESSAGE, self.BASE, shuffle=True, offset_hexagrams=True)
        decrypted = decrypt(bytes(encrypted, ENCODING), self.BASE, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)


class B32MessageEncryptionTests(unittest.TestCase, BaseTest):
    BASE = 32

    def test_encrypt(self):
        actual, _, _ = encrypt(TEST_MESSAGE, self.BASE)
        expected = b32encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(DEFAULT_BASE_CHARSET[self.BASE], HEXAGRAMS[:self.BASE]))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed(self):
        actual, encryption_key, _ = encrypt(TEST_MESSAGE, self.BASE, shuffle=True)
        hexagrams_slice = HEXAGRAMS[:self.BASE]
        expected = encode_and_translate(self.BASE, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_decrypt(self):
        encrypted, _, _ = encrypt(TEST_MESSAGE, self.BASE)
        decrypted = decrypt(bytes(encrypted, ENCODING), self.BASE)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_keyed(self):
        encrypted, encryption_key, _ = encrypt(TEST_MESSAGE, self.BASE, shuffle=True)
        decrypted = decrypt(bytes(encrypted, ENCODING), self.BASE, encryption_key)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_offset(self):
        encrypted, encryption_key, offset = encrypt(TEST_MESSAGE, self.BASE, offset_hexagrams=True)
        decrypted = decrypt(bytes(encrypted, ENCODING), self.BASE, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_keyed_offset(self):
        encrypted, encryption_key, offset = encrypt(TEST_MESSAGE, self.BASE, shuffle=True, offset_hexagrams=True)
        decrypted = decrypt(bytes(encrypted, ENCODING), self.BASE, encryption_key, offset)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)


class B64MessageEncryptionTests(unittest.TestCase, BaseTest):
    BASE = 64

    def test_encrypt(self):
        actual, _, _ = encrypt(TEST_MESSAGE, self.BASE)
        expected = b64encode(TEST_MESSAGE).decode(ENCODING).replace('=', '')
        mapping = dict(zip(DEFAULT_BASE_CHARSET[self.BASE], HEXAGRAMS))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_encrypt_keyed(self):
        actual, encryption_key, _ = encrypt(TEST_MESSAGE, self.BASE, shuffle=True)
        hexagrams_slice = HEXAGRAMS[:self.BASE]
        expected = encode_and_translate(self.BASE, encryption_key)
        mapping = dict(zip(encryption_key, hexagrams_slice))
        for letter in set(expected):
            expected = expected.replace(letter, mapping[letter])
        self.assertEqual(actual, expected)

    def test_decrypt(self):
        encrypted, _, _ = encrypt(TEST_MESSAGE, self.BASE)
        decrypted = decrypt(bytes(encrypted, ENCODING), self.BASE)
        self.assertEqual(TEST_MESSAGE.decode(ENCODING), decrypted)

    def test_decrypt_keyed(self):
        encrypted, encryption_key, _ = encrypt(TEST_MESSAGE, self.BASE, shuffle=True)
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
