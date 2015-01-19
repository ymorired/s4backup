import unittest
import subprocess
import filecmp
import binascii

from crypt import Encryptor


class EncryptorTest(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_encrypt_multi(self):
        org_file = './test/check.txt'

        with open(org_file, 'wt') as f:
            f.write('')
        self._test_encrypt(org_file)

        for i in range(1000, 1100):
            # print('i:%s' % i)
            with open(org_file, 'wt') as f:
                for j in range(1, i + 1):
                    f.write('e')
            self._test_encrypt(org_file)

    def _test_encrypt(self, org_file):
        # iv = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0a'
        # iv_str = '000102030405060708090a0b0c0d0e0a'
        iv = Encryptor.generate_iv()

        cryptor = Encryptor(
            '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f',
            iv
        )
        # org_file = './test/check.txt'
        enc_file = './test/check.enc.txt'
        cryptor.encrypt_file_by_path(org_file, enc_file)

        dec_file = './test/check.dec_openssl.txt'
        key_str = '000102030405060708090a0b0c0d0e0f'
        iv_str = binascii.b2a_hex(iv)
        cmd = 'openssl enc -d -aes-128-cbc -in %s -out %s -K %s -iv %s' % (enc_file, dec_file, key_str, iv_str)
        subprocess.call(cmd, shell=True)

        self.assertTrue(filecmp.cmp(org_file, dec_file))

    def test_decrypt_multi(self):
        org_file = './test/check.txt'

        with open(org_file, 'wt') as f:
            f.write('')
        self._test_decrypt(org_file)

        for i in range(1000, 1100):
            # print('i:%s' % i)
            with open(org_file, 'wt') as f:
                for j in range(1, i + 1):
                    f.write('e')
            self._test_decrypt(org_file)

    def _test_decrypt(self, org_file):
        iv = Encryptor.generate_iv()

        # org_file = './test/check.txt'
        enc_file = './test/check.enc_openssl.txt'
        key_str = '000102030405060708090a0b0c0d0e0f'
        iv_str = binascii.b2a_hex(iv)
        cmd = 'openssl enc -e -aes-128-cbc -in %s -out %s -K %s -iv %s' % (org_file, enc_file, key_str, iv_str)
        subprocess.call(cmd, shell=True)

        # dec_file = './test/check.dec_openssl.txt'
        # cmd = 'openssl enc -d -aes-128-cbc -in %s -out %s -K %s -iv %s' % (enc_file, dec_file, key_str, iv_str)
        # subprocess.call(cmd, shell=True)
        #
        # self.assertTrue(filecmp.cmp(org_file, dec_file))

        cryptor = Encryptor(
            '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f',
            iv
        )

        dec_file = './test/check.dec.txt'
        cryptor.decrypt_file_by_path(enc_file, dec_file)
        self.assertTrue(filecmp.cmp(org_file, dec_file))


if __name__ == '__main__':
    unittest.main()
