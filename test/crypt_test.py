__author__ = 'mori.yuichiro'

import unittest
import os
import subprocess
import filecmp
import binascii

from crypt import Encryptor


BASE_TESTFILE_DIR = os.path.join(os.getcwd(), 'test', 'test_data_tmp')


class EncryptorTest(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_encrypt_multi(self):
        org_file = os.path.join(BASE_TESTFILE_DIR, 'check.txt')

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

        # key = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        key = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        # key_str = '000102030405060708090a0b0c0d0e0f'
        cryptor = Encryptor(key, iv)

        enc_file = os.path.join(BASE_TESTFILE_DIR, 'check.enc.txt')
        cryptor.encrypt_file_by_path(org_file, enc_file)

        dec_file = os.path.join(BASE_TESTFILE_DIR, 'check.dec_openssl.txt')
        key_str = binascii.b2a_hex(key)
        iv_str = binascii.b2a_hex(iv)
        cmd = 'openssl enc -d -aes-128-cbc -in %s -out %s -K %s -iv %s' % (enc_file, dec_file, key_str, iv_str)
        subprocess.call(cmd, shell=True)

        self.assertTrue(filecmp.cmp(org_file, dec_file))

    def test_decrypt_multi(self):
        org_file = os.path.join(BASE_TESTFILE_DIR, 'check.txt')

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
        key = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'

        enc_file = os.path.join(BASE_TESTFILE_DIR, 'check.enc_openssl.txt')
        key_str = binascii.b2a_hex(key)
        iv_str = binascii.b2a_hex(iv)
        cmd = 'openssl enc -e -aes-128-cbc -in %s -out %s -K %s -iv %s' % (org_file, enc_file, key_str, iv_str)
        subprocess.call(cmd, shell=True)

        # dec_file = './test/check.dec_openssl.txt'
        # cmd = 'openssl enc -d -aes-128-cbc -in %s -out %s -K %s -iv %s' % (enc_file, dec_file, key_str, iv_str)
        # subprocess.call(cmd, shell=True)
        #
        # self.assertTrue(filecmp.cmp(org_file, dec_file))

        cryptor = Encryptor(key, iv)

        dec_file = os.path.join(BASE_TESTFILE_DIR, 'check.dec.txt')
        cryptor.decrypt_file_by_path(enc_file, dec_file)
        self.assertTrue(filecmp.cmp(org_file, dec_file))

    def test_encrypt_decrypt(self):
        org_file = os.path.join(BASE_TESTFILE_DIR, 'check.txt')

        # test 0 byte file
        with open(org_file, 'wt') as f:
            f.write('')
        self._test_encrypt_decrypt(org_file)

        # test 1000 - 1100 bytes file
        for i in range(1000, 1100):
            with open(org_file, 'wt') as f:
                for j in range(0, i):
                    f.write('e')
            self._test_encrypt_decrypt(org_file)

    def _test_encrypt_decrypt(self, org_file):
        iv = Encryptor.generate_iv()
        key = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        cryptor = Encryptor(key, iv)

        enc_file = os.path.join(BASE_TESTFILE_DIR, 'check.enc.txt')
        cryptor.encrypt_file_by_path(org_file, enc_file)

        decryptor = Encryptor(key, iv)

        dec_file = os.path.join(BASE_TESTFILE_DIR, 'check.dec.txt')
        decryptor.decrypt_file_by_path(enc_file, dec_file)
        self.assertTrue(filecmp.cmp(org_file, dec_file))

    # def _openssl_command(self, encrypt_flg, key_bin, iv_bin, in_file, out_file):
    #
    #     if encrypt_flg:
    #         encrypt_opt = '-e'
    #     else:
    #         encrypt_opt = '-d'
    #
    #     if len(key_bin) == 16:
    #         enc_method = '-aes-128-cbc'
    #     elif len(key_bin) == 24:
    #         enc_method = '-aes-196-cbc'
    #     elif len(key_bin) == 32:
    #         enc_method = '-aes-256-cbc'
    #     else:
    #         raise Exception('Unsupported key length')
    #
    #     key_str = binascii.b2a_hex(key_bin)
    #     iv_str = binascii.b2a_hex(iv_bin)
    #
    #     cmd = 'openssl enc %s %s -in %s -out %s -K %s -iv %s' % \
    #         (encrypt_opt, enc_method, in_file, out_file, key_str, iv_str)
    #     subprocess.call(cmd, shell=True)


if __name__ == '__main__':
    unittest.main()
