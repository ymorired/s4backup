# -*- coding: utf-8 -*-

__author__ = 'yuichi'

import unittest
import json
import os
import pprint

from atomic_rw import AtomicRWer


BASE_TESTFILE_DIR = os.path.join(os.getcwd(), 'test', 'test_data_tmp')
TEST_FILE = os.path.join(BASE_TESTFILE_DIR, 'rw_test.txt')


class FileListerTest(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_atomic_write(self):

        if os.path.isfile(TEST_FILE):
            os.unlink(TEST_FILE)

        rwer = AtomicRWer(TEST_FILE)

        rwer.prepare_write()
        rwer.write_dict({
            'test': 'testtttt!',
            'num': 1,
            # 'bin': '日本語',
            'unic': u'ユニコード',
        })

        rwer.finish_write()

        for obj in rwer.open_and_read():
            pprint.pprint(obj)

    def test_empty_file(self):

        if os.path.isfile(TEST_FILE):
            os.unlink(TEST_FILE)

        rwer = AtomicRWer(TEST_FILE)
        for obj in rwer.open_and_read():
            pprint.pprint(obj)


if __name__ == '__main__':
    unittest.main()
