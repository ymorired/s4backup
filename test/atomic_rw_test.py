# -*- coding: utf-8 -*-

__author__ = 'yuichi'

import unittest
import json

from atomic_rw import AtomicRWer


class FileListerTest(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_atomic_write(self):
        rwer = AtomicRWer('test/rw_test.txt')

        rwer.open_for_write()
        rwer.write(json.dumps({
            'test': 'testtttt!',
            'num': 1,
        }))

        rwer.close_for_write()

if __name__ == '__main__':
    unittest.main()
