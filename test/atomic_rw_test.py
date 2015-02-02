# -*- coding: utf-8 -*-

__author__ = 'yuichi'

from atomic_rw import AtomicRWer
import json


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

        rwer.close()3

if __name__ == '__main__':
    unittest.main()
