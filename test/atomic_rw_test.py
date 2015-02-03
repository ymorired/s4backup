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
            # 'bin': '日本語',
            'unic': u'ユニコード',
        }, ensure_ascii=False).encode('utf8'))

        rwer.close_for_write()

        # rwer.open_for_read()

        for line in rwer.yield_read():
            #
            # for line in rwer.read():
            import pprint
            pprint.pprint(json.loads(line))
            # print line

        # rwer.close_for_read()


if __name__ == '__main__':
    unittest.main()
