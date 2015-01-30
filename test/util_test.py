__author__ = 'mori.yuichiro'

import unittest
import os

import util


class UtilLockTest(unittest.TestCase):

    def setup(self):
        pass

    def teardown(self):
        pass

    def test_humanize_bytes(self):
        bytes = 3142
        print(util.humanize_bytes(bytes))

        bytes = bytes * 10
        print(util.humanize_bytes(bytes))
        bytes = bytes * 100
        print(util.humanize_bytes(bytes))

        bytes = bytes * 10
        print(util.humanize_bytes(bytes))
        bytes = bytes * 100
        print(util.humanize_bytes(bytes))

        bytes = bytes * 10
        print(util.humanize_bytes(bytes))
        bytes = bytes * 10
        print(util.humanize_bytes(bytes))

        self.assertTrue(True)

if __name__ == '__main__':
    unittest.main()
