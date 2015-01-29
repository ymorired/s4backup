__author__ = 'mori.yuichiro'

import unittest
import os

from flock import SimpleFileLock


class SimpleFileLockTest(unittest.TestCase):

    def setup(self):
        pass

    def teardown(self):
        pass

    def test_lock(self):

        path = 'test/test_lock'
        a_lock = SimpleFileLock(path)
        b_lock = SimpleFileLock(path)

        self.assertTrue(a_lock.aquire_lock())
        self.assertFalse(b_lock.aquire_lock())

        a_lock.release()

        self.assertTrue(b_lock.aquire_lock())
        b_lock.release()

if __name__ == '__main__':
    unittest.main()
