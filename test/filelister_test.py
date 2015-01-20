__author__ = 'mori.yuichiro'

import unittest
import os

from filelister import FileLister


class FileListerTest(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_ignore_file_patterns(self):
        file_patterns = [
            '*.txt',
            '.DS_Store',
        ]

        lister = FileLister('./test/', ignore_dirs=[], ignore_file_patterns=file_patterns)

        self.assertTrue(lister._is_ignore_file('.DS_Store'))
        self.assertTrue(lister._is_ignore_file('test.txt'))
        self.assertFalse(lister._is_ignore_file('test.tx'))
        self.assertFalse(lister._is_ignore_file('file.pdf'))

    def test_ignore_dir_patterns(self):
        dir_names = [
            '.git',
            '.s4backup',
            'test_ignore',
            'test/two'
        ]

        path = os.path.join('.', 'test')
        lister = FileLister(path, ignore_dirs=dir_names)

        abpath = os.path.abspath(path)
        self.assertTrue(lister._is_ignore_dir(os.path.join(abpath, '.git')))
        self.assertTrue(lister._is_ignore_dir(os.path.join(abpath, '.s4backup')))
        self.assertTrue(lister._is_ignore_dir(os.path.join(abpath, 'test_ignore')))
        self.assertTrue(lister._is_ignore_dir(os.path.join(abpath, 'test', 'two')))

        self.assertFalse(lister._is_ignore_dir(os.path.join(abpath, 'test_ignores')))
        self.assertFalse(lister._is_ignore_dir(os.path.join(abpath, 'test', '.git')))


if __name__ == '__main__':
    unittest.main()
