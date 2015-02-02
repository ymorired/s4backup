# -*- coding: utf-8 -*-

__author__ = 'yuichi'

import os
import zlib


class AtomicRWer(object):

    def __init__(self, file_path):

        self.file_path = os.path.abspath(file_path)
        self.fd = None

    def open_for_write(self):

        self.fd = open(self.file_path, 'ab')

    def write(self, record):
        checksum = '{:8x}'.format(zlib.crc32(record)).encode()
        self.fd.write(record + b' ' + checksum + b'\n')
