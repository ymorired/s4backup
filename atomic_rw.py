# -*- coding: utf-8 -*-

__author__ = 'yuichi'

import os
import zlib


class AtomicRWer(object):

    def __init__(self, file_path):

        self.file_path = os.path.abspath(file_path)
        self.fd = None
        self.r_fd = None

    def open_for_write(self):
        self.fd = open(self.file_path, 'ab')

    def write(self, record):
        if self.fd is None:
            raise Exception('File descriptor is not open!')

        checksum = '{:8x}'.format(zlib.crc32(record)).encode('utf8')
        self.fd.write(record + b' ' + checksum + b'\n')

    def close_for_write(self):
        self.fd.close()
        self.fd = None

    def yield_read(self):

        with open(self.file_path, 'rb') as r_fd:
            for line in r_fd:
                record, checksum = line.strip().rsplit(b' ', 1)
                if checksum.decode('utf8') == '{:8x}'.format(zlib.crc32(record)).encode('utf8'):
                    yield record.decode('utf8')

    def open_for_read(self):
        self.r_fd = open(self.file_path, 'rb')

    def read(self):
        if self.r_fd is None:
            raise Exception('File descriptor is not open!')

        ret_lines = []
        for line in self.r_fd:
            record, checksum = line.strip().rsplit(b' ', 1)
            if checksum.decode('utf8') == '{:8x}'.format(zlib.crc32(record)).encode('utf8'):
                ret_lines.append(record.decode('utf8'))
            else:
                print('checksum error for record {}'.format(record))

        return ret_lines

    def close_for_read(self):
        self.r_fd.close()
        self.r_fd = None

