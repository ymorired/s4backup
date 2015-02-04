# -*- coding: utf-8 -*-

__author__ = 'yuichi'

import os
import json
import zlib


class AtomicRWer(object):

    def __init__(self, file_path):

        self.file_path = os.path.abspath(file_path)
        self.w_fd = None

    def prepare_write(self):
        self.w_fd = open(self.file_path, 'ab')

    def write_dict(self, record):
        if self.w_fd is None:
            raise Exception('File descriptor is not open!')

        if not isinstance(record, dict):
            raise Exception('Input must be dictionary!')

        output_string = json.dumps(record, ensure_ascii=False).encode('utf8')
        checksum = '{:8x}'.format(zlib.crc32(output_string)).encode('utf8')

        self.w_fd.write(output_string + b' ' + checksum + b'\n')

    def finish_write(self):
        self.w_fd.close()
        self.w_fd = None

    def open_and_read(self):
        if not os.path.isfile(self.file_path):
            return

        with open(self.file_path, 'rb') as r_fd:
            for line in r_fd:
                record, checksum = line.strip().rsplit(b' ', 1)
                if checksum.decode('utf8') == '{:8x}'.format(zlib.crc32(record)).encode('utf8'):
                    try:
                        val = json.loads(record.decode('utf8'))
                        yield val
                    except ValueError as e:
                        pass
                else:
                    # checksum error
                    pass
