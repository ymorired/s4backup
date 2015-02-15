# -*- coding: utf-8 -*-

__author__ = 'yuichi'

import os
import json
import zlib
import logging


class AtomicRWer(object):

    def __init__(self, file_path):

        self.file_path = os.path.abspath(file_path)
        self.w_fd = None
        self.logger = logging.getLogger(__name__)

    def prepare_write(self):
        self.w_fd = open(self.file_path, 'ab')

    def write_dict(self, record):
        if self.w_fd is None:
            raise Exception('File descriptor is not open!')

        if not isinstance(record, dict):
            raise Exception('Input must be dictionary!')

        output_string = json.dumps(record, ensure_ascii=False).encode('utf8')
        checksum = '{:x}'.format(zlib.crc32(output_string)).encode('utf8')

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
                validation_checksum = '{:x}'.format(zlib.crc32(record)).encode('utf8')
                unicode_record = record.decode('utf8')
                if checksum.decode('utf8') == validation_checksum:
                    try:
                        val = json.loads(unicode_record)
                        yield val
                    except ValueError as e:
                        self.logger.warn('Failed to parse json line:{}'.format(unicode_record))
                else:
                    # checksum error
                    calced_checksum = '{:x}'.format(zlib.crc32(record)).encode('utf8')
                    warn_msg = 'Error on checksum validation calced_checksum:{}, read_checksum:{}'.format(calced_checksum, checksum.decode('utf8'))
                    self.logger.warn(warn_msg)
