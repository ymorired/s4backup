__author__ = 'mori.yuichiro'

import os
import errno
import hashlib


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def calc_md5_from_filename(file_path, block_size=2**20):
    with open(file_path) as f:
        return calc_md5_from_file(f, block_size)


def calc_md5_from_file(fp, block_size=2**20):
    md5 = hashlib.md5()
    while True:
        data = fp.read(block_size)
        if not data:
            break
        md5.update(data)

    return md5.hexdigest()

