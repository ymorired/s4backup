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


def calc_sha1_from_str(input_str):
    h = hashlib.sha1()
    h.update(input_str)
    return h.hexdigest()


def humanize_bytes(bytes):
    if bytes < 10000:
        return '{:}B'.format(bytes)

    kibytes = float(bytes) / 1024.0
    if kibytes < 100.0:
        return '{:.2f}KiB'.format(kibytes)
    if kibytes < 10000.0:
        return '{:.1f}KiB'.format(kibytes)

    mibytes = float(kibytes) / 1024.0
    if mibytes < 100.0:
        return '{:.2f}MiB'.format(mibytes)
    if mibytes < 10000.0:
        return '{:.1f}MiB'.format(mibytes)

    gibytes = float(mibytes) / 1024.0
    if gibytes < 100.0:
        return '{:.2f}GiB'.format(gibytes)
    return '{:.1f}GiB'.format(gibytes)


def percentize(progress, total):
    progress = float(progress)
    if total == 0 or total == 0.0:
        total = 1
    total = float(total)
    return progress / total * 100

