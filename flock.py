__author__ = 'mori.yuichiro'

import os


class SimpleFileLock():

    def __init__(self, file_path):
        self.lockfile = os.path.abspath(file_path)
        self.is_locked = False
        self.fd = None

    def aquire_lock(self):
        # http://linuxjm.sourceforge.jp/html/LDP_man-pages/man2/open.2.html
        if self.is_locked:
            return True

        try:
            self.fd = os.open(self.lockfile, os.O_CREAT | os.O_EXCL | os.O_RDWR)
        except OSError as e:
            if e.errno != os.errno.EEXIST:
                raise
            return False

        self.is_locked = True
        return True

    def release(self):
        if self.is_locked:
            os.close(self.fd)
            os.unlink(self.lockfile)
            self.is_locked = False

