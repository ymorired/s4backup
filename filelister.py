__author__ = 'mori.yuichiro'

import os
import fnmatch


class FileLister():
    def __init__(self, target_path, ignore_dirs=None, ignore_file_patterns=None):
        abs_path = os.path.abspath(target_path)
        if not os.path.isdir(abs_path):
            raise Exception('Invalid target path!')

        self.target_path = abs_path

        ignore_file_patterns = ignore_file_patterns or []
        self.ignore_file_patterns = ignore_file_patterns
        ignore_dirs = ignore_dirs or []
        self.ignore_dirs = ignore_dirs

    def _is_ignore_dir(self, dir_name):
        relative_path = dir_name.replace(self.target_path, "", 1)
        relative_path += '/'
        for ignore_dir in self.ignore_dirs:
            if relative_path.startswith('/' + ignore_dir + '/'):
                return True
        return False

    def _is_ignore_file(self, file_name):
        for ignore_pattern in self.ignore_file_patterns:
            if fnmatch.fnmatch(file_name, ignore_pattern):
                return True
        return False

    def _fild_all_files(self, directory):
        for root, dirs, files in os.walk(directory):
            if self._is_ignore_dir(root):
                continue

            for file_name in files:
                if self._is_ignore_file(file_name):
                    continue

                yield os.path.join(root, file_name)

    def get_file_list(self):
        files = []
        for found_file in self._fild_all_files(self.target_path):
            files.append(found_file)
        return files

