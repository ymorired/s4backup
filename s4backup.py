#!/usr/bin/env python

r"""

Copyright (c) 2015 Yuichiro Mori

This software is released under the MIT License.

http://opensource.org/licenses/mit-license.php

"""

__author__ = 'mori.yuichiro'

import time
import pprint
import logging
import json
import argparse
import tempfile

import boto
from boto.s3.key import Key

from crypt import Encryptor
from filelister import FileLister
from flock import SimpleFileLock
from atomic_rw import AtomicRWer
from util import *

CONFIG_DIR = '.s4backup'
CONFIG_FILE_NAME = 'config.json'
IGNORE_FILE_NAME = 'file_ignore'
IGNORE_DIR_NAME = 'dir_ignore'
LOCK_FILE_NAME = 'lock'

IGNORE_FILE_RULES = [
    '.DS_Store',
    '*~',
]

IGNORE_DIRS = [
    '.git',
    '.idea',
    CONFIG_DIR
]


class S4Backupper():
    def __init__(self, target_path, aws_access_key_id, aws_secret_access_key, s3bucket_name, s3prefix,
                 use_hash_filename=False, use_encryption=False, key_str=None, iv_str=None, aws_region=None,
                 dry_run_flg=False):

        abs_path = os.path.abspath(target_path)
        if not os.path.isdir(abs_path):
            raise Exception('Invalid target path!')
        self.target_path = abs_path

        self.snapshot_version = time.strftime('%Y-%m-%d_%H-%M-%S', time.gmtime(time.time()))

        # *** directoy initialization ***
        log_base_path = os.path.join(abs_path, CONFIG_DIR, 'logs')
        mkdir_p(log_base_path)
        log_path = os.path.join(log_base_path, self.snapshot_version)
        mkdir_p(log_path)
        self.log_path = log_path

        self.stats = {
            # 'bytes_uploaded': 0,
            'bytes_scanned': 0,
            'files_uploaded': 0,
            'files_scanned': 0,
            'bytes_total': 0,
            'files_total': 0,
            'bytes_processed': 0,
            'files_processed': 0,
        }

        self.s3keys = {}

        # *** AWS S3 Connection ***
        self.s3conn = boto.s3.connect_to_region(
            aws_region or 'us-east-1',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
        )
        self.s3bucket = self.s3conn.get_bucket(s3bucket_name)
        self.s3prefix = str(s3prefix)  # get lid of unicode
        self.dry_run_flg = dry_run_flg

        # *** Logger ***
        # Logger to show progress
        logger = logging.getLogger('S3ArchiverStdout')
        logger.setLevel(logging.DEBUG)
        h = logging.StreamHandler()
        h.setLevel(logging.INFO)
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
        logger.addHandler(h)

        h2 = logging.FileHandler(os.path.join(self.log_path, 'detail.log'))
        h2.setLevel(logging.DEBUG)
        h2.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
        logger.addHandler(h2)
        self.logger = logger

        self.file_lister = FileLister(
            self.target_path,
            ignore_dirs=IGNORE_DIRS,
            ignore_file_patterns=IGNORE_FILE_RULES,
        )

        state_path = os.path.join(abs_path, CONFIG_DIR, 'state.txt')
        self.state_writer = AtomicRWer(state_path)
        self.prev_state = {}

        self.hash_filename_flg = use_hash_filename

        self.encryption_flg = use_encryption
        if self.encryption_flg:
            self.encryptor = Encryptor.initialize_by_hex(key_str, iv_str)
        else:
            self.encryptor = None

        self.update_count = 0

    def _is_modified(self, file_path):

        unicode_file_path = file_path.decode('utf8')
        (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(file_path)

        if unicode_file_path in self.prev_state:
            prev_file_state = self.prev_state[unicode_file_path]

            if size == prev_file_state['size'] and \
                    mtime == prev_file_state['mtime']:
                return False

        return True

    def _encrypt_file(self, in_file_p, out_file_p):

        encryption_start_time = time.time()
        self.encryptor.encrypt_file(in_file_p, out_file_p)
        encryption_seconds = time.time() - encryption_start_time
        encrypted_size = out_file_p.tell()
        in_file_p.seek(0, os.SEEK_SET)
        out_file_p.seek(0, os.SEEK_SET)

        return encrypted_size, encryption_seconds

    def _upload_file(self, upload_path, meta_info, target_file_p):

        md5_start_time = time.time()
        md5sum = calc_md5_from_file(target_file_p)
        md5_seconds = time.time() - md5_start_time
        target_file_p.seek(0, os.SEEK_SET)

        parts = [
            'action:upload_md5',
            's3path:{}'.format(upload_path),
            'upload_md5_sec:{:.4f}'.format(md5_seconds),
        ]
        self.logger.debug(' '.join(parts))

        s3path = '/'.join([self.s3prefix, upload_path])
        if s3path in self.s3keys:
            cached_key = self.s3keys[s3path]
            if cached_key.etag == '"%s"' % md5sum:
                self.logger.warn('Upload skipped using cached key %s ' % upload_path)
                return

        # TODO: this action is verbose...
        fkey = self.s3bucket.get_key(s3path)
        if fkey and fkey.etag == '"%s"' % md5sum:
            self.logger.warn('%s skipped using remote key' % upload_path)
            return

        # file does not exist on s3 or modified from s3 version
        if self.dry_run_flg:
            self.logger.warn('Upload skipped due to dry run flg file:%s' % upload_path)
            return

        obj_key = Key(self.s3bucket)
        obj_key.key = s3path
        for key, value in meta_info.items():
            obj_key.set_metadata(key, value)
        upload_start_time = time.time()
        obj_key.set_contents_from_file(target_file_p, encrypt_key=True)
        upload_seconds = time.time() - upload_start_time

        parts = [
            'action:upload_s3',
            's3path:{}'.format(upload_path),
            'upload_sec:{:.4f}'.format(upload_seconds),
        ]
        self.logger.debug(' '.join(parts))

        self.stats['files_uploaded'] += 1
        # self.stats['bytes_uploaded'] += size

        return

    def _backup_file(self, file_path, upload_path):

        if not self._is_modified(file_path):
            self.logger.debug('File is not modified. Skipping:%s, %s' % (file_path, upload_path))
            self.stats['files_processed'] += 1
            return

        unicode_file_path = file_path.decode('utf8')
        (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(file_path)
        with open(file_path, 'rb') as in_file_p:
            with tempfile.TemporaryFile() as out_file_p:

                upload_file_p = in_file_p

                encryption_seconds = 0
                encrypted_size = 0
                if self.encryption_flg:
                    encrypted_size, encryption_seconds = self._encrypt_file(in_file_p, out_file_p)
                    upload_file_p = out_file_p

                log_parts = [
                    'path=%s' % upload_path,
                    'size=%s' % size,
                    'enc_size=%s' % encrypted_size,
                ]
                self.logger.debug(' '.join(log_parts))

                file_info = {
                    'size': size,
                    'mtime': mtime,
                    'enc_size': encrypted_size,
                    'file_path': unicode_file_path,
                    'upload_path': upload_path.decode('utf8'),
                }
                self.stats['files_scanned'] += 1
                self.stats['bytes_scanned'] += size

                meta_info = {
                    'original_size': str(size),
                    'mtime': str(mtime),
                }

                self._upload_file(upload_path, meta_info, upload_file_p)
                if not self.dry_run_flg:
                    self.state_writer.write_dict(file_info)

                log_parts = [
                    'file={}'.format(file_path),
                    'path={}'.format(upload_path),
                    'mtime={:}'.format(mtime),
                    'enc_sec={:.3f}'.format(encryption_seconds),
                ]
                self.logger.debug(' '.join(log_parts))

                self.stats['files_processed'] += 1
                self.logger.debug('%s/%s uploaded file=%s' % (self.stats['files_scanned'], self.stats['files_total'], upload_path))

    def _auto_log_update(self):
        self.update_count += 1
        if self.update_count % 20 != 0:
            return

        # bytes_total = self.stats['bytes_total']
        # bytes_uploaded = self.stats['bytes_uploaded']
        # bytes_scanned = self.stats['bytes_scanned']
        # self.logger.info(
        #     'Bytes uploaded:{}({:.2f}%) '.format(humanize_bytes(bytes_uploaded), percentize(bytes_uploaded, bytes_total)) +
        #     'scanned:{}({:.2f}%) '.format(humanize_bytes(bytes_scanned), percentize(bytes_scanned, bytes_total)) +
        #     'total:{} '.format(humanize_bytes(self.stats['bytes_total'])) +
        #     ''
        # )

        files_total = self.stats['files_total']
        if files_total == 0:
            files_total = 1

        files_processed = self.stats['files_processed']
        files_uploaded = self.stats['files_uploaded']
        files_scanned = self.stats['files_scanned']
        self.logger.info(
            'Files processed:{}({:.2f}%) '.format(files_processed, percentize(files_processed, files_total)) +
            'uploaded:{} '.format(files_uploaded) +
            'total:{} '.format(files_total) +
            ''
        )

    def _save_directory_state(self, files):
        state_file_path = os.path.join(self.log_path, 'state.txt')
        with open(state_file_path, 'wt') as f:
            bytes_total = 0
            files_total = 0
            for found_file in files:
                relative_path = found_file.replace(self.target_path + '/', "", 1)
                (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(found_file)
                parts = [
                    'path=%s' % relative_path,
                    'size=%s' % size,
                    'ctime=%s' % ctime,
                    'mtime=%s' % mtime,
                ]
                line = '\t'.join(parts) + '\n'
                f.write(line)

                bytes_total += size
                files_total += 1

            self.stats['bytes_total'] = bytes_total
            self.stats['files_total'] = files_total

        upload_path = '/'.join(['logs', self.snapshot_version, 'state.txt'])
        self._backup_file(state_file_path, upload_path)

    def _load_prev_state(self):
        prev_state = {}
        for rec in self.state_writer.open_and_read():
            key = rec['file_path']
            prev_state[key] = rec

        self.prev_state = prev_state

    def _convert_to_upload_filename(self, file_path):
        relative_path = file_path.replace(self.target_path + '/', "", 1)
        if self.hash_filename_flg:
            relative_path = calc_sha1_from_str(relative_path)

        return relative_path

    def _validate_filenames(self, file_paths):
        if not self.hash_filename_flg:
            return

        hashed_names = set([])
        for test_target in file_paths:
            relative_path = self._convert_to_upload_filename(test_target)
            if relative_path in hashed_names:
                raise Exception('Filename hash is duplicated! path:{}'.format(test_target))
            hashed_names.add(relative_path)

    def _save_finished_state(self, files):
        index_file_path = os.path.join(self.target_path, CONFIG_DIR, 'index.txt')
        with open(index_file_path, 'wt') as f:
            for found_file in files:
                relative_path = found_file.replace(self.target_path + '/', "", 1)
                (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(found_file)
                parts = [
                    u'type:file',
                    u'file_path:{}'.format(filename_to_unicode(relative_path)),
                    's3_path:{}'.format(self._convert_to_upload_filename(found_file)),
                    'size:{:}'.format(size),
                    'ctime:{:}'.format(ctime),
                    'mtime:{:}'.format(mtime),
                ]
                line = u'\t'.join(parts) + u'\n'
                f.write(line.encode('utf8'))

            parts = [
                'type:meta',
                'time:{:}'.format(int(time.time()))
            ]
            f.write('\t'.join(parts) + '\n')

        upload_path = '/'.join(['meta', 'index.txt'])
        self._backup_file(index_file_path, upload_path)

    def _execute_backup(self):
        self.logger.info('Snapshot version:%s' % self.snapshot_version)
        time_start = time.time()

        self._load_prev_state()
        self.state_writer.prepare_write()

        s3path = '/'.join([self.s3prefix, 'data'])
        key_num = 0
        for fkey in self.s3bucket.list(s3path):
            self.s3keys[fkey.key.encode('utf-8')] = fkey
            key_num += 1

        self.logger.info('Cached keys:%s' % key_num)

        files = self.file_lister.get_file_list()

        self._validate_filenames(files)
        self._save_directory_state(files)

        for found_file in files:
            relative_path = self._convert_to_upload_filename(found_file)
            self._backup_file(found_file, '/'.join(['data', relative_path]))
            self._auto_log_update()

        self._save_finished_state(files)

        # self.logger.info('Bytes uploaded:%s scanned:%s total:%s' % (self.stats['bytes_uploaded'], self.stats['bytes_scanned'], self.stats['bytes_total']))
        self.logger.info('Files uploaded:%s scanned:%s total:%s' % (self.stats['files_uploaded'], self.stats['files_scanned'], self.stats['files_total']))

        time_end = time.time()

        summary_file_path = os.path.join(self.log_path, 'summary.txt')
        with open(summary_file_path, 'wt') as f:
            f.write('time_start :%s (%s)\n' % (time.strftime('%Y-%m-%d %H-%M-%S', time.gmtime(time_start)), time_start))
            f.write('time_end   :%s (%s)\n' % (time.strftime('%Y-%m-%d %H-%M-%S', time.gmtime(time_end)), time_end))
            seconds_spent = time_end - time_start
            f.write('seconds_spent:%s\n' % (seconds_spent))
            f.write('\n')
            # f.write('Bytes uploaded:%s scanned:%s total:%s\n' % (self.stats['bytes_uploaded'], self.stats['bytes_scanned'], self.stats['bytes_total']))
            f.write('Files uploaded:%s scanned:%s total:%s\n' % (self.stats['files_uploaded'], self.stats['files_scanned'], self.stats['files_total']))

        upload_path = '/'.join(['logs', self.snapshot_version, 'summary.txt'])
        self._backup_file(summary_file_path, upload_path)

    def execute_backup(self):
        locker = SimpleFileLock(os.path.join(self.target_path, CONFIG_DIR, LOCK_FILE_NAME))
        if not locker.aquire_lock():
            self.logger.error('Cannot get lock!')
            return

        try:
            self._execute_backup()
        except Exception as e:
            self.logger.exception(e)
            raise e
        finally:
            locker.release()

    def _fetch_list(self):
        remote_path = '/'.join(['meta', 'index.txt'])
        remote_index_file_path = os.path.join(self.target_path, CONFIG_DIR, 'remote_index.txt')

        self._retrive_file(remote_path, remote_index_file_path)

    def _retrive_file(self, remote_path, output_file_path):
        s3path = '/'.join([self.s3prefix, remote_path])

        fkey = self.s3bucket.get_key(s3path)
        if fkey is None:
            raise Exception('Remote key does not exist! key:{}'.format(s3path))

        dirname = os.path.dirname(output_file_path)
        if not os.path.isdir(dirname):
            os.makedirs(dirname)

        parts = [
            's3_path:{}'.format(s3path),
            'output_filename:{}'.format(output_file_path)
        ]
        self.logger.info(' '.join(parts))

        with tempfile.TemporaryFile() as temp_file_p:
            with open(output_file_path, 'wb') as out_file_p:

                fkey.get_contents_to_file(temp_file_p)
                # fkey.get_contents_to_filename(remote_index_file_path)
                temp_file_p.seek(0, os.SEEK_SET)

                decryption_start_time = time.time()
                self.encryptor.decrypt_file(temp_file_p, out_file_p)
                decryption_seconds = time.time() - decryption_start_time

        self.logger.info('Fetched list to {}'.format(output_file_path))

    def fetch_list(self):
        locker = SimpleFileLock(os.path.join(self.target_path, CONFIG_DIR, LOCK_FILE_NAME))
        if not locker.aquire_lock():
            self.logger.error('Cannot get lock!')
            return

        try:
            self._fetch_list()
        except Exception as e:
            self.logger.exception(e)
            raise e
        finally:
            locker.release()


    def _restore(self):
        # self._fetch_list()

        output_path = 'output'
        os.makedirs(os.path.join(output_path))

        recs = []
        remote_index_file_path = os.path.join(self.target_path, CONFIG_DIR, 'remote_index.txt')
        with open(remote_index_file_path, 'rb') as out_file_p:

            for line in out_file_p:
                rec = {}
                line = line.rstrip()
                for col in line.split('\t'):
                    vs = col.split(':', 1)
                    k = vs[0]
                    v = vs[1]
                    rec[k] = v.decode('utf8')

                if rec['type'] == 'file':
                    recs.append(rec)

        for rec in recs:
            file_name = unicode_to_filename(rec['file_path'])

            remote_path = '/'.join(['data', rec['s3_path']])
            file_path = os.path.join(output_path, file_name)
            self._retrive_file(remote_path, file_path)

    def restore(self):
        locker = SimpleFileLock(os.path.join(self.target_path, CONFIG_DIR, LOCK_FILE_NAME))
        if not locker.aquire_lock():
            self.logger.error('Cannot get lock!')
            return

        try:
            self._restore()
        except Exception as e:
            self.logger.exception(e)
            raise e
        finally:
            locker.release()


def init():
    config_path = os.path.join(os.getcwd(), CONFIG_DIR)
    config_json_path = os.path.join(config_path, CONFIG_FILE_NAME)
    file_ignore_path = os.path.join(config_path, IGNORE_FILE_NAME)
    dir_ignore_path = os.path.join(config_path, IGNORE_DIR_NAME)

    if not os.path.isdir(config_path):
        os.mkdir(config_path)

    if not os.path.isfile(config_json_path):
        with open(config_json_path, 'wt') as f:
            json.dump({}, f)

    if not os.path.isfile(file_ignore_path):
        with open(file_ignore_path, 'wt') as f:
            f.write('')

    if not os.path.isfile(dir_ignore_path):
        with open(dir_ignore_path, 'wt') as f:
            f.write('')

    print('Initialization finished!')


def _assure_initialized():
    config_path = os.path.join(os.getcwd(), CONFIG_DIR)
    config_json_path = os.path.join(config_path, CONFIG_FILE_NAME)

    if not os.path.isdir(config_path) or not os.path.isfile(config_json_path):
        raise Exception('Current working directory is not initialized!')


def config(args_obj):
    _assure_initialized()

    config_json_path = os.path.join(os.getcwd(), CONFIG_DIR, CONFIG_FILE_NAME)
    with open(config_json_path) as f:
        config_dict = json.load(f)

    if not args_obj.list and 'set' in args_obj and args_obj.set is not None:
        set_values = args_obj.set
        key = set_values[0]
        value = set_values[1]
        if value == '':
            config_dict.pop(key, None)
        else:
            config_dict[key] = value
        with open(config_json_path, 'wt') as f:
            json.dump(config_dict, f)

        print('%s is set to %s' % (key, value))
        return

    if not args_obj.list and args_obj.keyg:
        if config_dict.get('encryption', False):
            raise Exception('Encryption is already turned on!')

        iv_str, key_str = Encryptor.generate_str_keyset(1)

        config_dict['encryption'] = 'true'
        config_dict['iv'] = iv_str
        config_dict['key'] = key_str

        with open(config_json_path, 'wt') as f:
            json.dump(config_dict, f)

        print('encryption is turned on')
        print('key %s' % key_str)
        print('iv %s' % iv_str)
        return

    for key in sorted(config_dict.keys()):
        print('%s=%s' % (key, config_dict[key]))


def _initialize_backupper(dry_run_flg):
    config_json_path = os.path.join(os.getcwd(), CONFIG_DIR, CONFIG_FILE_NAME)
    with open(config_json_path) as f:
        config_dict = json.load(f)

    if 'aws_access_key_id' in config_dict:
        aws_access_key_id = config_dict['aws_access_key_id']
    else:
        aws_access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')

    if 'aws_secret_access_key' in config_dict:
        aws_secret_access_key = config_dict['aws_secret_access_key']
    else:
        aws_secret_access_key = os.environ.get('AWS_SECRET_ACCESS_KEY')

    encryption_value = config_dict.get('encryption', None)
    if encryption_value and encryption_value.lower() == 'true':
        encryption_flg = True
    else:
        encryption_flg = False

    hash_filename = config_dict.get('hash_filename', None)
    if hash_filename and hash_filename.lower() == 'true':
        hash_filename_flg = True
    else:
        hash_filename_flg = False

    backupper = S4Backupper(
        target_path=os.getcwd(),
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_region=config_dict.get('aws_region', None),
        s3bucket_name=config_dict['s3bucket'],
        s3prefix=config_dict['s3prefix'],
        use_hash_filename=hash_filename_flg,
        use_encryption=encryption_flg,
        key_str=config_dict.get('key', ''),
        iv_str=config_dict.get('iv', ''),
        dry_run_flg=dry_run_flg,
    )
    return backupper


def execute_backup(dry_run_flg):
    _assure_initialized()

    backupper = _initialize_backupper(dry_run_flg)
    backupper.execute_backup()


def fetch_list():
    _assure_initialized()

    backupper = _initialize_backupper(False)
    backupper.fetch_list()


def restore():
    _assure_initialized()

    backupper = _initialize_backupper(False)
    backupper.restore()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest="subparser", help='sub-command help')

    parser_init = subparsers.add_parser('init', help='initialize current working directory as backup target')

    parser_config = subparsers.add_parser('config', help='list / set current working directory config')
    parser_config.add_argument('-l', '--list', dest='list', action='store_true', help='List')
    parser_config.add_argument('-s', '--set', nargs=2, dest='set', help='Set')
    parser_config.add_argument('-k', '--key', dest='keyg', action='store_true', help='Generate encryption key')

    parser_push = subparsers.add_parser('push', help='execute backup against current working directory')
    parser_push.add_argument('-d', '--dry', dest='dry_run', action='store_true', help='Dry run')

    parser_fetch_list = subparsers.add_parser('fetch_list', help='list files from latest backup')

    parser_restore = subparsers.add_parser('restore', help='restore')

    parsed_args = parser.parse_args()

    if parsed_args.subparser == 'init':
        init()
    elif parsed_args.subparser == 'config':
        config(parsed_args)
    elif parsed_args.subparser == 'fetch_list':
        fetch_list()
    elif parsed_args.subparser == 'restore':
        restore()
    else:
        execute_backup(parsed_args.dry_run)

