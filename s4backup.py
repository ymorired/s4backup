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
from util import *

CONFIG_DIR = '.s4backup'
CONFIG_FILE_NAME = 'config.json'

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
                 config_dict, dry_run_flg=False):

        abs_path = os.path.abspath(target_path)
        if not os.path.isdir(abs_path):
            raise Exception('Invalid target path!')

        self.snapshot_version = time.strftime('%Y-%m-%d_%H-%M-%S', time.gmtime(time.time()))

        log_base_path = os.path.join(abs_path, CONFIG_DIR, 'logs')
        mkdir_p(log_base_path)
        log_path = os.path.join(log_base_path, self.snapshot_version)
        mkdir_p(log_path)

        self.log_path = log_path

        self.target_path = abs_path
        self.stats = {
            'bytes_uploaded': 0,
            'bytes_scanned': 0,
            'files_uploaded': 0,
            'files_scanned': 0,
            'bytes_total': 0,
            'files_total': 0,
        }

        self.s3conn = boto.s3.connect_to_region(
            'us-east-1',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
        )
        self.s3bucket = self.s3conn.get_bucket(s3bucket_name)
        self.s3prefix = str(s3prefix)  # get lid of unicode

        self.dry_run_flg = dry_run_flg

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
        self.update_count = 0
        self.update_time = time.time()

        import binascii
        self.encryptor = Encryptor(binascii.a2b_hex(config_dict['key']), binascii.a2b_hex(config_dict['iv']))
        self.encryption_flg = True

    def _backup_file(self, file_path, upload_path):

        with tempfile.TemporaryFile() as out_file_p:
            with open(file_path, 'rb') as in_file_p:

                file_backp_start_time = time.time()

                (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(file_path)

                encryption_seconds = 0
                encrypted_size = 0
                if self.encryption_flg:
                    encryption_start_time = time.time()
                    self.encryptor.encrypt_file(in_file_p, out_file_p)
                    encryption_seconds = time.time() - encryption_start_time
                    encrypted_size = out_file_p.tell()
                    in_file_p.seek(0, os.SEEK_SET)
                    out_file_p.seek(0, os.SEEK_SET)

                md5_start_time = time.time()
                md5sum = calc_md5_from_file(out_file_p)
                md5_seconds = time.time() - md5_start_time
                out_file_p.seek(0, os.SEEK_SET)

                self.logger.debug(
                    'file=%s md5=%s size=%s ' % (upload_path, md5sum, size) +
                    'enc_size=%s enc_sec=%s md5_sec=%s ' % (encrypted_size, encryption_seconds, md5_seconds)
                )

                self.stats['files_scanned'] += 1
                self.stats['bytes_scanned'] += size

                s3path = '/'.join([self.s3prefix, upload_path])
                fkey = self.s3bucket.get_key(s3path)
                if fkey is None or fkey.etag != '"%s"' % md5sum:
                    # file does not exist or modified

                    obj_key = Key(self.s3bucket)
                    obj_key.key = s3path
                    obj_key.set_contents_from_file(out_file_p)

                    self.stats['bytes_uploaded'] += encrypted_size
                    self.stats['files_uploaded'] += 1

                    self.logger.debug('%s/%s uploaded file=%s' % (self.stats['files_scanned'], self.stats['files_total'], upload_path))
                else:
                    self.logger.debug('%s/%s skipped file=%s' % (self.stats['files_scanned'], self.stats['files_total'], upload_path))

    def _auto_log_update(self):
        self.update_count += 1
        if self.update_count % 20 == 0:
            self.logger.info('Bytes uploaded:%s scanned:%s total:%s' % (self.stats['bytes_uploaded'], self.stats['bytes_scanned'], self.stats['bytes_total']))
            self.logger.info('Files uploaded:%s scanned:%s total:%s' % (self.stats['files_uploaded'], self.stats['files_scanned'], self.stats['files_total']))

    def backup(self):
        self.logger.info('Snapshot version:%s' % self.snapshot_version)
        time_start = time.time()

        files = self.file_lister.get_file_list()

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

        for found_file in files:
            relative_path = found_file.replace(self.target_path + '/', "", 1)

            self._backup_file(found_file, '/'.join(['data', relative_path]))
            self._auto_log_update()

        self.logger.info('Bytes uploaded:%s scanned:%s total:%s' % (self.stats['bytes_uploaded'], self.stats['bytes_scanned'], self.stats['bytes_total']))
        self.logger.info('Files uploaded:%s scanned:%s total:%s' % (self.stats['files_uploaded'], self.stats['files_scanned'], self.stats['files_total']))

        time_end = time.time()

        summary_file_path = os.path.join(self.log_path, 'summary.txt')
        with open(summary_file_path, 'wt') as f:
            f.write('time_start :%s (%s)\n' % (time.strftime('%Y-%m-%d %H-%M-%S', time.gmtime(time_start)), time_start))
            f.write('time_end   :%s (%s)\n' % (time.strftime('%Y-%m-%d %H-%M-%S', time.gmtime(time_end)), time_end))
            seconds_spent = time_end - time_start
            f.write('seconds_spent:%s\n' % (seconds_spent))
            f.write('\n')
            f.write('Bytes uploaded:%s scanned:%s total:%s\n' % (self.stats['bytes_uploaded'], self.stats['bytes_scanned'], self.stats['bytes_total']))
            f.write('Files uploaded:%s scanned:%s total:%s\n' % (self.stats['files_uploaded'], self.stats['files_scanned'], self.stats['files_total']))

        upload_path = '/'.join(['logs', self.snapshot_version, 'summary.txt'])
        self._backup_file(summary_file_path, upload_path)


def init():
    config_path = os.path.join(os.getcwd(), CONFIG_DIR)
    config_json_path = os.path.join(config_path, CONFIG_FILE_NAME)

    if os.path.isdir(config_path) and os.path.isfile(config_json_path):
        raise Exception('Current working directory is already initialized!')

    if not os.path.isdir(config_path):
        os.mkdir(config_path)

    if not os.path.isfile(config_json_path):
        with open(config_json_path, 'wt') as f:
            json.dump({}, f)

    print('Initialization finished!')


def _assure_initialized():
    config_path = os.path.join(os.getcwd(), CONFIG_DIR)
    config_json_path = os.path.join(config_path, CONFIG_FILE_NAME)

    if not os.path.isdir(config_path) or not os.path.isfile(config_json_path):
        raise Exception('Current working directory is not initialized!')


def config(args):
    _assure_initialized()

    config_json_path = os.path.join(os.getcwd(), CONFIG_DIR, CONFIG_FILE_NAME)
    with open(config_json_path) as f:
        config_dict = json.load(f)

    if not args.list and 'set' in args and args.set is not None:
        set_values = args.set
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

    if not args.list and args.keyg:
        iv_str, key_str = Encryptor.generate_str_keyset(2)

        config_dict['iv'] = iv_str
        config_dict['key'] = key_str

        with open(config_json_path, 'wt') as f:
            json.dump(config_dict, f)

        print('key %s' % key_str)
        print('iv %s' % iv_str)
        return

    for key in sorted(config_dict.keys()):
        print('%s=%s' % (key, config_dict[key]))


def execute_backup(dry_run_flg):
    _assure_initialized()

    config_json_path = os.path.join(os.getcwd(), CONFIG_DIR, CONFIG_FILE_NAME)
    with open(config_json_path) as f:
        config_dict = json.load(f)

    aws_access_key_id = ''
    if 'aws_access_key_id' in config_dict:
        aws_access_key_id = config_dict['aws_access_key_id']
    else:
        aws_access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')

    aws_secret_access_key = ''
    if 'aws_secret_access_key' in config_dict:
        aws_secret_access_key = config_dict['aws_secret_access_key']
    else:
        aws_secret_access_key = os.environ.get('AWS_SECRET_ACCESS_KEY')

    archiver = S4Backupper(
        target_path=os.getcwd(),
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        s3bucket_name=config_dict['s3bucket'],
        s3prefix=config_dict['s3prefix'],
        config_dict=config_dict,
        dry_run_flg=dry_run_flg,
    )
    archiver.backup()


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

    args = parser.parse_args()

    if args.subparser == 'init':
        init()
    elif args.subparser == 'config':
        config(args)
    else:
        execute_backup(args.dry_run)

