#!/usr/bin/env python3

import argparse
import sys
import logging

import mitigator


PROG_VERSION = '3.2008.2'


def parse_options(args):
    parser = argparse.ArgumentParser()

    parser.add_argument(
        'task',
        metavar='TASK',
        choices=['backup', 'restore', 'update-file'],
        help='may be one of following: backup, restore, update-file',
    )
    parser.add_argument('-v', '--version', action='version', version=PROG_VERSION)
    parser.add_argument('-s', '--server', metavar='URL', help='target server URL')
    parser.add_argument('-u', '--user', metavar='USERNAME', help='system admin username')
    parser.add_argument('-p', '--passwd', metavar='PASSWORD', help='system admin password')
    parser.add_argument('-q', '--quiet', action='store_true', help='disable logging')
    parser.add_argument('-pj', '--pretty-json', action='store_true', help='output json is pretty')
    parser.add_argument('-k', '--insecure', action='store_true', help='if set, no check SSL certificate')
    parser.add_argument(
        '-i',
        '--input',
        metavar='PATH',
        type=argparse.FileType('r'),
        help='target file for write json-format backup',
    )
    parser.add_argument(
        '-o',
        '--output',
        metavar='PATH',
        type=argparse.FileType('x'),
        help='source file with json-format backup for restore',
    )
    parser.add_argument(
        '-c', '--config', metavar='PATH', type=argparse.FileType('r'), help='configuration file'
    )

    return parser.parse_args(args)


def main(options):
    if options.config:
        import configparser

        _config = configparser.ConfigParser()
        _config.read_file(options.config)

        _section = options.task.upper()

        if _section not in _config:
            sys.exit(f'section {_section} not in config file')

        _section_config = _config[_section]

        _server = _section_config.get('server') or options.server
        _user = _section_config.get('user') or options.user
        _passwd = _section_config.get('password') or options.passwd
        _output = (
            open(_section_config.get('backup_target'), 'w')
            if _section_config.get('backup_target')
            else options.output
        )
        _input = (
            open(_section_config.get('backup_source'), 'r')
            if _section_config.get('backup_source')
            else options.input
        )
        _insecure = _section_config.getboolean('insecure') or options.insecure
        _pretty = _section_config.getboolean('pretty') or options.pretty_json

    else:
        _server = options.server
        _user = options.user
        _passwd = options.passwd
        _output = options.output
        _input = options.input
        _insecure = options.insecure
        _pretty = options.pretty_json

    if _server and _user:
        logging.info(f'execute params: server: {_server}; user: {_user}; insecure: {_insecure}')

    if options.task == 'backup':
        if not (_server and _user and _passwd and _output):
            sys.exit('for backup --server, --user, --passwd and --output is required')

        logging.info('getting authtoken on mitigator server')
        _mitigator = mitigator.Mitigator(_server, _user, _passwd, _insecure)

        logging.info('backuping start')
        try:
            _mitigator.create_backup()
        except mitigator.MOthException as e:
            logging.error(e)

        logging.info(f'writing backup data in {_output.name}')
        _output.write(_mitigator.get_backup_as_json(_pretty))

    elif options.task == 'restore':
        if not (_server and _user and _passwd and _input):
            sys.exit('for restore --server, --user, --passwd and --input is required')

        _mitigator = mitigator.Mitigator(_server, _user, _passwd, _insecure)

        _file_data = _input.read()

        if not _file_data:
            sys.exit('source file is empty')

        _mitigator.load_params_from_json(_file_data)

        try:
            _mitigator.restore()
        except mitigator.MOthException as e:
            logging.error(e)
            logging.error('retry restore not support, reset your mitigator database')

    elif options.task == 'update-file':
        import __update

        if not (_input and _output):
            sys.exit('for update-file --input and --output is required')

        _upd = __update.Update()

        _file_data = _input.read()
        if not _file_data:
            sys.exit('source file is empty')

        _upd.load_params_from_json(_file_data)

        _upd.update_params()

        logging.info(f'writing updated data in {_output.name}')
        _output.write(_upd.get_params_as_json(_pretty))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s: %(levelname)s: %(message)s')

    opt = parse_options(sys.argv[1:])

    try:
        main(options=opt)
    except mitigator.MOthException as e:
        sys.exit(f'FATAL ERROR: {e}')
