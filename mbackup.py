#!/usr/bin/env python3

import argparse
import sys
import logging


PROG_VERSION = '2.1905.0'


def parse_options(args):
    parser = argparse.ArgumentParser()

    # parser.add_argument('task', metavar='TASK', choices=['backup', 'restore', 'update-backup'])
    parser.add_argument('task', metavar='TASK', choices=['backup', 'restore'])
    parser.add_argument('-v', '--version', action='version', version=PROG_VERSION)
    parser.add_argument('-s', '--server', metavar='URL', help='target server URL')
    parser.add_argument('-u', '--user', metavar='USERNAME', help='system admin username')
    parser.add_argument('-p', '--passwd', metavar='PASSWORD', help='system admin password')
    parser.add_argument('-q', '--quiet', action='store_true', help='disable logging')
    # parser.add_argument('-ns', '--no_switch', action='store_true', help='if set, no restore switch values')
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

    return parser.parse_args(args)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s: %(levelname)s: %(message)s')

    # TODO: params from config file
    options = parse_options(sys.argv[1:])

    if options.task == 'backup':
        if not (options.server and options.user and options.passwd and options.output):
            sys.exit(f'for backup --server, --user, --passwd and --output is required')

        import mitigator
        import backup

        logging.info('getting authtoken on mitigator server')
        _mitigator = mitigator.Mitigator(options.server, options.user, options.passwd, options.insecure)
        _backup = backup.Backup(_mitigator)

        logging.info('backuping start')
        try:
            _backup.create_backup()
        except mitigator.MOthException as e:
            logging.error(e)

        logging.info(f'writing backup data in {options.output.name}')
        options.output.write(_backup.get_backup_as_json())

    elif options.task == 'restore':
        if not (options.server and options.user and options.passwd and options.input):
            sys.exit(f'for restore --server, --user, --passwd and --input is required')

        import mitigator
        import restore

        _mitigator = mitigator.Mitigator(options.server, options.user, options.passwd, options.insecure)
        _restore = restore.Restore(_mitigator)

        _file_data = options.input.read()
        if _file_data:
            _restore.load_params_from_json(_file_data)
        else:
            sys.exit('source file is empty')

        try:
            _restore.restore()
        except mitigator.MOthException as e:
            logging.error(e)
            logging.error('retry restore not support, reset your mitigator database')

    # elif options.task == 'file-update':
    #     import file_update

        # file_update.update()
