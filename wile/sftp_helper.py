import os
import types
import logging

import paramiko

logger = logging.getLogger(__name__)

_cache = dict()


def cachedSFTPfactory(host, port, user, private_key):
    key = (host, port, user)

    if key in _cache:
        return _cache[key]
    else:
        ssh = paramiko.SSHClient()
        ssh.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
        ssh.connect(hostname=host, port=port or 22,
                    username=user, key_filename=private_key,
                    password=os.getenv('WILE_SSH_PASS'))
        sftp = ssh.open_sftp()
        sftp._ssh = ssh  # workaround for paramiko issue #344
        sftp.makedirs = types.MethodType(_makedirs, sftp)
        _cache[key] = sftp

        return sftp


def _makedirs(self, path):
    head, tail = os.path.split(path)
    if head and head != '/':
        self.makedirs(head)
    try:
        logger.debug('creating directory %s on remote host', path)
        self.mkdir(path)
    except OSError:
        # sftp doesn't return any useful information, so we assume it's an EEXIST and hope for the best ;)
        pass
