import os

import paramiko

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
        _cache[key] = sftp

        return sftp
