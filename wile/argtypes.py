import os
import re
from datetime import timedelta
from collections import namedtuple

import click

_DomainRemoteWebrootTuple = namedtuple('DomainRemoteWebrootTuple', ['domain', 'remote', 'webroot'])


class _DomainRemoteWebrootType(click.ParamType):
    domain = None
    remote = None
    webroot = None

    def convert(self, value, param, ctx):
        if isinstance(value, _DomainRemoteWebrootTuple):
            return value
        url = value.split(':')
        if len(url) not in range(1, 5):
            self.fail('could not parse %s as DOMAIN:[[[USER@]HOST[:PORT]:]WEBROOT]' % value)
        domain = url[0]
        if len(url) > 2:
            split_tmp = url[1].split('@')
            if url[2].isdigit():
                remote = (split_tmp[0], split_tmp[1], url[2])
                webroot = len(url) == 4 and os.path.expanduser(url[3]) or None
            else:
                remote = (split_tmp[0], split_tmp[1], None)
                webroot = os.path.expanduser(url[2])
        else:
            remote = None
            webroot = len(url) > 1 and os.path.expanduser(url[1]) or None
        return _DomainRemoteWebrootTuple(domain=domain, remote=remote, webroot=webroot)

    def get_metavar(self, param):
        return 'DOMAIN:[[[USER@]HOST[:PORT]:]WEBROOT]'


class _TimespanType(click.ParamType):
    _re = re.compile(r'^(?P<amount>\d+)(?P<unit>h|d|w)$')
    _unitmap = {
        'h': 'hours',
        'd': 'days',
        'w': 'weeks',
    }

    def convert(self, value, param, ctr):
        if isinstance(value, timedelta):
            return value
        match = self._re.match(value)
        if not match:
            self.fail('could not parse %s as timespan' % value)
        return timedelta(**{self._unitmap[match.group('unit')]: int(match.group('amount'))})

    def get_metavar(self, param):
        return 'TIME'


DomainWebrootType = _DomainRemoteWebrootType()
TimespanType = _TimespanType()
WritablePathType = click.Path(exists=True, writable=True, readable=False, file_okay=False, dir_okay=True,
                              resolve_path=True)
