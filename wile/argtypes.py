import os
import re
from datetime import timedelta
from collections import namedtuple

import click

_DomainWebrootTuple = namedtuple('DomainWebrootTuple', ['domain', 'webroot'])
_WebrootTuple = namedtuple('WebrootTuple', ['remote_user', 'remote_host', 'remote_port', 'path'])
_WebrootTuple.__new__.__defaults__ = (None,) * len(_WebrootTuple._fields)


class _DomainWebrootType(click.ParamType):
    _re = re.compile((r'^(?P<domain>[^:]+)'
                      r'(?::'
                      r'(?:'
                      r'(?:(?P<remote_user>[^@]+)@)?'
                      r'(?P<remote_host>[^@:]+)'
                      r'(?::(?P<remote_port>\d+))?:'
                      r')?'
                      r'(?P<path>[^@:]+)'
                      r')?$'))

    domain = None
    webroot = None

    def convert(self, value, param, ctx):
        if isinstance(value, _DomainWebrootTuple):
            return value

        match = self._re.match(value)
        if not match:
            self.fail('could not parse %s as %s' % (value, self.get_metavar(None)))

        remote_port = match.group('remote_port')
        if remote_port:  # will never be empty according to regex
            remote_port = int(remote_port)

        if match.group('path'):
            path = match.group('path')
            if not match.group('remote_host'):
                path = WritablePathType(os.path.expanduser(path))
            webroot = _WebrootTuple(
                remote_user=match.group('remote_user'),
                remote_host=match.group('remote_host'),
                remote_port=remote_port,
                path=path)
        else:
            webroot = None
        return _DomainWebrootTuple(domain=match.group('domain'), webroot=webroot)

    def get_metavar(self, param):
        return 'DOMAIN[[[USER@]HOST[:PORT]]:WEBROOT]'


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


DomainWebrootType = _DomainWebrootType()
TimespanType = _TimespanType()
WritablePathType = click.Path(exists=True, writable=True, readable=False, file_okay=False, dir_okay=True,
                              resolve_path=True)
