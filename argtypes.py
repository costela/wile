import os
import re
from datetime import timedelta
from collections import namedtuple

import click

_DomainWebrootTuple = namedtuple('DomainWebrootTuple', ['domain', 'webroot'])


class _DomainWebrootType(click.ParamType):
    domain = None
    webroot = None

    def convert(self, value, param, ctx):
        if isinstance(value, _DomainWebrootTuple):
            return value
        url = value.split(':')
        if len(url) not in (1, 2):
            self.fail('could not parse %s as DOMAIN[:WEBROOT]' % value)
        domain = url[0]
        webroot = len(url) > 1 and os.path.expanduser(url[1]) or None
        return _DomainWebrootTuple(domain=domain, webroot=webroot)

    def get_metavar(self, param):
        return 'DOMAIN[:WEBROOT]'


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
