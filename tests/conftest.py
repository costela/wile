import os
import sys
import logging
import datetime
from functools import partial

from mock import Mock, PropertyMock
import pytest
from click.testing import CliRunner
from testfixtures import LogCapture
from acme import client

if sys.version_info.major < 3:
    import backports.tempfile as tempfile
else:
    import tempfile


@pytest.fixture(scope="function")
def clirunner(inside_tmpdir):
    return CliRunner()


@pytest.fixture()
def logcapture():
    with LogCapture(level=logging.WARN) as lc:
        yield lc


@pytest.fixture(scope="function")
def inside_tmpdir(monkeypatch):
    tmpdir = tempfile.TemporaryDirectory()
    homedir = tempfile.TemporaryDirectory()

    monkeypatch.setenv('HOME', homedir.name)
    os.chdir(tmpdir.name)

    return (tmpdir, homedir)


@pytest.fixture()
def fixed_datetime_monkeypatch(monkeypatch):
    def _factory(now):
        class _fixed_datetime(datetime.datetime):
            @classmethod
            def now(cls):
                return now
        monkeypatch.setattr(datetime, 'datetime', _fixed_datetime)
    return _factory


def _acmeclientcmock(monkeypatch, ask_for_tos=True, emails='', phones=''):
    '''
    This mocks most of the acme client's functionality that we use.
    '''

    if ask_for_tos:
        TOS1 = 'http://some.tos.url'
        TOS2 = 'http://some.other.tos.url'
    else:
        TOS1 = TOS2 = 'http://some.tos.url'

    original_contacts = dict(
        emails=(emails,),
        phones=(phones,),
    )

    def upd_reg(_, new_reg):
        original_contacts['emails'] = new_reg.emails
        original_contacts['phones'] = new_reg.phones

    acmeRegistrationMock = Mock(spec_set=['body', 'terms_of_service'], **{
        'body': Mock(spec_set=['agreement', 'emails', 'phones'], **{
            'agreement': TOS1,
        }),
        'terms_of_service': TOS2,
    })
    type(acmeRegistrationMock.body).emails = PropertyMock(side_effect=lambda: original_contacts['emails'])
    type(acmeRegistrationMock.body).phones = PropertyMock(side_effect=lambda: original_contacts['phones'])

    acmeClientInstanceMock = Mock(spec_set=['register', 'agree_to_tos', 'update_registration',
                                            'query_registration', 'revoke'], **{
        'register.return_value': acmeRegistrationMock,
        'update_registration.return_value': acmeRegistrationMock,
        'update_registration.side_effect': upd_reg,
        'query_registration.return_value': acmeRegistrationMock,
        'agree_to_tos.return_value': None,
    })
    acmeClientClassMock = Mock(spec_set=[], return_value=acmeClientInstanceMock)

    monkeypatch.setattr(client, 'Client', acmeClientClassMock)

    return acmeClientClassMock


@pytest.fixture(scope="function")
def acmeclientmock_factory(monkeypatch):
    return partial(_acmeclientcmock, monkeypatch)
