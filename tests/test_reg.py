import os

from mock import ANY

import wile
from wile.lazyclient import LazyClient


def test_wile_register__no_args(clirunner, logcapture, acmeclientmock):
    result = clirunner.invoke(wile.wile, args=['register'], obj=LazyClient())
    # should fail without --auto-accept-tos, but after creating a key
    assert result.exit_code == 2
    assert 'Accept Terms of Service?' in result.output
    logcapture.check(
        ('wile', 'WARNING',
         'no account key found; creating a new 2048 bit key in %s' % os.path.expanduser('~/.wile/account.key'))
    )
    assert os.listdir(os.path.expanduser('~')) == ['.wile']
    assert os.listdir(os.path.expanduser('~/.wile')) == ['account.key']
    assert os.listdir(os.curdir) == []
    acmeclientmock.assert_called_once_with(wile.LETSENCRYPT_URL, ANY)


def test_wile_register__staging(clirunner, logcapture, acmeclientmock):
    result = clirunner.invoke(wile.wile, args=['--staging', 'register'], obj=LazyClient())
    # should fail without --auto-accept-tos, but after creating a key
    assert result.exit_code == 2
    assert 'Accept Terms of Service?' in result.output
    logcapture.check(
        ('wile', 'WARNING',
         'no account key found; creating a new 2048 bit key in %s' % os.path.expanduser('~/.wile/account.key'))
    )
    assert os.listdir(os.path.expanduser('~')) == ['.wile']
    assert os.listdir(os.path.expanduser('~/.wile')) == ['account.key']
    assert os.listdir(os.curdir) == []
    acmeclientmock.assert_called_once_with(wile.LETSENCRYPT_STAGING_URL, ANY)


def test_wile_register__help(clirunner, logcapture, acmeclientmock):
    result = clirunner.invoke(wile.wile, args=['register', '--help'], obj=LazyClient())
    assert result.exit_code == 0
    logcapture.check()
    assert os.listdir(os.path.expanduser('~')) == []
    assert os.listdir(os.curdir) == []
    assert not acmeclientmock.called


def test_wile_register__autoaccept(clirunner, logcapture, acmeclientmock):
    assert os.listdir(os.path.expanduser('~')) == []
    result = clirunner.invoke(wile.wile, args=['register', '--auto-accept-tos'], obj=LazyClient())
    assert result.exit_code == 0
    assert 'Accept Terms of Service?' not in result.output
    logcapture.check(
        ('wile', 'WARNING',
         'no account key found; creating a new 2048 bit key in %s' % os.path.expanduser('~/.wile/account.key'))
    )
    assert os.listdir(os.path.expanduser('~')) == ['.wile']
    assert os.listdir(os.path.expanduser('~/.wile')) == ['account.key']
    assert os.listdir(os.curdir) == []
    acmeclientmock.assert_called_once_with(wile.LETSENCRYPT_URL, ANY)
