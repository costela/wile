import os

import pytest
from mock import ANY

import wile
from wile.lazyclient import LazyClient


@pytest.mark.parametrize("args, exit_code, tos_asked, url, expected_email, expected_phone", [
    (['register'], 2, True, wile.LETSENCRYPT_URL, '', ''),
    (['--staging', 'register'], 2, True, wile.LETSENCRYPT_STAGING_URL, '', ''),
    (['register', '--auto-accept-tos'], 0, False, wile.LETSENCRYPT_URL, '', ''),
    (['register', '--auto-accept-tos', '--email', 'example@example.com'], 0, False, wile.LETSENCRYPT_URL,
     'example@example.com', ''),
    (['register', '--auto-accept-tos', '--phone', '555-6666'], 0, False, wile.LETSENCRYPT_URL,
     '', '555-6666'),
])
def test_wile_register__arg_combinations(args, exit_code, tos_asked, url, expected_email, expected_phone, clirunner,
                                         logcapture, acmeclientmock_factory):
    acmeclientmock = acmeclientmock_factory(tos_asked)

    result = clirunner.invoke(wile.wile, args=args, obj=LazyClient())

    assert result.exit_code == exit_code
    assert ('Accept Terms of Service?' in result.output) == tos_asked
    logcapture.check(
        ('wile', 'WARNING',
         'no account key found; creating a new 2048 bit key in %s' % os.path.expanduser('~/.wile/account.key'))
    )
    assert os.listdir(os.path.expanduser('~')) == ['.wile']
    assert os.listdir(os.path.expanduser('~/.wile')) == ['account.key']
    assert os.listdir(os.curdir) == []
    if not tos_asked:
        assert ('Email: %s' % expected_email) in result.output
        assert ('Phone: %s' % expected_phone) in result.output
    acmeclientmock.assert_called_once_with(url, ANY)


def test_wile_register__help(clirunner, logcapture, acmeclientmock_factory):
    acmeclientmock = acmeclientmock_factory()
    result = clirunner.invoke(wile.wile, args=['register', '--help'], obj=LazyClient())
    assert result.exit_code == 0
    assert result.output.startswith('Usage:')
    logcapture.check()
    assert os.listdir(os.path.expanduser('~')) == []
    assert os.listdir(os.curdir) == []
    assert not acmeclientmock.called
