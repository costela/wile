import os

import pytest
from mock import Mock, ANY

import wile


def test_wile_register__no_args(clirunner, logcapture, acmeclientmock):
    obj_dict = {}
    ctx = Mock()
    ctx.__getitem__ = Mock(side_effect=lambda k: obj_dict[k])
    ctx.__setitem__ = Mock(side_effect=lambda k, v: obj_dict.__setitem__(k, v))

    result = clirunner.invoke(wile.wile, args=['register'], obj=ctx)
    # should fail without --auto-accept-tos
    assert result.exit_code == 2
    logcapture.check(
        ('wile', 'WARNING',
         'no account key found; creating a new 2048 bit key in %s' % os.path.expanduser('~/.wile/account.key'))
        )
    assert os.listdir(os.path.expanduser('~')) == ['.wile']
    assert os.listdir(os.curdir) == []
    acmeclientmock.assert_called_once_with(wile.LETSENCRYPT_URL, ANY)
    assert set(obj_dict.keys()) == {'account_key', 'acme'}


@pytest.mark.xfail
def test_wile_register__help(clirunner, logcapture, acmeclientmock):
    obj_dict = {}
    ctx = Mock()
    ctx.__getitem__ = Mock(side_effect=lambda k: obj_dict[k])
    ctx.__setitem__ = Mock(side_effect=lambda k, v: obj_dict.__setitem__(k, v))

    # TODO: this should not fail (see other TODO in cert.py)
    result = clirunner.invoke(wile.wile, args=['register', '--help'], obj=ctx)
    assert result.exit_code == 0
    logcapture.check()
    assert os.listdir(os.path.expanduser('~')) == []
    assert os.listdir(os.curdir) == []
    assert not acmeclientmock.called


def test_wile_register__autoaccept(clirunner, logcapture, acmeclientmock):
    obj_dict = {}
    ctx = Mock()
    ctx.__getitem__ = Mock(side_effect=lambda k: obj_dict[k])
    ctx.__setitem__ = Mock(side_effect=lambda k, v: obj_dict.__setitem__(k, v))

    result = clirunner.invoke(wile.wile, args=['register', '--auto-accept-tos'], obj=ctx)
    assert result.exit_code == 0
    logcapture.check(
        ('wile', 'WARNING',
         'no account key found; creating a new 2048 bit key in %s' % os.path.expanduser('~/.wile/account.key'))
    )
    assert os.listdir(os.curdir) == []
    acmeclientmock.assert_called_once_with(wile.LETSENCRYPT_URL, ANY)
