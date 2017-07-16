import os

import pytest
import click

import wile


def test_wile__get_or_gen_key(inside_tmpdir, logcapture, monkeypatch):
    account_key_path = 'account.key'
    account_key_size = 2048

    monkeypatch.setattr(click, 'prompt', lambda *args, **kwargs: u'somepassword')

    assert os.listdir(os.curdir) == []
    key1 = wile.get_or_gen_key(None, account_key_path, account_key_size)
    logcapture.check(
        ('wile', 'WARNING', 'no account key found; creating a new 2048 bit key in account.key')
    )
    logcapture.clear()
    assert os.listdir(os.curdir) == [account_key_path]

    key2 = wile.get_or_gen_key(None, account_key_path, account_key_size)
    logcapture.check()
    assert key1 == key2


@pytest.mark.parametrize("args", [
    [],
    ['--help'],
])
def test_wile__no_args_or_help(args, clirunner, acmeclientmock_factory):
    acmeclientmock = acmeclientmock_factory()
    result = clirunner.invoke(wile.wile, args=args)
    assert result.output_bytes.startswith(b'Usage:')
    assert result.exit_code == 0
    assert os.listdir(os.path.expanduser('~')) == []
    assert os.listdir(os.curdir) == []  # ensure it's a noop
    assert not acmeclientmock.called


def test_wile__version(clirunner, acmeclientmock_factory):
    acmeclientmock = acmeclientmock_factory()
    result = clirunner.invoke(wile.wile, args=['--version'])
    assert ('version %s' % wile._version) in str(result.output_bytes)
    assert result.exit_code == 0
    assert os.listdir(os.path.expanduser('~')) == []
    assert os.listdir(os.curdir) == []  # ensure it's a noop
    assert not acmeclientmock.called
