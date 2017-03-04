import os

import click

import wile


def test_get_or_gen_key(inside_tmpdir, monkeypatch):
    account_key_path = 'account.key'
    account_key_size = 2048

    monkeypatch.setattr(click, 'prompt', lambda *args, **kwargs: b'somepassword')

    assert os.listdir(os.curdir) == []
    key1 = wile.get_or_gen_key(account_key_path, account_key_size)
    assert os.listdir(os.curdir) == [account_key_path]
    key2 = wile.get_or_gen_key(account_key_path, account_key_size)
    assert key1 == key2


def test_wile_no_args(clirunner, inside_tmpdir):
    result = clirunner.invoke(wile.wile)
    assert result.output_bytes.startswith(b'Usage:')
    assert result.exit_code == 0
    assert os.listdir(os.curdir) == []  # ensure it's a noop
