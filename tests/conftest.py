import os
import sys
import logging

from mock import Mock
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


@pytest.fixture(scope="function")
def acmeclientmock(monkeypatch):
    acmeClientMock = Mock(spec_set=[])
    monkeypatch.setattr(client, 'Client', acmeClientMock)
    return acmeClientMock


@pytest.fixture()
def ctxmock():
    obj_dict = {}
    ctx = Mock()
    ctx.__getitem__ = Mock(side_effect=lambda k: obj_dict[k])
    ctx.__setitem__ = Mock(side_effect=lambda k, v: obj_dict.__setitem__(k, v))
    ctx.keys = obj_dict.keys
    return ctx
