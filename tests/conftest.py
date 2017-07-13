import os
import sys
import logging

from mock import Mock
import pytest
from click.testing import CliRunner
from testfixtures import LogCapture
from acme import client

from wile.lazyclient import LazyClient

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
def objmock():
    '''
    This mocks the click "obj" argument passed around between different subcommands
    '''
    objMock = Mock(spec_set=LazyClient)
    return objMock
