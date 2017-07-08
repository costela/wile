import logging

import pytest
from click.testing import CliRunner
from testfixtures import LogCapture


@pytest.fixture
def clirunner():
    return CliRunner()


@pytest.fixture()
def logcapture():
    with LogCapture(level=logging.WARN) as lc:
        yield lc


