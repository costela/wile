import pytest
from click.testing import CliRunner


@pytest.fixture
def clirunner():
    return CliRunner()


@pytest.fixture
def inside_tmpdir(tmpdir):
    with tmpdir.as_cwd() as cd:
        yield cd
