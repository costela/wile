import os
from datetime import datetime, timedelta

import pytest
from mock import Mock, ANY, call

import wile
from wile import lazyclient
from wile import argtypes
from wile import cert

FIXTURE_DATA_DIR = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    'certs',
)


def test_generate_domain_and_webroot_lists_from_args__fail(inside_tmpdir):
    ctx_mock = Mock(spec_set=['exit'])
    (dl, wrl) = cert._generate_domain_and_webroot_lists_from_args(ctx_mock, [
                    argtypes.DomainWebrootType('example.org'),
                ])
    ctx_mock.exit.assert_called_with(1)


@pytest.mark.parametrize("args, expected_dl, expected_wrl", [
    (['example.org:folder1'], ['example.org'], ['folder1']),
    (['example.org:folder1', 'foo.example.org'], ['example.org', 'foo.example.org'], ['folder1', 'folder1']),
    (['example.org:folder1', 'foo.example.org:folder2'], ['example.org', 'foo.example.org'], ['folder1', 'folder2']),
])
def test_generate_domain_and_webroot_lists_from_args__success(args, expected_dl, expected_wrl, inside_tmpdir):
    ctx_mock = Mock(spec_set=['exit'])

    os.mkdir('folder1')
    os.mkdir('folder2')

    (dl, wrl) = cert._generate_domain_and_webroot_lists_from_args(ctx_mock, list(
                    map(argtypes.DomainWebrootType, args),
                ))
    ctx_mock.exit.assert_not_called()

    assert dl == expected_dl
    assert wrl == list(map(lambda f: argtypes._WebrootTuple(path=os.path.join(os.path.abspath('.'), f)), expected_wrl))


@pytest.mark.parametrize("args", [
    ['cert'],
    ['cert', '--help'],
    ['cert', 'revoke', '--help'],
])
def test_wile_cert__noargs_and_help(args, clirunner, logcapture, acmeclientmock_factory):
    acmeclientmock = acmeclientmock_factory()
    result = clirunner.invoke(wile.wile, args=args, obj=lazyclient.LazyClient())
    assert result.exit_code == 0
    assert result.output.startswith('Usage:')
    logcapture.check()
    assert os.listdir(os.path.expanduser('~')) == []
    assert os.listdir(os.curdir) == []
    assert not acmeclientmock.called


def test_wile_cert_revoke__noargs(clirunner, logcapture, acmeclientmock_factory):
    acmeclientmock = acmeclientmock_factory()
    result = clirunner.invoke(wile.wile, args=['cert', 'revoke'], obj=lazyclient.LazyClient())
    assert result.exit_code == 2
    assert result.output.startswith('Usage:')
    logcapture.check()
    assert os.listdir(os.path.expanduser('~')) == []
    assert os.listdir(os.curdir) == []
    assert not acmeclientmock.called


@pytest.mark.datafiles(
    os.path.join(FIXTURE_DATA_DIR, 'cert1.crt'),
    os.path.join(FIXTURE_DATA_DIR, 'cert2.crt'),
)
def test_wile_cert_revoke(datafiles, clirunner, logcapture, acmeclientmock_factory):
    acmeclientmock = acmeclientmock_factory()
    certs = list(map(str, datafiles.listdir()))
    result = clirunner.invoke(wile.wile, args=['cert', 'revoke']+certs, obj=lazyclient.LazyClient())
    assert result.exit_code == 0
    logcapture.check(
        ('wile', 'WARNING',
         'no account key found; creating a new 2048 bit key in %s' % os.path.expanduser('~/.wile/account.key'))
    )
    assert os.listdir(os.path.expanduser('~')) == ['.wile']
    assert os.listdir(os.path.expanduser('~/.wile')) == ['account.key']
    assert os.listdir(os.curdir) == []
    acmeclientmock.assert_called_once_with(wile.LETSENCRYPT_URL, ANY)
    acmeclientmock.return_value.revoke.assert_has_calls([call(ANY, 0), call(ANY, 0)])


@pytest.mark.datafiles(
    os.path.join(FIXTURE_DATA_DIR, 'cert_example.com.crt')
)
def test_is_valid_and_unchanged__expired(datafiles, fixed_datetime_monkeypatch):
    # time after cert validity
    fixed_datetime_monkeypatch(datetime(2017, 10, 17, 0, 0, 0))
    res = cert._is_valid_and_unchanged(str(datafiles / 'cert_example.com.crt'),
                                       ['example.com', 'www.example.com', 'test.example.com'],
                                       timedelta(0))
    assert res is False


@pytest.mark.datafiles(
    os.path.join(FIXTURE_DATA_DIR, 'cert_example.com.crt')
)
def test_is_valid_and_unchanged__new_domain(datafiles, fixed_datetime_monkeypatch):
    # time after cert validity
    fixed_datetime_monkeypatch(datetime(2017, 10, 16, 0, 0, 0))
    res = cert._is_valid_and_unchanged(str(datafiles / 'cert_example.com.crt'),
                                       ['example.com', 'www.example.com', 'test.example.com', 'new.example.com'],
                                       timedelta(0))
    assert res is False


@pytest.mark.datafiles(
    os.path.join(FIXTURE_DATA_DIR, 'cert_example.com.crt')
)
def test_is_valid_and_unchanged__removed_domain(datafiles, fixed_datetime_monkeypatch):
    # time after cert validity
    fixed_datetime_monkeypatch(datetime(2017, 10, 16, 0, 0, 0))
    res = cert._is_valid_and_unchanged(str(datafiles / 'cert_example.com.crt'),
                                       ['example.com', 'www.example.com'],
                                       timedelta(0))
    assert res is False


@pytest.mark.datafiles(
    os.path.join(FIXTURE_DATA_DIR, 'cert_example.com.crt')
)
def test_is_valid_and_unchanged(datafiles, fixed_datetime_monkeypatch):
    # time after cert validity
    fixed_datetime_monkeypatch(datetime(2017, 10, 16, 0, 0, 0))
    res = cert._is_valid_and_unchanged(str(datafiles / 'cert_example.com.crt'),
                                       ['example.com', 'www.example.com', 'test.example.com'],
                                       timedelta(0))
    assert res is True


def test_store_webroot_validation__local(inside_tmpdir):
    webroot = Mock(spec_set=['path', 'remote_host'], **{
        'path': inside_tmpdir[0].name,
        'remote_host': None,
    })

    challb = Mock(spec_set=['path', 'URI_ROOT_PATH'], **{
        'path': '.well-known/acme-challenge/sometoken',
        'URI_ROOT_PATH': '.well-known/acme-challenge',
    })
    cert._store_webroot_validation(webroot, None, challb, 'some validation content')

    assert os.listdir(os.curdir) == ['.well-known']
    assert os.listdir('.well-known') == ['acme-challenge']
    assert os.listdir('.well-known/acme-challenge') == ['sometoken']
    assert open('.well-known/acme-challenge/sometoken').read() == 'some validation content'
