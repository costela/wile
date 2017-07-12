import os

import pytest
from mock import Mock

from wile import argtypes
from wile import cert


def test_generate_domain_and_webroot_lists_from_args_fail(inside_tmpdir):
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
def test_generate_domain_and_webroot_lists_from_args_success(args, expected_dl, expected_wrl, inside_tmpdir):
    ctx_mock = Mock(spec_set=['exit'])

    os.mkdir('folder1')
    os.mkdir('folder2')

    (dl, wrl) = cert._generate_domain_and_webroot_lists_from_args(ctx_mock, list(
                    map(argtypes.DomainWebrootType, args),
                ))
    ctx_mock.exit.assert_not_called()

    assert dl == expected_dl
    assert wrl == list(map(lambda f: os.path.join(os.path.abspath('.'), f), expected_wrl))
