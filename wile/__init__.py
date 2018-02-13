import os
import logging
from functools import partial

import setuptools_scm
import click
import josepy as jose
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from . import cert
from . import reg
from .lazyclient import LazyClient

logger = logging.getLogger(__name__)

try:  # if we're in the checked out tree, use setuptools_scm
    _version = setuptools_scm.get_version()
except LookupError:  # otherwise click will attempt to find it via pkg_resources
    _version = None

LETSENCRYPT_URL = 'https://acme-v01.api.letsencrypt.org/directory'
LETSENCRYPT_STAGING_URL = 'https://acme-staging.api.letsencrypt.org/directory'


@click.group()
@click.pass_context
@click.version_option(version=_version)
@click.option('--staging', is_flag=True, default=False, help='use letsencrypt\'s staging server (for testing)')
@click.option('--directory-url', metavar='URL', default=LETSENCRYPT_URL,
              show_default=True, help='URL for alternative ACME directory (will be overriden by --staging)')
@click.option('--account-key', 'account_key_path', type=click.Path(dir_okay=False, allow_dash=True),
              default='~/.wile/account.key', show_default=True, help='path to existing account key')
@click.option('--new-account-key-size', type=int, metavar='BITS', default=2048, show_default=True,
              help='bit size to use when creating a new account key; ignored for existing keys')
@click.option('--verbose', '-v', count=True, help='be more verbose; can be passed multiple times')
def wile(ctx, directory_url, staging, account_key_path, new_account_key_size, verbose):
    '''
    Simple client for ACME servers (e.g. letsencrypt).
    '''

    if verbose > 1:
        logging.basicConfig(level=logging.DEBUG)
    elif verbose > 0:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.WARNING)

    if staging:
        directory_url = LETSENCRYPT_STAGING_URL

    account_key_callback = partial(get_or_gen_key, ctx, account_key_path, new_account_key_size)

    logger.debug('connecting to ACME directory at %s', directory_url)
    ctx.obj.init(directory_url, account_key_callback)


wile.add_command(cert.cert)
wile.add_command(reg.register)


def get_or_gen_key(ctx, account_key_path, new_account_key_size):
    account_key_path = os.path.expanduser(account_key_path)
    if os.path.exists(account_key_path):
        logger.debug('opening existing account key %s', account_key_path)
        with open(account_key_path, 'rb') as key_file:
            key_contents = key_file.read()
            try:
                try:
                    account_key = jose.JWKRSA(key=serialization.load_pem_private_key(key_contents, None,
                                              default_backend()))
                except TypeError:  # password required
                    password = click.prompt('Password for %s' % account_key_path, hide_input=True, default=None)
                    key = serialization.load_pem_private_key(key_contents, password.encode('utf-8'), default_backend())
                    account_key = jose.JWKRSA(key=key)
            except ValueError as e:
                logger.error('could not open key %s: %s', account_key_path, e)
                ctx.exit(1)
    else:
        logger.warn('no account key found; creating a new %d bit key in %s', new_account_key_size, account_key_path)
        account_key = jose.JWKRSA(key=rsa.generate_private_key(
            public_exponent=65537,
            key_size=new_account_key_size,
            backend=default_backend()))
        try:
            os.makedirs(os.path.dirname(account_key_path), 0o750)
        except os.error:
            pass  # dir already exists

        encryption_algorithm = ask_for_password_or_no_crypto(account_key_path)
        with open(account_key_path, 'wb') as key_file:
            key_file.write(account_key.key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            ))
    return account_key


def ask_for_password_or_no_crypto(key_path):
    # we can't use prompt's "default" and "value_proc" arguments because we monkeypatch prompt in test_wile.py
    password = click.prompt('(optional) Password for %s' % key_path, default='',
                            hide_input=True, confirmation_prompt=True, show_default=False)
    if password:
        return serialization.BestAvailableEncryption(password.encode('utf-8'))
    else:
        return serialization.NoEncryption()


def main():
    return wile(obj=LazyClient())
