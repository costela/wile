#!/usr/bin/env python

import os
import logging

from setuptools_scm import get_version
import click
from acme import client
from acme import messages
from acme import jose
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

import cert
import reg

logger = logging.getLogger('wile')

try:
    _version = get_version()
except LookupError:
    _version = None

@click.group(help='Simple client for ACME (letsencrypt) servers')
@click.pass_obj
@click.version_option(version=_version)
@click.option('--staging', is_flag=True, default=False, help='use letsencrypt\'s staging server (for testing)')
@click.option('--directory-url', metavar='URL', default='https://acme-v01.api.letsencrypt.org/directory', show_default=True, help='URL for alternative ACME directory (will be overriden by --staging)')
@click.option('--account-key', 'account_key_path', type=click.Path(dir_okay=False, allow_dash=True), default='~/.wile/account.key', show_default=True, help='path to existing account key')
@click.option('--new-account-key-size', type=int, metavar='BITS', default=2048, show_default=True, help='bit size to use when creating a new account key; ignored for existing keys')
@click.option('--verbose', '-v', count=True, help='be more verbose; can be passed multiple times')
def wile(obj, directory_url, staging, account_key_path, new_account_key_size, verbose):
    if verbose > 1:
        logging.basicConfig(level=logging.DEBUG)
    elif verbose > 0:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.WARNING)

    if staging:
        directory_url = 'https://acme-staging.api.letsencrypt.org/directory'
    account_key = get_or_gen_key(account_key_path, new_account_key_size)

    logger.debug('connecting to ACME directory at %s' % directory_url)
    obj['account_key'] = account_key
    obj['acme'] = client.Client(directory_url, account_key)

wile.add_command(cert.cert)
wile.add_command(reg.register)


def get_or_gen_key(account_key_path, new_account_key_size):
    account_key_path = os.path.expanduser(account_key_path)
    if os.path.exists(account_key_path):
        logger.debug('opening existing account key %s' % account_key_path)
        with open(account_key_path, 'rb') as key_file:
            key_contents = key_file.read()
            try:
                account_key = jose.JWKRSA(key=serialization.load_pem_private_key(key_contents, None, default_backend()))
            except TypeError:  # password required
                account_key = jose.JWKRSA(key=serialization.load_pem_private_key(key_contents, bytes(click.prompt('Password for %s' % account_key_path, hide_input=True, default=None)), default_backend()))
    else:
        logger.warn('no account key found; creating a new %d bit key in %s' % (new_account_key_size, account_key_path))
        account_key = jose.JWKRSA(key=rsa.generate_private_key(
            public_exponent=65537,
            key_size=new_account_key_size,
            backend=default_backend()))
        try:
            os.makedirs(os.path.dirname(account_key_path), 0750)
        except os.error:
            pass  # dir already exists
        with open(account_key_path, 'wb') as key_file:
            key_file.write(account_key.key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=ask_for_password_or_no_crypto(account_key_path)
            ))
    return account_key


def ask_for_password_or_no_crypto(key_path):
    return click.prompt('(optional) Password for %s' % key_path,
                        hide_input=True, confirmation_prompt=True, show_default=False,
                        default=serialization.NoEncryption(),
                        value_proc=serialization.BestAvailableEncryption)


def main():
    return wile(obj={})


if __name__ == '__main__':
    main()
