
import os
import logging
import errno

import click
from OpenSSL import crypto

import reg  # imported first for monkey-patching

from acme import challenges
from acme import messages
from acme import errors
from acme.jose.util import ComparableX509


logger = logging.getLogger('wile').getChild('cert')


@click.group(help='Certificate management')
def cert():
    pass


@cert.command(help='''Request a new certificate for the provided domains and respective webroot paths. If a webroot is not provided for a domain, the one of the previous domain is used.''')
@click.pass_context
@click.option('--with-chain/--separate-chain', is_flag=True, default=True, show_default=True, help='Whether to include the certificate\'s chain in the output certificate; --separate-chain implies a separate .chain.crt file, containing only the signing certificates up to the root')
@click.option('--key-size', '-s', metavar='SIZE', type=int, default=2048, show_default=True, help='Size in bits for the generated certificate\'s key')
@click.option('--output-dir', metavar='DIR', type=click.Path(exists=True, writable=True, readable=False, file_okay=False, dir_okay=True, resolve_path=True), default='.', help='Where to store created certificates (default: current directory)')
@click.option('--basename', metavar='BASENAME', help='Basename to use when storing output: BASENAME.crt and BASENAME.key [default: first domain]')
@click.option('--key-digest', metavar='DIGEST', default='sha256', show_default=True, help='The digest to use when signing the request with its key (must be supported by openssl)')
@click.option('--overwrite/--no-overwrite', is_flag=True, default=False, show_default=True, help='Whether to overwrite existing certificate and key files (for automatic updates)')
@click.argument('domainroots', metavar='DOMAIN[:WEBROOT]', nargs=-1, required=True)
def request(ctx, domainroots, with_chain, key_size, output_dir, basename, key_digest, overwrite):
    regr = ctx.invoke(reg.register, quiet=True, auto_accept_tos=True)
    domain_list = list()
    authzrs = list()
    webroot = None
    for domainroot in domainroots:
        url = domainroot.split(':')
        if len(url) not in (1, 2):
            logger.error('could not parse %s as DOMAIN[:WEBROOT]; skipping' % domainroot)
            continue
        webroot = len(url) > 1 and url[1] or webroot  # use previous webroot if not present
        if not webroot:
            logger.error('domain without webroot: %s' % domainroot)
            continue
        domain = url[0]
        domain_list.append(domain)

        logger.info('requesting challange for %s in %s' % (domain, webroot))

        authzr = ctx.obj['acme'].request_domain_challenges(domain, new_authzr_uri=regr.new_authzr_uri)
        authzrs.append(authzr)

        challb = _get_http_challenge(ctx, authzr)
        chall_response, chall_validation = challb.response_and_validation(ctx.obj['account_key'])
        _store_webroot_validation(webroot, challb, chall_validation)
        ctx.obj['acme'].answer_challenge(challb, chall_response)

    key, csr = _generate_key_and_csr(domain_list, key_size, key_digest)

    try:
        # import pdb; pdb.set_trace()
        crt, updated_authzrs = ctx.obj['acme'].poll_and_request_issuance(csr, authzrs)
    except errors.PollError as e:
        if e.exhausted:
            logger.error('validation timed out for the following domains: %s' % ', '.join(authzr.body.identifier for authzr in e.exhausted))
        invalid_domains = [authzr.body.identifier for authzr in e.updated if authzr.body.status == messages.STATUS_INVALID]
        if invalid_domains:
            logger.error('validation invalid for the following domains: %s' % ', '.join(invalid_domains))

    basename = basename or domain_list[0]

    if not overwrite and os.path.exists(os.path.join(output_dir, '%s.key' % basename)):
        click.confirm('file %s.key exists; overwrite?' % basename, abort=True)

    with open(os.path.join(output_dir, '%s.key' % basename), 'wb') as f:
        os.fchmod(f.fileno(), 0640)
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    chain = ctx.obj['acme'].fetch_chain(crt)
    certs = [crt.body]
    if with_chain:
        certs.extend(chain)
    else:
        if not overwrite and os.path.exists(os.path.join(output_dir, '%s.chain.crt' % basename)):
            click.confirm('file %s.chain.crt exists; overwrite?' % basename, abort=True)

        with open(os.path.join(output_dir, '%s.chain.crt' % basename), 'wb') as f:
            for crt in chain:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, crt))

    if not overwrite and os.path.exists(os.path.join(output_dir, '%s.crt' % basename)):
        click.confirm('File %s.crt exists; overwrite?' % basename, abort=True)

    with open(os.path.join(output_dir, '%s.crt' % basename), 'wb') as f:
        for crt in certs:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, crt))


@cert.command(help='Revoke existing certificates')
@click.pass_context
@click.argument('cert_paths', metavar='CERT_FILE [CERT_FILE ...]', nargs=-1, required=True)
def revoke(ctx, cert_paths):
    for cert_path in cert_paths:
        with open(cert_path, 'rb') as f:
            crt = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
            ctx.obj['acme'].revoke(ComparableX509(crt))


def _get_http_challenge(ctx, authzr):
    for c in authzr.body.combinations:
        if len(c) == 1 and isinstance(authzr.body.challenges[c[0]].chall, challenges.HTTP01):
            return authzr.body.challenges[c[0]]
    ctx.fail('no acceptable challenge type found; only HTTP01 supported')


def _store_webroot_validation(webroot, challb, val):
    try:
        os.makedirs(os.path.join(webroot, challb.URI_ROOT_PATH), 0755)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

    with open(os.path.join(webroot, challb.path.strip('/')), 'wb') as outf:
        logger.info('storing validation to %s' % outf.name)
        outf.write(val)


def _generate_key_and_csr(domains, key_size, key_digest):
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, key_size)

    csr = crypto.X509Req()
    csr.set_version(2)
    csr.set_pubkey(key)

    sans = ', '.join('DNS:{}'.format(d) for d in domains)
    exts = [crypto.X509Extension('subjectAltName', False, sans)]
    csr.add_extensions(exts)

    csr.sign(key, str(key_digest))

    return (key, ComparableX509(csr))
