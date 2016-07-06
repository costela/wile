
import os
import logging
import errno
from datetime import datetime

import click
from OpenSSL import crypto

import reg  # imported first for monkey-patching

from acme import challenges
from acme import messages
from acme import errors
from acme.jose.util import ComparableX509

import argtypes

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
@click.option('--min-valid-time', type=argtypes.TimespanType, metavar='TIMESPAN', default='1d', show_default=True, help='If a certificate is found and its expiration lies inside of this timespan, it will be automatically requested and overwritten; otherwise no request will be made. The format for this option is "1d" for one day. Supported units are hours, days and weeks.')
@click.option('--force', is_flag=True, default=False, show_default=True, help='Whether to force a request to be made, even if a valid certificate is found')
@click.argument('domainroots', 'DOMAIN[:WEBROOT]', type=argtypes.DomainWebrootType, metavar='DOMAIN[:WEBROOT]', nargs=-1, required=True)
def request(ctx, domainroots, with_chain, key_size, output_dir, basename, key_digest, min_valid_time, force):
    regr = ctx.invoke(reg.register, quiet=True, auto_accept_tos=True)
    authzrs = list()

    domain_list, webroot_list = _generate_domain_and_webroot_lists_from_args(ctx, domainroots)
    basename = basename or domain_list[0]
    keyfile_path = os.path.join(output_dir, '%s.key' % basename)
    certfile_path = os.path.join(output_dir, '%s.crt' % basename)
    chainfile_path = os.path.join(output_dir, '%s.chain.crt' % basename)

    if os.path.exists(certfile_path):
        if not force and _is_valid_and_unchanged(certfile_path, domain_list, min_valid_time):
            logger.info('found existing valid certificate (%s); not requesting a new one' % certfile_path)
            ctx.exit(0)
        elif force:
            logger.info('found existing valid certificate (%s), but forcing renewal on request' % certfile_path)
        else:
            logger.info('existing certificate (%s) will expire inside of renewal time (%s) or has changes; requesting new one' % (certfile_path, min_valid_time))
            force = True

    for (domain, webroot) in zip(domain_list, webroot_list):
        logger.info('requesting challange for %s in %s' % (domain, webroot))

        authzr = ctx.obj['acme'].request_domain_challenges(domain, new_authzr_uri=regr.new_authzr_uri)
        authzrs.append(authzr)

        challb = _get_http_challenge(ctx, authzr)
        chall_response, chall_validation = challb.response_and_validation(ctx.obj['account_key'])
        _store_webroot_validation(webroot, challb, chall_validation)
        ctx.obj['acme'].answer_challenge(challb, chall_response)

    key, csr = _generate_key_and_csr(domain_list, key_size, key_digest)

    try:
        crt, updated_authzrs = ctx.obj['acme'].poll_and_request_issuance(csr, authzrs)
    except errors.PollError as e:
        if e.exhausted:
            logger.error('validation timed out for the following domains: %s' % ', '.join(authzr.body.identifier for authzr in e.exhausted))
        invalid_domains = [(authzr.body.identifier.value, _get_http_challenge(ctx, authzr).error.detail) for authzr in e.updated.values() if authzr.body.status == messages.STATUS_INVALID]
        if invalid_domains:
            logger.error('validation invalid for the following domains:')
            for invalid_domain in invalid_domains:
                logger.error('%s: %s' % invalid_domain)
        ctx.exit(1)

    # write optional chain
    chain = ctx.obj['acme'].fetch_chain(crt)
    certs = [crt.body]
    if with_chain:
        certs.extend(chain)
    else:
        if not force and os.path.exists(chainfile_path):
            _confirm_overwrite(chainfile_path)

        with open(chainfile_path, 'wb') as f:
            for crt in chain:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, crt))

    # write cert
    with open(certfile_path, 'wb') as f:
        for crt in certs:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, crt))

    # write key
    if not force and os.path.exists(keyfile_path):
        _confirm_overwrite(keyfile_path)

    with open(keyfile_path, 'wb') as f:
        os.fchmod(f.fileno(), 0640)
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))


@cert.command(help='Revoke existing certificates')
@click.pass_context
@click.argument('cert_paths', metavar='CERT_FILE [CERT_FILE ...]', nargs=-1, required=True)
def revoke(ctx, cert_paths):
    for cert_path in cert_paths:
        with open(cert_path, 'rb') as f:
            crt = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
            ctx.obj['acme'].revoke(ComparableX509(crt))


def _confirm_overwrite(filepath):
    click.confirm('file %s exists; overwrite?' % filepath, abort=True)


def _generate_domain_and_webroot_lists_from_args(ctx, domainroots):
    domain_list = list()
    webroot_list = list()
    webroot = None
    for domainroot in domainroots:
        webroot = domainroot.webroot or webroot
        if not webroot:
            logger.error('domain without webroot: %s' % domainroot.domain)
            ctx.exit(1)
        domain_list.append(domainroot.domain)
        webroot_list.append(webroot)

    return (domain_list, webroot_list)


def _get_http_challenge(ctx, authzr):
    for c in authzr.body.combinations:
        if len(c) == 1 and isinstance(authzr.body.challenges[c[0]].chall, challenges.HTTP01):
            return authzr.body.challenges[c[0]]
    ctx.fail('no acceptable challenge type found; only HTTP01 supported')


def _store_webroot_validation(webroot, challb, val):
    logger.info('storing validation of %s' % webroot)
    try:
        os.makedirs(os.path.join(webroot, challb.URI_ROOT_PATH), 0755)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

    with open(os.path.join(webroot, challb.path.strip('/')), 'wb') as outf:
        logger.info('storing validation to %s' % outf.name)
        outf.write(val)


def _is_valid_and_unchanged(certfile_path, domains, min_valid_time):
    with open(certfile_path, 'rb') as f:
        crt = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
        # TODO: do we need to support the other possible ASN.1 date formats?
        expiration = datetime.strptime(crt.get_notAfter(), '%Y%m%d%H%M%SZ')

        # create a set of domain names in the cert (DN + SANs)
        crt_domains = {dict(crt.get_subject().get_components())['CN']}
        for i in xrange(crt.get_extension_count()):
            ext = crt.get_extension(i)
            if ext.get_short_name() == 'subjectAltName':
                # we strip 'DNS:' without checking if it's there; if it
                # isn't, the cert uses some other unsupported identifier,
                # and is definitely different from the one we're creating
                crt_domains = crt_domains.union(map(lambda x: x.strip()[4:], str(ext).split(',')))

        if datetime.now() + min_valid_time > expiration:
            logger.info('EXPIRATION')
            return False
        elif crt_domains != set(domains):
            logger.info('DOMAINS: %s != %s' % (crt_domains, set(domains)))
            return False
        else:
            return True


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
