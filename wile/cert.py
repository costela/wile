import atexit
import os
import logging
import errno
from collections import OrderedDict
from datetime import datetime
from six import b
from six.moves import range

import click
import paramiko
from OpenSSL import crypto

from acme import challenges
from acme import messages
from acme import errors
from acme.jose.util import ComparableX509

from . import reg
from . import argtypes

logger = logging.getLogger('wile').getChild('cert')

# Taken from https://tools.ietf.org/html/rfc5280#section-5.3.1
# Not all all supported by letsencrypt's boulder.
REVOCATION_REASONS = OrderedDict((
    ('unspecified', 0),
    ('keyCompromise', 1),
    ('CACompromise', 2),
    ('affiliationChanged', 3),
    ('superseded', 4),
    ('cessationOfOperation', 5),
    ('certificateHold', 6),
    ('removeFromCRL', 8),
    ('privilegeWithdrawn', 9),
    ('AACompromise', 10),
))


@click.group(help='Certificate management')
def cert():
    pass


@cert.command(help='''Request a new certificate for the provided domains and respective webroot paths. \
                      If a webroot is not provided for a domain, the one of the previous domain is used.''')
@click.pass_context
@click.option('--with-chain/--separate-chain', is_flag=True, default=True, show_default=False,
              help='''Whether to include the certificate\'s chain in the output certificate; --separate-chain implies a \
                      separate .chain.crt file, containing only the signing certificates up to the root \
                      [default: with chain]''')
@click.option('--key-size', '-s', metavar='SIZE', type=int, default=2048, show_default=True,
              help='Size in bits for the generated certificate\'s key')
@click.option('--output-dir', metavar='DIR', type=argtypes.WritablePathType, default='.',
              help='Where to store created certificates (default: current directory)')
@click.option('--basename', metavar='BASENAME',
              help='Basename to use when storing output: BASENAME.crt and BASENAME.key [default: first domain]')
@click.option('--key-digest', metavar='DIGEST', default='sha256', show_default=True,
              help='The digest to use when signing the request with its key (must be supported by openssl)')
@click.option('--min-valid-time', type=argtypes.TimespanType, metavar='TIMESPAN', default='25h', show_default=True,
              help='''If a certificate is found and its expiration lies inside of this timespan, it will be automatically \
                      requested and overwritten; otherwise no request will be made. The format for this option is "1d" \
                      for one day. Supported units are hours, days and weeks.''')
@click.option('--force', is_flag=True, default=False, show_default=True,
              help='Whether to force a request to be made, even if a valid certificate is found')
@click.option('--ssh-private-key', type=click.Path(exists=True, file_okay=True, dir_okay=False),
              default='~/.ssh/id_rsa', show_default=True, help='path to SSH private key')
@click.option('--ssh-private-key-pass', prompt=True, hide_input=True, default=lambda: os.environ.get('WILE_SSH_PASS', ''),
              help='SSH private key password')
@click.option('--ssh-private-key-type', default='RSA', show_default=True, help='SSH private key type')
@click.argument('domainroots', 'DOMAIN:[[[USER@]HOST[:PORT]:]WEBROOT]', type=argtypes.DomainRemoteWebrootType,
                metavar='DOMAIN:[[[USER@]HOST[:PORT]:]WEBROOT]', nargs=-1, required=True)
def request(ctx, domainroots, with_chain, key_size, output_dir, basename, key_digest, min_valid_time, force,
            ssh_private_key, ssh_private_key_pass, ssh_private_key_type):
    regr = ctx.invoke(reg.register, quiet=True, auto_accept_tos=True)
    authzrs = list()

    domain_list, remote_list, webroot_list = _generate_domain_and_webroot_lists_from_args(ctx, domainroots)
    basename = basename or domain_list[0]
    keyfile_path = os.path.join(output_dir, '%s.key' % basename)
    certfile_path = os.path.join(output_dir, '%s.crt' % basename)
    chainfile_path = os.path.join(output_dir, '%s.chain.crt' % basename)

    if os.path.exists(certfile_path):
        if not force and _is_valid_and_unchanged(certfile_path, domain_list, min_valid_time):
            logger.info('found existing valid certificate (%s); not requesting a new one', certfile_path)
            ctx.exit(0)
        elif force:
            logger.info('found existing valid certificate (%s), but forcing renewal on request', certfile_path)
        else:
            logger.info('''existing certificate (%s) will expire inside of renewal time (%s) or has changes; \
                           requesting new one''', certfile_path, min_valid_time)
            force = True

    for (domain, remote, webroot) in zip(domain_list, remote_list, webroot_list):
        if not remote or remote.count(None) is len(remote):
            logger.info('requesting challange for %s in %s', domain, webroot)
            remote = None
        else:
            logger.info('requesting challange for %s in %s on %s', domain, webroot, remote[1])
            remote += (ssh_private_key, ssh_private_key_pass, ssh_private_key_type,)

        authzr = ctx.obj.acme.request_domain_challenges(domain, new_authzr_uri=regr.new_authzr_uri)
        authzrs.append(authzr)

        challb = _get_http_challenge(ctx, authzr)
        chall_response, chall_validation = challb.response_and_validation(ctx.obj.account_key)
        _store_webroot_validation(ctx, remote, webroot, challb, chall_validation)
        ctx.obj.acme.answer_challenge(challb, chall_response)

    key, csr = _generate_key_and_csr(domain_list, key_size, key_digest)

    try:
        crt, updated_authzrs = ctx.obj.acme.poll_and_request_issuance(csr, authzrs)
    except errors.PollError as e:
        if e.exhausted:
            logger.error('validation timed out for the following domains: %s', ', '.join(authzr.body.identifier for
                                                                                         authzr in e.exhausted))
        invalid_domains = [(e_authzr.body.identifier.value, _get_http_challenge(ctx, e_authzr).error.detail)
                           for e_authzr in e.updated.values() if e_authzr.body.status == messages.STATUS_INVALID]
        if invalid_domains:
            logger.error('validation invalid for the following domains:')
            for invalid_domain in invalid_domains:
                logger.error('%s: %s' % invalid_domain)
        ctx.exit(1)

    # write optional chain
    chain = ctx.obj.acme.fetch_chain(crt)
    certs = [crt.body]
    if with_chain:
        certs.extend(chain)
    else:
        if not force and os.path.exists(chainfile_path):
            _confirm_overwrite(chainfile_path)

        with open(chainfile_path, 'wb') as chainfile:
            for crt in chain:
                chainfile.write(crypto.dump_certificate(crypto.FILETYPE_PEM, crt))

    # write cert
    with open(certfile_path, 'wb') as certfile:
        for crt in certs:
            certfile.write(crypto.dump_certificate(crypto.FILETYPE_PEM, crt))

    # write key
    if not force and os.path.exists(keyfile_path):
        _confirm_overwrite(keyfile_path)

    with open(keyfile_path, 'wb') as keyfile:
        os.chmod(keyfile.name, 0o640)
        keyfile.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))


@cert.command(help='Revoke existing certificates')
@click.pass_context
@click.option('--reason', metavar='REASON', default='unspecified', type=click.Choice(REVOCATION_REASONS.keys()),
              show_default=True, help='reason for revoking certificate. Valid values: %s; not all are supported by '
                                      'Let\'s Encrypt' % REVOCATION_REASONS.keys())
@click.argument('cert_paths', metavar='CERT_FILE [CERT_FILE ...]', nargs=-1, required=True)
def revoke(ctx, reason, cert_paths):
    for cert_path in cert_paths:
        with open(cert_path, 'rb') as certfile:
            crt = crypto.load_certificate(crypto.FILETYPE_PEM, certfile.read())
            try:
                ctx.obj.acme.revoke(ComparableX509(crt), REVOCATION_REASONS[reason])
            except messages.Error as e:
                logger.error(e)


def _confirm_overwrite(filepath):
    click.confirm('file %s exists; overwrite?' % filepath, abort=True)


def _generate_domain_and_webroot_lists_from_args(ctx, domainroots):
    domain_list = list()
    remote_list = list()
    webroot_list = list()
    webroot = None
    for domainroot in domainroots:
        if domainroot.webroot:
            webroot = argtypes.WritablePathType(domainroot.webroot)
        elif webroot:
            pass  # if we already have one from the last element, just use it
        else:
            logger.error('domain without webroot: %s', domainroot.domain)
            ctx.exit(1)
        domain_list.append(domainroot.domain)
        remote_list.append(domainroot.remote)
        webroot_list.append(webroot)

    return (domain_list, remote_list, webroot_list)


def _get_http_challenge(ctx, authzr):
    for combis in authzr.body.combinations:
        if len(combis) == 1 and isinstance(authzr.body.challenges[combis[0]].chall, challenges.HTTP01):
            return authzr.body.challenges[combis[0]]
    ctx.fail('no acceptable challenge type found; only HTTP01 supported')


def _store_webroot_validation(ctx, remote, webroot, challb, val):
    logger.info('storing validation of %s', webroot)
    chall_path = os.path.join(webroot, challb.path.strip('/'))
    if not remote:
        try:
            os.makedirs(os.path.join(webroot, challb.URI_ROOT_PATH), 0o755)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

        with open(chall_path, 'wb') as outf:
            logger.info('storing validation to %s', outf.name)
            outf.write(b(val))
            atexit.register(os.unlink, outf.name)
    else:
        username = remote[0] is not None and remote[0] or os.environ.get('USER')
        hostname = remote[1]
        port = remote[2] is not None and int(remote[2]) or 22
        private_key_path = os.path.expanduser(remote[3])
        private_key_pass = remote[4] is not '' and remote[4] or None
        private_key_type = remote[5]
        if private_key_type == 'RSA':
            private_key = paramiko.RSAKey.from_private_key_file(private_key_path, password=private_key_pass)
        elif private_key_type == 'ECDSA':
            private_key = paramiko.ECDSAKey.from_private_key_file(private_key_path, password=private_key_pass)
        elif private_key_type == 'DSA' or private_key_type == 'DSS':
            private_key = paramiko.DSSKey.from_private_key_file(private_key_path, password=private_key_pass)
        else:
            ctx.fail('invalid SSH key type (valid: RSA, ECDSA, DSA, DSS)')
        try:
            transport = paramiko.Transport((hostname, port))
            transport.connect(hostkey=None, username=username, pkey=private_key)
            sftp = paramiko.SFTPClient.from_transport(transport)
            with sftp.open(chall_path, 'wb') as outf:
                logger.info('storing validation to %s:%s' % (remote[1], chall_path))
                outf.write(b(val))
                atexit.register(os.unlink, outf.name)
            transport.close()
        except Exception as e:
            try:
                transport.close()
            except:
                pass
            ctx.fail('SFTP connection failed')


def _is_valid_and_unchanged(certfile_path, domains, min_valid_time):
    with open(certfile_path, 'rb') as certfile:
        crt = crypto.load_certificate(crypto.FILETYPE_PEM, certfile.read())
        # TODO: do we need to support the other possible ASN.1 date formats?
        expiration = datetime.strptime(crt.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')

        # create a set of domain names in the cert (DN + SANs)
        crt_domains = {dict(crt.get_subject().get_components())[b('CN')].decode('ascii')}
        for ext_idx in range(crt.get_extension_count()):
            ext = crt.get_extension(ext_idx)
            if ext.get_short_name() == b'subjectAltName':
                # we strip 'DNS:' without checking if it's there; if it
                # isn't, the cert uses some other unsupported identifier,
                # and is definitely different from the one we're creating
                crt_domains = crt_domains.union((x.strip()[4:] for x in str(ext).split(',')))

        if datetime.now() + min_valid_time > expiration:
            logger.info('EXPIRATION')
            return False
        elif crt_domains != set(domains):
            logger.info('DOMAINS: %s != %s', crt_domains, set(domains))
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
    exts = [crypto.X509Extension(b'subjectAltName', False, b(sans))]
    csr.add_extensions(exts)

    csr.sign(key, str(key_digest))

    return (key, ComparableX509(csr))
