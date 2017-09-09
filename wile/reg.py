import logging

import click
from acme import messages
from acme import client
from acme import errors

logger = logging.getLogger(__name__)


@click.command()
@click.pass_context
@click.option('--email', '-e', metavar='EMAIL', help='email for contact')
# telephone contact hasn't been supported by Boulder since a while:
# https://github.com/letsencrypt/boulder/commit/03427ccb810731eecaf32f70a1d21a0001a4abe7
#
# but it's still in the specs:
# https://tools.ietf.org/html/draft-ietf-acme-acme-07#section-7.1.2
@click.option('--phone', '-p', metavar='PHONE', help='telephone number for contact; this is not supported by Let\'s'
                                       'Encrypt, but is in the ACME specs, so other providers might support it.')
@click.option('--auto-accept-tos', is_flag=True, default=False, show_default=True,
              help='Automatically accept directory\'s Terms of Service')
def register(ctx, email, phone, auto_accept_tos, quiet=False):
    '''
    Register a new account key or update an existing registration.
    '''

    logger.info('starting registration for email:"%s", phone:"%s"', email, phone)
    try:
        regr = ctx.obj.acme.register(messages.NewRegistration.from_data(email=email, phone=phone))
    except errors.ConflictError as e:
        logger.info('found existing registration for key; fetching')
        response = ctx.obj.acme.net.post(e.location, messages.UpdateRegistration())
        regr = client.Client._regr_from_response(response, uri=e.location)

    if regr.body.agreement != regr.terms_of_service:
        if not auto_accept_tos and not click.confirm('Accept Terms of Service? (%s)' % regr.terms_of_service,
                                                     default=None):
            ctx.fail('Must accept ToS to continue')
        elif auto_accept_tos:
            logger.info('automatically accepting ToS')
        ctx.obj.acme.agree_to_tos(regr)

    if (email and (email,) != regr.body.emails) or (phone and (phone,) != regr.body.phones):
        logger.info('updating contact information')
        upd_reg = messages.UpdateRegistration().from_data(email=email, phone=phone)
        try:
            regr = ctx.obj.acme.update_registration(regr, upd_reg)
        except errors.UnexpectedUpdate:
            pass  # no idea why it complains, but updates anyway
        regr = ctx.obj.acme.query_registration(regr)

    if not quiet:
        click.echo('Registration:')
        click.echo('Email: %s' % (regr.body.emails or ''))
        click.echo('Phone: %s' % (regr.body.phones or ''))
    else:
        return regr
