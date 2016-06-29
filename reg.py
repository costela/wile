
import os
import logging

import click
from acme import messages
from acme import client
from acme import errors

logger = logging.getLogger('wile').getChild('register')


@click.command(help='Register a new account key or update an existing registration')
@click.pass_context
@click.option('--email', '-e', metavar='EMAIL')
@click.option('--phone', '-p', metavar='PHONE')
@click.option('--auto-accept-tos', is_flag=True, default=False, show_default=True, help='Automatically accept directory\'s Terms of Service')
def register(ctx, email, phone, auto_accept_tos, quiet=False):
    regr = ctx.obj['acme'].register(messages.NewRegistration.from_data(email=email, phone=phone))
    if regr.body.agreement != regr.terms_of_service:
        if not auto_accept_tos and not click.confirm('Accept Terms of Service? (%s)' % regr.terms_of_service, default=None):
            ctx.fail('Must accept ToS to continue')
        elif auto_accept_tos:
            logger.info('automatically accepting ToS')
        ctx.obj['acme'].agree_to_tos(regr)

    if (email and (email,) != regr.body.emails) or (phone and (phone,) != regr.body.phones):
        logger.info('updating contact information')
        upd_reg = messages.UpdateRegistration().from_data(email=email, phone=phone)
        try:
            regr = ctx.obj['acme'].update_registration(regr, upd_reg)
        except errors.UnexpectedUpdate:
            pass  # no idea why it complains, but updates anyway
        regr = ctx.obj['acme'].query_registration(regr)

    if not quiet:
        click.echo('Registration:')
        click.echo('Email: %s' % (regr.body.emails,))
        click.echo('Phone: %s' % (regr.body.phones,))
    else:
        return regr


# TODO: this should be merged upstream, with a more elegant solution.
# This is partially solved by https://github.com/letsencrypt/letsencrypt/pull/2085
# Missing: actual handling of the problem in register() (maybe with argument existing_ok?)
def _monkeypatch_post(self, url, obj, content_type=client.ClientNetwork.JSON_CONTENT_TYPE, check_response=True, **kwargs):
    data = self._wrap_in_jws(obj, self._get_nonce(url))
    response = self._send_request('POST', url, data=data, **kwargs)
    self._add_nonce(response)
    if check_response:
        return self._check_response(response, content_type=content_type)
    else:
        return response
client.ClientNetwork.post = _monkeypatch_post


def _monkeypatch_register(self, new_reg=None):
    new_reg = new_reg or messages.NewRegistration()
    response = self.net.post(self.directory[new_reg], new_reg, check_response=False)
    loc = None
    if response.status_code == client.http_client.CONFLICT and response.headers.get('Location'):
        reg = messages.UpdateRegistration()
        loc = response.headers.get('Location')
        response = self.net.post(loc, reg)
    return self._regr_from_response(response, uri=loc)
client.Client.register = _monkeypatch_register
