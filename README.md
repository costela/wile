[![Build Status](https://travis-ci.org/costela/wile.svg?branch=master)](https://travis-ci.org/costela/wile)
[![PyPI version](https://badge.fury.io/py/wile.svg)](https://badge.fury.io/py/wile)

# Overview

Wile is a simple [Let's Encrypt](https://letsencrypt.org) (ACME) client that only supports the "webroot" method of validation. It only needs access to the root folder serving the domains in question. Specifically, it only needs access to the `.well-known` sub-folder and therefore doesn't need permission to access the actual website's content.

The `.well-known` folder must also be accessible from external sources. I.e.: if you run a reverse proxy for some backend application, it should include an exception for this folder.

# Usage

## Generating a certificate request

Simple anonymous certificate request:
```
$ wile cert request example.com:/var/www/example.com/
```

Registration with contact information, and saving certs to some other location (by default the certificate is saved to current folder):
```
$ wile register -e name@example.com
$ wile cert request --output-dir /etc/ssl/private/ example.com:/var/www/example.com/
```

Certificate request using remote webroot validation of SSH/SFTP:
```
$ wile cert request example.com:username@example.com:/var/www/example.com/
```

Syntax for remote webroot validation argument is: DOMAIN:[[[USER@]HOST[:PORT]:]PATH].

Storing remote webroot validation is done via SFTP using SSH public key authentication. You can explicitly define path to your private key using `--ssh-private-key` option. Also, if your private key has been secured with a password you must provide your private key password using an ENV variable (`WILE_SSH_PASS='<your password>'`). Note that there are single quotes around the password so that your shell doesn't try to expand the symbols within the password.

Note that you can also pass multiple domains with a single document root, which creates a certificate with [Subject Alternative Names](https://en.wikipedia.org/wiki/Subject_Alternative_Name).
```
$ wile cert request example.com:/var/www/example.com/ www.example.com
```

In case of a remote webroot validation:
```
$ wile cert request example.com:username@example.com:/var/www/example.com/ www.example.com
```

## Revoking a certificate

Simple anonymous certificate revocation:
```
$ wile cert revoke /etc/ssl/private/example.com.crt
```

## Certificate renewal

By default, no new request will be made if `wile` detects an existing certificate for the same requested domains with a validity of at least 1 week. This can be changed with the `--min-valid-time` and `--force` options.

This way a simple daily cronjob is enough to ensure certificate freshness and should make renewals resiliant against moderate letsencrypt API downtime.
