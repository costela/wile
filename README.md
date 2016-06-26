# Overview

Wile is a simple [Let's Encrypt](https://letsencrypt.org) (ACME) client that only supports the "webroot" method of validation. It only needs access to the root folder serving the domanis in question. Specifically, it only needs access to the ".well-known" sub-folder and therefore doesn't need root permissions.

The ".well-known" folder must also be accessible from external sources. I.e.: if you run a reverse proxy for some backend application, it should include an exception for this folder.

# Usage

Simple anonymous certificate request:
```
$ wile cert request example.com:/var/www/example.com/
```

Registration with contact information, and saving certs to some other location (default saves to current folder):
```
$ wile register -e name@example.com
$ wile cert request --output-dir /etc/ssl/private/ example.com:/var/www/example.com/
```

Revoking a certificate:
```
$ wile cert revoke /etc/ssl/private/example.com.crt
```