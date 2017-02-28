# Let's Encrypt (AMCE protocol) support for Play Framework

*Let's Encrypt* HTTPS certificates must be renewed every 60 days or so. This module automates the HTTPS certificate set up and renewal for your Play app by including a minimal *Let's Encrypt* ACME client in your app. After we request and set up the initial HTTPS certificate in your Play app, the module will also take care of automatically renewing certificate without any further headaches.

## Running

Clone, and build samples/acme-client-sample . Run it via `sbt run`. Open https://localhost:9443/cert in browser. The certificate request (or renewal) progress is shown in output and also is logged.

After setting up your initial keys, you should set up crontab entry to poll the `http://localhost/cert` command every 60 days. You can use wget or curl.

# Automated Certificate Management Environment (ACME) protocol library written in scala.

This library is based on the draft specification "draft-barnes-acme-04" and the Let's Encrypt [boulder implementation](https://github.com/letsencrypt/boulder/blob/release/docs/acme-divergences.md).

ACME is a protocol for automating the management of domain-validation certificates, based on a simple JSON-over-HTTPS interface.

The ACME protocol is developed at [Let's Encrypt](https://letsencrypt.org/). Let’s Encrypt is a free, automated, and open certificate authority (CA), run for the public’s benefit.
Let’s Encrypt is a service provided by the Internet Security Research Group (ISRG).

## Documentation

See [Let's Encrypt](https://letsencrypt.org/) and the [ACME protocol description](https://tools.ietf.org/html/draft-ietf-acme-acme-04)
 (draft-barnes-acme-04) that we used (verbatim) in the documentation of the scala code.

## Dependencies

The **play-acme-protocol** module depends on the scala Play Framework Json library and the Nimbus JOSE + JWT Java library for JSON Web Tokens (JWT).

See also the build.sbt file.

## Status

This is a work in progress.

- JDK 8
- Scala 2.11
- Play 2.5
