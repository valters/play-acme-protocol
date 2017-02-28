# Let's Encrypt (AMCE protocol) support for Play Framework

*Let's Encrypt* HTTPS certificates must be renewed every 60 days or so. This module automates the HTTPS certificate set up and renewal for your Play app by including a minimal *Let's Encrypt* ACME client in your app. After we request and set up the initial HTTPS certificate in your Play app, the module will also take care of automatically renewing certificate without any further headaches.

In fact, you only need to configure 2 settings in your _application.conf_:
```
acme.for-domain = "(your domain here)"
acme.account-email = "(your email address here)"
```
(See example: acme-client-sample [conf/application.conf](https://github.com/valters/play-acme-protocol/blob/master/samples/acme-client-sample/conf/application.conf).)

## Running

Clone the project, build by running `sbt clean compile publish-local`.

Then, `cd samples/acme-client-sample` . Run the example app via `./run-app.sh` (important, because it asks Play to activate https and sets keypass variables.)

Open [https://localhost:9443/cert](https://localhost:9443/cert) in browser. The certificate request (or renewal) progress is shown in output and also is logged (so keep an eye on the logging messages flying by).

Currently opening the _/cert_ page is allowed only from local host (127.0.0.1).

After initial set-up, you can set a crontab entry to poll the `http://localhost/cert` command every 60 days (or monthly). (Use _wget_ or _curl_.)

# Automated Certificate Management Environment (ACME) protocol library written in scala.

This library is based on the draft specification "draft-barnes-acme-04" and the Let's Encrypt [boulder implementation](https://github.com/letsencrypt/boulder/blob/release/docs/acme-divergences.md).

ACME is a protocol for automating the management of domain-validation certificates, based on a simple JSON-over-HTTPS interface.

The ACME protocol is developed at [Let's Encrypt](https://letsencrypt.org/). Let’s Encrypt is a free, automated, and open certificate authority (CA), run for the public’s benefit.
Let’s Encrypt is a service provided by the Internet Security Research Group (ISRG).

## Documentation

See [Let's Encrypt](https://letsencrypt.org/) and the [ACME protocol description](https://tools.ietf.org/html/draft-ietf-acme-acme-04)
 (draft-barnes-acme-04) that we used (verbatim) in the documentation of the Scala code.

## Dependencies

The **play-acme-protocol** module depends on the the Nimbus JOSE + JWT Java library for JSON Web Tokens (JWT).

See also the build.sbt file.

## Status

This is a work in progress. Certificate renewal is not completely figured out - we simply get a new certificate and overwrite the existing (old one), but I suspect we can be a bit more subtle than that.

- JDK 8
- Scala 2.11
- Play 2.5


## Credits

Developed by Valters Vingolds.
Based on ideas I borrowed from Franz Bettag's [scala-acme](https://github.com/wasted/scala-acme) code, and borrowing Scala [JSON definitions](https://github.com/workingDog/acme-protocol) by Ringo Wathelet.
