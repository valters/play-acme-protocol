# *Let's Encrypt* free CA (ACME protocol) support for Play Framework

This module automates the HTTPS certificate provisioning, setup and renewal for your Play app. In nutshell, you will be able to start serving HTTPS with minimum fuss and for free!

Also *Let's Encrypt* HTTPS certificates must be renewed every 60 days or so. We can automate all that by including a minimal *Let's Encrypt* ACME client based on Play WS. After we set up the initial HTTPS certificate, the module also will take care of automatically renewing your certificate.

To get started you only need to configure 2 settings in your _application.conf_:
```
acme.for-domain = "(your domain here)"
acme.account-email = "(your email address here)"
```

A new *Let's Encrypt* account will be automatically created for you.

(See example: acme-client-sample [conf/application.conf](https://github.com/valters/play-acme-protocol/blob/master/samples/acme-client-sample/conf/application.conf).)

By default, certificate .keystore will be generated in conf/ folder. (As conf/private.keystore for the private ACME account key and conf/domain.keystore which holds the HTTPS certificate.)

Use `-Dplay.user.keyStore.path=` and `-Dplay.server.https.keyStore.path=` to change file location (you might put the outside of play folder, for example), and don't forget to set up nice and secure `-Dplay.server.https.keyStore.password=`.
Note: _play.server.https.keyStore.path_ is the setting you use to set up HTTPS support in Play. But the _play.user.keyStore.path_ is our custom setting.

On the first run, the files don't exist and will be auto generated (the _domain.keystore_ will get generated once you request the certificate). No hassle.

## Running

Clone the project, build by running `sbt clean compile publish-local`.

Then, `cd samples/acme-client-sample` . Run the example app via `./run-app.sh` (important, because it asks Play to activate https and sets keystore variables.)

Open [http://localhost:8080/cert](http://localhost:8080/cert) in browser. The certificate request (or renewal) progress is shown in output and also is logged (so keep an eye on the logging messages flying by). Make sure to route the 80 port and 433 port from your router to your actual IP where app is running (ports 8080 and 9443 respectively).

Currently opening the _/cert_ page is allowed only from local host (127.0.0.1).

After initial set-up, you can set a crontab entry to poll the `http://localhost/cert` command every 60 days (or monthly). (Use _wget_ or _curl_.)

### Sample screenshot

![Running /cert endpoint](https://valters.github.io/play-acme-protocol/certify-progress-screenshot.png)

## What does it do on Let's Encrypt side?

It's simple. We generate a private key, transparently request and authorize Let's Encrypt account, then fulfill the http-01 challenge, send CSR (Certificate Signing Request) and get a nice and shiny HTTPS certificate back!
The best part is, once time rolls by when you have to renew it, it's all automatic and you don't have to do anything manually.

## What does it do on Playframework side?

This is the value-added part. In Play (or JVM generally) [working with certificates](https://www.playframework.com/documentation/2.5.x/CertificateGeneration) involves considerable amount of manual steps and using _openssl_ to convert a certificate file into something _keytool_ will understand, and then using _keytool_ to generate appropriate _keystore_. But all this can be automated and work out of the box, programmatically. We take care of all that for you.

## Adding to your own app

To adding this to your app, simply add dependency to _play-acme-protocol_ in your _build.sbt_:
```
libraryDependencies += "io.github.valters" %% "play-acme-protocol" % "0.1.0-SNAPSHOT"
```

And add AcmeController in your _routes_:
```
GET     /cert                                 io.github.valters.acme.AcmeController.cert
GET     /.well-known/acme-challenge/:token    io.github.valters.acme.AcmeController.challenge( token: String )
```

(See for example [https://github.com/valters/lawlog-play](https://github.com/valters/lawlog-play/blob/master/conf/routes) )
_/cert_ will respond only to requests from localhost. (If you don't have shell access, you might use _AcmeController.certAny_ which does not restrict IP, or wrap AcmeController to restrict access as appropriate.)

# Documentation

This library is based on the draft specification "draft-barnes-acme-04" and the Let's Encrypt [boulder implementation](https://github.com/letsencrypt/boulder/blob/release/docs/acme-divergences.md).

ACME is a protocol for automating the management of domain-validation certificates, based on a simple JSON-over-HTTPS interface.

The ACME protocol is developed at [Let's Encrypt](https://letsencrypt.org/). Let’s Encrypt is a free, automated, and open certificate authority (CA), run for the public’s benefit.
Let’s Encrypt is a service provided by the Internet Security Research Group (ISRG).

Please see [Let's Encrypt](https://letsencrypt.org/) and the [ACME protocol description](https://tools.ietf.org/html/draft-ietf-acme-acme-04)
 (draft-barnes-acme-04) that we used (verbatim) in the documentation of the Scala code.

## Dependencies

The **play-acme-protocol** module depends on the the Nimbus JOSE + JWT Java library for JSON Web Tokens (JWT).

See also the build.sbt file.

## Status

This is a work in progress. Certificate renewal is not completely figured out - currently we simply would get a new certificate and overwrite the existing (old one), but I suspect we can be a bit more subtle than that. I guess switching certificates will require restarting your application, and I am looking whether it would be possible to avoid it - have zero downtime.

- JDK 8
- Scala 2.11
- Play 2.5


## Credits

Developed by Valters Vingolds.
Based on ideas I borrowed from Franz Bettag's [scala-acme](https://github.com/wasted/scala-acme) code, and borrowing Scala [JSON definitions](https://github.com/workingDog/acme-protocol) by Ringo Wathelet.
