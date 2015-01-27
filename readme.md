# Automated Certificate Management Environment (ACME) protocol library written in scala.

From reference 1, "ACME is a protocol for automating the management of domain-validation certificates,
based on a simple JSON-over-HTTPS interface."

"[Let's Encrypt](https://letsencrypt.org/) is a free, automated, and open certificate authority (CA), run for the public’s benefit.
Let’s Encrypt is a service provided by the Internet Security Research Group (ISRG)."

For a description of the ACME protocol see the [ACME protocol specification](https://github.com/letsencrypt/acme-spec) and
the [latest version](https://letsencrypt.github.io/acme-spec/)

This scala AcmeProtocol library provides the ACME specification as scala classes.

## Documentation

See the excellent project [Let's Encrypt](https://letsencrypt.org/) and the [ACME protocol description](https://letsencrypt.github.io/acme-spec/)
that I used (verbatim) in the documentation of the scala code.

## References

1) Let's Encrypt at: https://letsencrypt.org/

2) ACME protocol specification at: https://letsencrypt.github.io/acme-spec

## Packages

The scala AcmeProtocol object package consists of the following sections:
- 1) supporting elements, with AcmeIdentifier, Hints, AcmeSignature and Contact
- 2) Message types, such as error, defer, statusRequest
- 3) Challenges, such as simpleHttps, dvsni, dns, recoveryToken, recoveryContact, proofOfPossession
- 4) Responses, such as challenge, authorization, revocation, certificate
- 5) Requests, such as challengeRequest, authorizationRequest, certificateRequest, revocationRequest

There is a supporting Util object package that provides some convenient methods such as generating
randomString, nonce and token.

## Dependencies

The AcmeProtocol library depends on the scala Play Framework Json library and the Nimbus JOSE + JWT Java library for JSON Web Tokens (JWT).

See also the build.sbt file.

## Status

Early stage of the project.

Using scala 2.11.5 and java 1.8 SDK, with IntelliJ IDEA 14.

To generate a new jar file from the source using sbt:
sbt package

To generate the scaladoc:
sbt doc
