# Automated Certificate Management Environment (ACME) protocol library written in scala.

This scala ACME protocol library is based on the draft specification "draft-barnes-acme-04".

From reference 1, "ACME is a protocol for automating the management of domain-validation certificates,
based on a simple JSON-over-HTTPS interface."

The ACME protocol is developed at [Let's Encrypt](https://letsencrypt.org/). "Let’s Encrypt is a free, automated, and open certificate authority (CA), run for the public’s benefit.
Let’s Encrypt is a service provided by the Internet Security Research Group (ISRG)."

For a description of the ACME protocol see the [ACME protocol specification](https://github.com/letsencrypt/acme-spec) and
the [latest version](https://letsencrypt.github.io/acme-spec/)

This scala **AcmeProtocol** library provides the ACME specification as scala classes to assist developers in 
using ACME in scala applications.

## Documentation

See [Let's Encrypt](https://letsencrypt.org/) and the [ACME protocol description](https://letsencrypt.github.io/acme-spec/)
 (draft-barnes-acme-04) that I used (verbatim) in the documentation of the scala code.

## References

1) Let's Encrypt at: https://letsencrypt.org/

2) ACME protocol specification at: https://letsencrypt.github.io/acme-spec

## Dependencies

The **AcmeProtocol** library depends on the scala Play Framework Json library and the Nimbus JOSE + JWT Java library for JSON Web Tokens (JWT).

See also the build.sbt file.

## Status

This is very much a work in progress.

Using scala 2.11.7 and java 1.8 SDK.

To generate a new jar file from the source using sbt: sbt package

To generate the scaladoc: sbt doc
