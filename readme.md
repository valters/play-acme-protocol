# Automated Certificate Management Environment (ACME) protocol library written in scala.

From reference 1, ACME is a protocol for automating the management of domain-validation certificates,
based on a simple JSON-over-HTTPS interface. [Let's Encrypt](https://letsencrypt.org/) is a free, automated, and open certificate authority (CA), run for the public’s benefit.
Let’s Encrypt is a service provided by the Internet Security Research Group (ISRG).

For a description of the protocol see the [ACME protocol specification](https://github.com/letsencrypt/acme-spec) and
the [latest version](https://letsencrypt.github.io/acme-spec/)

## References

1) Let's Encrypt at: https://letsencrypt.org/

2) ACME protocol specification at: https://letsencrypt.github.io/acme-spec


## Dependencies

see build.sbt

## Status

Just starting the project.

Using scala 2.11.5 and java 1.8 SDK, with IntelliJ IDEA 14.

To generate a new jar file from the source using sbt, type: sbt package

To generate the scaladoc, type: sbt doc
