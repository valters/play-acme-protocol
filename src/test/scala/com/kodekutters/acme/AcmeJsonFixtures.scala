package com.kodekutters.acme

import org.scalatest.WordSpec
import org.scalatest.Matchers

/**
 * This tests only the JSON parsing part of ACME protocol support.
 */
class AcmeJsonFixtures extends WordSpec with Matchers {

  val TestDirectoryBody = """{
  "key-change": "https://acme-staging.api.letsencrypt.org/acme/key-change",
  "new-authz": "https://acme-staging.api.letsencrypt.org/acme/new-authz",
  "new-cert": "https://acme-staging.api.letsencrypt.org/acme/new-cert",
  "new-reg": "https://acme-staging.api.letsencrypt.org/acme/new-reg",
  "revoke-cert": "https://acme-staging.api.letsencrypt.org/acme/revoke-cert"
}"""


  "Acme Json Suite" when {
    val client = new AcmeHttpClient()

    "asked to parse JSON" should {
      "parse Directory body" in {
        val d: AcmeProtocol.Directory = AcmeJson.parseDirectory( TestDirectoryBody )
        d.get(AcmeProtocol.new_authz) shouldBe "https://acme-staging.api.letsencrypt.org/acme/new-authz"
        d.get(AcmeProtocol.new_cert) shouldBe "https://acme-staging.api.letsencrypt.org/acme/new-cert"
        d.get(AcmeProtocol.new_reg) shouldBe "https://acme-staging.api.letsencrypt.org/acme/new-reg"
        d.get(AcmeProtocol.revoke_cert) shouldBe "https://acme-staging.api.letsencrypt.org/acme/revoke-cert"
        d.get(AcmeProtocol.key_change) shouldBe "https://acme-staging.api.letsencrypt.org/acme/key-change"
      }

    }
  }
}
