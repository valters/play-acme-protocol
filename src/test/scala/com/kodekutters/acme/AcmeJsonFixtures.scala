package com.kodekutters.acme

import org.scalatest.{ Matchers, WordSpec }

import com.nimbusds.jose.util.Base64

import play.api.libs.json.Json

/**
 * This tests only the JSON parsing part of ACME protocol support.
 */
class AcmeJsonFixtures extends WordSpec with Matchers {

  val keypair = AcmeJson.generateKeyPair()

  val TestDirectoryBody = """{
  "key-change": "https://acme-staging.api.letsencrypt.org/acme/key-change",
  "new-authz": "https://acme-staging.api.letsencrypt.org/acme/new-authz",
  "new-cert": "https://acme-staging.api.letsencrypt.org/acme/new-cert",
  "new-reg": "https://acme-staging.api.letsencrypt.org/acme/new-reg",
  "revoke-cert": "https://acme-staging.api.letsencrypt.org/acme/revoke-cert"
}"""

  val TestRegistrationRequest = """{"resource":"new-reg","contact":["mailto:cert-admin@example.com","tel:+12025551212"]}"""


  "Acme Json Suite" when {

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

    "asked to create JSON" should {
      "create Request body with JWS" in {
        val req = new AcmeProtocol.RegistrationRequest( Array( "mailto:cert-admin@example.com", "tel:+12025551212"  ) )
        val jreq = Json.toJson( req ).toString()
        jreq shouldBe TestRegistrationRequest
        val j = AcmeJson.encodeRequest(req, "<nonce>", keypair )
        println( j )
        val payload = new Base64( (j \ "payload").as[String] ).decodeToString()
        payload shouldBe TestRegistrationRequest

        val protectedHeader = new Base64( (j \ "protected").as[String] ).decodeToString()
        println( protectedHeader )
        val header = Json.parse(protectedHeader)

        val nonce = ( header \ "nonce" ).as[String]
        nonce shouldBe "<nonce>"

        val alg = ( header \ "alg" ).as[String]
        alg shouldBe "RS256"

        val kty = ( header \ "jwk" \ "kty" ).as[String]
        kty shouldBe "RSA"

        val jwkalg = ( header \ "jwk" \ "alg" ).as[String]
        jwkalg shouldBe "RS256"
      }
    }
  }
}
