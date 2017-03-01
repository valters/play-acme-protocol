/*
  Copyright 2017 Valters Vingolds

  This file is licensed to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

package io.github.valters.acme

import org.scalatest.{ Matchers, WordSpec }

import com.nimbusds.jose.util.Base64

import play.api.libs.json.Json

import AcmeJsonImplicits.fmtAcceptHttpChallenge

/**
 * This tests only the JSON parsing part of ACME protocol support.
 */
class AcmeJsonFixtures extends WordSpec with Matchers {

  val Keys = new KeyStorage( TestEnv )

  val TestContacts = Array( "mailto:cert-admin@example.com", "tel:+12025551212"  )

  val TestDirectoryBody = """{
  "key-change": "https://acme-staging.api.letsencrypt.org/acme/key-change",
  "new-authz": "https://acme-staging.api.letsencrypt.org/acme/new-authz",
  "new-cert": "https://acme-staging.api.letsencrypt.org/acme/new-cert",
  "new-reg": "https://acme-staging.api.letsencrypt.org/acme/new-reg",
  "revoke-cert": "https://acme-staging.api.letsencrypt.org/acme/revoke-cert"
}"""

  val TestRegistrationRequest = """{"resource":"new-reg","contact":["mailto:cert-admin@example.com","tel:+12025551212"]}"""

  val TestAuthorizationRequest = """{"resource":"new-authz","identifier":{"type":"dns","value":"unit-test.domain"}}"""

  val TermsOfService = "https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf"

  val TestRegistrationRequestWithAgreement = """{"resource":"reg","agreement":"https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf"}"""

  val TestSniChallenge = """    {
      "type": "tls-sni-01",
      "status": "pending",
      "uri": "https://acme-staging.api.letsencrypt.org/acme/challenge/zgy5u_aCgUg6A0o6QzwVejSStjnX7qpt8L7kAmc4SpI/26567983",
      "token": "1YonOX7Hg66rwryDwYeyHQCUlnkLjZoTR4B7UXLF6Os"
    }
"""

  val TestAuthorizationChallenge = """{
  "identifier": {
    "type": "dns",
    "value": "unit-test.mydomain.example.org"
  },
  "status": "pending",
  "expires": "2017-02-28T09:05:29.382845812Z",
  "challenges": [
    {
      "type": "http-01",
      "status": "pending",
      "uri": "https://acme-staging.api.letsencrypt.org/acme/challenge/zgy5u_aCgUg6A0o6QzwVejSStjnX7qpt8L7kAmc4SpI/26567981",
      "token": "64i9fs15NaaD-y09SAdySPJkMXc7chV9w2jCOMca7Fg"
    },
    {
      "type": "dns-01",
      "status": "pending",
      "uri": "https://acme-staging.api.letsencrypt.org/acme/challenge/zgy5u_aCgUg6A0o6QzwVejSStjnX7qpt8L7kAmc4SpI/26567982",
      "token": "I1kxljrIAGz3nUm2YHzPgrMvwKkAHg9qZMWXJx9QI9E"
    },
    {
      "type": "tls-sni-01",
      "status": "pending",
      "uri": "https://acme-staging.api.letsencrypt.org/acme/challenge/zgy5u_aCgUg6A0o6QzwVejSStjnX7qpt8L7kAmc4SpI/26567983",
      "token": "1YonOX7Hg66rwryDwYeyHQCUlnkLjZoTR4B7UXLF6Os"
    }
  ],
  "combinations": [
    [
      0
    ],
    [
      1
    ],
    [
      2
    ]
  ]
}"""

  val HttpAuthToken = "64i9fs15NaaD-y09SAdySPJkMXc7chV9w2jCOMca7Fg"

  val TestHttpChallengeReq = """{"type":"http-01","resource":"challenge","keyAuthorization":"64i9fs15NaaD-y09SAdySPJkMXc7chV9w2jCOMca7Fg","tls":false}"""

  val TestHttpChallengeResp = """{
  "type": "http-01",
  "status": "invalid",
  "error": {
    "type": "urn:acme:error:connection",
    "detail": "DNS problem: NXDOMAIN looking up A for unit-test.mydomain.example.org",
    "status": 400
  },
  "uri": "https://acme-staging.api.letsencrypt.org/acme/challenge/HbneD62ctzzq0-0WQ2-eTTNE2pO9TIehCy3heA_5oWg/26655337",
  "token": "pJw_sdRD01Qd1pR1WKAGf4IksL4DtUYmfBmMOdaSYMg",
  "keyAuthorization": "pJw_sdRD01Qd1pR1WKAGf4IksL4DtUYmfBmMOdaSYMg.Axtsf3VDiDeRH9TB7ok6taUGEvKsvdaGk-EiTDN4Ihk",
  "validationRecord": [
    {
      "url": "http://unit-test.mydomain.example.org/.well-known/acme-challenge/pJw_sdRD01Qd1pR1WKAGf4IksL4DtUYmfBmMOdaSYMg",
      "hostname": "unit-test.mydomain.example.org",
      "port": "80",
      "addressesResolved": [],
      "addressUsed": ""
    }
  ]
}"""

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

      "parse tls-sni challenge" in {
        val challenge: AcmeProtocol.ChallengeType = AcmeJson.parseChallenge( TestSniChallenge )
        challenge.`type` shouldBe "tls-sni-01"
        val tls = challenge.asInstanceOf[AcmeProtocol.ChallengeTlsSni]
        tls.status.get shouldBe AcmeProtocol.pending
        tls.token shouldBe "1YonOX7Hg66rwryDwYeyHQCUlnkLjZoTR4B7UXLF6Os"
      }

      "parse http challenge with details" in {
        val challenge: AcmeProtocol.ChallengeType = AcmeJson.parseChallenge( TestHttpChallengeResp )
        challenge.`type` shouldBe "http-01"
        val http = challenge.asInstanceOf[AcmeProtocol.ChallengeHttp]
        http.status.get shouldBe AcmeProtocol.invalid
        http.token shouldBe "pJw_sdRD01Qd1pR1WKAGf4IksL4DtUYmfBmMOdaSYMg"
        http.error.get.status.get shouldBe 400
      }

      "parse Authorization body" in {
        val ares: AcmeProtocol.AuthorizationResponse = AcmeJson.parseAuthorization( TestAuthorizationChallenge )
        val challenge = AcmeJson.findHttpChallenge( ares.challenges )
        challenge should not be (None)
        val http_challenge: AcmeProtocol.ChallengeHttp = challenge.get
        http_challenge.token shouldBe HttpAuthToken
        http_challenge.uri shouldBe "https://acme-staging.api.letsencrypt.org/acme/challenge/zgy5u_aCgUg6A0o6QzwVejSStjnX7qpt8L7kAmc4SpI/26567981"
      }

    }

    "asked to create JSON" should {
      "create Registration req with JWS" in {
        val req = new AcmeProtocol.RegistrationRequest( TestContacts )
        val jreq = AcmeJson.toJson( req ).toString()
        jreq shouldBe TestRegistrationRequest
        val j = AcmeJson.encodeRequest(req, "<nonce>", Keys.userKey )
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

      "create Registration+Agreement req with JWS" in {
        val req = AcmeProtocol.RegistrationRequest( resource = AcmeProtocol.reg, agreement = Some(TermsOfService) )
        val jreq = AcmeJson.toJson( req ).toString()
        jreq shouldBe TestRegistrationRequestWithAgreement
        val j = AcmeJson.encodeRequest(req, "<nonce>", Keys.userKey )
        println( j )
        val payload = new Base64( (j \ "payload").as[String] ).decodeToString()
        payload shouldBe TestRegistrationRequestWithAgreement

      }

      "create Authorization req with JWS" in {
        val req = AcmeProtocol.AuthorizationRequest( identifier = AcmeProtocol.AcmeIdentifier( value = "unit-test.domain" ) )
        val jreq = Json.toJson( req ).toString()
        jreq shouldBe TestAuthorizationRequest

        val j = AcmeJson.encodeRequest(req, "<nonce>", Keys.userKey )
        println( j )
        val payload = new Base64( (j \ "payload").as[String] ).decodeToString()
        payload shouldBe TestAuthorizationRequest

      }

      "create HttpChallenge acceptance" in {
        val req = AcmeProtocol.AcceptChallengeHttp( keyAuthorization = HttpAuthToken )
        val jreq = Json.toJson( req ).toString()
        jreq shouldBe TestHttpChallengeReq
      }

    }
  }
}
