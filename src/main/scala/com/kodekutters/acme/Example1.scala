package com.kodekutters.acme

import java.net.URL
import com.kodekutters.Util._
import com.kodekutters.acme.AcmeProtocol._
import com.nimbusds.jose.{JWSAlgorithm, Algorithm}
import com.nimbusds.jose.jwk.{KeyUse, RSAKey}
import com.nimbusds.jose.util.Base64URL
import play.api.libs.json.{JsError, JsSuccess, Json}

/**
 * just a basic example
 */
object Example1 {
  import AcmeJsonImplicits._

  def main(args: Array[String]): Unit = {

    // json representation of an Authorization Request
    val jsVal = Json.parse(""" {"resource":"new_authz","identifier": {"type": "dns", "value": "example.org"}} """.stripMargin)

    // the scala AuthorizationRequest from the json
    val theRequest = Json.fromJson[AuthorizationRequest](jsVal).asOpt
    println("theRequest: " + theRequest)

    // validate the json message and turn it into a scala AuthorizationRequest
    jsVal.validate[AuthorizationRequest] match {
      case request: JsSuccess[AuthorizationRequest] => println("\nvalidated AuthorizationRequest: " + request.get)
      case e: JsError => println("\nError: " + JsError.toJson(e).toString())
    }

    // ..... starting with scala objects

    // a JWK object, a RSAKey
    val rsakey = new RSAKey(new Base64URL("abc"), new Base64URL("def"), KeyUse.SIGNATURE,
      null, JWSAlgorithm.RS256, "5678", null, null, null, null)

    // a AcmeSignature
    val sig = new AcmeSignature(nonce = newNonce,
      alg = "ES256", jwk = rsakey, sig = "lxj0Ucdo4r5s1c1cuY2R7oKqWi4QuNJzdwe5/4m9zWQ")

    // the AuthorizationRequest
    val authReq = new AuthorizationRequest(identifier = new AcmeIdentifier())

    println("\nauthReq: " + authReq)

    // convert the scala AuthorizationRequest into a json message
    println("\njson authReq: " + Json.prettyPrint(Json.toJson(authReq)))

    // the list of challenges
    val challengeList = List(new ChallengeHttp(uri = "some-uri", token = newToken), new ChallengeDns(uri = "some-uri", token = newToken))

    // the challenges combinations
    val combins = Array.ofDim[Int](2, 2)
    combins(0)(0) = 0
    combins(0)(1) = 2
    combins(1)(0) = 1
    combins(1)(1) = 2

    // create an AuthorizationResponse
    val theAuthorization = new AuthorizationResponse(identifier = new AcmeIdentifier("example.org"), challenges = challengeList, combinations = combins)

    println("\t theAuthorization: " + theAuthorization)

    println("\t theAuthorization json: " + Json.prettyPrint(Json.toJson(theAuthorization)))

    // a recoveryToken response
    val jsRecov = Json.parse( """{"type": "recoveryToken", "token": "a-token"}""")
    val recov = Json.fromJson[RecoveryTokenResponse](jsRecov).asOpt
    println("\nrecov: " + recov)
    jsRecov.validate[RecoveryTokenResponse] match {
      case s: JsSuccess[RecoveryTokenResponse] => println("\nvalidated ResponseType: " + s.get + "\n")
      case e: JsError => println("\nError: " + JsError.toFlatJson(e).toString())
    }

  }

}
