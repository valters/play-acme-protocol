package com.kodekutters.acme

import java.net.URL
import com.kodekutters.Util._
import com.kodekutters.acme.AcmeProtocol._
import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.jwk.{KeyUse, RSAKey}
import com.nimbusds.jose.util.Base64URL
import play.api.libs.json.{JsError, JsSuccess, Json}

/**
 * just a basic example
 */

object Example1 {

  def main(args: Array[String]) {

    // json representation of an Authorization Request
    val jsVal = Json.parse(
      """{"type":"authorizationRequest","sessionID":"aefoGaavieG9Wihuk2aufai3aeZ5EeW4","nonce":"czpsrF0KMH6dgajig3TGHw","signature":{"alg":"ES256","sig":"lxj0Ucdo4r5s1c1cuY2R7oKqWi4QuNJzdwe5/4m9zWQ","nonce":"Aenb3DvfvOPImdXdnxHMlp7Jh4qsgYeTEM-dFgFOGxU","jwk":"{\"kty\":\"RSA\",\"e\":\"e\",\"use\":\"sig\",\"x5t\":\"something here\",\"kid\":\"kid\",\"x5u\":\"https:\\/\\/www.example.com\",\"alg\":\"ES256\",\"n\":\"n\"}"},
         "responses":[ {"type": "simpleHttps","path": "Hf5GrX4Q7EBax9hc2jJnfw"},{"type": "recoveryToken","token": "23029d88d9e123e"} ],
        "contact":[ ]
        }""".stripMargin)

    // the scala AuthorizationRequest from the json
    val theRequest = Json.fromJson[AuthorizationRequest](jsVal).asOpt
    println("theRequest: " + theRequest)

    // validate the json message and turn it into a scala AuthorizationRequest
    jsVal.validate[AuthorizationRequest] match {
      case request: JsSuccess[AuthorizationRequest] => println("\nvalidated AuthorizationRequest: " + request.get)
      case e: JsError => println("\nError: " + JsError.toFlatJson(e).toString())
    }

    // ..... starting with scala objects

    // a JWK object, a RSAKey
    val rsakey = new RSAKey(new Base64URL("n"), new Base64URL("e"), KeyUse.SIGNATURE,
      null, new Algorithm("ES256"), "kid", new URL("https://www.example.com"),
      new Base64URL("something here"), null)

    // a AcmeSignature
    val sig = new AcmeSignature(nonce = "Aenb3DvfvOPImdXdnxHMlp7Jh4qsgYeTEM-dFgFOGxU",
      alg = "ES256", jwk = rsakey, sig = "lxj0Ucdo4r5s1c1cuY2R7oKqWi4QuNJzdwe5/4m9zWQ")

    // the AuthorizationRequest
    val authReq = new AuthorizationRequest(
      sessionID = "aefoGaavieG9Wihuk2aufai3aeZ5EeW4",
      nonce = "czpsrF0KMH6dgajig3TGHw",
      signature = sig,
      responses = List.empty,
      contact = None)

    println("\nauthReq: " + authReq)

    // convert the scala AuthorizationRequest into a json message
    println("\njson authReq: " + Json.toJson(authReq))


    // some challenges
    val simpleHTTPS = new ChallengeSimpleHTTPS(token = newToken)
    val dns = new ChallengeDNS(token = newToken)
    val recoveryToken = new RecoveryToken()
    // the list of challenges
    val challengeList = List(simpleHTTPS, dns, recoveryToken)

    // the challenges combinations
    val combins = Array.ofDim[Int](2, 2)
    combins(0)(0) = 0
    combins(0)(1) = 2
    combins(1)(0) = 1
    combins(1)(1) = 2

    // create a challenge response
    val theChallenge = new Challenge(sessionID = newNonce, nonce = newNonce, challenges = challengeList, combinations = Some(combins))

    println("\ntheChallenge: " + theChallenge)

    println("\ntheChallenge json: " + Json.toJson(theChallenge))


    // a response
    val jsRecov = Json.parse( """{"type": "recoveryToken", "token": "a-token"}""")
    val recovRequest = Json.fromJson[ResponseType](jsRecov).asOpt
    println("\nrecovRequest: " + recovRequest)
    jsRecov.validate[ResponseType] match {
      case s: JsSuccess[ResponseType] => println("\nvalidated ResponseType: " + s.get + "\n")
      case e: JsError => println("\nError: " + JsError.toFlatJson(e).toString())
    }

  }

}