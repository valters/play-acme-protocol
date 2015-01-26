package com.kodekutters.acme

import java.net.URL
import com.kodekutters.acme.AcmeProtocol.{AcmeSignature, AuthorizationRequest}
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
        "contact":[ {"name":"some-name","uri":"some-uri","email":"some-email","tel":"some-telephone"} ]
        }""".stripMargin)

    // the scala AuthorizationRequest from the json
    val theRequest = Json.fromJson[AuthorizationRequest](jsVal).asOpt
    println("theRequest: " + theRequest)

    // validate the json message and turn it into a scala AuthorizationRequest
    jsVal.validate[AuthorizationRequest] match {
      case s: JsSuccess[AuthorizationRequest] => println("\nvalidated AuthorizationRequest: " + s.get)
      case e: JsError => println("\n Error: " + JsError.toFlatJson(e).toString())
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

  }

}