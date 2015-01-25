package com.kodekutters

import java.net.URL
import com.kodekutters.acme.AcmeProtocol._
import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.jwk.{JWK, KeyUse, RSAKey}
import com.nimbusds.jose.util.Base64URL
import play.api.libs.json._


// subclasses of JWK    ECKey, OctetSequenceKey, RSAKey


object MainTest {

  def main(args: Array[String]) {
    test1
  }

  def test1 = {

    val jsVal = Json.parse( """{"alg": "algo", "sig":"a-sig", "nonce": "a-nonce", "jwk": {"kty":"RSA","e":"e","use":"sig","x5t":"something here","kid":"kid","x5u":"https://www.example.com","alg":"ES256","n":"n"} }""".stripMargin)
    //   println("jsVal: " + jsVal)

    val jwkJs = jsVal \ "jwk"
  //  println("\njwk: " + jwkJs)

    //   val theKey = RSAKey.parse(jwkJs.toString)

    //Json.fromJson[JWK](jwkJs).asOpt
    //   println("\ntheKey: " + theKey)

  //  println("JWK: " + Json.fromJson[JWK](jwkJs).asOpt)

    val rsakey = new RSAKey(new Base64URL("n"), new Base64URL("e"), KeyUse.SIGNATURE,
      null, new Algorithm("ES256"), "kid", new URL("https://www.example.com"),
      new Base64URL("x5t"), null)

    val jsObj = rsakey.toJSONObject
    println("\njsObj:  " + jsObj)

    val keyObj = RSAKey.parse(jsObj)
    println("\nkeyObj: " + keyObj)

//    val theRequest = Json.fromJson[AcmeSignature](jsVal).asOpt
//    println("\ntheRequest: " + theRequest)
//
//    jsVal.validate[AcmeSignature] match {
//      case s: JsSuccess[AcmeSignature] => println("\n validated AcmeSignature: " + s.get + "\n")
//      case e: JsError => println("\n Error: " + JsError.toFlatJson(e).toString())
//    }
  }

  def test3 = {
    val jsVal = Json.parse(
      """{"type":"authorizationRequest","sessionID":"aefoGaavieG9Wihuk2aufai3aeZ5EeW4","nonce":"czpsrF0KMH6dgajig3TGHw","signature":{"alg":"ES256","sig":"lxj0Ucdo4r5s1c1cuY2R7oKqWi4QuNJzdwe5/4m9zWQ","nonce":"Aenb3DvfvOPImdXdnxHMlp7Jh4qsgYeTEM-dFgFOGxU","jwk":"{\"kty\":\"RSA\",\"e\":\"e\",\"use\":\"sig\",\"x5t\":\"something here\",\"kid\":\"kid\",\"x5u\":\"https:\\/\\/www.example.com\",\"alg\":\"ES256\",\"n\":\"n\"}"},
         "responses":[ {"type": "simpleHttps","path": "Hf5GrX4Q7EBax9hc2jJnfw"},{"type": "recoveryToken","token": "23029d88d9e123e"} ],
        "contact":[ {"name":"some-name","uri":"uri","email":"email","tel":"telephone"} ]
        }""".stripMargin)

    val theRequest = Json.fromJson[AuthorizationRequest](jsVal).asOpt
    println("theRequest: " + theRequest)

    jsVal.validate[AuthorizationRequest] match {
      case s: JsSuccess[AuthorizationRequest] => println("\n validated AuthorizationRequest: " + s.get + "\n")
      case e: JsError => println("\n Error: " + JsError.toFlatJson(e).toString())
    }
  }

  def test2 = {
    val jsVal = Json.parse( """{"type": "simpleHttps", "token":"a-token"}""".stripMargin)

    println("jsVal: " + jsVal)

    val theRequest = Json.fromJson[ChallengeSimpleHTTPS](jsVal).asOpt
    println("theRequest: " + theRequest)

    jsVal.validate[ChallengeSimpleHTTPS] match {
      case s: JsSuccess[ChallengeSimpleHTTPS] => println("\n validated ChallengeSimpleHTTPS: " + s.get + "\n")
      case e: JsError => println("\n Error: " + JsError.toFlatJson(e).toString())
    }
  }

}


//  object AuthorizationRequest {

/**
 * convert a JsValue into the corresponding dvsni ResponseType,
 * there are 2 dvsni responses, return the appropriate one
 * param js the json value to convert
 * return Some(dvsni response) or None
 */
//    def toDvsniResponse(js: JsValue): Option[ResponseType] = {
//      try {
//        if ((js \ "s").asOpt[String].isDefined) return Json.fromJson[DVSNIResponceS](js).asOpt
//        if ((js \ "r").asOpt[String].isDefined) return Json.fromJson[DVSNIResponceR](js).asOpt
//        return None
//      }
//      catch {
//        case e: Exception =>
//          println("error in AuthorizationRequest.toDvsniResponse(js): " + e.toString)
//          None
//      }
//    }

/**
 * convert a JsValue into the corresponding ResponseType, one of the ChallengeTypeEnum
 * param js the json value to convert
 * return Some(ResponseType) or None
 */
//    def toResponse(js: JsValue): Option[ResponseType] = {
//
//      if (js == null) return None
//
//      try {
//        (js \ "type").asOpt[String] match {
//          case Some(typeName) => {
//            ChallengeTypeEnum.withName(typeName) match {
//              case ChallengeTypeEnum.simpleHttps => Json.fromJson[SimpleHTTPSResponse](js).asOpt
//              case ChallengeTypeEnum.dvsni => toDvsniResponse(js)
//              case ChallengeTypeEnum.dns => Json.fromJson[ChallengeDNSResponse](js).asOpt
//              case ChallengeTypeEnum.recoveryToken => Json.fromJson[RecoveryTokenResponse](js).asOpt
//              case ChallengeTypeEnum.recoveryContact => Json.fromJson[RecoveryContactResponse](js).asOpt
//              case ChallengeTypeEnum.proofOfPossession => Json.fromJson[ChallengeProofOfPossessionResponse](js).asOpt
//              case _ => None
//            }
//          }
//          case None => None
//        }
//      }
//      catch {
//        case e: Exception =>
//          println("error in AuthorizationRequest.toResponse(js): " + e.toString)
//          None
//      }
//    }
//  }
