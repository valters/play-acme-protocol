package com.kodekutters.acme

import java.security.{ KeyPair, KeyPairGenerator }
import java.security.interfaces.{ RSAPrivateKey, RSAPublicKey }

import com.nimbusds.jose.{ JWSAlgorithm, JWSHeader, JWSObject, JWSSigner, Payload }
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.Base64URL

import play.api.libs.json.{ JsError, JsSuccess, JsValue, Json, Writes }

/**
 * Implements JSON reads and writes for AcmeProtocol.
 */
object AcmeJson {

  val NonceKey = "nonce"

  val RSA = "RSA"
  val RsaKeySize = 512 //4096
  val RS256: JWSAlgorithm = JWSAlgorithm.RS256

  private def keyPairGenerator = {
    val kpg = KeyPairGenerator.getInstance(RSA)
    kpg.initialize(RsaKeySize)
    kpg
  }

  /** java security key pair */
  def generateKeyPair(): RSAKey = {
    val kp: KeyPair = keyPairGenerator.generateKeyPair

    val jkeypair = new RSAKey.Builder( kp.getPublic().asInstanceOf[RSAPublicKey] )
      .privateKey( kp.getPrivate().asInstanceOf[RSAPrivateKey] )
      .algorithm( RS256 )

    jkeypair.build()
  }

  def sign( payload: String, nonce: String, keypair: RSAKey ): JWSObject = {
    val signer: JWSSigner = new RSASSASigner( keypair );

    // Prepare JWS object with simple string as payload
    val jwsHeader = new JWSHeader.Builder( RS256 )
          .customParam(NonceKey, nonce)
          .jwk( keypair.toPublicJWK() )
          .build();

    val jwsPayload = new Payload( payload )
    val jwsObject: JWSObject = new JWSObject( jwsHeader, jwsPayload );

    // Compute the RSA signature
    jwsObject.sign(signer);

    jwsObject
  }

  def toJson( jwsObject: JWSObject ): JsValue = {
    val jws = JwsFlattenedJson( jwsObject.getHeader.toBase64URL(), jwsObject.getPayload.toBase64URL(), jwsObject.getSignature() )
    Json.toJson( jws )( implicitly( JwsFlattenedJson.writesJson ) )
  }

  def parseDirectory( jsonBody: String ): AcmeProtocol.Directory = {
    val directory = Json.parse( jsonBody ).validate[AcmeProtocol.Directory]
    directory match {
        case s: JsSuccess[AcmeProtocol.Directory] ⇒ s.get
        case e: JsError ⇒ throw new IllegalStateException( "Unable to parse json as directory response: "+JsError.toJson( e ).toString() )
    }
  }

  def encodeRequest( req: AcmeProtocol.RegistrationRequest, nonce: String, keypair: RSAKey ): JsValue = {
    val payload = Json.toJson( req ).toString()
    toJson( sign( payload, nonce, keypair ) )
  }

  /** see https://tools.ietf.org/html/rfc7515#appendix-A.7 */
  case class JwsFlattenedJson( protectedHeader: Base64URL, payload: Base64URL, signature: Base64URL )

  object JwsFlattenedJson {
    implicit val writesJson = new Writes[JwsFlattenedJson] {
      def writes( jws: JwsFlattenedJson ) = {
        Json.obj( "protected" -> jws.protectedHeader.toString(),
            "payload" -> jws.payload.toString(),
            "signature" -> jws.signature.toString() )
      }
    }
  }

}
