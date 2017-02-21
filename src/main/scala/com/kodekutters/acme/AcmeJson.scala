package com.kodekutters.acme

import java.security.{ KeyPair, KeyPairGenerator }
import java.security.interfaces.{ RSAPrivateKey, RSAPublicKey }

import com.nimbusds.jose.{ JWSAlgorithm, JWSHeader, JWSObject, JWSSigner, Payload }
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.{ JWK, RSAKey }
import com.nimbusds.jose.util.Base64URL

import play.api.libs.json.{ Format, JsError, JsPath, JsResult, JsString, JsSuccess, JsValue, Json }
import play.api.libs.json.{ Reads, Writes }
import play.api.libs.json.Json.JsValueWrapper

/**
 * Implicit JSON converters
 */
object AcmeImplicits {
  implicit def StringMapToResourceTypeMap(value: Map[String, String]): Map[AcmeProtocol.ResourceType, String] = {
    val resMap = scala.collection.mutable.Map[AcmeProtocol.ResourceType, String]()
    value.foreach {
      case (k, v) => resMap += AcmeProtocol.ResourceType.fromString(k) -> v.asInstanceOf[String]
    }
    resMap.toMap
  }

  val dirReads = new Reads[AcmeProtocol.Directory] {
    def reads(json: JsValue): JsResult[AcmeProtocol.Directory] = {
      JsPath.read[Map[String, String]].reads(json).asOpt match {
        case Some(dir) => JsSuccess(new AcmeProtocol.Directory(dir))
        case None => JsSuccess(new AcmeProtocol.Directory(Map[AcmeProtocol.ResourceType, String]()))  // todo log an error?
      }
    }
  }

  val dirWrites = new Writes[AcmeProtocol.Directory] {
    def writes(dir: AcmeProtocol.Directory) = {
      Json.obj(dir.directory.map { case (k, v) =>
        val entry: (String, JsValueWrapper) = k.toString -> JsString(v.asInstanceOf[String])
        entry
      }.toSeq: _*)
    }
  }

  implicit val fmtDir: Format[AcmeProtocol.Directory] = Format(dirReads, dirWrites)

  // implicits for reading and writing json JWK objects ..... used in Authorization and Hints
  implicit val jwkWrites = new Writes[JWK] {
    def writes(jwk: JWK) = Json.toJson(jwk.toJSONString)
  }
  implicit val jwkReads: Reads[JWK] = JsPath.read[String].map(JWK.parse(_))

  implicit val fmtAcmeSignature = Json.format[AcmeProtocol.AcmeSignature]

  implicit val fmtRecoveryKeyClient = Json.format[AcmeProtocol.RecoveryKeyClient]
  implicit val fmtRecoveryKeyServer = Json.format[AcmeProtocol.RecoveryKeyServer]

  implicit val fmtRegistrationReq = Json.format[AcmeProtocol.RegistrationRequest]
  implicit val fmtRegistationResp = Json.format[AcmeProtocol.RegistrationResponse]

  val crtReads = new Reads[AcmeProtocol.ChallengeResponseType] {
    def reads(json: JsValue) = {
      (json \ "type").asOpt[String] match {
        case Some(msgType) =>
          msgType match {
            case AcmeProtocol.simpleHttps => Json.format[AcmeProtocol.SimpleHTTPSResponse].reads(json)
            case AcmeProtocol.dvsni => Json.format[AcmeProtocol.DVSNIResponse].reads(json)
            case AcmeProtocol.dns => Json.format[AcmeProtocol.DNSResponse].reads(json)
            case AcmeProtocol.proofOfPossession => Json.format[AcmeProtocol.ProofOfPossessionResponse].reads(json)
            case _ => JsError("could not read jsValue: " + json + " into a ResponseType")
          }
        case None => JsError("could not read jsValue: " + json + " into a ResponseType")
      }
    }
  }

  val crtWrites = Writes[AcmeProtocol.ChallengeResponseType] {
    case x: AcmeProtocol.SimpleHTTPSResponse => Json.format[AcmeProtocol.SimpleHTTPSResponse].writes(x)
    case x: AcmeProtocol.DVSNIResponse => Json.format[AcmeProtocol.DVSNIResponse].writes(x)
    case x: AcmeProtocol.DNSResponse => Json.format[AcmeProtocol.DNSResponse].writes(x)
    case x: AcmeProtocol.ProofOfPossessionResponse => Json.format[AcmeProtocol.ProofOfPossessionResponse].writes(x)
  }

  implicit val fmtChallengeResponseType: Format[AcmeProtocol.ChallengeResponseType] = Format(crtReads, crtWrites)

}

/**
 * Implements JSON reads and writes for AcmeProtocol.
 */
object AcmeJson {
  import AcmeImplicits._

  val NonceKey = "nonce"

  val RSA = "RSA"
  val RsaKeySize = 2048 //4096
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

  def toJson( reg: AcmeProtocol.RegistrationRequest ): JsValue = {
    Json.toJson(reg)
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

  /** Wrap the paylad object into JWS envelope {@code ->} header + signature */
  def encodeRequest( req: AcmeProtocol.RegistrationRequest, nonce: String, keypair: RSAKey ): JsValue = {
    val payload = Json.toJson( req ).toString()
    toJson( sign( payload, nonce, keypair ) )
  }

  def encodeRequest( req: AcmeProtocol.AuthorizationRequest, nonce: String, keypair: RSAKey ): JsValue = {
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

  def parseAuthorization(body: String) = {
    AcmeProtocol.AuthorizationResponse(AcmeProtocol.AcmeIdentifier())
  }

}

