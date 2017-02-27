package io.github.valters.acme

import java.security.{ KeyPair, KeyPairGenerator }
import java.security.interfaces.{ RSAPrivateKey, RSAPublicKey }

import com.nimbusds.jose.{ JWSAlgorithm, JWSHeader, JWSObject, JWSSigner, Payload }
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.{ JWK, RSAKey }
import com.nimbusds.jose.util.Base64URL
import com.typesafe.scalalogging.Logger

import play.api.libs.json.{ Format, JsError, JsPath, JsResult, JsString, JsSuccess, JsValue, Json }
import play.api.libs.json.{ Reads, Writes }
import play.api.libs.json.Json.JsValueWrapper

/**
 * Implicit JSON converters
 */
object AcmeJsonImplicits {
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

    val challengeTypeReads = new Reads[AcmeProtocol.ChallengeType] {
      def reads(json: JsValue) = {
        (json \ "type").asOpt[String] match {
          case None => JsError("could not read jsValue: " + json + " into a ChallengeType")
          case Some(msgType) => msgType match {
            case AcmeProtocol.simple_http => Json.format[AcmeProtocol.ChallengeHttp].reads(json)
            case AcmeProtocol.tls_sni => Json.format[AcmeProtocol.ChallengeTlsSni].reads(json)
            case AcmeProtocol.dns => Json.format[AcmeProtocol.ChallengeDns].reads(json)
            case AcmeProtocol.proofOfPossession => Json.format[AcmeProtocol.ChallengeProofOfPossession].reads(json)
            case _ => JsError("could not process jsValue: " + json + " into a ChallengeType")
          }
        }
      }
    }

    val challengeTypeWrites = Writes[AcmeProtocol.ChallengeType] {
      case x: AcmeProtocol.ChallengeHttp => Json.format[AcmeProtocol.ChallengeHttp].writes(x)
      case x: AcmeProtocol.ChallengeTlsSni => Json.format[AcmeProtocol.ChallengeTlsSni].writes(x)
      case x: AcmeProtocol.ChallengeDns => Json.format[AcmeProtocol.ChallengeDns].writes(x)
      case x: AcmeProtocol.ChallengeProofOfPossession => Json.format[AcmeProtocol.ChallengeProofOfPossession].writes(x)
    }

    implicit val fmtChallengeType: Format[AcmeProtocol.ChallengeType] = Format(challengeTypeReads, challengeTypeWrites)

  val crtReads = new Reads[AcmeProtocol.ChallengeResponseType] {
    def reads(json: JsValue) = {
      (json \ "type").asOpt[String] match {
        case Some(msgType) =>
          msgType match {
            case AcmeProtocol.simple_http => Json.format[AcmeProtocol.SimpleHTTPSResponse].reads(json)
            case AcmeProtocol.tls_sni => Json.format[AcmeProtocol.DVSNIResponse].reads(json)
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

  implicit val fmtAuthorizationResponse = Json.format[AcmeProtocol.AuthorizationResponse]

  implicit val fmtAcceptHttpChallenge = Json.format[AcmeProtocol.AcceptChallengeHttp]

}

/**
 * Implements JSON reads and writes for AcmeProtocol.
 */
object AcmeJson {
  private val logger = Logger[AcmeHttpClient]

  import AcmeJsonImplicits._

  val NonceKey = "nonce"


  def sign( payload: String, nonce: String, keypair: RSAKey ): JWSObject = {
    val signer: JWSSigner = new RSASSASigner( keypair );

    // Prepare JWS object with simple string as payload
    val jwsHeader = new JWSHeader.Builder( KeyStorageUtil.RS256 )
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

  def parseAuthorization( jsonBody: String ): AcmeProtocol.AuthorizationResponse = {
    val authz = Json.parse( jsonBody ).validate[AcmeProtocol.AuthorizationResponse]
    authz match {
      case s: JsSuccess[AcmeProtocol.AuthorizationResponse] ⇒ s.get
      case e: JsError ⇒ throw new IllegalStateException( "Unable to parse json as auth response: "+JsError.toJson( e ).toString() )
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

  def encodeRequest( req: AcmeProtocol.AcceptChallengeHttp, nonce: String, keypair: RSAKey ): JsValue = {
    val payload = Json.toJson( req ).toString()
    logger.debug("accepting challenge: {}", payload )
    toJson( sign( payload, nonce, keypair ) )
  }

  def encodeRequest( req: AcmeProtocol.CertificateRequest, nonce: String, keypair: RSAKey ): JsValue = {
    val payload = Json.toJson( req ).toString()
    logger.debug("accepting challenge: {}", payload )
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

  def parseChallenge( jsonBody: String): AcmeProtocol.ChallengeType = {
    val challenge = Json.parse( jsonBody ).validate[AcmeProtocol.ChallengeType]
    challenge match {
      case s: JsSuccess[AcmeProtocol.ChallengeType] ⇒ s.get
      case e: JsError ⇒ throw new IllegalStateException( "Unable to parse json as challenge: "+JsError.toJson( e ).toString() )
    }
  }

  /** dirty casting shortcut */
  def parseHttpChallenge( jsonBody: String): AcmeProtocol.ChallengeHttp = parseChallenge( jsonBody ).asInstanceOf[AcmeProtocol.ChallengeHttp]

  def findHttpChallenge( challenges: List[AcmeProtocol.ChallengeType] ): Option[AcmeProtocol.ChallengeHttp] = {
      challenges.find(_.`type` == AcmeProtocol.simple_http).map { challenge =>
        challenge.asInstanceOf[AcmeProtocol.ChallengeHttp]
      }
  }

  def withThumbprint(token: String, keypair: RSAKey): String = {
    token + "." + keypair.computeThumbprint()
  }

}

