package com.kodekutters.acme

import com.nimbusds.jose.jwk.JWK
import play.api.libs.json._

import scala.reflect.ClassTag

/**
 * ACME protocol objects and messages package
 *
 * Reference, the Let's Encrypt project at: https://letsencrypt.org/
 *
 * For the ACME protocol specification see:
 * https://github.com/letsencrypt/acme-spec and
 * https://letsencrypt.github.io/acme-spec/
 *
 */
package object AcmeProtocol {

  //----------------------------------------------------------------------------
  //-----------------supporting elements----------------------------------------
  //----------------------------------------------------------------------------

  // implicits for reading and writing json JWK objects ..... used in Authorization and Hints
  implicit val jwkWrites = new Writes[JWK] { def writes(jwk: JWK) = Json.toJson(jwk.toJSONString) }
  implicit val jwkReads: Reads[JWK] = JsPath.read[String].map(JWK.parse(_))

  /**
   * determine if the input string is a valid acme message of any 'type'.
   * Note: the input string is trim before testing
   * @param t the input string to test
   * @return true if the input represents a valid acme type, else false
   */
  def isAcmeType(t: String): Boolean = {
    if (t == null) false
    else
      MessageTypeEnum.withNameString(t.trim).isDefined ||
        ChallengeTypeEnum.withNameString(t.trim).isDefined ||
        ResponseTypeEnum.withNameString(t.trim).isDefined ||
        RequestTypeEnum.withNameString(t.trim).isDefined
  }

  /**
   * determine if the input json message is a valid acme message based on testing its "type" field
   * @param msg the input json message to test
   * @return true if the input json message represents a valid acme message type, else false
   */
  def isValidAcmeType(msg: JsValue) = {
    (msg \ "type").asOpt[String] match {
      case Some(t) => isAcmeType(t)
      case None => false
    }
  }

  /**
   * An AcmeIdentifier encodes an identifier that can
   * be validated by ACME. The protocol allows for different
   * types of identifier to be supported (DNS names, IP
   * addresses, etc.), but currently only supports domain names.
   * @param type The identifier type, default dns
   * @param value The identifier itself, default "dns"
   */
  final case class AcmeIdentifier(`type`: String = "dns", value: String = "dns") {
    // consider only "dns" for now  todo
    def identifierValid = "dns".equalsIgnoreCase(`type`) && "dns".equalsIgnoreCase(value)
  }

  object AcmeIdentifier {
    implicit val fmt = Json.format[AcmeIdentifier]
  }

  /**
   * A JSON object that contains various clues for the client about what the requested key is, such that the client can find it.
   *
   * @param jwk A JSON Web Key object describing the public key whose corresponding private key should be used to generate the signature
   * @param certFingerprints An array of certificate fingerprints, hex-encoded SHA1 hashes of DER-encoded certificates that are known to contain this key
   * @param certs An array of certificates, in PEM encoding, that contain acceptable public keys
   * @param subjectKeyIdentifiers An array of hex-encoded Subject Key Identifiers (SKIDs) from certificate(s) that contain the key.
   * @param serialNumbers An array of serial numbers of certificates that are known to contain the requested key
   * @param issuers An array of X.509 Distinguished Names {{RFC5280}} of CAs that have been observed to issue certificates for this key
   * @param authorizedFor An array of domain names, if any, for which this server regards the key as an ACME Authorized key
   */
  final case class Hints(jwk: JWK, certFingerprints: Option[Array[String]] = None, certs: Option[Array[String]] = None,
                         subjectKeyIdentifiers: Option[Array[String]] = None, serialNumbers: Option[Array[Long]] = None,
                         issuers: Option[Array[String]] = None, authorizedFor: Option[Array[String]] = None)

  object Hints {
    implicit val fmt = Json.format[Hints]
  }

  /**
   * a contact  .... todo ... not specified in acme yet
   * @param name
   * @param uri
   * @param email
   * @param tel
   */
  final case class Contact(name: Option[String] = None, uri: Option[String] = None, email: Option[String] = None, tel: Option[String] = None)

  object Contact {
    implicit val fmt = Json.format[Contact]
  }

  /**
   * ACME simple JSON-based structure for encoding signature.
   *
   * @param alg A token indicating the cryptographic algorithm used to compute the signature {{I-D.ietf-jose-json-web-algorithms}}.
   *            (MAC algorithms such as "HS*" MUST NOT be used.)
   * @param sig The signature, base64-encoded.
   * @param nonce A signer-provided random nonce of at least 16 bytes, base64-encoded. (For anti-replay)
   * @param jwk A JSON Web Key object describing the key used to verify the signature {{I-D.ietf-jose-json-web-key}}.
   */
  case class AcmeSignature(alg: String, sig: String, nonce: String, jwk: JWK)

  object AcmeSignature {
    implicit val fmt = Json.format[AcmeSignature]
  }

  //----------------------------------------------------------------------------
  //-----------------Message Type-----------------------------------------------
  //----------------------------------------------------------------------------

  /**
   * enumeration of acme general message types: error, defer, statusRequest
   */
  object MessageTypeEnum extends Enumeration {
    type MessageTypeEnum = Value
    val error, defer, statusRequest = Value

    implicit def messageTypeEnumToString(value: MessageTypeEnum.Value): String = value.toString

    /**
     * safely returns the enumeration value as an option given a string representation of the enumeration name
     * @param s the input string representing the enumeration type
     * @return the enumeration value or None
     */
    def withNameString(s: String): Option[MessageTypeEnum] = {
      try {
        Option(MessageTypeEnum.withName(s))
      } catch {
        case e: NoSuchElementException => None
      }
    }
  }

  /**
   * an acme message type
   */
  sealed trait MessageType

  object MessageType {
    implicit val fmt1 = Json.format[AcmeErrorMessage]
    implicit val fmt2 = Json.format[AcmeDefer]
    implicit val fmt3 = Json.format[AcmeStatusRequest]
  }

  /**
   * an acme error message
   * @param type type of the acme message, "error"
   * @param error error description, a token from the set of error types, indicating what type of error occurred
   * @param message A human-readable string describing the error
   * @param moreInfo Typically a URL of a resource containing additional human-readable documentation about the error,
   *                 such as advice on how to revise the request or adjust the client
   *                 configuration to allow the request to succeed, or documentation
   *                 of CA issuance policies that describe why the request cannot be fulfilled
   */
  final case class AcmeErrorMessage(`type`: String = MessageTypeEnum.error.toString,
                                    error: String,
                                    message: Option[String] = None,
                                    moreInfo: Option[String] = None) extends MessageType

  /**
   * an acme defer message
   * @param type type of the acme message, "defer"
   * @param token An opaque value that the client uses to check on the status of the request (using a statusRequest message)
   * @param interval The amount of time, in seconds, that the client should wait before checking on the status of the request.
   *                 (This is a recommendation only, and clients SHOULD enforce minimum and maximum deferral times.)
   * @param message A human-readable string describing the reason for the deferral
   */
  final case class AcmeDefer(`type`: String = MessageTypeEnum.defer.toString,
                             token: String,
                             interval: Option[Int] = None,
                             message: Option[String] = None) extends MessageType

  /**
   * an acme statusRequest message
   * @param type type of the acme message, "statusRequest"
   * @param token An opaque value that was provided in a defer message
   */
  final case class AcmeStatusRequest(`type`: String = MessageTypeEnum.statusRequest.toString, token: String) extends MessageType

  //----------------------------------------------------------------------------
  //-----------------Challenges-------------------------------------------------
  //----------------------------------------------------------------------------

  /**
   * enumeration of acme challenge types:
   * simpleHttps, dvsni, dns, recoveryToken, recoveryContact, proofOfPossession.
   * Note: values in ChallengeTypeEnum can also be used in responses as well as challenges
   */
  object ChallengeTypeEnum extends Enumeration {
    type ChallengeTypeEnum = Value
    val simpleHttps, dvsni, dns, recoveryToken, recoveryContact, proofOfPossession = Value

    implicit def challengeTypeEnumToString(value: ChallengeTypeEnum.Value): String = value.toString

    /**
     * safely returns the enumeration value as an option given a string representation of the enumeration name
     * @param s the input string representing the enumeration type
     * @return the enumeration value
     */
    def withNameString(s: String): Option[ChallengeTypeEnum] = {
      try {
        Option(ChallengeTypeEnum.withName(s))
      } catch {
        case e: NoSuchElementException => None
      }
    }
  }

  /**
   * a challenge type message
   */
  sealed trait ChallengeType

  object ChallengeType {

    implicit val challengeTypeWrites = new Writes[ChallengeType] {
      def writes(c: ChallengeType) = c match {
        case x: ChallengeSimpleHTTPS => Json.format[ChallengeSimpleHTTPS].writes(x)
        case x: ChallengeDVSNI => Json.format[ChallengeDVSNI].writes(x)
        case x: ChallengeDNS => Json.format[ChallengeDNS].writes(x)
        case x: RecoveryToken => Json.format[RecoveryToken].writes(x)
        case x: ChallengeProofOfPossession => Json.format[ChallengeProofOfPossession].writes(x)
        case x: ChallengeRecoveryContact => Json.format[ChallengeRecoveryContact].writes(x)
        case x => JsNull
      }
    }

    implicit val challengeTypeReads = new Reads[ChallengeType] {
      def reads(json: JsValue) = {
        (json \ "type").asOpt[String] match {
          case Some(typeName) => {
            ChallengeTypeEnum.withName(typeName) match {
              case ChallengeTypeEnum.simpleHttps => Json.format[ChallengeSimpleHTTPS].reads(json)
              case ChallengeTypeEnum.dvsni => Json.format[ChallengeDVSNI].reads(json)
              case ChallengeTypeEnum.dns => Json.format[ChallengeDNS].reads(json)
              case ChallengeTypeEnum.recoveryToken => Json.format[RecoveryToken].reads(json)
              case ChallengeTypeEnum.recoveryContact => Json.format[ChallengeProofOfPossession].reads(json)
              case ChallengeTypeEnum.proofOfPossession => Json.format[ChallengeRecoveryContact].reads(json)
            }
          }
          case None => JsError("could not read jsValue: \"" + json + "\" into a ChallengeType")
        }
      }
    }

    implicit val fmt: Format[ChallengeType] = Format(challengeTypeReads, challengeTypeWrites)

  }

  /**
   * Simple HTTPS validation challenge
   * @param type type of the challenge, "simpleHttps"
   * @param token The value to be provisioned in the file. This value MUST have at least 128 bits of entropy,
   *              in order to prevent an attacker from guessing it. It MUST NOT contain any non-ASCII characters.
   */
  final case class ChallengeSimpleHTTPS(`type`: String = ChallengeTypeEnum.simpleHttps.toString, token: String) extends ChallengeType

  /**
   * a dvsni challenge
   * @param type type of the challenge, "dvsni"
   */
  final case class ChallengeDVSNI(`type`: String = ChallengeTypeEnum.dvsni.toString) extends ChallengeType

  /**
   * a dns challenge
   * @param type type of the challenge, "dns"
   * @param token An ASCII string that is to be provisioned in the TXT record.
   *              This string SHOULD be randomly generated, with at least 128 bits of entropy
   *              (e.g., a hex-encoded random octet string).
   */
  final case class ChallengeDNS(`type`: String = ChallengeTypeEnum.dns.toString, token: String) extends ChallengeType

  /**
   * a recovery token challenge
   * @param type type of the challenge, "recoveryToken"
   */
  final case class RecoveryToken(`type`: String = ChallengeTypeEnum.recoveryToken.toString) extends ChallengeType

  /**
   * a proofOfPossession challenge
   * @param type type of the challenge, "proofOfPossession"
   * @param alg A token indicating the cryptographic algorithm that should be used by the client to
   *            compute the signature {{I-D.ietf-jose-json-web-algorithms}}.
   * @param nonce A random 16-byte octet string, base64-encoded
   * @param hints A JSON object that contains various clues for the client about what the requested key is,
   *              such that the client can find it. May include a jwk object.
   */
  final case class ChallengeProofOfPossession(`type`: String = ChallengeTypeEnum.proofOfPossession.toString,
                                              alg: String, nonce: String, hints: Hints) extends ChallengeType

  /**
   * a recovery contact challenge
   * @param type type of the challenge, "recoveryContact"
   * @param activationURL A URL the client can visit to cause a recovery message to be sent to client's contact address.
   * @param successURL A URL the client may poll to determine if the user has successfully clicked a link or completed other tasks specified by the recovery message.
   * @param contact A full or partly obfuscated version of the contact URI that the server will use to contact the client.
   */
  final case class ChallengeRecoveryContact(`type`: String = ChallengeTypeEnum.recoveryContact.toString,
                                            activationURL: Option[String] = None, successURL: Option[String] = None,
                                            contact: Option[Contact] = None) extends ChallengeType

  //----------------------------------------------------------------------------
  //-----------------Responses--------------------------------------------------
  //----------------------------------------------------------------------------

  /**
   * enumeration of acme response message types:
   * challenge, authorization, revocation, certificate
   */
  object ResponseTypeEnum extends Enumeration {
    type ResponseTypeEnum = Value
    val challenge, authorization, revocation, certificate = Value

    implicit def responseTypeEnumToString(value: ResponseTypeEnum.Value): String = value.toString

    /**
     * safely returns the enumeration value as an option given a string representation of the enumeration name
     * @param s the input string representing the enumeration type
     * @return the enumeration value
     */
    def withNameString(s: String): Option[ResponseTypeEnum] = {
      try {
        Option(ResponseTypeEnum.withName(s))
      } catch {
        case e: NoSuchElementException => None
      }
    }
  }

  /**
   * an acme response message type
   * Note: ResponseTypeEnum set as well as responses to challenges are ResponseType messages
   */
  sealed trait ResponseType

  object ResponseType {

    private def dvsniReads(js: JsValue) = {
      if ((js \ "s").asOpt[String].isDefined) Json.format[DVSNIResponceS].reads(js)
      else
      if ((js \ "r").asOpt[String].isDefined) Json.format[DVSNIResponceR].reads(js)
      else
        JsError("could not read jsValue: \"" + js + "\" into a dvsni")
    }

    implicit val responseTypeReads = new Reads[ResponseType] {
      def reads(json: JsValue) = {
        (json \ "type").as[String] match {
          case x if ChallengeTypeEnum.simpleHttps.toString == x => Json.format[SimpleHTTPSResponse].reads(json)
          case x if ChallengeTypeEnum.dvsni.toString == x => dvsniReads(json)
          case x if ChallengeTypeEnum.dns.toString == x => Json.format[ChallengeDNSResponse].reads(json)
          case x if ChallengeTypeEnum.recoveryToken.toString == x => Json.format[RecoveryTokenResponse].reads(json)
          case x if ChallengeTypeEnum.proofOfPossession.toString == x => Json.format[ChallengeProofOfPossessionResponse].reads(json)
          case x if ChallengeTypeEnum.recoveryContact.toString == x => Json.format[RecoveryContactResponse].reads(json)
          case x if ResponseTypeEnum.challenge.toString == x => Json.format[Challenge].reads(json)
          case x if ResponseTypeEnum.authorization.toString == x => Json.format[Authorization].reads(json)
          case x if ResponseTypeEnum.certificate.toString == x => Json.format[CertificateIssuance].reads(json)
          case x if ResponseTypeEnum.revocation.toString == x => Json.format[Revocation].reads(json)
          case x => JsError("could not read jsValue: \"" + json + "\" into a ResponseType")
        }
      }
    }

    implicit val responseTypeWrites = new Writes[ResponseType] {
      def writes(c: ResponseType) = c match {
        case x: SimpleHTTPSResponse => Json.format[SimpleHTTPSResponse].writes(x)
        case x: DVSNIResponceS => Json.format[DVSNIResponceS].writes(x)
        case x: DVSNIResponceR => Json.format[DVSNIResponceR].writes(x)
        case x: ChallengeDNSResponse => Json.format[ChallengeDNSResponse].writes(x)
        case x: RecoveryTokenResponse => Json.format[RecoveryTokenResponse].writes(x)
        case x: ChallengeProofOfPossessionResponse => Json.format[ChallengeProofOfPossessionResponse].writes(x)
        case x: RecoveryContactResponse => Json.format[RecoveryContactResponse].writes(x)
        case x: Challenge => Json.format[Challenge].writes(x)
        case x: Authorization => Json.format[Authorization].writes(x)
        case x: CertificateIssuance => Json.format[CertificateIssuance].writes(x)
        case x: Revocation => Json.format[Revocation].writes(x)
        case x => JsNull
      }
    }

    implicit val fmt: Format[ResponseType] = Format(responseTypeReads, responseTypeWrites)

  }

  /**
   * response by the client to the simple HTTPS challenge request
   * @param type type of the response, "simpleHttps"
   * @param path The string to be appended to the standard prefix ".well-known/acme-challenge" in order to
   *             form the path at which the nonce resource is provisioned. The result of concatenating
   *             the prefix with this value MUST match the "path" production in the standard URI format {{RFC3986}}
   */
  final case class SimpleHTTPSResponse(`type`: String = ChallengeTypeEnum.simpleHttps.toString, path: String) extends ResponseType

  /**
   * random value and nonce (server) response to a dvsni challenge request
   * @param type type of the response, "dvsni"
   * @param r A random 32-byte octet, base64-encoded
   * @param nonce A random 16-byte octet string, hex-encoded (so that it can be used as a DNS label)
   */
  final case class DVSNIResponceR(`type`: String = ChallengeTypeEnum.dvsni.toString, r: String, nonce: String) extends ResponseType

  /**
   * random value (client) response to a dvsni challenge request
   * @param type type of the response, "dvsni"
   * @param s A random 32-byte secret octet string, base64-encoded
   */
  final case class DVSNIResponceS(`type`: String = ChallengeTypeEnum.dvsni.toString, s: String) extends ResponseType

  /**
   * a response to a dns challenge
   * @param type type of the response, "dns"
   */
  final case class ChallengeDNSResponse(`type`: String = ChallengeTypeEnum.dns.toString) extends ResponseType

  /**
   * a recovery token response
   * @param type type of the challenge, "recoveryToken
   * @param token The recovery token provided by the server.
   */
  final case class RecoveryTokenResponse(`type`: String = ChallengeTypeEnum.recoveryToken.toString, token: Option[String]) extends ResponseType

  /**
   * a response to a proofOfPossession challenge
   * @param type type of the response, "proofOfPossession"
   * @param nonce A random 16-byte octet string, base64-encoded
   * @param signature The ACME signature computed over the signature-input using the server-specified algorithm
   */
  final case class ChallengeProofOfPossessionResponse(`type`: String = ChallengeTypeEnum.proofOfPossession.toString,
                                                      nonce: String, signature: AcmeSignature) extends ResponseType

  /**
   * a challenge response
   * @param type type of the response, "challenge"
   * @param sessionID An opaque string that allows the server to correlate transactions related to this challenge request.
   * @param nonce A base64-encoded octet string that the client is expected to sign with the private key of the key pair being authorized.
   * @param challenges A list of challenges to be fulfilled by the client in order to prove possession of the identifier.
   *                   The syntax for challenges is described in Section {{identifier-validation-challenges}}.
   * @param combinations A collection of sets of challenges, each of which would be sufficient to prove possession of the identifier.
   *                     Clients SHOULD complete a set of challenges that that covers at least one set in this array.
   *                     Challenges are represented by their associated zero-based index in the challenges array.
   */
  final case class Challenge(`type`: String = ResponseTypeEnum.challenge.toString,
                             sessionID: String, nonce: String, challenges: List[ChallengeType] = List.empty,
                             combinations: Option[Array[Array[Int]]]) extends ResponseType

  /**
   * a recovery contact response
   * @param type type of the response, "recoveryContact"
   * @param token If the user transferred a token from a contact email or call into the client software, the client sends it here.
   */
  final case class RecoveryContactResponse(`type`: String = ChallengeTypeEnum.recoveryContact.toString, token: Option[String] = None) extends ResponseType

  /**
   * an authorization response message
   * @param type type of the response, "authorization"
   * @param recoveryToken   An arbitrary server-generated string. If the server provides a recovery token, it MUST
   *                      generate a unique value for every authorization transaction, and this value MUST NOT
   *                      be predictable or guessable by a third party.
   * @param identifier The identifier for which authorization has been granted.
   * @param jwk A JSON Web Key object describing the authorized public key.
   */
  final case class Authorization(`type`: String = ResponseTypeEnum.authorization.toString,
                                 recoveryToken: Option[String] = None, identifier: Option[String] = None, jwk: Option[JWK] = None) extends ResponseType

  /**
   * a certificate issuance response message
   * @param type type of the response, "certificate"
   * @param certificate The issued certificate, as a base64-encoded DER certificate.
   * @param chain A chain of CA certificates (AcmeCertificate) which are parents of the issued certificate.
   *              Each certificate is in base64-encoded DER form (not PEM, as for CSRs above).
   *              This array MUST be presented in the same order as would be required in
   *              a TLS handshake {{RFC5246}}.
   * @param refresh An HTTP or HTTPS URI from which updated versions of this certificate can be fetched.
   */
  final case class CertificateIssuance(`type`: String = ResponseTypeEnum.certificate.toString,
                                       certificate: String, chain: Option[List[String]] = None,
                                       refresh: Option[String] = None) extends ResponseType

  /**
   * a revocation of certificate response message issued by the CA server, this represents a successful revocation
   * @param type type of the response, "revocation"
   */
  final case class Revocation(`type`: String = ResponseTypeEnum.revocation.toString) extends ResponseType

  //----------------------------------------------------------------------------
  //-----------------Requests---------------------------------------------------
  //----------------------------------------------------------------------------

  /**
   * enumeration of acme request message types:
   * challengeRequest, authorizationRequest, certificateRequest, revocationRequest
   */
  object RequestTypeEnum extends Enumeration {
    type RequestTypeEnum = Value
    val challengeRequest, authorizationRequest, certificateRequest, revocationRequest = Value

    implicit def requestTypeEnumToString(value: RequestTypeEnum.Value): String = value.toString

    /**
     * safely returns the enumeration value as an option given a string representation of the enumeration name
     * @param s the input string representing the enumeration type
     * @return the enumeration value
     */
    def withNameString(s: String): Option[RequestTypeEnum] = {
      try {
        Option(RequestTypeEnum.withName(s))
      } catch {
        case e: NoSuchElementException => None
      }
    }
  }

  /**
   * an acme request message type
   */
  sealed trait RequestType

  object RequestType {
    implicit val fmt1 = Json.format[ChallengeRequest]
    implicit val fmt2 = Json.format[AuthorizationRequest]
    implicit val fmt3 = Json.format[CertificateRequest]
    implicit val fmt4 = Json.format[RevocationRequest]
  }

  /**
   * a challengeRequest message
   * @param type type of the request, "challengeRequest"
   * @param identifier The identifier for which authorization is being sought.
   *                   For implementations of this specification, this identifier MUST be a domain name.
   *                   (If other types of identifier are supported, then an extension to this protocol
   *                   will need to add a field to distinguish types of identifier.)
   */
  final case class ChallengeRequest(`type`: String = RequestTypeEnum.challengeRequest.toString, identifier: String) extends RequestType

  /**
   * A certificate signed request (CSR)
   *
   * @param type type of the request, "certificateRequest"
   * @param csr A CSR encoding the parameters for the certificate being requested.
   *            The CSR is sent in base64-encoded version the DER format.
   *            (Note: This field uses the same modified base64-encoding rules used elsewhere in this document, so it is different from PEM.)
   * @param signature A signature object reflecting a signature by an authorized key pair over the CSR.
   *
   */
  final case class CertificateRequest(`type`: String = RequestTypeEnum.certificateRequest.toString,
                                      csr: String, signature: AcmeSignature) extends RequestType

  /**
   * request that a signed certificate be revoked
   * @param type type of the request, "revocationRequest"
   * @param certificate The certificate to be revoked.
   * @param signature A signature object reflecting a signature by an authorized key pair over the certificate.
   */
  final case class RevocationRequest(`type`: String = RequestTypeEnum.revocationRequest.toString,
                                     certificate: String, signature: AcmeSignature) extends RequestType

  /**
   * an authorization request
   * @param type type of the request, "authorizationRequest"
   * @param sessionID The session ID provided by the server in the challenge message (to allow the server to correlate the two transactions).
   * @param nonce The nonce provided by the server in the challenge message.
   * @param signature A signature object reflecting a signature over the identifier being authorized and the nonce provided by the server.
   * @param responses The client's responses to the server's challenges, in the same order as the challenges.
   *                  If the client chooses not to respond to a given challenge, then the corresponding entry
   *                  in the response array is set to null. Otherwise, it is set to a value defined by the challenge type.
   * @param contact An array of URIs that the server can use to contact the client for issues related to this authorization.
   */
  final case class AuthorizationRequest(`type`: String = RequestTypeEnum.authorizationRequest.toString,
                                        sessionID: String,
                                        nonce: String,
                                        signature: AcmeSignature,
                                        responses: List[ResponseType] = List.empty,
                                        contact: Option[List[Contact]] = None) extends RequestType

}
