package io.github.valters.acme

import javax.inject._
import play.api._
import play.api.mvc._
import play.api.libs.ws.WSClient
import scala.concurrent.duration.`package`.DurationInt
import scala.concurrent.Await
import scala.concurrent.Promise
import scala.concurrent.Future
import scala.concurrent.ExecutionContext.Implicits.global
import java.util.concurrent.atomic.AtomicReference
import java.security.cert.X509Certificate
import com.typesafe.scalalogging.Logger
import scala.util.Success
import scala.util.Failure
import scala.annotation.tailrec
import scala.util.Try
import akka.stream.scaladsl.Source
import scala.concurrent.ExecutionContext
import akka.stream.OverflowStrategy
import akka.stream.scaladsl.SourceQueueWithComplete

/**
 * Handles HTTP certificate provisioning and renewal
 */
@Singleton
class AcmeController @Inject() ( exec: ExecutionContext, HttpClient: AcmeHttpClient, configuration: play.api.Configuration ) extends Controller {
  private val logger = Logger[AcmeController]

  /** config key */
  val PropAcmeDomain = "acme.for-domain"
  val PropAcmeEmail = "acme.account-email"

  val Keys = new KeyStorage( KeyStorage.Defaults )

  val keyAuthHandle = new AtomicReference[String]()

  /** Acme Server URL (may be Let's Encrypt production or staging) */
  val AcmeServer: Option[String] = configuration.getString( "acme.server" )
    .orElse( Some("https://acme-v01.api.letsencrypt.org") )

  val AcmeDomain: Option[String] = configuration.getString( PropAcmeDomain )
  val AcmeAccountEmail: Option[String] = configuration.getString( PropAcmeEmail )

  /**
   * Validate configuration and proceed with retrieving Let's Encrypt HTTPS certificate.
   */
  def cert = Action {

    AcmeDomain match {
      case Some(domain) => {

        AcmeAccountEmail match {
          case Some(email) =>
            Ok.chunked( certify( domain, email ) )
          case None =>
            ServiceUnavailable( s"Can not proceed to retrieve HTTPS certificate: contact email address was not provided. Please set configuration value [$PropAcmeEmail] to your email address (to be used for ACME server account) in Play app configuration." )
        }

      }
      case None =>
        ServiceUnavailable( s"Can not proceed to retrieve HTTPS certificate: domain name was not provided. Please set configuration value [$PropAcmeDomain] to your domain name in Play app configuration." )
    }
  }

  /** ACME: Provides proper auth response to the .well-known/acme-challenge/ HTTP request which we expect the ACME server will perform */
  def challenge( token: String ) = Action {
     Option( keyAuthHandle.get() ) match {
       case None => {
         logger.warn( "Unrecognized token {}, providing diagnostic response", token )
         NotFound( s"""{ "error": 404, "token": "$token" }""" )
       }
       case Some(key) => {
         logger.warn( "ACME server came by, providing successful response to challenge {}", token )
         Ok( key )
       }
    }
  }

  private def certify( acmeDomain: String, accountEmail: String ): Source[String, SourceQueueWithComplete[String]] = {
    val ( queueSource, futureQueue ) = peekMatValue( Source.queue[String]( 50, OverflowStrategy.fail ) )
    futureQueue.map { q ⇒
      q.offer( s"Welcome to automatic HTTPS certificate provisioning.\nWill set up certificate for [$acmeDomain], setting up account for [$accountEmail]\n" )
      if( Keys.defaultPassword ) {
        q.offer( "\n*** Warning: app currently is using a default keystore password (insecure)." +
            "\nPlease start app with following settings to configure HTTPS keystore password: '-Dplay.server.https.keyStore.path=\"conf/play-app.keystore\" -Dplay.server.https.keyStore.password=\"(properly secure password)\"'\n" )
      }

      Future {
        try {
          certify( acmeDomain, accountEmail, q )
        }
        catch {
          case e: Throwable =>
            q.offer("\n\nException " + e )
            logger.error("Failure on all levels: " +e, e );
        }
      }
      .onComplete{ _ =>
        q.offer("✅") // end of transmission
        q.complete()
      }
    }

    queueSource
  }
  /** Retrieve HTTPS certificate from provider, then finally generate a .keystore file */
  private def certify( acmeDomain: String, accountEmail: String, log: SourceQueueWithComplete[String] ): Unit = {

    val acmeRegistration = Promise[AcmeProtocol.SimpleRegistrationResponse]()
    val acmeAgreement = Promise[AcmeProtocol.RegistrationResponse]()
    val acmeChallenge = Promise[AcmeProtocol.AuthorizationResponse]()
    val acmeChallengeDetails = Promise[AcmeProtocol.ChallengeHttp]()
    val afterChallengeDetails = Promise[AcmeProtocol.ChallengeHttp]()
    val certificate = Promise[X509Certificate]()

    // when successfully retrieved directory, notify that AcmeServer promise is now available
    val directory = AcmeServer.get + AcmeProtocol.DirectoryFragment
    log.offer( s"\nGET $directory ... (waiting)\n" )
    HttpClient.getDirectory( directory ).onComplete {
        case Success( d: AcmeProtocol.Directory ) =>
          val server = new AcmeProtocol.AcmeServer( directory, d )
          HttpClient.acmeServer.success( server )
          log.offer( s"\n+ acme server initialized: $server.dir +"  )
        case Failure(e) =>
          logger.error( "Failed GET: "+e, e )
          log.offer( "\nFailed to contact ACME server: " + e  )
    }

    getInitialAccount( acmeRegistration, accountEmail, log )

    agree( acmeRegistration.future, acmeAgreement, log )

    getAuthorizedAccount( acmeAgreement.future, acmeChallenge, log )

    startChallenge( acmeChallenge.future, acmeChallengeDetails, log )

    finishChallenge( acmeChallengeDetails.future, afterChallengeDetails, log )

    afterChallengeDetails.future.onComplete {
      case Success(challengeDetails) =>
        issueCertificate( certificate, challengeDetails, acmeDomain, log )

      case Failure(e) =>
        logger.error( "Failed challenge: " + e, e )
        certificate.failure( e )
    }

    try {
      log.offer( "\nwaiting." )
      Await.result( afterChallengeDetails.future, new DurationInt(120).seconds )
      log.offer( "." )
      Await.result( certificate.future, new DurationInt(120).seconds )
      log.offer( "." )

      certificate.future.value match {
        case Some( Success( _ ) ) ⇒
          val keystoreLocation = Keys.location
          log.offer( "\n\nSuccess! We have saved the certificate to \""+keystoreLocation+"\"." )
          log.offer( "\n\nPlease restart app with following settings to run with HTTPS: '-Dplay.server.https.keyStore.path=\""+keystoreLocation+"\" -Dplay.server.https.keyStore.password=(your password)'\n" )
        case x ⇒
          log.offer( "\n\n*** "+x )
          log.offer( "\n" )
      }

    }
    catch {
      case e: Throwable =>
        log.offer( "\n\n*** " + e )
        log.offer( "\n***\nSorry, unable to produce HTTPS certificate. Please correct the issues outlined above and try again.\n***\n" )
        logger.error("Failure while waiting: " +e, e );
    }

    log.offer("✅") // end of transmission
  }

  /** register (or retrieve existing) ACME server account */
  private def getInitialAccount( registration: Promise[AcmeProtocol.SimpleRegistrationResponse], accountEmail: String, log: SourceQueueWithComplete[String] ): Unit = {

    val futureReg: Future[AcmeProtocol.SimpleRegistrationResponse] = HttpClient.acmeServer.future.flatMap{ server: AcmeProtocol.AcmeServer => {
      log.offer( "\n+ server directory details received" )
      val req = new AcmeProtocol.RegistrationRequest( Array( s"mailto:$accountEmail" ) )
      val nonce = HttpClient.getNonce()
      logger.debug("++ dir nonce: {}", nonce )
      val jwsReq = AcmeJson.encodeRequest( req, nonce, Keys.userKey )
      log.offer( "\n+ requesting account..." )
      HttpClient.registration( server.newReg, jwsReq.toString() )
    } }
    // after we retrieved registration, we notify that registration response is available
    futureReg.onSuccess{ case response: AcmeProtocol.SimpleRegistrationResponse =>
      logger.debug("resp: {}", response)
      registration.success( response ) }
  }

  /** check if reg.agreement Terms of Service URL is provided: we need to indicate we accept it. or otherwise proceed directly to next step */
  private def agree( newReg: Future[AcmeProtocol.SimpleRegistrationResponse], agreement: Promise[AcmeProtocol.RegistrationResponse], log: SourceQueueWithComplete[String] ): Unit = {

    val futureAgree: Future[AcmeProtocol.RegistrationResponse] = newReg.flatMap {
      reg: AcmeProtocol.SimpleRegistrationResponse => {
        reg.agreement match {
          case None =>
            log.offer( "\n+ registration: existing account located" )
            Future.successful( AcmeProtocol.RegistrationResponse() ) // no registration needed
          case agreement =>
              log.offer( "\n+ registration: indicate agreement with Terms of Service: " + agreement )
              val req = new AcmeProtocol.RegistrationRequest( resource = AcmeProtocol.reg, agreement = agreement )
              val nonce = HttpClient.getNonce()
              logger.debug("++ new-reg nonce: {}", nonce )
              val jwsReq = AcmeJson.encodeRequest( req, nonce, Keys.userKey )
              HttpClient.agreement( reg.uri, jwsReq.toString() )
        }
      }
    }

    // after we retrieved agreement, notify that final registration response is available
    futureAgree.onSuccess{ case response: AcmeProtocol.RegistrationResponse =>
      agreement.success( response ) }
  }

  private def getAuthorizedAccount( getAgreedReg: Future[AcmeProtocol.RegistrationResponse], challenge: Promise[AcmeProtocol.AuthorizationResponse], log: SourceQueueWithComplete[String] ): Unit = {

    val domainIdent = AcmeProtocol.AcmeIdentifier( value = AcmeDomain.get )

    val futureAuth: Future[AcmeProtocol.AuthorizationResponse] = getAgreedReg.flatMap{ _ => {

      log.offer( "\n+ requesting to authorize the account" )
      val nonce = HttpClient.getNonce()
      logger.debug("++ reg-agree nonce: {}", nonce )

      val req = new AcmeProtocol.AuthorizationRequest( identifier = domainIdent )
      val jwsReq = AcmeJson.encodeRequest( req, nonce, Keys.userKey )

      HttpClient.acmeServer.future.value.map {
        case Success(server) => HttpClient.authorize( server.newAuthz, jwsReq.toString() )
        case Failure(e) =>
          log.offer( "\nserver did not show up: " + e )
          logger.error( "Server did not show up: {}", e,e )
          Future.failed(e)
      }
      .get
    } }
    // after authorization is done
    futureAuth.onSuccess{ case response: AcmeProtocol.AuthorizationResponse =>
      challenge.success( response ) }
  }

  def startChallenge( getChallenges: Future[AcmeProtocol.AuthorizationResponse], challengeDetails: Promise[AcmeProtocol.ChallengeHttp], log: SourceQueueWithComplete[String] ): Unit = {

    val futureChallenge: Future[AcmeProtocol.ChallengeHttp] = getChallenges.flatMap{ authz: AcmeProtocol.AuthorizationResponse => {

      log.offer( "\n+ starting http-01 challenge" )
      val httpChallenge = AcmeJson.findHttpChallenge( authz.challenges ).get
      log.offer( "\n  + with " + httpChallenge )

      val nonce = HttpClient.getNonce()
      logger.debug("++ authz nonce: {}", nonce )

      val keyAuth = AcmeJson.withThumbprint( httpChallenge.token, Keys.userKey )
      keyAuthHandle.set( keyAuth ) // shared resource
      val req = AcmeProtocol.AcceptChallengeHttp( keyAuthorization = keyAuth )
      val jwsReq = AcmeJson.encodeRequest( req, nonce, Keys.userKey )

      HttpClient.acmeServer.future.value.map {
        case Success(server) => HttpClient.challenge( httpChallenge.uri, jwsReq.toString() )
        case Failure(e) =>
          log.offer( "\nserver did not show up: " + e )
          logger.error( "Server did not show up: {}", e, e )
          Future.failed(e)
      }
      .get

    } }
    // after challenge is accepted
    futureChallenge.onSuccess{ case response: AcmeProtocol.ChallengeHttp =>
      challengeDetails.success( response ) }
  }

  def finishChallenge( getChallengeDetails: Future[AcmeProtocol.ChallengeHttp], afterChallengeDetails: Promise[AcmeProtocol.ChallengeHttp], log: SourceQueueWithComplete[String] ): Unit = {

    log.offer( "\nawaiting challenge phase" )
    Await.result( getChallengeDetails, new DurationInt(200).seconds )

    afterChallengeDetails.complete( finishChallenge( getChallengeDetails, log, 0 ) )

    log.offer( "\nchallenge phase ended" )
  }

  @tailrec
  private def finishChallenge( getChallengeDetails: Future[AcmeProtocol.ChallengeHttp], log: SourceQueueWithComplete[String], retry: Int ): Try[AcmeProtocol.ChallengeHttp] = {
    val afterChallenge: Future[AcmeProtocol.ChallengeType] = getChallengeDetails.flatMap{ challenge: AcmeProtocol.ChallengeHttp => {

      HttpClient.challengeDetails( challenge.uri )
    } }

    Await.result( afterChallenge, new DurationInt(2).seconds )

    afterChallenge.value match {

      case Some(Success(response: AcmeProtocol.ChallengeHttp)) if response.status == Some(AcmeProtocol.valid) =>
         // ACME server agrees the challenge is fulfilled
        Success(response)

      case Some(Success(response: AcmeProtocol.ChallengeHttp)) if response.status == Some(AcmeProtocol.invalid) =>
         // ACME server denies us
        log.offer( "\n... denied. response = " + response )
        Failure( new RuntimeException( "Server says challenge is invalid: " + response.error + ", full response: " + response ) )

      case Some(Success(response: AcmeProtocol.ChallengeHttp)) if response.status == Some(AcmeProtocol.pending) =>
          if( retry > 30 ) {
            Failure( new RuntimeException("retry count exceeded") )
          }
          else {
            log.offer( "\n... sleeping 1s (status= " + response + ")" )
            Thread.sleep( 1000L )
            finishChallenge( getChallengeDetails, log, retry + 1 )
          }

      case other => {
          log.offer( "\n... error response = " + other )
          Failure( new RuntimeException("Error, unexpected state encountered: " + other ) )
      }
    }
  }

  def issueCertificate( certificate: Promise[X509Certificate], challenge: AcmeProtocol.ChallengeHttp, acmeDomain: String, log: SourceQueueWithComplete[String] ): Unit = {

    log.offer( s"\n+ requesting certificate for $acmeDomain" )

    val issueCertificate: Future[X509Certificate] = {

      val server = HttpClient.acmeServer.future.value.get.get

      val nonce = HttpClient.getNonce()
      logger.debug("++ challenge nonce: {}", nonce )

      val csr = Keys.generateCertificateSigningRequest( acmeDomain )
      val req = AcmeProtocol.CertificateRequest( csr = KeyStorageUtil.asBase64( csr ) )
      val jwsReq = AcmeJson.encodeRequest( req, nonce, Keys.userKey )

      HttpClient.issue( server.newCert, jwsReq.toString() )
    }
    issueCertificate.onSuccess{ case cert: X509Certificate =>
      log.offer( "\n+ saving certificate to key store" )
      Keys.updateKeyStore( cert )
      certificate.success( cert )
    }
  }

  /**
   * @param T source type, here String
   * @param M materialization type, here a SourceQueue[String]
   */
  def peekMatValue[T, M]( src: Source[T, M] ): ( Source[T, M], Future[M] ) = {
    val p = Promise[M]
    val s = src.mapMaterializedValue { m ⇒
      p.trySuccess( m )
      m
    }
    ( s, p.future )
  }

}
