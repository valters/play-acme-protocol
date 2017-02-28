package io.github.valters.acme

import org.scalatestplus.play._

import scala.concurrent.{ Future, Promise }
import scala.concurrent.Await
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration.DurationInt

import com.typesafe.scalalogging.Logger

class AcmeClientExampleSpec extends PlaySpec with OneAppPerSuite {


  "AcmeClient" should {

    "issue certificate if all goes well" in {
      val logger = Logger[AcmeClientExampleSpec]

      val Keys = new KeyStorage(KeyStorage.Defaults)

      /** test env URL */
      val LetsEncryptStaging = "https://acme-staging.api.letsencrypt.org"
    
      val TestDomain: String = "unit-test.mydomain.example.org"
    
      val TestDomainIdent = AcmeProtocol.AcmeIdentifier( value = TestDomain )

      val HttpClient: AcmeHttpClient = app.injector.instanceOf[AcmeHttpClient]


      val acmeRegistration = Promise[AcmeProtocol.SimpleRegistrationResponse]()
      val acmeAgreement = Promise[AcmeProtocol.RegistrationResponse]()
      val acmeChallenge = Promise[AcmeProtocol.AuthorizationResponse]()
      val acmeChallengeDetails = Promise[AcmeProtocol.ChallengeHttp]()

      // when successfully retrieved directory, notify that AcmeServer promise is now available
      val directory = LetsEncryptStaging + AcmeProtocol.DirectoryFragment
      HttpClient.getDirectory( directory ).onSuccess{ case d: AcmeProtocol.Directory =>
        HttpClient.acmeServer.success( new AcmeProtocol.AcmeServer( directory, d ) )
      }
  
      val futureReg: Future[AcmeProtocol.SimpleRegistrationResponse] = HttpClient.acmeServer.future.flatMap{ server: AcmeProtocol.AcmeServer => {
        logger.info("+ server received" )
        val req = new AcmeProtocol.RegistrationRequest( Array( "mailto:cert-admin@example.com" ) )
        val nonce = HttpClient.getNonce()
        logger.info("++ dir nonce: " + nonce )
        val jwsReq = AcmeJson.encodeRequest( req, nonce, Keys.userKey )
        HttpClient.registration( server.newReg, jwsReq.toString() )
      } }
      // after we retrieved registration, we notify that registration response is available
      futureReg.onSuccess{ case response: AcmeProtocol.SimpleRegistrationResponse =>
        acmeRegistration.success( response ) }
  
  
      val getNewReg = acmeRegistration.future
      val futureAgree: Future[AcmeProtocol.RegistrationResponse] = getNewReg.flatMap{
        reg: AcmeProtocol.SimpleRegistrationResponse => {
  
          reg.agreement match {
            case None => Future.successful( AcmeProtocol.RegistrationResponse() ) // no registration needed
            case agreement =>
                logger.info("+ start ToS agree {}", agreement )
                val req = new AcmeProtocol.RegistrationRequest( resource = AcmeProtocol.reg, agreement = agreement )
                val nonce = HttpClient.getNonce()
                logger.debug("++ new-reg nonce: {}", nonce )
                val jwsReq = AcmeJson.encodeRequest( req, nonce, Keys.userKey )
                HttpClient.agreement( reg.uri, jwsReq.toString() )
          }
  
      } }
      // after we retrieved agreement, notify that final registration response is available
      futureAgree.onSuccess{ case response: AcmeProtocol.RegistrationResponse =>
        acmeAgreement.success( response ) }
  
      val getAgreedReg = acmeAgreement.future
      val futureAuth: Future[AcmeProtocol.AuthorizationResponse] = getAgreedReg.flatMap{ reg: AcmeProtocol.RegistrationResponse => {
  
        logger.info("+ start ToS agreement" )
        val nonce = HttpClient.getNonce()
        logger.info("++ reg-agree nonce: " + nonce )
  
        val req = new AcmeProtocol.AuthorizationRequest( identifier = TestDomainIdent )
        val jwsReq = AcmeJson.encodeRequest( req, nonce, Keys.userKey )
  
        val server = HttpClient.acmeServer.future.value.get.get
  
        HttpClient.authorize( server.newAuthz, jwsReq.toString() )
      } }
      // after authorization is done
      futureAuth.onSuccess{ case response: AcmeProtocol.AuthorizationResponse =>
        acmeChallenge.success( response ) }
  
      val getChallenges = acmeChallenge.future
      val futureChallenge: Future[AcmeProtocol.ChallengeHttp] = getChallenges.flatMap{ authz: AcmeProtocol.AuthorizationResponse => {
  
        logger.info("+ start accept http-01 challenge" )
        val httpChallenge = AcmeJson.findHttpChallenge( authz.challenges ).get
  
        val nonce = HttpClient.getNonce()
        logger.info("++ authz nonce: " + nonce )
  
        val req = AcmeProtocol.AcceptChallengeHttp( keyAuthorization = AcmeJson.withThumbprint( httpChallenge.token, Keys.userKey ) )
        val jwsReq = AcmeJson.encodeRequest( req, nonce, Keys.userKey )
  
        val server = HttpClient.acmeServer.future.value.get.get
  
        HttpClient.challenge( httpChallenge.uri, jwsReq.toString() )
      } }
      // after challenge is accepted
      futureChallenge.onSuccess{ case response: AcmeProtocol.ChallengeHttp =>
        acmeChallengeDetails.success( response ) }
  
  
      logger.info("+awaiting CHAL end" )
      Await.result( futureChallenge, new DurationInt(40).seconds )
  
      logger.info("+revisit details" )
  
      val getChallengeDetails = acmeChallengeDetails.future
      val failedChallenge: Future[AcmeProtocol.ChallengeType] = getChallengeDetails.flatMap{ challenge: AcmeProtocol.ChallengeHttp => {
  
        HttpClient.challengeDetails( challenge.uri )
      } }
      failedChallenge.onSuccess{ case response: AcmeProtocol.ChallengeType =>
         logger.info( s"Details parsed: $response" ) }
  
      Await.result( failedChallenge, new DurationInt(10).seconds )
      logger.info("+ending" )

    }
  }

}
