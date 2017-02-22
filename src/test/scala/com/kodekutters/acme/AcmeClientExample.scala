package com.kodekutters.acme

import scala.concurrent.{ Future, Promise }
import scala.concurrent.Await
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration.DurationInt

object AcmeClientExample {

  val keypair = AcmeJson.generateKeyPair()

  /** test env URL */
  val LetsEncryptStaging = "https://acme-staging.api.letsencrypt.org"

  val TestDomain: String = "unit-test.mydomain.example.org"

  val TestDomainIdent = AcmeProtocol.AcmeIdentifier( value = TestDomain )

  val HttpClient = new AcmeHttpClient()

  def main(args: Array[String]) {


    val acmeServer = Promise[AcmeProtocol.AcmeServer]()
    val acmeRegistration = Promise[AcmeProtocol.SimpleRegistrationResponse]()
    val acmeAgreement = Promise[AcmeProtocol.RegistrationResponse]()
    val acmeChallenge = Promise[AcmeProtocol.AuthorizationResponse]()
    val acmeChallengeDetails = Promise[AcmeProtocol.ChallengeHttp]()

    // when successfully retrieved directory, notify that AcmeServer promise is now available
    HttpClient.getDirectory( LetsEncryptStaging ).onSuccess{ case d: AcmeProtocol.Directory =>
      acmeServer.success( new AcmeProtocol.AcmeServer( d ) )
    }

    val getServer = acmeServer.future
    val futureReg: Future[AcmeProtocol.SimpleRegistrationResponse] = getServer.flatMap{ server: AcmeProtocol.AcmeServer => {
      println("+ server received" )
      val req = new AcmeProtocol.RegistrationRequest( Array( "mailto:cert-admin@example.com" ) )
      val nonce = HttpClient.getNonce()
      println("++ dir nonce: " + nonce )
      val jwsReq = AcmeJson.encodeRequest( req, nonce, keypair )
      HttpClient.registration( server.newReg, jwsReq.toString() )
    } }
    // after we retrieved registration, we notify that registration response is available
    futureReg.onSuccess{ case response: AcmeProtocol.SimpleRegistrationResponse =>
      acmeRegistration.success( response ) }


    val getNewReg = acmeRegistration.future
    val futureAgree: Future[AcmeProtocol.RegistrationResponse] = getNewReg.flatMap{ reg: AcmeProtocol.SimpleRegistrationResponse => {

      val req = new AcmeProtocol.RegistrationRequest( resource = AcmeProtocol.reg, agreement = Some( reg.agreement ) )
      val nonce = HttpClient.getNonce()
      println("++ new-reg nonce: " + nonce )
      val jwsReq = AcmeJson.encodeRequest( req, nonce, keypair )
      HttpClient.agreement( reg.uri, jwsReq.toString() )

    } }
    // after we retrieved agreement, notify that final registration response is available
    futureAgree.onSuccess{ case response: AcmeProtocol.RegistrationResponse =>
      acmeAgreement.success( response ) }

    val getAgreedReg = acmeAgreement.future
    val futureAuth: Future[AcmeProtocol.AuthorizationResponse] = getAgreedReg.flatMap{ reg: AcmeProtocol.RegistrationResponse => {

      println("+ start ToS agreement" )
      val nonce = HttpClient.getNonce()
      println("++ reg-agree nonce: " + nonce )

      val req = new AcmeProtocol.AuthorizationRequest( identifier = TestDomainIdent )
      val jwsReq = AcmeJson.encodeRequest( req, nonce, keypair )

      val server = getServer.value.get.get

      HttpClient.authorize( server.newAuthz, jwsReq.toString() )
    } }
    // after authorization is done
    futureAuth.onSuccess{ case response: AcmeProtocol.AuthorizationResponse =>
      acmeChallenge.success( response ) }

    val getChallenges = acmeChallenge.future
    val futureChallenge: Future[AcmeProtocol.ChallengeHttp] = getChallenges.flatMap{ authz: AcmeProtocol.AuthorizationResponse => {

      println("+ start accept http-01 challenge" )
      val httpChallenge = AcmeJson.findHttpChallenge( authz.challenges ).get

      val nonce = HttpClient.getNonce()
      println("++ authz nonce: " + nonce )

      val req = AcmeProtocol.AcceptChallengeHttp( keyAuthorization = AcmeJson.withThumbprint( httpChallenge.token, keypair ) )
      val jwsReq = AcmeJson.encodeRequest( req, nonce, keypair )

      val server = getServer.value.get.get

      HttpClient.challenge( httpChallenge.getUri, jwsReq.toString() )
    } }
    // after challenge is accepted
    futureChallenge.onSuccess{ case response: AcmeProtocol.ChallengeHttp =>
      acmeChallengeDetails.success( response ) }


    println("+awaiting CHAL end" )
    Await.result( futureChallenge, new DurationInt(40).seconds )

    sleep( 3000L )
    println("+revisit details" )

    val getChallengeDetails = acmeChallengeDetails.future
    val failedChallenge: Future[AcmeProtocol.ChallengeType] = getChallengeDetails.flatMap{ challenge: AcmeProtocol.ChallengeHttp => {

      HttpClient.challengeDetails( challenge.getUri() )
    } }
    failedChallenge.onSuccess{ case response: AcmeProtocol.ChallengeType =>
      println( s"Details parsed: $response" ) }

    Await.result( failedChallenge, new DurationInt(10).seconds )
    println("+ending" )
    HttpClient.shutdown()

  }

  private def sleep(duration: Long) { Thread.sleep(duration) }

}
