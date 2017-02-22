package com.kodekutters.acme

import scala.concurrent.{ Future, Promise }
import scala.concurrent.Await
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration.DurationInt

import org.scalatest.{ Matchers, WordSpec }

import com.kodekutters.acme.AcmeProtocol.AcmeServer
import java.net.URI

class AcmeHttpClientSpec extends WordSpec with Matchers {

  val keypair = AcmeJson.generateKeyPair()

  /** test env URL */
  val LetsEncryptStaging = "https://acme-staging.api.letsencrypt.org"

  val TestDomain: String = "unit-test.mydomain.example.org"


  "Acme Http Client" when {
    val httpClient = new AcmeHttpClient()
    val acmeServer = Promise[AcmeServer]()
    val acmeRegistration = Promise[AcmeProtocol.SimpleRegistrationResponse]()
    val acmeAgreement = Promise[AcmeProtocol.RegistrationResponse]()
    val acmeChallenge = Promise[AcmeProtocol.AuthorizationResponse]()

    "initialized" should {
      "request directory" in {
        val f = httpClient.getDirectory( LetsEncryptStaging )
        Await.result( f, new DurationInt(5).seconds )
        val d: AcmeProtocol.Directory = f.value.get.get
        d.get(AcmeProtocol.new_authz) shouldBe "https://acme-staging.api.letsencrypt.org/acme/new-authz"
        d.get(AcmeProtocol.new_cert) shouldBe "https://acme-staging.api.letsencrypt.org/acme/new-cert"
        d.get(AcmeProtocol.new_reg) shouldBe "https://acme-staging.api.letsencrypt.org/acme/new-reg"
        d.get(AcmeProtocol.revoke_cert) shouldBe "https://acme-staging.api.letsencrypt.org/acme/revoke-cert"
        d.get(AcmeProtocol.key_change) shouldBe "https://acme-staging.api.letsencrypt.org/acme/key-change"
        acmeServer.success( new AcmeServer( d ) )
      }

      "request registration" in {
        println("+ set on serv promise" )
        val getServer = acmeServer.future
        val f: Future[AcmeProtocol.SimpleRegistrationResponse] = getServer.flatMap{ server: AcmeServer => {
          println("+ server received" )
          val req = new AcmeProtocol.RegistrationRequest( Array( "mailto:cert-admin@example.com" ) )
          val nonce = httpClient.getNonce()
          println("++ dir nonce: " + nonce )
          val jwsReq = AcmeJson.encodeRequest( req, nonce, keypair )
          httpClient.registration( server.newReg, jwsReq.toString() )
        } }
        f.onSuccess{ case response: AcmeProtocol.SimpleRegistrationResponse => acmeRegistration.success( response ) }

        Await.result( f, new DurationInt(10).seconds )
        println("+sleeping till REG end" )
        sleep( 4000L )
      }

      "accept agreement" in {
        println("+ set on registration promise" )
        val getServer = acmeServer.future
        val f = getServer.flatMap{ server: AcmeServer => {

          val getRegistration = acmeRegistration.future
          val futureResponse: Future[AcmeProtocol.RegistrationResponse] = getRegistration.flatMap{ reg: AcmeProtocol.SimpleRegistrationResponse => {

            val req = new AcmeProtocol.RegistrationRequest( resource = AcmeProtocol.reg, contact = Some(Array( "mailto:cert-admin@example.com" )),
                agreement = Some( reg.agreement ) )
            val nonce = httpClient.getNonce()
            println("++ dir nonce: " + nonce )
            val jwsReq = AcmeJson.encodeRequest( req, nonce, keypair )
            httpClient.agreement( reg.uri, jwsReq.toString() )

          } }

          futureResponse
        } }

        f.onSuccess{ case response: AcmeProtocol.RegistrationResponse => acmeAgreement.success( response ) }

        Await.result( f, new DurationInt(10).seconds )
        println("+sleeping till ToS end" )
        sleep( 4000L )
      }

      "request authorization" in {
        println("+ set on agreement promise" )
        val getServer = acmeServer.future
        val f = getServer.flatMap{ server: AcmeServer => {

          val acmeIdent = AcmeProtocol.AcmeIdentifier( value = TestDomain )
          val getAgreement = acmeAgreement.future
          val futureResponse: Future[AcmeProtocol.AuthorizationResponse] = getAgreement.flatMap{ reg: AcmeProtocol.RegistrationResponse => {

            println("+ ToS agreement received" )
            val nonce = httpClient.getNonce()
            println("++ agreement nonce: " + nonce )

            val req = new AcmeProtocol.AuthorizationRequest( identifier = acmeIdent )
            val jwsReq = AcmeJson.encodeRequest( req, nonce, keypair )

            httpClient.authorize( server.newAuthz, jwsReq.toString() )
          } }

          futureResponse
        } }

        f.onSuccess{ case response: AcmeProtocol.AuthorizationResponse => acmeChallenge.success( response ) }

        println("+awaiting AUTH end" )
        Await.result( f, new DurationInt(20).seconds )
        println("+sleeping till AUTH end" )
        sleep( 4000L )
      }

      "accept challenge" in {
        println("+ set on challenge start" )
        val getServer = acmeServer.future
        val f = getServer.flatMap{ server: AcmeServer => {

          val getChallenge = acmeChallenge.future
          val futureResponse: Future[AcmeProtocol.ChallengeHttp] = getChallenge.flatMap{ authz: AcmeProtocol.AuthorizationResponse => {

            println("+ challenges received" )
            val httpChallenge = AcmeJson.findHttpChallenge( authz.challenges ).get

            val nonce = httpClient.getNonce()
            println("++ challenges nonce: " + nonce )

            val req = AcmeProtocol.AcceptChallengeHttp( keyAuthorization = AcmeJson.withThumbprint( httpChallenge.token, keypair ) )
            val jwsReq = AcmeJson.encodeRequest( req, nonce, keypair )

            httpClient.challenge( new URI( httpChallenge.uri ), jwsReq.toString() )
          } }
          futureResponse
        } }

        println("+awaiting CHAL end" )
        Await.result( f, new DurationInt(20).seconds )
        println("+sleeping till CHAL end" )
        sleep( 4000L )

      }


    } // initialized
  } // "Acme Http Client"

  def sleep(duration: Long) { Thread.sleep(duration) }

}
