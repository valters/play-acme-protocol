package io.github.valters.acme

import org.scalatestplus.play._

import scala.concurrent.{ Future, Promise }
import scala.concurrent.Await
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration.DurationInt

import org.scalatest.{ Matchers, WordSpec }
import play.api.libs.ws.WSClient

import com.typesafe.scalalogging.Logger

class AcmeHttpClientSpec extends PlaySpec with OneAppPerSuite {

  "Acme Http Client" should {
    val logger = Logger[AcmeClientExampleSpec]

      val Keys = new KeyStorage(KeyStorage.Defaults)

  /** test env URL */
  val LetsEncryptStaging = "https://acme-staging.api.letsencrypt.org"

  val TestDomain: String = "unit-test.mydomain.example.org"

    val wsClient = app.injector.instanceOf[WSClient]

    val HttpClient = new AcmeHttpClientImpl( wsClient )

    val acmeRegistration = Promise[AcmeProtocol.SimpleRegistrationResponse]()
    val acmeAgreement = Promise[AcmeProtocol.RegistrationResponse]()
    val acmeChallenge = Promise[AcmeProtocol.AuthorizationResponse]()

      "request directory" in {
      val directory = LetsEncryptStaging + AcmeProtocol.DirectoryFragment
        val f = HttpClient.getDirectory( directory )
        Await.result( f, new DurationInt(5).seconds )
        val d: AcmeProtocol.Directory = f.value.get.get
//        d.get(AcmeProtocol.new_authz) should be ("https://acme-staging.api.letsencrypt.org/acme/new-authz")
//        d.get(AcmeProtocol.new_cert) shouldBe "https://acme-staging.api.letsencrypt.org/acme/new-cert"
//        d.get(AcmeProtocol.new_reg) shouldBe "https://acme-staging.api.letsencrypt.org/acme/new-reg"
//        d.get(AcmeProtocol.revoke_cert) shouldBe "https://acme-staging.api.letsencrypt.org/acme/revoke-cert"
//        d.get(AcmeProtocol.key_change) shouldBe "https://acme-staging.api.letsencrypt.org/acme/key-change"
        HttpClient.acmeServer.success( new AcmeProtocol.AcmeServer( directory, d ) )
      }

      "request registration" in {
        println("+ set on serv promise" )
        val f: Future[AcmeProtocol.SimpleRegistrationResponse] = HttpClient.acmeServer.future.flatMap{ server: AcmeProtocol.AcmeServer => {
          println("+ server received" )
          val req = new AcmeProtocol.RegistrationRequest( Array( "mailto:cert-admin@example.com" ) )
          val nonce = HttpClient.getNonce()
          println("++ dir nonce: " + nonce )
          val jwsReq = AcmeJson.encodeRequest( req, nonce, Keys.userKey )
          HttpClient.registration( server.newReg, jwsReq.toString() )
        } }
        f.onSuccess{ case response: AcmeProtocol.SimpleRegistrationResponse => acmeRegistration.success( response ) }

        Await.result( f, new DurationInt(10).seconds )
        println("+sleeping till REG end" )
        sleep( 4000L )
      }

      "accept agreement" in {
        println("+ set on registration promise" )
        val f = HttpClient.acmeServer.future.flatMap{ server: AcmeProtocol.AcmeServer => {

          val getRegistration = acmeRegistration.future
          val futureResponse: Future[AcmeProtocol.RegistrationResponse] = getRegistration.flatMap{
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
            }

          }

          futureResponse
        } }

        f.onSuccess{ case response: AcmeProtocol.RegistrationResponse => acmeAgreement.success( response ) }

        Await.result( f, new DurationInt(10).seconds )
        println("+sleeping till ToS end" )
        sleep( 4000L )
      }

      "request authorization" in {
        println("+ set on agreement promise" )
        val f = HttpClient.acmeServer.future.flatMap{ server: AcmeProtocol.AcmeServer => {

          val acmeIdent = AcmeProtocol.AcmeIdentifier( value = TestDomain )
          val getAgreement = acmeAgreement.future
          val futureResponse: Future[AcmeProtocol.AuthorizationResponse] = getAgreement.flatMap{ reg: AcmeProtocol.RegistrationResponse => {

            println("+ ToS agreement received" )
            val nonce = HttpClient.getNonce()
            println("++ agreement nonce: " + nonce )

            val req = new AcmeProtocol.AuthorizationRequest( identifier = acmeIdent )
            val jwsReq = AcmeJson.encodeRequest( req, nonce, Keys.userKey )

            HttpClient.authorize( server.newAuthz, jwsReq.toString() )
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
        val f = HttpClient.acmeServer.future.flatMap{ server: AcmeProtocol.AcmeServer => {

          val getChallenge = acmeChallenge.future
          val futureResponse: Future[AcmeProtocol.ChallengeHttp] = getChallenge.flatMap{ authz: AcmeProtocol.AuthorizationResponse => {

            println("+ challenges received" )
            val httpChallenge = AcmeJson.findHttpChallenge( authz.challenges ).get

            val nonce = HttpClient.getNonce()
            println("++ challenges nonce: " + nonce )

            val req = AcmeProtocol.AcceptChallengeHttp( keyAuthorization = AcmeJson.withThumbprint( httpChallenge.token, Keys.userKey ) )
            val jwsReq = AcmeJson.encodeRequest( req, nonce, Keys.userKey )

            HttpClient.challenge( httpChallenge.uri, jwsReq.toString() )
          } }
          futureResponse
        } }

        println("+awaiting CHAL end" )
        Await.result( f, new DurationInt(20).seconds )
        println("+sleeping till CHAL end" )
        sleep( 4000L )

      }


  } // "Acme Http Client"

  def sleep(duration: Long) { Thread.sleep(duration) }

}
