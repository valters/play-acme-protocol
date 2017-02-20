package com.kodekutters.acme

import scala.concurrent.{ Future, Promise }
import scala.concurrent.Await
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration.DurationInt

import org.scalatest.{ Matchers, WordSpec }

import com.kodekutters.acme.AcmeProtocol.AcmeServer

class AcmeHttpClientSpec extends WordSpec with Matchers {

  val keypair = AcmeJson.generateKeyPair()

  /** test env URL */
  val LetsEncryptStaging = "https://acme-staging.api.letsencrypt.org"

  val TestDomain: String = "unit-test.mydomain.example.org"


  "Acme Http Client" when {
    val httpClient = new AcmeHttpClient()
    val acmeServer = Promise[AcmeServer]()
    val acmeRegistration = Promise[AcmeProtocol.SimpleRegistrationResponse]()

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
        f.onSuccess{ case response => acmeRegistration.success( response ) }

        Await.result( f, new DurationInt(10).seconds )
        println("+sleeping till REG end" )
        sleep( 4000L )
      }

      "request authorization" in {
        println("+ set on reg promise" )
        val getServer = acmeServer.future
        val f = getServer.flatMap{ server: AcmeServer => {

          val acmeIdent = AcmeProtocol.AcmeIdentifier( value = TestDomain )
          val fut = acmeRegistration.future
          val f: Future[AcmeProtocol.AuthorizationResponse] = fut.flatMap{ reg: AcmeProtocol.SimpleRegistrationResponse => {

            println("+ registration received" )
            val nonce = httpClient.getNonce()
            println("++ reg nonce: " + nonce )

            val req = new AcmeProtocol.AuthorizationRequest( identifier = acmeIdent )
            val jwsReq = AcmeJson.encodeRequest( req, nonce, keypair )

            httpClient.authorize( server.newAuthz, jwsReq.toString() )
          } }

          f
        } }

        Await.result( f, new DurationInt(10).seconds )
        println("+sleeping till AUTH end" )
        sleep( 4000L )
      }

    }
  }

def sleep(duration: Long) { Thread.sleep(duration) }

}
