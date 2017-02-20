package com.kodekutters.acme

import org.scalatest.WordSpec
import scala.concurrent.Await
import scala.concurrent.duration.DurationInt
import org.scalatest._
import scala.concurrent.Promise
import com.kodekutters.acme.AcmeProtocol.AcmeServer
import scala.concurrent.ExecutionContext.Implicits.global

class AcmeHttpClientSpec extends WordSpec with Matchers {

  val keypair = AcmeJson.generateKeyPair()

  /** test env URL */
  val LetsEncryptStaging = "https://acme-staging.api.letsencrypt.org"

  "Acme Http Client" when {
    val httpClient = new AcmeHttpClient()
    val acmeServer = Promise[AcmeServer]()

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
        println("+ set on promise" )
        val fut = acmeServer.future
        val f = fut.flatMap{ server => {
          println("+ server received" )
          val req = new AcmeProtocol.RegistrationRequest( Array( "mailto:cert-admin@example.com" ) )
          val jwsReq = AcmeJson.encodeRequest( req, httpClient.getNonce(), keypair )
          httpClient.registration( server.newReg, jwsReq.toString() )
        } }

        Await.result( f, new DurationInt(10).seconds )
        println("+sleeping till end" )
        sleep( 4000L )
      }
    }
  }

def sleep(duration: Long) { Thread.sleep(duration) }

}
