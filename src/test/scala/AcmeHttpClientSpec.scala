import org.scalatest.WordSpec
import com.kodekutters.acme.AcmeHttpClient
import scala.concurrent.Await
import scala.concurrent.duration.DurationInt
import com.kodekutters.acme.AcmeProtocol
import org.scalatest._

class AcmeHttpClientSpec extends WordSpec with Matchers {

  val LetsEncryptStaging = "https://acme-staging.api.letsencrypt.org"

  "Acme Http Client" when {
    val client = new AcmeHttpClient()

    "initialized" should {
      "request directory" in {
        val f = client.getDirectory( LetsEncryptStaging )
        Await.result( f, new DurationInt(5).seconds )
        val dir = f.value.get.get
        val newReg = dir.directory.get( AcmeProtocol.new_reg )
        newReg shouldBe Some("https://acme-staging.api.letsencrypt.org/acme/new-reg")
      }

      "produce NoSuchElementException when head is invoked" in {
        assertThrows[NoSuchElementException] {
          Set.empty.head
        }
      }
    }
  }
}
