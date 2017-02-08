import org.scalatest.WordSpec
import com.kodekutters.acme.AcmeHttpClient
import scala.concurrent.Await
import scala.concurrent.duration.`package`.DurationInt

class AcmeHttpClientSpec extends WordSpec {

  val LetsEncryptStaging = "https://acme-staging.api.letsencrypt.org"

  "Acme Http Client" when {
    val client = new AcmeHttpClient()

    "initialized" should {
      "request directory" in {
        val f = client.getDirectory( LetsEncryptStaging )
        Await.result( f, new DurationInt(5).seconds )

      }

      "produce NoSuchElementException when head is invoked" in {
        assertThrows[NoSuchElementException] {
          Set.empty.head
        }
      }
    }
  }
}
