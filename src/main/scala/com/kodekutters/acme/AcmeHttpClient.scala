package com.kodekutters.acme

import scala.concurrent.ExecutionContext.Implicits.global

import io.netty.handler.codec.http.FullHttpResponse
import com.kodekutters.acme.netty.NettyHttpCodec
import io.netty.handler.codec.http.HttpRequest
import com.kodekutters.acme.netty.HttpClient
import java.nio.charset.StandardCharsets
import java.net.URI
import scala.concurrent.Future
import io.netty.handler.codec.http.HttpHeaders
import org.slf4j.LoggerFactory

class AcmeHttpClient {
  private val logger = LoggerFactory.getLogger( getClass )


  private val httpCodec = NettyHttpCodec[HttpRequest, FullHttpResponse]()
    .withDecompression(true)
    .withKeepAlive(false)
    .withInsecureTls()

  private val httpClient = HttpClient()
    .withSpecifics(httpCodec)
    .withTcpNoDelay(true)
    .withTcpKeepAlive(false)

  private def httpGET(uri: URI, headers: Map[String, String] = Map.empty ): Future[(Int, String, HttpHeaders, Option[String])] = {
    logger.info( "GET {}", uri )

    httpClient.get(uri, headers).map { resp =>
      val nonce = Option(resp.headers().get("Replay-Nonce")) // should set to client
      val r = (resp.getStatus().code, resp.content().toString(StandardCharsets.UTF_8), resp.headers(), nonce)

      resp.release()
      r
    }
  }

  def getDirectory(endpoint: String ): Future[Unit] = {
    httpGET(new URI(endpoint + "/directory")).map {
      case (200, body, headers, nonce) =>
        logger.info( "body {}", body )
//        val j = JsonParser.parseOpt(body).flatMap(_.extractOpt[AcmePaths])
//        j.map { paths =>
//          val newAuth = new URI(paths.`new-authz`)
//          val newCert = new URI(paths.`new-cert`)
//          val newReg = new URI(paths.`new-reg`)
//          val revokeCert = new URI(paths.`revoke-cert`)
//          val terms = new URI(endpoint + "/terms")
//          val acme = AcmeClient(keyPair, endpoint, newAuth, newCert, newReg, revokeCert, terms, contacts)
//          nonce.map(acme.nonce ! _)
//          acme
//        }.getOrElse(throw new IllegalArgumentException("Directory index did not contain expected listing"))
      case (status, body, headers, nonce) =>
        throw new IllegalStateException("Unable to get directory index: " + status + ": " + body)
    }
  }

}
