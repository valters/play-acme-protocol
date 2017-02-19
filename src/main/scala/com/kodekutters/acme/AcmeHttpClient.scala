package com.kodekutters.acme

import java.net.URI
import java.nio.charset.StandardCharsets

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future

import com.kodekutters.acme.netty.{ HttpClient, NettyHttpCodec }
import com.typesafe.scalalogging.Logger

import io.netty.handler.codec.http.{ FullHttpResponse, HttpHeaders, HttpRequest }

class AcmeHttpClient {
  private val logger = Logger[AcmeHttpClient]

  private val httpCodec = NettyHttpCodec[HttpRequest, FullHttpResponse]()
    .withDecompression(true)
    .withKeepAlive(false)
    .withInsecureTls()

  private val httpClient = HttpClient()
    .withSpecifics(httpCodec)
    .withTcpNoDelay(true)
    .withTcpKeepAlive(false)

 private var nonce: Option[String] = None

  /** extract few fields of interest from the underlying FullHttpResponse */
  case class Response( val status: Int, body: String, headers: HttpHeaders, nonce: Option[String] ) {
    def this( resp: FullHttpResponse ) {
      this( resp.status().code, resp.content().toString(StandardCharsets.UTF_8), resp.headers(), Option( resp.headers().get( AcmeProtocol.NonceHeader ) ) )
    }
  }

  private def httpGET(uri: URI, headers: Map[String, String] = Map.empty ): Future[Response] = {
    logger.info( "GET {}", uri )

    val nonceHeader: Option[(String, String)] = nonce.map( n => ( AcmeProtocol.NonceHeader, n ) )

    httpClient.get( uri, headers ++ nonceHeader ).map { resp: FullHttpResponse =>
      val r = new Response( resp )

      resp.release()
      r
    }
  }

  def getDirectory(endpoint: String ): Future[AcmeProtocol.Directory] = {
    httpGET(new URI(endpoint + AcmeProtocol.DirectoryFragment)).map {
      case Response(200, body, headers, nonce) =>
        this.nonce = nonce // update state
        logger.info( "body= {}, nonce= {}", body, nonce.getOrElse("<none>") )
        AcmeJson.parseDirectory( body )
      case Response(status, body, headers, nonce) =>
        throw new IllegalStateException("Unable to get directory index: " + status + ": " + body)
    }
  }

}
