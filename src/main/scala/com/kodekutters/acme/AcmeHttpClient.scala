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
import com.typesafe.scalalogging.Logger
import play.api.libs.json.Json
import play.api.libs.json.JsSuccess
import play.api.libs.json.JsError

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

  case class Response( val status: Int, body: String, headers: HttpHeaders, nonce: Option[String] ) {
    def this( resp: FullHttpResponse ) {
      this( resp.status().code, resp.content().toString(StandardCharsets.UTF_8), resp.headers(), Option( resp.headers().get( AcmeProtocol.NonceHeader ) ) )
    }
  }

  private def httpGET(uri: URI, headers: Map[String, String] = Map.empty ): Future[Response] = {
    logger.info( "GET {}", uri )

    httpClient.get(uri, headers).map { resp: FullHttpResponse =>
      val r = new Response( resp )

      resp.release()
      r
    }
  }

  def getDirectory(endpoint: String ): Future[AcmeProtocol.Directory] = {
    httpGET(new URI(endpoint + "/directory")).map {
      case Response(200, body, headers, nonce) =>
        logger.info( "body= {}, nonce= {}", body, nonce.getOrElse("<none>") )
        val directory = Json.parse( body ).validate[AcmeProtocol.Directory]
        directory match {
            case s: JsSuccess[AcmeProtocol.Directory] ⇒ s.get
            case e: JsError ⇒ throw new IllegalStateException( "Unable to parse json as directory response: "+JsError.toJson( e ).toString() )
        }
      case Response(status, body, headers, nonce) =>
        throw new IllegalStateException("Unable to get directory index: " + status + ": " + body)
    }
  }

}
