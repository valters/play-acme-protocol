package com.kodekutters.acme

import java.net.URI
import java.nio.charset.StandardCharsets

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future

import com.kodekutters.acme.netty.{ HttpClient, NettyHttpCodec }
import com.typesafe.scalalogging.Logger

import io.netty.handler.codec.http.{ FullHttpResponse, HttpHeaders, HttpRequest }
import io.netty.handler.codec.http.HttpMethod

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

  private val MimeUrlencoded = "application/x-www-form-urlencoded"

  private var nonce: Option[String] = None

  /** extract few fields of interest from the underlying FullHttpResponse */
  case class Response( val status: Int, body: String, headers: HttpHeaders, nonce: Option[String] ) {
    def this( resp: FullHttpResponse ) {
      this( resp.status().code, resp.content().toString(StandardCharsets.UTF_8), resp.headers(), Option( resp.headers().get( AcmeProtocol.NonceHeader ) ) )
    }
  }

  /** low level method */
  private def httpGET(uri: URI, headers: Map[String, String] = Map.empty ): Future[Response] = {
    logger.info( "GET {}", uri )

    httpClient.get( uri, headers ).map { resp: FullHttpResponse =>
      val r = new Response( resp )

      resp.release()
      r
    }
  }

  /** low level method */
  private def httpPOST( uri: URI, mime: String, bytes: String ): Future[Response] = {
    httpClient.post(uri, mime, bytes.getBytes(StandardCharsets.UTF_8).toSeq, Map.empty, HttpMethod.POST).map { resp =>
      val r = new Response(resp)

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

  def registration( uri: URI, message: String  ): Future[Unit] = {
    httpPOST( uri, MimeUrlencoded, message ).flatMap {
        case Response(201, body, headers, nonce) =>
          logger.info("Successfully registered account: {} {} {} {}", uri, body, headers, nonce)
          val regURL = new URI(headers.get(HttpHeaders.Names.LOCATION))
          logger.info("  . folow up: {}", regURL )
          findTerms( headers )
//          getTerms(client, headers).map { terms =>
//            info("[%s] Agreement needs signing", client.endpoint, numTry)
//            agreement(client, regURL, terms)
//          }
          Future.successful( () )

        case Response(400, body, headers, nonce) if body contains "urn:acme:error:badNonce" =>
          logger.debug("[{}] Expired nonce used, getting new one", uri)
//          getNonce(client).flatMap { gotNonce =>
//            registration(client, numTry) // we don't count this as an error
//          }
          Future.successful( () )

        case Response(409, body, headers, nonce) =>
          logger.info("[%s] We already have an account", uri)
//          val termsAndServices = for {
//            regURL <- Option(headers.get(HttpHeaders.Names.LOCATION)).map(new URI(_))
//            terms <- findTerms(headers)
//          } yield {
//            info("[%s] Agreement needs signing", client.endpoint, numTry)
//            agreement(client, regURL, terms)
//          }
//          termsAndServices.getOrElse(Future.Done)
          Future.successful( () )

        case Response(status, body, headers, nonce) =>
          logger.error("[{}] Unable to register account after error {} tried {}", uri, status.toString(), body )
          throw new IllegalStateException("Unable to register: " + status + ": " + body)
    }
  }

  def getNonce(): String = {
    nonce.get
  }

  private def findTerms(headers: HttpHeaders): Option[String] = {
    import scala.collection.JavaConverters.asScalaBufferConverter

    headers.getAll("Link").asScala.foreach{ item =>  println( s"Link: $item" ) }

    None
  }


}
