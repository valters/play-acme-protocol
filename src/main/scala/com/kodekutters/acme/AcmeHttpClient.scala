package com.kodekutters.acme

import java.net.URI
import java.nio.charset.StandardCharsets

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future

import com.kodekutters.acme.netty.{ HttpClient, NettyHttpCodec }
import com.typesafe.scalalogging.Logger

import io.netty.handler.codec.http.{ FullHttpResponse, HttpHeaders, HttpMethod, HttpRequest }
import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedBlockingQueue

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

  /** ask Netty to exit its event loops to allow VM to wrap up threads and end */
  def shutdown() = {
    httpClient.shutdown()
  }

  private val MimeUrlencoded = "application/x-www-form-urlencoded"

  private val HeaderLink = "Link"

  private val nonceQueue:BlockingQueue[String] = new LinkedBlockingQueue[String]();

  /** blocks until a nonce value is available */
  def getNonce(): String = {
    nonceQueue.take
  }

  /** insert nonce into queue if we gone one */
  def putNonce( opt: Option[String]): Unit = {
    opt.foreach( nonce => nonceQueue.put( nonce ) )
  }

  /** extract few fields of interest from the underlying FullHttpResponse */
  final case class Response( val status: Int, body: String, headers: HttpHeaders, nonce: Option[String] ) {
    def this( resp: FullHttpResponse ) {
      this( resp.status().code, resp.content().toString(StandardCharsets.UTF_8), resp.headers(), Option( resp.headers().get( AcmeProtocol.NonceHeader ) ) )
    }
  }

  /** low level method */
  private def httpGET(uri: URI, headers: Map[String, String] = Map.empty ): Future[Response] = {
    logger.info( "GET {}", uri )

    httpClient.get( uri, headers ).map { resp: FullHttpResponse =>
      val r = new Response( resp )
      putNonce( r.nonce )

      resp.release()
      r
    }
  }

  /** low level method */
  private def httpPOST( uri: URI, mime: String, bytes: String ): Future[Response] = {
    httpClient.post(uri, mime, bytes.getBytes(StandardCharsets.UTF_8).toSeq, Map.empty, HttpMethod.POST).map { resp =>
      val r = new Response(resp)
      putNonce( r.nonce )

      resp.release()
      r
    }
  }

  def getDirectory(endpoint: String ): Future[AcmeProtocol.Directory] = {
    httpGET(new URI(endpoint + AcmeProtocol.DirectoryFragment)).map {
      case Response(200, body, headers, nonce) =>
        logger.info( "body= {}, nonce= {}", body, nonce )

        AcmeJson.parseDirectory( body )
      case Response(status, body, headers, nonce) =>
        throw new IllegalStateException("Unable to get directory index: " + status + ": " + body)
    }
  }

  /** server asks us to accept ToS as response */
  def registration( uri: URI, message: String  ): Future[AcmeProtocol.SimpleRegistrationResponse] = {
    httpPOST( uri, MimeUrlencoded, message ).flatMap {
        case Response(201, body, headers, nonce) =>
          logger.info("Successfully registered account: {} {} {} {}", uri, body, headers, nonce)

          val regUrl = new URI(headers.get(HttpHeaders.Names.LOCATION))
          logger.info("  . folow up: {}", regUrl )
          val termsUrl = findTerms( headers ).get
          logger.info("  . terms of service: {}", termsUrl )
          Future.successful( AcmeProtocol.SimpleRegistrationResponse( regUrl, termsUrl ) )

        case Response(400, body, headers, nonce) if body contains "urn:acme:error:badNonce" =>
          logger.debug("[{}] Expired nonce used, getting new one", uri)
//          getNonce(client).flatMap { gotNonce =>
//            registration(client, numTry) // we don't count this as an error
//          }
          Future.failed( new IllegalStateException("400 nonce expired" ) )

        case Response(409, body, headers, nonce) =>
          logger.info("[{}] We already have an account", uri)
//          val termsAndServices = for {
//            regURL <- Option(headers.get(HttpHeaders.Names.LOCATION)).map(new URI(_))
//            terms <- findTerms(headers)
//          } yield {
//            info("[%s] Agreement needs signing", client.endpoint, numTry)
//            agreement(client, regURL, terms)
//          }
//          termsAndServices.getOrElse(Future.Done)
          Future.failed( new IllegalStateException("409 acct exists" ) )

        case Response(status, body, headers, nonce) =>
          logger.error("[{}] Unable to register account after error {} tried {}", uri, status.toString(), body )
          throw new IllegalStateException("Unable to register: " + status + ": " + body)
    }
  }

  /** server provides list of challenges as response */
  def authorize( uri: URI, message: String  ): Future[AcmeProtocol.AuthorizationResponse] = {
    httpPOST( uri, MimeUrlencoded, message ).flatMap {
        case Response(201, body, headers, nonce) =>
          logger.info("Successfully authorized account: {} {} {} {}", uri, body, headers, nonce)
          Future.successful( AcmeJson.parseAuthorization( body ) )
        case Response(status, body, headers, nonce) =>
          logger.error("[{}] Unable to authorized account after error {} tried {}", uri, status.toString(), body )
          throw new IllegalStateException("Unable to authorize: " + status + ": " + body)
    }
  }

  /** accept ToS to complete the registration: we need to pass the detected "terms of service" doc url to indicate agreement
   *  @param uri regURL returned as Location by new-reg call, for example "https://acme-staging.api.letsencrypt.org/acme/reg/930540"
   *  @param message registration message wrapped as JWS
   */
  def agreement( uri: URI, message: String ): Future[AcmeProtocol.RegistrationResponse] = {
    logger.info("[{}] Handling agreement", uri)
      httpPOST( uri, MimeUrlencoded, message ).flatMap {
        case Response(code, body, headers, nonce) if code < 250 =>
          logger.info("[{}] Successfully signed Terms of Service: {} {} {} {}", uri, body, headers, nonce)
          Future.successful( AcmeProtocol.RegistrationResponse( null ) )

        case Response(400, body, headers, nonce) if body contains "urn:acme:error:badNonce" =>
          logger.error("[{}] Expired nonce used, getting new one: {} {} {} {}", uri, body, headers, nonce)
          throw new IllegalStateException("Unable to sign agreement: error 400: " + body)

        case Response(status, body, headers, nonce) =>
          logger.error("[{}] Unable to sign Terms of Service: {} {} {} {}", uri, body, headers, nonce)
          throw new IllegalStateException("Unable to sign agreement: " + status + ": " + body)
      }
  }

  /** locate the terms-of-service link and get the URI */
  private def findTerms(headers: HttpHeaders): Option[String] = {
    import scala.collection.JavaConverters.asScalaBufferConverter

    val links = headers.getAll(HeaderLink).asScala

    links.foreach{ item =>  println( s"Link: $item" ) }
    links.find(_.endsWith(";rel=\"terms-of-service\""))
      .flatMap(_.split(">").headOption.map(_.replaceAll("^<", "")))
  }


  /** indicate that we would like to try the particular challenge */
  def challenge( uri: URI, message: String ): Future[AcmeProtocol.ChallengeHttp] = {
    logger.debug("[{}] Accepting challenge", uri )

    httpPOST( uri, MimeUrlencoded, message ).flatMap {
      case Response(status, body, headers, nonce) if status < 250 =>
        logger.info("[{}] Successfully accepted challenge: {} {} {} {}", uri, body, headers, nonce)
        Future.successful( AcmeJson.parseHttpChallenge( body ) )

      case Response(status, body, headers, nonce) =>
        logger.error("[{}] Unable to accept challenge: {} {} {} {}", uri, body, headers, nonce)
        throw new IllegalStateException("Unable to accept challenge: " + status + ": " + body)
    }
  }

  def challengeDetails(uri: URI): Future[AcmeProtocol.ChallengeType]  = {
    httpGET( uri ).map {
      case Response(status, body, headers, nonce) if status < 250 =>
        logger.info( "body= {}, nonce= {}", body, nonce )

        AcmeJson.parseChallenge( body )
      case Response(status, body, headers, nonce) =>
        throw new IllegalStateException("Unable to get challenge status details: " + status + ": " + body)
    }
  }

}
