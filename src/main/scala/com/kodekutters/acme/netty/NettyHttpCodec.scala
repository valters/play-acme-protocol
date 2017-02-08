package com.kodekutters.acme.netty

import scala.concurrent.{ Future, Promise }

import io.netty.channel.{ Channel, ChannelHandlerContext, SimpleChannelInboundHandler }
import io.netty.handler.codec.http.{ HttpClientCodec, HttpContentDecompressor, HttpHeaderNames, HttpHeaderValues, HttpMessage, HttpObject, HttpObjectAggregator, HttpUtil }
import io.netty.handler.ssl.{ SslContext, SslContextBuilder }
import io.netty.handler.ssl.util.InsecureTrustManagerFactory
import io.netty.util.ReferenceCountUtil

/**
 * wasted.io Scala Http Codec
 *
 * For composition you may use HttpCodec[HttpObject]().withChunking(true)...
 *
 * @param compressionLevel GZip compression level
 * @param decompression GZip decompression?
 * @param keepAlive TCP KeepAlive. Defaults to false
 * @param chunked Should we pass through chunks?
 * @param chunking Should we allow chunking?
 * @param maxChunkSize Maximum chunk size
 * @param maxRequestSize Maximum request size
 * @param maxResponseSize Maximum response size
 * @param maxInitialLineLength Maximum line length for GET/POST /foo...
 * @param maxHeaderSize Maximum header size
 * @param readTimeout Channel Read Timeout
 * @param writeTimeout Channel Write Timeout
 * @param sslCtx Netty SSL Context
 */
final case class NettyHttpCodec[Req <: HttpMessage, Resp <: HttpObject](compressionLevel: Int = -1,
                                                                        decompression: Boolean = true,
                                                                        keepAlive: Boolean = false,
                                                                        chunked: Boolean = false,
                                                                        chunking: Boolean = true,
                                                                        maxChunkSize: Int = 5000000,
                                                                        maxRequestSize: Int = 5000000,
                                                                        maxResponseSize: Int = 5000000,
                                                                        maxInitialLineLength: Int = 4096,
                                                                        maxHeaderSize: Int = 8192,
                                                                        sslCtx: Option[SslContext] = None) extends NettyCodec[Req, Resp] {

  def withChunking(chunking: Boolean, chunked: Boolean = false, maxChunkSize: Int = 5000000) =
    copy[Req, Resp](chunking = chunking, chunked = chunked, maxChunkSize = maxChunkSize)

  def withCompression(compressionLevel: Int) = copy[Req, Resp](compressionLevel = compressionLevel)
  def withDecompression(decompression: Boolean) = copy[Req, Resp](decompression = decompression)
  def withTls(sslCtx: SslContext) = copy[Req, Resp](sslCtx = Some(sslCtx))
  def withKeepAlive(keepAlive: Boolean) = copy[Req, Resp](keepAlive = keepAlive)

  def withInsecureTls() = {
    val ctx = SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE).build()
    copy[Req, Resp](sslCtx = Some(ctx))
  }


  /**
   * Sets up basic HTTP Pipeline
   * @param channel Channel to apply the Pipeline to
   */
  def clientPipeline(channel: Channel): Unit = {
    val pipeline = channel.pipeline()
    sslCtx.foreach(e => pipeline.addLast(HttpClient.Handlers.ssl, e.newHandler(channel.alloc())))
    val maxInitialBytes = this.maxInitialLineLength
    val maxHeaderBytes = this.maxHeaderSize
    val maxChunkSize = this.maxChunkSize
    val maxContentLength = this.maxResponseSize
    pipeline.addLast(HttpClient.Handlers.codec, new HttpClientCodec(maxInitialBytes, maxHeaderBytes, maxChunkSize))
    if (chunking && !chunked) {
      pipeline.addLast(HttpClient.Handlers.aggregator, new HttpObjectAggregator(maxContentLength))
    }
    if (decompression) {
      pipeline.addLast(HttpClient.Handlers.decompressor, new HttpContentDecompressor())
    }
  }

  /**
   * Handle the connected channel and send the request
   * @param channel Channel we're connected to
   * @param request Object we want to send
   * @return
   */
  def clientConnected(channel: Channel, request: Req): Future[Resp] = {
    val result = Promise[Resp]

    channel.pipeline.addLast(HttpClient.Handlers.handler, new SimpleChannelInboundHandler[Resp] {
      override def exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        ExceptionHandler(ctx, cause)
        result.failure(cause)
        ctx.channel.close
      }

      def channelRead0(ctx: ChannelHandlerContext, msg: Resp) {
        if ( ! result.isCompleted ) result.success(ReferenceCountUtil.retain(msg))
        if (keepAlive && HttpUtil.isKeepAlive(request)) {} else channel.close()
      }
    })
    val ka = if (keepAlive && HttpUtil.isKeepAlive(request))
      HttpHeaderValues.KEEP_ALIVE else HttpHeaderValues.CLOSE
    request.headers().set(HttpHeaderNames.CONNECTION, ka)

    channel.writeAndFlush(request)
    result.future
  }
}
