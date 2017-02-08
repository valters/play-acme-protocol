package com.kodekutters.acme.netty

import scala.concurrent.Future

import io.netty.channel.Channel

trait NettyCodec[Req, Resp] {

  /**
   * Sets up basic Client-Pipeline for this Codec
   * @param channel Channel to apply the Pipeline to
   */
  def clientPipeline(channel: Channel): Unit

  /**
   * Gets called once the TCP Connection has been established
   * with this being the API Client connecting to a Server
   * @param channel Channel we're connected to
   * @param request Request object we want to use
   * @return Future Response
   */
  def clientConnected(channel: Channel, request: Req): Future[Resp]
}
