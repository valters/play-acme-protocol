package com.kodekutters.acme
package netty

import io.netty.channel.nio.NioEventLoopGroup

/** globals used by HttpClient */
private[netty] object Netty {
  val eventLoop = new NioEventLoopGroup
}
