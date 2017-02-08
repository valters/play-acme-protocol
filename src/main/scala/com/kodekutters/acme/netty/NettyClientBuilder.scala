package com.kodekutters.acme.netty

import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicLong

import scala.concurrent.{ Future, Promise }

import org.slf4j.LoggerFactory

import io.netty.bootstrap.Bootstrap
import io.netty.channel.{ Channel, ChannelFuture, ChannelFutureListener, ChannelInitializer, ChannelOption, EventLoopGroup }
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioSocketChannel

trait NettyClientBuilder[Req, Resp] {

  protected def loggerName = this.getClass.getCanonicalName
  private[this] lazy val logger = LoggerFactory.getLogger(loggerName)

  def codec: NettyCodec[Req, Resp]
  def remote: List[InetSocketAddress]
  //def hostConnectionLimit: Int
  //def hostConnectionCoreSize: Int
  def tcpKeepAlive: Boolean
  def reuseAddr: Boolean
  def tcpNoDelay: Boolean
  def soLinger: Int
  def retries: Int
  def eventLoop: EventLoopGroup


  protected[this] lazy val requestCounter = new AtomicLong()
  protected[this] lazy val clnt = new Bootstrap
  protected[this] lazy val bootstrap = {

    val handler = new ChannelInitializer[SocketChannel] {
      override def initChannel(ch: SocketChannel): Unit = codec.clientPipeline(ch)
    }
    val baseGrp = clnt.group(eventLoop)
      .channel(classOf[NioSocketChannel])
      .option[java.lang.Boolean](ChannelOption.TCP_NODELAY, tcpNoDelay)
      .option[java.lang.Boolean](ChannelOption.SO_KEEPALIVE, tcpKeepAlive)
      .option[java.lang.Boolean](ChannelOption.SO_REUSEADDR, reuseAddr)
      .option[java.lang.Integer](ChannelOption.SO_LINGER, soLinger)

    val tcpCtGrp = baseGrp //tcpConnectTimeout.map { tcpCT =>
      //baseGrp.option[java.lang.Integer](ChannelOption.CONNECT_TIMEOUT_MILLIS, tcpCT.inMillis.toInt)
    //}.getOrElse(baseGrp)

    tcpCtGrp.handler(handler)
  }

  /**
   * Write a Request directly through to the given URI.
   * The request to generate the response should be used to prepare
   * the request only once the connection is established.
   * This reduces the context-switching for allocation/deallocation
   * on failed connects.
   *
   * @param uri What could this be?
   * @param req Request object
   * @return Future Resp
   */
  def write(uri: java.net.URI, req: Req): Future[Resp] = write(uri.toString, req)

  /**
   * Write a Request directly through to the given URI.
   * The request to generate the response should be used to prepare
   * the request only once the connection is established.
   * This reduces the context-switching for allocation/deallocation
   * on failed connects.
   *
   * @param uri What could this be?
   * @param req Request object
   * @return Future Resp
   */
  def write(uri: String, req: Req): Future[Resp] = {
    val result = run(uri, req)
    result
  }

  /**
   * Run the request against one of the specified remotes
   * @param uri What could this be?
   * @param req Request object
   * @param counter Request counter
   * @return Future Resp
   */
  protected[this] def run(uri: String, req: Req, counter: Int = 0): Future[Resp] = {
    import scala.concurrent.ExecutionContext.Implicits.global

    val conn: Future[Channel] = getConnection(uri)

    conn.flatMap { chan =>
      val resp: Future[Resp] = codec.clientConnected(chan, req)
      resp
    }

  }

  /**
   * Get a connection from the pool and regard the hostConnectionLimit
   * @param uri URI we want to connect to
   * @return Future Channel
   */
  protected[this] def getConnection(uri: String): Future[Channel] = {
    // TODO this is not implemented yet, looking for a nice way to keep track of connections
    connect(uri)
  }

  /**
   * Connects to the given URI and returns a Channel using a round-robin remote selection
   * @param uri URI we want to connect to
   * @return Future Channel
   */
  protected[this] def connect(uri: String): Future[Channel] = {
    val connectPromise = Promise[Channel]()

    val safeUri = new java.net.URI(uri.split("/", 4).take(3).mkString("/"))

    val connected = remote match {
      case Nil => bootstrap.clone().connect(safeUri.getHost, getPort(safeUri))
      case hosts =>
        // round robin connection
        val sock = hosts((requestCounter.incrementAndGet() % hosts.length).toInt)
        bootstrap.connect(sock)
    }
    connected.addListener { cf: ChannelFuture =>
      if (!cf.isSuccess) connectPromise.failure(cf.cause())
      else connectPromise.success(cf.channel)
    }
    connectPromise.future
  }

  /**
   * Gets the port for the given URI.
   * @param uri The URI where we want the Port number for
   * @return Port Number
   */
  protected[this] def getPort(uri: java.net.URI): Int

  /** convert listener from Netty into Scala terms */
  implicit val channelFutureListener: (ChannelFuture => Any) => ChannelFutureListener = { pf =>
    new ChannelFutureListener {
      override def operationComplete(f: ChannelFuture): Unit = pf(f)
    }
  }

}
