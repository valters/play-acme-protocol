package controllers

import javax.inject._
import play.api._
import play.api.mvc._
import akka.stream.scaladsl.Source
import scala.concurrent.Promise
import scala.concurrent.Future
import akka.stream.OverflowStrategy
import play.api.libs.EventSource
import scala.concurrent.ExecutionContext
import akka.actor.ActorSystem

/**
 * This controller creates an `Action` to handle HTTP requests to the
 * application's home page.
 */
@Singleton
class HomeController @Inject() ( implicit actorSystem: ActorSystem, exec: ExecutionContext ) extends Controller {

  /**
   * Create an Action to render an HTML page.
   *
   * The configuration in the `routes` file means that this method
   * will be called when the application receives a `GET` request with
   * a path of `/`.
   */
  def index = Action { implicit request ⇒
    Ok( views.html.index() )
  }

  def queue = Action {

    val ( queueSource, futureQueue ) = peekMatValue( Source.queue[String]( 10, OverflowStrategy.fail ) )

    futureQueue.map { q ⇒
      q.offer( "bla" )
      q.offer( "bla" )
      q.offer( "bla" )
      q.complete()
    }

    Ok.chunked( queueSource )
  }

  /**
   * @param T source type, here String
   * @param M materialization type, here a SourceQueue[String]
   */
  def peekMatValue[T, M]( src: Source[T, M] ): ( Source[T, M], Future[M] ) = {
    val p = Promise[M]
    val s = src.mapMaterializedValue { m ⇒
      p.trySuccess( m )
      m
    }
    ( s, p.future )
  }
}
