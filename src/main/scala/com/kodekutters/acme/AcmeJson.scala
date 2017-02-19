package com.kodekutters.acme

import play.api.libs.json.JsSuccess
import play.api.libs.json.JsError
import play.api.libs.json.Json

/**
 * Implements JSON reads and writes for AcmeProtocol.
 */
object AcmeJson {

  def parseDirectory( jsonBody: String ): AcmeProtocol.Directory = {
    val directory = Json.parse( jsonBody ).validate[AcmeProtocol.Directory]
    directory match {
        case s: JsSuccess[AcmeProtocol.Directory] ⇒ s.get
        case e: JsError ⇒ throw new IllegalStateException( "Unable to parse json as directory response: "+JsError.toJson( e ).toString() )
    }
  }

}
