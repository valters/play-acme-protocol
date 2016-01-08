package com.kodekutters.acme

import com.kodekutters.acme.AcmeProtocol._
import com.nimbusds.jose.jwk.JWK

/**
  * some implicits
  */
object AcmeImplicits {

  implicit def StringMapToResourceTypeMap(value: Map[String, String]): Map[ResourceType, String] = {
    val resMap = scala.collection.mutable.Map[ResourceType, String]()
    value.foreach {
      case (k, v) => resMap += ResourceType.fromString(k) -> v.asInstanceOf[String]
    }
    resMap.toMap
  }

  // ------------------X to Option[X]-----------------------------------------------------------------------------------

  implicit def StringToStringOp(value: String): Option[String] = Option(value)

  implicit def DoubleToDoubleOp(value: Double): Option[Double] = Option(value)

  implicit def IntToIntOp(value: Int): Option[Int] = Option(value)

  implicit def BoolToBoolOp(value: Boolean): Option[Boolean] = Option(value)

  implicit def StatusCodeToOp(value: StatusCode): Option[StatusCode] = Option(value)

  implicit def AcmeErrorMessageToOp(value: AcmeErrorMessage): Option[AcmeErrorMessage] = Option(value)

  implicit def RecoveryKeyClientToOp(value: RecoveryKeyClient): Option[RecoveryKeyClient] = Option(value)

  implicit def RecoveryKeyServerToOp(value: RecoveryKeyServer): Option[RecoveryKeyServer] = Option(value)

  implicit def ArrayStringToOp(value: Array[String]): Option[Array[String]] = Option(value)

  implicit def JWKToOp(value: JWK): Option[JWK] = Option(value)

  implicit def ArrArrIntToOp(value: Array[Array[Int]]): Option[Array[Array[Int]]] = Option(value)


}
