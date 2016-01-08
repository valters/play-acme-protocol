sbtPlugin := true

name := "AcmeProtocol"

organization := "com.kodekutters"

version := "1.0"

scalaVersion := "2.11.7"

libraryDependencies ++= Seq(
  "com.nimbusds" % "nimbus-jose-jwt" % "4.11",
  "com.typesafe.play" % "play-json_2.11" % "2.5.0-M1"
)

