sbtPlugin := true

name := "AcmeProtocol"

organization := "com.kodekutters"

version := "1.0"

scalaVersion := "2.11.8"

libraryDependencies ++= Seq(
  "com.nimbusds" % "nimbus-jose-jwt" % "4.34.1",
  "com.typesafe.play" % "play-json_2.11" % "2.5.12"
)

