sbtPlugin := true

name := "acme-protocol"

organization := "com.kodekutters"

version := "1.0"

scalaVersion := "2.11.5"

libraryDependencies ++= Seq(
  "com.nimbusds" % "nimbus-jose-jwt" % "3.7",
  "com.typesafe.play" % "play-json_2.11" % "2.4.0-M2",
  "net.minidev" % "json-smart" % "2.1.1",
  "junit" % "junit" % "4.12" % "test"
)

