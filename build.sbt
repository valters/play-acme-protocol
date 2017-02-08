name := "AcmeProtocol"

organization := "com.kodekutters"

version := "1.1"

scalaVersion := "2.11.8"

libraryDependencies += "com.nimbusds" % "nimbus-jose-jwt" % "4.34.1"
libraryDependencies += "com.typesafe.play" % "play-json_2.11" % "2.5.12"

// http transport
libraryDependencies += "io.netty" % "netty-all" % "4.1.8.Final"

// logging
libraryDependencies += "com.typesafe.scala-logging" %% "scala-logging" % "3.5.0"

// unit tests
libraryDependencies += "org.scalatest" % "scalatest_2.11" % "3.0.1" % "test"
libraryDependencies += "org.slf4j" % "slf4j-simple" % "1.7.22" % "test"
