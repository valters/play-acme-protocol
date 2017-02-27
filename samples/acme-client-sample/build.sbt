name := """acme-client-sample"""
organization := "io.github.valters"

version := "0.1.0-SNAPSHOT"

lazy val root = (project in file(".")).enablePlugins(PlayScala)

scalaVersion := "2.11.8"

libraryDependencies += "io.github.valters" %% "play-acme-protocol" % "0.1.0-SNAPSHOT"

