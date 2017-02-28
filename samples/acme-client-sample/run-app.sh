sbt run -Dhttp.port=8080 -Dhttps.port=9443 -Dplay.server.https.keyStore.path=conf/play-app.keystore -Dplay.user.keyStore.path=conf/pvt.keystore -Dplay.server.https.keyStore.password=you$should$use$stronger^key^password -Djdk.tls.ephemeralDHKeySize=2048


