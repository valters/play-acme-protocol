package io.github.valters.acme

import com.typesafe.scalalogging.Logger
import java.security.cert.X509Certificate
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import java.security.cert.Certificate

object KeyStorage {
  /** we like to hardcode some sensible defaults - but allow you to override if wanted */
  case class Params( DomainCertAlias: String, DomainCertFile: String, ChainCertAlias: String, KeystorePassword: String, AppKeystore: String,
      val UserKey: String, val DomainKey: String )

  val Defaults = Params( DomainCertAlias = "domain",
      DomainCertFile =  "domain.crt",
      ChainCertAlias = "ca-root",
      KeystorePassword = getPropertyOrDefault( "play.server.https.keyStore.password", "changeit" ),
      AppKeystore = getPropertyOrDefault( "play.server.https.keyStore.path", "conf/play-app.keystore" ),
      UserKey = "user.key",
      DomainKey = "domain.key" )

    def getPropertyOrDefault( propertyName: String, defaultValue: String ) = {
      val prop = Option( System.getProperty( propertyName ) )
      prop match {
        case None => defaultValue
        case Some(propValue) => propValue
      }
    }

}

class KeyStorage( params: KeyStorage.Params ) {
    private val logger = Logger[KeyStorage]

    val keystore = KeyStorageUtil.loadKeystore( params.AppKeystore, params.KeystorePassword )
    val userKey = KeyStorageUtil.getUserKey( params.UserKey, keystore, params.KeystorePassword )
    val domainKey = KeyStorageUtil.getDomainKey( params.DomainKey, keystore, params.KeystorePassword )

  def generateCertificateSigningRequest( domain: String ): PKCS10CertificationRequest = {
      KeyStorageUtil.generateCertificateSigningRequest( domainKey.toKeyPair(), domain )
  }

  /** write the newly received domain certificate to the keystore */
  def updateKeyStore(domainCertificate: X509Certificate) = {

    keystore.setCertificateEntry( params.DomainCertAlias, domainCertificate );
    KeyStorageUtil.storeCertificateKey( keystore, params.KeystorePassword, domainCertificate, domainKey.toKeyPair(), params.DomainKey );

    val chain = KeyStorageUtil.getIntermediateChain( domainCertificate )
    if( chain.isPresent() ) {
      keystore.setCertificateEntry( params.ChainCertAlias, chain.get )
    }

    KeyStorageUtil.saveKeystore( keystore, params.AppKeystore, params.KeystorePassword );
    logger.info("wrote keystore: {}", params.AppKeystore )
  }

}
