package io.github.valters

package object acme {

  val TestEnv = KeyStorage.Params( DomainCertAlias = "domain",
    ChainCertAlias = "root",
    KeystorePassword = "changeit",
    UserKeystore = "target/private.keystore",
    AppKeystore = "target/domain.keystore",
    UserKey = "user.key" )

}
