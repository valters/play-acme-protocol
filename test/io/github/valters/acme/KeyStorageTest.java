package io.github.valters.acme;

import java.security.KeyStore;

import org.junit.Test;

import com.nimbusds.jose.jwk.RSAKey;

import io.github.valters.acme.KeyStorage;
import io.github.valters.acme.KeyStorageUtil;

public class KeyStorageTest {

    @Test
    public void shouldGenerateKeyStore() throws Exception {

        final KeyStore keystore = KeyStorageUtil.newKeystore();
        final String password = "unit-test";

        final RSAKey userKey = KeyStorageUtil.getUserKey( KeyStorage.Defaults().UserKey(), keystore, "target/x-user.keystore", password );
        final RSAKey domainKey = KeyStorageUtil.getDomainKey( KeyStorage.Defaults().DomainCertAlias(), keystore, "target/x-domain.keystore", password );

        KeyStorageUtil.saveKeystore( keystore, "target/x-unit-test.keystore", password );
    }
}
