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

        final RSAKey userKey = KeyStorageUtil.getUserKey( KeyStorage.Defaults().UserKey(), keystore, password );
        final RSAKey domainKey = KeyStorageUtil.getDomainKey( KeyStorage.Defaults().DomainKey(), keystore, password );

        KeyStorageUtil.saveKeystore( keystore, "unit-test.keystore", password );
    }
}
