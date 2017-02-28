/*
  Copyright 2017 Valters Vingolds

  This file is licensed to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

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
