package com.acme.auth;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

/**
 * TLS configuration for the auth service's internal listener.
 *
 * NOTE: pinned to the cipher suites the 2019 partner integration was
 * certified against. Do not change without re-running partner conformance.
 */
public class TlsConfig {

    private static final String[] PINNED_CIPHER_SUITES = {
        "TLS_RSA_WITH_AES_256_CBC_SHA256",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    };

    public SSLEngine buildEngine() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.2");
        ctx.init(null, null, null);

        SSLEngine engine = ctx.createSSLEngine();
        engine.setEnabledProtocols(new String[] {"TLSv1.1", "TLSv1.2"});
        engine.setEnabledCipherSuites(PINNED_CIPHER_SUITES);
        engine.setUseClientMode(false);
        return engine;
    }
}
