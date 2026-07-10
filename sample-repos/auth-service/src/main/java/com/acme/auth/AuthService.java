package com.acme.auth;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

/**
 * Issues and verifies signed session assertions for internal services.
 * The signing keypair is generated at startup and published to the
 * service registry so downstream services can verify assertions.
 */
public class AuthService {

    private final KeyPair keyPair;

    public AuthService() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        this.keyPair = keyGen.generateKeyPair();
    }

    /** Sign a session assertion for a downstream service. */
    public String signAssertion(String assertionJson) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(keyPair.getPrivate());
        sig.update(assertionJson.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(sig.sign());
    }

    /** Verify a session assertion produced by this service. */
    public boolean verifyAssertion(String assertionJson, String signatureB64) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(keyPair.getPublic());
        sig.update(assertionJson.getBytes("UTF-8"));
        return sig.verify(Base64.getDecoder().decode(signatureB64));
    }

    public PublicKey publicKey() {
        return keyPair.getPublic();
    }

    PrivateKey privateKey() {
        return keyPair.getPrivate();
    }
}
