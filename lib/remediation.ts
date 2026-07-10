import type { Classification, Finding } from './types';

/**
 * Built-in remediation templates.
 *
 * Used when no Claude API key is configured (or a live call fails), so the
 * demo never dies on stage. The seeded sample-repo patches below are
 * hand-verified hybrid implementations that follow the real, current
 * standards-track patterns:
 *   - ML-DSA-65 (FIPS 204) composite signing alongside RSA/ECDSA, matching
 *     the IETF draft-ietf-lamps-pq-composite-sigs approach
 *   - X25519MLKEM768 hybrid key exchange for TLS (the group Chrome and
 *     Cloudflare deploy today)
 */

export interface BuiltinRemediation {
  classification: Classification;
  patchedCode: string;
  changes: string[];
  newAlgorithm: string;
}

const SIGNER_PY_PATCHED = `"""Transaction signing for the payments service.

Every outbound settlement message is signed before it is handed to the
clearing network. Keys are rotated quarterly by ops (see runbook PAY-114).

Hybrid post-quantum migration: signatures are now composite — the existing
RSA-2048 (PSS) signature plus an ML-DSA-65 signature (NIST FIPS 204), per
the IETF draft-ietf-lamps-pq-composite-sigs pattern. Verifiers MUST check
both during the hybrid period.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import oqs  # liboqs-python (Open Quantum Safe) — real FIPS 204 implementation


def generate_keys():
    """Generate the service signing keypair (rotated quarterly)."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def generate_pq_signer():
    """Generate the post-quantum signing key (ML-DSA-65, NIST FIPS 204).

    Done once at service startup, alongside the classical keypair.
    """
    pq_signer = oqs.Signature("ML-DSA-65")
    pq_public_key = pq_signer.generate_keypair()
    return pq_signer, pq_public_key


def sign_transaction(private_key, transaction_bytes, pq_signer):
    """Sign a serialized settlement transaction (hybrid composite).

    Returns both signatures; the clearing network verifies BOTH against
    our published classical and post-quantum public keys.
    """
    # Classical signature — kept for backward compatibility during migration
    classical_signature = private_key.sign(
        transaction_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    # Post-quantum signature — ML-DSA-65 (NIST FIPS 204)
    pq_signature = pq_signer.sign(transaction_bytes)
    return {
        "classical_signature": classical_signature,
        "pq_signature": pq_signature,
        "pq_algorithm": "ML-DSA-65",
    }


def verify_transaction(public_key, pq_public_key, transaction_bytes, signatures):
    """Verify a settlement signature (used by the reconciliation job).

    BOTH signatures must verify during the hybrid period.
    """
    public_key.verify(
        signatures["classical_signature"],
        transaction_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    pq_verifier = oqs.Signature("ML-DSA-65")
    if not pq_verifier.verify(transaction_bytes, signatures["pq_signature"], pq_public_key):
        raise ValueError("post-quantum signature verification failed")
    return True


def export_public_key(private_key):
    """PEM-encode the public half for the clearing network onboarding form."""
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
`;

const AUTH_SERVICE_JAVA_PATCHED = `package com.acme.auth;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

/**
 * Issues and verifies signed session assertions for internal services.
 *
 * Hybrid post-quantum migration: assertions now carry a composite of the
 * existing SHA256withRSA signature and an ML-DSA-65 signature (NIST FIPS
 * 204). ML-DSA is available natively in JDK 24+ (JEP 497) and via
 * BouncyCastle 1.79+ on older JDKs. Verifiers check BOTH signatures
 * during the hybrid period (draft-ietf-lamps-pq-composite-sigs).
 */
public class AuthService {

    private final KeyPair keyPair;
    private final KeyPair pqKeyPair;

    public AuthService() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        this.keyPair = keyGen.generateKeyPair();

        // Post-quantum keypair — ML-DSA-65 (FIPS 204)
        KeyPairGenerator pqKeyGen = KeyPairGenerator.getInstance("ML-DSA-65");
        this.pqKeyPair = pqKeyGen.generateKeyPair();
    }

    /** Sign a session assertion for a downstream service (hybrid composite). */
    public String signAssertion(String assertionJson) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(keyPair.getPrivate());
        sig.update(assertionJson.getBytes("UTF-8"));
        String classical = Base64.getEncoder().encodeToString(sig.sign());

        Signature pqSig = Signature.getInstance("ML-DSA");
        pqSig.initSign(pqKeyPair.getPrivate());
        pqSig.update(assertionJson.getBytes("UTF-8"));
        String postQuantum = Base64.getEncoder().encodeToString(pqSig.sign());

        // Composite: both signatures travel together; verifier checks both.
        return classical + "." + postQuantum;
    }

    /** Verify a session assertion produced by this service (both must pass). */
    public boolean verifyAssertion(String assertionJson, String signatureB64) throws Exception {
        String[] parts = signatureB64.split("\\\\.", 2);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(keyPair.getPublic());
        sig.update(assertionJson.getBytes("UTF-8"));
        boolean classicalOk = sig.verify(Base64.getDecoder().decode(parts[0]));

        Signature pqSig = Signature.getInstance("ML-DSA");
        pqSig.initVerify(pqKeyPair.getPublic());
        pqSig.update(assertionJson.getBytes("UTF-8"));
        boolean pqOk = parts.length > 1 && pqSig.verify(Base64.getDecoder().decode(parts[1]));

        return classicalOk && pqOk; // BOTH must pass during hybrid period
    }

    public PublicKey publicKey() {
        return keyPair.getPublic();
    }

    public PublicKey pqPublicKey() {
        return pqKeyPair.getPublic();
    }

    PrivateKey privateKey() {
        return keyPair.getPrivate();
    }
}
`;

const TLS_CONFIG_JAVA_PATCHED = `package com.acme.auth;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

/**
 * TLS configuration for the auth service's internal listener.
 *
 * Post-quantum migration: key exchange now prefers X25519MLKEM768 — the
 * hybrid classical + ML-KEM-768 (NIST FIPS 203) group already deployed by
 * Chrome and Cloudflare. Static-RSA cipher suites (no forward secrecy,
 * quantum-vulnerable key transport) are removed; TLS 1.3 handles suite
 * selection. Requires JDK 24+ (JEP 496) or the BouncyCastle/oqs provider.
 */
public class TlsConfig {

    static {
        // Prefer the hybrid post-quantum group, fall back to X25519 for
        // peers that don't support it yet.
        System.setProperty("jdk.tls.namedGroups", "X25519MLKEM768,x25519,secp256r1");
    }

    public SSLEngine buildEngine() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(null, null, null);

        SSLEngine engine = ctx.createSSLEngine();
        engine.setEnabledProtocols(new String[] {"TLSv1.3"});
        // TLS 1.3 cipher suites are AEAD-only and negotiated automatically;
        // the pinned static-RSA suites are gone.
        engine.setUseClientMode(false);
        return engine;
    }
}
`;

const AUTH_JS_PATCHED = `/**
 * JWT issuance and verification for the API gateway.
 *
 * Hybrid post-quantum migration: each RS256 JWT now carries a detached
 * ML-DSA-65 signature (NIST FIPS 204) computed over the compact JWS.
 * Downstream services verify BOTH signatures during the hybrid period.
 * ML-DSA via @noble/post-quantum (audited, pure-JS FIPS 204).
 */

const fs = require('fs');
const jwt = require('jsonwebtoken');
const { ml_dsa65 } = require('@noble/post-quantum/ml-dsa.js');

const privateKey = fs.readFileSync(process.env.JWT_PRIVATE_KEY_PATH || './keys/gateway.pem');
const publicKey = fs.readFileSync(process.env.JWT_PUBLIC_KEY_PATH || './keys/gateway.pub');

// Post-quantum signing key — ML-DSA-65 (FIPS 204), loaded from the KMS in
// production; generated at boot for the demo.
const pqKeys = ml_dsa65.keygen();

const TOKEN_TTL_SECONDS = 15 * 60;

function issueToken(user) {
  const payload = {
    sub: user.id,
    email: user.email,
    scopes: user.scopes || [],
  };
  const token = jwt.sign(payload, privateKey, {
    algorithm: 'RS256',
    expiresIn: TOKEN_TTL_SECONDS,
    issuer: 'api-gateway',
  });
  // Detached post-quantum signature over the compact JWS
  const pqSig = ml_dsa65.sign(Buffer.from(token), pqKeys.secretKey);
  return { token, pqSig: Buffer.from(pqSig).toString('base64url'), pqAlg: 'ML-DSA-65' };
}

function verifyToken(token, pqSigB64) {
  const claims = jwt.verify(token, publicKey, {
    algorithms: ['RS256'],
    issuer: 'api-gateway',
  });
  // BOTH signatures must verify during the hybrid period
  const pqOk = ml_dsa65.verify(
    Buffer.from(pqSigB64, 'base64url'),
    Buffer.from(token),
    pqKeys.publicKey
  );
  if (!pqOk) throw new Error('post-quantum signature verification failed');
  return claims;
}

module.exports = { issueToken, verifyToken, TOKEN_TTL_SECONDS };
`;

interface SeededPatch {
  patched: string;
  changes: string[];
  newAlgorithm: string;
  classification: Classification;
}

const SEEDED: Record<string, SeededPatch> = {
  'payments/signer.py:rsa-signing': {
    patched: SIGNER_PY_PATCHED,
    newAlgorithm: 'RSA-2048 + ML-DSA-65 (hybrid)',
    changes: [
      'Added liboqs-python (oqs) import — the Open Quantum Safe reference implementation of FIPS 204',
      'Added generate_pq_signer() to create the ML-DSA-65 keypair at service startup',
      'sign_transaction() now returns a composite of the classical RSA-PSS signature and an ML-DSA-65 signature',
      'verify_transaction() requires BOTH signatures to verify during the hybrid period',
      'Classical RSA path is preserved unchanged for backward compatibility with the clearing network',
    ],
    classification: {
      algorithm: 'RSA (PSS padding, SHA-256)',
      key_size: '2048',
      usage_type: 'signing',
      explanation:
        'This module signs payment settlement transactions with RSA-2048, which is breakable by a large-scale quantum computer running Shor’s algorithm. Because these signatures authorize financial transactions sent to an external clearing network, this is classified Critical.',
    },
  },
  'src/main/java/com/acme/auth/AuthService.java:rsa-signing': {
    patched: AUTH_SERVICE_JAVA_PATCHED,
    newAlgorithm: 'RSA-2048 + ML-DSA-65 (hybrid)',
    changes: [
      'Added an ML-DSA-65 keypair (FIPS 204) generated at startup alongside the RSA keypair — native in JDK 24+ (JEP 497), BouncyCastle 1.79+ on older JDKs',
      'signAssertion() now produces a composite signature: SHA256withRSA + ML-DSA, dot-separated',
      'verifyAssertion() requires BOTH signatures to verify (draft-ietf-lamps-pq-composite-sigs pattern)',
      'Added pqPublicKey() so downstream services can fetch the post-quantum verification key from the registry',
    ],
    classification: {
      algorithm: 'RSA (SHA256withRSA)',
      key_size: '2048',
      usage_type: 'signing',
      explanation:
        'This service signs session assertions with RSA-2048 that every internal service trusts for authentication. A quantum-capable adversary could forge assertions and impersonate any user or service, so this internal signing path is classified High.',
    },
  },
  'src/main/java/com/acme/auth/TlsConfig.java:tls-rsa-key-exchange': {
    patched: TLS_CONFIG_JAVA_PATCHED,
    newAlgorithm: 'X25519MLKEM768 hybrid key exchange (TLS 1.3)',
    changes: [
      'Key exchange now prefers X25519MLKEM768 — hybrid classical + ML-KEM-768 (FIPS 203), the group Chrome and Cloudflare already deploy',
      'Protocol floor raised from TLS 1.1 to TLS 1.3',
      'Removed the pinned TLS_RSA_* static-RSA cipher suites (quantum-vulnerable key transport, no forward secrecy)',
      'NOTE: the 2019 partner-conformance pin means this change needs partner re-certification — flagged for engineering review',
    ],
    classification: {
      algorithm: 'RSA key transport (TLS_RSA_* cipher suites), TLS 1.1/1.2',
      key_size: '2048',
      usage_type: 'key_exchange',
      explanation:
        'This listener accepts static-RSA key exchange over TLS 1.1/1.2. Traffic recorded today can be decrypted retroactively once a quantum computer exists ("harvest now, decrypt later"). The pinned 2019 partner cipher suites mean an automated change may break a certified integration, so confidence is reduced and human review is required.',
    },
  },
  'auth.js:jwt-rs256': {
    patched: AUTH_JS_PATCHED,
    newAlgorithm: 'RS256 + ML-DSA-65 detached signature (hybrid)',
    changes: [
      'Added @noble/post-quantum (audited, pure-JS FIPS 204 implementation) for ML-DSA-65',
      'issueToken() now returns the RS256 JWT plus a detached ML-DSA-65 signature over the compact JWS',
      'verifyToken() requires BOTH the RS256 and the ML-DSA signature to verify',
      'RS256 path unchanged — existing consumers keep working while they add PQ verification',
    ],
    classification: {
      algorithm: 'RSA (JWT RS256)',
      key_size: '2048',
      usage_type: 'authentication',
      explanation:
        'The gateway issues RS256-signed JWTs that every downstream service trusts. Forged tokens would grant an attacker access to the whole API surface. RS256 relies on RSA, which quantum computers break, so this is classified High.',
    },
  },
};

/** Generic fallback for arbitrary snippets when the Claude API is unavailable. */
function genericPatch(finding: Finding): BuiltinRemediation {
  const isKem = finding.usageType === 'key_exchange';
  const lang = finding.language;
  const commentPrefix = lang === 'python' ? '#' : '//';
  const hybridNote = isKem
    ? `${commentPrefix} HYBRID MIGRATION (template): pair the existing classical key exchange with
${commentPrefix} ML-KEM-768 (NIST FIPS 203). Both parties derive the session key from the
${commentPrefix} concatenated classical + post-quantum shared secrets (X25519MLKEM768 pattern).`
    : `${commentPrefix} HYBRID MIGRATION (template): keep the existing classical signature and add
${commentPrefix} an ML-DSA-65 signature (NIST FIPS 204). Verifiers must check BOTH during the
${commentPrefix} hybrid period (draft-ietf-lamps-pq-composite-sigs pattern).`;

  const lib =
    lang === 'python'
      ? `${commentPrefix} Real implementation: liboqs-python — pip install oqs\n${commentPrefix}   pq = oqs.${isKem ? 'KeyEncapsulation("ML-KEM-768")' : 'Signature("ML-DSA-65")'}`
      : lang === 'java'
        ? `${commentPrefix} Real implementation: JDK 24+ (JEP 496/497) or BouncyCastle 1.79+\n${commentPrefix}   KeyPairGenerator.getInstance("${isKem ? 'ML-KEM-768' : 'ML-DSA-65'}")`
        : `${commentPrefix} Real implementation: @noble/post-quantum — npm i @noble/post-quantum\n${commentPrefix}   const { ${isKem ? 'ml_kem768' : 'ml_dsa65'} } = require('@noble/post-quantum/${isKem ? 'ml-kem' : 'ml-dsa'}.js')`;

  return {
    classification: {
      algorithm: finding.algorithm,
      key_size: 'unknown',
      usage_type: finding.usageType,
      explanation: `Detected ${finding.algorithm} used for ${finding.usageType.replace('_', ' ')}. This algorithm is breakable by a large-scale quantum computer and should be migrated to a hybrid classical + NIST post-quantum construction (${isKem ? 'ML-KEM, FIPS 203' : 'ML-DSA, FIPS 204'}).`,
    },
    patchedCode: `${hybridNote}\n${lib}\n\n${finding.fullCode}`,
    changes: [
      `Template patch: annotate the ${finding.algorithm} call sites with the hybrid ${isKem ? 'ML-KEM-768' : 'ML-DSA-65'} migration pattern`,
      'Connect a Claude API key (ANTHROPIC_API_KEY) for a full AI-generated patch of arbitrary code',
    ],
    newAlgorithm: isKem ? 'classical + ML-KEM-768 (hybrid)' : 'classical + ML-DSA-65 (hybrid)',
  };
}

export function builtinRemediation(finding: Finding): BuiltinRemediation {
  const seeded = SEEDED[`${finding.file}:${finding.findingKey}`];
  if (seeded) {
    return {
      classification: seeded.classification,
      patchedCode: seeded.patched,
      changes: seeded.changes,
      newAlgorithm: seeded.newAlgorithm,
    };
  }
  return genericPatch(finding);
}
