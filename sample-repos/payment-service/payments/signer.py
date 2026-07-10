"""Transaction signing for the payments service.

Every outbound settlement message is signed before it is handed to the
clearing network. Keys are rotated quarterly by ops (see runbook PAY-114).
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


def generate_keys():
    """Generate the service signing keypair (rotated quarterly)."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def sign_transaction(private_key, transaction_bytes):
    """Sign a serialized settlement transaction.

    The signature travels with the transaction to the clearing network,
    which verifies it against our published public key.
    """
    signature = private_key.sign(
        transaction_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


def verify_transaction(public_key, transaction_bytes, signature):
    """Verify a settlement signature (used by the reconciliation job)."""
    public_key.verify(
        signature,
        transaction_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return True


def export_public_key(private_key):
    """PEM-encode the public half for the clearing network onboarding form."""
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
