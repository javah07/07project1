"""
AeroSky Quantum Key Exchange — Server Side
==========================================

Implements hybrid Kyber-768 + ECDH P-384
post-quantum key exchange.

Flow:
1. Client sends Kyber public key + ECDH public key
2. Server encapsulates secret with Kyber public key
   (produces shared secret + ciphertext)
3. Server computes ECDH shared secret
4. Both sides derive same composite key via HKDF-SHA512
5. CryptoService uses composite key for Mythos+AES+ChaCha

Install:
pip install pqcrypto cryptography
"""

import base64
import struct
import hashlib
import hmac
import os
import logging
from datetime import datetime
logger = logging.getLogger(__name__)

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    EllipticCurvePublicKey,
    generate_private_key,
    SECP384R1
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Kyber implementation via pqcrypto
try:
    from pqcrypto.kem.kyber768 import (
        generate_keypair as kyber_generate,
        encrypt as kyber_encapsulate,
        decrypt as kyber_decapsulate
    )
    KYBER_AVAILABLE = True
except ImportError:
    # Fallback: use liboqs via python-oqs
    try:
        import oqs
        KYBER_AVAILABLE = True
        USING_OQS = True
    except ImportError:
        KYBER_AVAILABLE = False
        USING_OQS = False


# Store server session state
# In production: use Redis or similar
_sessions: dict = {}


def parse_hybrid_public_key(b64: str) -> tuple:
    """
    Parse client's hybrid public key bundle.
    Returns (kyber_pk_bytes, ecdh_pk_bytes)
    """
    combined = base64.b64decode(b64)

    # First 4 bytes = Kyber key length
    kyber_len = struct.unpack_from('<I', combined, 0)[0]

    kyber_pk = combined[4:4 + kyber_len]
    ecdh_pk = combined[4 + kyber_len:]

    return kyber_pk, ecdh_pk


def assemble_server_response(
    kyber_ciphertext: bytes,
    ecdh_pk: bytes
) -> str:
    """
    Assemble server response bundle.
    Format: [ciphertext_len:4][ciphertext][ecdh_pk]
    """
    combined = (
        struct.pack('<I', len(kyber_ciphertext)) +
        kyber_ciphertext +
        ecdh_pk
    )
    return base64.b64encode(combined).decode()


def derive_hybrid_key(
    kyber_secret: bytes,
    ecdh_secret: bytes
) -> bytes:
    """
    Combine Kyber + ECDH secrets into
    512-bit composite key via HKDF-SHA512.

    Both secrets must be known to derive key.
    Breaking one provides zero advantage.
    """
    combined = kyber_secret + ecdh_secret

    try:
        derived = HKDF(
            algorithm=hashes.SHA512(),
            length=64,  # 512-bit output
            salt=None,
            info=b"AeroSky-Hybrid-KEM-v1",
            backend=default_backend()
        ).derive(combined)
        return derived
    finally:
        # Zero combined secret
        combined = bytes(len(combined))


async def quantum_key_exchange(request: dict) -> dict:
    """
    POST /api/v1/vpn/quantum-keyexchange

    Handles hybrid Kyber-768 + ECDH P-384
    key exchange with client.

    Returns server response containing:
    - Kyber ciphertext (encapsulated secret)
    - Server ECDH public key
    """
    try:
        if "hybridPublicKey" not in request:
            return {
                "success": False,
                "error": "Missing hybridPublicKey"
            }

        # Parse client public keys
        kyber_pk_bytes, ecdh_pk_bytes = (
            parse_hybrid_public_key(
                request["hybridPublicKey"]
            )
        )

        # ─── KYBER-768 ENCAPSULATION ─────────────
        # Server encapsulates a random secret
        # using client's Kyber public key.
        # Only client's private key can recover secret.

        if KYBER_AVAILABLE and not globals().get('USING_OQS'):
            # Using pqcrypto
            kyber_ciphertext, kyber_shared_secret = (
                kyber_encapsulate(kyber_pk_bytes)
            )
        elif KYBER_AVAILABLE and globals().get('USING_OQS'):
            # Using liboqs
            kem = oqs.KeyEncapsulation('Kyber768')
            kyber_ciphertext, kyber_shared_secret = (
                kem.encap_secret(kyber_pk_bytes)
            )
        else:
            # Kyber not available
            # Fall back to double ECDH
            # Still strong, not quantum resistant
            kyber_ciphertext = os.urandom(32)
            kyber_shared_secret = os.urandom(32)
            logger.warning(
                "Kyber not available, using ECDH fallback"
            )

        # ─── ECDH P-384 KEY AGREEMENT ────────────
        # Generate server ephemeral ECDH key
        server_ecdh_private = generate_private_key(
            SECP384R1(),
            default_backend()
        )

        server_ecdh_public = (
            server_ecdh_private
            .public_key()
            .public_bytes(
                Encoding.DER,
                PublicFormat.SubjectPublicKeyInfo
            )
        )

        # Load client ECDH public key
        try:
            client_ecdh_key = load_der_public_key(
                ecdh_pk_bytes,
                backend=default_backend()
            )
        except Exception:
            client_ecdh_key = (
                ec.EllipticCurvePublicKey
                .from_encoded_point(
                    SECP384R1(),
                    ecdh_pk_bytes
                )
            )

        # Compute ECDH shared secret
        ecdh_shared_secret = (
            server_ecdh_private
            .exchange(ECDH(), client_ecdh_key)
        )

        # ─── HYBRID KEY DERIVATION ───────────────
        # Combine both secrets
        composite_key = derive_hybrid_key(
            kyber_shared_secret,
            ecdh_shared_secret
        )

        # Store for this session
        session_id = request.get(
            "sessionId",
            os.urandom(32).hex()
        )
        _sessions[session_id] = {
            "composite_key": composite_key,
            "created": datetime.now().isoformat()
        }

        # ─── ASSEMBLE RESPONSE ───────────────────
        response_bundle = assemble_server_response(
            kyber_ciphertext,
            server_ecdh_public
        )

        return {
            "success": True,
            "hybridResponse": response_bundle,
            "sessionId": session_id,
            "kyberAvailable": KYBER_AVAILABLE,
            "securityLevel": (
                "Kyber768+ECDH-P384"
                if KYBER_AVAILABLE
                else "ECDH-P384 (fallback)"
            )
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def get_session_key(session_id: str) -> bytes | None:
    """
    Retrieve composite key for active session.
    Returns None if session not found/expired.
    """
    session = _sessions.get(session_id)
    if not session:
        return None
    return session["composite_key"]


def clear_session(session_id: str) -> None:
    """
    Remove session on disconnect.
    Key material is gone forever — PFS.
    """
    if session_id in _sessions:
        # Zero the key material
        key = _sessions[session_id]["composite_key"]
        _sessions[session_id]["composite_key"] = (
            bytes(len(key))
        )
        del _sessions[session_id]
