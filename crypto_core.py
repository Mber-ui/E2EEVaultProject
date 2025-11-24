import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


# -------------------------------------------------------
# AES–GCM ENCRYPTION
# -------------------------------------------------------

def generate_aes_key():
    """Generate a secure 256-bit AES key."""
    return AESGCM.generate_key(bit_length=256)


def aes_encrypt(aes_key: bytes, plaintext: bytes):
    """Encrypt data using AES-GCM. Returns (nonce, ciphertext, tag)."""
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def aes_decrypt(aes_key: bytes, nonce: bytes, ciphertext: bytes):
    """Decrypt AES-GCM ciphertext."""
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# -------------------------------------------------------
# RSA KEY MANAGEMENT
# -------------------------------------------------------

def generate_rsa_key_pair():
    """Generate RSA private + public key (PEM bytes)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


def load_public_key(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes)


def load_private_key(pem_bytes: bytes):
    return serialization.load_pem_private_key(pem_bytes, password=None)


# -------------------------------------------------------
# RSA WRAPPING / UNWRAPPING AES KEYS
# -------------------------------------------------------

def rsa_wrap_aes_key(public_pem: bytes, aes_key: bytes):
    """Encrypt AES key using RSA-OAEP."""
    pubkey = load_public_key(public_pem)
    encrypted = pubkey.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


def rsa_unwrap_aes_key(private_pem: bytes, wrapped_key: bytes):
    """Decrypt AES key using RSA-OAEP."""
    privkey = load_private_key(private_pem)
    decrypted = privkey.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted


# -------------------------------------------------------
# SAVE RSA KEYS TO VAULT (MISSING FUNCTION ADDED)
# -------------------------------------------------------

def save_rsa_keys(vault_dir: str, private_pem: bytes, public_pem: bytes):
    """
    Save RSA private_key.pem and public_key.pem into the vault directory.
    """
    priv_path = os.path.join(vault_dir, "private_key.pem")
    pub_path = os.path.join(vault_dir, "public_key.pem")

    with open(priv_path, "wb") as f:
        f.write(private_pem)

    with open(pub_path, "wb") as f:
        f.write(public_pem)

    return priv_path, pub_path
