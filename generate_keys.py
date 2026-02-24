import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


# --------------------------------------------------------
# CONFIGURATION
# --------------------------------------------------------

# Set this as an environment variable on your server:
# export ELECTION_MASTER_KEY="your-very-strong-password"
MASTER_KEY = os.environ.get("ELECTION_MASTER_KEY")

if not MASTER_KEY:
    raise ValueError("ELECTION_MASTER_KEY environment variable not set.")


# --------------------------------------------------------
# KEY GENERATION FUNCTION
# --------------------------------------------------------

def generate_election_keypair():
    """
    Generates an RSA keypair for an election.
    Returns:
        public_key_pem (str)
        encrypted_private_key_pem (str)
    """

    # 1. Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # 2. Extract public key
    public_key = private_key.public_key()

    # 3. Serialize public key (PEM format)
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # 4. Serialize and encrypt private key using server master key
    encrypted_private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            MASTER_KEY.encode()
        )
    )

    return public_key_pem.decode(), encrypted_private_key_pem.decode()


# --------------------------------------------------------
# PRIVATE KEY DECRYPTION (FOR TALLY PHASE)
# --------------------------------------------------------

def load_private_key(encrypted_private_key_pem: str):
    """
    Decrypts and loads the private key for tallying.
    """

    private_key = serialization.load_pem_private_key(
        encrypted_private_key_pem.encode(),
        password=MASTER_KEY.encode(),
        backend=default_backend()
    )

    return private_key