from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives import serialization


def generate_rsa_key_pair(key_size: int = 2048) -> tuple:
    """
    Generates a RSA private and public key pair.

    Args:
        key_size (int): The size of the key in bits. Default is 2048.

    Returns:
        tuple: A tuple containing the RSA private key and public key.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def generate_ed25519_key_pair() -> tuple:
    """
    Generates an Ed25519 private and public key pair.

    Returns:
        tuple: A tuple containing the Ed25519 private key and public key.
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def save_key(key, file_path: str, password: str = None) -> None:
    """
    Saves a private or public key to a file. If it's a private key and a password is provided,
    the key will be encrypted.

    Args:
        key: The key to save (private or public).
        file_path (str): Path to the file where the key should be saved.
        password (str): Optional password to encrypt the private key.
    """
    if hasattr(key, 'private_bytes'):
        encoding = serialization.Encoding.PEM
        format = serialization.PrivateFormat.PKCS8
        encryption_algorithm = (serialization.BestAvailableEncryption(password.encode())
                                if password else serialization.NoEncryption())
        key_data = key.private_bytes(encoding, format, encryption_algorithm)
    else:
        encoding = serialization.Encoding.PEM
        format = serialization.PublicFormat.SubjectPublicKeyInfo
        key_data = key.public_bytes(encoding, format)

    with open(file_path, "wb") as key_file:
        key_file.write(key_data)


def load_private_key(file_path: str, password: str = None):
    """
    Loads a private key from a file. If the file is encrypted, a password must be provided.

    Args:
        file_path (str): Path to the private key file.
        password (str): The password used to encrypt the key file.

    Returns:
        The private key.
    """
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password.encode() if password else None,
            backend=default_backend()
        )
    return private_key


def load_public_key(file_path: str):
    """
    Loads a public key from a file.

    Args:
        file_path (str): Path to the public key file.

    Returns:
        The public key.
    """
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key
