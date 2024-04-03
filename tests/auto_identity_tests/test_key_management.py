from auto_identity import key_management
import os
import tempfile


def test_generate_rsa_key_pair():
    private_key, public_key = key_management.generate_rsa_key_pair()
    assert private_key is not None
    assert public_key is not None


def test_generate_ed25519_key_pair():
    private_key, public_key = key_management.generate_ed25519_key_pair()
    assert private_key is not None
    assert public_key is not None


def test_save_and_load_key():
    private_key, _ = key_management.generate_rsa_key_pair()

    # Use tempfile for creating a temporary file
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        file_path = tmp_file.name

    # Assuming save_key and load_private_key are implemented
    from auto_identity.key_management import save_key, load_private_key
    save_key(private_key, file_path, password="secret")

    loaded_key = load_private_key(file_path, password="secret")
    assert loaded_key is not None

    # Clean up
    os.remove(file_path)


def test_key_to_hex():
    private_key, _ = key_management.generate_ed25519_key_pair()
    hex_key = key_management.key_to_hex(private_key)

    assert hex_key is not None
    assert isinstance(hex_key, str)
