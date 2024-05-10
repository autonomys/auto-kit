import os
import random
import string
from dotenv import load_dotenv
from auto_identity import generate_ed25519_key_pair, CertificateManager, Registry, Keypair

# Configuration
load_dotenv()
RPC_URL = os.getenv("RPC_URL")
KEYPAIR_URI = os.getenv("KEYPAIR_URI")


def generate_random_string(length):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choices(characters, k=length))
    return random_string


def register(certificate, registry, issuer_id=None):
    # Attempt to register the certificate
    receipt, identifer = registry.register_auto_id(certificate, issuer_id)
    if receipt.is_success:
        print(f"Registration successful. {identifer}")
        return identifer
    else:
        print(f"Registration failed.", receipt)


def main():
    # Initialize the signer keypair
    substrate_keypair = Keypair.create_from_uri(
        KEYPAIR_URI, ss58_format=42)
    # Initialize the Registry instance
    registry = Registry(rpc_url=RPC_URL, signer=substrate_keypair)

    issuer_keys = generate_ed25519_key_pair()
    self_issued_cm = CertificateManager(private_key=issuer_keys[0])
    issuer_name = generate_random_string(10)
    issuer_cert = self_issued_cm.self_issue_certificate(issuer_name)
    issuer_id = register(self_issued_cm.certificate, registry)
    print(
        f"auto id from issuer cert: {CertificateManager.get_certificate_auto_id(issuer_cert)}")

    user_keys = generate_ed25519_key_pair()
    user_cm = CertificateManager(private_key=user_keys[0])
    user_name = generate_random_string(10)
    user_csr = user_cm.create_and_sign_csr(user_name)
    user_cert = self_issued_cm.issue_certificate(user_csr)
    CertificateManager.pretty_print_certificate(user_cert)
    _user_id = register(user_cert, registry, issuer_id)

    print(
        f"auto id from cert: {CertificateManager.get_certificate_auto_id(user_cert)}")


if __name__ == "__main__":
    main()
