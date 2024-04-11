import os
from dotenv import load_dotenv
from auto_identity import generate_ed25519_key_pair, CertificateManager, Registry, Keypair


# Configuration
load_dotenv()
RPC_URL = os.getenv("RPC_URL")
KEYPAIR_URI = os.getenv("KEYPAIR_URI")


def register(certificate, registry, issuer_id=None):
    # Attempt to register the certificate
    receipt, identifer = registry.register_auto_id(certificate, issuer_id)
    if receipt.is_success:
        print(f"Registration successful. {identifer}")
        return identifer
    else:
        print("Registration failed.")


def main():
    # Initialize the signer keypair
    substrate_keypair = Keypair.create_from_uri(
        KEYPAIR_URI, ss58_format=42)
    # Initialize the Registry instance
    registry = Registry(rpc_url=RPC_URL, signer=substrate_keypair)

    keys = generate_ed25519_key_pair()
    self_issued_cm = CertificateManager(private_key=keys[0])
    self_issued_cm.self_issue_certificate("test")
    issuer_id = register(self_issued_cm.certificate, registry)

    user_keys = generate_ed25519_key_pair()
    user_cm = CertificateManager(private_key=user_keys[0])
    user_csr = user_cm.create_and_sign_csr("user")
    user_cert = self_issued_cm.issue_certificate(user_csr)
    register_user = register(user_cert, registry, issuer_id)


if __name__ == "__main__":
    main()
