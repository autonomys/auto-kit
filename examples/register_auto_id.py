import os
from dotenv import load_dotenv
from substrateinterface import Keypair
from auto_identity import generate_ed25519_key_pair, self_issue_certificate, Registry


# Configuration
load_dotenv()
RPC_URL = os.getenv("RPC_URL")
KEYPAIR_URI = os.getenv("KEYPAIR_URI")


def main():
    # Initialize the signer keypair
    keypair = Keypair.create_from_uri(
        KEYPAIR_URI, ss58_format=42)

    # Initialize the Registry instance
    registry = Registry(rpc_url=RPC_URL, signer=keypair)

    keys = generate_ed25519_key_pair()
    certificate = self_issue_certificate("test", private_key=keys[0])

    # Attempt to register the certificate
    receipt = registry.register_auto_id(certificate)
    if receipt:
        print("Registration successful. Receipt:", receipt)
    else:
        print("Registration failed.")


if __name__ == "__main__":
    main()
