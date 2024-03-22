from typing import Optional
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519
from substrateinterface import Keypair, SubstrateInterface
from .utils import keccak_256


class Registry():
    """
    Registry class for managing identities on Autonomys identity domains.
    """

    def __init__(self, rpc_url: str = "ws://127.0.0.1:9944", signer=None):
        self.registry = SubstrateInterface(url=rpc_url)
        self.signer: Optional[Keypair] = signer

    def register(self, certificate: x509.Certificate):
        """
        Register a certificate in the registry.

        :param certificate: Certificate to register.
        """

        # TODO register the certificate in the registry

        # TODO return receipt
        return certificate

    def get_auto_entity(self, subject_name: str):
        """
        Get an auto identity from the registry.

        :param subject_name: Subject name of the certificate.
        :return: Certificate with the provided subject name.
        """

        # TODO in demo-chain app identifiers were keccak_256 hashes of the subject name,
        # we may not keep this convention
        identifier = keccak_256(subject_name.encode())
        result = self.registry.query('Registry', 'AutoID', [identifier])

        if result is None:
            return None

        # TODO map result to AutoEntity type
        auto_entity = result

        return auto_entity

    def verify(self, subject_name: str, public_key: ed25519.Ed25519PublicKey):
        """
        Get a certificate from the registry.

        :param subject_name: Subject name of the certificate.
        :return: Certificate with the provided subject name.
        """

        entity = self.get_auto_entity(subject_name)

        if entity is None:
            return False

        # TODO check public key and subject name match certificate, and that it is within the validity period

        return True
