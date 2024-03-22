from typing import Optional
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from substrateinterface import ExtrinsicReceipt, Keypair, SubstrateInterface, exceptions
from .utils import keccak_256


class Registry():
    """
    Registry class for managing identities on Autonomys identity domains.
    """

    def __init__(self, rpc_url: str = "ws://127.0.0.1:9944", signer=None):
        self.registry = SubstrateInterface(url=rpc_url)
        self.signer: Optional[Keypair] = signer

    def _compose_call(self, call_function: str, call_params: dict) -> Optional[ExtrinsicReceipt]:
        """Composes an extrinsic and call the registry module."""
        if self.signer is None:
            return None

        call = self.registry.compose_call(
            call_module='auto_id',
            call_function=call_function,
            call_params=call_params,
        )

        extrinsic = self.registry.create_signed_extrinsic(
            call=call, keypair=self.signer)

        try:
            return self.registry.submit_extrinsic(extrinsic, wait_for_inclusion=True)

        except exceptions.SubstrateRequestException as e:
            print("Failed to send: {}".format(e))
            return None

    def register_auto_id(self, issuer_id, certificate: x509.Certificate):
        """
        Register a certificate in the registry.

        :param certificate: Certificate to register.
        """

        call_params = {
            "X509": {
                "issuer_id": issuer_id,
                "certificate": certificate.tbs_certificate_bytes,
                # TODO: DER encode?
                "signature_algorithm": certificate.signature_algorithm_oid,
                "signature": certificate.signature,
            }
        }

        receipt = self._compose_call(
            call_function="register_auto_id", call_params=call_params)
        return receipt

    def get_auto_id(self, subject_name: str):
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

        entity = self.get_auto_id(subject_name)

        if entity is None:
            return False

        # TODO check public key and subject name match certificate, and that it is within the validity period

        return True
