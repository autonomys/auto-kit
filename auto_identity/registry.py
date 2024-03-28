from typing import Optional
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519
from substrateinterface import ExtrinsicReceipt, Keypair, SubstrateInterface, exceptions
from .utils import der_encode_signature_algorithm_oid, keccak_256


class Registry():
    """
    Registry class for managing identities on Autonomys identity domains.
    """

    def __init__(self, rpc_url: str = "ws://127.0.0.1:9944", signer=None):
        """
        Initialize the Registry class.

        Args:
            rpc_url (str): The URL of the RPC server.
            signer (Keypair): The signer keypair.
        """
        self.registry = SubstrateInterface(url=rpc_url)
        self.signer: Optional[Keypair] = signer

    def _compose_call(self, call_function: str, call_params: dict) -> Optional[ExtrinsicReceipt]:
        """
        Composes an extrinsic and calls the registry module.

        Args:
            call_function (str): The name of the call function.
            call_params (dict): The parameters for the call function.

        Returns:
            Optional[ExtrinsicReceipt]: The receipt of the extrinsic if successful, None otherwise.
        """
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

        Args:
            issuer_id: The issuer ID.
            certificate (x509.Certificate): The certificate to register.

        Returns:
            Optional[ExtrinsicReceipt]: The receipt of the extrinsic if successful, None otherwise.
        """
        call_params = {
            "X509": {
                "issuer_id": issuer_id,
                "certificate": certificate.tbs_certificate_bytes,
                "signature_algorithm": der_encode_signature_algorithm_oid(certificate.signature_algorithm_oid),
                "signature": certificate.signature,
            }
        }

        receipt = self._compose_call(
            call_function="register_auto_id", call_params=call_params)
        return receipt

    def get_auto_id(self, identifier):
        """
        Get an auto identity from the registry.

        Args:
            subject_name (str): The subject name of the certificate.

        Returns:
            The auto entity with the provided subject name.
        """

        result = self.registry.query('auto-id', 'AutoIds', [identifier])

        if result is None:
            return None

        # TODO map result to AutoEntity type
        auto_entity = result

        return auto_entity

    def verify(self, subject_name: str, public_key: ed25519.Ed25519PublicKey):
        """
        Verify a certificate from the registry.

        Args:
            subject_name (str): The subject name of the certificate.
            public_key (ed25519.Ed25519PublicKey): The public key to verify.

        Returns:
            bool: True if the certificate is valid, False otherwise.
        """
        entity = self.get_auto_id(subject_name)

        if entity is None:
            return False

        # TODO check public key and subject name match certificate, and that it is within the validity period

        return True
