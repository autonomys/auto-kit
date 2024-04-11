from typing import Optional, NamedTuple
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519
from substrateinterface import ExtrinsicReceipt, Keypair, SubstrateInterface, exceptions
from .utils import der_encode_signature_algorithm_oid


class RegistrationResult(NamedTuple):
    receipt: Optional[ExtrinsicReceipt]
    identifier: Optional[int]


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
            call_module='AutoId',
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

    def register_auto_id(self, certificate: x509.Certificate, issuer_id=None) -> RegistrationResult:
        """
        Register a certificate in the registry.

        Args:            
            certificate (x509.Certificate): The certificate to register.
            issuer_id: The issuer ID. If None, the ID will be self-issued.

        Returns:
            RegistrationResult: A named tuple containing the receipt of the extrinsic and the identifier if successful,
                                or None for both fields if unsuccessful.
        """

        base_certificate = {
            "certificate": certificate.tbs_certificate_bytes,
            "signature_algorithm": der_encode_signature_algorithm_oid(certificate.signature_algorithm_oid),
            "signature": certificate.signature,
        }
        if issuer_id is None:
            certificate_param = {"Root": base_certificate}
        else:
            certificate_param = {
                "Leaf": {
                    "issuer_id": issuer_id,
                    **base_certificate,
                }
            }

        req = {"req": {"X509": certificate_param}}

        receipt = self._compose_call(
            call_function="register_auto_id", call_params=req)

        if receipt.is_success:
            for event in receipt.triggered_events:
                event_data = event['event'].serialize()
                if event_data.get('event_id') == 'NewAutoIdRegistered':
                    identifier = event_data['attributes']
                    return RegistrationResult(receipt=receipt, identifier=identifier)

        return RegistrationResult(receipt=receipt, identifier=None)
