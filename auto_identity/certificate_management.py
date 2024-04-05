from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from .key_management import do_public_keys_match


class CertificateManager:
    """
    Certificate management class.
    """

    def __init__(self,  certificate=None, private_key=None):
        """
        Initializes a certificate issuer.

        Args:
            certificate(Certificate): Certificate.
            private_key(PrivateKey): Private key.
        """
        self.private_key = private_key
        self.certificate = certificate

    @staticmethod
    def _to_common_name(subject_name):
        """
        Converts a subject name to a common name.

        Args:
            subject_name(str): Subject name for the certificate(common name).

        Returns:
            str: Common name.
        """
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])

    def _prepare_signing_params(self):
        """
        Prepares the signing parameters based on the key type.

        Returns:
            dict: Signing parameters.
        """
        private_key = self.private_key
        if isinstance(private_key, ed25519.Ed25519PrivateKey):
            return {"private_key": private_key, "algorithm": None}
        if isinstance(private_key, rsa.RSAPrivateKey):
            return {"private_key": private_key, "algorithm": hashes.SHA256()}

        raise ValueError("Unsupported key type for signing.")

    def create_csr(self, subject_name):
        """
        Creates a Certificate Signing Request(CSR).

        Args:
            subject_name(str): Subject name for the CSR(common name).

        Returns:
            CertificateSigningRequest: Created X.509 CertificateSigningRequest.
        """
        signing_params = self._prepare_signing_params()
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])
        ).sign(**signing_params)

        return csr

    def issue_certificate(self, csr, validity_period_days=365):
        """
        Issues a certificate for Certificate Signing Request(CSR).

        Args:
            csr(CertificateSigningRequest): Certificate Signing Request.
            issuer_certificate(Certificate): Issuer certificate.
            issuer_private_key(PrivateKey): Private key to sign the certificate with .
            validity_period_days(int, optional): Number of days the certificate is valid. Defaults to 365.

        Returns:
            Certificate: Created X.509 certificate.
        """
        if self.certificate is None:
            raise ValueError("Certificate is not set.")
        if self.private_key is None:
            raise ValueError("Private key is not set.")

        issuer_certificate = self.certificate

        # Verify that the public key derived from the private key matches the one in the issuer's certificate
        if not do_public_keys_match(issuer_certificate.public_key(), self.private_key.public_key()):
            raise ValueError(
                "Issuer certificate public key does not match the private key used for signing.")

        signing_params = self._prepare_signing_params()

        certificate = x509.CertificateBuilder().subject_name(
            csr.subject,
        ).issuer_name(
            issuer_certificate.subject,
        ).public_key(
            csr.public_key(),
        ).serial_number(
            x509.random_serial_number(),
        ).not_valid_before(
            datetime.now(timezone.utc),
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=validity_period_days),
        ).sign(**signing_params)

        return certificate

    def self_issue_certificate(self, subject_name: str, validity_period_days=365):
        """
        Issues a self-signed certificate for the identity.

        Args:
            subject_name(str): Subject name for the certificate(common name).
            private_key(PrivateKey): Private key to sign the certificate with .
            validity_period_days(int, optional): Number of days the certificate is valid. Defaults to 365.

        Returns:
            Certificate: Created X.509 certificate.
        """
        if self.private_key is None:
            raise ValueError("Private key is not set.")

        signing_params = self._prepare_signing_params()
        common_name = self._to_common_name(subject_name)

        certificate = x509.CertificateBuilder().subject_name(
            common_name,
        ).issuer_name(
            common_name,
        ).public_key(
            self.private_key.public_key(),
        ).serial_number(
            x509.random_serial_number(),
        ).not_valid_before(
            datetime.now(timezone.utc),
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=validity_period_days),
        ).sign(**signing_params)

        self.certificate = certificate
        return certificate

    @staticmethod
    def get_subject_common_name(certificate: x509.Certificate):
        """
        Retrieves the common name from the subject of the certificate.

        Args:
            certificate(x509.Certificate): Certificate to retrieve the common name from .

        Returns:
            str: Common name of the certificate.
        """
        return certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
