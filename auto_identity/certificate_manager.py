from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from .key_management import do_public_keys_match


class CertificateManager:
    """
    Certificate management class.
    """

    def __init__(self,  certificate=None, private_key=None):
        """
        Initializes a certificate manager.

        Args:
            certificate(Certificate): Certificate.
            private_key(PrivateKey): Private key.
        """
        self.private_key = private_key
        self.certificate = certificate

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

    @staticmethod
    def certificate_to_pem(certificate: x509.Certificate):
        """
        Converts an x509 certificate to PEM format.

        Returns:
            bytes: PEM encoded certificate.
        """
        return certificate.public_bytes(serialization.Encoding.PEM)

    @staticmethod
    def pem_to_certificate(pem_bytes: bytes) -> x509.Certificate:
        """
        Converts PEM bytes to an x509 Certificate object.

        Args:
            pem_bytes (bytes): The PEM-encoded certificate as bytes.

        Returns:
            An x509.Certificate object.
        """
        certificate = x509.load_pem_x509_certificate(pem_bytes)
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

    @staticmethod
    def create_csr(subject_name, uri: str = None):
        """
        Creates an unsigned Certificate Signing Request(CSR).

        Args:
            subject_name(str): Subject name for the CSR(common name).

        Returns:
            CertificateSigningRequestBuilder: Created X.509 CertificateSigningRequestBuilder.
        """
        common_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])

        csr = x509.CertificateSigningRequestBuilder().subject_name(
            common_name)
        if uri:
            csr = csr.add_extension(
                x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]), critical=False)

        return csr

    def sign_csr(self, csr):
        """
        Signs a Certificate Signing Request(CSR).

        Args:
            csr(CertificateSigningRequest): Certificate Signing Request.

        Returns:
            CertificateSigningRequest: Created X.509 CertificateSigningRequest.
        """
        if self.private_key is None:
            raise ValueError("Private key is not set.")

        signing_params = self._prepare_signing_params()

        return csr.sign(**signing_params)

    def create_and_sign_csr(self, subject_name, uri: str = None):
        """
        Creates and signs a Certificate Signing Request(CSR).

        Args:
            subject_name(str): Subject name for the CSR(common name).

        Returns:
            CertificateSigningRequest: Created X.509 CertificateSigningRequest.
        """
        csr = self.create_csr(subject_name, uri)
        return self.sign_csr(csr)

    def issue_certificate(self, csr: x509.CertificateSigningRequest, validity_period_days=365):
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
        if self.private_key is None:
            raise ValueError("Private key is not set.")

        if self.certificate is None:
            issuer_name = csr.subject
        else:
            if not do_public_keys_match(self.certificate.public_key(), self.private_key.public_key()):
                raise ValueError(
                    "Issuer certificate public key does not match the private key used for signing.")
            issuer_name = self.certificate.subject

        # Prepare the certificate builder with information from the CSR
        certificate_builder = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            issuer_name
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            # Set the certificate's validity period
            datetime.utcnow() + timedelta(days=validity_period_days)
        )

        # Copy all extensions from the CSR to the certificate
        for extension in csr.extensions:
            certificate_builder = certificate_builder.add_extension(
                extension.value, extension.critical
            )

        return certificate_builder.sign(**self._prepare_signing_params())

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

        csr = self.sign_csr(self.create_csr(subject_name))
        certificate = self.issue_certificate(csr, validity_period_days)

        self.certificate = certificate
        return certificate

    def save_certificate(self, file_path: str):
        """
        Saves the certificate to a file.

        Args:
            file_path (str): Path to the file where the certificate should be saved.
        """
        certificate_data = self.certificate.public_bytes(
            serialization.Encoding.PEM)
        with open(file_path, "wb") as cert_file:
            cert_file.write(certificate_data)
