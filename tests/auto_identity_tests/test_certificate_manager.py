from auto_identity import CertificateManager, key_management
from cryptography import x509
from cryptography.x509.oid import NameOID


def test_create_csr():
    # Create a private key for testing
    private_key, _ = key_management.generate_ed25519_key_pair()

    # Define the subject name for the CSR
    subject_name = "Test"

    csr_creator = CertificateManager(private_key=private_key)

    # Call the create_csr function
    csr = csr_creator.create_csr(subject_name)

    # Assert that the CSR is not None
    assert csr is not None

    # Assert that the CSR is of type x509.CertificateSigningRequest
    assert isinstance(csr, x509.CertificateSigningRequest)

    # Assert that the CSR subject name matches the provided subject name
    assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[
        0].value == subject_name

    # Assert that the CSR public key matches the private key's public key
    assert csr.public_key() == private_key.public_key()


# test issue_certificate
def test_issue_certificate():
    # Create a private key for testing
    subject_private_key, subject_public_key = key_management.generate_ed25519_key_pair()
    issuer_private_key, issuer_public_key = key_management.generate_ed25519_key_pair()

    issuer = CertificateManager(private_key=issuer_private_key)
    _issuer_certificate = issuer.self_issue_certificate("issuer")

    # Define the subject name for the certificate
    subject_name = "Test"

    csr_creator = CertificateManager(private_key=subject_private_key)
    # Call the create_csr function to generate a CSR
    csr = csr_creator.create_csr(subject_name)

    # Issue a certificate using the CSR
    certificate = issuer.issue_certificate(csr)

    # Assert that the certificate is not None
    assert certificate is not None

    # Assert that the certificate is of type x509.Certificate
    assert isinstance(certificate, x509.Certificate)

    # Assert that the certificate subject name matches the provided subject name
    assert certificate.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME)[0].value == subject_name

    # Assert that the certificate public key matches the private key's public key
    assert certificate.public_key() == subject_public_key

    cert_bytes = certificate.tbs_certificate_bytes
    signature = certificate.signature
    issuer_public_key.verify(signature, cert_bytes)


def test_self_issue_certificate():
    # Create a private key for testing
    private_key, public_key = key_management.generate_ed25519_key_pair()
    self_issuer = CertificateManager(private_key=private_key)
    certificate = self_issuer.self_issue_certificate("Test")

    # Define the subject name for the certificate
    subject_name = "Test"

    # Assert that the certificate is not None
    assert certificate is not None

    # Assert that the certificate is of type x509.Certificate
    assert isinstance(certificate, x509.Certificate)

    # Assert that the certificate subject name matches the provided subject name
    assert certificate.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME)[0].value == subject_name

    # Assert that the certificate public key matches the private key's public key
    assert certificate.public_key() == public_key

    cert_bytes = certificate.tbs_certificate_bytes
    signature = certificate.signature
    public_key.verify(signature, cert_bytes)


def test_get_subject_common_name():
    # Create a private key for testing
    private_key, _ = key_management.generate_ed25519_key_pair()
    subject_name = "Test"

    self_issuer = CertificateManager(private_key=private_key)
    certificate = self_issuer.self_issue_certificate("Test")

    # Retrieve the common name from the certificate
    common_name = self_issuer.get_subject_common_name(certificate)

    # Assert that the common name matches the provided subject name
    assert common_name == subject_name
