from auto_identity import certificate_management, key_management
from cryptography import x509
from cryptography.x509.oid import NameOID


def test_create_csr():
    # Create a private key for testing
    private_key, _ = key_management.generate_ed25519_key_pair()

    # Define the subject name for the CSR
    subject_name = "Test"

    # Call the create_csr function
    csr = certificate_management.create_csr(subject_name, private_key)

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

    # Define the subject name for the certificate
    subject_name = "Test"

    # Call the create_csr function to generate a CSR
    csr = certificate_management.create_csr(subject_name, subject_private_key)

    # Issue a certificate using the CSR
    certificate = certificate_management.issue_certificate(
        csr, issuer_private_key)

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
    certificate = certificate_management.self_issue_certificate(
        "Test", private_key)

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
