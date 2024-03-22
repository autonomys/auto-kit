from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta


def create_csr(subject_name, private_key):
    """
    Creates a Certificate Signing Request (CSR).

    :param subject_name: Subject name for the CSR (common name).
    :param private_key: Private key to sign the CSR with.
    :return: Created X.509 CertificateSigningRequest.
    """

    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])
    ).sign(private_key, None)

    return csr


def issue_certificate(csr, private_key, validity_period_days=365):
    """
    Issues a certificate for Certificate Signing Request (CSR).

    :param subject_name: Subject name for the certificate (common name).
    :param private_key: Private key to sign the certificate with.
    :param validity_period_days: Number of days the certificate is valid.
    :return: Created X.509 certificate.
    """

    certificate = x509.CertificateBuilder().subject_name(
        csr.subject,
    ).issuer_name(
        csr.subject,
    ).public_key(
        csr.public_key(),
    ).serial_number(
        x509.random_serial_number(),
    ).not_valid_before(
        datetime.now(),
    ).not_valid_after(
        datetime.now() + timedelta(days=validity_period_days),
    ).sign(private_key, None)

    return certificate


def self_issue_certificate(subject_name, private_key, validity_period_days=365):
    """
    Issues a self-signed certificate for the identity.

    :param subject_name: Subject name for the certificate (common name).
    :param private_key: Private key to sign the certificate with.
    :param validity_period_days: Number of days the certificate is valid.
    :return: Created X.509 certificate.
    """
    csr = create_csr(subject_name, private_key)
    certificate = issue_certificate(csr, private_key, validity_period_days)

    return certificate


def get_subject_common_name(certificate: x509.Certificate):
    """
    Retrieves the common name from the subject of the certificate.

    :param certificate: Certificate to retrieve the common name from.
    :return: Common name of the certificate.
    """
    return certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
