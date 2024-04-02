import pathlib
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from auto_identity import der_encode_signature_algorithm_oid


def test_der_encode_algorithm2():
    # Load the certificate from a file
    cert_path = pathlib.Path('./tests/auto_identity_tests/issuer.cert.der')
    with open(cert_path, 'rb') as f:
        cert_data = f.read()

    # Load the certificate using cryptography
    cert = x509.load_der_x509_certificate(cert_data, default_backend())

    # Extract the OID of the signature algorithm
    signature_algorithm_oid = cert.signature_algorithm_oid

    der_encoded_oid = der_encode_signature_algorithm_oid(
        signature_algorithm_oid)

    # Compare the DER encoded OID with the result from tests in https://github.com/subspace/subspace/blob/d875a5aac35c1732eec61ce4359782eff58ff6fc/domains/pallets/auto-id/src/tests.rs#L127
    from_rust_implementation = "300d06092a864886f70d01010b0500"
    assert (der_encoded_oid.hex() == from_rust_implementation)
