from cryptography.x509.oid import ObjectIdentifier
from pyasn1.type import namedtype, univ
from pyasn1.codec.der.encoder import encode


class AlgorithmIdentifier(univ.Sequence):
    """
    Represents an algorithm identifier.

    Attributes:
        algorithm (ObjectIdentifier): The algorithm identifier.
        parameters (Null): The parameters for the algorithm (assumed to be NULL in this example).
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
        # This example assumes NULL parameters for simplicity; adjust as needed
        namedtype.NamedType('parameters', univ.Null())
    )


def der_encode_signature_algorithm_oid(oid: ObjectIdentifier):
    """
    DER encodes the given signature algorithm OID.

    Args:
        signature_algorithm_oid (ObjectIdentifier): The signature algorithm OID to be DER encoded.

    Returns:
        bytes: The DER encoded OID.

    """
    algorithm_identifier = AlgorithmIdentifier()
    algorithm_identifier.setComponentByName('algorithm', oid.dotted_string)
    algorithm_identifier.setComponentByName('parameters', univ.Null())

    der_encoded_oid = encode(algorithm_identifier)
    return der_encoded_oid
