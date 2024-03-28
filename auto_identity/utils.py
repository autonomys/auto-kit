import sha3


def keccak_256(data: bytes) -> str:
    """
    Compute the Keccak-256 hash of the input data.

    Args:
        data (bytes): Input data to hash.

    Returns:
        str: Keccak-256 hash of the input data.
    """

    result = sha3.keccak_256(data)
    return result.hexdigest()
