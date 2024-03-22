import sha3


def keccak_256(data: bytes) -> str:
    """
    Compute the Keccak-256 hash of the input data.

    :param data: Input data to hash.
    :return: Keccak-256 hash of the input data.
    """

    result = sha3.keccak_256(data)
    return result.hexdigest()
