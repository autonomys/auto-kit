from auto_identity import keccak_256


def test_keccak_256():
    data = b"hello"
    result = keccak_256(data)
    # https://emn178.github.io/online-tools/keccak_256.html?input_type=utf-8&input=hello
    assert result == "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
