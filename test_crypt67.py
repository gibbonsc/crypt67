import pytest
from crypt67 import encrypt67,decrypt67

SUBSTANTIAL_MSG = b"\x072\xd8\xcaO\x01E\xdc$\xa8%#C\x89\x8c8\xb9\xb2[\xd6\xdd%>7\xd5=\xa3\x10\xed\xaf\xea\x04\x93\x03v|&\xe2\xbc\xbdN\x9dn\x8e\xb5%AU\xd3*\xb02]3F\xe3\xe5\x06\xec\xa3\xfd\xca\x14\x0e\xc8\xcf\xc9\xab"
QUOTATION = b"One doesn't just learn to program. One learns to program something."

def test_encrypt67():
    """
    verify several test encryptions
    """
    assert encrypt67(b'K') == b'\x01\x93\x96'
    assert encrypt67(b'za') == 'W$'.encode()
    assert encrypt67(b'Ack') == b'\x021F\x17\xb0'
    assert encrypt67(b'n00B') == b'\x9d\x12\xc7\xbe'
    assert encrypt67(QUOTATION) == SUBSTANTIAL_MSG

def test_decrypt67():
    """
    verify several test decryptions
    """
    assert decrypt67(b'\x01\x96\x16') == 'c'.encode()
    assert decrypt67(b'\x01\xac\x02') == b'us'
    assert decrypt67(b'\x01\xa2\xb0\xab\xfb') == b'NaN'
    assert decrypt67(b'5\xfbW,') == b'1337'
    assert decrypt67(b'\x02\x06\x92P\xc4\xd52') == "OU812".encode()
    assert decrypt67(SUBSTANTIAL_MSG) == QUOTATION

if __name__ == "__main__":
    #arguments: verbose, line-by-line compact failure tracebacks,
    #  no short test summary after results, test with *this* file.
    pytest.main(["-v", "--tb=line", "-rN", __file__])
