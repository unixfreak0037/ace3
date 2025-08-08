import pytest

from saq.crypto import InvalidPasswordError, PasswordNotSetError, decrypt_chunk, encrypt_chunk, encryption_key_set, get_aes_key, set_encryption_password

@pytest.mark.integration
def test_set_password():
    assert encryption_key_set()
    # verify the password
    aes_key = get_aes_key('test')
    assert isinstance(aes_key, bytes)
    assert len(aes_key) == 32

    # encrypt and decrypt something with this password
    encrypted_chunk = encrypt_chunk('Hello, World!'.encode(), password=aes_key)
    assert decrypt_chunk(encrypted_chunk, password=get_aes_key('test')) == 'Hello, World!'.encode()

@pytest.mark.integration
def test_change_password():
    assert encryption_key_set()
    # verify the password
    aes_key = get_aes_key('test')
    # now change the password to something else
    set_encryption_password('new password', old_password='test')
    # aes key should still be the same
    assert aes_key == get_aes_key('new password')

@pytest.mark.integration
def test_invalid_password():
    assert encryption_key_set()
    with pytest.raises(InvalidPasswordError):
        aes_key = get_aes_key('invalid_password')

@pytest.mark.integration
def test_encrypt_chunk():
    chunk = b'1234567890'
    encrypted_chunk = encrypt_chunk(chunk)
    assert chunk != encrypted_chunk
    decrypted_chunk = decrypt_chunk(encrypted_chunk)
    assert chunk == decrypted_chunk

@pytest.mark.integration
def test_encrypt_empty_chunk():
    chunk = b''
    encrypted_chunk = encrypt_chunk(chunk)
    assert chunk != encrypted_chunk
    decrypted_chunk = decrypt_chunk(encrypted_chunk)
    assert chunk == decrypted_chunk