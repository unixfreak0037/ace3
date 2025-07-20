# vim: sw=4:ts=4:et:cc=120
#
# cryptography functions used by ACE
#

from getpass import getpass
import io
import logging
import os.path
import socket
import struct

from typing import Optional, Union

import Crypto.Random

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

from saq.configuration import get_config, get_config_value_as_int
from saq.constants import CONFIG_ENCRYPTION, CONFIG_ENCRYPTION_ITERATIONS, CONFIG_ENCRYPTION_SALT_SIZE, G_ECS_SOCKET_PATH, G_ENCRYPTION_INITIALIZED, G_ENCRYPTION_KEY, G_INSTANCE_TYPE, INSTANCE_TYPE_DEV
from saq.environment import g, g_boolean, set_g

CHUNK_SIZE = 64 * 1024

CONFIG_KEY_ENCRYPTION_KEY = 'encryption-key'
CONFIG_KEY_ENCRYPTION_SALT = 'encryption-salt'
CONFIG_KEY_ENCRYPTION_VERIFICATION = 'encryption-verification'
CONFIG_KEY_ENCRYPTION_ITERATIONS = 'encryption-iterations'

class PasswordNotSetError(Exception):
    """Thrown when an attempt is made to load the encryption key but it has not been set."""
    pass

class InvalidPasswordError(Exception):
    """Thrown when an invalid password is provided."""
    pass

def is_encryption_initialized() -> bool:
    """Returns True if encryption has been initialized."""
    return g_boolean(G_ENCRYPTION_INITIALIZED)

def encryption_key_set():
    """Returns True if the encryption key has been set, False otherwise."""
    from saq.configuration.database import get_database_config_value
    for key in [ 
        CONFIG_KEY_ENCRYPTION_KEY, 
        CONFIG_KEY_ENCRYPTION_SALT,
        CONFIG_KEY_ENCRYPTION_VERIFICATION,
        CONFIG_KEY_ENCRYPTION_ITERATIONS ]:
        if get_database_config_value(key) is None:
            return False

    return True

    #return os.path.exists(os.path.join(get_encryption_store_path(), 'key')) \
           #and os.path.exists(os.path.join(get_encryption_store_path(), 'salt')) \
           #and os.path.exists(os.path.join(get_encryption_store_path(), 'verification')) \
           #and os.path.exists(os.path.join(get_encryption_store_path(), 'iterations'))

def get_decryption_key(password):
    """Returns the 32 byte key used to decrypt the encryption key.
       Raises InvalidPasswordError if the password is incorrect.
       Raises PasswordNotSetError if the password has not been set."""
    from saq.configuration.database import get_database_config_value

    if not encryption_key_set():
        raise PasswordNotSetError()

    # the salt and iterations used are stored when we set the password
    salt = get_database_config_value(CONFIG_KEY_ENCRYPTION_SALT, bytes)
    iterations = get_database_config_value(CONFIG_KEY_ENCRYPTION_ITERATIONS, int)
    target_verification = get_database_config_value(CONFIG_KEY_ENCRYPTION_VERIFICATION, bytes)

    result = PBKDF2(password, salt, 64, iterations)
    if target_verification != result[32:]:
        raise InvalidPasswordError()

    return result[:32]

def get_aes_key(password):
    """Returns the 32 byte system encryption key."""
    from saq.configuration.database import get_database_config_value
    decryption_key = get_decryption_key(password)
    encrypted_key = get_database_config_value(CONFIG_KEY_ENCRYPTION_KEY, bytes)
    return decrypt_chunk(encrypted_key, decryption_key)

def set_encryption_password(password, old_password=None, key=None):
    """Sets the encryption password for the system. If a password has already been set, then
       old_password can be provided to change the password. Otherwise, the old password is
       over-written by the new password.
       If the key parameter is None then the PRIMARY AES KEY is random. Otherwise, the given key is used.
       The default of a random key is fine."""

    from saq.configuration import set_database_config_value

    assert isinstance(password, str)
    assert old_password is None or isinstance(old_password, str)
    assert key is None or (isinstance(key, bytes) and len(key) == 32)

    # has the encryption password been set yet?
    if encryption_key_set():
        # did we provide a password for it?
        if old_password is not None:
            # get the existing encryption password
            set_g(G_ENCRYPTION_KEY, get_aes_key(old_password))

    if g(G_ENCRYPTION_KEY) is None:
        # otherwise we just make a new one
        if key is None:
            #saq.ENCRYPTION_PASSWORD = Crypto.Random.OSRNG.posix.new().read(32)
            set_g(G_ENCRYPTION_KEY, Crypto.Random.get_random_bytes(32))
        else:
            set_g(G_ENCRYPTION_KEY, key)

    # now we compute the key to use to encrypt the encryption key using the user-supplied password
    #salt = Crypto.Random.OSRNG.posix.new().read(get_config()['encryption'].getint('salt_size', fallback=32))
    salt = Crypto.Random.get_random_bytes(get_config_value_as_int(CONFIG_ENCRYPTION, CONFIG_ENCRYPTION_SALT_SIZE, default=32))
    iterations =  get_config_value_as_int(CONFIG_ENCRYPTION, CONFIG_ENCRYPTION_ITERATIONS, default=8192)
    result = PBKDF2(password, salt, 64, iterations)
    user_encryption_key = result[:32] # the first 32 bytes is the user encryption key
    verification_key = result[32:] # and the second 32 bytes is used for password verification

    #create_directory(get_encryption_store_path())

    set_database_config_value(CONFIG_KEY_ENCRYPTION_VERIFICATION, verification_key)
    #with open(os.path.join(get_encryption_store_path(), 'verification'), 'wb') as fp:
        #fp.write(verification_key)

    encrypted_encryption_key = encrypt_chunk(g(G_ENCRYPTION_KEY), password=user_encryption_key)
    set_database_config_value(CONFIG_KEY_ENCRYPTION_KEY, encrypted_encryption_key)
    #with open(os.path.join(get_encryption_store_path(), 'key'), 'wb') as fp:
        #fp.write(encrypted_encryption_key)

    set_database_config_value(CONFIG_KEY_ENCRYPTION_SALT, salt)
    #with open(os.path.join(get_encryption_store_path(), 'salt'), 'wb') as fp:
        #fp.write(salt)

    set_database_config_value(CONFIG_KEY_ENCRYPTION_ITERATIONS, iterations)
    #with open(os.path.join(get_encryption_store_path(), 'iterations'), 'w') as fp:
        #fp.write(str(iterations))

def _get_password(password: Optional[Union[bytes, str]]=None) -> bytes:
    if password is None:
        return g(G_ENCRYPTION_KEY)

    if isinstance(password, str):
        h = SHA256.new()
        h.update(password.encode())
        return h.digest()

    if not isinstance(password, bytes) or len(password) != 32:
        raise ValueError("password must be 32 bytes")

    return password

# https://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
def encrypt(source_path, target_path, password=None):
    """Encrypts the given file at source_path with the given password and saves the results in target_path.
       If password is None then saq.ENCRYPTION_PASSWORD is used instead.
       password must be a byte string 32 bytes in length."""

    password = _get_password(password)
    #iv = Crypto.Random.OSRNG.posix.new().read(AES.block_size)
    iv = Crypto.Random.get_random_bytes(AES.block_size)
    encryptor = AES.new(password, AES.MODE_CBC, iv)
    file_size = os.path.getsize(source_path)

    with open(source_path, 'rb') as fp_in:
        with open(target_path, 'wb') as fp_out:
            fp_out.write(struct.pack('<Q', file_size))
            fp_out.write(iv)

            while True:
                chunk = fp_in.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)

                fp_out.write(encryptor.encrypt(chunk))

def encrypt_chunk(chunk, password=None):
    """Encrypts the given chunk of data and returns the encrypted chunk.
       If password is None then saq.ENCRYPTION_PASSWORD is used instead.
       password must be a byte string 32 bytes in length."""

    password = _get_password(password)
    #iv = Crypto.Random.OSRNG.posix.new().read(AES.block_size)
    iv = Crypto.Random.get_random_bytes(AES.block_size)
    encryptor = AES.new(password, AES.MODE_CBC, iv)

    original_size = len(chunk)

    if len(chunk) % 16 != 0:
        chunk += b' ' * (16 - len(chunk) % 16)

    result = struct.pack('<Q', original_size) + iv + encryptor.encrypt(chunk)
    return result

def decrypt(source_path, target_path=None, password=None):
    """Decrypts the given file at source_path with the given password and saves the results in target_path.
       If target_path is None then output will be sent to standard output.
       If password is None then saq.ENCRYPTION_PASSWORD is used instead.
       password must be a byte string 32 bytes in length."""

    password = _get_password(password)
    with open(source_path, 'rb') as fp_in:
        original_size = struct.unpack('<Q', fp_in.read(struct.calcsize('Q')))[0]
        iv = fp_in.read(16)
        decryptor = AES.new(password, AES.MODE_CBC, iv)

        with open(target_path, 'wb') as fp_out:
            while True:
                chunk = fp_in.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    break

                fp_out.write(decryptor.decrypt(chunk))

            fp_out.truncate(original_size)

def decrypt_chunk(chunk, password=None):
    """Decrypts the given encrypted chunk with the given password and returns the decrypted chunk.
       If password is None then saq.ENCRYPTION_PASSWORD is used instead.
       password must be a byte string 32 bytes in length."""

    password = _get_password(password)
    _buffer = io.BytesIO(chunk)
    original_size = struct.unpack('<Q', _buffer.read(struct.calcsize('Q')))[0]
    iv = _buffer.read(16)
    chunk = _buffer.read()

    #original_size = struct.unpack('<Q', chunk[0:struct.calcsize('Q')])[0]
    #iv = chunk[struct.calcsize('Q'):struct.calcsize('Q') + 16]
    #chunk = chunk[struct.calcsize('Q') + 16:]
    decryptor = AES.new(password, AES.MODE_CBC, iv)
    result = decryptor.decrypt(chunk)
    return result[:original_size]

def initialize_encryption(encryption_password_plaintext: Optional[str]=None, prompt_for_missing_password: Optional[bool]=False):
    try:
        # are we prompting for the decryption password?
        if encryption_password_plaintext:
            set_g(G_ENCRYPTION_KEY, get_aes_key(encryption_password_plaintext))
        elif prompt_for_missing_password:
            while True:
                encryption_password_plaintext = getpass("Enter the decryption password:")
                try:
                    set_g(G_ENCRYPTION_KEY, get_aes_key(encryption_password_plaintext))
                except InvalidPasswordError:
                    logging.error("invalid encryption password")
                    continue

                break

        elif encryption_key_set():
            # if we're not prompting for it then we can do one of two things
            # 1) pass it in via an environment variable SAQ_ENC
            # 2) run the encryption cache service 
            if "SAQ_ENC" in os.environ:
                logging.debug("reading encryption password from environment variable")
                encryption_password_plaintext = os.environ['SAQ_ENC']
                # Leave the SAQ_ENC variable in place if we are in the dev container environment.
                # This fixes the ability to load encrypted passwords when the container first starts up.
                if g(G_INSTANCE_TYPE) != INSTANCE_TYPE_DEV:
                    del os.environ["SAQ_ENC"]
                
                if encryption_password_plaintext == "test":
                    logging.warning("Using default encryption key 'test'. This is not recommended for production use.")

            if encryption_password_plaintext is not None:
                try:
                    set_g(G_ENCRYPTION_KEY, get_aes_key(encryption_password_plaintext))
                except InvalidPasswordError:
                    logging.error(f"encryption password is wrong")
                    ENCRYPTION_PASSWORD_PLAINTEXT = None

    except Exception as e:
        logging.error(f"unable to get encryption key: {e}")
        raise e

    set_g(G_ENCRYPTION_INITIALIZED, True)