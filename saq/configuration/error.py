class ConfigurationException(Exception):
    """Thrown when ACE is unable to load the configuration."""
    pass

class EncryptedPasswordError(Exception):
    """Thrown whenever an attept is made to access a password that is encrypted without the decryption key loaded."""
    def __init__(self, key=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.key = key