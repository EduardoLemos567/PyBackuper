"""
:license:
    license is described in the LICENSE file provided.
    A copy can be accessed in: https://github.com/EduardoLemos567/PyBackuper/blob/master/LICENSE
:author:
    Eduardo Lemos de Moraes
"""
import oscrypto.util as crypt_util
import oscrypto.kdf as crypt_kdf
import oscrypto.symmetric as crypt_symm


def generate_salt():
    return crypt_util.rand_bytes(256)


def generate_app_key():
    """
    Generate a random str of bytes for the app_key
    """
    return crypt_util.rand_bytes(32)


def apply_salt(password, salt):
    """
    Apply salt to password and derive the hash, doing 2 millions of iterations.
    """
    return crypt_kdf.pbkdf2("sha512", password, salt, 2 * 1000 * 1000, 32)


class AESCipher:
    """
    For each session or file or message, we need to generate a different iv.
    You use the same iv on the same file and save it together.
    """

    IV_LENGTH = 16

    def __init__(self, salted_key, iv=None):
        self.salted_key = salted_key[
            :32
        ]  # this implementation supports only (256 bits) // 8 = 32 bytes.
        self.iv = iv if iv is not None else crypt_util.rand_bytes(self.IV_LENGTH)

    def encrypt(self, data):
        return crypt_symm.aes_cbc_pkcs7_encrypt(self.salted_key, data, self.iv)[1]

    def decrypt(self, data):
        try:
            return crypt_symm.aes_cbc_pkcs7_decrypt(self.salted_key, data, self.iv)
        except OSError as error:
            if str(error).startswith("error:06065064"):
                raise AttributeError(
                    "Could not decrypt the current data with given key. (possible wrong key)"
                ) from error
            else:
                raise error
