"""
PyPinkSign - A package for managing certifications in Korea (NPKI)
"""

from .pypinkseed import (
    process_block, set_key
)
from .pypinksign import (
    PinkSign, get_npki_path, choose_cert, seed_cbc_128_encrypt, seed_cbc_128_decrypt,
    seed_generator, separate_p12_into_npki, encrypt_decrypted_prikey, inject_rand_in_plain_prikey,
    seed_cbc_128_decrypt_pure, seed_cbc_128_encrypt_pure, seed_cbc_128_encrypt_openssl, seed_cbc_128_decrypt_openssl,
)

# https://www.python.org/dev/peps/pep-0396/
__version__ = '0.5.3'

__all__ = [
    "PinkSign",
    "get_npki_path",
    "choose_cert",
    "seed_cbc_128_encrypt",
    "seed_cbc_128_decrypt",
    "seed_generator",
    "separate_p12_into_npki",
    "encrypt_decrypted_prikey",
    "inject_rand_in_plain_prikey",
    "seed_cbc_128_decrypt_pure",
    "seed_cbc_128_encrypt_pure",
    "seed_cbc_128_encrypt_openssl",
    "seed_cbc_128_decrypt_openssl",
    "process_block",
    "set_key",
]
