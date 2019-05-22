"""
Basic Template system for project pinksign,
similar to the template part of PasteScript but without any dependencies.

"""

from .pypinksign import (
    PinkSign, get_npki_path, url_encode, paramize, choose_cert, seed_cbc_128_encrypt, seed_cbc_128_decrypt, seed_generator,
    bit2string, separate_p12_into_npki, encrypt_decrypted_prikey, inject_rand_in_plain_prikey
)
