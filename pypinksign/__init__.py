"""
Basic Template system for project pinksign,
similar to the template part of PasteScript but without any dependencies.

"""

from pypinksign import (
    PinkSign, get_npki_path, url_encode, paramize, choose_cert, seed_cbc_128_encrypt, seed_cbc_128_decrypt, seed_generator,
    get_pubkey_from_pub, get_pub_e_from_pub, bit2string
)
