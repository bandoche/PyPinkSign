# coding=utf-8
import getpass
import hashlib
import os
import random
from os.path import expanduser

from Crypto.PublicKey import RSA

from read_cert import KoCertificate, select_cert, bit2string
from pkcs1 import emsa_pkcs1_v15
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type.univ import Sequence, ObjectIdentifier, Null, Set, Integer, OctetString
from pyasn1.type import tag

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

"""
TODO:
- native enveloping code (not hard-wired function)
"""


# utils
def url_encode(str):
    '''escape char to url encoding'''
    return str.replace(' ', '%20')


def paramize(param):
    '''make dict to param for get'''
    params = []
    for k in param:
        params.append("%s=%s" % (url_encode(k), url_encode(param[k])))

    return "&".join(params)


def select_cert_with_owner(cert_owner=None):
    '''updated select cert code from @twkang gist (https://gist.github.com/twkang/f5acf360c67ea0bf3f55)'''
    cert_list = []

    def adddir(a, d, f):
        l = os.path.split(d)[1]
        if l[:3] == "cn=":
            cert_list.append(d)

    def _df(d):
        return "20" + d[:2] + "/" + d[2:4] + "/" + d[4:6] + " " + \
               d[6:8] + ":" + d[8:10] + ":" + d[10:12]

    npki_path = expanduser("~/Documents/NPKI/")
    os.path.walk(npki_path, adddir, None)
    i = 1

    if cert_owner is not None:
        for p in cert_list:
            cert = KoCertificate(p)
            if cert.owner.find(cert_owner) > 0:
                return p
        raise Exception
        pass
    else:
        for p in cert_list:
            cert = KoCertificate(p)
            print "%2d: %s (valid: %s ~ %s)" % \
                (i, cert.owner, _df(cert.valid_date[0]), _df(cert.valid_date[1]))
            i += 1

        print
        sel = raw_input("Select Certificate: ")
        return cert_list[int(sel) - 1]
        pass


def pubkey_encrypt(server_key, plaintext):
    '''general function - encrypt plaintext with public key from server'''
    encrypted_key = server_key.encrypt(plaintext, None)[0]
    return encrypted_key


def seed_cbc_128_encrypt(key, plaintext, iv='0123456789012345'):
    '''general function - encrypt plaintext with seed-cbc-128(key, iv)'''
    backend = default_backend()
    cipher = Cipher(algorithms.SEED(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_text = padder.update(plaintext) + padder.finalize()
    encrypted_text = encryptor.update(padded_text)
    return encrypted_text


def seed_cbc_128_decrypt(key, ciphertext, iv='0123456789012345'):
    '''general function - decrypt ciphertext with seed-cbc-128(key, iv)'''
    backend = default_backend()
    cipher = Cipher(algorithms.SEED(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(ciphertext)
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_text = unpadder.update(decrypted_text) + unpadder.finalize()
    return unpadded_text


def seed_generator(size):
    '''general function - get random size-bytes string for seed'''
    return ''.join(chr(random.choice(range(255)) + 1) for _ in range(size))


def sign_msg(cert, msg, algorithm=hashlib.sha256, length=256):
    '''general function - return signed data(hashed/pkcs1/decrypt), part of SignData function'''
    hashed = emsa_pkcs1_v15.encode(msg, length, None, algorithm)
    aa = cert.pri_key.private_numbers()
    pri_key = RSA.construct((cert.pub_key.public_numbers().n, long(cert.pub_key.public_numbers().e), aa.d, aa.p, aa.q))
    return pri_key.decrypt(hashed)


def get_pubkey_from_cert(cert_msg):
    '''general function - extract public key from certificate'''
    if cert_msg[:2] == "MI":
        # feels like base64
        cert = cert_msg.decode('base64')

    der, _ = der_decoder.decode(cert)
    pub_cert = der[0][6][1]
    pub_der = der_decoder.decode(bit2string(pub_cert))
    return int(pub_der[0][0])


def get_cert(owner_name, password):
    '''wrap select_cert function'''
    if password is None:
        password = getpass.getpass("Password: ")

    if owner_name is None:
        cert = KoCertificate(select_cert(), password)
    else:
        cert = KoCertificate(select_cert_with_owner(owner_name), password)
    return cert


def get_signed_timestamp(paramized_timestamp_str, cert):
    '''get stringized parameter and sign with certification'''
    s = sign_msg(cert, paramized_timestamp_str, hashlib.sha256, 256)
    return s


def envelop_with_sign_msg(pub_cert, msg, signed):
    '''WIP: envelop with certificate
    pub_cert: binary data from file
    pri_cert: so we called KoCertificate
    '''

    owner_cert_pub = der_decoder.decode(pub_cert)

    # signedData (PKCS #7)
    oi_pkcs7_signed = ObjectIdentifier((1, 2, 840, 113549, 1, 7, 2))
    oi_pkcs7_data = ObjectIdentifier((1, 2, 840, 113549, 1, 7, 1))
    oi_sha256 = ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 1))
    oi_pkcs7_rsa_enc = ObjectIdentifier((1, 2, 840, 113549, 1, 1, 1))

    der = Sequence().setComponentByPosition(0, oi_pkcs7_signed)

    data = Sequence()
    data = data.setComponentByPosition(0, Integer(1))
    data = data.setComponentByPosition(1, Set().setComponentByPosition(0, Sequence().setComponentByPosition(0, oi_sha256).setComponentByPosition(1, Null(''))))
    data = data.setComponentByPosition(2, Sequence().setComponentByPosition(0, oi_pkcs7_data).setComponentByPosition(1, Sequence().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)).setComponentByPosition(0, OctetString(hexValue=msg.encode('hex')))))
    data = data.setComponentByPosition(3, Sequence().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)).setComponentByPosition(0, owner_cert_pub[0]))

    data4001 = Sequence().setComponentByPosition(0, owner_cert_pub[0][0][3])
    data4001 = data4001.setComponentByPosition(1, owner_cert_pub[0][0][1])
    data4002 = Sequence().setComponentByPosition(0, oi_sha256).setComponentByPosition(1, Null(''))
    data4003 = Sequence().setComponentByPosition(0, oi_pkcs7_rsa_enc).setComponentByPosition(1, Null(''))
    data4004 = OctetString(hexValue=signed.encode('hex'))

    data = data.setComponentByPosition(4, Set().setComponentByPosition(0, Sequence().setComponentByPosition(0, Integer(1)).setComponentByPosition(1, data4001).setComponentByPosition(2, data4002).setComponentByPosition(3, data4003).setComponentByPosition(4, data4004)))

    der = der.setComponentByPosition(1, Sequence().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)).setComponentByPosition(0, data))

    return der_encoder.encode(der)
