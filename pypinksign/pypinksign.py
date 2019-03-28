# coding=utf-8
import base64
from datetime import datetime
import hashlib
import os
import random
from os.path import expanduser
from sys import platform as _platform


from bitarray import bitarray
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography import x509

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type.univ import Sequence, ObjectIdentifier, Null, Set, Integer, OctetString
from pyasn1.type import tag

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers, RSAPrivateNumbers, rsa_crt_iqmp, \
    rsa_crt_dmp1, rsa_crt_dmq1
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from OpenSSL import crypto
from hashlib import sha1
# Python 2 and 3 compatibility
from builtins import input, range


id_seed_cbc = (1, 2, 410, 200004, 1, 4)
id_seed_cbc_with_sha1 = (1, 2, 410, 200004, 1, 15)
id_pkcs7_enveloped_data = (1, 2, 840, 113549, 1, 7, 3)


# class
class PinkSign:
    """Main class for PinkSign

    If the class has public attributes, they may be documented here
    in an ``Attributes`` section and follow the same formatting as a
    function's ``Args`` section. Alternatively, attributes may be documented
    inline with the attribute's declaration (see __init__ method below).

    Properties created with the ``@property`` decorator should be documented
    in the property's getter method.

    """

    def __init__(self, pubkey_path=None, pubkey_data=None, prikey_path=None, prikey_data=None, prikey_password=None, p12_path=None, p12_data=None):
        """
        Initialize
        :param pubkey_path: path for public key file (e.g "/some/path/signCert.der")
        :param pubkey_data(bytes): raw payload for public key file (e.g "0\x82...")
        :param prikey_path: path for private key file (e.g "/some/path/signPri.key")
        :param prikey_data(bytes): raw payload for private key file (e.g "0\x82...")
        :param prikey_password: passworkd for NPKI (e.g "h@ppy-chr1stm@s")
        :param p12_path: path for p12/pfx file (e.g "/some/path/p12file.pfx")
        :param p12_data: raw payload for p12/pfx (e.g "0\x82..."

        You can init like
        p = PinkSign()
        p = PinkSign(pubkey_path="/some/path/signCert.der")
        p = PinkSign(pubkey_path="/some/path/signCert.der", prikey_path="/some/path/signPri.key", prikey_password="my-0wn-S3cret")
        p = PinkSign(pubkey_data="0\x82...")
        p = PinkSign(p12_path='/some/path/p12file.pfx', prikey_password="h@ppy-chr1stm@s")
        You can get help with choose_cert() function.

        Order of parameter
        1) P12 oath
        2) P12 data
            A) Public Key path
            B) Public Key data

            A) Private Key path
            B) Private Key data
        """
        self.pubkey_path = pubkey_path
        self.prikey_path = prikey_path
        self.prikey_data = prikey_data
        self.prikey_password = prikey_password
        self.p12_path = p12_path
        self.p12_data = p12_data
        self.pub_cert = None
        self.prikey = None
        self.pubkey = None
        self.rand_num = None
        if p12_path is not None:
            self.load_p12()
        elif p12_data is not None:
            self.load_p12(p12_data=p12_data)
        else:
            if pubkey_path is not None:
                self.load_pubkey()
            elif pubkey_data is not None:
                self.load_pubkey(pubkey_data=pubkey_data)
            if prikey_path is not None and prikey_password is not None:
                self.load_prikey()
        return

    def load_pubkey(self, pubkey_path=None, pubkey_data=None):
        """Load public key file
        :param pubkey_path: (str) path for public key file
        :param pubkey_data: (bytes) raw data from public key file

        p = PinkSign()
        p.load_pubkey('/my/cert/signCert.der')
        p.load_pubkey(pubkey_data="0\x82...")

        """
        if not any([self.pubkey_path, pubkey_path, pubkey_data]):
            raise ValueError("Neither pubkey_path nor pubkey_data is exist.")

        if pubkey_data is not None:
            d = pubkey_data
        else:
            if pubkey_path is not None:
                self.pubkey_path = pubkey_path
            d = open(self.pubkey_path, 'rb').read()
        self.pub_cert = x509.load_der_x509_certificate(d, default_backend())  # Certificate
        self.pubkey = self.pub_cert.public_key()  # cryptography.hazmat.backends.openssl.rsa._RSAPublicKey
        return

    def load_prikey(self, prikey_path=None, prikey_data=None, prikey_password=None):
        """Load public key file

        p = PinkSign(pubkey_path='/my/cert/signCert.der')
        p.load_prikey('/my/cert/signPri.key', prikey_password='Y0u-m@y-n0t-p@ss')

        """
        if self.pubkey is None:
            raise ValueError("pubkey should be loaded first.")
        if not any([self.prikey_path, prikey_path, self.prikey_data, prikey_data]):
            raise ValueError("prikey_path(prikey_data) is not defined.")
        if not any([self.prikey_password, prikey_password]):
            raise ValueError("prikey_password is not defined.")

        if prikey_path is not None:
            self.prikey_path = prikey_path
        if prikey_data is not None:
            self.prikey_data = prikey_data
        if prikey_password is not None:
            self.prikey_password = prikey_password

        if self.prikey_path is not None:
            d = open(self.prikey_path, 'rb').read()
        else:
            d = self.prikey_data
        der = der_decoder.decode(d)[0]

        # check if correct K-PKI prikey file
        algorithm_type = der[0][0].asTuple()

        if algorithm_type not in (id_seed_cbc_with_sha1, id_seed_cbc):
            raise ValueError("prikey is not correct K-PKI private key file")

        salt = der[0][1][0].asOctets()  # salt for pbkdf#5
        iter_cnt = int(der[0][1][1])  # usually 2048
        cipher_key = der[1].asOctets()  # encryped private key
        dk = pbkdf1(self.prikey_password, salt, iter_cnt, 20)
        k = dk[:16]
        div = hashlib.sha1(dk[16:20]).digest()

        # IV for SEED-CBC has dependency on Algorithm type (Old-style K-PKI or Renewal)
        if algorithm_type == id_seed_cbc_with_sha1:
            iv = div[:16]
        else:
            iv = "123456789012345"

        prikey_data = seed_cbc_128_decrypt(k, cipher_key, iv)
        self._load_prikey_with_decrypted_data(decrypted_prikey_data=prikey_data)
        return

    def _load_prikey_with_decrypted_data(self, decrypted_prikey_data):
        der_pri = der_decoder.decode(decrypted_prikey_data)
        der_pri2 = der_decoder.decode(der_pri[0][2])

        # (n, e, d, p, q)
        (n, e, d, p, q) = (der_pri2[0][1], der_pri2[0][2], der_pri2[0][3], der_pri2[0][4], der_pri2[0][5])
        (n, e, d, p, q) = (int(n), int(e), int(d), int(p), int(q))
        iqmp = rsa_crt_iqmp(p, q)
        dmp1 = rsa_crt_dmp1(e, p)
        dmq1 = rsa_crt_dmq1(e, q)
        pn = RSAPublicNumbers(n=n, e=e)

        self.prikey = RSAPrivateNumbers(p=p, q=q, d=d, dmp1=dmp1, dmq1=dmq1, iqmp=iqmp,
                                        public_numbers=pn).private_key(backend=default_backend())
        if len(der_pri[0]) > 3:
            # sometimes, r value is not exist -  (i don't know why..)
            self._rand_num = der_pri[0][3][1][0]  # so raw data, can't be eaten
        return

    def load_p12(self, p12_data=None):
        """Load key information from P12(PKCS12, Usually pfx)"""
        if p12_data is None:
            p12_data = open(self.p12_path, 'rb').read()

        p12 = crypto.load_pkcs12(p12_data, self.prikey_password)
        prikey_data = crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey())
        prikey_data = prikey_data.replace(b'-----BEGIN PRIVATE KEY-----\n', b'').replace(b'\n-----END PRIVATE KEY-----', b'')
        prikey_data = base64.b64decode(prikey_data)
        pubkey_data = crypto.dump_certificate(crypto.FILETYPE_PEM, p12.get_certificate())
        pubkey_data = pubkey_data.replace(b'-----BEGIN CERTIFICATE-----\n', b'').replace(b'\n-----END CERTIFICATE-----', b'')
        pubkey_data = base64.b64decode(pubkey_data)
        self.load_pubkey(pubkey_data=pubkey_data)
        self._load_prikey_with_decrypted_data(decrypted_prikey_data=prikey_data)
        return

    def dn(self):
        """Get dn value

        p = PinkSign(pubkey_path="/some/path/signCert.der")
        print p.dn()  # "홍길순()0010023400506789012345"
        """
        if self.pub_cert is None:
            raise ValueError("Public key should be loaded for fetch DN.")
        for dn in self.pub_cert.subject.rdns:
            if dn.rfc4514_string().startswith('CN='):
                return dn.rfc4514_string()[3:]
        return ''

    def issuer(self):
        """Get issuer value

        p = PinkSign(pubkey_path="/some/path/signCert.der")
        print p.issuer()  # "yessign"
        """
        if self.pub_cert is None:
            raise ValueError("Public key should be loaded for fetch issuer.")
        for dn in self.pub_cert.issuer.rdns:
            if dn.rfc4514_string().startswith('O='):
                return dn.rfc4514_string()[2:]

    def cert_type(self):
        """Get issuer value

        p = PinkSign(pubkey_path="/some/path/signCert.der")
        print p.issuer()  # "yessignCA Class 2"
        """
        if self.pub_cert is None:
            raise ValueError("Public key should be loaded for fetch issuer.")
        for dn in self.pub_cert.issuer.rdns:
            if dn.rfc4514_string().startswith('CN='):
                return dn.rfc4514_string()[3:]

    def valid_date(self):
    def valid_date(self) -> (datetime, datetime):
        """Get valid date range

        p = PinkSign(pubkey_path="/some/path/signCert.der")
        print p.valid_date()  # datetime.datetime(2019, 6, 11, 14, 59, 59), datetime.datetime(2018, 6, 5, 7, 22)
        """
        if self.pub_cert is None:
            raise ValueError("Public key should be loaded for fetch valid date.")
        return self.pub_cert.not_valid_before, self.pub_cert.not_valid_after

    def serialnum(self):
        """Get serial number value

        p = PinkSign(pubkey_path="/some/path/signCert.der")
        print p.serialnum()  # 123456789
        print hex(p.serialnum())  # 0x1a2b3c4d
        """
        if self.pub_cert is None:
            raise ValueError("Public key should be loaded for fetch serial number.")
        return self.pub_cert.serial_number

    def sign(self, msg, algorithm=hashes.SHA256(), padding_=PKCS1v15()):
        """Signing with private key - pkcs1 encode and decrypt

        p = PinkSign(pubkey_path="/some/path/signCert.der", prikey_path="/some/path/signPri.key", prikey_password="my-0wn-S3cret")
        s = p.sign('my message')  # '\x00\x01\x02...'
        """
        if self.prikey is None:
            raise ValueError("Private key is required for signing.")
        return self.prikey.sign(data=msg, padding=padding_, algorithm=algorithm)

    def verify(self, signature, msg, algorithm=hashes.SHA256(), padding_=PKCS1v15()):
        """Verify with public key - encrypt and decode pkcs1 with hashed msg

        p = PinkSign(pubkey_path="/some/path/signCert.der")
        s = p.sign('my message')  # '\x00\x01\x02...'
        v = p.verify(s, 'my message')  # True
        """
        if self.pubkey is None:
            raise ValueError("Public key is required for verification.")
        try:
            self.pubkey.verify(data=msg, signature=signature, padding=padding_, algorithm=algorithm)
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            raise e

    def decrypt(self, msg, padding_=PKCS1v15()):
        """Decrypt with private key - also used when signing.

        p = PinkSign(pubkey_path="/some/path/signCert.der", prikey_path="/some/path/signPri.key", prikey_password="my-0wn-S3cret")
        msg = p.decrypt('\x0a\x0b\x0c...')  # 'my message'
        """
        if self.prikey is None:
            raise ValueError("Private key is required for decryption.")
        return self.prikey.decrypt(ciphertext=msg, padding=padding_)

    def encrypt(self, msg, padding_=PKCS1v15()):
        """Encrypt with public key - also used when verify sign

        p = PinkSign(pubkey_path="/some/path/signCert.der")
        encrypted = p.encrypt('my message')  # '\x0a\x0b\x0c...'
        """
        if self.pubkey is None:
            raise ValueError("Public key is required for encryption.")
        return self.pubkey.encrypt(msg, padding=padding_)

    # def pkcs7_sign_msg(self, msg):
    #     """WIP: PKCS#7 sign with certificate
    #     Sign and encapsulize message
    #     """
    #     signed = self.sign(msg)
    #
    #     owner_cert_pub = self.pub_cert
    #
    #     # signedData (PKCS #7)
    #     oi_pkcs7_signed = ObjectIdentifier((1, 2, 840, 113549, 1, 7, 2))
    #     oi_pkcs7_data = ObjectIdentifier((1, 2, 840, 113549, 1, 7, 1))
    #     oi_sha256 = ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 1))
    #     oi_pkcs7_rsa_enc = ObjectIdentifier((1, 2, 840, 113549, 1, 1, 1))
    #
    #     der = Sequence().setComponentByPosition(0, oi_pkcs7_signed)
    #
    #     data = Sequence()
    #     data = data.setComponentByPosition(0, Integer(1))
    #     data = data.setComponentByPosition(1, Set().setComponentByPosition(0, Sequence().setComponentByPosition(0, oi_sha256).setComponentByPosition(1, Null(''))))
    #     data = data.setComponentByPosition(2, Sequence().setComponentByPosition(0, oi_pkcs7_data).setComponentByPosition(1, Sequence().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)).setComponentByPosition(0, OctetString(hexValue=msg.encode('hex')))))
    #     data = data.setComponentByPosition(3, Sequence().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)).setComponentByPosition(0, owner_cert_pub))
    #
    #     data4001 = Sequence().setComponentByPosition(0, owner_cert_pub[0][3])
    #     data4001 = data4001.setComponentByPosition(1, owner_cert_pub[0][1])
    #     data4002 = Sequence().setComponentByPosition(0, oi_sha256).setComponentByPosition(1, Null(''))
    #     data4003 = Sequence().setComponentByPosition(0, oi_pkcs7_rsa_enc).setComponentByPosition(1, Null(''))
    #     data4004 = OctetString(hexValue=signed.encode('hex'))
    #
    #     data = data.setComponentByPosition(4, Set().setComponentByPosition(0, Sequence().setComponentByPosition(0, Integer(1)).setComponentByPosition(1, data4001).setComponentByPosition(2, data4002).setComponentByPosition(3, data4003).setComponentByPosition(4, data4004)))
    #
    #     der = der.setComponentByPosition(1, Sequence().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)).setComponentByPosition(0, data))
    #
    #     return der_encoder.encode(der)
    #
    # def pkcs7_enveloped_msg(self, msg, data, iv="0123456789012345"):
    #     """WIP: PKCS#7 envelop msg, data with cert"""
    #     oi_pkcs7_rsa_enc = ObjectIdentifier((1, 2, 840, 113549, 1, 1, 1))
    #     oi_pkcs7_data = ObjectIdentifier((1, 2, 840, 113549, 1, 7, 1))
    #     oi_seed_cbc = ObjectIdentifier(id_seed_cbc)
    #
    #     der = Sequence().setComponentByPosition(0, ObjectIdentifier(id_pkcs7_enveloped_data))
    #
    #     data_set = Sequence().setComponentByPosition(0, Integer(0))
    #     data_set = data_set.setComponentByPosition(1, Sequence().setComponentByPosition(0, self.pub_cert[0][3]).setComponentByPosition(1, self.pub_cert[0][1]))
    #     data_set = data_set.setComponentByPosition(2, Sequence().setComponentByPosition(0, oi_pkcs7_rsa_enc).setComponentByPosition(1, Null('')))
    #     data_set = data_set.setComponentByPosition(3, OctetString(hexValue=msg.encode('hex')))
    #
    #     data_seq = Sequence().setComponentByPosition(0, oi_pkcs7_data)
    #     data_seq = data_seq.setComponentByPosition(1, Sequence().setComponentByPosition(0, oi_seed_cbc).setComponentByPosition(1, OctetString(hexValue=iv.encode('hex'))))
    #     data_seq = data_seq.setComponentByPosition(2, OctetString(hexValue=data.encode('hex')).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)))
    #
    #     data = Sequence().setComponentByPosition(0, Integer(0))
    #     data = data.setComponentByPosition(1, Set().setComponentByPosition(0, data_set))
    #     data = data.setComponentByPosition(2, data_seq)
    #
    #     der = der.setComponentByPosition(1, Sequence().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)).setComponentByPosition(0, data))
    #     return der_encoder.encode(der)


# utils
def get_npki_path():
    """Return path for npki, depends on platform.
    This function can't manage certificates in poratble storage.
    Path for certifiacte is defined at http://www.rootca.or.kr/kcac/down/TechSpec/6.1-KCAC.TS.UI.pdf
    """
    if _platform == "linux" or _platform == "linux2":
        # linux
        path = expanduser("~/NPKI/")
    elif _platform == "darwin":
        # OS X
        suspect = ["~/Documents/NPKI/", "~/NPKI/", "~/Library/Preferences/NPKI/"]
        for p in suspect:
            path = expanduser(p)
            if os.path.isdir(path):
                return path
        raise ValueError("can't find certificate folder")

    elif _platform == "win32":
        # Windows Vista or above. Sorry for XP.
        suspect = ["C:/Program Files/NPKI/", "~/AppData/LocalLow/NPKI/"]
        for p in suspect:
            path = expanduser(p)
            if os.path.isdir(path):
                return path
        raise ValueError("can't find certificate folder")
    else:
        # default, but not expected to use this code.
        path = expanduser("~/NPKI/")
    return path


def url_encode(str):
    """Escape char to url encoding"""
    return str.replace(' ', '%20')


def paramize(param):
    """Make dict to param for get
    TODO: use urllib or else
    """
    params = []
    for k in param:
        params.append("%s=%s" % (url_encode(k), url_encode(param[k])))

    return "&".join(params)


def choose_cert(basepath=None, dn=None, pw=None):
    cert_list = []
    if basepath is not None:
        path = basepath
    else:
        path = get_npki_path()

    for root, dirs, files in os.walk(path):
        if root[-5:] == "/USER":
            for cert_dir in dirs:
                if cert_dir[:3] == "cn=":
                    cert_path = "%s/%s" % (root, cert_dir)
                    cert = PinkSign(pubkey_path="%s/signCert.der" % cert_path)
                    cert.prikey_path = "%s/signPri.key" % cert_path
                    if dn is not None:
                        if cert.dn().find(dn) > 0:
                            if pw is not None:
                                cert.load_prikey(prikey_path="%s/signPri.key" % cert_path, prikey_password=pw)
                            return cert
                    cert_list.append(cert)
    i = 1
    for cert in cert_list:
        (dn, (valid_from, valid_until), issuer) = (cert.dn(), cert.valid_date(), cert.issuer())
        print ("[%d] %s (%s ~ %s) issued by %s" % (i, dn, valid_from, valid_until, issuer))
        i += 1
    i = int(input("Choose your certifiacte: "))
    return cert_list[i - 1]


def seed_cbc_128_encrypt(key, plaintext, iv='0123456789012345'):
    """General function - encrypt plaintext with seed-cbc-128(key, iv)"""
    backend = default_backend()
    cipher = Cipher(algorithms.SEED(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_text = padder.update(plaintext) + padder.finalize()
    encrypted_text = encryptor.update(padded_text)
    return encrypted_text


def seed_cbc_128_decrypt(key, ciphertext, iv='0123456789012345'):
    """General function - decrypt ciphertext with seed-cbc-128(key, iv)"""
    backend = default_backend()
    cipher = Cipher(algorithms.SEED(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(ciphertext)
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_text = unpadder.update(decrypted_text) + unpadder.finalize()
    return unpadded_text


def seed_generator(size):
    """General function - get random size-bytes string for seed"""
    return ''.join(chr(random.choice(range(255)) + 1) for _ in range(size))


def bit2string(bit):
    """Convert bit-string asn.1 object to string"""
    # FIXME: not work
    return bitarray(bit.prettyPrint()[2:-3]).tobytes()


def bit2int(bit):
    """Convert bit-string asn.1 object to number"""
    return int(bit.prettyPrint())

# originally from https://pypi.python.org/pypi/PBKDF (Public Domain)
# modified for python2/3 compatibility
def pbkdf1(password, salt, c=1200, dk_len=20):
    """From PKCS#5 2.0 sect 5.1
    PBKDF1 (P, S, c, dkLen)
    Options: Hash underlying hash function
    Input: P password, an octet string
    S salt, an eight-octet string
    c iteration count, a positive integer
    dkLen intended length in octets of derived key, a positive integer, at most
    16 for MD2 or MD5 and 20 for SHA-1
    Output: DK derived key, a dkLen-octet string
    """
    # password, salt = checkTypes(password, salt, c, dkLen)
    dk_max_len = hashlib.sha1().digest_size

    assert dk_len <= dk_max_len, "derived key too long"
    assert len(salt) == 8, 'Salt should be 8 bytes'

    t = sha1(password + salt).digest()
    for _ in range(2, c + 1):
        t = sha1(t).digest()

    return t[:dk_len]
