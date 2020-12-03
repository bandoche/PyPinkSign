# PyPinkSign
Python code for PKI certificate. 공인인증서(공동인증서)를 다루는 파이썬 코드입니다.

## Status
[![CircleCI](https://circleci.com/gh/bandoche/PyPinkSign.svg?style=svg)](https://circleci.com/gh/bandoche/PyPinkSign) [![Build Status](https://travis-ci.org/bandoche/PyPinkSign.svg)](https://travis-ci.org/bandoche/PyPinkSign) [![codecov](https://codecov.io/gh/bandoche/PyPinkSign/branch/master/graph/badge.svg)](https://codecov.io/gh/bandoche/PyPinkSign)

## Support method
- Load personal purpose of PKI a.k.a "NPKI" or "[공인인증서](http://www.rootca.or.kr/kor/accredited/accredited03_05.jsp)"
- Encrypt, Decrypt, Sign, Verify (part of Public-key cryptography)
- Get Details (Valid date, Serial number, CN)
- PKCS#7 sign, envelop (WIP)

## Usage example

Load public key file and private key file.

```python
import pypinksign
p = pypinksign.PinkSign()
p.load_pubkey(pubkey_path="/path/signCert.der")
p.load_prikey(prikey_path="/path/signPri.key", prikey_password=b"my-0wn-S3cret")
sign = p.sign(b'1') 
verify = p.verify(sign, b'1')  # True
```

Load specific certificate. (by CN)

```python
import pypinksign

# choose_cert function automatically fetch path for certificates
# and load certificate which match CN and passpharase for Private Key
p = pypinksign.choose_cert(cn="홍길순", pw=b"i-am-h0ng")
sign = p.sign(b'1') 
verify = p.verify(sign, b'1')  # True
envelop = p.pkcs7_signed_msg(b'message')  # PKCS7 signed with K-PKI
```

Load PFX(p12) certificate.

```python
import pypinksign

# choose_cert function automatically fetch path for certificates
# and load certificate which match DN and passpharase for Private Key
p = pypinksign.PinkSign(p12_path="홍길순.pfx", prikey_password=b"i-am-h0ng")
p.load_prikey()
sign = p.sign(b'1') 
verify = p.verify(sign, b'1')  # True
envelop = p.pkcs7_enveloped_msg(b'message')  # Envelop with K-PKI - Temporary removed
```


## Requirement & Dependency
- Python 3.6 or above
- [PyASN1](http://pyasn1.sourceforge.net) for pyasn1
- [cryptography](https://cryptography.io/en/latest/) for cryptography.hazmat
- OpenSSL 1.1.1 or above due to cryptography package

## Installation

The easiest way to get PyPinkSign is pip

	pip install pypinksign

The current development version can be found at 
[http://github.com/bandoche/pypinksign/tarball/master](http://github.com/bandoche/pypinksign/tarball/master)



## History

### Ver. 0.4.4 (2020-12-03)
- Fix CRT related param error
- Remove PyOpenSSL dependency
- Remove old OpenSSL version dependency with pure SEED implementation.
  - If SEED algorithm is not supported by local OpenSSL, use python version of SEED algorithm automatically.

### Ver. 0.4.3 (2020-02-26)
- Fix seed_generator to generate bytes 

### Ver. 0.4.2 (2020-02-26)
- Test code fix

### Ver. 0.4.1 (2020-02-26)
- Add PKCS7 sign message.

### Ver. 0.4 (2020-02-26)
- Drop Python 2 support. 
- Support Python 3.6 or above.
- Add type hinting.
- Add test code.
- Add PBKDF2 for support PBES2 private key. (by [yongminz])
- Add function to inject `r` (rand num) value to private key. 
- Update `pyasn1` to `0.4.8`
- Update `cryptography` to `2.8`
- Update `pyOpenSSL` to `19.1.0`
- Temporary remove enveloping function.

### Ver. 0.3 (2017-03-14)
- Add support for PFX (PKCS 12).
- Add `PyOpenSSL` module for PFX support.
- Remove `PBKDF1` module.

### Ver. 0.2.3 (2016-09-19)
- Update `cryptography` dependency version to `1.5`.

### Ver. 0.2.2 (2016-07-25)
- You can load private key file from string.
- Update Docstring format.

### Ver. 0.2.1 (2016-06-23)
- Bug fix.

### Ver. 0.2 (2016-06-21)
- Add function for get serial number of cert.
- Remove README.rst in repository. 

### Ver. 0.1.1 (2015-06-07)
- Add README.rst for PyPI.

### Ver. 0.1 (2015-06-07)
- First release.

## Thanks to
- [item4](https://github.com/item4)
- [peio](https://github.com/peio) for [PBKDF1](https://github.com/peio/PBKDF/) code.
- [youngminz](https://github.com/youngminz) for PBES2 support.

## See also
- [rootca.or.kr](http://rootca.or.kr/kor/standard/standard01A.jsp) - Technical Specification for K-PKI System
