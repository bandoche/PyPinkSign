# PyPinkSign
Small python code for K-PKI certificates. 공인인증서를 다루는 파이선 코드입니다.

## Support method
- Load personal purpose of [NPKI](http://www.nsic.go.kr/ndsi/help/pki.do?menuId=MN050503) a.k.a "[공인인증서](http://www.rootca.or.kr/kor/accredited/accredited03_05.jsp)"
- Encrypt, Decrypt, Sign, Verify (part of Public-key cryptography)
- Get Details (Valid date, Serial number, DN)
- PKCS#7 sign, envelop

## Usage example
```python
import pypinksign
p = pypinksign.PinkSign()
p.load_pubkey(pubkey_path="/path/signCert.der")
p.load_prikey(prikey_path="/path/signPri.key", prikey_password="my-0wn-S3cret")
sign = p.sign('1') 
verify = p.verify(sign, '1')  # True
```

```python
import pypinksign

# choose_cert function automatically fetch path for certificates
# and load certificate which match DN and passpharase for Private Key
p = pypinksign.choose_cert(dn="홍길순", pw="i-am-h0ng")
sign = p.sign('1') 
verify = p.verify(sign, '1')  # True
envelop = p.envelop_with_sign_msg('message')  # Envelop with K-PKI
```


## Requirement & Dependency
- Python 2.7 (Probably works with python 3 and above, but not tested)
- [PyCrypto](https://pypi.python.org/pypi/pycrypto) for Crypto.PublicKey
- [python-pkcs1](https://github.com/bdauvergne/python-pkcs1) for pkcs1
- [PyASN1](http://pyasn1.sourceforge.net) for pyasn1
- [cryptography](https://cryptography.io/en/latest/) for cryptography.hazmat
- [bitarray](https://pypi.python.org/pypi/bitarray/) 0.8.1 for bitarray.bitarray

## Installation

The easiest way to get PyPinkSign is if you have setuptools / distribute *or* pip installed

	easy_install pypinksign

or

	pip install pypinksign

The current development version can be found at 
[http://github.com/bandoche/pypinksign/tarball/master](http://github.com/bandoche/pypinksign/tarball/master)



## History

### Ver. 0.2.1
- Bug fix

### Ver. 0.2
- Add function for get serial number of cert.
- Remove README.rst in repository. 

### Ver. 0.1.1
- Add README.rst for PyPI.

### Ver. 0.1
- First release.

## Thanks to
- [item4](https://github.com/item4)

## See also
- [rootca.or.kr](http://rootca.or.kr/kor/standard/standard01A.jsp) - Technical Specification for K-PKI System
