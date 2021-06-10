# coding=utf-8
import base64
import datetime
import os
import tempfile
import unittest
from unittest import TestCase

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers, RSAPrivateNumbers
from pyasn1.codec.der import decoder as der_decoder

from . import PinkSign, seed_cbc_128_encrypt, seed_cbc_128_decrypt, seed_generator, separate_p12_into_npki, \
    encrypt_decrypted_prikey, inject_rand_in_plain_prikey, seed_cbc_128_decrypt_pure, seed_cbc_128_encrypt_pure, \
    seed_cbc_128_encrypt_openssl, seed_cbc_128_decrypt_openssl, set_key, process_block

# Test certificate data

TEST_CERT = {
    'signCert': 'MIIFtDCCBJygAwIBAgIDRZx1MA0GCSqGSIb3DQEBCwUAMFcxCzAJBgNVBAYTAmtyMRAwDgYDVQQKDAd5ZXNzaWduMRUwEwYDVQQLD'
                'AxBY2NyZWRpdGVkQ0ExHzAdBgNVBAMMFnllc3NpZ25DQS1UZXN0IENsYXNzIDQwHhcNMjAwMjI0MTUwMDAwWhcNMjAwMzI1MTQ1OT'
                'U5WjB7MQswCQYDVQQGEwJrcjEQMA4GA1UECgwHeWVzc2lnbjEUMBIGA1UECwwLcGVyc29uYWw0SUIxEDAOBgNVBAsMB0lOSVRFQ0g'
                'xMjAwBgNVBAMMKUhLRChLSUxET05HLkhPTkcpMDA5MTA0MTIwMjAwMjI1MTkxMDAwMDMwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A'
                'MIIBCgKCAQEAgQsW0pBCC6tBH8PEqG0Y66ivm+O3FS70TxqSWJnhT86baZnpjYMa0hYRGbGdyYc1Voovz1fQfZryFUI8mQb1BzXn/'
                'HVXPbG1u50UZLncoFAIvRhRYXtgSzRgiddjSN2S5gM1DM3i2e4BRMi2E0VOUBkSNBjzjaebTlRYDZKNWyFvW8Hvf4ylFmiH'
                '+cvfN1IS4VEBQudXDysZ739mlNSSh0064/19aZQGIBGP8d9/WA7Yy3OgMuvOoQb00wemVquLka0pPxoI'
                '/1wCJHKnrKnl3qxRjjLHw/+tKpGL845PFF0W3lzjEEXd3clq'
                '+5U6stYTPAv1LUJeAQrMEggWkWJ7gwIDAQABo4ICYzCCAl8wgZMGA1UdIwSBizCBiIAUZjXs6P3+27gqYqkCsebch1zc'
                '+cOhbaRrMGkxCzAJBgNVBAYTAktSMQ0wCwYDVQQKDARLSVNBMS4wLAYDVQQLDCVLb3JlYSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eS'
                'BDZW50cmFsMRswGQYDVQQDDBJLaXNhIFRlc3QgUm9vdENBIDeCAQIwHQYDVR0OBBYEFKmrmL0khR7NYl8f3XkLVKqMgX72MA4GA1Ud'
                'DwEB/wQEAwIGwDB+BgNVHSABAf8EdDByMHAGCSqDGoyaRQEBBDBjMDAGCCsGAQUFBwICMCQeIsd0ACDHeMmdwRyylAAgwtzV2MapAC'
                'DHeMmdwRzHhbLIsuQwLwYIKwYBBQUHAgEWI2h0dHA6Ly9zbm9vcHkueWVzc2lnbi5vci5rci9jcHMuaHRtMGIGA1UdEQRbMFmgVwYJ'
                'KoMajJpECgEBoEowSAwDSEtEMEEwPwYKKoMajJpECgEBATAxMAsGCWCGSAFlAwQCAaAiBCCK1PZzQS+CXaTR+01CFpRrvH+BlKCvAf'
                'hmIu4jx+4N5zB2BgNVHR8EbzBtMGugaaBnhmVsZGFwOi8vc25vb3B5Lnllc3NpZ24ub3Iua3I6NjAyMC9vdT1kcDE4cDM5NSxvdT1B'
                'Y2NyZWRpdGVkQ0Esbz15ZXNzaWduLGM9a3I/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdDA8BggrBgEFBQcBAQQwMC4wLAYIKwYBBQ'
                'UHMAGGIGh0dHA6Ly9zbm9vcHkueWVzc2lnbi5vci5rcjo0NjEyMA0GCSqGSIb3DQEBCwUAA4IBAQCJZFvhY4YaLsY+j'
                '+ZfEeCHn3il3tm0vSVEy7bN3cpXu9yccEQwWeZnhF7ayDFH1NK5UX0MBA4JHmeuC6Qj6OF68UQLtZCaQw3OILSGio'
                '/uFzQRMVnctVHwhXz1RxZoyfilOiSepX9FDTJeURk9OYOWjyLX+oUVUgAjfo6aqHUiql1VO7i8j2VFwyX8ARVO5n2mPVrfjMG'
                '+SE107dW+uUsWQtX3E5kO1jtINbvPn5oapcm1wFAR20Fs/APZ4xxODx4539C6bula47FrLq1qxz+rFaRdAFmddyM4wv8OZF4l'
                '/hbg7vKsFbceJB5wPIobxfKYRaGysjyD/G595AAGTkCs',
    'signPri': 'MIIFEDAaBggqgxqMmkQBDzAOBAjI6i+iUCPChQICCAAEggTwMST3W7ufOC++4ZRMDspf7BvMcMKi0UakUTLYykkGLMFhDVVbktK'
               '/mIXP6qtUfkm3LvtXjF54xehoyF/joZdxXSbFvFnQlC2Pcuy99Tzz+4Zmr940Oc2'
               '/P9OD8SgNIc2k1M0aykrnwgP1XSrDkujKBWlMDuPVZkdNvntMI1PcldoJHNyP0fmvS1ZjSIjuFDFKWuTErP33Xt3Os9XgYA2ySzHP'
               '8xIEcxnl5yfBZVPOY2FmP9YIBV2MjHKxXABIfmwn95FFw8RtV5/Lw3jmBmYq0n2jUyL7lxCddyNIJDZN7ZsCnnx66OB+CqV6jwVI'
               '/oxHipiXGwv3UjrHUY1Ydxvbo4KYSS+RGywKL/LFc2b+ToAsw2TJiPU8jV8RbMz++PgOyvyo6NS33j1xhMf5YaGtTNqRw7'
               '+kGNk5tuSKDSTr5zOkK2vnFcP9KM1XpyNsOOHPrJt9JrXaZ3aRSjHciOVAM9FpbzYKwldr6I1k7k2UkEJsrpwwVt8Pi7FQ'
               '/42LDEeyP2TL7ITELLYmiyAjGlKjrfTurBmju+tsB6C8qeuAMZo2EZ8/LH79crrvnqtY0ZWalNZvQLtPsUZ9wVf4EsXbc4Sm'
               '+mkU4dIVl2/BrkNEQjS4O17zVHLPpH/M41Ftx0U7ja3h+ne3J9GvN7PWYir18G8Zly5lsdI670'
               '+MVfKqhSwcLGgBBVvs3qbTFMITjvYFvYelK+CWEJdlCHti+mlA7tA'
               '/GK2MUwQy7ngVOEdHjxMjcn0F9RdVOxnuGuYXfQcNfFlPEcZRPHl772X/3BaNW0gqbaA9HQ/UZMEzwG'
               '+dHE4zbwAc33reae0Q6FWtFYWcMLkeyBw/AL/hcQ0rp61Ae7dfpLie69OfyespYLasSRzrMg6E73UPwc4ydiX1ZK'
               '+5sShIqeZAHE4W9yRk+BxUs0Fyj2PWTAUNiIvfVwmGxBrZ0CM/Iymvska9mwzNIZszxG2ebX9XAU031F/0'
               '+e8yOuYqjCneFVhFvvCgpllfc6jHy7XhCOG7fT2SoUzxJdnYe7BYI1eC3F4Kqi9qSdYUcnMgZWjNRfbc50bBXxd'
               '/mJu7r5rRlCmP1scgH9gJZ9beRNq8q/r13xhaHyaIzy1vAHkhfBrzb5pwNO4RR2gP80cKQXRW/pS9nh'
               '/e3dmYEA8TojvAgmT8pMn5HRh9znmN0u2NpxrFjOV+NFWb4l1o47XKsosV4nIe0s'
               '/3W4f8WjsS2Q16ag3hpZ60k5UyeHv5exV0UHViA5fbwHf/zVqYXpEQP6hHu8miVo5bF+BTReXyKrP8wgy30jGG1'
               '+OWWOwI1CJsPzGqpkcp91LatTaCgDV5ex9gglefBHT55J68jmVKLwMng5a54x39WpumStd19WbeqgcPX1bbkRylTg0d322w1UiEEV'
               'lrogh4G9uNZHwT2RtEV6bIeCLbXUJbtTdUh267ppwutQk+hUpj8A91Yx3UsLhV9wBQPbbTBlfxhCw9nt3hRReNGwH1g1'
               '/DYQXaKNYuPnw5i4lkV6XF+asyqkrFVrzLGM4VvQ0HeR91RUwTbPo+wQHWrFEjAE/Kk75YCdg/H27ArsWfi/QXCm72hex4'
               '/XAIkydoEgznMs3kTnU8XdGvtrXYrid1svzBAGqxLYaRj292o8oVxz+rpMCL8TZA3gQJ47HcyngTZUvuau1KpaOVrE2Eo/LHIRQk'
               '/0U0Ew==',
    'plainSignPri': 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCBCxbSkEILq0Efw8SobRjrqK'
                    '+b47cVLvRPGpJYmeFPzptpmemNgxrSFhEZsZ3JhzVWii'
                    '/PV9B9mvIVQjyZBvUHNef8dVc9sbW7nRRkudygUAi9GFFhe2BLNGCJ12NI3ZLmAzUMzeLZ7gFEyLYTRU5QGRI0GPONp5tOVFgN'
                    'ko1bIW9bwe9/jKUWaIf5y983UhLhUQFC51cPKxnvf2aU1JKHTTrj/X1plAYgEY/x339YDtjLc6Ay686hBvTTB6ZWq4uRrSk'
                    '/Ggj/XAIkcqesqeXerFGOMsfD/60qkYvzjk8UXRbeXOMQRd3dyWr7lTqy1hM8C'
                    '/UtQl4BCswSCBaRYnuDAgMBAAECggEARKrb+CxfmMoGm5qXOXDkg/J9kBy6vgEAbF'
                    '+dZJxt8wPkW2tVhsIvMYAglWWYqzbRwT1Dd7go783V6E4Y5O140d9zlTnztJauOCm8QmVM69nq7ITWOWNnuF0kyfTdllah5tfq'
                    'EOg2QPWPo0SS7upAZAsTTrnAUK7Ry/rB6GcF5Wm5wAp1nWZTr6q+QqcA/w60wIPyuvkhR/H3LMdW/is2rk0y7uQ2MOWXLtJAds'
                    '4MOQt1YypjgzWuPuNr9I28r1NmKAQXrxlfJq/AC9MvuiEP/jZL1srcBJpl4ZXmv+ligEGEhxL1htJ/jVk9zaoXFpUuxLhtTzJ1'
                    'wIecAYcdRktWAQKBgQDyqL1572xla7XlGu4j/5VgCNddEuu+iVdhfL1JmzVLqjPeUnv3UJzQn10GmL8kjW6slrC8qJ1LoppB0q'
                    'sE+LbBO/5yxDo0sf4mBm7sy2gF3c6leyA3Edy4d59JYLFQIRk'
                    '+DWKZAWixiFu1CWtcixlHeP73tgrrfh1PdDgyEtazgQKBgQCII0jkUhjt67B2weAvicdyYpuIGFjDIpJKtr6A07pX1sWyoVa79'
                    'J2138WHNiqJOIh9BdOP2+04ze8ueO2OZ86Mjz8bWOiQG0gce9WiNJkU72wYpnvLtFXw3gXyBKDuYKf7se4ksgh7Cr0C5jpzyIq'
                    'IEQtcOOzMy4CtxrTQahrhAwKBgG9g9j8+nvFaZA35s27AhE6lIDzvT1eQcJQljjh3zhmh0Nbt40qcLK4xR6CcgbeEV1VOgWbGu'
                    'hQaWVV3HdpVUoUVRXBmExVW0YGgmE+F+YQf0BbykdHVGAtvlKQ4hopx9sUdnbD/DY/XN8i7vxSmH/9HUThfzVlT9J4giR6quPO'
                    'BAoGAQSUpX2DN3yRWuC2EWxtCXsFDDfggmZg0ix4xwTIQTLJQvm8oMx8WTQ781fwclLeB0Nn16DRkqzcYipOBkhCorWhq2WpN'
                    'N5BmjILRsyIaUwNTJeSc/tiX+4AzNiHy5L9KA06c1+B94Gs+EWIcfIVtjTkix4nR/xouxHl'
                    '+0vDDVgMCgYEAn9cB4gLY1h6LNdpl1ALLkrTEitqK2TW0n9y8BiI3QE1qfof6lvYjM44mo496jHNxi9KFIsr2VtLHFeGz6nilb'
                    'UAiDdxkhv5twQBuogELbUQOqAs44r9hyABHVHvQMm2XtG8Q6AQGYG25lgI8/MdG2/sgukP+C5hGDGqcy23LwpE=',
    'plainSignPriFullB64': 'MIIE5gIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCBCxbSkEILq0Efw8SobRjrqK+b47cVLvRPGpJYmeF'
                           'PzptpmemNgxrSFhEZsZ3JhzVWii/PV9B9mvIVQjyZBvUHNef8dVc9sbW7nRRkudygUAi9GFFhe2BLNGCJ12NI3ZLmAz'
                           'UMzeLZ7gFEyLYTRU5QGRI0GPONp5tOVFgNko1bIW9bwe9/jKUWaIf5y983UhLhUQFC51cPKxnvf2aU1JKHTTrj/X1pl'
                           'AYgEY/x339YDtjLc6Ay686hBvTTB6ZWq4uRrSk/Ggj/XAIkcqesqeXerFGOMsfD/60qkYvzjk8UXRbeXOMQRd3dyWr7'
                           'lTqy1hM8C/UtQl4BCswSCBaRYnuDAgMBAAECggEARKrb+CxfmMoGm5qXOXDkg/J9kBy6vgEAbF+dZJxt8wPkW2tVhsI'
                           'vMYAglWWYqzbRwT1Dd7go783V6E4Y5O140d9zlTnztJauOCm8QmVM69nq7ITWOWNnuF0kyfTdllah5tfqEOg2QPWPo0'
                           'SS7upAZAsTTrnAUK7Ry/rB6GcF5Wm5wAp1nWZTr6q+QqcA/w60wIPyuvkhR/H3LMdW/is2rk0y7uQ2MOWXLtJAds4MO'
                           'Qt1YypjgzWuPuNr9I28r1NmKAQXrxlfJq/AC9MvuiEP/jZL1srcBJpl4ZXmv+ligEGEhxL1htJ/jVk9zaoXFpUuxLht'
                           'TzJ1wIecAYcdRktWAQKBgQDyqL1572xla7XlGu4j/5VgCNddEuu+iVdhfL1JmzVLqjPeUnv3UJzQn10GmL8kjW6slrC'
                           '8qJ1LoppB0qsE+LbBO/5yxDo0sf4mBm7sy2gF3c6leyA3Edy4d59JYLFQIRk+DWKZAWixiFu1CWtcixlHeP73tgrrfh'
                           '1PdDgyEtazgQKBgQCII0jkUhjt67B2weAvicdyYpuIGFjDIpJKtr6A07pX1sWyoVa79J2138WHNiqJOIh9BdOP2+04z'
                           'e8ueO2OZ86Mjz8bWOiQG0gce9WiNJkU72wYpnvLtFXw3gXyBKDuYKf7se4ksgh7Cr0C5jpzyIqIEQtcOOzMy4CtxrTQ'
                           'ahrhAwKBgG9g9j8+nvFaZA35s27AhE6lIDzvT1eQcJQljjh3zhmh0Nbt40qcLK4xR6CcgbeEV1VOgWbGuhQaWVV3Hdp'
                           'VUoUVRXBmExVW0YGgmE+F+YQf0BbykdHVGAtvlKQ4hopx9sUdnbD/DY/XN8i7vxSmH/9HUThfzVlT9J4giR6quPOBAo'
                           'GAQSUpX2DN3yRWuC2EWxtCXsFDDfggmZg0ix4xwTIQTLJQvm8oMx8WTQ781fwclLeB0Nn16DRkqzcYipOBkhCorWhq2'
                           'WpNN5BmjILRsyIaUwNTJeSc/tiX+4AzNiHy5L9KA06c1+B94Gs+EWIcfIVtjTkix4nR/xouxHl+0vDDVgMCgYEAn9cB'
                           '4gLY1h6LNdpl1ALLkrTEitqK2TW0n9y8BiI3QE1qfof6lvYjM44mo496jHNxi9KFIsr2VtLHFeGz6nilbUAiDdxkhv5'
                           'twQBuogELbUQOqAs44r9hyABHVHvQMm2XtG8Q6AQGYG25lgI8/MdG2/sgukP+C5hGDGqcy23LwpGgJzAlBgoqgxqMmk'
                           'QKAQEDMRcDFQB4WLQyg5CAUSnwHJf+bKSlIMvUeQ==',
    'signPriSalt': 'yOovolAjwoU=',
    'signPw': b'WTuA8Ev0lWXVFSiI!',
    'pfx': 'MIILygIBAzCCC5AGCSqGSIb3DQEHAaCCC4EEggt9MIILeTCCC3UGCSqGSIb3DQEHAaCCC2YEggtiMIILXjCCBggGCyqGSIb3DQEMCgEDoII'
           'F0DCCBcwGCiqGSIb3DQEJFgGgggW8BIIFuDCCBbQwggScoAMCAQICA0WcdTANBgkqhkiG9w0BAQsFADBXMQswCQYDVQQGEwJrcjEQMA4GA1'
           'UECgwHeWVzc2lnbjEVMBMGA1UECwwMQWNjcmVkaXRlZENBMR8wHQYDVQQDDBZ5ZXNzaWduQ0EtVGVzdCBDbGFzcyA0MB4XDTIwMDIyNDE1M'
           'DAwMFoXDTIwMDMyNTE0NTk1OVowezELMAkGA1UEBhMCa3IxEDAOBgNVBAoMB3llc3NpZ24xFDASBgNVBAsMC3BlcnNvbmFsNElCMRAwDgYD'
           'VQQLDAdJTklURUNIMTIwMAYDVQQDDClIS0QoS0lMRE9ORy5IT05HKTAwOTEwNDEyMDIwMDIyNTE5MTAwMDAzMDCCASIwDQYJKoZIhvcNAQE'
           'BBQADggEPADCCAQoCggEBAIELFtKQQgurQR/DxKhtGOuor5vjtxUu9E8akliZ4U/Om2mZ6Y2DGtIWERmxncmHNVaKL89X0H2a8hVCPJkG9Q'
           'c15/x1Vz2xtbudFGS53KBQCL0YUWF7YEs0YInXY0jdkuYDNQzN4tnuAUTIthNFTlAZEjQY842nm05UWA2SjVshb1vB73+MpRZoh'
           '/nL3zdSEuFRAULnVw8rGe9/ZpTUkodNOuP9fWmUBiARj/Hff1gO2MtzoDLrzqEG9NMHplari5GtKT8aCP9cAiRyp6yp5d6sUY4yx8P'
           '/rSqRi/OOTxRdFt5c4xBF3d3JavuVOrLWEzwL9S1CXgEKzBIIFpFie4MCAwEAAaOCAmMwggJfMIGTBgNVHSMEgYswgYiAFGY17Oj9'
           '/tu4KmKpArHm3Idc3PnDoW2kazBpMQswCQYDVQQGEwJLUjENMAsGA1UECgwES0lTQTEuMCwGA1UECwwlS29yZWEgQ2VydGlmaWNhdGlvbiB'
           'BdXRob3JpdHkgQ2VudHJhbDEbMBkGA1UEAwwSS2lzYSBUZXN0IFJvb3RDQSA3ggECMB0GA1UdDgQWBBSpq5i9JIUezWJfH915C1SqjIF'
           '+9jAOBgNVHQ8BAf8EBAMCBsAwfgYDVR0gAQH'
           '/BHQwcjBwBgkqgxqMmkUBAQQwYzAwBggrBgEFBQcCAjAkHiLHdAAgx3jJncEcspQAIMLc1djGqQAgx3jJncEcx4WyyLLkMC8GCCsGAQUFBw'
           'IBFiNodHRwOi8vc25vb3B5Lnllc3NpZ24ub3Iua3IvY3BzLmh0bTBiBgNVHREEWzBZoFcGCSqDGoyaRAoBAaBKMEgMA0hLRDBBMD8GCiqDG'
           'oyaRAoBAQEwMTALBglghkgBZQMEAgGgIgQgitT2c0Evgl2k0ftNQhaUa7x/gZSgrwH4ZiLuI8fuDecwdgYDVR0fBG8wbTBroGmgZ4ZlbGRh'
           'cDovL3Nub29weS55ZXNzaWduLm9yLmtyOjYwMjAvb3U9ZHAxOHAzOTUsb3U9QWNjcmVkaXRlZENBLG89eWVzc2lnbixjPWtyP2NlcnRpZml'
           'jYXRlUmV2b2NhdGlvbkxpc3QwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzABhiBodHRwOi8vc25vb3B5Lnllc3NpZ24ub3Iua3I6NDYxMj'
           'ANBgkqhkiG9w0BAQsFAAOCAQEAiWRb4WOGGi7GPo/mXxHgh594pd7ZtL0lRMu2zd3KV7vcnHBEMFnmZ4Re2sgxR9TSuVF9DAQOCR5nrgukI'
           '+jhevFEC7WQmkMNziC0hoqP7hc0ETFZ3LVR8IV89UcWaMn4pToknqV/RQ0yXlEZPTmDlo8i1/qFFVIAI36Omqh1IqpdVTu4vI9lRcMl/AEV'
           'TuZ9pj1a34zBvkhNdO3VvrlLFkLV9xOZDtY7SDW7z5+aGqXJtcBQEdtBbPwD2eMcTg8eOd/Qum7pWuOxay6tasc/qxWkXQBZnXcjOML/DmR'
           'eJf4W4O7yrBW3HiQecDyKG8XymEWhsrI8g/xufeQABk5ArDElMCMGCSqGSIb3DQEJFTEWBBSpq5i9JIUezWJfH915C1SqjIF+9jCCBU4GCy'
           'qGSIb3DQEMCgECoIIFFjCCBRIwHAYKKoZIhvcNAQwBAzAOBAjZu3ffwvzVQgICBAAEggTw8TJR41xg5soVX0MOItCmyDq93t15u0bwQ7y7y'
           'IOpENbWHGR1olpl/Bp6Gibbz0hjelYXiP6m0y9tPYnkkY2t/qfVzAgfRRMLnjke3aWgJxOWv9qDg3Fd5HYKICkSmBMKTGbjxGKYR3zWYS/t'
           'IPsmtL3Q0K/fORPk602wnKhPogUQ/ABN6i8i2ds6j164zop2at25itr8zvEjSPf0u9icsILhH/wWvLeZiWpWS30nj6h07M7LoLwlJaFpWjx'
           '3JbEsBf+pSosts32bNeD5iiP65Gn9T2Ykv8jhXfbSl6F9UANBqKoEpzDWwrz'
           '/Hjdx9SrrLL0wDTC3hyCAoQiEkvxWyThNOCmG8IQjNA2kKfAIgVpoWQcKfvS5mZhOWkAyghHnSCDCUk/HLyMsSWIr7a+rswOzkmlgnA7'
           '+Cbh3c/ROds2gdi00DbYmFsriSF5/L2Goua3eHeQVrN7kzHP+SqRfmslVFLb13n1P66oYC5q/lJqK/7AKA4ADdfZuDBlGX8gwdkoagFgi'
           '/y38FKtm/R3yI3guPdwvjp74Pu8Cpi'
           '/37VvsNPD2VdmvLEhI9i6Ltn6wVhv2C3Hj5BZwaQMrlGQQdprAhsCI0GuD1zmHCfwLtH2t8iH5OnwPnTwM7RVlHDCmtbSrvRGyLru1z'
           '/b9367w9/IFU+giXRf1lDH1fnvARzS0Y1ofEniOCdw591Wl57cGeKjkMMb9ixnIGgB64GAieK1KrtKEY1RA09Af6chuyyeiCBsux0XarfXL'
           '8aTtDQJdZ16ZuLVe7tXOZGNJIXs/eWrUasXDq//r6O2sh/HtS/W6+3ZU70NlHui3j/gkbCGyFtfp7lEUmG+/M91L+Bq0H+t2WeIjkzXyCtn'
           'Dmfz72Nt1cU4HRXqEoUhuPpJuLQ07k07YKlnkT1CwDQcqayE/PkEPUAtjv/C874TWeRwYoWFmGF5uNy9DP5UYtQgCXDuzH4V0FzRI/jma0F'
           'tslYSttTUgUvZraxW1SiKMSG7hmNpJf6m+G85iHaS7JDEmith8zSzGplTYBcUAIo+yTdxk1p'
           '+1U6j0bW3ThFHcXOj4X8VgvCoBt8fmuz7Jgw1TWB1hN7N7oV3RXDURTS1KkLr0ElF9A5aqAOvtFcpfUaF+D2MgJXknIzOEDBKwEYz8Jz2'
           '/32v5uTQJZ3rt1wLPTnw+wTxTOUslWQQKuyTzQXrm381lWvHr0aeV6n5zhIWONACEfgGQ8z7dh/ocMHjQOPjWcZySvShZpbtGsI1VSLzw'
           '/HliP0NQHY2skxgn1+S5495tQqN2Wtf37vm1DjLS8RkyR6yDsgDcW3EtgKwRNjrzuEk67jKRj80WXfneigOsQFD'
           '++NO7UsqPLjWPzeranFnKBFbZ7GeZOrHPEZGEO1LxcPrKSXAZcSIGZGukH9JW0fPMz+ijTEJQUzkrBpH/BaynIE6AK6DMD7'
           '/4cf3SbOW6l4rmmIKWBJpFhXZHmnDy/5TII8INkjPHx+xjYryv7g3R/1FFcMOJbtS5mUCv4QX5Gm0w'
           '+7OP7r6EoKas5s6wgeadVTGajh4PrxIbJCiJo0Opg4+P+ZsXc/kthaJKIPvW0KQVJcYgRr1rfav+eCJTmpxlZ4xlaWT8a'
           '+AdAAFeeB4IeH4TbzYZUmGejBjwDt5cQzHv1XIxAoYxedvsMcOOsQKE4p85o8xwQ9tvxiu9Qgb'
           '/pTElMCMGCSqGSIb3DQEJFTEWBBSpq5i9JIUezWJfH915C1SqjIF'
           '+9jAxMCEwCQYFKw4DAhoFAAQUqwNUkwHFswoTOl6hsyNmkzvJ3AIECNm7d9/C/NVCAgIEAA==',
    'cn': 'HKD(KILDONG.HONG)009104120200225191000030',
    'issuer': 'yessign',
    'certClass': 'yessignCA-Test Class 4',
    'typeOid': '1.2.410.200005.1.1.4',
    'notValidBefore': datetime.datetime(2020, 2, 24, 15, 0),
    'notValidAfter': datetime.datetime(2020, 3, 25, 14, 59, 59),
    'serialnum': 4562037,
    'r': bytes.fromhex('78 58 B4 32 83 90 80 51 29 F0 1C 97 FE 6C A4 A5 20 CB D4 79'.replace(' ', '')),
    'n': 16290209604510558512424059741651375064654753567992722580828628971708562130349008444810203521124558177825814339343207835427689025822285584732821780446150030117526628261085286225778211374294648916395223865257683288643551550943391795793773752999484548197810621853518105898239621319606067171572461184051376253498427234926384321524162077496373015541984328411287155862092598397499222651575268924929909579288769213787457173333761144872762255105990945866750105589086207927132458172404823977276816345606547939329781107327373658261705552620519785541773479297095905819124179278019444174466369977583873333772287403026516394802051,
    'p': 170401043831697500886160249453602583335155029958192979892846760308792096042785207717320177143506192175989057818875274069078126428428664188191002040247312453076759639094986555140352677217431824482125801965793292922161731900555514681105243113154959058263263456989915155467472762129413377977445986545324277543809,
    'q': 95599236003507988162256917245689855045632483977786697851995594997401446652676983578811144407419929034577038823467981696549011583201801033558606302793999799945569038528599429915741121712483113541005448714575076774872507683991561353700970060867945659335299477867471142542568350398654542405553691414296004321539,
    'd': 8668458576799383822303075505902773303702791948520350447591705551968573412481366563991501557832946913857781852545203931408291912759607358926597597865008104587006174130294158594958410416515122546200879458580594885456386724866866739193311653907014726549131751934320924441082267328378503540617025669966701183522206919710449881328235253220883492065780702278929839911087532908363820393717661474109958999654386682492736918207066351293501839778273759891568844178991557314782743427392173790999061264519292907633369044977763132786126117625410260941849282676595630566162691980887645244419763077955294840876726431237055938516481,
    'dmp1': 78212823283050681663130544025723168733765635536756382320776407172265667349177134036417722029598696413414206452074204178890384379717757105832942191016973707997039942377836803106290322770001170518132142895357249254490548198736750799126093932996846413958790119317540287038116608291726563970574678750475297813377,
    'dmq1': 45746488858294002117224456135344607535988530601452135913093883679654344392855987945970921765736856957953072532199816500381060351569215591397705910583679871310755613123814131278324569602288522876534963106913483722733367616425215612759450723696227227709756731699677472287066634677391475111472440246635289859587,
    'iqmp': 112243375560447953437465068186677931961946386104381573565781248145631941626834895758173236022282569436875755478253924009132537455132096217156676030889058324791773265762456745881170246853470533950609848943359263192558068577390682467473304759782525131932828121083302204086500535048470761777373171230451769787025,
    'testMsg': b'TEST_MSG',
    'sign': b'A\x81\xb9$\xf2\xc8\xa9\xfd\x8e\x0c\xfd\xc4Z\xb1k;|\xc6\xf8\xd5\xa5uQv'
            b'\x96m\xa1\x15WR;n\xden\x05h/\x94\xaf\xa2\xcc\xac\xde"\x06r\x19\xef'
            b'\xd1\xb3\xfao\xf32W\x06a\xa7\xb6\x98s+\x1e\x1eq\xaa\x96"\xb3\x11\x03\xeb'
            b"\x93\x7f\xb2\xc2\xe5\x9760t\xc5\xc8M=\xa5+\xda/\n'\x16u.\xc9\x9a"
            b'?\xd8\x95\x18!\xdfn\xeb\x9a\x80\xd0\xa9\xe5\xa7\x120N\x138\x95'
            b'\xa1\xae\xfb\x8c\x16\x02\xf9\x073\xd2\xbd\xbb\x85\x86\xfa^\xfeTx\xba'
            b'\xe6\xa2O\x00\xbf\xed\x9f\xe6\x8d\x88\xe9\x94\x0b\x1b^d\x06;\x842@^\x12\xe9'
            b'{"#,\xb0O\x81\xc5\x02\xda?\xa0Bzp>"\x7f\xe50\xa7\x1f\xcc\t\xed\xee\x06u'
            b'\x84"\x8a\x98L\x86\xb4`.V\xf0\x8e\x0bX\xf5\xc0c7<\xd9f\xef]-\xb7\xc4Lw'
            b'C\xc2\xf6\x06&;\xc9\xe4\xb2;\x98\xeePD\xd7\x88\xa2"V\xf2\x05\xbcc\xd3'
            b'\x8f\x00]\xb41\xa0\x05\x11\xb4\xa5zJz\x18\x1a>',
    'pkcs7SignMsg': b'0\x82\x07\x89\x06\t*\x86H\x86\xf7\r\x01\x07\x02\xa0\x82\x07z0\x82\x07v\x02'
                    b'\x01\x011\x0f0\r\x06\t`\x86H\x01e\x03\x04\x02\x01\x05\x000\x17\x06\t*'
                    b'\x86H\x86\xf7\r\x01\x07\x01\xa0\n\x04\x08TEST_MSG\xa0\x82\x05\xb8'
                    b'0\x82\x05\xb40\x82\x04\x9c\xa0\x03\x02\x01\x02\x02\x03E\x9cu0\r\x06\t*\x86'
                    b'H\x86\xf7\r\x01\x01\x0b\x05\x000W1\x0b0\t\x06\x03U\x04\x06\x13\x02kr'
                    b'1\x100\x0e\x06\x03U\x04\n\x0c\x07yessign1\x150\x13\x06\x03U\x04\x0b\x0c'
                    b'\x0cAccreditedCA1\x1f0\x1d\x06\x03U\x04\x03\x0c\x16yessignCA-Test Class'
                    b' 40\x1e\x17\r200224150000Z\x17\r200325145959Z0{1\x0b0\t\x06\x03U\x04'
                    b'\x06\x13\x02kr1\x100\x0e\x06\x03U\x04\n\x0c\x07yessign1\x140\x12\x06'
                    b'\x03U\x04\x0b\x0c\x0bpersonal4IB1\x100\x0e\x06\x03U\x04\x0b\x0c\x07INITECH1'
                    b'200\x06\x03U\x04\x03\x0c)HKD(KILDONG.HONG)0091041202002251910000300'
                    b'\x82\x01"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x000'
                    b'\x82\x01\n\x02\x82\x01\x01\x00\x81\x0b\x16\xd2\x90B\x0b\xabA\x1f\xc3\xc4'
                    b'\xa8m\x18\xeb\xa8\xaf\x9b\xe3\xb7\x15.\xf4O\x1a\x92X\x99\xe1O\xce'
                    b'\x9bi\x99\xe9\x8d\x83\x1a\xd2\x16\x11\x19\xb1\x9d\xc9\x875V\x8a/\xcf'
                    b'W\xd0}\x9a\xf2\x15B<\x99\x06\xf5\x075\xe7\xfcuW=\xb1\xb5\xbb\x9d\x14d'
                    b'\xb9\xdc\xa0P\x08\xbd\x18Qa{`K4`\x89\xd7cH\xdd\x92\xe6\x035\x0c'
                    b'\xcd\xe2\xd9\xee\x01D\xc8\xb6\x13ENP\x19\x124\x18\xf3\x8d\xa7\x9bNTX\r'
                    b'\x92\x8d[!o[\xc1\xef\x7f\x8c\xa5\x16h\x87\xf9\xcb\xdf7R\x12\xe1Q\x01B'
                    b'\xe7W\x0f+\x19\xef\x7ff\x94\xd4\x92\x87M:\xe3\xfd}i\x94\x06 \x11\x8f\xf1'
                    b'\xdf\x7fX\x0e\xd8\xcbs\xa02\xeb\xce\xa1\x06\xf4\xd3\x07\xa6V\xab\x8b'
                    b'\x91\xad)?\x1a\x08\xff\\\x02$r\xa7\xac\xa9\xe5\xde\xacQ\x8e2\xc7\xc3\xff\xad'
                    b'*\x91\x8b\xf3\x8eO\x14]\x16\xde\\\xe3\x10E\xdd\xdd\xc9j\xfb\x95:\xb2\xd6\x13'
                    b'<\x0b\xf5-B^\x01\n\xcc\x12\x08\x16\x91b{\x83\x02\x03\x01\x00\x01\xa3\x82\x02'
                    b'c0\x82\x02_0\x81\x93\x06\x03U\x1d#\x04\x81\x8b0\x81\x88\x80\x14f5\xec'
                    b'\xe8\xfd\xfe\xdb\xb8*b\xa9\x02\xb1\xe6\xdc\x87\\\xdc\xf9\xc3\xa1m\xa4k0i1'
                    b'\x0b0\t\x06\x03U\x04\x06\x13\x02KR1\r0\x0b\x06\x03U\x04\n\x0c\x04KISA1'
                    b'.0,\x06\x03U\x04\x0b\x0c%Korea Certification Authority Central1\x1b0\x19\x06'
                    b'\x03U\x04\x03\x0c\x12Kisa Test RootCA 7\x82\x01\x020\x1d\x06\x03U'
                    b'\x1d\x0e\x04\x16\x04\x14\xa9\xab\x98\xbd$\x85\x1e\xcdb_\x1f\xddy\x0b'
                    b'T\xaa\x8c\x81~\xf60\x0e\x06\x03U\x1d\x0f\x01\x01\xff\x04\x04\x03\x02'
                    b'\x06\xc00~\x06\x03U\x1d \x01\x01\xff\x04t0r0p\x06\t*\x83\x1a\x8c'
                    b'\x9aE\x01\x01\x040c00\x06\x08+\x06\x01\x05\x05\x07\x02\x020$\x1e"\xc7'
                    b't\x00 \xc7x\xc9\x9d\xc1\x1c\xb2\x94\x00 \xc2\xdc\xd5\xd8\xc6\xa9\x00'
                    b' \xc7x\xc9\x9d\xc1\x1c\xc7\x85\xb2\xc8\xb2\xe40/\x06\x08+\x06\x01'
                    b'\x05\x05\x07\x02\x01\x16#http://snoopy.yessign.or.kr/cps.htm0b\x06\x03U\x1d'
                    b'\x11\x04[0Y\xa0W\x06\t*\x83\x1a\x8c\x9aD\n\x01\x01\xa0J0H\x0c\x03HKD0A0?\x06'
                    b'\n*\x83\x1a\x8c\x9aD\n\x01\x01\x01010\x0b\x06\t`\x86H\x01e\x03\x04'
                    b'\x02\x01\xa0"\x04 \x8a\xd4\xf6sA/\x82]\xa4\xd1\xfbMB\x16\x94k\xbc\x7f'
                    b'\x81\x94\xa0\xaf\x01\xf8f"\xee#\xc7\xee\r\xe70v\x06\x03U\x1d\x1f\x04o0'
                    b'm0k\xa0i\xa0g\x86eldap://snoopy.yessign.or.kr:6020/ou=dp18p395,ou=Accredi'
                    b'tedCA,o=yessign,c=kr?certificateRevocationList0<\x06\x08+\x06'
                    b'\x01\x05\x05\x07\x01\x01\x0400.0,\x06\x08+\x06\x01\x05\x05\x070\x01\x86 http'
                    b'://snoopy.yessign.or.kr:46120\r\x06\t*\x86H\x86\xf7\r\x01\x01'
                    b'\x0b\x05\x00\x03\x82\x01\x01\x00\x89d[\xe1c\x86\x1a.\xc6>\x8f\xe6'
                    b'_\x11\xe0\x87\x9fx\xa5\xde\xd9\xb4\xbd%D\xcb\xb6\xcd\xdd\xcaW\xbb\xdc\x9cpD'
                    b'0Y\xe6g\x84^\xda\xc81G\xd4\xd2\xb9Q}\x0c\x04\x0e\t\x1eg\xae\x0b\xa4'
                    b'#\xe8\xe1z\xf1D\x0b\xb5\x90\x9aC\r\xce \xb4\x86\x8a\x8f\xee\x174\x111Y'
                    b'\xdc\xb5Q\xf0\x85|\xf5G\x16h\xc9\xf8\xa5:$\x9e\xa5\x7fE\r2^Q\x19=9\x83\x96'
                    b'\x8f"\xd7\xfa\x85\x15R\x00#~\x8e\x9a\xa8u"\xaa]U;\xb8\xbc\x8feE\xc3%\xfc\x01'
                    b'\x15N\xe6}\xa6=Z\xdf\x8c\xc1\xbeHMt\xed\xd5\xbe\xb9K\x16B\xd5\xf7\x13'
                    b'\x99\x0e\xd6;H5\xbb\xcf\x9f\x9a\x1a\xa5\xc9\xb5\xc0P\x11\xdbAl'
                    b'\xfc\x03\xd9\xe3\x1cN\x0f\x1e9\xdf\xd0\xban\xe9Z\xe3\xb1k.\xadj\xc7?\xab'
                    b'\x15\xa4]\x00Y\x9dw#8\xc2\xff\x0ed^%\xfe\x16\xe0\xee\xf2\xac\x15\xb7\x1e'
                    b'$\x1ep<\x8a\x1b\xc5\xf2\x98E\xa1\xb2\xb2<\x83\xfcn}\xe4\x00\x06N@\xac'
                    b'1\x82\x01\x890\x82\x01\x85\x02\x01\x010^0W1\x0b0\t\x06\x03U\x04\x06'
                    b'\x13\x02kr1\x100\x0e\x06\x03U\x04\n\x0c\x07yessign1\x150\x13\x06\x03'
                    b'U\x04\x0b\x0c\x0cAccreditedCA1\x1f0\x1d\x06\x03U\x04\x03\x0c\x16yessignCA-Te'
                    b'st Class 4\x02\x03E\x9cu0\r\x06\t`\x86H\x01e\x03\x04\x02\x01\x05\x000\r'
                    b'\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x04\x82\x01\x00A\x81\xb9'
                    b'$\xf2\xc8\xa9\xfd\x8e\x0c\xfd\xc4Z\xb1k;|\xc6\xf8\xd5\xa5uQv\x96m\xa1\x15WR;'
                    b'n\xden\x05h/\x94\xaf\xa2\xcc\xac\xde"\x06r\x19\xef\xd1\xb3\xfao\xf32W'
                    b'\x06a\xa7\xb6\x98s+\x1e\x1eq\xaa\x96"\xb3\x11\x03\xeb\x93\x7f\xb2'
                    b"\xc2\xe5\x9760t\xc5\xc8M=\xa5+\xda/\n'\x16u.\xc9\x9a?\xd8\x95\x18!\xdfn"
                    b'\xeb\x9a\x80\xd0\xa9\xe5\xa7\x120N\x138\x95\xa1\xae\xfb\x8c\x16\x02\xf9'
                    b'\x073\xd2\xbd\xbb\x85\x86\xfa^\xfeTx\xba\xe6\xa2O\x00\xbf\xed\x9f'
                    b'\xe6\x8d\x88\xe9\x94\x0b\x1b^d\x06;\x842@^\x12\xe9{"#,\xb0O\x81\xc5\x02\xda?'
                    b'\xa0Bzp>"\x7f\xe50\xa7\x1f\xcc\t\xed\xee\x06u\x84"\x8a\x98L\x86\xb4`.V\xf0'
                    b'\x8e\x0bX\xf5\xc0c7<\xd9f\xef]-\xb7\xc4LwC\xc2\xf6\x06&;\xc9\xe4\xb2;\x98'
                    b'\xeePD\xd7\x88\xa2"V\xf2\x05\xbcc\xd3\x8f\x00]\xb41\xa0\x05\x11\xb4\xa5z'
                    b'Jz\x18\x1a>'
}
TEST_DATA = {
    'plaintext': b'TEST_MSG_IS_QUITE_LONG_ENOUGH!',
    'iv': b'0123456789abcdef',
    'key': b'abcdefghijklmnop',
    'seedCiphertext': b'\xce\x9bx=\xe4\xdd\x93\xbfR\xad\xbb>Y\xa7C[I\xd7\x1eEp4`\xfb\xdce^,\\\xa3_\xec',
    'seed_key': bytearray(b"|\x8f\x8c~\xc77\xa2,\xff'l\xdb\xa7\xcahJ/\x9d\x01\xa1p\x04\x9eA"
                          b'\xaeY\xb3\xc4BE\xe9\x0c\xa1\xd6@\x0f\xdb\xc19N\x85\x965\x08'
                          b'\x0c_\x1f\xcb\xb6\x84\xbd\xa7a\xa4\xae\xae\xd1~\x07A\xfe\xe9\n\xa1'
                          b'v\xcc\x05\xd5\xe9zs\x94P\xaco\x92\x1b&f\xe5e\xb7\x90J'
                          b'\x8e\xc3\xa7\xb3/~."\xa2\xb1!\xb9M\x0b\xfd\xe4N\x88\x8d\x9b'
                          b'c\x1c\x8d\xdcCx\xa6\xc4!j\xf6_xx\xc01q\x89\x11P\x98\xb2U\xb0'),
    'seed_block_plain': bytes.fromhex('00 01 22 03 04 05 06 07 08 09 0A CB 0C 0D 0E 0F'.replace(' ', '')),
    'seed_block_cipher': b'\x00\xfa\x15\xed*\x89\xcb\x0c\xe28&\xe5\\3A\xcc',
    'seed_block_key': bytes.fromhex('01 02 02 01 03 05 05 03 09 08 08 09 11 33 33 11'.replace(' ', '')),
}


class TestPinkSign(TestCase):
    def setUp(self) -> None:
        """
        Load test certificate
        :return: None
        """
        self.c = PinkSign(pubkey_data=base64.b64decode(TEST_CERT['signCert']),
                          prikey_data=base64.b64decode(TEST_CERT['signPri']),
                          prikey_password=TEST_CERT['signPw']
                          )
        pass

    def test_load_pubkey(self):
        cert = PinkSign()
        cert.load_pubkey(pubkey_data=base64.b64decode(TEST_CERT['signCert']))
        expected = RSAPublicNumbers(e=65537, n=TEST_CERT['n'])
        self.assertEqual(expected, cert.pubkey.public_numbers())

    def test_load_prikey(self):
        cert = PinkSign(pubkey_data=base64.b64decode(TEST_CERT['signCert']),
                        prikey_data=base64.b64decode(TEST_CERT['signPri']),
                        prikey_password=TEST_CERT['signPw']
                        )
        cert.load_prikey()
        expected_public_numbers = RSAPublicNumbers(e=65537, n=TEST_CERT['n'])
        expected = RSAPrivateNumbers(p=TEST_CERT['p'], q=TEST_CERT['q'], d=TEST_CERT['d'], dmp1=TEST_CERT['dmp1'],
                                     dmq1=TEST_CERT['dmq1'], iqmp=TEST_CERT['iqmp'],
                                     public_numbers=expected_public_numbers)
        self.assertEqual(expected, cert.prikey.private_numbers())

    def test_load_p12(self):
        cert = PinkSign(p12_data=base64.b64decode(TEST_CERT['pfx']),
                        prikey_password=TEST_CERT['signPw'])
        expected_public_numbers = RSAPublicNumbers(e=65537, n=TEST_CERT['n'])
        self.assertEqual(cert.pubkey.public_numbers(), expected_public_numbers)
        expected = RSAPrivateNumbers(p=TEST_CERT['p'], q=TEST_CERT['q'], d=TEST_CERT['d'], dmp1=TEST_CERT['dmp1'],
                                     dmq1=TEST_CERT['dmq1'], iqmp=TEST_CERT['iqmp'],
                                     public_numbers=expected_public_numbers)
        self.assertEqual(expected, cert.prikey.private_numbers())

    def test_load_12_file(self):
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(base64.b64decode(TEST_CERT['pfx']))
        f.close()
        cert = PinkSign(p12_path=f.name, prikey_password=TEST_CERT['signPw'])
        signed = cert.sign(msg=b'1')
        cert.verify(signature=signed, msg=b'1')
        os.unlink(f.name)
        expected_public_numbers = RSAPublicNumbers(e=65537, n=TEST_CERT['n'])
        self.assertEqual(cert.pubkey.public_numbers(), expected_public_numbers)
        expected = RSAPrivateNumbers(p=TEST_CERT['p'], q=TEST_CERT['q'], d=TEST_CERT['d'], dmp1=TEST_CERT['dmp1'],
                                     dmq1=TEST_CERT['dmq1'], iqmp=TEST_CERT['iqmp'],
                                     public_numbers=expected_public_numbers)
        self.assertEqual(expected, cert.prikey.private_numbers())

    def test_cn(self):
        expected = TEST_CERT['cn']
        self.assertEqual(expected, self.c.cn())

    def test_issuer(self):
        expected = TEST_CERT['issuer']
        self.assertEqual(expected, self.c.issuer())

    def test_cert_class(self):
        expected = TEST_CERT['certClass']
        self.assertEqual(expected, self.c.cert_class())

    def test_cert_type_oid(self):
        expected = TEST_CERT['typeOid']
        self.assertEqual(expected, self.c.cert_type_oid())

    def test_valid_date(self):
        expected = tuple((TEST_CERT['notValidBefore'], TEST_CERT['notValidAfter']))
        self.assertEqual(expected, self.c.valid_date())

    def test_serialnum(self):
        expected = TEST_CERT['serialnum']
        self.assertEqual(expected, self.c.serialnum())

    def test_sign(self):
        test_msg = TEST_CERT['testMsg']
        expected = TEST_CERT['sign']
        self.c.load_prikey()
        self.assertEqual(expected, self.c.sign(test_msg))

    def test_verify(self):
        test_msg = TEST_CERT['testMsg']
        test_signed = TEST_CERT['sign']
        self.c.load_prikey()
        self.assertTrue(self.c.verify(test_signed, test_msg))

    def test_encrypt_decrypt(self):
        expected = TEST_CERT['testMsg']
        self.c.load_prikey()
        self.assertEqual(expected, self.c.decrypt(self.c.encrypt(expected)))

    def test_get_private_key_decryption_key_for_seed_cbc_with_sha1(self):
        der = der_decoder.decode(self.c.prikey_data)[0]
        expected = (b'b@\xe2hjj\xbb\xc4\x8c\x92,\xcb\xa9\x06\xbb\x91', b'Dq\xa1\xfd\x15Ag\xf2(Hw\rW\x8a[s')
        self.assertEqual(expected, self.c.get_private_key_decryption_key_for_seed_cbc_with_sha1(der))

    def test_get_private_key_decryption_key_for_seed_cbc(self):
        der = der_decoder.decode(self.c.prikey_data)[0]
        expected = (b'b@\xe2hjj\xbb\xc4\x8c\x92,\xcb\xa9\x06\xbb\x91', b'0123456789012345')
        self.assertEqual(expected, self.c.get_private_key_decryption_key_for_seed_cbc(der))

    def test_get_private_key_decryption_key_for_pbes2(self):
        # generated pbes2 style random private key
        data = 'MIIFPjBIBgkqhkiG9w0BBQ0wOzAbBgkqhkiG9w0BBQwwDgQIKM6QieKCgAkCAgQAMBwGCCqDGoyaRAEEBBCYE1' \
               '+QI4X5ATWQgjCY4Jz+BIIE8GaQ1I49aNKzxNWZh2gXWFRK2v/tXl4Uu2jgLnu7' \
               '+M3H3ljD8NSVu1UNYwN4lpTN612EoRQF4qdmwgDk9ul6pd+stLeQsjIZN6Ixckms+suery8GlA9IQbDnLEjAlJjFrD5aUoH0' \
               '+8T8d6rDSOgQvgeTVpq+H+pjDULmwuh1J95CikkhNrVV6hqQCo6ZXJGLSyllNm3BlouHZCttH' \
               '+3Rah186QN9phQaRnuoNytZWCYzpeeEAh956fXeA8GAiQtIan' \
               '+nVSJjiCd9cv5qrp7rxzkGsgOvL5mpzw8eoDyYQQbJlYHwatBFf8TgFR1OTeTsn4YspSkXj8mDXevEoV/9kryo' \
               '/nfPI1zaHzwFkiLe4HOAC/9oiMKSJB6G62gqSX634I5t' \
               '/0uvxJQaOuVslPxi8dDG9wCaG68MGm8WqXww81PSN9vNN0jh9lcEjOTd4AmN8a4jzhk6arDi0z2sjpWS3fobxjL3aPUEqzFGuXRyE' \
               '3Siah/QwfrwZIYUHLz4EanyttgdhWiSIoGWNsRbBAyp4++teG688YVEoCAEZE799hdhqIT7JEaqYZTV21EzFnVSBEMzckVq9H+hyd' \
               'tHihOaL79mf4854b7pABDX/wUAVxqPfTOJZx25fXLiAX6S1YNWuoSlRwy1zDwzbjiY60M1Br5xRLrSePXj7YTi4dTsg' \
               '/iOvxAKNmPHSQJ2R1BLAdXAf67cpnisfe+1DQkgm/Hl8Ce8NL5wFijGkoCuXOw7VDawUgYfz6tIWlPgypBLvm2zrvjMzjanHQwVEp' \
               '/reTLKj9f/KwxKrYvOkH0u6qncC23GSCIgnt2ETXLJaJ76NYh/b+Z+mwKwibaaSuBxrZVjzUViJikT6s17pZQCv73wueR4Cj' \
               '/1nPVJSrDo03ttgxSl9secx57Sq954X9gOu+03Ekcv3Naicz7sFoQOnWwMCB1MDYKDPMR5nIv9FlmLUaP0uCkyyHS5m4oVb' \
               '/U6KAIPMdo5gdUdad45+M6ikwGVvIHZAAKL/OtPtBsG' \
               '/5wjcMHHFUrSFwQLkdftWXqzqCqWTXl2cIIatwx3NvvR64uV0WonTPEMOooAVDIwMseTrbFWjmtk+G7grW3U7CSrokmroHVkQuD' \
               '/PzMOmZ3P33SoB7C2zEcxkcl/00Pt4/31i46lU/Uc4VByZulgpng6gw0uDQV2jkTWrvs83ifj+82br6oF525/8xBOJbPJjsSFr' \
               '/g8xSTG4zEJzt/5PjnmcLOb9PEbo/Hf8rw2zcUbeOKwfqhjb9O3evq0cvgKLdJVsKnJtPHbecrQ5YhldiSdFfFQa6ELttgn' \
               '/qL2IHhCG/Oxc00jgf8YiehFp/1WKYeeAnijxzo9XdxILLnoAFjzAMLV8zY4Gn' \
               '+NQmZQAvL9a2mmAxMLlNP1dnjeAVNFoOmCRFcP2malXxJdq6NsTWDikugYP6Sk5E8i' \
               '/yq61i3PUCzQ2Wm7qBNAdPpWsMHmCLOxZpdfluo0d+gDOFa57ReYCDZTUUnaHocUsdoSo/N9Gkw0x4tB' \
               '/XKQEYdmazVdjw65MR025k4tOvI3v/DRS+tWJ0ptP5g+p3g34/52GeBmDX' \
               '/y84QDp8QrWRl8sa0JFZRKENeY6yDrNL1rHZ7ZEwSEJXRKxy7mIe+F5Z+5dr' \
               '/XySW8PSfXfEwmdff3zDby05gwSzKLLD0mxD72gJGwi0kQqWUMR68='
        pbes2_private_key = base64.b64decode(data)
        der = der_decoder.decode(pbes2_private_key)[0]
        expected = (b'\x01s\x94\x01\xd7\xf3\xdfS\x19\xef\xf4\xed\xb0\xaf\xa6o',
                    b'\x98\x13_\x90#\x85\xf9\x015\x90\x820\x98\xe0\x9c\xfe')
        self.c.load_prikey()
        self.assertEqual(expected, self.c.get_private_key_decryption_key_for_pbes2(der))

    def test_pkcs7_signed_msg(self):
        expected = TEST_CERT['pkcs7SignMsg']
        self.c.load_prikey()
        self.assertEqual(expected, self.c.pkcs7_signed_msg(TEST_CERT['testMsg']))

    def test_seed_cbc_128_encrypt(self):
        expected = TEST_DATA['seedCiphertext']
        self.assertEqual(expected, seed_cbc_128_encrypt(TEST_DATA['key'], TEST_DATA['plaintext'], TEST_DATA['iv']))

    def test_seed_cbc_128_encrypt_openssl(self):
        expected = TEST_DATA['seedCiphertext']
        self.assertEqual(expected,
                         seed_cbc_128_encrypt_openssl(
                             TEST_DATA['key'],
                             TEST_DATA['plaintext'],
                             TEST_DATA['iv']))

    def test_seed_cbc_128_encrypt_pure(self):
        expected = TEST_DATA['seedCiphertext']
        self.assertEqual(expected,
                         seed_cbc_128_encrypt_pure(
                             TEST_DATA['key'],
                             TEST_DATA['plaintext'],
                             TEST_DATA['iv']))

    def test_seed_cbc_128_decrypt(self):
        expected = TEST_DATA['plaintext']
        self.assertEqual(expected, seed_cbc_128_decrypt(TEST_DATA['key'], TEST_DATA['seedCiphertext'], TEST_DATA['iv']))

    def test_seed_cbc_128_decrypt_openssl(self):
        expected = TEST_DATA['plaintext']
        self.assertEqual(expected,
                         seed_cbc_128_decrypt_openssl(
                             TEST_DATA['key'],
                             TEST_DATA['seedCiphertext'],
                             TEST_DATA['iv']))

    def test_seed_cbc_128_decrypt_pure(self):
        expected = TEST_DATA['plaintext']
        self.assertEqual(expected,
                         seed_cbc_128_decrypt_pure(
                             TEST_DATA['key'],
                             TEST_DATA['seedCiphertext'],
                             TEST_DATA['iv']))

    def test_seed_generator(self):
        self.assertEqual(16, len(seed_generator(16)))
        self.assertIsInstance(seed_generator(16), bytes)

    def test_separate_p12_into_npki(self):
        expected = tuple((base64.b64decode(TEST_CERT['signCert']), base64.b64decode(TEST_CERT['plainSignPri'])))
        self.assertEqual(expected, separate_p12_into_npki(base64.b64decode(TEST_CERT['pfx']), TEST_CERT['signPw']))

    def test_inject_rand_in_plain_prikey(self):
        expected = TEST_CERT['plainSignPriFullB64']
        self.assertEqual(expected, inject_rand_in_plain_prikey(TEST_CERT['plainSignPri'], TEST_CERT['r']))

    def test_encrypt_decrypted_prikey(self):
        expected = TEST_CERT['signPri']
        self.assertEqual(expected, encrypt_decrypted_prikey(TEST_CERT['plainSignPriFullB64'], TEST_CERT['signPw'],
                                                            TEST_CERT['signPriSalt']))

    def test_set_key(self):
        expected = TEST_DATA['seed_key']
        self.assertEqual(expected, set_key(bytes(16)), expected)

    def test_process_block(self):
        expected = bytearray(TEST_DATA['seed_block_cipher'])
        self.assertEqual(expected, process_block(True, TEST_DATA['seed_block_key'], TEST_DATA['seed_block_plain']),
                         expected)

        expected = bytearray(TEST_DATA['seed_block_plain'])
        self.assertEqual(expected, process_block(False, TEST_DATA['seed_block_key'], TEST_DATA['seed_block_cipher']),
                         expected)

    def test_process_block_openssl(self):
        expected = TEST_DATA['seed_block_cipher']
        self.assertEqual(expected,
                         seed_cbc_128_encrypt_openssl(
                             TEST_DATA['seed_block_key'],
                             TEST_DATA['seed_block_plain'],
                             bytes(16))[:16], expected)

    def test_pure_vs_openssl(self):
        for i in range(100):
            random_bytes = seed_generator(128)
            key = seed_generator(16)
            iv = seed_generator(16)
            enc = seed_cbc_128_encrypt_pure(key, random_bytes, iv)
            self.assertEqual(enc, seed_cbc_128_encrypt_openssl(key, random_bytes, iv))
            dec = seed_cbc_128_decrypt_pure(key, enc, iv)
            self.assertEqual(dec, seed_cbc_128_decrypt_openssl(key, enc, iv))
            self.assertEqual(dec, random_bytes)


if __name__ == '__main__':
    unittest.main()
