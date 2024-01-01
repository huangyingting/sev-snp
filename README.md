# Confidential computing sev-snp tools

## Background
**AMD SEV-SNP**: SEV-SNP (Secure Encrypted Virtualization - Secure Nested Paging) is the third-generation SEV architecture offered by AMD. It builds on the previous two SEV generations (SEV and SEV-ES), allowing for encrypted in-use data (RAM) and register state while introducing memory integrity protection to prevent a number of malicious hypervisor attacks. You can read more about SEV-SNP in [this white paper from AMD](https://www.amd.com/system/files/TechDocs/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf).

**Attestation**: A process intended to establish trust between a client running a confidential workload and the platform in which the workload is being run on. Attestation is a process that confirms that only code/data that is known to the client and intended to be used is included in the TEE workload, and that the workload is running on a verified TEE architecture. An explanation of attestation in a bit more detail can be found [here](https://confidentialcomputing.io/2023/04/06/why-is-attestation-required-for-confidential-computing/).

## Access confidential container node

Deploy sev-snp pod to AKS cluster that supports confidential container 
```bash
kubectl create secret generic id_rsa --from-file=id-rsa=<PATH_TO_PRIVATE_KEY> -n <NAMESPACE>
kubectl apply -f sev-snp.yaml -n <NAMESPACE>
```

Access sev-snp pod
```bash
kubectl exec -it deploy/sev-snp -n cc -- /bin/ash
```

SSH into node
```bash
kubectl get node -o wide
ssh aureuser@<NODE_IP>
```

## VCEK, ASK and ARK
From confidential container guest, use curl for requesting AMD collateral that includes the VCEK certificate and certificate chain. 

```bash
curl -s -XGET "http://169.254.169.254/metadata/THIM/amd/certification" -H "Metadata: true" | jq -r '.vc
ekCert' > vcek.pem

curl -s -XGET "http://169.254.169.254/metadata/THIM/amd/certification" -H "Metadata: true" | jq -r '.certificateChain' > cert_chain.pem

openssl x509 -in vcek.pem -text -noout

openssl verify --CAfile cert_chain.pem vcek.pem

```

It contains the following fields:

vcekCert: X.509v3 certificate as defined in RFC 5280.
tcbm: Trusted computing base, should match the CURRENT_TCB value found in the attestation report.
certificateChain: AMD SEV Key (ASK) and AMD Root Key (ARK) certificates.

VCEKs can be trusted through the following trust chain:

AMD Root Signing Key (ARK): a 4096 bit RSA key
AMD SEV Signing Key (ASK): a 4096 bit RSA key signed with the ARK
Versioned Chip Endorsement Key (VCEK): a 384 bit EC key signed with the ASK

For details on this collateral and where it comes from, see [Versioned Chip Endorsement Key (VCEK) Certificate and KDS Interface Specification](https://www.amd.com/system/files/TechDocs/57230.pdf) and [Trusted Hardware Identity Management](https://learn.microsoft.com/en-us/azure/security/fundamentals/trusted-hardware-identity-management)

```bash
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 0 (0x0)
        Signature Algorithm: rsassaPss        
        Hash Algorithm: sha384
        Mask Algorithm: mgf1 with sha384
         Salt Length: 0x30
        Trailer Field: 0x01
        Issuer: OU = Engineering, C = US, L = Santa Clara, ST = CA, O = Advanced Micro Devices, CN = SEV-Milan
        Validity
            Not Before: Nov 28 22:51:51 2022 GMT
            Not After : Nov 28 22:51:51 2029 GMT
        Subject: OU = Engineering, C = US, L = Santa Clara, ST = CA, O = Advanced Micro Devices, CN = SEV-VCEK
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                pub:
                    04:b4:48:8b:32:c6:cc:b5:3d:91:be:98:2b:4b:39:
                    f5:2b:67:ea:96:03:82:b3:26:02:be:57:30:af:ff:
                    c4:67:7f:58:83:1a:61:08:c5:99:52:2c:65:ad:68:
                    65:e9:a0:ac:5a:b4:e5:57:66:54:e0:07:8b:f3:8f:
                    10:6a:92:96:eb:b9:e2:75:34:5f:fb:0e:c0:73:df:
                    4a:93:62:fe:9e:6c:72:f9:6b:3f:83:c3:46:a6:2f:
                    db:fe:f3:3a:b8:89:04
                ASN1 OID: secp384r1
                NIST CURVE: P-384
        X509v3 extensions:
            1.3.6.1.4.1.3704.1.1: 
                ...
            1.3.6.1.4.1.3704.1.2: 
                ..Milan-B0
            1.3.6.1.4.1.3704.1.3.1: 
                ...
            1.3.6.1.4.1.3704.1.3.2: 
                ...
            1.3.6.1.4.1.3704.1.3.4: 
                ...
            1.3.6.1.4.1.3704.1.3.5: 
                ...
            1.3.6.1.4.1.3704.1.3.6: 
                ...
            1.3.6.1.4.1.3704.1.3.7: 
                ...
            1.3.6.1.4.1.3704.1.3.3: 
                ...
            1.3.6.1.4.1.3704.1.3.8: 
                ..s
            1.3.6.1.4.1.3704.1.4: 
..];.d..Br.^.Q....F...OI].z5.... 6..n........gEW.._..L......
    Signature Algorithm: rsassaPss
    Signature Value:        
        Hash Algorithm: sha384
        Mask Algorithm: mgf1 with sha384
         Salt Length: 0x30
        Trailer Field: 0x01
        03:d3:7d:68:3d:d4:a0:20:4e:70:7d:c2:bd:46:df:9b:8a:45:
        81:e0:1d:ed:60:e7:7b:39:df:66:67:42:aa:62:79:1d:be:76:
        6f:6b:b1:6b:df:17:45:46:86:f3:c9:9b:98:db:48:d8:02:cd:
        a0:39:f7:d6:22:f8:28:8c:cb:c2:ad:42:10:94:e3:27:f1:ee:
        db:10:58:fb:b9:81:a4:48:85:9c:da:44:80:4f:f5:a3:48:0d:
        1a:10:47:a7:c0:35:01:c5:83:04:02:2e:a3:61:29:21:7a:04:
        5a:77:0a:7b:68:06:37:46:e0:34:59:7a:b6:7a:5a:22:ca:8f:
        e4:ef:26:59:d3:98:be:48:51:c6:6c:64:a3:5b:df:93:f3:98:
        3d:b0:d3:44:a8:ae:9f:31:34:66:41:9e:3c:11:10:69:d8:d5:
        cc:32:5f:40:aa:7f:fe:44:0f:b8:87:58:d6:5a:4b:da:7f:11:
        3f:ea:ef:36:b8:d0:4d:22:da:3c:53:70:2b:12:0b:d2:ac:58:
        3c:c7:40:6b:99:05:40:59:a7:d6:f7:c0:12:b1:5e:ec:70:41:
        32:f7:cf:10:3b:9d:5d:37:a4:f6:a3:1c:68:be:39:4d:13:44:
        d8:85:a4:48:d0:fa:40:54:eb:43:6e:79:28:8c:2b:0b:c4:4d:
        bb:04:67:dd:94:7f:52:b8:ce:71:45:6d:8e:f3:51:32:8f:45:
        26:1e:fc:aa:a3:df:44:a9:5d:b8:2c:9f:18:d6:b6:32:98:76:
        2d:12:cb:e4:70:e6:ec:20:5f:42:6b:5f:ec:50:e8:d9:e0:5b:
        43:29:35:ba:e3:b9:4a:3f:b0:d0:6b:54:dc:93:bf:53:cb:85:
        fc:9b:d6:02:79:2e:b6:c6:c1:b1:4f:11:6d:a5:a6:c4:80:ab:
        3c:36:9a:ba:c5:c1:85:87:ee:cf:ce:79:46:10:e3:cf:f1:90:
        66:48:c8:ca:5a:12:f4:77:9b:f5:17:19:54:16:ec:9a:9e:35:
        76:0c:f8:15:19:e5:50:86:d5:08:0d:80:5c:a4:bb:0a:20:cb:
        ed:58:ef:96:91:91:b2:74:a7:24:69:4c:a6:9c:f0:44:39:76:
        60:93:d3:6d:68:2c:0a:aa:40:6c:e3:3d:a8:20:0d:1b:63:0f:
        30:f3:2f:78:11:ec:ae:d4:7d:a1:4a:b7:08:2e:c1:2f:90:37:
        c6:e4:21:f8:0a:f9:9d:48:e6:51:a4:01:7d:d5:c7:81:01:16:
        80:2b:7a:f2:e2:f3:a6:74:fd:82:26:16:b8:03:a8:22:6b:0a:
        e2:69:02:2e:58:68:f1:56:e2:8d:c6:39:4b:3a:25:38:5b:2d:
        6a:54:59:55:9f:32:1e:6b
```

Notice the TCB Version to OID Mapping from above VCEK certificate. The TCB version is a 64-bit value that is used to identify the version of the TCB that the VCEK is valid for.

| Bits | Field | OID | Name |
|---|---|---|---|
| 63:56 | Microcode | 1.3.6.1.4.1.3704.1.3.8 | ucodeSPL |
| 55:48 | SNP | 1.3.6.1.4.1.3704.1.3.3 | snpSPL |
| 47:40 | Reserved | 1.3.6.1.4.1.3704.1.3.7 | spl_7 |
| 39:32 | Reserved | 1.3.6.1.4.1.3704.1.3.6 | spl_6 |
| 31:24 | Reserved | 1.3.6.1.4.1.3704.1.3.5 | spl_5 |
| 23:16 | Reserved | 1.3.6.1.4.1.3704.1.3.4 | spl_4 |
| 15:8 | TEE | 1.3.6.1.4.1.3704.1.3.2 | teeSPL |
| 7:0 | BOOT LOADER | 1.3.6.1.4.1.3704.1.3.1 | bISPL |

TCB Version from attestation report should match the TCB Version from VCEK certificate.

## Validate attestation report came from a genuine AMD processor
REPORT_DATA contents, which is 64 bytes of user-provided data to include in the attestation report. This is typically a nonce.

Refer to [link](https://learn.microsoft.com/en-us/rest/api/attestation/attestation/attest-sev-snp-vm?view=rest-attestation-2022-08-01&tabs=HTTP), for a SEV-SNP quote, the SHA256 hash of the RuntimeData must match the quote's "report data" attribute.

Requesting Attestation Report using a 64 bytes data file request-file.txt
```bash
printf "%-64s" "confidential container" > request-file.txt
./snpguest report attestation-report.bin request-file.txt
```

Prints the attestation report contents into the terminal.
```bash
./snpguest display report attestation-report.bin 
```
Or
```bash
./sev-guest-parse-report attestation-report.bin
```

Output
```bash
Version: 2
Guest SVN: 2
Policy: 0x3001f
 - Debugging Allowed:       No
 - Migration Agent Allowed: No
 - SMT Allowed:             Yes
 - Min. ABI Major:          0
 - Min. ABI Minor:          0x1f
Family ID:
    01000000000000000000000000000000
Image ID:
    02000000000000000000000000000000
VMPL: 1
Signature Algorithm: 1 (ECDSA P-384 with SHA-384)
Platform Version: 03000000000008210
 - Boot Loader SVN:   3
 - TEE SVN:           0
 - SNP firmware SVN:  8
 - Microcode SVN:    210
Platform Info: 0x1
 - SMT Enabled: Yes
Author Key Enabled: Yes
Report Data:
    636f6e666964656e7469616c20636f6e7461696e657220202020202020202020
    2020202020202020202020202020202020202020202020202020202020202020
Measurement:
    10ea9102cffca36b831d3271e984d980e29949874aa6d8b4
    d6b22328c771dae4183deb131b4455f7c8ffb5f0dc041155
Host Data:
    0000000000000000000000000000000000000000000000000000000000000000
ID Key Digest:
    22087e0b99b911c9cffccfd9550a054531c105d46ed6d31f
    948eae56bd2defa4887e2fc4207768ec610aa232ac7490c4
Author Key Digest:
    000000000000000000000000000000000000000000000000
    000000000000000000000000000000000000000000000000
Report ID:
    78e9bfc4f2474f75504120c0e6adda9b7baec07529704be6bea185150694dfc3
Migration Agent Report ID:
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
Reported TCB: 03000000000008210
 - Boot Loader SVN:   3
 - TEE SVN:           0
 - SNP firmware SVN:  8
 - Microcode SVN:    210
Chip ID:
    dace52981bef4f495db57a351f1cab092036c0816ef4b4b3b0badca9bc674557
    ed075fe9054c11b49a9c09d40de5115d3b0664e99d4272ee5e0e5118c99db346
Signature:
  R:
    2bb14898baee212c6077d3d0537219d0f9f9967bf035fef315111f90d9b6f1d087e9c959
    6a8b9bd9e3f94136f99fd6ff000000000000000000000000000000000000000000000000
  S:
    9e31be3ad40bd9f224c28457ba895bc587c9801d3a528fb0395b8ff126220a8a82acbbe3
    0b67ccf5255e65d18cb399eb000000000000000000000000000000000000000000000000
```

Verify Attestation
```bash
./snpguest verify attestation ./certs-kds attestation-report.bin
```

Output
```bash
Reported TCB Boot Loader from certificate matches the attestation report.
Reported TCB TEE from certificate matches the attestation report.
Reported TCB SNP from certificate matches the attestation report.
Reported TCB Microcode from certificate matches the attestation report.
Chip ID from certificate matches the attestation report.
VCEK signed the Attestation Report!
```

go-sev-guest for attestation verification of fundamental components of an attestation report.
```bash
printf "%-64s" "confidential container" | ./attest > attestation.bin
hexnonce=$(printf "%-64s" "confidential container" | xxd -p)
./check -in attestation.bin -report_data=${hexnonce}
```

## Confidential container
There is a base64 encoded endorsement file /opt/confidential-containers/share/kata-containers/reference-info-base64, which decodes to a COSE_Sign1 document.

COSE_Sign1 envelopes are signed wrappers for arbitary data. See https://datatracker.ietf.org/doc/html/rfc8152. 

The COSE Sign1 document containing the measurement of the utility VM (UVM) used to launch the container (Base64 encoded). The measurement contained in the document payload should match the report measurement. There is a header which contains the iss (issuer) and feed fields that must match Confidential AKS's signing identity and the certificate chain used to sign the whole bundle.

The payload of the COSE_Sign1 envelope is json containing the following fields:

x-ms-sevsnpvm-guestsvn: Version of the UVM
x-ms-sevsnpvm-launchmeasurement: The measurement of the UVM at launch time, this should match the MEASUREMENT field of the attestation report.

To validate the UVM, unpack the COSE_Sign1 envelope and check that the issuer matches the Confidential AKS signing identity which is the DID:x509 string:
```
did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.5
```

For details, see [Confidential Azure Kubernetes Service (AKS)](https://microsoft.github.io/CCF/main/operations/platforms/snp.html#confidential-azure-kubernetes-service-aks), [did:x509 Method Specification](https://github.com/microsoft/did-x509/blob/main/specification.md)

```bash
base64 -d /opt/confidential-containers/share/kata-containers/reference-info-base64 > reference-info.cbor
```

Use https://gluecose.github.io/cose-viewer/ to view the contents of file reference-info.cbor

```
Type: COSE_Sign1 (tagged: true)
Size: 10826 bytes

Protected Header
================

1 (alg): -38 (PS384)
3 (content type): "application/json"
33 (x5chain): [<1637 bytes: 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>, <1748 bytes: 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>, <1459 bytes: MIIFrzCCA5egAwIBAgIQaCjVTH5c2r1DOa4MwVoqNTANBgkqhkiG9w0BAQwFADBfMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTAwLgYDVQQDEydNaWNyb3NvZnQgU3VwcGx5IENoYWluIFJTQSBSb290IENBIDIwMjIwHhcNMjIwMjE3MDAxMjM2WhcNNDcwMjE3MDAyMTA5WjBfMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTAwLgYDVQQDEydNaWNyb3NvZnQgU3VwcGx5IENoYWluIFJTQSBSb290IENBIDIwMjIwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCeJQFmGR9kNMGdOSNiHXGLVuol0psf7ycBgr932JQzgxhIm1Cee5ZkwtDDX0X/MpzoFxe9eO11mF86BggrHDebRkqQCrCvRpI+M4kq+rjnMmPzI8du0hT7Jlju/gaEVPrBHzeq29TsViq/Sb3M6wLtxk78rBm1EjVpFYkXTaNo6mweKZoJ8856IcYJ0RnqjzBGaTtoBCt8ii3WY13qbdY5nr0GPlvuLxFbKGunUqRoXkyk6q7OI79MNnHagUVQjsqGzv9Tw7hDsyTuB3qitPrHCh17xlI1MewIH4SAklv4sdo51snn5YkEflF/9OZqZEdJ6vjspvagQ1P+2sMjJNgl2hMsKrc/lN53HEx4HGr5mo/rahV3d61JhM4QQMeZSA/Vlh6AnHOhOKEDb9NNINC1Q+T3LngPTve8v2XabZALW7/e6icnmWT4OXxzPdYh0u7W81MRLlXD3OrxKVfeUaF4c5ALL/XJdTbrjdJtjnlduho4/98ZAajSyNHW8uuK9S7RzJMTm5yQeGVjeQTE8Z6fjDrzZAz+mB2T4o9WpWNTI7hucxZFGrb3ew/NpDL/Wv6WjeGHeNtwg6gkhWkgwm0SDeV59ipZz9ar54HmoLGILQiMC7HP12w2r575A2fZQXOpq0W4cWBYGNQWLGW60QXeksVQEBGQzkfM+6+/I8CfBQIDAQABo2cwZTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUC7NoO6/ar+5wpXbZIffMRBYH0PgwEAYJKwYBBAGCNxUBBAMCAQAwEQYDVR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEBDAUAA4ICAQBIxzf//8FoV9eLQ2ZGOiZrL+j63mihj0fxPTSVetpVMfSV0jhfLLqPpY1RMWqJVWhsK0JkaoUkoFEDx93RcljtbB6M2JHF50kRnRl6N1ged0T7wgiYQsRN45uKDs9ARU8bgHBZjJOB6A/VyCaVqfcfdwa4yu+c++hm2uU54NLSYsOn1LYYmiebJlBKcpfVs1sqpP1fL37mYqMnZgz62RnMER0xqAFSCOZUDJljK+rYhNS0CBbvvkpbiFj0Bhag63pd4cdE1rsvVVYl8J4M5A8S28B/r1ZdxokOcalWEuS5nKhkHrVHlZKu0HDIk318WljxBfFKuGxyGKmuH1eZJnRm9R0P313w5zdbX7rwtO/kYwd+HzIYaalwWpL5eZxY1H6/cl1TRituo5lg1oWMZncWdq/ixRhb4l0INtZmNxdl8C7PoeW85o0NZbRWU12fyK9OblHPiL6S6jD7LOd1P0JgxHHnl59zx5/K0bhsI+pQKB0OQ8z1qRtA66aY5eUPxZIvpZbH1/o8GO4dG2ED/YbnJEEzvdjztmB88xyCA9Vgr9/0IKTkgQYiWsyFM31k+OS4v4AX1PshP2Ou54+3F0Tsci41yQvQgR3pcgMJQdnfCUjmzbeyHGAlGVLzPRJJ7Z2UIo5xKPjBB1Rz3TgItIWPFGyqAK9Aq7WHzrY5XHP5kA==>]
34 (x5t): [-16 (SHA-256), <32 bytes: 7303c0d87fed8932185be5006679295da3c30e99fbbd730eaffc50aa876828d5>]
"iss": "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.5"
"feed": "ConfAKS-AMD-UVM"
"signingtime": Tag(1) 1700690448


Unprotected Header
==================

"timestamp": <5193 bytes: 3082144506092a864886f70d010702a082143630821432020103310f300d060960864801650304020105003082016c060b2a864886f70d0109100104a082015b0482015730820153020101060a2b0601040184590a03013031300d060960864801650304020105000420ac16851460287204ef32106b66e09e6e6409db3a49bc63fd98b11346ea2fc37e02066556c15cd120181332303233313132323232303035302e3534395a3004800201f4021827bdb15cd4537c346d1f3c89a1ad106719cc69ffb9d839bca081d1a481ce3081cb310b3009060355040613025553311330110603550408130a57617368696e67746f6e3110300e060355040713075265646d6f6e64311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e31253023060355040b131c4d6963726f736f667420416d6572696361204f7065726174696f6e7331273025060355040b131e6e536869656c64205453532045534e3a413430302d303545302d44393437312530230603550403131c4d6963726f736f66742054696d652d5374616d702053657276696365a0820e993082072030820508a003020102021333000001d62769ff722d56c8ae0001000001d6300d06092a864886f70d01010b0500307c310b3009060355040613025553311330110603550408130a57617368696e67746f6e3110300e060355040713075265646d6f6e64311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e312630240603550403131d4d6963726f736f66742054696d652d5374616d70205043412032303130301e170d3233303532353139313233345a170d3234303230313139313233345a3081cb310b3009060355040613025553311330110603550408130a57617368696e67746f6e3110300e060355040713075265646d6f6e64311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e31253023060355040b131c4d6963726f736f667420416d6572696361204f7065726174696f6e7331273025060355040b131e6e536869656c64205453532045534e3a413430302d303545302d44393437312530230603550403131c4d6963726f736f66742054696d652d5374616d70205365727669636530820222300d06092a864886f70d01010105000382020f003082020a0282020100cf2ccd8e9bcaf9bb77dc6c310e5f2749b5b916e54df828569fb42fbc43236aa65308cd24c2d53a04d337307900af3c87e962dc8f0778ede9f3d1a6bbe1c0292c530f69d0e7e667358f0ef92de340544adbbcd77425ae5a1176994bcf6c69936f6320e678fab05b29a66404f6784782d74219241e77b463f621f3966a30c45a31690133a9d4c15e5a0e2c17a9d13d2729748b569661b0aacf005174dec24e5009c6b278ee8bf7b9ffe5160f619d541ca9062046b445a4334530e3f4830cf9363e9adb81999dc14419198ac0898bfb92963e7560bda749491a7a66aad85771666c1999b6c1748529558cb40ef27c5e94657b4efa8821222cbf66d0320501544cfcc07172537f3ade01e3f0109b1292739bbe5f2c9b0bdcfeba94950d44dec246c7cd11b1dd5ff77a8e8a55385c05ee89a64d08e9537ec0ffb611d302434ede99b1753e8ffc18968f5bdb6b75a94b61aa346cdf6a067f64d14c2a1058b8497b770021846595afe010a95bb830ec1b7f76eb2e043071714e3b23adc6446c35b08c1df0ae9d750f283540a703c8b52cd9a9c1a25bd0c094cdd2630eb973bcb41cf6d2783ff97c3ee30f96f4f324bd6d5f6988b8df956329166c1dfc483e3233674c1fe0589b9953c91d9f9a4f11ac5493f1c9d0a1bef1827f87def177d863d3f995b9fd49c29ce1a753778e060ab06527f24eb280383af34763a5be5dc2957082065b0203010001a382014930820145301d0603551d0e04160414619a54363b4d00623022a0dbe8ffcd14dc62c64e301f0603551d230418301680149fa7155d005e625d83f4e5d265a71b533519e972305f0603551d1f045830563054a052a050864e687474703a2f2f7777772e6d6963726f736f66742e636f6d2f706b696f70732f63726c2f4d6963726f736f667425323054696d652d5374616d70253230504341253230323031302831292e63726c306c06082b060105050701010460305e305c06082b060105050730028650687474703a2f2f7777772e6d6963726f736f66742e636f6d2f706b696f70732f63657274732f4d6963726f736f667425323054696d652d5374616d70253230504341253230323031302831292e637274300c0603551d130101ff0402300030160603551d250101ff040c300a06082b06010505070308300e0603551d0f0101ff040403020780300d06092a864886f70d01010b05000382020100d4bfe46336277027149b324d48bd2f0b7f134cf15695869c51d52916f85458e802a49f6b373a7dbd9c611595ab5b948bf5a954ca92b5312d8319d33f9103a9a67d7b9ed98eff6016f3339914794814db2d4c99b8a7eb169d4fd0f3102784ec4e3ede4d83999c6e57e18b15842caa40db7bca32efedc14a2536f6ac990184fdbd10c02cf502e59c32a0f90d7ca6ea8e5dd58054ea22e6c442be7a33461d31696a0aaab4c95967f663db8471f35c73a3690b2eae884709fed54fc72defda68df815df1772caa6ca174a072d63772927ae293e177bc497ff74a9aa27e4df0a4d9a06b4e16568914f9d9d83a90b5bd965a47ee028196ac6480e3733297bf8f61b52cae2fcdaccbc077d67e27d165aac3305d0171001eee8c98b884ff011fc8faaa49b2e2eba553949241ae9790495c68a4184a925c4a3923c930c83a97fa2d9053685c7a79ea2a0d9d2551186246a3bed72a3cb973bcf5eea4801782f2dd56379213a979e3a1c6200efc85a69b6c503827454888d4cfd097f3b6f7d564b4c9082fbda2e90778041b2b8f767e88b12728ff5ea54c28b0fd66dcddaff728574351e2bac265eb721f5c8c9f049696bd00e0537264e1e2194abff62888f8a6d5ede3de824621d38b4d7591cc03a5d8d02c04220afa23d69bb285fc157f61b9670069b485e2bcd45b6b7e0a903e68aa6128175c91150f38883b1ffe08b29ff5c84fb618ff3082077130820559a00302010202133300000015c5e76b9e029b4999000000000015300d06092a864886f70d01010b0500308188310b3009060355040613025553311330110603550408130a57617368696e67746f6e3110300e060355040713075265646d6f6e64311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e31323030060355040313294d6963726f736f667420526f6f7420436572746966696361746520417574686f726974792032303130301e170d3231303933303138323232355a170d3330303933303138333232355a307c310b3009060355040613025553311330110603550408130a57617368696e67746f6e3110300e060355040713075265646d6f6e64311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e312630240603550403131d4d6963726f736f66742054696d652d5374616d7020504341203230313030820222300d06092a864886f70d01010105000382020f003082020a0282020100e4e1a64ce7b472210b79a2cbd72479bd0ed582d3fdee9c0707d2a96c4e75c8ca3557f6017f6c4ae0e2bdb93e176033ff5c4fc766f79553715ae27e4a5afeb836678546230cb58d13cf7732c01018e8607d6a528344b7a68e466b0714f3c576f58650dcc144c8715c513137a00a386e8dedd70fd826537c3961027ac4aafd7269af1dabacf636be352664da983bba1a7b33ad805b7e8c101c9d52feb6e86225dc6a0fcf5df4fe8e53cfd6ec85564defddbc8da4e3918fb2392c519ce970690dca362d708e31c83528bde3b48724c3e0c98f7eb5548fdcfa0555986d683b9a46bdeda4ae7a2937accbeb8345e7466eca32d5c086305c4f2ce262b2cdb9e28d88e496ac014abbbe71a9175b6760def892911e1d3dfd20cf737d419a4675cdc45f34dd1289d6fda5207d7efcd99e45dfb6722fdb7d5f80badbaa7e36ec364cf62b6ea81251e8bf0503a3d173a64d3774941c34820ff010f2b74718eda7e8997c3f4cdbaf5ec2f3d5d8733d434ec133394c8e02bc42682e10ea845146e2d1bd6a185a610173ca67a25ed7287602e2331872d7a720f0c2fa120ad7636f0cc936648b5ba0a683215d5f3074919494d8b950f90b8961f3360635188447dbdc1bd1fdb2d41cc56bf65c52515d12db25baaf50057a6cc5111d72ef8df952c4851793c03c15db1a37c70815183f78ab45b6f51e875eda8f9e167269c6ae7bb7b73e6ae22ead0203010001a38201dd308201d9301206092b060104018237150104050203010001302306092b0601040182371502041604142aa752fe64c49abe82913c463529cf10ff2f04ee301d0603551d0e041604149fa7155d005e625d83f4e5d265a71b533519e972305c0603551d20045530533051060c2b0601040182374c837d01013041303f06082b060105050702011633687474703a2f2f7777772e6d6963726f736f66742e636f6d2f706b696f70732f446f63732f5265706f7369746f72792e68746d30130603551d25040c300a06082b06010505070308301906092b0601040182371402040c1e0a00530075006200430041300b0603551d0f040403020186300f0603551d130101ff040530030101ff301f0603551d23041830168014d5f656cb8fe8a25c6268d13d94905bd7ce9a18c430560603551d1f044f304d304ba049a0478645687474703a2f2f63726c2e6d6963726f736f66742e636f6d2f706b692f63726c2f70726f64756374732f4d6963526f6f4365724175745f323031302d30362d32332e63726c305a06082b06010505070101044e304c304a06082b06010505073002863e687474703a2f2f7777772e6d6963726f736f66742e636f6d2f706b692f63657274732f4d6963526f6f4365724175745f323031302d30362d32332e637274300d06092a864886f70d01010b050003820201009d557dfc2aade12c1f670131245be19e724bfca96fea5c14b63e4e476478b10693973d3133b539d7c271363fda646c7cd075396dbb0f31e4c28ffb6cd1a1941822eee966673a534ddd98bab61e78d8362e9ca982560003b005be89e869e0ba09ee7bdf6a6fbe29cb6ed83f487501d918de6d820cf56d2354e47853752457b9dd9ff38e3dc6f368df65f6a456aaf795b6285527d024bd40a0bf19b61212115d3d27e0409638acf7f92989c3bc17b0548542b3fc0c9e8b1989e7f00b6a81c28119421952758a36c21dc361732e2c6b7b6e3f2c097814e991b2a95bdf49a3740cbcec9180d23de64a3e663b4fbb86fa321ad996f48ff69101f6cec674fdf64c726f10ab7530c534b07ad850fe0a58dd403cc7546d9d6374482cb14e472dc1140471bf64f924be736dca8e09bdb30157495464d973d77f1e5b44018e5a19916b0d9fa428dc67192824ba384b9a6efb21546b6a451147a9f1b7aec8e8895e4f9dd2d04c76b5575409b16901447e7ca1616c73fe0abbec41663d69fdcbc141497e7e93becbf83be4b715bfb4ce3ea5315184bcbf02c182a27b171d15898d70fee7b5d0281a890b8f36daba4cf99bff0ae934f82435672be00db8e68c99d6e122eaf027423d2594e674745b6ad19e3eed7ea031337dbccbe97bbf387044d190f1c8ab3a8a3a08627fd97063534d8dee826da50510c171066a10b41d553358b3a17066f23182040d30820409020101308193307c310b3009060355040613025553311330110603550408130a57617368696e67746f6e3110300e060355040713075265646d6f6e64311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e312630240603550403131d4d6963726f736f66742054696d652d5374616d70205043412032303130021333000001d62769ff722d56c8ae0001000001d6300d06096086480165030402010500a082014a301a06092a864886f70d010903310d060b2a864886f70d0109100104302f06092a864886f70d01090431220420be0bf8d1c2f3fef1562d316e73b88ee23a68c8379e908fc000fff4a1a916b5e43081fa060b2a864886f70d010910022f3181ea3081e73081e43081bd0420d6cb4d0d5778d33e1018a738424c8d97748cc343babf802be3bc3f5da3e524fc308198308180a47e307c310b3009060355040613025553311330110603550408130a57617368696e67746f6e3110300e060355040713075265646d6f6e64311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e312630240603550403131d4d6963726f736f66742054696d652d5374616d70205043412032303130021333000001d62769ff722d56c8ae0001000001d630220420008bec188364bec68e2b350680f479a2f865e81246ac487e3d18d1eee2c779e0300d06092a864886f70d01010b050004820200ba6a65c98fc7a3b4ba94472e577855a24b0e24ac9ce7d4e99f496fa42149ca9f78a85ff01d752646045081c97ebd05237b970b904374f34f930d066ec2eba9c1515f9b6aeece607c820774d41957043e32f4b347d0510fdd4f26f6d7626b892748c08ee3d015d3b2a21ad557fe1113dfd12592c1e88d9e1d1a26028af3c95875df58a1624fa87fa31b7027ce7093968c1b1cf7cbf1a0eca439298bf7bb5c2619bdde8506d17f5ae29ed3bc32d1c983219be6fa8f9193067bd6ccb3d475594feafc69aab0a818ae1f679ac44f579c3faa164360324214b432e79af4cf5a098f89fa7fe1676dd3bfb32954d2ebc26a93f24e04ae8d8845f02f4c807cce6865a3bf2d4c833ec3233edd1b9d736d37c4f0583b182331fa7bd8fbd2503e2f84d5a86f8727b983b9df638128441ad499b79c807e10f2ceea1c259e3de50489e262f5a7872e17273d04d96ea8b61ffb4f4560f652c8f9e4f3332b8aab3498880bbd8536933f75a66e834484e4e2db141360a3b6da7431654f1bfb6a57c9c822013f160ffe0384eb788e69d119e017adeaccca93292b6222cf55ae4b855e4edc8e9a128868700bc3f515214273ce0761db54f246855cc1d9b4f01ef70659c0b829978ad6f828802a35cdf9454a3e19aec6845d3df80f509cb401226b0a96cecd068371d07fb517b7085824249bd60417b55c98f4654cf362ebe655599d1a14262b5cb8c3>


Payload
=======

<172 bytes: 7b0a202022782d6d732d736576736e70766d2d677565737473766e223a202230222c0a202022782d6d732d736576736e70766d2d6c61756e63686d6561737572656d656e74223a2022313065613931303263666663613336623833316433323731653938346439383065323939343938373461613664386234643662323233323863373731646165343138336465623133316234343535663763386666623566306463303431313535220a7d>

Text:
{
  "x-ms-sevsnpvm-guestsvn": "0",
  "x-ms-sevsnpvm-launchmeasurement": "10ea9102cffca36b831d3271e984d980e29949874aa6d8b4d6b22328c771dae4183deb131b4455f7c8ffb5f0dc041155"
}

Signature
=========

<384 bytes: 1f7969445d393186f85b47d0391dca81ac7e39fddb7b57c7244d6d4ba5f61293c5366b790e578d9ddd94935693b4065395aed7d3b0d8ad776d1f6fc931bfcd165807bfa0603ba2e30a617f93e88a0404f8d1e8582d28338579d77bc4dd59560cb82945bf7b39942c2fd9e0abcce99ac6154a2a70ac1fa7007ce0cc52ed4e8d4696c5e4a87291b3540ef5d2b7295aab0e580032ffcc1ef6070f885ba5096ac1c44d355f4386ff9d917a5126e3cd3562e583bc893771199469e4d5bd83f90637449a181c96fce9976f8a56c3be5ef5f1ff84574fa171ffea6178b4a8d52b785f7930dcc36284c512cf9a34e65441f260957d9fff125bd8eed34a227b438363fd432c92e4af2572d36f83fe3d7948b000ecf543e00e5605978e8fcd484d29aa68002b73b20d50c5e4d5a10a9e54955d786781160f56b7b724ba119114f5b56b48ab761864f1010ded91b63dd6a1b53a143c84fd163eb6c19b721dc90900ce66f795a5155ec03f7de26845d0634977e8911321decda7e01cee8d399a992d5600430a>
```

There are 3 certficates from x5chain

```bash
base64 -d cert1.pem > cert1.der
openssl x509 -in cert1.der -text -noout
```

```
openssl x509 -in cert1.der -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            33:00:00:00:0f:3b:d6:2b:4c:82:69:37:a7:00:00:00:00:00:0f
        Signature Algorithm: sha384WithRSAEncryption
        Issuer: C = US, O = Microsoft Corporation, CN = Microsoft SCD Systems RSA CA
        Validity
            Not Before: Apr 20 18:46:57 2023 GMT
            Not After : Apr 17 18:46:57 2024 GMT
        Subject: C = US, ST = WA, L = Redmond, O = Microsoft Corporation, CN = AKSKataConfUvm
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (3072 bit)
                Modulus:
                    00:82:ef:54:cb:f7:a9:13:88:94:2b:06:08:ff:4c:
                    d0:1e:3d:77:a8:e2:04:b1:23:8c:92:94:f5:e9:60:
                    6a:f8:75:a8:31:95:ca:b3:3b:05:e5:94:5a:14:75:
                    4b:bc:17:a6:86:8e:e5:1e:c5:0b:13:3b:38:68:42:
                    a3:f1:e0:48:08:43:c6:77:80:64:b2:58:9e:6d:95:
                    7e:5e:b8:5f:b8:64:c5:45:3c:37:69:e0:be:43:bd:
                    ea:9c:c4:fc:69:0d:c6:38:b7:c0:be:53:47:87:2b:
                    bd:f8:6c:37:c8:54:bb:f7:3c:d9:ec:02:af:39:1d:
                    bb:8f:55:a0:db:20:d4:25:57:06:9c:f2:c8:02:d3:
                    03:67:ae:c0:9a:66:37:63:3b:47:82:b9:d9:ee:37:
                    f8:25:65:a6:a4:00:5b:53:67:f1:27:23:fa:9f:d7:
                    53:ff:29:34:4e:d8:d8:1b:21:97:93:ff:77:f2:c6:
                    6f:17:91:c6:a2:99:d4:bd:fb:63:50:f8:99:9e:af:
                    06:21:70:9c:c9:c7:12:76:bc:8f:1d:da:b0:f0:11:
                    d7:9a:d0:35:7a:b4:4c:18:67:83:85:63:da:c7:0b:
                    d3:14:c6:20:a2:92:94:53:7e:3f:bd:28:f6:93:56:
                    59:32:0f:4e:d8:83:c3:30:4d:54:ee:a7:06:ae:bc:
                    56:e4:df:62:39:2b:17:01:c0:a9:0d:ef:7e:ba:fb:
                    9a:f3:c4:f6:db:04:26:34:fa:36:88:27:5b:ba:99:
                    70:54:77:16:59:48:e0:2e:f3:15:ed:d9:da:a1:7f:
                    86:17:6b:48:27:a2:02:91:f1:d0:a2:68:40:92:71:
                    32:c6:78:b7:f6:22:2c:48:e4:23:67:28:76:9a:d2:
                    82:ac:df:fb:a5:03:a8:7a:d4:0f:f6:48:01:cd:4e:
                    a0:bb:4d:d7:3e:23:0a:a2:a2:0a:e7:59:2e:68:5e:
                    b1:27:df:13:59:ed:11:ec:1b:e8:c3:3f:6d:c7:78:
                    1b:b8:7d:d0:4f:8f:6c:84:22:2b
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                1.3.6.1.4.1.311.76.59.1.1, 1.3.6.1.4.1.311.76.59.1.5
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                62:F5:41:E6:C7:84:66:DA:86:33:68:5B:4D:5D:68:B5:D1:10:FE:8F
            X509v3 Subject Alternative Name: 
                DirName:/OU=Microsoft Corporation/serialNumber=500095\+500980
            X509v3 Authority Key Identifier: 
                6D:38:7E:87:BC:22:E5:AA:6A:C9:AC:90:DB:C2:68:D4:EE:82:8E:FF
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:http://www.microsoft.com/pkiops/crl/Microsoft%20SCD%20Systems%20RSA%20CA.crl
            Authority Information Access: 
                CA Issuers - URI:http://www.microsoft.com/pkiops/certs/Microsoft%20SCD%20Systems%20RSA%20CA.crt
    Signature Algorithm: sha384WithRSAEncryption
    Signature Value:
        97:44:bd:42:bd:8a:d9:9b:3d:83:3c:8c:93:92:28:c0:45:b0:
        46:1b:09:bd:48:8b:8f:af:13:81:0b:97:44:7e:f7:a8:26:56:
        8f:8f:c6:8b:b1:30:36:a7:47:c6:85:0e:4e:09:ef:ab:30:71:
        03:aa:99:60:71:fa:0e:e0:fc:f8:79:fa:bd:fc:75:ef:1a:d8:
        17:e5:eb:da:6b:68:15:a0:12:97:26:55:19:65:45:26:5d:97:
        2e:f9:44:25:0e:ea:1e:22:6b:19:50:16:26:67:bd:fd:95:67:
        53:de:8f:05:4d:87:85:4d:71:3b:e7:7f:cd:65:f0:2d:ae:9b:
        e7:d5:75:2c:de:c4:db:08:71:f1:3f:e6:42:34:d8:0b:ea:f7:
        f4:75:29:97:2b:e2:2d:41:a6:9d:3d:0e:15:11:29:2d:2b:70:
        51:d7:1a:83:a9:fd:da:8b:18:f4:18:83:43:c4:ae:0a:e5:af:
        fe:b4:10:58:5b:36:1f:2f:45:4f:1a:dd:53:4a:11:18:48:a1:
        fb:29:df:30:f3:4d:12:18:d2:82:c6:ca:a1:9b:ef:cc:cc:d7:
        bb:66:d3:f7:d2:bd:d5:eb:59:44:b3:95:0a:ce:11:bf:e1:d8:
        d1:3b:9c:87:fc:e6:3d:bc:d7:af:fa:8a:2f:a8:b1:cf:75:1a:
        36:cc:0d:98:82:83:29:be:4a:43:0e:43:d1:6c:91:b6:23:9b:
        6a:79:73:9b:7a:2b:14:45:e3:d7:05:b3:6e:50:e2:c3:29:d2:
        d8:cd:98:bb:ec:78:b8:92:76:37:75:3b:91:43:39:b6:92:16:
        b7:7f:88:a4:57:b7:40:b0:c3:3c:df:2c:e5:5a:eb:83:de:06:
        0a:41:f4:0d:97:63:b2:a3:31:26:cc:96:6c:2e:c1:0a:93:3f:
        1e:d3:9b:69:29:8b:2e:7b:06:f6:f0:0c:9d:8b:9c:b4:79:37:
        a9:43:5b:57:0f:4a:a6:ae:2a:6b:22:03:72:6b:39:5c:ed:87:
        92:57:ac:be:a6:b6:54:48:04:24:e4:df:58:26:67:ca:3b:8a:
        34:a2:26:b2:3e:61:57:9d:e4:fd:00:d4:c2:1e:46:e7:45:53:
        86:b4:a2:71:85:c2:2f:68:b2:9e:aa:24:5a:e1:38:37:33:98:
        6a:d2:96:a6:7b:80:6f:0b:93:53:ec:65:09:96:e4:9f:d4:e2:
        d2:12:23:3b:19:01:36:bc:ea:5a:09:db:84:b2:bd:a2:3e:84:
        04:7e:20:e4:f0:7f:e7:5c:db:6f:63:19:69:fb:4c:11:92:04:
        e4:07:77:6f:90:62:5b:4a:68:f6:82:0b:2d:43:79:51:42:e9:
        f5:48:82:6c:dc:31:ca:de
```

```bash
base64 -d cert2.pem > cert2.der
openssl x509 -in cert2.der -text -noout
```

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            33:00:00:00:02:cb:1e:1d:ae:36:7f:a7:7e:00:00:00:00:00:02
        Signature Algorithm: sha384WithRSAEncryption
        Issuer: C = US, O = Microsoft Corporation, CN = Microsoft Supply Chain RSA Root CA 2022
        Validity
            Not Before: Feb 17 00:45:19 2022 GMT
            Not After : Feb 17 00:55:19 2042 GMT
        Subject: C = US, O = Microsoft Corporation, CN = Microsoft SCD Systems RSA CA
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                    00:a0:0f:5a:b1:04:a8:e2:39:e8:e6:23:a0:53:ee:
                    f0:6c:af:7e:c8:a9:ff:e5:63:fb:45:5d:c3:55:b6:
                    9c:1d:33:a3:36:d0:15:c9:57:21:4e:41:d3:16:4d:
                    fa:92:08:da:d3:72:ae:b2:f5:9a:f4:9e:8e:d7:b4:
                    62:b7:02:12:b2:8e:16:f6:ef:74:02:e4:86:d7:07:
                    da:0b:f0:d9:05:7c:85:c1:7f:34:0e:6e:47:c6:f0:
                    27:a4:04:4a:78:65:d5:44:fd:32:6a:1b:27:9f:79:
                    62:bc:97:96:68:3e:2e:28:f7:20:34:d3:a8:62:41:
                    4a:b3:b0:97:19:b5:ff:8a:e5:fa:ea:97:47:7e:f2:
                    47:e9:8d:85:90:1e:93:76:80:91:b5:50:54:7d:9b:
                    90:08:5e:6e:7e:8b:fb:2f:76:f3:cf:05:75:9c:d9:
                    b2:5d:94:d6:ef:c1:05:f7:d6:fc:95:ad:42:b4:58:
                    39:bc:78:d6:12:87:d4:02:64:f1:ac:12:48:03:3b:
                    e1:56:fe:37:5f:e3:20:55:a9:b7:17:e8:af:61:05:
                    48:39:a0:41:b4:aa:5d:ce:b8:73:42:ff:75:58:56:
                    c4:3d:0f:8f:02:77:c5:42:68:10:1a:b7:b5:55:33:
                    27:59:83:4f:09:27:d7:ff:41:c4:36:3c:8e:44:e2:
                    06:1f:d5:1e:53:98:57:f4:e9:a7:32:72:65:7e:7a:
                    02:ca:bd:da:11:b5:04:cb:c1:f7:de:f8:3f:61:2c:
                    76:77:9c:3a:6b:a9:38:65:d2:be:93:68:7c:81:1d:
                    4e:fb:11:8d:f1:27:f3:f5:0e:02:6b:12:e2:06:66:
                    94:8b:f5:f5:41:0b:b9:4b:47:a8:9d:88:da:ba:6d:
                    77:e3:67:3d:8e:63:6f:10:52:01:6e:d0:ad:24:e8:
                    65:8e:ca:ad:18:3a:bb:65:c8:bd:d2:bd:fb:ea:0b:
                    93:8c:8c:32:61:e3:f8:6b:80:a1:e8:f3:b6:ea:f3:
                    40:2a:09:fb:ba:c0:9b:90:ef:43:0c:4e:0a:5e:15:
                    04:b0:17:ec:ac:fe:94:86:94:6b:94:4d:1a:20:63:
                    15:4e:ec:24:cb:9b:96:3a:58:af:bf:b1:29:02:20:
                    38:b0:00:11:a1:35:87:4b:4a:a6:54:52:02:55:ae:
                    81:a9:e6:d2:09:df:95:a1:6b:ca:1b:84:3e:ed:43:
                    b5:5d:61:8e:74:23:54:a1:e0:42:65:72:b3:8e:3a:
                    c4:15:96:6a:26:a1:ce:ea:c6:ff:42:33:53:c6:01:
                    c2:da:b9:7b:86:c3:4f:ac:29:02:0a:bd:a2:be:59:
                    2f:05:53:0e:c1:57:6c:e1:6c:46:87:9c:b8:d1:2d:
                    08:98:7d
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
            1.3.6.1.4.1.311.21.1: 
                ...
            X509v3 Subject Key Identifier: 
                6D:38:7E:87:BC:22:E5:AA:6A:C9:AC:90:DB:C2:68:D4:EE:82:8E:FF
            X509v3 Certificate Policies: 
                Policy: X509v3 Any Policy
            1.3.6.1.4.1.311.20.2: 
                .
.S.u.b.C.A
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Authority Key Identifier: 
                0B:B3:68:3B:AF:DA:AF:EE:70:A5:76:D9:21:F7:CC:44:16:07:D0:F8
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:http://www.microsoft.com/pkiops/crl/Microsoft%20Supply%20Chain%20RSA%20Root%20CA%202022.crl
            Authority Information Access: 
                CA Issuers - URI:http://www.microsoft.com/pkiops/certs/Microsoft%20Supply%20Chain%20RSA%20Root%20CA%202022.crt
    Signature Algorithm: sha384WithRSAEncryption
    Signature Value:
        43:80:c7:a3:76:d7:16:96:7b:b5:29:84:8f:f5:20:14:76:40:
        93:dc:e1:92:50:b4:d7:a6:ce:aa:86:68:c2:6e:4f:57:40:c3:
        77:3d:b5:bb:d0:2b:37:7f:08:cd:c6:5a:d9:30:66:e3:68:12:
        c7:09:40:e9:f2:5c:07:04:b3:f7:c0:8b:b5:6d:ce:2c:9a:ef:
        c8:14:f7:f7:75:81:7c:bc:e3:39:2a:d1:44:31:f1:e9:00:76:
        27:50:88:be:de:7c:78:99:75:d6:d0:bb:72:32:8e:0f:df:a6:
        d0:01:9b:23:83:06:d8:27:27:2e:e8:be:f1:07:45:97:ab:d5:
        9b:e4:e2:f0:44:3b:5e:2f:5f:df:18:cb:82:89:6b:d6:5f:d1:
        9e:a0:a3:d2:91:9a:fb:26:aa:47:3d:11:80:29:bf:49:6a:4a:
        9c:92:9d:7a:19:ec:60:2d:cf:4a:c4:d7:a0:3f:9d:d5:7c:e1:
        26:d9:b0:d3:45:78:55:62:dd:24:62:b4:1c:e3:d3:08:6a:47:
        83:48:9a:ce:8b:3f:82:d1:fe:27:8b:bf:de:39:21:b9:52:f2:
        85:5f:c6:3a:41:ed:4f:e6:5c:a7:f5:b8:0d:dc:e2:cd:a1:5f:
        f2:fa:07:f0:d1:99:9b:04:61:71:04:c3:c0:e0:fb:b3:f7:5f:
        fc:25:a5:f4:47:0a:81:67:a3:76:54:1d:b9:f8:c9:55:86:4b:
        b5:3d:8f:2f:d0:3b:91:08:dd:06:d1:1d:90:10:fe:cf:98:d1:
        e7:16:b5:d5:d5:9d:53:b1:1e:0b:d6:6c:c3:5d:a6:33:1e:4c:
        df:0a:77:e1:4f:a2:67:a5:e7:2f:9b:55:fc:d1:70:9d:37:51:
        37:f4:b3:7c:cc:7b:21:4b:ac:3b:05:91:c7:d2:20:77:c1:ac:
        58:ec:69:14:23:07:69:34:72:90:74:12:09:dd:db:68:a8:c8:
        c3:f8:71:35:30:3a:cd:b2:27:d0:d6:00:a9:07:90:06:8a:53:
        6f:a4:7f:36:18:a1:7f:28:4c:32:7b:86:7f:2c:f0:c4:af:6c:
        53:e4:52:84:fb:6a:26:7c:1b:01:28:56:1d:cf:67:1d:0e:05:
        95:6c:31:aa:3e:05:0a:fb:be:72:a9:89:f0:82:bd:e0:a8:38:
        71:81:f9:ec:45:06:40:4c:db:ca:d0:b7:25:02:65:0b:cb:29:
        3d:c6:a2:6d:e2:59:58:d0:d6:25:30:cc:6c:1c:04:81:74:4f:
        11:b3:cb:e8:84:bf:3e:a2:36:ba:3c:53:4b:b1:1f:bd:b7:e0:
        e8:eb:a8:71:4e:84:3b:0f:2d:a7:dc:fd:7c:12:14:93:17:b6:
        a2:54:01:d2:46:7c:79:78
```

```bash
base64 -d cert3.pem > cert3.der
openssl x509 -in cert3.der -text -noout
```

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            68:28:d5:4c:7e:5c:da:bd:43:39:ae:0c:c1:5a:2a:35
        Signature Algorithm: sha384WithRSAEncryption
        Issuer: C = US, O = Microsoft Corporation, CN = Microsoft Supply Chain RSA Root CA 2022
        Validity
            Not Before: Feb 17 00:12:36 2022 GMT
            Not After : Feb 17 00:21:09 2047 GMT
        Subject: C = US, O = Microsoft Corporation, CN = Microsoft Supply Chain RSA Root CA 2022
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                    00:9e:25:01:66:19:1f:64:34:c1:9d:39:23:62:1d:
                    71:8b:56:ea:25:d2:9b:1f:ef:27:01:82:bf:77:d8:
                    94:33:83:18:48:9b:50:9e:7b:96:64:c2:d0:c3:5f:
                    45:ff:32:9c:e8:17:17:bd:78:ed:75:98:5f:3a:06:
                    08:2b:1c:37:9b:46:4a:90:0a:b0:af:46:92:3e:33:
                    89:2a:fa:b8:e7:32:63:f3:23:c7:6e:d2:14:fb:26:
                    58:ee:fe:06:84:54:fa:c1:1f:37:aa:db:d4:ec:56:
                    2a:bf:49:bd:cc:eb:02:ed:c6:4e:fc:ac:19:b5:12:
                    35:69:15:89:17:4d:a3:68:ea:6c:1e:29:9a:09:f3:
                    ce:7a:21:c6:09:d1:19:ea:8f:30:46:69:3b:68:04:
                    2b:7c:8a:2d:d6:63:5d:ea:6d:d6:39:9e:bd:06:3e:
                    5b:ee:2f:11:5b:28:6b:a7:52:a4:68:5e:4c:a4:ea:
                    ae:ce:23:bf:4c:36:71:da:81:45:50:8e:ca:86:ce:
                    ff:53:c3:b8:43:b3:24:ee:07:7a:a2:b4:fa:c7:0a:
                    1d:7b:c6:52:35:31:ec:08:1f:84:80:92:5b:f8:b1:
                    da:39:d6:c9:e7:e5:89:04:7e:51:7f:f4:e6:6a:64:
                    47:49:ea:f8:ec:a6:f6:a0:43:53:fe:da:c3:23:24:
                    d8:25:da:13:2c:2a:b7:3f:94:de:77:1c:4c:78:1c:
                    6a:f9:9a:8f:eb:6a:15:77:77:ad:49:84:ce:10:40:
                    c7:99:48:0f:d5:96:1e:80:9c:73:a1:38:a1:03:6f:
                    d3:4d:20:d0:b5:43:e4:f7:2e:78:0f:4e:f7:bc:bf:
                    65:da:6d:90:0b:5b:bf:de:ea:27:27:99:64:f8:39:
                    7c:73:3d:d6:21:d2:ee:d6:f3:53:11:2e:55:c3:dc:
                    ea:f1:29:57:de:51:a1:78:73:90:0b:2f:f5:c9:75:
                    36:eb:8d:d2:6d:8e:79:5d:ba:1a:38:ff:df:19:01:
                    a8:d2:c8:d1:d6:f2:eb:8a:f5:2e:d1:cc:93:13:9b:
                    9c:90:78:65:63:79:04:c4:f1:9e:9f:8c:3a:f3:64:
                    0c:fe:98:1d:93:e2:8f:56:a5:63:53:23:b8:6e:73:
                    16:45:1a:b6:f7:7b:0f:cd:a4:32:ff:5a:fe:96:8d:
                    e1:87:78:db:70:83:a8:24:85:69:20:c2:6d:12:0d:
                    e5:79:f6:2a:59:cf:d6:ab:e7:81:e6:a0:b1:88:2d:
                    08:8c:0b:b1:cf:d7:6c:36:af:9e:f9:03:67:d9:41:
                    73:a9:ab:45:b8:71:60:58:18:d4:16:2c:65:ba:d1:
                    05:de:92:c5:50:10:11:90:ce:47:cc:fb:af:bf:23:
                    c0:9f:05
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier: 
                0B:B3:68:3B:AF:DA:AF:EE:70:A5:76:D9:21:F7:CC:44:16:07:D0:F8
            1.3.6.1.4.1.311.21.1: 
                ...
            X509v3 Certificate Policies: 
                Policy: X509v3 Any Policy
    Signature Algorithm: sha384WithRSAEncryption
    Signature Value:
        48:c7:37:ff:ff:c1:68:57:d7:8b:43:66:46:3a:26:6b:2f:e8:
        fa:de:68:a1:8f:47:f1:3d:34:95:7a:da:55:31:f4:95:d2:38:
        5f:2c:ba:8f:a5:8d:51:31:6a:89:55:68:6c:2b:42:64:6a:85:
        24:a0:51:03:c7:dd:d1:72:58:ed:6c:1e:8c:d8:91:c5:e7:49:
        11:9d:19:7a:37:58:1e:77:44:fb:c2:08:98:42:c4:4d:e3:9b:
        8a:0e:cf:40:45:4f:1b:80:70:59:8c:93:81:e8:0f:d5:c8:26:
        95:a9:f7:1f:77:06:b8:ca:ef:9c:fb:e8:66:da:e5:39:e0:d2:
        d2:62:c3:a7:d4:b6:18:9a:27:9b:26:50:4a:72:97:d5:b3:5b:
        2a:a4:fd:5f:2f:7e:e6:62:a3:27:66:0c:fa:d9:19:cc:11:1d:
        31:a8:01:52:08:e6:54:0c:99:63:2b:ea:d8:84:d4:b4:08:16:
        ef:be:4a:5b:88:58:f4:06:16:a0:eb:7a:5d:e1:c7:44:d6:bb:
        2f:55:56:25:f0:9e:0c:e4:0f:12:db:c0:7f:af:56:5d:c6:89:
        0e:71:a9:56:12:e4:b9:9c:a8:64:1e:b5:47:95:92:ae:d0:70:
        c8:93:7d:7c:5a:58:f1:05:f1:4a:b8:6c:72:18:a9:ae:1f:57:
        99:26:74:66:f5:1d:0f:df:5d:f0:e7:37:5b:5f:ba:f0:b4:ef:
        e4:63:07:7e:1f:32:18:69:a9:70:5a:92:f9:79:9c:58:d4:7e:
        bf:72:5d:53:46:2b:6e:a3:99:60:d6:85:8c:66:77:16:76:af:
        e2:c5:18:5b:e2:5d:08:36:d6:66:37:17:65:f0:2e:cf:a1:e5:
        bc:e6:8d:0d:65:b4:56:53:5d:9f:c8:af:4e:6e:51:cf:88:be:
        92:ea:30:fb:2c:e7:75:3f:42:60:c4:71:e7:97:9f:73:c7:9f:
        ca:d1:b8:6c:23:ea:50:28:1d:0e:43:cc:f5:a9:1b:40:eb:a6:
        98:e5:e5:0f:c5:92:2f:a5:96:c7:d7:fa:3c:18:ee:1d:1b:61:
        03:fd:86:e7:24:41:33:bd:d8:f3:b6:60:7c:f3:1c:82:03:d5:
        60:af:df:f4:20:a4:e4:81:06:22:5a:cc:85:33:7d:64:f8:e4:
        b8:bf:80:17:d4:fb:21:3f:63:ae:e7:8f:b7:17:44:ec:72:2e:
        35:c9:0b:d0:81:1d:e9:72:03:09:41:d9:df:09:48:e6:cd:b7:
        b2:1c:60:25:19:52:f3:3d:12:49:ed:9d:94:22:8e:71:28:f8:
        c1:07:54:73:dd:38:08:b4:85:8f:14:6c:aa:00:af:40:ab:b5:
        87:ce:b6:39:5c:73:f9:90
```

## Remote attestation
When perform remote attestation against Microsoft Azure Attestation, runtime data in request body is in base64 encoded JSON format, the MAA will verify that the runtime data is known to the attestation target, and included it in the attestation token.

For more details, see [Attestation](https://learn.microsoft.com/en-us/rest/api/attestation/attestation/attest-sev-snp-vm?view=rest-attestation-2022-08-01&tabs=HTTP).

During Secure Key Release, application can generate a RSA key pair, RSA public key will be embedded into runtime data and used to encrypt the key encryption key from Azure Key Vault, the key encryption key will be decrypted by using the RSA private key and used to decrypt the private key from Azure Key Vault.

For example, MAA Attestation Request could add below runtime data in request body:

```json
{
  "keys": [
    {
      "e": "AQAB",
      "key_ops": [
        "encrypt"
      ],
      "kid": "AlKDxHf-oEnfzO3ShWSEIn0md9Pos0AZ70dSjl0Z_w8",
      "kty": "RSA",
      "n": "yyZXwIQhClf8aDsToDWkzX6RcsCgFpna4BKT3TEEKp3SPaOI89k8tU81_6SxRvx9i8RSjyP-rr9cjiReukVcXlYxqX-MOfia7vjPhwOEUDhgR8Hij6qKL2ozkjGrf46MGaH_ZY9_iTjHc9kS3Nt5WyGRSL_XRDVlopo3eKRoe4tIwweOL_jnrixjp32JzOsQ8ZeuacoWWLZ6vtv3k8CAS4iotTJVi7mapcgh7o3yBnUQXkHcLZ-q8uQhCY86jKBHpOZPteqFfNN09lBGnfmq7ZM6fSClR9yix-bExBjEeNW59SfelQRLPJ3gh4M9pYXebE7f6M5WmqXlIRTL0UuxtQ"
    }
  ]
}
```

MAA Attestation Response will have below field in token:

```json
{
...
  "x-ms-runtime": {
    "keys": [
      {
        "e": "AQAB",
        "key_ops": [
          "encrypt"
        ],
        "kid": "AlKDxHf-oEnfzO3ShWSEIn0md9Pos0AZ70dSjl0Z_w8",
        "kty": "RSA",
        "n": "yyZXwIQhClf8aDsToDWkzX6RcsCgFpna4BKT3TEEKp3SPaOI89k8tU81_6SxRvx9i8RSjyP-rr9cjiReukVcXlYxqX-MOfia7vjPhwOEUDhgR8Hij6qKL2ozkjGrf46MGaH_ZY9_iTjHc9kS3Nt5WyGRSL_XRDVlopo3eKRoe4tIwweOL_jnrixjp32JzOsQ8ZeuacoWWLZ6vtv3k8CAS4iotTJVi7mapcgh7o3yBnUQXkHcLZ-q8uQhCY86jKBHpOZPteqFfNN09lBGnfmq7ZM6fSClR9yix-bExBjEeNW59SfelQRLPJ3gh4M9pYXebE7f6M5WmqXlIRTL0UuxtQ"
      }
    ]
  }
...
}
```

```bash
runtime_data=$(echo '{"keys": "none"}' | base64)

token=$(curl -H "Content-Type: application/json" -XPOST -d '{"maa_endpoint":"sharedsasia.sasia.attest.azure.net","runtime_data":"'"$runtime_data"'"}' http://localhost:8080/attest/maa)

header=$(echo "${token}" | jq -r '.token' | cut -d "." -f 1)

r_header=$((${#header} % 4))
if [ $r_header -ne 0 ]; then
    padding=$(printf "%0.s=" $(seq $((4 - r_header))))
    header="${header}${padding}"
fi

echo $header | base64 -d

payload=$(echo "${token}" | jq -r '.token' | cut -d "." -f 2)

r_payload=$((${#payload} % 4))
if [ $r_payload -ne 0 ]; then
    padding=$(printf "%0.s=" $(seq $((4 - r_header))))
    payload="${payload}${padding}"
fi

echo $payload | base64 -d

```  

## Security policy for Confidential Containers

In AKS Confidential Containers, security policy that specifies the rules and data for creating and managing CVM-based Kubernetes pods. The policy is enforced by the Kata agent inside the TEE using the Open Policy Agent (OPA)

For more details, see [Security policy for Confidential Containers on Azure Kubernetes Service](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-containers-aks-security-policy), [Proposal for Container Metadata Validation](https://github.com/confidential-containers/confidential-containers/issues/126), [Kata Agent Policy](https://github.com/microsoft/kata-containers/blob/cc-msft-prototypes/docs/how-to/how-to-use-the-kata-agent-policy.md)

```bash
sha256sum ./debug/katacc-cce-policy-debug.rego 
59f6818ede2b7124ea2c912a88fa99d9a052e472bcfd3bcc4be69d3866e9d3c3  ./debug/katacc-cce-policy-debug.rego
```