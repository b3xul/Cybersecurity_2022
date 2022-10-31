# X.509 certificates and PKI

### Laboratory for the class “Cybersecurity” (01UDR)

### Politecnico di Torino – AA 2021/

### Prof. Antonio Lioy

### prepared by:

### Diana Berbecaru (diana.berbecaru@polito.it)

### Andrea Atzeni (andrea.atzeni@polito.it)

### v. 1.0 (22/10/2021)

## Contents

1 Purpose of this laboratory 2

2 Analysis and status checking of X.509 certificates 5

```
2.1 Getting and analysing an X.509 certificate............................ 5
2.2 Certificate status checking.................................... 6
2.2.1 CRL verification..................................... 6
2.2.2 OCSP verification.................................... 7
2.2.3 OCSP Stapling...................................... 8
2.3 Extended Validation (EV), Organization Validation (OV), Domain Validated (DV)....... 8
```
3 Certificate Transparency 9

```
3.1 Analysing SCT extensions in an X.509 certificate........................ 9
3.2 Checking certificate presence in CT logs............................. 9
3.3 Known CT Logs.......................................... 10
```
4 Certificate chains and PKI models 10

```
4.1 Viewing and verification of simple certificate chains....................... 10
4.2 Viewing of a real Federal PKI.................................. 12
```

## 1 Purpose of this laboratory

In this laboratory, you will perform exercises to experiment more in depth with PKIs and X.509 certificates.

The laboratory uses the OpenSSL (http://www.openssl.org/) open-source library and tools, available for
various platforms, including Linux and Windows.

Most of the proposed exercises basically use the OpenSSL command line program, which allows the use of
several cryptographic functions by means of the OpenSSL shell that can be started with the following command:

```
openssl command [commandopts ] [commandargs ]
```
## openssl x

```
To sign and view an X.509 certificate, you can use the OpenSSL commandx509. Actually, thex
command is a multi purpose certificate utility: it can be used to display certificate information, convert
certificates to various forms, sign certificate requests (behaving thus as a “mini CA”), or edit certificate
trust settings. The simplified syntax of this command for the purpose of exercises proposed is:
openssl x509 [-inform DER|PEM] [-outform DER|PEM] [-in file] [-out file]
[-noout] [-req] [-text]
where the main options have the following meaning:
```
```
-inform DER|PEMspecifies the input format; normally the command will expect an X.509 certificate
but this can change if other options (such as-req) are present. The DER value indicates that the
input certificate is encoded with the DER encoding, PEM that the certificate is encoded in PEM,
which is the base64 encoding of the DER encoding with header and footer lines added.
```
```
-outform DER|PEMspecifies the output format (same possible values as with the-informoption).
```
```
-infilenamespecifies the input file to read a certificate from (standard input is used otherwise).
```
```
-out filenamespecifies the output file to write to (standard output is used otherwise).
```
```
-nooutindicates not to produce in output the Base64 representation of the certificate.
```
```
-reqindicates that the filefilepassed in with the option-incontains a request and not a certificate.
```
```
-textprints out the certificate in text form. Full details are shown including the public key, signature
algorithms, issuer and subject names, serial number any extensions present and any trust settings.
```
```
-ext extensionsprints out the certificate extensions in text form. Extensions are specified with a
comma separated string, e.g. “subjectAltName,subjectKeyIdentifier”.
```
```
-ocspuriOutputs the OCSP responder address(es) if any
```
```
To find out more details about thex509command execute:
man x
```
## openssl verify

```
This command allows the verification of a certificate and its certification chain. The verify operation
consists of a number of separate steps:
```
1. First a certificate chain is built up starting from the supplied certificate and ending in the root CA


```
(that is the first self-signed certificate being found). If the whole chain cannot be built up, an error
is signalled. The chain is built up by looking up the issuers certificate of the current certificate. If
a certificate is found which is its own issuer it is assumed to be the root CA.
In practice, to find the issuer, all certificates whose subject name matches the issuer name of the
current certificate are subject to further tests. The relevant authority key identifier components of
the current certificate (if present) must match the subject key identifier (if present) and issuer and
serial number of the candidate issuer, in addition the keyUsage extension of the candidate issuer
(if present) must permit certificate signing.
The lookup first looks in the list of untrusted certificates and if no match is found the remaining
lookups are from the trusted certificates. The root CA is always looked up in the trusted certificate
list: if the certificate to verify is a root certificate then an exact match must be found in the list.
```
2. The second operation is to check every untrusted certificate’s extensions for consistency with the
    supplied purpose. If the -purpose option is not included then no checks are done. The supplied
    or “leaf” certificate must have extensions compatible with the supplied purpose and all other
    certificates must also be valid CA certificates. The precise extensions required are described in
    more detail in the CERTIFICATE EXTENSIONS section of the x509 utility.
```
CERTIFICATE EXTENSIONS
       The -purpose option checks the certificate extensions and determines what the certificate can be used for. The actual checks done are rather complex and include various hacks and workarounds
       to handle broken certificates and software.

       The same code is used when verifying untrusted certificates in chains so this section is useful if a chain is rejected by the verify code.

       The basicConstraints extension CA flag is used to determine whether the certificate can be used as a CA. If the CA flag is true then it is a CA, if the CA flag is false then it is not a CA.
       All CAs should have the CA flag set to true.

       If the basicConstraints extension is absent then the certificate is considered to be a "possible CA" other extensions are checked according to the intended use of the certificate. A warning
       is given in this case because the certificate should really not be regarded as a CA: however it is allowed to be a CA to work around some broken software.

       If the certificate is a V1 certificate (and thus has no extensions) and it is self signed it is also assumed to be a CA but a warning is again given: this is to work around the problem of
       Verisign roots which are V1 self signed certificates.

       If the keyUsage extension is present then additional restraints are made on the uses of the certificate. A CA certificate must have the keyCertSign bit set if the keyUsage extension is
       present.

       The extended key usage extension places additional restrictions on the certificate uses. If this extension is present (whether critical or not) the key can only be used for the purposes
       specified.

       A complete description of each test is given below. The comments about basicConstraints and keyUsage and V1 certificates above apply to all CA certificates.

       SSL Client
           The extended key usage extension must be absent or include the "web client authentication" OID.  keyUsage must be absent or it must have the digitalSignature bit set. Netscape certificate
           type must be absent or it must have the SSL client bit set.

       SSL Client CA
           The extended key usage extension must be absent or include the "web client authentication" OID. Netscape certificate type must be absent or it must have the SSL CA bit set: this is used
           as a work around if the basicConstraints extension is absent.

       SSL Server
           The extended key usage extension must be absent or include the "web server authentication" and/or one of the SGC OIDs.  keyUsage must be absent or it must have the digitalSignature, the
           keyEncipherment set or both bits set.  Netscape certificate type must be absent or have the SSL server bit set.

       SSL Server CA
           The extended key usage extension must be absent or include the "web server authentication" and/or one of the SGC OIDs.  Netscape certificate type must be absent or the SSL CA bit must be
           set: this is used as a work around if the basicConstraints extension is absent.

       Netscape SSL Server
           For Netscape SSL clients to connect to an SSL server it must have the keyEncipherment bit set if the keyUsage extension is present. This isn't always valid because some cipher suites use
           the key for digital signing.  Otherwise it is the same as a normal SSL server.

       Common S/MIME Client Tests
           The extended key usage extension must be absent or include the "email protection" OID. Netscape certificate type must be absent or should have the S/MIME bit set. If the S/MIME bit is not
           set in Netscape certificate type then the SSL client bit is tolerated as an alternative but a warning is shown: this is because some Verisign certificates don't set the S/MIME bit.

       S/MIME Signing
           In addition to the common S/MIME client tests the digitalSignature bit or the nonRepudiation bit must be set if the keyUsage extension is present.

       S/MIME Encryption
           In addition to the common S/MIME tests the keyEncipherment bit must be set if the keyUsage extension is present.

       S/MIME CA
           The extended key usage extension must be absent or include the "email protection" OID. Netscape certificate type must be absent or must have the S/MIME CA bit set: this is used as a work
           around if the basicConstraints extension is absent.

       CRL Signing
           The keyUsage extension must be absent or it must have the CRL signing bit set.

       CRL Signing CA
           The normal CA tests apply. Except in this case the basicConstraints extension must be present.
```
3. The third operation is to check the root trust settings, i.e. check that the root CA is trusted.
4. The final operation is to check the validity of the certificate chain. The validity period is checked
    against the current system time and thenotBeforeandnotAfterdates in the certificate. The certifi-
    cate signatures are also checked at this point.

If all operations complete successfully then the certificate is considered valid. If any operation fails then
the certificate is invalid. When a verify operation fails, the output messages can be somewhat cryptic.
The general form of the error message is:

```
server.pem: /C=AU/O=CryptSoft Ltd/CN=Test CA (1024 bit)
error 24 at 1 depth lookup:invalid CA certificate
```
The first line contains the name of the certificate being verified, followed by the Subject in the certificate.
The second line contains the error number and the depth. The depth is number of the certificate being
verified when a problem was detected, starting with zero for the certificate being verified itself, then 1
for the CA that signed this certificate, and so on. Finally a text version of the error number is presented.
The most common error codes returned are listed in the manual page of this command (man verify).
```
0 X509_V_OK: ok
the operation was successful.
2 X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT: unable to get issuer certificate
the issuer certificate of a looked up certificate could not be found. This normally means the list of trusted certificates is not complete.
3 X509_V_ERR_UNABLE_TO_GET_CRL: unable to get certificate CRL
the CRL of a certificate could not be found.
4 X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE: unable to decrypt certificate's signature
the certificate signature could not be decrypted. This means that the actual signature value could not be determined rather than it not matching the expected value, this is only meaningful for RSA keys.
5 X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE: unable to decrypt CRL 's signature
the CRL signature could not be decrypted: this means that the actual signature value could not be determined rather than it not matching the expected value. Unused.
6 X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY: unable to decode issuer public key
the public key in the certificate SubjectPublicKeyInfo could not be read.
7 X509_V_ERR_CERT_SIGNATURE_FAILURE: certificate signature failure
the signature of the certificate is invalid.
8 X509_V_ERR_CRL_SIGNATURE_FAILURE: CRL signature failure
the signature of the certificate is invalid.
9 X509_V_ERR_CERT_NOT_YET_VALID: certificate is not yet valid
the certificate is not yet valid: the notBefore date is after the current time.
10 X509_V_ERR_CERT_HAS_EXPIRED: certificate has expired
the certificate has expired: that is the notAfter date is before the current time.
11 X509_V_ERR_CRL_NOT_YET_VALID: CRL is not yet valid
the CRL is not yet valid.
12 X509_V_ERR_CRL_HAS_EXPIRED: CRL has expired
the CRL has expired.
13 X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD: format error in certificate's notBefore field
the certificate notBefore field contains an invalid time.
14 X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD: format error in certificate's notAfter field
the certificate notAfter field contains an invalid time.
15 X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD: format error in CRL 's lastUpdate field
the CRL lastUpdate field contains an invalid time.
16 X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD: format error in CRL 's nextUpdate field
the CRL nextUpdate field contains an invalid time.
17 X509_V_ERR_OUT_OF_MEM: out of memory
an error occurred trying to allocate memory. This should never happen.
18 X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: self signed certificate
the passed certificate is self signed and the same certificate cannot be found in the list of trusted certificates.
19 X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN: self signed certificate in certificate chain
the certificate chain could be built up using the untrusted certificates but the root could not be found locally.
20 X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: unable to get local issuer certificate
the issuer certificate could not be found: this occurs if the issuer certificate of an untrusted certificate cannot be found.
21 X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE: unable to verify the first certificate
no signatures could be verified because the chain contains only one certificate and it is not self signed.
22 X509_V_ERR_CERT_CHAIN_TOO_LONG: certificate chain too long
the certificate chain length is greater than the supplied maximum depth. Unused.
23 X509_V_ERR_CERT_REVOKED: certificate revoked
the certificate has been revoked.
24 X509_V_ERR_INVALID_CA: invalid CA certificate
a CA certificate is invalid. Either it is not a CA or its extensions are not consistent with the supplied purpose.
25 X509_V_ERR_PATH_LENGTH_EXCEEDED: path length constraint exceeded
the basicConstraints pathlength parameter has been exceeded.
26 X509_V_ERR_INVALID_PURPOSE: unsupported certificate purpose
the supplied certificate cannot be used for the specified purpose.
27 X509_V_ERR_CERT_UNTRUSTED: certificate not trusted
the root CA is not marked as trusted for the specified purpose.
28 X509_V_ERR_CERT_REJECTED: certificate rejected
the root CA is marked to reject the specified purpose.
29 X509_V_ERR_SUBJECT_ISSUER_MISMATCH: subject issuer mismatch
the current candidate issuer certificate was rejected because its subject name did not match the issuer name of the current certificate. Only displayed when the -issuer_checks option is set.
30 X509_V_ERR_AKID_SKID_MISMATCH: authority and subject key identifier mismatch
the current candidate issuer certificate was rejected because its subject key identifier was present and did not match the authority key identifier current certificate. Only displayed when the -issuer_checks option is set.
31 X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH: authority and issuer serial number mismatch
the current candidate issuer certificate was rejected because its issuer name and serial number was present and did not match the authority key identifier of the current certificate. Only displayed when the -issuer_checks option is set.
32 X509_V_ERR_KEYUSAGE_NO_CERTSIGN:key usage does not include certificate signing
the current candidate issuer certificate was rejected because its keyUsage extension does not permit certificate signing.
50 X509_V_ERR_APPLICATION_VERIFICATION: application verification failure
an application specific error. Unused.
```
The simplified syntax of this command is:
```
openssl verify [-CAfilefile] [-crlcheck] [-CRLfilefile] [-verbose]
[certificates]
```
where:

```
-CAfilefileindicates a file (whose name is given infile) of trusted certificates. The file should
contain multiple certificates in PEM format concatenated together;
```
```
-helpprints out a usage message;
```
```
-verboseprints extra information about the operations being performed;
certificatesindicates one or more certificates to verify. If no certificate filenames are included, then
an attempt is made to read a certificate from standard input. They should all be in PEM format;
-crlcheckchecks end entity certificate validity by attempting to look up a valid CRL. If a valid CRL
cannot be found an error occurs;
-CRLfilefileThe file should contain one or more CRLs in PEM format. This option can be specified
more than once to include CRLs from multiple files;
```

For more details on the options of this command, you should run:

```
man verify
```
## openssl crl

The crl command processes CRL files in DER or PEM format. Among the other, it allow for CRL
validity verification and conversion from DER to PEM format and vice-versa
The simplified syntax of this command is:

```
openssl crl [-inform DER|PEM] [-outform PEM|DER] [-text] [-in filename]
[-out filename] [-noout] [-issuer] [-lastupdate] [-nextupdate] [-CAfile
file]
```
where:

```
-inform DER|PEMthis specifies the input format. DER format is DER encoded CRL structure. PEM
(the default) is a base64 encoded version of the DER form with header and footer lines;
```
```
-outform DER|PEMthis specifies the output format, the options have the same meaning and default as
the -inform option;
```
```
-infilenamethis specifies the input filename to read from or standard input if this option is not speci-
fied;
```
```
-textprint out the CRL in text form;
```
```
-nooutdon’t output the encoded version of the CRL;
```
```
-issueroutput the issuer name;
```
```
-lastupdateoutput the lastUpdate field;
```
```
-nextupdateoutput the nextUpdate field;
```
```
-CAfilefileverify the signature on a CRL by looking up the issuing certificate in file.
```
## openssl ocsp

The ocsp command performs many common OCSP tasks. It can be used to print out requests and
responses, create requests and send queries to an OCSP responder, and behave like a mini OCSP server
itself.
The simplified syntax of this command is:

```
openssl ocsp [-out file] [-issuer file] [-cert file] [-resptext] [-url
URL] [-CAfile file]
```
where:

```
-out filespecify output filename, default is standard output;
```
```
-issuerfilenamethis specifies the current issuer certificate. This option can be used multiple times.
The certificate specified infilenamemust be in PEM format. This option MUST come before any
-cert options;
```
```
-certfilenameadd the certificate filename to the request. The issuer certificate is taken from the
```

```
previous issuer option, or an error occurs if no issuer certificate is specified;
```
```
-resptextprint out the text form of the OCSP response
```
```
-url responderurlspecify the responder URL. Both HTTP and HTTPS (SSL/TLS) URLs can be
specified;
```
```
-CAfilefilefile containing trusted CA certificates. These are used to verify the signature on the OCSP
response.
```
## 2 Analysis and status checking of X.509 certificates

### 2.1 Getting and analysing an X.509 certificate

The first step consists in downloading the certificate you want to analyse. Open your browser (such as Firefox,
Chrome, or Edge) and connect to the URL:https://www.polito.it.

```
NOTE
You can alternatively use also other web sites, such ashttps://www.repubblica.it, orhttps://
http://www.sony.comand try to perform the operations below.
```
Click on the padlock sign in the address bar, that allows you to check the exchanged certificates (for example,
in Firefox select “Connection secure”, “More information”, “View certificate”) and view the details of the
certificate and of the certificate chain.

Save the server certificate and the signing CA’s certificate in PEM format (look for the “Download” entry
in the Miscellanous section), let’s suppose to call themwww-polito-it.pemandwww-polito-it-CA.pem
respectively.

```
NOTE
Some browser try to save those certificates using misleading names. For example, Firefox try to save
both the server certificate AND the CA certificate with the same namewww-polito-it.pem. Pay atten-
tion to this issue and properly rename them
```
Next, you can analyse their content with OpenSSL commands, as follows.

View the certificate/chain content:

```
openssl x509 -in www-polito-it.pem -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            a4:18:52:df:08:dc:33:ee:07:4c:82:c3:91:b3:dc:de
        Signature Algorithm: sha384WithRSAEncryption
        Issuer: C = NL, O = GEANT Vereniging, CN = GEANT OV RSA CA 4
        Validity
            Not Before: Feb 19 00:00:00 2021 GMT
            Not After : Feb 19 23:59:59 2022 GMT
        Subject: C = IT, postalCode = 10129, ST = Torino, L = Torino, street = Corso Duca degli Abruzzi 24, O = Politecnico di Torino, CN = www.polito.it
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (3072 bit)
                Modulus:
                    00:bc:02:41:4b:6e:bb:5b:5c:14:11:f0:e3:a1:e1:
                    9c:4f:05:53:66:07:b8:66:38:14:0e:7f:d6:10:39:
                    e1:f1:62:b6:fd:90:24:1a:56:88:a8:c9:9b:b4:da:
                    44:15:e0:36:5b:5e:84:d9:03:92:a6:1c:0e:f6:20:
                    62:21:c9:91:c7:cd:ec:47:69:62:01:ad:25:c6:67:
                    1d:75:1a:02:b5:06:cd:cb:31:3b:75:42:60:76:91:
                    b7:93:59:39:a6:e0:8b:3a:bd:3a:ef:77:38:0e:29:
                    d6:e4:72:d6:ae:87:c9:8b:f9:a7:ba:8f:65:c5:bf:
                    56:3a:ca:ad:73:05:21:fe:fc:86:0b:fc:ce:e4:95:
                    a6:f3:04:07:5e:90:50:c2:7a:65:c7:33:e2:0d:2e:
                    39:b8:81:20:27:e0:04:4d:bf:bf:b5:20:0f:af:08:
                    e5:f2:7d:44:c3:81:76:d6:07:ca:d3:f7:80:81:85:
                    13:17:99:24:b5:81:5e:7e:a2:a5:81:18:55:f3:71:
                    22:53:3f:8d:b4:92:4b:41:42:4d:25:d2:e8:e5:f1:
                    be:ae:2d:a4:18:0c:d1:76:c9:05:ab:18:bb:4d:4c:
                    9a:ab:d9:35:60:f1:65:02:86:1c:0d:37:96:1d:1d:
                    52:bf:57:41:13:be:3e:4c:14:25:99:83:5b:82:94:
                    63:8f:b4:64:a3:2a:95:bb:a9:d1:c1:ad:06:c8:10:
                    e8:ae:da:8e:a3:70:4f:f1:8c:64:8a:3f:72:37:ea:
                    31:4c:72:b6:0b:26:ca:34:72:cd:ce:c6:de:d6:94:
                    8f:2f:87:b4:2b:6b:22:1d:17:49:7f:01:08:45:9f:
                    33:d9:2f:73:66:04:2d:f3:95:a3:5f:ba:12:b7:c2:
                    b2:e1:1f:16:26:f9:d5:c2:0a:8d:ee:e5:6e:b5:fe:
                    ac:b5:d2:c8:2c:5c:d2:5e:7f:c5:d6:34:94:4e:0a:
                    5d:b7:67:9d:27:75:9a:95:dd:30:3f:6c:cf:ec:af:
                    c9:9a:b9:37:5c:62:ee:fc:99:ff
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Authority Key Identifier: 
                keyid:6F:1D:35:49:10:6C:32:FA:59:A0:9E:BC:8A:E8:1F:95:BE:71:7A:0C

            X509v3 Subject Key Identifier: 
                97:32:21:07:E2:BD:3B:DD:C9:DE:66:6C:35:6C:15:26:4E:9C:9F:9C
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Certificate Policies: 
                Policy: 1.3.6.1.4.1.6449.1.2.2.79
                  CPS: https://sectigo.com/CPS
                Policy: 2.23.140.1.2.2

            X509v3 CRL Distribution Points: 

                Full Name:
                  URI:http://GEANT.crl.sectigo.com/GEANTOVRSACA4.crl

            Authority Information Access: 
                CA Issuers - URI:http://GEANT.crt.sectigo.com/GEANTOVRSACA4.crt
                OCSP - URI:http://GEANT.ocsp.sectigo.com

            CT Precertificate SCTs: 
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : 46:A5:55:EB:75:FA:91:20:30:B5:A2:89:69:F4:F3:7D:
                                11:2C:41:74:BE:FD:49:B8:85:AB:F2:FC:70:FE:6D:47
                    Timestamp : Feb 19 10:09:11.355 2021 GMT
                    Extensions: none
                    Signature : ecdsa-with-SHA256
                                30:44:02:20:43:72:FD:5A:C9:AA:02:5D:98:37:C5:5E:
                                E4:10:CB:62:AF:D7:12:49:B9:8F:CB:12:90:5B:8E:1A:
                                47:50:44:05:02:20:70:E3:2D:F2:C5:CB:FB:2D:15:B8:
                                6E:EF:18:97:84:0A:82:67:DF:81:7E:0D:9D:31:AA:75:
                                5B:B3:CC:22:F0:41
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : DF:A5:5E:AB:68:82:4F:1F:6C:AD:EE:B8:5F:4E:3E:5A:
                                EA:CD:A2:12:A4:6A:5E:8E:3B:12:C0:20:44:5C:2A:73
                    Timestamp : Feb 19 10:09:11.679 2021 GMT
                    Extensions: none
                    Signature : ecdsa-with-SHA256
                                30:45:02:20:05:58:55:F1:11:13:D7:A6:42:40:F6:DD:
                                A3:8F:52:1C:BC:D6:87:04:0B:39:84:9A:92:5B:E1:DC:
                                25:E9:49:4A:02:21:00:D4:CF:24:06:47:E1:CD:69:6F:
                                B0:C9:75:16:5A:51:81:11:4B:4C:44:AB:B9:7D:2F:3A:
                                34:99:48:39:5F:0E:81
            X509v3 Subject Alternative Name: 
                DNS:www.polito.it, DNS:polito.it, DNS:wwwtest.polito.it
    Signature Algorithm: sha384WithRSAEncryption
         31:1f:45:61:76:5d:58:8e:61:2c:c6:e0:3c:0e:7c:be:2c:8d:
         c7:74:43:40:7a:b8:d3:02:20:b3:b9:4d:e8:57:59:62:5e:66:
         75:3d:a1:c3:9a:e1:37:63:02:34:b2:f8:57:4b:3b:51:62:7d:
         5a:7b:d5:b4:64:4f:7b:bc:1f:62:77:56:34:9b:63:41:74:50:
         0b:4d:ea:ee:79:54:a5:d0:6f:d2:9c:b9:40:36:55:be:4a:05:
         de:95:dd:12:2e:f9:bc:4b:ba:77:bc:76:2e:14:d9:63:9d:56:
         cc:d3:64:69:7f:fc:f5:0f:f9:9a:06:aa:54:f6:52:b7:81:8e:
         5d:1b:b5:cf:21:73:2f:6d:ca:a5:e3:ad:e4:39:00:1f:1b:36:
         a5:85:21:82:8a:0c:bf:79:99:7c:d8:fb:e2:b6:97:56:87:f7:
         7b:05:b7:e2:7a:32:7c:c8:1a:e9:7c:43:95:1c:49:dc:dd:2b:
         aa:cf:6f:cd:70:99:a8:bf:c3:59:bb:78:aa:06:64:fa:78:44:
         8f:73:25:20:60:7b:ea:08:68:73:bb:0c:4c:fa:d9:74:43:23:
         98:99:17:b1:70:eb:ce:67:bb:e3:32:5a:eb:fd:7e:1d:65:0d:
         2a:81:47:44:1e:2e:84:ad:b7:ae:d1:90:c6:7b:70:2e:a6:0c:
         49:09:a8:73:85:e0:8b:ed:68:b6:56:a8:6e:90:5b:7c:f7:d4:
         39:1d:bb:b0:cb:8e:1c:f4:62:68:c8:f3:76:c4:78:d1:b1:10:
         04:77:af:66:18:19:af:fb:ef:03:68:d5:1a:67:47:15:4a:79:
         5b:0e:c7:38:16:1a:44:d4:70:88:55:c1:18:05:08:ba:b8:68:
         ea:1e:64:b5:66:6a:e1:19:6e:9e:dc:bd:cc:97:11:16:11:35:
         22:20:51:c6:2f:4e:c5:43:1f:1b:45:34:dd:b0:e0:cf:78:bb:
         7d:f2:50:c5:7a:99:cd:ac:6d:78:c1:52:ea:dd:6c:8e:24:cb:
         48:e1:20:26:19:cd:0a:d7:fc:95:c4:42:eb:eb:54:46:9e:cc:
         47:48:9b:52:eb:21:c9:00:8a:3c:5d:0f:4e:23:77:fc:fd:80:
         93:fb:1c:21:b9:cc:ef:06:49:b9:3f:c5:0b:62:fd:b5:c6:e7:
         17:7e:5c:d6:65:a3:9d:14:46:46:aa:72:c1:1e:ad:4d:96:a8:
         a2:30:69:b6:e5:db:a0:0a:78:90:a7:5f:d7:e7:9b:c3:54:77:
         40:3e:49:d4:1a:6a:12:3a:3d:5e:39:8b:a4:70:70:62:09:dc:
         a1:ba:ff:5d:15:d0:4f:ab:8a:0c:93:7a:2d:5b:db:08:96:c7:
         93:78:90:1c:63:7c:38:76
```
```
openssl x509 -in www-polito-it-CA.pem -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            da:43:bd:13:9b:d2:58:bb:4d:d6:1c:ac:c4:f3:db:e0
        Signature Algorithm: sha384WithRSAEncryption
        Issuer: C = US, ST = New Jersey, L = Jersey City, O = The USERTRUST Network, CN = USERTrust RSA Certification Authority
        Validity
            Not Before: Feb 18 00:00:00 2020 GMT
            Not After : May  1 23:59:59 2033 GMT
        Subject: C = NL, O = GEANT Vereniging, CN = GEANT OV RSA CA 4
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (4096 bit)
                Modulus:
                    00:a5:88:62:d5:a1:22:3e:c8:3d:64:a4:4c:03:0f:
                    50:af:c3:2d:86:ca:fa:47:6d:15:49:f1:5e:87:b4:
                    e0:c2:d2:d0:8b:a4:52:44:b3:a1:e2:8a:f8:10:c1:
                    bf:d6:d8:7c:96:28:ef:ef:19:c1:31:56:64:4f:2b:
                    05:88:f9:93:3e:22:ce:7e:fc:fe:43:03:b5:37:08:
                    ef:81:8f:89:ae:ce:df:4a:85:40:fd:34:24:5f:37:
                    31:bb:84:e5:dd:61:e2:fa:a2:66:28:b2:55:bb:f2:
                    4e:b8:7b:9d:ea:63:a9:2d:69:08:6e:13:83:4b:33:
                    b1:00:d2:76:e0:81:8f:c7:d8:78:39:70:f2:cb:af:
                    f7:e3:67:84:e9:43:d7:0a:d2:7c:03:37:ae:99:31:
                    ba:0d:fb:f9:29:5c:76:e2:50:85:4c:65:33:1d:40:
                    7e:8f:e8:34:95:22:a0:fd:27:f5:3b:38:02:6a:32:
                    55:f5:e9:e6:67:ff:38:c9:d8:78:f3:03:e9:ea:f6:
                    d6:7f:51:f4:3b:74:5d:dc:b8:69:31:25:67:4e:a1:
                    53:2c:a6:52:6d:07:8b:73:1f:e5:f4:33:8a:65:f0:
                    42:0b:d8:21:5b:1b:20:4e:a5:bd:81:0e:ef:dd:3d:
                    da:21:f4:9a:54:2f:6b:9f:05:71:3b:45:63:98:37:
                    4f:14:d6:dd:a3:19:e1:d3:36:30:7f:8e:67:57:54:
                    10:82:94:70:64:9f:77:c9:67:9d:86:9e:1c:87:56:
                    ba:02:3c:2a:b3:ec:2f:e2:66:73:98:14:a3:a2:fb:
                    55:d2:62:b0:77:e0:90:6d:24:e8:6a:51:14:3f:84:
                    1e:26:ae:14:77:3e:56:36:63:4c:23:83:98:3f:a7:
                    20:ae:79:49:e7:46:9a:d0:36:4f:94:9a:ab:29:03:
                    c6:2f:af:4a:41:0c:f5:d9:68:31:be:10:ae:55:4e:
                    f4:cb:a6:56:00:fa:29:05:ad:72:91:bb:2d:b6:92:
                    f1:00:36:6b:7b:97:07:e7:bd:e5:22:e2:c7:76:3c:
                    7b:36:3a:58:21:74:71:db:e4:09:51:19:d7:da:ac:
                    77:ed:e6:48:c5:85:f3:f2:08:0c:fb:05:c7:e9:10:
                    db:53:75:76:a3:90:cf:eb:b8:57:3c:74:80:6c:0f:
                    a9:d2:8a:e3:02:87:29:93:6a:2c:c4:72:a8:35:21:
                    37:2c:28:cd:c7:c5:95:77:19:d7:be:e4:36:f2:d2:
                    9d:68:ae:bd:92:77:e6:dd:b0:7b:c6:97:5f:b0:d3:
                    53:3c:7f:44:95:c8:ec:71:66:71:a5:e6:79:22:28:
                    fc:97:2a:c2:1b:5c:f4:bd:25:ad:48:1b:20:4a:75:
                    32:1b:fb
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Authority Key Identifier: 
                keyid:53:79:BF:5A:AA:2B:4A:CF:54:80:E1:D8:9B:C0:9D:F2:B2:03:66:CB

            X509v3 Subject Key Identifier: 
                6F:1D:35:49:10:6C:32:FA:59:A0:9E:BC:8A:E8:1F:95:BE:71:7A:0C
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Certificate Policies: 
                Policy: X509v3 Any Policy
                  CPS: https://sectigo.com/CPS

            X509v3 CRL Distribution Points: 

                Full Name:
                  URI:http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl

            Authority Information Access: 
                CA Issuers - URI:http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt
                OCSP - URI:http://ocsp.usertrust.com

    Signature Algorithm: sha384WithRSAEncryption
         52:d9:42:dd:ed:31:8f:fd:41:31:f3:e1:75:08:54:5d:e2:e3:
         6f:4c:69:f1:41:36:f2:4c:d6:13:9c:43:cc:62:9b:7c:68:27:
         ad:3d:91:97:0e:60:2c:8c:7e:fd:c3:55:ad:a7:7f:ff:e3:2b:
         a5:3a:69:32:5c:6a:e7:d0:2c:5d:86:56:df:14:5a:b2:bb:e4:
         8c:67:cd:47:7b:ed:ff:54:40:97:c8:88:df:59:46:84:88:3a:
         75:f2:17:e4:de:1e:b0:b9:2b:41:e3:7c:1e:2c:87:28:7e:a4:
         86:6e:3d:eb:a2:24:55:5b:67:c7:3e:42:81:43:ea:11:89:f8:
         79:0f:b8:79:e1:12:ad:60:61:02:a5:da:8a:fe:c7:46:fa:6c:
         77:02:d8:7a:40:21:9e:b9:46:a6:2a:19:fc:22:48:4f:63:d3:
         4f:17:fe:18:73:3a:72:e5:27:36:a7:54:cd:fb:eb:42:00:3c:
         92:dd:7f:01:25:f1:da:87:7f:33:e7:3c:9e:52:6a:ac:6c:f6:
         f6:5a:c9:bd:e2:4e:48:43:17:d1:cf:ed:b3:4d:96:86:c7:cc:
         86:46:1a:e9:7b:a3:51:92:e6:bd:1d:44:ab:4f:2b:e3:cf:c4:
         67:89:7e:b7:92:f8:c2:dd:03:57:c5:5a:3d:bb:04:04:5d:44:
         38:5a:73:fd:84:b6:1f:a9:92:c1:c1:5a:34:96:e7:62:aa:89:
         1c:8b:e6:dc:f2:c9:1e:41:66:12:82:d7:45:5a:d0:5d:d0:93:
         fb:7c:20:05:f8:14:ea:17:82:57:90:98:07:3f:d8:92:b7:56:
         11:2e:ed:8a:24:fc:b1:55:03:a9:79:95:95:3b:1b:89:13:62:
         c8:bb:36:6e:61:16:58:55:25:ef:a8:d5:88:82:68:83:97:e8:
         9e:01:2a:37:78:cb:20:64:c6:fe:65:eb:25:3d:54:cb:29:88:
         72:86:e7:20:6a:db:c3:04:55:cf:f9:a9:15:0a:34:bc:16:08:
         8b:59:36:4e:15:61:d0:3c:7c:f0:16:c5:f5:88:8f:f3:87:5d:
         f0:59:27:e7:06:c4:e8:5c:57:60:9d:bc:ee:a7:d1:4e:09:a1:
         78:f7:9c:3d:ce:f7:62:bc:ed:6a:97:51:72:c2:95:1a:43:a9:
         69:32:09:3f:f9:7e:94:01:d1:2d:9c:64:fd:d5:2d:c8:df:79:
         1b:ef:9b:39:24:2a:9c:e0:a9:54:f6:9b:50:69:76:13:f3:84:
         c8:5a:e9:22:9c:20:bb:62:ff:58:97:25:bd:de:a0:f9:90:3f:
         89:69:0b:48:c7:29:9c:56:fe:b9:7e:90:06:ab:c3:eb:e4:4d:
         c6:e9:75:15:a0:79:88:76
```
To save the public key out of the certificate:

```
openssl x509 -in www-polito-it-CA.pem -pubkey -noout >terena.pubkey.pem
cat terena.pubkey.pem 
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApYhi1aEiPsg9ZKRMAw9Q
r8Mthsr6R20VSfFeh7TgwtLQi6RSRLOh4or4EMG/1th8lijv7xnBMVZkTysFiPmT
PiLOfvz+QwO1NwjvgY+Jrs7fSoVA/TQkXzcxu4Tl3WHi+qJmKLJVu/JOuHud6mOp
LWkIbhODSzOxANJ24IGPx9h4OXDyy6/342eE6UPXCtJ8AzeumTG6Dfv5KVx24lCF
TGUzHUB+j+g0lSKg/Sf1OzgCajJV9enmZ/84ydh48wPp6vbWf1H0O3Rd3LhpMSVn
TqFTLKZSbQeLcx/l9DOKZfBCC9ghWxsgTqW9gQ7v3T3aIfSaVC9rnwVxO0VjmDdP
FNbdoxnh0zYwf45nV1QQgpRwZJ93yWedhp4ch1a6Ajwqs+wv4mZzmBSjovtV0mKw
d+CQbSToalEUP4QeJq4Udz5WNmNMI4OYP6cgrnlJ50aa0DZPlJqrKQPGL69KQQz1
2WgxvhCuVU70y6ZWAPopBa1ykbsttpLxADZre5cH573lIuLHdjx7NjpYIXRx2+QJ
URnX2qx37eZIxYXz8ggM+wXH6RDbU3V2o5DP67hXPHSAbA+p0orjAocpk2osxHKo
NSE3LCjNx8WVdxnXvuQ28tKdaK69knfm3bB7xpdfsNNTPH9ElcjscWZxpeZ5Iij8
lyrCG1z0vSWtSBsgSnUyG/sCAwEAAQ==
-----END PUBLIC KEY-----

```
To view the subject you can use the command:

```
openssl x509 -in www-polito-it.pem -subject -noout
subject=C = IT, postalCode = 10129, ST = Torino, L = Torino, street = Corso Duca degli Abruzzi 24, O = Politecnico di Torino, CN = www.polito.it

```
To view thesubjectAltName and the subjectKeyIdentifierextensions you can use the command:

```
openssl x509 -in www-polito-it.pem -ext "subjectAltName,subjectKeyIdentifier" -noout
X509v3 Subject Key Identifier: 
    97:32:21:07:E2:BD:3B:DD:C9:DE:66:6C:35:6C:15:26:4E:9C:9F:9C
X509v3 Subject Alternative Name: 
    DNS:www.polito.it, DNS:polito.it, DNS:wwwtest.polito.it

```
What is the purpose of the subjectAltNameextension?


#### → Give informations useful for the service for which the certificate is being used (map address is not useful for http website, better to have the dns server!)

To view the dates you can use the commands:

```
openssl x509 -in www-polito-it.pem -dates -noout
notBefore=Feb 19 00:00:00 2021 GMT
notAfter=Feb 19 23:59:59 2022 GMT
```
To display the CRL pointer in the crlDistributionPointextension, you can use the command:

```
openssl x509 -in www-polito-it.pem -ext crlDistributionPoints -noout
X509v3 CRL Distribution Points: 

    Full Name:
      URI:http://GEANT.crl.sectigo.com/GEANTOVRSACA4.crl

```
To display the URL of the OCSP responder in the Authority Information Access (AIA) extension, you can use
the command:

```
openssl x509 -in www-polito-it.pem -ocsp_uri -noout
http://GEANT.ocsp.sectigo.com

```
To display the whole certificate content with OpenSSL asn1parse:

```
openssl asn1parse -in www-polito-it.pem

    0:d=0  hl=4 l=1970 cons: SEQUENCE          
    4:d=1  hl=4 l=1434 cons: SEQUENCE          
    8:d=2  hl=2 l=   3 cons: cont [ 0 ]        
   10:d=3  hl=2 l=   1 prim: INTEGER           :02
   13:d=2  hl=2 l=  17 prim: INTEGER           :A41852DF08DC33EE074C82C391B3DCDE
   32:d=2  hl=2 l=  13 cons: SEQUENCE          
   34:d=3  hl=2 l=   9 prim: OBJECT            :sha384WithRSAEncryption
   45:d=3  hl=2 l=   0 prim: NULL              
   47:d=2  hl=2 l=  68 cons: SEQUENCE          
   49:d=3  hl=2 l=  11 cons: SET               
   51:d=4  hl=2 l=   9 cons: SEQUENCE          
   53:d=5  hl=2 l=   3 prim: OBJECT            :countryName
   58:d=5  hl=2 l=   2 prim: PRINTABLESTRING   :NL
   62:d=3  hl=2 l=  25 cons: SET               
   64:d=4  hl=2 l=  23 cons: SEQUENCE          
   66:d=5  hl=2 l=   3 prim: OBJECT            :organizationName
   71:d=5  hl=2 l=  16 prim: PRINTABLESTRING   :GEANT Vereniging
   89:d=3  hl=2 l=  26 cons: SET               
   91:d=4  hl=2 l=  24 cons: SEQUENCE          
   93:d=5  hl=2 l=   3 prim: OBJECT            :commonName
   98:d=5  hl=2 l=  17 prim: PRINTABLESTRING   :GEANT OV RSA CA 4
  117:d=2  hl=2 l=  30 cons: SEQUENCE          
  119:d=3  hl=2 l=  13 prim: UTCTIME           :210219000000Z
  134:d=3  hl=2 l=  13 prim: UTCTIME           :220219235959Z
  149:d=2  hl=3 l= 157 cons: SEQUENCE          
  152:d=3  hl=2 l=  11 cons: SET               
  154:d=4  hl=2 l=   9 cons: SEQUENCE          
  156:d=5  hl=2 l=   3 prim: OBJECT            :countryName
  161:d=5  hl=2 l=   2 prim: PRINTABLESTRING   :IT
  165:d=3  hl=2 l=  14 cons: SET               
  167:d=4  hl=2 l=  12 cons: SEQUENCE          
  169:d=5  hl=2 l=   3 prim: OBJECT            :postalCode
  174:d=5  hl=2 l=   5 prim: PRINTABLESTRING   :10129
  181:d=3  hl=2 l=  15 cons: SET               
  183:d=4  hl=2 l=  13 cons: SEQUENCE          
  185:d=5  hl=2 l=   3 prim: OBJECT            :stateOrProvinceName
  190:d=5  hl=2 l=   6 prim: PRINTABLESTRING   :Torino
  198:d=3  hl=2 l=  15 cons: SET               
  200:d=4  hl=2 l=  13 cons: SEQUENCE          
  202:d=5  hl=2 l=   3 prim: OBJECT            :localityName
  207:d=5  hl=2 l=   6 prim: PRINTABLESTRING   :Torino
  215:d=3  hl=2 l=  36 cons: SET               
  217:d=4  hl=2 l=  34 cons: SEQUENCE          
  219:d=5  hl=2 l=   3 prim: OBJECT            :streetAddress
  224:d=5  hl=2 l=  27 prim: PRINTABLESTRING   :Corso Duca degli Abruzzi 24
  253:d=3  hl=2 l=  30 cons: SET               
  255:d=4  hl=2 l=  28 cons: SEQUENCE          
  257:d=5  hl=2 l=   3 prim: OBJECT            :organizationName
  262:d=5  hl=2 l=  21 prim: PRINTABLESTRING   :Politecnico di Torino
  285:d=3  hl=2 l=  22 cons: SET               
  287:d=4  hl=2 l=  20 cons: SEQUENCE          
  289:d=5  hl=2 l=   3 prim: OBJECT            :commonName
  294:d=5  hl=2 l=  13 prim: PRINTABLESTRING   :www.polito.it
  309:d=2  hl=4 l= 418 cons: SEQUENCE          
  313:d=3  hl=2 l=  13 cons: SEQUENCE          
  315:d=4  hl=2 l=   9 prim: OBJECT            :rsaEncryption
  326:d=4  hl=2 l=   0 prim: NULL              
  328:d=3  hl=4 l= 399 prim: BIT STRING        
  731:d=2  hl=4 l= 707 cons: cont [ 3 ]        
  735:d=3  hl=4 l= 703 cons: SEQUENCE          
  739:d=4  hl=2 l=  31 cons: SEQUENCE          
  741:d=5  hl=2 l=   3 prim: OBJECT            :X509v3 Authority Key Identifier
  746:d=5  hl=2 l=  24 prim: OCTET STRING      [HEX DUMP]:301680146F1D3549106C32FA59A09EBC8AE81F95BE717A0C
  772:d=4  hl=2 l=  29 cons: SEQUENCE          
  774:d=5  hl=2 l=   3 prim: OBJECT            :X509v3 Subject Key Identifier
  779:d=5  hl=2 l=  22 prim: OCTET STRING      [HEX DUMP]:041497322107E2BD3BDDC9DE666C356C15264E9C9F9C
  803:d=4  hl=2 l=  14 cons: SEQUENCE          
  805:d=5  hl=2 l=   3 prim: OBJECT            :X509v3 Key Usage
  810:d=5  hl=2 l=   1 prim: BOOLEAN           :255
  813:d=5  hl=2 l=   4 prim: OCTET STRING      [HEX DUMP]:030205A0
  819:d=4  hl=2 l=  12 cons: SEQUENCE          
  821:d=5  hl=2 l=   3 prim: OBJECT            :X509v3 Basic Constraints
  826:d=5  hl=2 l=   1 prim: BOOLEAN           :255
  829:d=5  hl=2 l=   2 prim: OCTET STRING      [HEX DUMP]:3000
  833:d=4  hl=2 l=  29 cons: SEQUENCE          
  835:d=5  hl=2 l=   3 prim: OBJECT            :X509v3 Extended Key Usage
  840:d=5  hl=2 l=  22 prim: OCTET STRING      [HEX DUMP]:301406082B0601050507030106082B06010505070302
  864:d=4  hl=2 l=  73 cons: SEQUENCE          
  866:d=5  hl=2 l=   3 prim: OBJECT            :X509v3 Certificate Policies
  871:d=5  hl=2 l=  66 prim: OCTET STRING      [HEX DUMP]:30403034060B2B06010401B2310102024F3025302306082B06010505070201161768747470733A2F2F7365637469676F2E636F6D2F4350533008060667810C010202
  939:d=4  hl=2 l=  63 cons: SEQUENCE          
  941:d=5  hl=2 l=   3 prim: OBJECT            :X509v3 CRL Distribution Points
  946:d=5  hl=2 l=  56 prim: OCTET STRING      [HEX DUMP]:30363034A032A030862E687474703A2F2F4745414E542E63726C2E7365637469676F2E636F6D2F4745414E544F565253414341342E63726C
 1004:d=4  hl=2 l= 117 cons: SEQUENCE          
 1006:d=5  hl=2 l=   8 prim: OBJECT            :Authority Information Access
 1016:d=5  hl=2 l= 105 prim: OCTET STRING      [HEX DUMP]:3067303A06082B06010505073002862E687474703A2F2F4745414E542E6372742E7365637469676F2E636F6D2F4745414E544F565253414341342E637274302906082B06010505073001861D687474703A2F2F4745414E542E6F6373702E7365637469676F2E636F6D
 1123:d=4  hl=4 l= 259 cons: SEQUENCE          
 1127:d=5  hl=2 l=  10 prim: OBJECT            :CT Precertificate SCTs
 1139:d=5  hl=3 l= 244 prim: OCTET STRING      [HEX DUMP]:0481F100EF00750046A555EB75FA912030B5A28969F4F37D112C4174BEFD49B885ABF2FC70FE6D4700000177B9C3C6BB000004030046304402204372FD5AC9AA025D9837C55EE410CB62AFD71249B98FCB12905B8E1A47504405022070E32DF2C5CBFB2D15B86EEF1897840A8267DF817E0D9D31AA755BB3CC22F041007600DFA55EAB68824F1F6CADEEB85F4E3E5AEACDA212A46A5E8E3B12C020445C2A7300000177B9C3C7FF00000403004730450220055855F11113D7A64240F6DDA38F521CBCD687040B39849A925BE1DC25E9494A022100D4CF240647E1CD696FB0C975165A5181114B4C44ABB97D2F3A349948395F0E81
 1386:d=4  hl=2 l=  54 cons: SEQUENCE          
 1388:d=5  hl=2 l=   3 prim: OBJECT            :X509v3 Subject Alternative Name
 1393:d=5  hl=2 l=  47 prim: OCTET STRING      [HEX DUMP]:302D820D7777772E706F6C69746F2E69748209706F6C69746F2E69748211777777746573742E706F6C69746F2E6974
 1442:d=1  hl=2 l=  13 cons: SEQUENCE          
 1444:d=2  hl=2 l=   9 prim: OBJECT            :sha384WithRSAEncryption
 1455:d=2  hl=2 l=   0 prim: NULL              
 1457:d=1  hl=4 l= 513 prim: BIT STRING        

```
To convert from PEM format to DER format:

```
openssl asn1parse -in www-polito-it.pem -out www-polito-it.der

file www-polito-it.der                                          
www-polito-it.der: Certificate, Version=3

file www-polito-it.pem 
www-polito-it.pem: PEM certificate
```
### 2.2 Certificate status checking

2.2.1 CRL verification

Verifying certificate status with a CRL consists basically of the following steps:

- obtain the certificate you wish to check for revocation
- obtain the issuer certificate (CA)
- download and verify the CRL (for authentication, integrity, and trust)
- check the certificate status with the CRL.

Now proceed as follows. Try to download the CRL (for the Polito web server certificate) through the browser.
Connect towww.polito.it, click on the padlock sign in the address bar, and view the details of the certificate.
To find out the URL of the CRL, check once again thecrlDistributionPointextension in the server certifi-
cate. Insert the CRL’s URL is the browser address bar and save it locally. You should have afilename.crl(e.g.
GEANT OV RSACA4.crl). By double-clicking on thefilename.crl, in Windows you should be able to import
and see the content of the CRL imported in the dedicated trust store of Windows. In Fig. 1 we show an example
of a CRL in Windows:

At this point, you can inspect the CRL with the dedicated OpenSSL command:

```
openssl crl -inform DER -in GEANTOVRSACA4.crl -text
Certificate Revocation List (CRL):
        Version 2 (0x1)
        Signature Algorithm: sha384WithRSAEncryption
        Issuer: C = NL, O = GEANT Vereniging, CN = GEANT OV RSA CA 4
        Last Update: Nov 14 13:25:09 2021 GMT
        Next Update: Nov 21 13:25:09 2021 GMT
        CRL extensions:
            X509v3 Authority Key Identifier: 
                keyid:6F:1D:35:49:10:6C:32:FA:59:A0:9E:BC:8A:E8:1F:95:BE:71:7A:0C

            X509v3 CRL Number: 
                655
Revoked Certificates:
    Serial Number: 2BC06D124D067960C8ECFF82128391CA
        Revocation Date: Mar 24 16:11:09 2020 GMT
    Serial Number: 56626FA9670F86C965A6328903AF0DD2
        Revocation Date: Mar 26 17:51:44 2020 GMT
    Serial Number: E3012C57E32222A973BE748580C8FD87
        Revocation Date: Mar 27 10:08:43 2020 GMT
    Serial Number: 9C167D6107DE3747A0E3898D2CDC48C4
        Revocation Date: Mar 27 10:11:10 2020 GMT
    Serial Number: 1EA2B9CB328550F830FD7A832CF8D69C
        Revocation Date: Mar 28 18:28:47 2020 GMT
...... A lot of other serial numbers ....
    Signature Algorithm: sha384WithRSAEncryption
         26:cb:62:a5:54:8b:fd:0e:87:f2:88:6d:1b:4a:aa:34:f8:67:
         7f:91:6a:af:ef:1c:10:d3:a6:ca:05:af:ca:09:55:8f:c9:dc:
         e2:15:d4:b7:43:4f:d0:91:f3:88:55:8f:c5:64:ad:6f:d4:5d:
         50:77:8b:92:40:0c:f5:67:f1:4a:cc:99:79:22:d3:1d:b0:d6:
         35:2e:90:56:ce:48:5f:81:5f:23:df:6e:34:ab:8a:32:2c:8c:
         27:3f:ed:39:b9:cc:a8:d0:30:fb:0a:f0:04:bf:c1:32:6b:cc:
         d9:5c:4f:37:1d:bf:2a:d0:9b:a5:b0:1e:d1:53:70:30:bb:dc:
         24:62:71:90:2f:35:e4:bf:bf:48:b9:b5:69:c5:8e:c8:d4:94:
         b9:9b:5e:ac:98:24:b4:ab:3f:68:17:32:63:ae:54:80:6b:5f:
         01:12:4e:f0:51:d3:0c:3a:17:19:68:cb:f9:14:17:72:11:1b:
         fb:41:bf:a4:be:9e:a0:cb:27:28:1f:c3:b1:23:34:15:d6:a0:
         55:5f:f3:ab:08:ec:19:89:c8:1c:e0:57:9f:50:93:ec:b8:9d:
         d8:93:4b:60:2f:16:6f:9f:5e:94:46:a8:64:9e:b9:8a:ec:31:
         ea:45:55:54:63:26:13:6e:8a:c5:b8:78:46:25:46:49:f1:70:
         c7:5f:cf:77:ef:66:b8:df:49:f6:9a:f2:9f:e8:2a:90:d6:ae:
         1e:13:88:a1:78:ad:cc:55:4d:24:43:5f:93:9e:e9:cf:ab:10:
         1f:e2:68:93:d7:6e:d5:57:88:11:8c:ec:ac:99:8c:d8:69:8d:
         4c:4a:b0:a7:25:8b:32:4c:ae:6e:8c:51:ce:d0:e6:c8:c4:8a:
         39:55:e7:ea:36:71:e7:cb:38:03:10:2a:e9:37:7a:0b:59:d9:
         ba:a7:7d:47:ef:1a:d2:37:61:9f:f7:3c:f3:78:a9:7e:a8:13:
         be:c4:37:b9:11:3b:4c:aa:25:3e:b2:c9:76:18:c3:8a:59:ff:
         1a:0f:f1:6f:7a:be:9f:f0:a0:80:87:67:fc:a1:ab:b5:b9:f9:
         a9:54:89:92:23:f9:49:34:44:12:1a:fa:79:04:b1:1c:3c:ff:
         8f:ae:95:11:35:6b:c7:a5:4a:39:38:1f:a8:04:b9:35:c4:33:
         fd:6e:6f:0f:43:8a:ab:ca:c2:29:55:a2:63:61:56:1b:36:fd:
         80:b8:1a:45:41:87:4d:e3:fc:c6:a7:4f:49:13:5d:6f:0b:e7:
         b2:0f:48:e3:7e:7e:16:34:df:61:d5:73:7f:3c:86:db:fa:b7:
         3f:51:b7:1b:66:e6:25:03:b2:3a:e6:dc:ed:ed:b7:ab:58:13:
         ce:9c:45:f0:c2:0f:b3:31
-----BEGIN X509 CRL-----
MIMFhHcwgwWCXgIBATANBgkqhkiG9w0BAQwFADBEMQswCQYDVQQGEwJOTDEZMBcG
A1UEChMQR0VBTlQgVmVyZW5pZ2luZzEaMBgGA1UEAxMRR0VBTlQgT1YgUlNBIENB
IDQXDTIxMTExNDEzMjUwOVoXDTIxMTEyMTEzMjUwOVowgwWBsTAhAhArwG0STQZ5
...blahblah.....
-----END X509 CRL-----

```
Look at the first revoked certificate in this list: it indicates “Revocation Date: Mar 24 18:11:09 2020 GMT”.
If we receive on Nov 6 20:40 2021 a document signed with that certificate, should we accept that document as
valid?

RevocationDate vs InvalidityDate: 
InvalidityDate (key compromise event date) always refers to a prior time than the RevocationDate (cert revocation time) (time from the discovery of the key compromise, to the issuing of the revocation request) 
BUT the invalidity date is optional (extension) and it has no legal validity, since it is only your word to the Certification Authority that attest that it was actually compromised at that moment! You need to PROVE IT! Otherways you could buy bitcoins using cert, then price drops, and you can go to the CA and revoke it telling that it wasn't you to buy them half an hour before! Fraud! 
N.B. even after the revocation was issued, there is a period of time when the new CRL has still not been published, so others will still accept that certificate as valid! In this case at least you are legally protected from bad usage of the certificate since you already revoked it. In this moment it is the RP responsibility to use correct security measures (wait next crl) to avoid using compromised certificates 
N.B. useful to look at the certificate policy to understand how long is the yellow period! If it is very long, it may not be very useful to check the latest crl, since the certificate may have been compromised in the meantime! 
All these considerations are also valid when using OCSP! 
CRL publication time or OCSP database update could be long! (even longer for OCSP if they wait for the new CRL to come out to update the db!) 
Solution for the RP would be to wait for the next CRL to be issued before accepting any certificate! This could sometimes be feasible: I temporarly accept the certificate, but it will be fully accepted only after the next issue. For other applications it is not! I want immediate access to my bank account, I do not want it in 3 days! Is the application reversible? Maybe looking at bank account is accepted, while for making a transfer the next CRL must be waited! Maybe for this reason the bank account can decide to trust only certificates from CA, which policy states that the CRL lifetime is max 1 hour! Acceptable wait for payment acceptation! 
N.B. the application should still accept revoked certificates, for "off-line" usages, for example for receiving a document digitally signed BEFORE the cert revocation time! (or the key compromise event) 
Time of Use vs Time of Verification: for online services they are the same: I use the certificate when sending the certificate to the relying party, but for offline services (signing document and then sending it) they are different! Potential problem! RP must accept the certificate even after its revocation, and it must be sure about the time of usage of the certificate? How can we be sure? If the datetime is self-asserted by the signer (file crafted to look like signed in a certain previous date) we are not safe!

```
- If the timestamp was issued by the same person that signed the document we can't trust it.
- If the timestamp was issued by a third party,then it depends on the date when the document was signed:
    - if it was signed before the invalidity date (and the invalidity date extension is present on the certificate) we can be sure that it was valid
    - if it was signed between the invalidity date and the revocation date we can trust it, and it is the sender that must prove to court that it was not really him the one that signed it (if he wants to prove it)
    - if it was signed after the revocation date we can't trust it
```
Look at the certificate in the list that indicates “Revocation Date: Oct 21 11:53:12 2021 GMT”


```
Figure 1: Viewing the CRL content in Windows.
```
Let’s assume that we are on Oct 21 12:05:12 2021 and we have just received a document signed with the above
certificate. Should we accept the document as valid?

```
→ Same considerations as above!
```
Convert the CRL in PEM format:

```
openssl crl -inform DER -in filename.crl > filename.crl.pem
file GEANTOVRSACA4.crl  
GEANTOVRSACA4.crl: data

file GEANTOVRSACA4.crl.pem
GEANTOVRSACA4.crl.pem: ASCII text
```
Verify that the CRL is valid (i.e., signed by the issuer certificate):

```
openssl crl -in GEANTOVRSACA4.crl -inform DER -CAfile www-polito-it-CA.pem -noout
```
You should see a “verify OK” message.

Verify the validity of the certificate (no revocation check):

```
openssl verify -CAfile www-polito-it-CA.pem www-polito-it.pem

www-polito-it.pem: OK
```
Verify the server certificate, including the checking of certificate revocation status with the CRL:

```
openssl verify -CAfile www-polito-it-CA.pem -crlcheck -CRLfile GEANTOVRSACA4.crl.pem www-polito-it.pem
```
You should see a “www-polito-it.pem: OK” message indicating that the verification completed successfully.

2.2.2 OCSP verification

To check the status of the server certificate with OCSP you can use the command:

```
openssl ocsp -issuer www-polito-it-CA.pem -cert www-polito-it.pem -url http://GEANT.ocsp.sectigo.com -resp_text
OCSP Response Data:
    OCSP Response Status: successful (0x0)
    Response Type: Basic OCSP Response
    Version: 1 (0x0)
    Responder Id: 6F1D3549106C32FA59A09EBC8AE81F95BE717A0C
    Produced At: Nov 14 14:20:56 2021 GMT
    Responses:
    Certificate ID:
      Hash Algorithm: sha1
      Issuer Name Hash: C3FDEA1EAA0EBEDE75016EEC6E5BB393F0F12E5D
      Issuer Key Hash: 6F1D3549106C32FA59A09EBC8AE81F95BE717A0C
      Serial Number: A41852DF08DC33EE074C82C391B3DCDE
    Cert Status: good
    This Update: Nov 14 14:20:56 2021 GMT
    Next Update: Nov 21 14:20:56 2021 GMT

    Signature Algorithm: sha384WithRSAEncryption
         0a:1d:27:54:a8:d4:34:06:bb:64:0a:45:72:98:9a:c4:7d:e9:
         af:c5:81:f9:7a:c7:17:20:47:b5:c9:99:94:f1:5d:e6:6d:ed:
         5d:e3:04:f0:c7:87:ba:c6:46:cb:24:f6:25:9d:bf:d7:9b:c0:
         99:8c:21:78:4e:90:30:b5:7f:a6:18:73:29:8a:41:fd:df:74:
         60:89:52:6c:bf:72:7e:65:72:38:78:7c:67:a3:1f:3c:50:7c:
         2d:a2:82:fe:1b:50:c8:ca:13:25:2f:ce:b7:fe:81:09:01:72:
         d6:47:24:99:67:7c:ca:05:25:9a:6a:57:e5:c8:be:c4:f5:b6:
         98:c9:0c:d8:5d:2b:f0:2b:6b:23:c1:be:6c:96:a6:93:66:c8:
         4c:c3:88:74:46:9a:75:81:89:89:c0:e5:c3:8c:29:7d:a6:ef:
         af:26:8a:f0:6d:45:34:d4:37:58:9f:68:8c:09:38:7f:72:f1:
         92:2a:35:52:eb:65:5a:4a:8d:45:bc:61:8c:d7:c8:59:85:a9:
         95:bb:d6:fd:3d:66:7a:c8:96:d8:cf:c3:de:30:56:86:13:e3:
         04:38:54:69:1b:94:94:53:d5:8e:be:57:18:c5:12:f2:31:0e:
         76:72:e5:fd:cf:66:e6:b5:28:5d:f5:ea:67:44:91:b3:9d:61:
         a4:05:90:37:0e:21:52:a4:ed:78:7e:27:1b:10:f3:38:43:93:
         85:3b:5c:bf:03:4c:f2:87:a1:09:a2:a6:00:59:07:9d:b3:3e:
         4a:94:06:1e:03:12:f8:d6:63:f2:9d:0c:04:09:15:b8:9c:8d:
         06:a3:8c:61:51:d6:10:ec:e7:88:cf:e7:93:db:83:ec:bc:b5:
         e6:6b:d6:45:f1:d7:77:e5:c7:29:0e:12:dd:4b:9b:87:90:fa:
         b0:8f:a6:d9:e4:56:e5:2b:dc:36:06:c8:85:f3:a1:4a:8e:0a:
         09:ac:49:be:fd:d5:3c:6f:da:d5:64:fb:dc:0f:99:86:15:ab:
         a0:08:4a:61:ab:86:da:71:73:ba:b1:15:98:6f:25:57:5d:c8:
         a6:73:82:56:ea:32:6e:97:01:35:8c:c5:fe:c7:96:71:2d:a0:
         53:b5:2d:a3:db:42:2b:65:fc:4e:f0:9a:89:84:52:64:5a:1a:
         ee:66:dc:71:b9:43:90:e3:4b:5e:ca:fd:33:9c:02:dd:71:dd:
         73:98:32:d9:2a:3c:82:07:67:da:38:b5:14:62:af:b3:a4:af:
         27:af:3f:03:09:c0:25:82:01:4e:68:a7:e5:60:25:1f:b9:76:
         5b:18:07:3b:ac:67:80:c5:75:29:c8:4c:7e:8b:48:20:d1:a3:
         bc:e4:07:c5:e5:26:2d:9c
WARNING: no nonce in response
Response verify OK
www-polito-it.pem: good
	This Update: Nov 14 14:20:56 2021 GMT
	Next Update: Nov 21 14:20:56 2021 GMT
```
where the ocsp_uri can be obtained querying the server certificate with the command

```
openssl x509 -in www-polito-it.pem -ocsp_uri -noout
http://GEANT.ocsp.sectigo.com
```
And you should see a “Response verify OK” message.

Now, to experiment with a revoked certificate, connect to https://revoked.badssl.com/ and redo the same
CRL and OCSP verification operations above, for the revoked certificate.

- CRL
1. Convert the CRL in PEM format:
```
openssl crl -inform DER -in RapidSSLTLSDVRSAMixedSHA2562020CA-1.crl > RapidSSLTLSDVRSAMixedSHA2562020CA-1.crl.pem
file GEANTOVRSACA4.crl  
GEANTOVRSACA4.crl: data

file GEANTOVRSACA4.crl.pem
GEANTOVRSACA4.crl.pem: ASCII text
```
2. Verify that the CRL is valid (i.e., signed by the issuer certificate):
```
openssl crl -in RapidSSLTLSDVRSAMixedSHA2562020CA-1.crl -inform DER -CAfile revoked.badssl.com-CA.pem -noout 

verify OK
```
You should see a “verify OK” message.

3. Verify the validity of the certificate (no revocation check):
```
openssl verify -CAfile revoked.badssl.com-CA.pem  revoked.badssl.com.pem

revoked.badssl.com.pem: OK
```
4. Verify the server certificate, including the checking of certificate revocation status with the CRL:
```
openssl verify -CAfile revoked.badssl.com-CA.pem  -crl_check -CRLfile RapidSSLTLSDVRSAMixedSHA2562020CA-1.crl.pem revoked.badssl.com.pem

CN = revoked.badssl.com
error 23 at 0 depth lookup: certificate revoked
error revoked.badssl.com.pem: verification failed
```
You should see a “revoked.badssl.com.pem: OK” message indicating that the verification completed successfully.

- OSCP
```
┌╼ ⚡ root@kali  /media/sf_Kali_Shared/Cybersecurity_Labs/CYB_lab02
└─╼ openssl x509 -in revoked.badssl.com.pem -ocsp_uri -noout

http://ocsp.digicert.com
┌╼ ⚡ root@kali  /media/sf_Kali_Shared/Cybersecurity_Labs/CYB_lab02
└─╼ openssl ocsp -issuer revoked.badssl.com-CA.pem -cert revoked.badssl.com.pem -url http://ocsp.digicert.com -resp_text

OCSP Response Data:
    OCSP Response Status: successful (0x0)
    Response Type: Basic OCSP Response
    Version: 1 (0x0)
    Responder Id: A48DE5BE7C79E470236D2E2934AD2358DCF5317F
    Produced At: Nov 16 02:24:47 2021 GMT
    Responses:
    Certificate ID:
      Hash Algorithm: sha1
      Issuer Name Hash: 74B4E72319C765921540447BC7CE3E90C21876EB
      Issuer Key Hash: A48DE5BE7C79E470236D2E2934AD2358DCF5317F
      Serial Number: 0D2E67A298853B9A5452E3A285A4572F
    Cert Status: revoked
    Revocation Time: Oct 27 21:38:48 2021 GMT
    This Update: Nov 16 02:09:00 2021 GMT
    Next Update: Nov 23 01:24:00 2021 GMT

    Signature Algorithm: sha256WithRSAEncryption
         38:80:18:b2:36:6e:a0:45:4d:5d:c0:ed:ef:61:00:dc:62:34:
         f7:1c:af:25:42:28:6f:2d:2f:f3:6c:78:41:10:40:ba:b1:8e:
         08:45:38:15:31:d4:de:a7:08:4a:72:39:5f:00:55:78:2b:d9:
         27:5c:0d:26:16:ce:3f:2b:4b:18:b4:b6:4f:69:f4:2f:db:24:
         90:bc:97:a8:15:b5:e3:4a:d8:a6:e4:26:a0:f8:20:8f:db:18:
         04:86:2a:14:18:5d:57:27:b2:f2:ed:26:f4:f3:a1:ec:5e:f1:
         f2:a5:bb:15:0f:ac:5c:a8:33:25:01:22:8f:5e:10:ce:fc:0f:
         94:d2:88:96:c0:0b:96:e4:85:af:9a:0b:10:45:5c:94:34:7b:
         c7:e2:9b:fc:b5:63:c6:26:04:6e:11:ac:e0:7a:80:56:57:74:
         0b:5b:42:1f:29:ca:87:50:92:c7:6f:a5:80:d6:f9:12:bd:f6:
         12:a8:ff:25:ae:a1:fd:f0:65:c5:72:d9:a3:8c:1d:ed:34:93:
         c3:97:c2:8f:ce:11:60:5f:65:ac:7d:81:1e:4d:67:b6:cd:fc:
         b1:48:75:ca:e1:56:f5:87:34:c4:6c:e9:e3:85:24:55:ad:05:
         12:47:af:8b:6c:ff:06:2d:0d:c9:b9:cb:3e:09:d3:94:79:0c:
         d7:cc:42:3e
WARNING: no nonce in response
Response verify OK
revoked.badssl.com.pem: revoked
	This Update: Nov 16 02:09:00 2021 GMT
	Next Update: Nov 23 01:24:00 2021 GMT
	Revocation Time: Oct 27 21:38:48 2021 GMT
```
2.2.3 OCSP Stapling

OCSP stapling is an optional feature that allows a server certificate to be accompanied by an OCSP response
that proves its validity. Because the OCSP response is delivered over an already existing connection, the client
does not have to fetch it separately.

OCSP stapling is used only if requested by a client, which submits thestatusrequestextension in the TLS
handshake request. A server that supports OCSP stapling will respond by including an OCSP response as part
of the TLS handshake.

You can use OpenSSL sclient tool to check if a server supports OCSP stapling. For example, the following
server supports it:

```
echo | openssl s_client -connect http://www.sony.com:443 -status
CONNECTED(00000003)
depth=2 C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Global Root CA
verify return:1
depth=1 C = US, O = DigiCert Inc, CN = DigiCert SHA2 Secure Server CA
verify return:1
depth=0 C = JP, ST = Tokyo, L = Minato-ku, O = Sony Global Solutions Inc, CN = www.sony.co.uk
verify return:1
OCSP response: 
======================================
OCSP Response Data:
    OCSP Response Status: successful (0x0)
    Response Type: Basic OCSP Response
    Version: 1 (0x0)
    Responder Id: 0F80611C823161D52F28E78D4638B42CE1C6D9E2
    Produced At: Nov 11 13:48:01 2021 GMT
    Responses:
    Certificate ID:
      Hash Algorithm: sha1
      Issuer Name Hash: 105FA67A80089DB5279F35CE830B43889EA3C70D
      Issuer Key Hash: 0F80611C823161D52F28E78D4638B42CE1C6D9E2
      Serial Number: 0F7B57FD566C9960A286F2031C6D70C7
    Cert Status: good
    This Update: Nov 11 13:33:01 2021 GMT
    Next Update: Nov 18 12:48:01 2021 GMT

    Signature Algorithm: sha256WithRSAEncryption
         7b:58:27:1e:da:b2:9d:0d:9b:4a:07:41:5a:64:ad:c0:0c:10:
         08:e8:5c:d7:14:8e:fd:a3:9c:2c:5e:6c:ff:84:01:17:3f:77:
         d3:5a:af:30:dc:4b:68:d4:12:f8:ac:67:73:a3:87:fd:e2:0f:
         98:c9:88:e3:7b:d6:27:32:36:6d:36:ef:53:94:31:d9:05:bf:
         2d:33:8a:33:1c:c5:c4:05:de:b1:15:af:ba:c9:a7:91:ec:9b:
         a6:81:0f:42:04:45:f4:89:5b:55:01:8b:a8:0d:6a:65:00:ed:
         28:04:b3:5b:80:61:26:cb:53:78:15:2d:47:20:e4:7e:a3:6e:
         bd:23:69:d0:19:81:46:55:59:c9:4e:3e:24:0a:ef:ca:d0:20:
         2e:1a:5b:8f:34:4d:f0:40:b4:f1:06:a7:8f:ec:f4:07:8a:11:
         47:d1:d3:f0:77:61:05:4d:44:32:a7:9e:85:8f:25:44:97:e9:
         d0:5d:63:6b:02:1a:e9:63:d3:7a:f4:ce:cb:7d:ac:50:c8:c6:
         5b:56:67:4e:0e:11:a2:1e:02:48:2f:21:64:22:9a:dc:42:37:
         6a:4b:06:70:7d:20:e5:8b:bb:92:57:6c:4d:55:b2:4a:a5:23:
         cf:97:0a:fe:29:9c:21:01:16:4e:a4:b2:01:7e:eb:a2:b6:da:
         8b:0c:4e:11
======================================
---
Certificate chain
 0 s:C = JP, ST = Tokyo, L = Minato-ku, O = Sony Global Solutions Inc, CN = www.sony.co.uk
   i:C = US, O = DigiCert Inc, CN = DigiCert SHA2 Secure Server CA
 1 s:C = US, O = DigiCert Inc, CN = DigiCert SHA2 Secure Server CA
   i:C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Global Root CA
---
Server certificate
-----BEGIN CERTIFICATE-----
MIILUjCCCjqgAwIBAgIQD3tX/VZsmWCihvIDHG1wxzANBgkqhkiG9w0BAQsFADBN
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMScwJQYDVQQDEx5E
aWdpQ2VydCBTSEEyIFNlY3VyZSBTZXJ2ZXIgQ0EwHhcNMjExMTExMDAwMDAwWhcN
MjIwMzMxMjM1OTU5WjBuMQswCQYDVQQGEwJKUDEOMAwGA1UECBMFVG9reW8xEjAQ
BgNVBAcTCU1pbmF0by1rdTEiMCAGA1UEChMZU29ueSBHbG9iYWwgU29sdXRpb25z
IEluYzEXMBUGA1UEAxMOd3d3LnNvbnkuY28udWswWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAQ8k4ZRGazrrCBvrr/E0oRyxkchiZTl2ppwGjJiw5zN4b8/V0i4dcY7
j46sONmaN8g6iXQSYwqYSK9uZCaDrL5fo4II1jCCCNIwHwYDVR0jBBgwFoAUD4Bh
HIIxYdUvKOeNRji0LOHG2eIwHQYDVR0OBBYEFJ6cGMuFOlv2V06QPzqNd5W3SXVC
MIIFnwYDVR0RBIIFljCCBZKCHGNhbXBhaWduLm9kdy5zb255LWV1cm9wZS5jb22C
EmNvbXBsaWFuY2Uuc29ueS5kZYISY29tcGxpYW5jZS5zb255LmV1ghFlc3VwcG9y
dC5zb255LmNvbYITZXh0cmEuc29ueS1hc2lhLmNvbYIOZm9udHMuc29ueS5uZXSC
Dmdsb2JhbC5zb255LmV1ghBtLnN0b3JlLnNvbnkuY29tghJzbWIuc3RvcmUuc29u
eS5jb22CCnNvbnkuY28udWuCCHNvbnkuY29tghJzcC5zb255LWV1cm9wZS5jb22C
DXN0b3JlLnNvbnkuY2GCDnN0b3JlLnNvbnkuY29tghB0dy5zb255LWFzaWEuY29t
ghZ3d3cuY29tcGxpYW5jZS5zb255LmRlghZ3d3cuY29tcGxpYW5jZS5zb255LmV1
gg53d3cua3ouc29ueS5ydYITd3d3LnNvbnktYWZyaWNhLmNvbYIRd3d3LnNvbnkt
YXNpYS5jb22CE3d3dy5zb255LWV1cm9wZS5jb22CEnd3dy5zb255LWxhdGluLmNv
bYIQd3d3LnNvbnktbWVhLmNvbYILd3d3LnNvbnkuYXSCC3d3dy5zb255LmJhggt3
d3cuc29ueS5iZYILd3d3LnNvbnkuYmeCC3d3dy5zb255LmNhggt3d3cuc29ueS5j
aIILd3d3LnNvbnkuY2yCDnd3dy5zb255LmNvLmNygg53d3cuc29ueS5jby5pZIIO
d3d3LnNvbnkuY28uaWyCDnd3dy5zb255LmNvLmlugg53d3cuc29ueS5jby5rcoIO
d3d3LnNvbnkuY28ubnqCDnd3dy5zb255LmNvLnRogg53d3cuc29ueS5jby51a4IM
d3d3LnNvbnkuY29tgg93d3cuc29ueS5jb20uYXKCD3d3dy5zb255LmNvbS5hdYIP
d3d3LnNvbnkuY29tLmJvgg93d3cuc29ueS5jb20uYnKCD3d3dy5zb255LmNvbS5j
b4IPd3d3LnNvbnkuY29tLmRvgg93d3cuc29ueS5jb20uZWOCD3d3dy5zb255LmNv
bS5ndIIPd3d3LnNvbnkuY29tLmhrgg93d3cuc29ueS5jb20uaG6CD3d3dy5zb255
LmNvbS5ta4IPd3d3LnNvbnkuY29tLm14gg93d3cuc29ueS5jb20ubXmCD3d3dy5z
b255LmNvbS5uaYIPd3d3LnNvbnkuY29tLnBhgg93d3cuc29ueS5jb20ucGWCD3d3
dy5zb255LmNvbS5waIIPd3d3LnNvbnkuY29tLnNngg93d3cuc29ueS5jb20uc3aC
D3d3dy5zb255LmNvbS50coIPd3d3LnNvbnkuY29tLnR3gg93d3cuc29ueS5jb20u
dm6CC3d3dy5zb255LmN6ggt3d3cuc29ueS5kZYILd3d3LnNvbnkuZGuCC3d3dy5z
b255LmVlggt3d3cuc29ueS5lc4ILd3d3LnNvbnkuZXWCC3d3dy5zb255LmZpggt3
d3cuc29ueS5mcoILd3d3LnNvbnkuZ3KCC3d3dy5zb255Lmhyggt3d3cuc29ueS5o
dYILd3d3LnNvbnkuaWWCC3d3dy5zb255Lml0ggt3d3cuc29ueS5reoILd3d3LnNv
bnkubHSCC3d3dy5zb255Lmx1ggt3d3cuc29ueS5sdoILd3d3LnNvbnkubmyCC3d3
dy5zb255Lm5vggt3d3cuc29ueS5wbIILd3d3LnNvbnkucHSCC3d3dy5zb255LnJv
ggt3d3cuc29ueS5yc4ILd3d3LnNvbnkucnWCC3d3dy5zb255LnNlggt3d3cuc29u
eS5zaYILd3d3LnNvbnkuc2uCC3d3dy5zb255LnVhghN3d3cuc29ueWxhdHZpamEu
Y29tMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUH
AwIwbwYDVR0fBGgwZjAxoC+gLYYraHR0cDovL2NybDMuZGlnaWNlcnQuY29tL3Nz
Y2Etc2hhMi1nNi0xLmNybDAxoC+gLYYraHR0cDovL2NybDQuZGlnaWNlcnQuY29t
L3NzY2Etc2hhMi1nNi0xLmNybDA+BgNVHSAENzA1MDMGBmeBDAECAjApMCcGCCsG
AQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwfAYIKwYBBQUHAQEE
cDBuMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wRgYIKwYB
BQUHMAKGOmh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJT
ZWN1cmVTZXJ2ZXJDQS5jcnQwDAYDVR0TAQH/BAIwADCCAX8GCisGAQQB1nkCBAIE
ggFvBIIBawFpAHcAKXm+8J45OSHwVnOfY6V35b5XfZxgCvj5TV0mXCVdx4QAAAF9
Dz6lNwAABAMASDBGAiEA/l/zHjIwh9TbGBQjhRi/qmEW54JzCYx3xXtG8v9LNBUC
IQCZcFFY8VaUMYES4qNIYnUGsUBIMLmkr2eVBZVPYlPYnQB2AFGjsPX9AXmcVm24
N3iPDKR6zBsny/eeiEKaDf7UiwXlAAABfQ8+pYwAAAQDAEcwRQIgS8UGb9mezREX
jpuhJXKcpcksWakED5VC5gwsihmLrRgCIQD3EkvmHkv+Ea903rpUL/HjvpQu01Sd
dT6Le8vU7P8zCgB2AN+lXqtogk8fbK3uuF9OPlrqzaISpGpejjsSwCBEXCpzAAAB
fQ8+pT8AAAQDAEcwRQIgeIq6PUWJLfO8XdT9bfIY+ISm12+COnHVX4fQBEd9vXwC
IQD9tlEkU2Eg3MbtMXiPCQQWLar6NDTgQPONZQDcwrBabDANBgkqhkiG9w0BAQsF
AAOCAQEAJY/Wv6QZESze42DHlNgR1d3u6ZZukmqyVbWJ4x/wL/LiXUeYQXM0jaI+
4zWzVFcpVzqlZdjQuJere/KlExal4YTVHWjucmkluIzL/d1xqY9CEHHNROjs4Wy5
DKkqrvwGmRK7hs+1N3/jWfRi8g/eivz1ZcM4LE7kW/I3Ew/TNm9ho2k/HgWB8MxH
Sk+DsgLLinisKT1Gm/JEv1ELqHTRko3dgOm7grq7CFBAeLrew6LJJ+JWsiA2yv+E
ZKmE2xbdxV/vJOsL0iUCwvLzL4O8l4vXXcn9e1UeGAe/ry1AJKmExUPjZQ7AILOF
Oyk0B3IIqpNXp4oD8Oja7lzkBMkZiQ==
-----END CERTIFICATE-----
subject=C = JP, ST = Tokyo, L = Minato-ku, O = Sony Global Solutions Inc, CN = www.sony.co.uk

issuer=C = US, O = DigiCert Inc, CN = DigiCert SHA2 Secure Server CA

---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: ECDSA
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 4947 bytes and written 403 bytes
Verification: OK
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Server public key is 256 bit
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---
DONE

```
You can also try out:

```
openssl s_client -connect ritter.vg:443 -status
CONNECTED(00000003)
depth=2 C = US, O = Internet Security Research Group, CN = ISRG Root X1
verify return:1
depth=1 C = US, O = Let's Encrypt, CN = R3
verify return:1
depth=0 CN = ritter.vg
verify return:1
OCSP response: 
======================================
OCSP Response Data:
    OCSP Response Status: successful (0x0)
    Response Type: Basic OCSP Response
    Version: 1 (0x0)
    Responder Id: C = US, O = Let's Encrypt, CN = R3
    Produced At: Nov 14 05:26:00 2021 GMT
    Responses:
    Certificate ID:
      Hash Algorithm: sha1
      Issuer Name Hash: 48DAC9A0FB2BD32D4FF0DE68D2F567B735F9B3C4
      Issuer Key Hash: 142EB317B75856CBAE500940E61FAF9D8B14C2C6
      Serial Number: 04809896E392CC9C62B6CCCD3F567B054536
    Cert Status: good
    This Update: Nov 14 05:00:00 2021 GMT
    Next Update: Nov 21 04:59:58 2021 GMT

    Signature Algorithm: sha256WithRSAEncryption
         1f:22:72:cf:18:e2:61:db:24:68:8c:59:93:ac:19:29:82:e5:
         3d:78:66:09:36:d5:24:8b:db:77:12:29:f7:61:bb:57:22:26:
         a1:39:25:1e:95:5c:4c:33:9a:dc:a3:e3:32:8c:54:5a:48:25:
         15:79:bc:22:2b:4e:d4:d8:ec:ca:20:b0:98:cf:50:c0:71:79:
         a2:4f:c8:99:dc:98:c1:4a:7f:e8:53:11:05:f6:94:7b:ad:7b:
         31:18:26:10:73:a0:28:de:42:38:d6:6e:ea:04:3c:e2:48:9e:
         cd:b8:60:4f:65:03:20:b3:6f:07:b0:d5:c6:74:82:78:84:35:
         5c:c0:66:1a:f9:f3:94:e6:ea:43:28:67:68:f6:3d:4c:10:07:
         77:45:81:fd:0e:be:44:f9:94:7e:1b:5d:54:c7:44:25:35:f5:
         78:90:8a:7a:fc:b2:22:b4:a7:27:9e:d7:02:52:e0:e3:e6:ec:
         b2:c9:e5:77:f1:16:3d:d9:28:d6:a4:27:65:18:62:c7:94:aa:
         eb:ba:ee:6e:ca:39:2e:97:e8:99:a5:2b:89:e3:7c:3b:b6:11:
         d8:7a:ae:ac:8c:2f:80:01:d6:a7:35:b8:39:2c:2c:6e:71:6e:
         25:49:2c:fc:94:49:10:e3:37:d7:34:d1:d3:c2:7c:a5:aa:f4:
         8f:0a:43:b1
======================================
---
Certificate chain
 0 s:CN = ritter.vg
   i:C = US, O = Let's Encrypt, CN = R3
 1 s:C = US, O = Let's Encrypt, CN = R3
   i:C = US, O = Internet Security Research Group, CN = ISRG Root X1
 2 s:C = US, O = Internet Security Research Group, CN = ISRG Root X1
   i:O = Digital Signature Trust Co., CN = DST Root CA X3
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIFFzCCA/+gAwIBAgISBICYluOSzJxitszNP1Z7BUU2MA0GCSqGSIb3DQEBCwUA
MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD
EwJSMzAeFw0yMTA5MjcxNjI2MDhaFw0yMTEyMjYxNjI2MDdaMBQxEjAQBgNVBAMT
CXJpdHRlci52ZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALcQJJal
S7FxXTWyB93h56TtD5x9awJ/wJGV3hJKI3T3lXb7vpRdNv3LgCIHGb9O8pBMDBRU
We7vvy4wyM16S1wN5j6ZyV5QhNCN27SL3cMFVpBzFoAttz42MxAYQXDJWgRzYDns
57XwOfajD7Vxhk2UB5SJ0hZdJBnbRckaUR462tiHoiymRemWSOTq7WH0i2858JP3
NHi8NBjJKKyFTvBwR+BmyckdB6UGQm0G6+4CJymKlVyXBvs0hgL6ohWHgErHJB+b
u4ykr9uIi5+g5dgCf/5CWEei8TGGazWh1NSH0pi1qCmgicnNF4RV15/BCbYFTg3l
/Fh36FUDYZrS+kkCAwEAAaOCAkMwggI/MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUE
FjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU
JfWurcvB5qgABZX0cLkGN1JVn1MwHwYDVR0jBBgwFoAUFC6zF7dYVsuuUAlA5h+v
nYsUwsYwVQYIKwYBBQUHAQEESTBHMCEGCCsGAQUFBzABhhVodHRwOi8vcjMuby5s
ZW5jci5vcmcwIgYIKwYBBQUHMAKGFmh0dHA6Ly9yMy5pLmxlbmNyLm9yZy8wFAYD
VR0RBA0wC4IJcml0dGVyLnZnMEwGA1UdIARFMEMwCAYGZ4EMAQIBMDcGCysGAQQB
gt8TAQEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcHMubGV0c2VuY3J5cHQub3Jn
MIIBAwYKKwYBBAHWeQIEAgSB9ASB8QDvAHYARJRlLrDuzq/EQAfYqP4owNrmgr7Y
yzG1P9MzlrW2gagAAAF8KErjzgAABAMARzBFAiBNjkgLjllj0UIcddLcJYI0uwY1
vyBfKFStP71U/qncEAIhAJ0DhEcHviRiBu6DBStchGsJwoRgieMFDsMGH6H47grf
AHUA9lyUL9F3MCIUVBgIMJRWjuNNExkzv98MLyALzE7xZOMAAAF8KErjmQAABAMA
RjBEAiBhvgt9MF6HLwFJ0/Q3cNQCXtEtQh6sgSQLbaT7qke4YwIgONAxM0WFFxxY
DSlwgyfx6ka+8qjYv1DzsQBe8/B8o8IwDQYJKoZIhvcNAQELBQADggEBAF7oDT/K
jznv3uPvgPCDHbjd2i1KQI4jGTjTV6WCKkIeqL3cG6BzzeWjV2B3WzLvzDre0l4Y
lTpUOUXm8iObpcdC5/mnvMyb0RT/gSbubu5DoHP0Mhk0SmFkNSmZEcczI5ihxrzv
uHlGfa3WeSF8QZVSju1P5zuWh7BOuXSbx4PWVP0wBMwPvTG9d+MfiOnSXqRs51vq
1+OGwRr0XoNK8QXpZlekwd0RRvheMbprnF13K2vSCgoVmrSRartbpjAMEhreOlLg
r+EAI/5KmP3IhpTidB9eFHGiAXj5qiNG6apio6J8vtCIlSUvvBTVd18e7dzerwyN
4RqC+J+QBrQiMHg=
-----END CERTIFICATE-----
subject=CN = ritter.vg

issuer=C = US, O = Let's Encrypt, CN = R3

---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: RSA-PSS
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 5188 bytes and written 405 bytes
Verification: OK
---
New, TLSv1.2, Cipher is ECDHE-RSA-CHACHA20-POLY1305
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-CHACHA20-POLY1305
    Session-ID: 202A64FB904358AB7E3F70624AFCC6A4967DD4EC89F9662ACF526CFF50741D5D
    Session-ID-ctx: 
    Master-Key: 463F6C0718B1BA1CEB48E21C77389C69159BE49D404CA0D44799BD383FF66A3E35E261C7268C4F157BBF0FF73421261B
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 300 (seconds)
    TLS session ticket:
    0000 - 42 8b f0 06 01 61 15 99-c9 2a 55 26 de f1 74 21   B....a...*U&..t!
    0010 - a3 93 a7 a1 36 63 4c f8-98 15 c4 b5 7e 6a bd 88   ....6cL.....~j..
    0020 - 0d f9 16 2b b8 59 c0 4f-11 24 4c ba af 2b 19 3f   ...+.Y.O.$L..+.?
    0030 - ff c3 3a bd 46 1c 8f 10-f5 b6 0c 1e 83 40 10 9a   ..:.F........@..
    0040 - f9 ef fe 82 29 76 bc f2-70 d7 b6 57 c5 32 e5 d2   ....)v..p..W.2..
    0050 - 62 bd 9e ea f4 23 ac 57-a0 7c b6 35 a1 66 91 0f   b....#.W.|.5.f..
    0060 - c6 d8 4b 94 73 56 16 6e-aa 3c b7 7b f3 7b 9a 20   ..K.sV.n.<.{.{. 
    0070 - c9 60 ef 2b 65 37 f6 9b-8c 73 1e 42 3b c6 b4 47   .`.+e7...s.B;..G
    0080 - aa c7 71 67 b3 10 6e 20-57 be 5e d8 12 76 ad 19   ..qg..n W.^..v..
    0090 - 06 b6 e7 29 fd a4 ba e9-30 24 6b 18 6d 34 55 9a   ...)....0$k.m4U.
    00a0 - 22 18 f2 ee 55 db f0 58-21 ae ee 5a 4e 9a 33 71   "...U..X!..ZN.3q
    00b0 - 06 0c 89 b6 58 90 70 4f-cc 1f 16 f9 15 50 07 ef   ....X.pO.....P..
    00c0 - 37 65 04 f8 d6 c3 33 72-5e 8e 55 6f 98 45 f3 9b   7e....3r^.Uo.E..

    Start Time: 1637053265
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: yes
---

```
The OCSP-related information will be displayed at the very beginning of the connection output. In case the
server supports stapling, you will see the entire OCSP response in the output. For example, with a server that
does not support stapling, you will see an “OCSP response: no response sent”.

Check out with the above command some famous website (e.g. [http://www.google.com)](http://www.google.com)) to verify whether they
support or not OCSP stapling.
```
openssl s_client -connect google.com:443 -status
CONNECTED(00000003)
depth=2 C = US, O = Google Trust Services LLC, CN = GTS Root R1
verify return:1
depth=1 C = US, O = Google Trust Services LLC, CN = GTS CA 1C3
verify return:1
depth=0 CN = *.google.com
verify return:1
OCSP response: no response sent
---
Certificate chain
 0 s:CN = *.google.com
   i:C = US, O = Google Trust Services LLC, CN = GTS CA 1C3
 1 s:C = US, O = Google Trust Services LLC, CN = GTS CA 1C3
   i:C = US, O = Google Trust Services LLC, CN = GTS Root R1
 2 s:C = US, O = Google Trust Services LLC, CN = GTS Root R1
   i:C = BE, O = GlobalSign nv-sa, OU = Root CA, CN = GlobalSign Root CA
---
Server certificate
-----BEGIN CERTIFICATE-----
MIINxTCCDK2gAwIBAgIQUMLplYhmsKwKAAAAARA0DDANBgkqhkiG9w0BAQsFADBG
MQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExM
QzETMBEGA1UEAxMKR1RTIENBIDFDMzAeFw0yMTEwMTgwOTAzMjRaFw0yMjAxMTAw
OTAzMjNaMBcxFTATBgNVBAMMDCouZ29vZ2xlLmNvbTBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABHMs/JkWADby98iFAuuaDtf5xgS80M4oJEMTYH3JqGNya7gAp7hH
glQiAbYcd/rfVFnvn8tt7u/xfqDqWZUGevyjggunMIILozAOBgNVHQ8BAf8EBAMC
B4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU
Zj0AN1aaSuTe5HSZ/kkhXRbzHVUwHwYDVR0jBBgwFoAUinR/r4XN7pXNPZzQ4kYU
83E1HScwagYIKwYBBQUHAQEEXjBcMCcGCCsGAQUFBzABhhtodHRwOi8vb2NzcC5w
a2kuZ29vZy9ndHMxYzMwMQYIKwYBBQUHMAKGJWh0dHA6Ly9wa2kuZ29vZy9yZXBv
L2NlcnRzL2d0czFjMy5kZXIwgglWBgNVHREEgglNMIIJSYIMKi5nb29nbGUuY29t
ghYqLmFwcGVuZ2luZS5nb29nbGUuY29tggkqLmJkbi5kZXaCEiouY2xvdWQuZ29v
Z2xlLmNvbYIYKi5jcm93ZHNvdXJjZS5nb29nbGUuY29tghgqLmRhdGFjb21wdXRl
Lmdvb2dsZS5jb22CCyouZ29vZ2xlLmNhggsqLmdvb2dsZS5jbIIOKi5nb29nbGUu
Y28uaW6CDiouZ29vZ2xlLmNvLmpwgg4qLmdvb2dsZS5jby51a4IPKi5nb29nbGUu
Y29tLmFygg8qLmdvb2dsZS5jb20uYXWCDyouZ29vZ2xlLmNvbS5icoIPKi5nb29n
bGUuY29tLmNvgg8qLmdvb2dsZS5jb20ubXiCDyouZ29vZ2xlLmNvbS50coIPKi5n
b29nbGUuY29tLnZuggsqLmdvb2dsZS5kZYILKi5nb29nbGUuZXOCCyouZ29vZ2xl
LmZyggsqLmdvb2dsZS5odYILKi5nb29nbGUuaXSCCyouZ29vZ2xlLm5sggsqLmdv
b2dsZS5wbIILKi5nb29nbGUucHSCEiouZ29vZ2xlYWRhcGlzLmNvbYIPKi5nb29n
bGVhcGlzLmNughEqLmdvb2dsZXZpZGVvLmNvbYIMKi5nc3RhdGljLmNughAqLmdz
dGF0aWMtY24uY29tghIqLmdzdGF0aWNjbmFwcHMuY26CD2dvb2dsZWNuYXBwcy5j
boIRKi5nb29nbGVjbmFwcHMuY26CEWdvb2dsZWFwcHMtY24uY29tghMqLmdvb2ds
ZWFwcHMtY24uY29tggxna2VjbmFwcHMuY26CDiouZ2tlY25hcHBzLmNughJnb29n
bGVkb3dubG9hZHMuY26CFCouZ29vZ2xlZG93bmxvYWRzLmNughByZWNhcHRjaGEu
bmV0LmNughIqLnJlY2FwdGNoYS5uZXQuY26CC3dpZGV2aW5lLmNugg0qLndpZGV2
aW5lLmNughFhbXBwcm9qZWN0Lm9yZy5jboITKi5hbXBwcm9qZWN0Lm9yZy5jboIR
YW1wcHJvamVjdC5uZXQuY26CEyouYW1wcHJvamVjdC5uZXQuY26CF2dvb2dsZS1h
bmFseXRpY3MtY24uY29tghkqLmdvb2dsZS1hbmFseXRpY3MtY24uY29tghdnb29n
bGVhZHNlcnZpY2VzLWNuLmNvbYIZKi5nb29nbGVhZHNlcnZpY2VzLWNuLmNvbYIR
Z29vZ2xldmFkcy1jbi5jb22CEyouZ29vZ2xldmFkcy1jbi5jb22CEWdvb2dsZWFw
aXMtY24uY29tghMqLmdvb2dsZWFwaXMtY24uY29tghVnb29nbGVvcHRpbWl6ZS1j
bi5jb22CFyouZ29vZ2xlb3B0aW1pemUtY24uY29tghJkb3VibGVjbGljay1jbi5u
ZXSCFCouZG91YmxlY2xpY2stY24ubmV0ghgqLmZscy5kb3VibGVjbGljay1jbi5u
ZXSCFiouZy5kb3VibGVjbGljay1jbi5uZXSCDmRvdWJsZWNsaWNrLmNughAqLmRv
dWJsZWNsaWNrLmNughQqLmZscy5kb3VibGVjbGljay5jboISKi5nLmRvdWJsZWNs
aWNrLmNughFkYXJ0c2VhcmNoLWNuLm5ldIITKi5kYXJ0c2VhcmNoLWNuLm5ldIId
Z29vZ2xldHJhdmVsYWRzZXJ2aWNlcy1jbi5jb22CHyouZ29vZ2xldHJhdmVsYWRz
ZXJ2aWNlcy1jbi5jb22CGGdvb2dsZXRhZ3NlcnZpY2VzLWNuLmNvbYIaKi5nb29n
bGV0YWdzZXJ2aWNlcy1jbi5jb22CF2dvb2dsZXRhZ21hbmFnZXItY24uY29tghkq
Lmdvb2dsZXRhZ21hbmFnZXItY24uY29tghhnb29nbGVzeW5kaWNhdGlvbi1jbi5j
b22CGiouZ29vZ2xlc3luZGljYXRpb24tY24uY29tgiQqLnNhZmVmcmFtZS5nb29n
bGVzeW5kaWNhdGlvbi1jbi5jb22CFmFwcC1tZWFzdXJlbWVudC1jbi5jb22CGCou
YXBwLW1lYXN1cmVtZW50LWNuLmNvbYILZ3Z0MS1jbi5jb22CDSouZ3Z0MS1jbi5j
b22CC2d2dDItY24uY29tgg0qLmd2dDItY24uY29tggsybWRuLWNuLm5ldIINKi4y
bWRuLWNuLm5ldIIUZ29vZ2xlZmxpZ2h0cy1jbi5uZXSCFiouZ29vZ2xlZmxpZ2h0
cy1jbi5uZXSCDGFkbW9iLWNuLmNvbYIOKi5hZG1vYi1jbi5jb22CDSouZ3N0YXRp
Yy5jb22CFCoubWV0cmljLmdzdGF0aWMuY29tggoqLmd2dDEuY29tghEqLmdjcGNk
bi5ndnQxLmNvbYIKKi5ndnQyLmNvbYIOKi5nY3AuZ3Z0Mi5jb22CECoudXJsLmdv
b2dsZS5jb22CFioueW91dHViZS1ub2Nvb2tpZS5jb22CCyoueXRpbWcuY29tggth
bmRyb2lkLmNvbYINKi5hbmRyb2lkLmNvbYITKi5mbGFzaC5hbmRyb2lkLmNvbYIE
Zy5jboIGKi5nLmNuggRnLmNvggYqLmcuY2+CBmdvby5nbIIKd3d3Lmdvby5nbIIU
Z29vZ2xlLWFuYWx5dGljcy5jb22CFiouZ29vZ2xlLWFuYWx5dGljcy5jb22CCmdv
b2dsZS5jb22CEmdvb2dsZWNvbW1lcmNlLmNvbYIUKi5nb29nbGVjb21tZXJjZS5j
b22CCGdncGh0LmNuggoqLmdncGh0LmNuggp1cmNoaW4uY29tggwqLnVyY2hpbi5j
b22CCHlvdXR1LmJlggt5b3V0dWJlLmNvbYINKi55b3V0dWJlLmNvbYIUeW91dHVi
ZWVkdWNhdGlvbi5jb22CFioueW91dHViZWVkdWNhdGlvbi5jb22CD3lvdXR1YmVr
aWRzLmNvbYIRKi55b3V0dWJla2lkcy5jb22CBXl0LmJlggcqLnl0LmJlghphbmRy
b2lkLmNsaWVudHMuZ29vZ2xlLmNvbYIbZGV2ZWxvcGVyLmFuZHJvaWQuZ29vZ2xl
LmNughxkZXZlbG9wZXJzLmFuZHJvaWQuZ29vZ2xlLmNughhzb3VyY2UuYW5kcm9p
ZC5nb29nbGUuY24wIQYDVR0gBBowGDAIBgZngQwBAgEwDAYKKwYBBAHWeQIFAzA8
BgNVHR8ENTAzMDGgL6AthitodHRwOi8vY3Jscy5wa2kuZ29vZy9ndHMxYzMvUU92
SjBOMXNUMkEuY3JsMIIBBQYKKwYBBAHWeQIEAgSB9gSB8wDxAHcAUaOw9f0BeZxW
bbg3eI8MpHrMGyfL956IQpoN/tSLBeUAAAF8ktsn7gAABAMASDBGAiEAlv+jUIT6
cAdrJ5gLVqDwqnp8NlNGTQLwK05vxE/Q4xYCIQCa0dvODw8eBIB1AcwktJnXg+Hp
hGuQW9bHnMx/DL+AcQB2AEalVet1+pEgMLWiiWn0830RLEF0vv1JuIWr8vxw/m1H
AAABfJLbKfIAAAQDAEcwRQIgdL55HAPChHyp2wnMxLxvDC+ZLx9dALZBAcFq/JsV
0woCIQChI468tRYXngZaCHmwyW2eVFicssPsl0g12iEU4woltjANBgkqhkiG9w0B
AQsFAAOCAQEAdn0K+RaM2sNI8ky8LtpUnU9IO47dVCtpP5nuIA7+ZjEPbduvA/wP
HH+Xg/aLoGTDNtn6UCL9RTxoYZc6KKsMr4lXGqwkjyhbyeQnsu8eB+CAG6boZMYN
aG3Aq31LU+AQCjrdBqxAuge+LR350j5jXnG2Iy4iQquUNzriEgDK3YZc8yYJhnr0
0/pjjvD2Ti+BxkUQBDwEL+wUIPMkvLG0wbVyk97x4LHjg1Vv7RLVFzyYt6lykPeG
vwL5kAkgBdpP3sM60rs/poJMr7o/3XUHotP5lyIMVT4jrerVvRPOpT6tzmHp57oT
BtRSAAWMcFsC9Y1zphWC27izvXWtzxv6Pg==
-----END CERTIFICATE-----
subject=CN = *.google.com

issuer=C = US, O = Google Trust Services LLC, CN = GTS CA 1C3

---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: ECDSA
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 6659 bytes and written 401 bytes
Verification: OK
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Server public key is 256 bit
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---

```

### 2.3 Extended Validation (EV), Organization Validation (OV), Domain Validated (DV)

Some CAs issue TLS server certificates with a particular extension named Extended Validation. During ad-
ministrative verification of an EV certificate request, the owner of the website passes a thorough and globally
standardized identity verification process (a set of vetting principles and policies ratified by the CA/Browser
forum) to prove exclusive rights to use a domain, confirm its legal, operational, and physical existence, and
prove the entity has authorized the issuance of the certificate. This verified identity information is included
within the certificate.

The verification process for OV and DV certificates is not as comprehensive as for EV. DV certificates only
require a proof that the website owner has administrative control over the domain. OV certificates include some
identity information about the site operator, but it is not as extensive as for EV.

Some example of TLS server certificates with EV, OV, and DV extensions may be found below. For each of the
examples, connect to the URL, view the server certificate and analyse the Certificate Policies extensions.

---
A server certificate with DV extension:https://www.nist.org/
OID.2.23.140.1.2.1
OID.1.3.6.1.4.1.44947.1.1.1:
  Certification Practice Statement Pointer:    http://cps.letsencrypt.org
3.2 Initial identity validation
ISRG may elect not to issue any certificate at its sole discretion.

3.2.1 Method to prove possession of private key
Applicants are required to prove possession of the Private Key corresponding to the Public Key in a Certificate request by signing the CSR provided to the Finalize method of the ACME Protocol defined in RFC 8555, Section 7.4.

3.2.2 Authentication of Organization and Domain Identity
ISRG only issues Domain Validation (DV) certificates. All FQDNs which will be listed in the Common Name and list of SANs in the certificate are fully validated prior to issuance.

ISRG uses three methods for validating domain control:

DNS Change (BR and ISRG CP Section 3.2.2.4.7)
Agreed-Upon Change to Website - ACME (BR and ISRG CP Section 3.2.2.4.19)
TLS Using ALPN (BR and ISRG CP Section 3.2.2.4.20)
Validation for Wildcard Domain Names must be completed using the DNS Change method.

All validations are performed in compliance with the current CAB Forum Baseline Requirements at the time of validation.

3.2.3 Authentication of individual identity
ISRG does not issue certificates to individuals, and thus does not authenticate individual identities.

3.2.4 Non-verified subscriber information
Non-verified Applicant information is not included in ISRG certificates.

3.2.5 Validation of authority
ISRG does not issue Subscriber Certificates containing Subject Identity Information, and thus does not validate any natural person's authority to request certificates on behalf of organizations.

3.2.6 Criteria for Interoperation or Certification
ISRG discloses Cross Certificates in its Certificate Repository.

---
A server certificate with OV extension:https://www.sony.com/
OID.2.23.140.1.2.2:
  Certification Practice Statement Pointer:    http://www.digicert.com/CPS
https://www.digicert.com/content/dam/digicert/pdfs/legal/DigiCert-DirectTrust-CP-CPS-v.1.0.pdf
A lot of pages with same numeration

---
A server certificate with EV extension:https://www.globalsign.com/
OID.1.3.6.1.4.1.4146.1.1:
  Certification Practice Statement Pointer:    https://www.globalsign.com/repository/
OID.2.23.140.1.1
Even more pages!

## 3 Certificate Transparency

### 3.1 Analysing SCT extensions in an X.509 certificate

In the browser, open the website (e.g.https://www.polito.it), click on the padlock icon next to the URLbar and view the certificate details. On theCertificate Detailspage click onDetailsand expand the SCT List (When a valid certificate is submitted to a log, the log MUST immediately return a Signed Certificate Timestamp (SCT). The SCT is the log's promise to incorporate the certificate in the Merkle Tree within a fixed amount of time known as the Maximum Merge Delay (MMD)).

```
Certificate Transparency
Log name
Google 'Xenon2022' log
Log ID
46 A5 55 EB 75 FA 91 20 30 B5 A2 89 69 F4 F3 7D 11 2C 41 74 BE FD 49 B8 85 AB F2 FC 70 FE 6D 47
Validation status
Verified
Source
Embedded in certificate
Issued at
Fri, 19 Feb 2021 10:09:11 GMT
Hash algorithm
SHA-256
Signature algorithm
ECDSA
Signature data
30 44 02 20 43 72 FD 5A C9 AA 02 5D 98 37 C5 5E E4 10 CB 62 AF D7 12 49 B9 8F CB 12 90 5B 8E 1A 47 50 44 05 02 20 70 E3 2D F2 C5 CB FB 2D 15 B8 6E EF 18 97 84 0A 82 67 DF 81 7E 0D 9D 31 AA 75 5B B3 CC 22 F0 41

Log name
Let's Encrypt 'Oak2022' log
Log ID
DF A5 5E AB 68 82 4F 1F 6C AD EE B8 5F 4E 3E 5A EA CD A2 12 A4 6A 5E 8E 3B 12 C0 20 44 5C 2A 73
Validation status
Verified
Source
Embedded in certificate
Issued at
Fri, 19 Feb 2021 10:09:11 GMT
Hash algorithm
SHA-256
Signature algorithm
ECDSA
Signature data
30 45 02 20 05 58 55 F1 11 13 D7 A6 42 40 F6 DD A3 8F 52 1C BC D6 87 04 0B 39 84 9A 92 5B E1 DC 25 E9 49 4A 02 21 00 D4 CF 24 06 47 E1 CD 69 6F B0 C9 75 16 5A 51 81 11 4B 4C 44 AB B9 7D 2F 3A 34 99 48 39 5F 0E 81
```

There you should see the date and time when the signed certificate stamp (SCT) was added to the public CT Log Servers. -> Fri, 19 Feb 2021 10:09:11 GMT

Then, run the command:

```
openssl x509 -in www-polito-it.pem -text
```
Analyse the output, in particular the “CT Precertificate SCTs” part.
```
CT Precertificate SCTs: 
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : 46:A5:55:EB:75:FA:91:20:30:B5:A2:89:69:F4:F3:7D:
                                11:2C:41:74:BE:FD:49:B8:85:AB:F2:FC:70:FE:6D:47
                    Timestamp : Feb 19 10:09:11.355 2021 GMT
                    Extensions: none
                    Signature : ecdsa-with-SHA256
                                30:44:02:20:43:72:FD:5A:C9:AA:02:5D:98:37:C5:5E:
                                E4:10:CB:62:AF:D7:12:49:B9:8F:CB:12:90:5B:8E:1A:
                                47:50:44:05:02:20:70:E3:2D:F2:C5:CB:FB:2D:15:B8:
                                6E:EF:18:97:84:0A:82:67:DF:81:7E:0D:9D:31:AA:75:
                                5B:B3:CC:22:F0:41
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : DF:A5:5E:AB:68:82:4F:1F:6C:AD:EE:B8:5F:4E:3E:5A:
                                EA:CD:A2:12:A4:6A:5E:8E:3B:12:C0:20:44:5C:2A:73
                    Timestamp : Feb 19 10:09:11.679 2021 GMT
                    Extensions: none
                    Signature : ecdsa-with-SHA256
                                30:45:02:20:05:58:55:F1:11:13:D7:A6:42:40:F6:DD:
                                A3:8F:52:1C:BC:D6:87:04:0B:39:84:9A:92:5B:E1:DC:
                                25:E9:49:4A:02:21:00:D4:CF:24:06:47:E1:CD:69:6F:
                                B0:C9:75:16:5A:51:81:11:4B:4C:44:AB:B9:7D:2F:3A:
                                34:99:48:39:5F:0E:81

```
You should be able to note a finer time precision in the “Timestamp” field.
-> Feb 19 10:09:11.355 2021 GMT
-> Feb 19 10:09:11.679 2021 GMT

Respond to the questions: Why the SCTs have been proposed, and in particular the Certificate Transparency occurred? What does it mean “Precertificate”?

```
To avoid the clients being compromised connecting to a server with a certificate supposedly emitted by a trusted server, when the certificate was actually mistakenly issued. This also allow companies to control that no certificates are wrongly emitted in their name.
Using SCT via x.509v3 extension, first the CA submits a precertificate to the log server, then it responds with the Signed Certificate Timestamp (log). The CA attaches it to the precertificate as an extension, signs the certificate and delivers it to the server operator. The SCP will accompany the certificate for its lifetime.
```

### 3.2 Checking certificate presence in CT logs

You can check whether a certain domain’s certificate is present in the active public certificate transparency log.

With your browser, go tohttps://transparencyreport.google.com/https/certificates. You should
see a page as illustrated in Fig. 2.

```
Figure 2: Google Transparency Report.
```
In the section “Search certificates by hostname”, insert the domainwww.polito.itYou should be able to see
the current status of the certificates issued for this domain, but also the past ones, as illustrated in Fig. 3.

Now, look for yourself in the Google Transparency Report for the certificate in thewww-globalsign-com.pem
that you can download by connectecting tohttps://www.globalsign.com.

The certificate retrieved in www-globalsign-com.pem is the same available from the transparencyreport public log at: https://transparencyreport.google.com/https/certificates/sIdtVJZl90pLLtjY98IT8S8LdSlLiMjsF2%2FhMjSf9CM%3D
Hence this is a real certificate


```
Figure 3: Google Transparency Report for http://www.polito.it.
```
### 3.3 Known CT Logs

At the linkhttp://www.certificate-transparency.org/known-logsyou find information about the CT
Logs that are currently compliant with Chrome’s CT policy:https://www.gstatic.com/ct/log_list/v2/
log_list.json

But you can check also a list of all known and announced CT Logs:https://www.gstatic.com/ct/log_
list/v2/all_logs_list.json

## 4 Certificate chains and PKI models

### 4.1 Viewing and verification of simple certificate chains

In this exercise we will explain first how you can view the certificate chain. Open Google Chrome browser,
and navigate for example to the URLhttps://globalsign.com. Click on the padlock, then on the Certificate
(to view its details). Finally select the tab “Certification Path”. You should be able to see the entire certificate
chain, from the server certificate up to the Root CA, as illustrated in Fig. 4.

Which fields in the certificate have been exploited to construct the certificate chain you see?

```
www-globalsign-com.pem 
Issuer: C = BE, O = GlobalSign nv-sa, CN = GlobalSign Extended Validation CA - SHA256 - G3

GlobalSign_CA.pem
Issuer: C = BE, O = GlobalSign nv-sa, OU = Root CA, CN = GlobalSign Root CA
Subject: OU = GlobalSign Root CA - R3, O = GlobalSign, CN = GlobalSign
```

Why the verification of this chain (as you see it in the browser) is successful? Hint: Check out the List of trusted Root CAs in your browser.
```
chrome://settings/certificates contains under org-GlobalSign nv-sa the GlobalSign Root CA certificate, which is the same certification at the top of the chain showed by the browser for the globalsign.com website

It is a self-signed certificate (Issuer==Subject):
openssl x509 -in GlobalSign_Root_CA.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            04:00:00:00:00:01:15:4b:5a:c3:94
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: C = BE, O = GlobalSign nv-sa, OU = Root CA, CN = GlobalSign Root CA
        Validity
            Not Before: Sep  1 12:00:00 1998 GMT
            Not After : Jan 28 12:00:00 2028 GMT
        Subject: C = BE, O = GlobalSign nv-sa, OU = Root CA, CN = GlobalSign Root CA
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:da:0e:e6:99:8d:ce:a3:e3:4f:8a:7e:fb:f1:8b:
                    83:25:6b:ea:48:1f:f1:2a:b0:b9:95:11:04:bd:f0:
                    63:d1:e2:67:66:cf:1c:dd:cf:1b:48:2b:ee:8d:89:
                    8e:9a:af:29:80:65:ab:e9:c7:2d:12:cb:ab:1c:4c:
                    70:07:a1:3d:0a:30:cd:15:8d:4f:f8:dd:d4:8c:50:
                    15:1c:ef:50:ee:c4:2e:f7:fc:e9:52:f2:91:7d:e0:
                    6d:d5:35:30:8e:5e:43:73:f2:41:e9:d5:6a:e3:b2:
                    89:3a:56:39:38:6f:06:3c:88:69:5b:2a:4d:c5:a7:
                    54:b8:6c:89:cc:9b:f9:3c:ca:e5:fd:89:f5:12:3c:
                    92:78:96:d6:dc:74:6e:93:44:61:d1:8d:c7:46:b2:
                    75:0e:86:e8:19:8a:d5:6d:6c:d5:78:16:95:a2:e9:
                    c8:0a:38:eb:f2:24:13:4f:73:54:93:13:85:3a:1b:
                    bc:1e:34:b5:8b:05:8c:b9:77:8b:b1:db:1f:20:91:
                    ab:09:53:6e:90:ce:7b:37:74:b9:70:47:91:22:51:
                    63:16:79:ae:b1:ae:41:26:08:c8:19:2b:d1:46:aa:
                    48:d6:64:2a:d7:83:34:ff:2c:2a:c1:6c:19:43:4a:
                    07:85:e7:d3:7c:f6:21:68:ef:ea:f2:52:9f:7f:93:
                    90:cf
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier: 
                60:7B:66:1A:45:0D:97:CA:89:50:2F:7D:04:CD:34:A8:FF:FC:FD:4B
    Signature Algorithm: sha1WithRSAEncryption
         d6:73:e7:7c:4f:76:d0:8d:bf:ec:ba:a2:be:34:c5:28:32:b5:
         7c:fc:6c:9c:2c:2b:bd:09:9e:53:bf:6b:5e:aa:11:48:b6:e5:
         08:a3:b3:ca:3d:61:4d:d3:46:09:b3:3e:c3:a0:e3:63:55:1b:
         f2:ba:ef:ad:39:e1:43:b9:38:a3:e6:2f:8a:26:3b:ef:a0:50:
         56:f9:c6:0a:fd:38:cd:c4:0b:70:51:94:97:98:04:df:c3:5f:
         94:d5:15:c9:14:41:9c:c4:5d:75:64:15:0d:ff:55:30:ec:86:
         8f:ff:0d:ef:2c:b9:63:46:f6:aa:fc:df:bc:69:fd:2e:12:48:
         64:9a:e0:95:f0:a6:ef:29:8f:01:b1:15:b5:0c:1d:a5:fe:69:
         2c:69:24:78:1e:b3:a7:1c:71:62:ee:ca:c8:97:ac:17:5d:8a:
         c2:f8:47:86:6e:2a:c4:56:31:95:d0:67:89:85:2b:f9:6c:a6:
         5d:46:9d:0c:aa:82:e4:99:51:dd:70:b7:db:56:3d:61:e4:6a:
         e1:5c:d6:f6:fe:3d:de:41:cc:07:ae:63:52:bf:53:53:f4:2b:
         e9:c7:fd:b6:f7:82:5f:85:d2:41:18:db:81:b3:04:1c:c5:1f:
         a4:80:6f:15:20:c9:de:0c:88:0a:1d:d6:66:55:e2:fc:48:c9:
         29:26:69:e0

```
Now, take the files provided as support material for this laboratory (CYBlab02support.zip):

```
Figure 4: Example of certificate chain viewed in Google Chrome.
```

- www-globalsign-com.pem,
- GlobalSignExtendedValidationCA.pem,
- GlobalSignRootOU.pem, and
- GlobalSignRootCA.pem.

Then, run the following command:

```
openssl verify -CAfile GlobalSign_Root_CA.pem www-globalsign-com.pem

businessCategory = Private Organization, serialNumber = 578611, jurisdictionC = US, jurisdictionST = New Hampshire, C = US, ST = New Hampshire, L = Portsmouth, street = "2 International Drive, Suite 150", O = "GMO GlobalSign, Inc.", CN = www.globalsign.com
error 20 at 0 depth lookup: unable to get local issuer certificate
error www-globalsign-com.pem: verification failed
```

Did you get any error? If yes, can you explain its cause? Note that we did specify a Root CA in the command, so the trust anchor is present.

```
You can't reconstruct the full chain because the globalsign-ca is missing, so openssl cannot know that it was issued by that root CA!
```
Now try out the following command:

```
openssl verify -verbose -CAfile <(cat GlobalSign_Extended_Validation_CA.pem GlobalSign_Root_OU.pem GlobalSign_Root_CA.pem) www-globalsign-com.pem

www-globalsign-com.pem: OK
```
Do you still get any error?
No, because now the chain is really complete! To reconstruct the chain from the browser you need to export the certificates seen on the website, and search in the trusted root certificates the one that has the subject==to the issuer of the highest certificate on the chain of the website.

```
Root_CA:
Issuer: C = BE, O = GlobalSign nv-sa, OU = Root CA, CN = GlobalSign Root CA
Subject: C = BE, O = GlobalSign nv-sa, OU = Root CA, CN = GlobalSign Root CA
```
```
Root_OU:
Issuer: C = BE, O = GlobalSign nv-sa, OU = Root CA, CN = GlobalSign Root CA
Subject: OU = GlobalSign Root CA - R3, O = GlobalSign, CN = GlobalSign
```
```
The relevant authority key identifier components of the current certificate (if present) must match the subject key identifier (if present) and issuer andserial number of the candidate issuer, in addition the keyUsage extension of the candidate issuer(if present) must permit certificate signing.

GlobalSign_Root_CA has 
    X509v3 Subject Key Identifier:
        60:7B:66:1A:45:0D:97:CA:89:50:2F:7D:04:CD:34:A8:FF:FC:FD:4B

GlobalSign_OU has
    X509v3 Subject Key Identifier: 
        8F:F0:4B:7F:A8:2E:45:24:AE:4D:50:FA:63:9A:8B:DE:E2:DD:1B:BC
    X509v3 Authority Key Identifier: 
        keyid:60:7B:66:1A:45:0D:97:CA:89:50:2F:7D:04:CD:34:A8:FF:FC:FD:4B -> GlobalSign_Root_CA

GlobalSign_Extended_Validation_CA has
    X509v3 Subject Key Identifier: 
        DD:B3:E7:6D:A8:2E:E8:C5:4E:6E:CF:74:E6:75:3C:94:15:CE:E8:1D
    X509v3 Authority Key Identifier: 
        keyid:8F:F0:4B:7F:A8:2E:45:24:AE:4D:50:FA:63:9A:8B:DE:E2:DD:1B:BC -> GlobalSign_Root_OU

www-globalsign-com.pem has
    X509v3 Authority Key Identifier: 
        keyid:DD:B3:E7:6D:A8:2E:E8:C5:4E:6E:CF:74:E6:75:3C:94:15:CE:E8:1 -> EV_CA
    X509v3 Subject Key Identifier: 
        7D:C3:DE:81:80:91:AC:9D:55:5D:48:6B:B9:C8:89:7B:CC:59:BB:F6
```

### 4.2 Viewing of a real Federal PKI

To have an idea about how complex the Federal PKIs can become, we suggest you to visit:https://playbooks.
idmanagement.gov/fpki/tools/fpkigraph/. At this site, which is an official site of United States Govern-
ment, you can see the (complex) connections of various CAs across US Government.

It’s interesting to note for example a Hierarchical PKI: the “US Treasury Root CA ” (which is rooted in the
“Federal Common Policy CA”), issued certificates to the “Social Security Administration Certification Au-
thority” and “US Treasury Fiscal Service”. This allows Relying Parties running fiscal applications to validate
certificates (e.g. signed documents exploiting such certificates) originating from the Social Security Adminis-
tration area.

Look for yourself in the graph, try to find the above mentioned connection between these PKIs.

It’s also interesting to note for example that the “Federal Bridge CA G4” issued a certificate to “Dod Interoper-
ability Root CA2”, which in turn issued a certificate to the “Dod Root CA3”, which issued certificates to several
other DoD SW CAs (DoD stands for Department fo Defense). On the other hand the “Federal Bridge CA G4”
issued a certificate to “Symantec Class SSP Intermediate CA GA3”, which issued a certificate to “Eid Passport
LRA 2 CA”. Thus, applications in the Dod SW area can validate (through the Bridge CA) certificate issued
by the Eid Passport LRA CA”. Look for yourself in the graph, and find out the other interesting connections.
For example, “ Boeing PCA G3” is connected through 2 Bridge CAs (CertiPath Bridge CA - G3 and Federal
Bridge CA G4) and 2 Root CAs (Dod Interoperability Root CA2 and Dod Root CA3) to the DoD CAs, e.g.
DoD EMAIL CA-41.

Now let’s assume a user exploits an application (e.g. email) that uses a certificate issued by DoD EMAIL CA-
41, for example a signed e-mail. Then, he send the signed e-mail to another user, which configured as trusted
the “Boeing PCA G3”.

Is the validation of the certificate (attached to the signed e-mail) successful? Which is the certificate path?

```
upwards
DoD EMAIL CA-41 -> DoD Root CA 3 -> DoD Interoperability Root CA 2 -> Federal Bridge CA G4
downwards
Federal Bridge CA G4 -> CertiPath Bridge CA - G3 -> Boeing PCA G3
```

