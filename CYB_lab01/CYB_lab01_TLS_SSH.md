[pdf instruction](CYB_lab01_TLS_SSH.pdf)

# TLS and SSH

### Laboratory for the class “Cybersecurity” (01UDR)

### Politecnico di Torino – AA 2021/

### Prof. Antonio Lioy

### prepared by:

### Diana Berbecaru (diana.berbecaru@polito.it)

### Andrea Atzeni (andrea.atzeni@polito.it)

### v. 2.0 (08/10/2021)

## Contents

#### 1 TLS 4

```
1.1 Setting up a TLS channel..................................... 4
1.2 Configuration of a TLS server.................................. 4
1.2.1 Analysing the TLS 1.2 handshake messages....................... 5
1.2.2 Session resumption.................................... 6
1.2.3 Analysing the TLS 1.3 handshake messages....................... 6
1.2.4 Client authentication in TLS............................... 7
1.3 Enabling TLS in Apache Web Server............................... 8
1.4 Enabling client authentication.................................. 9
1.4.1 Configure the TLS server for client authentication.................... 9
1.4.2 Importing the client certificate in the browser...................... 9
1.4.3 Enabling certificate revocation checking in Apache web server............. 10
1.5 Performance measurement.................................... 11
```
#### 2 SSH 11

```
2.1 Connecting through a secure channel............................... 11
2.2 Passwordless access........................................ 13
2.3 Tunnelling............................................. 14
2.3.1 Direct tunnelling..................................... 14
2.3.2 Local tunnelling..................................... 14
2.3.3 Remote tunnelling.................................... 15
```

## Purpose of this laboratory

In this laboratory, you will perform exercises aimed to create secure (communication) channels among two
nodes, to evaluate their security features, and to measure the performance of the system when the security
features are modified. In practice, the exercises use two famous security protocols: TLS (Transport Layer
Security) and SSH.

For this purpose, we will use the OpenSSL library (and some associated tools) offering in depth support for
the configuration and analysis of SSL/TLS channels. Some of the exercises proposed use OpenSSL command
line programs that provide various cryptographic functions via a specific shell, which you can start with the
following command:

```
openssl command [commandopts ] [commandargs ]
```
In particular, the commandsclientimplements the functionality of an SSL/TLS client (man sclient). The
commandsserverimplements instead the functionality of a simple SSL/TLS server (man sserver).

To experiment SSH protocol we will use the OpenSSH command line client

### Additional software tools

The tools listed below will be used as well throughout this laboratory:

Wireshark- open source tool (having a user-friendly graphical interface) which allows to capture network
traffic. Available for Linux and Win32.
Home page =https://www.wireshark.org/

### Additional (useful) commands

Some exercises may require to exchange messages between two computers. Consequently, you will have to
start thesshserver:

```
systemctl start ssh
```
To copy a file (e.g.mytest) from thesshclient machine into therootdirectory on the machine runningssh
server, you can use the command:

```
scp mytest root@IPaddresssshserver:/root
```
Insert the password ‘toor’ when asked.

The exercise will require also to use the Apache web server. To start the Apache server use the command:

```
systemctl start apache
```
The exercise will require also to use an SMTP mail server. To start it use the command:

To start, stop and restart the mail server, use the command:

```
systemctl start exim
```
## TLS
To configure TLS server you need a suitable certificate and you need to be able to see what is going on on the network. 
```
The OpenSSL library implements a simple SSL/TLS client and server, which can be used for testing the
SSL/TLS protocol very easily.
To check the syntax of the related OpenSSL commands, we strongly suggest you to use the man pages,
by running:
```

```
man sclient
man sserver
```
The OpenSSL command used to start an SSL/TLS client program issclient, whose syntax is given
below:

```
openssl sclient [commandopts]
```
For simplicity, we have selected below (only) some possible options, check out the man pages for the
description of the other options as you will need them to perform the proposed exercise:

```
openssl sclient [-connecthost:port] [-state] [-showcert] [-CAfile filecert]
[-ciphercipherlist] [-reconnect]
```
where:

- -connecthost:portspecifies the host and optional port to connect to. If host and port are not
    specified then an attempt is made to connect to the local host on port 4433.
- -stateprints out the SSL session states.
- -showcertsdisplays the whole server certificate chain: normally only the server certificate itself
    is displayed.
- -CAfilefileindicates the file containing trusted certificates to use during server authentication
    and to use when attempting to build the client certificate chain.
- -ciphercipherlistallows to specify the cipher list sent by the client in the ClientHello message
    of the Handshake protocol. Although the server determines which cipher suite is used it should
    take the first supported cipher in the list sent by the client. See the OpenSSLcipherscommand
    for more information.
- -reconnectallows the client to reconnect to the same server 5 times using the same session ID.

The OpenSSL command used to start an SSL/TLS server program issserver, whose syntax is given
below:

```
openssl sserver [commandopts]
```
For simplicity, we have selected below (only) some possible options, check out the man pages for the
description of the other options as you will need them to perform the proposed exercise:

```
openssl sserver [-www] [-nodhe] [-keyserverpkey.pem] [-certservercert.pem]
[-CAfilefilecert] [-{vV}erifydepth] [-cipherciphersuitelist]
```
where:

- -wwwsends a status message back to the client when it connects. This includes lots of information
    about the ciphers used and various session parameters. The output is in HTML format so this
    option will normally be used with a web browser.
- -keyserverpkey.pemindicates thatserverpkey.pemcontains the private key of the server.
- -certservercert.pemindicates thatservercert.pemcontains the certificate of the server.
- -CAfilefileindicates the file containing trusted certificates to use during client authentication
    and to use when attempting to build the server certificate chain. The list is also used in the list of
    acceptable client CAs passed to the client when a certificate is requested.


- -verifydepth, -Verify depthindicates the verify depth to use. This specifies the maximum
    length of the client certificate chain and makes the server request a certificate from the client.
    With the -verify option a certificate is requested but the client does not have to send one, with the
    -Verify option the client must supply a certificate or an error occurs.
- -ciphercipherlist, this option allows modification of the cipher list used by the server. When
    the client sends a list of supported ciphers, the first client cipher also included in the server list
    is used. Because the client specifies the preference order, the order of the server cipherlist is
    irrelevant. See the OpenSSLcipherscommand for more information.

## 1 TLS

## 1.1 Setting up a TLS channel

Try to connect with your browser on your physical machine to an SSL/TLS server, for example https://mail.polito.it.

All information are available from chrome devTools: F12->Security

In the browser, click on the lock in the navigation bar and check out some details of the TLS connection youhave just established. Which TLS version was used in the TLS connection to the above server?
```
Connection - secure connection settings
The connection to this site is encrypted and authenticated using TLS 1.2.
```
Analyse the content of the X.509 certificate sent by the server: which fields are used for the identification of the server?
```

Issued to:
Subject:
CN (Common Name) = mail.polito.it
O (Organization) = Politecnico di Torino
L = Torino
C = IT
Certificate Subject Alternative Name:
Not Critical
DNS Name: mail.polito.it
```
Which is the certification path? (An ordered sequence of certificates, leading from a certificate whose public key is known by a client, to a certificate whose public key is to be validated by the client)
```
Builtin object token: DigiCert Assured ID Root CA -> TERENA SSL CA 3 -> mail.polito.it
```
Which algorithms have been negotiated and used for protecting the data transferred?
```
Protocol: TLS 1.2
Key exchange: ECDHE_RSA
Key exchange group: X25519
Cipher: AES_256_GCM
```
## 1.2 Configuration of a TLS server
Try now to configure a TLS server. What do you need in the first place?

Prerequisites. For this purpose, you need a certificate for the TLS server. We have issued a server certificate
by exploiting the demoCA in OpenSSL. The certificate contains the name “Server” in the field “Common
Name” (the other X.509 fields have been set to “IT” for “Country”, “Some-State” for “State” and “Polito” for
“Organization). The password used to protect the private key is: “ciao”.

In case you cannot access the material provided for this laboratory or if you simply want to recreate it on your
own, we remind you the OpenSSL commands that you can use to generate a certificate for the TLS server:

Alice=TLS client
Bob=TLS server and Certification Authority (we don't use Carol)
1.  create a test CA by exploiting OpenSSL:
```
(BOB) (even if it should be done by Carol)
root@kali:~/Desktop# /usr/lib/ssl/misc/CA.pl -newca
CA certificate filename (or enter to create)

Making CA certificate ...
====
openssl req  -new -keyout ./demoCA/private/cakey.pem -out ./demoCA/careq.pem 
Generating a RSA private key
..........+++++
............+++++
writing new private key to './demoCA/private/cakey.pem'
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:IT
State or Province Name (full name) [Some-State]:Some-State
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Polito
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:PolitoCA
Email Address []:

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:
==> 0
====
====
openssl ca  -create_serial -out ./demoCA/cacert.pem -days 1095 -batch -keyfile ./demoCA/private/cakey.pem -selfsign -extensions v3_ca  -infiles ./demoCA/careq.pem
Using configuration from /usr/lib/ssl/openssl.cnf
Enter pass phrase for ./demoCA/private/cakey.pem:
Check that the request matches the signature
Signature ok
Certificate Details:
        Serial Number:
            1a:6c:aa:a1:98:a3:a2:54:27:ba:ee:e1:ed:4e:0b:28:a0:0c:0a:ac
        Validity
            Not Before: Oct 20 16:54:38 2021 GMT
            Not After : Oct 19 16:54:38 2024 GMT
        Subject:
            countryName               = IT
            stateOrProvinceName       = Some-State
            organizationName          = Polito
            commonName                = PolitoCA
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                D1:3B:93:3A:14:66:E7:58:C8:90:6E:92:C0:CE:AF:14:2B:F2:BF:19
            X509v3 Authority Key Identifier: 
                keyid:D1:3B:93:3A:14:66:E7:58:C8:90:6E:92:C0:CE:AF:14:2B:F2:BF:19

            X509v3 Basic Constraints: critical
                CA:TRUE
Certificate is to be certified until Oct 19 16:54:38 2024 GMT (1095 days)

Write out database with 1 new entries
Data Base Updated
==> 0
====
CA certificate is in ./demoCA/cacert.pem
```
2.  create a certificate request for the TLS server: (according to the default policy for a Kali distribution, you can only create certificates with the same info as the CA)
```
(BOB)
root@kali:~/Desktop# openssl req -new -keyout server_pkey.pem -out servercreq.pem
Generating a RSA private key
....+++++
.................................+++++
writing new private key to 'server_pkey.pem'
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:IT
State or Province Name (full name) [Some-State]:Some-State
Locality Name (eg, city) []:  
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Polito
Organizational Unit Name (eg, section) []:PolitoServer
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:^C
root@kali:~/Desktop# openssl req -new -keyout server_pkey.pem -out servercreq.pem
Generating a RSA private key
.+++++
.............................+++++
writing new private key to 'server_pkey.pem'
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:IT
State or Province Name (full name) [Some-State]:Some-State
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Polito
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:PolitoServer
Email Address []:

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:
```
3.  issue the new certificate for the TLS server:
```
(BOB) (even if it should be done by Carol)
root@kali:~/Desktop# openssl ca -in servercreq.pem -out servercert.pem4
Using configuration from /usr/lib/ssl/openssl.cnf
Enter pass phrase for ./demoCA/private/cakey.pem:
Check that the request matches the signature
Signature ok
Certificate Details:
        Serial Number:
            1a:6c:aa:a1:98:a3:a2:54:27:ba:ee:e1:ed:4e:0b:28:a0:0c:0a:ad
        Validity
            Not Before: Oct 20 16:55:44 2021 GMT
            Not After : Oct 20 16:55:44 2022 GMT
        Subject:
            countryName               = IT
            stateOrProvinceName       = Some-State
            organizationName          = Polito
            commonName                = PolitoServer
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            Netscape Comment: 
                OpenSSL Generated Certificate
            X509v3 Subject Key Identifier: 
                D2:2C:31:E1:5B:03:8E:E3:97:BD:2C:39:36:C0:3E:D0:E0:6F:5A:82
            X509v3 Authority Key Identifier: 
                keyid:D1:3B:93:3A:14:66:E7:58:C8:90:6E:92:C0:CE:AF:14:2B:F2:BF:19

Certificate is to be certified until Oct 20 16:55:44 2022 GMT (365 days)
Sign the certificate? [y/n]:y


1 out of 1 certificate requests certified, commit? [y/n]y
Write out database with 1 new entries
Data Base Updated
```

### 1.2.1 Analysing the TLS 1.2 handshake messages

Start the OpenSSL server with the following command:

```
(BOB)
root@kali:~/Desktop# openssl s_server -www -key server_pkey.pem -cert server_cert.pem
Enter pass phrase for server_pkey.pem:
Using default temp DH parameters
ACCEPT

```
By default, this server listens on port 4433/tcp.

Try to connect with s_client and check out the result:
(we use the same cacert.pem file present on the demoCA, meaning that we add to the client the certification authority that the client already trust before the connection, so that the certificate provided by the server will be trusted by the client)
```
(ALICE)
root@kali:~/Desktop# openssl s_client -connect 10.0.2.10:4433 -state -showcerts -CAfile /media/sf_Kali_Shared/Cybersecurity_Labs/Lab1/cacert.pem -tls1_2
CONNECTED(00000003)
SSL_connect:before SSL initialization
SSL_connect:SSLv3/TLS write client hello

(If someone is already trying to connect to the server, it will hang here)

SSL_connect:SSLv3/TLS write client hello
Can't use SSL_get_servername
SSL_connect:SSLv3/TLS read server hello
depth=1 C = IT, ST = Some-State, O = Polito, CN = PolitoCA
verify return:1
depth=0 C = IT, ST = Some-State, O = Polito, CN = PolitoServer
verify return:1
SSL_connect:SSLv3/TLS read server certificate
SSL_connect:SSLv3/TLS read server key exchange
SSL_connect:SSLv3/TLS read server done
SSL_connect:SSLv3/TLS write client key exchange                                                                    
SSL_connect:SSLv3/TLS write change cipher spec                                                                     
SSL_connect:SSLv3/TLS write finished                                                                               
SSL_connect:SSLv3/TLS write finished                                                                               
SSL_connect:SSLv3/TLS read server session ticket                                                                   
SSL_connect:SSLv3/TLS read change cipher spec                                                                      
SSL_connect:SSLv3/TLS read finished                                                                                
---                                                                                                                
Certificate chain                                                                                                  
 0 s:C = IT, ST = Some-State, O = Polito, CN = PolitoServer                                                        
   i:C = IT, ST = Some-State, O = Polito, CN = PolitoCA                                                            
-----BEGIN CERTIFICATE-----                                                                                        
MIIDmTCCAoGgAwIBAgIUGmyqoZijolQnuu7h7U4LKKAMCq0wDQYJKoZIhvcNAQEL                                                   
BQAwRjELMAkGA1UEBhMCSVQxEzARBgNVBAgMClNvbWUtU3RhdGUxDzANBgNVBAoM
BlBvbGl0bzERMA8GA1UEAwwIUG9saXRvQ0EwHhcNMjExMDIwMTY1NTQ0WhcNMjIx
MDIwMTY1NTQ0WjBKMQswCQYDVQQGEwJJVDETMBEGA1UECAwKU29tZS1TdGF0ZTEP
MA0GA1UECgwGUG9saXRvMRUwEwYDVQQDDAxQb2xpdG9TZXJ2ZXIwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8mNMJHULbWctZzkeuXWw3d4XJT9KRul9i
ZuLRB+n3pT39IyS67VDkRkbvtlmExJAyRnPzQ3XGDxAQuoJ2KS0Xm1/WDpiGH/u1
thUrq+xUY/+xNRnZZyheUli/62I5EWojx7HrexxGLZ8ghRXoDXqeaB9Jmdy5SDb5
CSogPDXSeMvNzc4zXjlIvm7SzkdzTVc8gHKMU8Uu1+o3566lgFtELRC7ph80CEDz
iOWtCKr+e1Ruh+mP2QfltXa3ysPq4Av3KFXr3KbBh59bGoRhyqGG2MBr0FhPzgWy
uqsosReB8mNAsAQTcSNFFxXFhv+y6IkhAdwGTO+b8Jdm+WbJHjMLAgMBAAGjezB5
MAkGA1UdEwQCMAAwLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENl
cnRpZmljYXRlMB0GA1UdDgQWBBTSLDHhWwOO45e9LDk2wD7Q4G9agjAfBgNVHSME
GDAWgBTRO5M6FGbnWMiQbpLAzq8UK/K/GTANBgkqhkiG9w0BAQsFAAOCAQEAPWgW
oHw+0OPQCzYRwFTCgQj/FYWdIfDkevduVUp1LQ0hEOGuJwOcTqV0XLSrI31QPFtP
TAbqCbsaevdEmnOLsBJSeKXdMwYd7OC6jK3jG+6rYp92k3dDpRBoLvceHvjhHqTg
exETkrtb8DeBDe5cIxyn1S2/qPY2+BIhy7cfrHhyv3mghbBK92fwvGbPyKX7TK7x
OTSnC7Z01X8Ouayu3njOMkAsps7eKQCl6CbyJK+mZ7tV3PW/msGqOap4g2D5TZ7t
hCchjuBgVHK85G7ZH8N4qDe1kS6YeY80bYB1mwWyTyLOcRfIP+xzRKx3z5XKZsoc
0h7mQPWE3MqDa8JRDQ==
-----END CERTIFICATE-----
---
Server certificate
subject=C = IT, ST = Some-State, O = Polito, CN = PolitoServer

issuer=C = IT, ST = Some-State, O = Polito, CN = PolitoCA

---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: RSA-PSS
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 1550 bytes and written 281 bytes
Verification: OK
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 394D8452F6F587E1BEAB9749687BEB4A17C9E8F2E3BEA3E5EE2FB692C03E56F2
    Session-ID-ctx: 
    Master-Key: 0085640582B99AEE922568FB099D174C97766E8D80B154EAA66874B067A56D073787C8F4BA53E4D6C00C39FE6608E94E
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - d0 c4 48 43 ca e0 8a ee-47 c3 0f d2 e4 fc 48 2c   ..HC....G.....H,
    0010 - ef 3e 82 9e 14 53 c5 fa-22 3f c7 e6 ae ad a6 45   .>...S.."?.....E
    0020 - ae 7c 3a 70 46 b4 ab db-ec 67 e8 5b 6b 48 bb 29   .|:pF....g.[kH.)
    0030 - 03 60 c4 e2 c6 79 e4 a9-f5 17 c4 3b 65 29 d1 57   .`...y.....;e).W
    0040 - 78 32 46 03 df e1 ce 3c-e1 ab a2 7f 69 73 87 3a   x2F....<....is.:
    0050 - 31 76 a0 c8 b2 cd 66 31-7c f8 8d ac 28 a4 6a 79   1v....f1|...(.jy
    0060 - c3 e0 6e e3 e0 9a 7a a8-11 64 0b 63 85 48 4a 8f   ..n...z..d.c.HJ.
    0070 - f9 b4 f3 d0 12 bb 03 4d-e3 c3 bc f0 fc 66 4d 74   .......M.....fMt
    0080 - d4 41 fa 41 57 9f ea 1c-f5 d1 63 a8 91 16 ff 95   .A.AW.....c.....
    0090 - e2 1d 93 d6 53 d5 f7 d1-ce c4 1f d6 2c 8e 6a df   ....S.......,.j.

    Start Time: 1634750987
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: yes
---

```

In a separate window, open a terminal (emulator) and start Wireshark:

```
wireshark
```
Select “eth0” and “Loopback:lo” and then click on the blue symbol (placed in the up, left position, under “File”)
corresponding to “Start capturing packets”.

Run thesclientwith the command above and intercept the TLS handshake communication messages ex-
changed between thesclientand thesserver. You should be able to view the captured messages exchanged
between the client and the server in a dedicated window in Wireshark.

[Captured packets](/home/bexul/Desktop/Kali_Shared/Cybersecurity_Labs/Lab1/TLS1_2.pcapng)

Now respond at the following questions:

How many RTTs do you see? Write them down in the following box:

```
→ 2 RTT (C-S):
(1. TCP SYN - TCP ACK)
2. TCP ACK+Client Hello - TCP ACK+Server Hello, Certificate, Server Key Exchange, Server Hello Done
3. TCP ACK+Client Key Exchange, Change Cipher Spec, Encrypted Handshake Message - TCP ACK + New Session Ticket, Change Cipher Spec, Encrypted Handshake Message

Now connection is established and the client can start sending Application Data

The destruction of the connection takes 2 RTTs, as for any TCP protocol:
1. TCP FIN ACK - TCP FIN ACK
2. TCP ACK

```
Which TLS handshake messages are exchanged? Write them down in the following box:

```
→ See above
```
Which ciphersuite has been negotiated?

```
→ The negotiated cipher suite is the one chosen by the server. It is contained in the Server Hello Cipher Suite field: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)
```
Does it provide forward secrecy (if yes, explain briefly why in the following box)?

```
→ Yes because it is ephemeral, so, assumed the server set a brief lifetime for the encryption keys exchanged using the ECDHE, those and only those can be used to decrypt the messages. So if in the future the long term private key of the server contained in the PKC is leaked, only the authentication is compromised, but not the integrity of the old messages.
```
What do you see in the “Extensions” of the Client Hello message?

```
→
- ec_point_formats
- supported_groups
- session_ticket(empty) :The client indicates that it supports this mechanism by including a SessionTicket TLS extension in the ClientHello message.The extension will be empty if the client does not already possess a ticket for the server. The server sends an empty SessionTicket extension to indicate that it will send a new session ticket using the NewSessionTicket handshake message. (https://datatracker.ietf.org/doc/html/rfc5077)
- encrypt_then_mac(empty)
- extended_master_secret(empty)
- signature_algorithms
```
What is the purpose of the “New Session Ticket”?

```
→ It contains the session ticket, its length and a lifetime hint for the client, stating how long that ID will last (2 hours). Within this document, the term 'ticket' refers to a cryptographically protected data structure that is created and consumed by the server to rebuild session-specific state.
  This mechanism is useful in the following situations:
   1.  servers that handle a large number of transactions from different users
   2.  servers that desire to cache sessions for a long time
   3.  ability to load balance requests across servers
   4.  embedded servers with little memory
The main improvement is to avoid the need to maintain a server-side session cache since the whole session state is remembered by the client, not the server. A session cache can be costly in terms of memory, and can be difficult to share between multiple hosts when requests are load-balanced across servers.
```

What is the “Encrypted Handshake Message” and which is its purpose?

```
→ The Encrypted Handshake (EH) extension allows endpoints to perform a key exchange and begin record layer encryption as early in the handshake as possible. Two levels of protection provide flexibility for the client and server (and the implementation) to manage practical considerations and level of effort.

While in general it is not possible to protect pre-authentication data from an active man-in-the-middle type attacker, this extension hides the bulk of the handshake data from a passive observer and can detect active attacks as a failed handshake.

Level one provides encryption with forward secrecy for all data in the Server Hello message (including Server Hello extensions) and all data following. This level incurs no additional computational or round-trip overhead over the traditional handshake and is intended to require minimal changes to the implementation of existing libraries, but it has the limitation that data sent by the client in the Client Hello continues to be sent in the clear.

The second level of implementation encrypts all the same handshake data as the first and additionally encrypts the most interesting parts of the Client Hello (e.g. the extensions), but it requires an additional round trip to the server.
```
1.2.2 Session resumption

Resumption refers to starting a new connection based on the session details from a previous connection.

Which techniques are used for session resumption in TLS and which is the difference among them?

```
→ Session-IDs, Session tickets, Pre Shared Keys.
Session IDs use the session ID stored in the server cache, which could become huge.
Session tickets allow the server to send the session data encrypted with a server secret key, different from the one used to protect the TLS channel, to the client, so that the client keeps the session cache of its sessions. It requires key sharing and update among the various end points in distributed environment.
Pre Shared Keys are computed, shared and stored by client and
```
Execute the followings client command, which opens up several consecutive connections by exploiting the session resumption:
[capture reconnect](/mnt/26158F5879578F52/Università/Magistrale/Cybersecurity/Labs/CYB_lab01/TLS1_3_reconnect.pcapng)
```
(ALICE)
openssl s_client -connect 10.0.2.10:4433 -state -CAfile /media/sf_Kali_Shared/Cybersecurity_Labs/CYB_lab01/cacert.pem -reconnect

CONNECTED(00000003)
SSL_connect:before SSL initialization
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS read server hello
Can't use SSL_get_servername
SSL_connect:TLSv1.3 read encrypted extensions
depth=1 C = IT, ST = Some-State, O = Polito, CN = PolitoCA
verify return:1
depth=0 C = IT, ST = Some-State, O = Polito, CN = PolitoServer
verify return:1
SSL_connect:SSLv3/TLS read server certificate
SSL_connect:TLSv1.3 read server certificate verify
SSL_connect:SSLv3/TLS read finished
SSL_connect:SSLv3/TLS write change cipher spec
SSL_connect:SSLv3/TLS write finished
---
Certificate chain
 0 s:C = IT, ST = Some-State, O = Polito, CN = PolitoServer
   i:C = IT, ST = Some-State, O = Polito, CN = PolitoCA                                                                                                                                                                                    
---                                                                                                                                                                                                                                        
Server certificate                                                                                                                                                                                                                         
-----BEGIN CERTIFICATE-----                                                                                                                                                                                                                
MIIDmTCCAoGgAwIBAgIUGmyqoZijolQnuu7h7U4LKKAMCq0wDQYJKoZIhvcNAQEL                                                                                                                                                                           
BQAwRjELMAkGA1UEBhMCSVQxEzARBgNVBAgMClNvbWUtU3RhdGUxDzANBgNVBAoM                                                                                                                                                                           
BlBvbGl0bzERMA8GA1UEAwwIUG9saXRvQ0EwHhcNMjExMDIwMTY1NTQ0WhcNMjIx                                                                                                                                                                           
MDIwMTY1NTQ0WjBKMQswCQYDVQQGEwJJVDETMBEGA1UECAwKU29tZS1TdGF0ZTEP                                                                                                                                                                           
MA0GA1UECgwGUG9saXRvMRUwEwYDVQQDDAxQb2xpdG9TZXJ2ZXIwggEiMA0GCSqG                                                                                                                                                                           
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8mNMJHULbWctZzkeuXWw3d4XJT9KRul9i                                                                                                                                                                           
ZuLRB+n3pT39IyS67VDkRkbvtlmExJAyRnPzQ3XGDxAQuoJ2KS0Xm1/WDpiGH/u1                                                                                                                                                                           
thUrq+xUY/+xNRnZZyheUli/62I5EWojx7HrexxGLZ8ghRXoDXqeaB9Jmdy5SDb5                                                                                                                                                                           
CSogPDXSeMvNzc4zXjlIvm7SzkdzTVc8gHKMU8Uu1+o3566lgFtELRC7ph80CEDz                                                                                                                                                                           
iOWtCKr+e1Ruh+mP2QfltXa3ysPq4Av3KFXr3KbBh59bGoRhyqGG2MBr0FhPzgWy
uqsosReB8mNAsAQTcSNFFxXFhv+y6IkhAdwGTO+b8Jdm+WbJHjMLAgMBAAGjezB5
MAkGA1UdEwQCMAAwLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENl
cnRpZmljYXRlMB0GA1UdDgQWBBTSLDHhWwOO45e9LDk2wD7Q4G9agjAfBgNVHSME
GDAWgBTRO5M6FGbnWMiQbpLAzq8UK/K/GTANBgkqhkiG9w0BAQsFAAOCAQEAPWgW
oHw+0OPQCzYRwFTCgQj/FYWdIfDkevduVUp1LQ0hEOGuJwOcTqV0XLSrI31QPFtP
TAbqCbsaevdEmnOLsBJSeKXdMwYd7OC6jK3jG+6rYp92k3dDpRBoLvceHvjhHqTg
exETkrtb8DeBDe5cIxyn1S2/qPY2+BIhy7cfrHhyv3mghbBK92fwvGbPyKX7TK7x
OTSnC7Z01X8Ouayu3njOMkAsps7eKQCl6CbyJK+mZ7tV3PW/msGqOap4g2D5TZ7t
hCchjuBgVHK85G7ZH8N4qDe1kS6YeY80bYB1mwWyTyLOcRfIP+xzRKx3z5XKZsoc
0h7mQPWE3MqDa8JRDQ==
-----END CERTIFICATE-----
subject=C = IT, ST = Some-State, O = Polito, CN = PolitoServer

issuer=C = IT, ST = Some-State, O = Polito, CN = PolitoCA

---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: RSA-PSS
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 1481 bytes and written 363 bytes
Verification: OK
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Server public key is 2048 bit
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---
drop connection and then reconnect
SSL3 alert write:warning:close notify
CONNECTED(00000003)
SSL_connect:before SSL initialization
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS read server hello
Can't use SSL_get_servername
SSL_connect:TLSv1.3 read encrypted extensions
depth=1 C = IT, ST = Some-State, O = Polito, CN = PolitoCA
verify return:1
depth=0 C = IT, ST = Some-State, O = Polito, CN = PolitoServer
verify return:1
SSL_connect:SSLv3/TLS read server certificate
SSL_connect:TLSv1.3 read server certificate verify
SSL_connect:SSLv3/TLS read finished
SSL_connect:SSLv3/TLS write change cipher spec
SSL_connect:SSLv3/TLS write finished
Verification: OK
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---
drop connection and then reconnect
SSL3 alert write:warning:close notify
CONNECTED(00000003)
SSL_connect:before SSL initialization
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS read server hello
Can't use SSL_get_servername
SSL_connect:TLSv1.3 read encrypted extensions
depth=1 C = IT, ST = Some-State, O = Polito, CN = PolitoCA
verify return:1
depth=0 C = IT, ST = Some-State, O = Polito, CN = PolitoServer
verify return:1
SSL_connect:SSLv3/TLS read server certificate
SSL_connect:TLSv1.3 read server certificate verify
SSL_connect:SSLv3/TLS read finished
SSL_connect:SSLv3/TLS write change cipher spec
SSL_connect:SSLv3/TLS write finished
Verification: OK
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---
drop connection and then reconnect
SSL3 alert write:warning:close notify
CONNECTED(00000003)
SSL_connect:before SSL initialization
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS read server hello
Can't use SSL_get_servername
SSL_connect:TLSv1.3 read encrypted extensions
depth=1 C = IT, ST = Some-State, O = Polito, CN = PolitoCA
verify return:1
depth=0 C = IT, ST = Some-State, O = Polito, CN = PolitoServer
verify return:1
SSL_connect:SSLv3/TLS read server certificate
SSL_connect:TLSv1.3 read server certificate verify
SSL_connect:SSLv3/TLS read finished
SSL_connect:SSLv3/TLS write change cipher spec
SSL_connect:SSLv3/TLS write finished
Verification: OK
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---
drop connection and then reconnect
SSL3 alert write:warning:close notify
CONNECTED(00000003)
SSL_connect:before SSL initialization
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS read server hello
Can't use SSL_get_servername
SSL_connect:TLSv1.3 read encrypted extensions
depth=1 C = IT, ST = Some-State, O = Polito, CN = PolitoCA
verify return:1
depth=0 C = IT, ST = Some-State, O = Polito, CN = PolitoServer
verify return:1
SSL_connect:SSLv3/TLS read server certificate
SSL_connect:TLSv1.3 read server certificate verify
SSL_connect:SSLv3/TLS read finished
SSL_connect:SSLv3/TLS write change cipher spec
SSL_connect:SSLv3/TLS write finished
Verification: OK
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---
drop connection and then reconnect
SSL3 alert write:warning:close notify
CONNECTED(00000003)
SSL_connect:before SSL initialization
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS read server hello
Can't use SSL_get_servername
SSL_connect:TLSv1.3 read encrypted extensions
depth=1 C = IT, ST = Some-State, O = Polito, CN = PolitoCA
verify return:1
depth=0 C = IT, ST = Some-State, O = Polito, CN = PolitoServer
verify return:1
SSL_connect:SSLv3/TLS read server certificate
SSL_connect:TLSv1.3 read server certificate verify
SSL_connect:SSLv3/TLS read finished
SSL_connect:SSLv3/TLS write change cipher spec
SSL_connect:SSLv3/TLS write finished
Verification: OK
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 50F17CECC2AEB8EDB5DAA44AF14380D443612C16403ECDEA2354AFC51A809E30
    Session-ID-ctx: 
    Resumption PSK: F91CC750743E4170F2E7CB8B2B9C2AF403405BBDD1379DF78C6D5E069B0512FABD3060DCDCC59C01B98CFA38C5525EE9
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 84 03 eb 3c a1 1e 0b 96-bf 8a 09 25 cd d9 31 10   ...<.......%..1.
    0010 - 2c 8b 00 fc 26 fe 4a b1-51 ab cb 2d 2c 10 90 31   ,...&.J.Q..-,..1
    0020 - a5 27 5b 53 40 69 22 32-24 f6 1f a7 36 1a 3c cd   .'[S@i"2$...6.<.
    0030 - 23 30 34 3f 9d fd 9d 2b-71 54 6b 99 b9 02 b0 f9   #04?...+qTk.....
    0040 - 82 05 4f 3e 82 a5 60 ce-9b 4a d7 7a e8 4f 93 60   ..O>..`..J.z.O.`
    0050 - 52 bd f0 69 35 80 27 bc-a4 43 d1 03 0c 78 0a 1a   R..i5.'..C...x..
    0060 - 81 5c b1 1a 47 65 bb 03-9c f1 37 43 22 ea 95 83   .\..Ge....7C"...
    0070 - d8 a7 a7 78 34 d1 12 df-78 9f 2c 63 fd 0f 53 a0   ...x4...x.,c..S.
    0080 - 14 ae 7f 61 dc 1f be 22-b5 14 a9 8c 69 a6 cf 35   ...a..."....i..5
    0090 - c3 85 36 6d 3b b4 a4 72-99 af e2 ac b1 4a b0 b0   ..6m;..r.....J..
    00a0 - 37 a3 6b 45 da 08 fa b8-f1 d3 02 65 b7 e8 18 3c   7.kE.......e...<
    00b0 - 11 dc b3 db d2 93 84 09-56 73 94 c6 4d cc a8 4d   ........Vs..M..M
    00c0 - 8c ff 37 10 98 2e 52 0c-63 d0 41 d4 ab a8 3e 73   ..7...R.c.A...>s

    Start Time: 1635604726
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: C57A5BB1CC0F90797B6D3238BED4D851A4EC2E6AA89833D08B1C504B500A10E7
    Session-ID-ctx: 
    Resumption PSK: 36874C711DFBBE0CC171C6ECA9A4473C6F7BDE8927335B0232A2AC843C113191FF83B8974F3367BFBFBCC21B3C8A38C2
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 84 03 eb 3c a1 1e 0b 96-bf 8a 09 25 cd d9 31 10   ...<.......%..1.
    0010 - ab ba 4b 0b 73 3f f8 a5-da e7 b2 16 4c 2c 3c cf   ..K.s?......L,<.
    0020 - b7 78 0a 34 3c 34 10 d6-03 25 03 b0 0c a8 6d d2   .x.4<4...%....m.
    0030 - 2d 78 c1 12 0b 5c 8b 14-cc 2c 33 3f 30 47 71 cc   -x...\...,3?0Gq.
    0040 - ca 78 cd be 02 04 a2 bd-8a bd 49 02 cb 18 04 5e   .x........I....^
    0050 - 79 1c 9a 63 8b dd 45 59-c8 ab 52 5a ff 1c 04 d6   y..c..EY..RZ....
    0060 - 30 a7 a1 66 43 19 01 02-97 bc b2 0d 08 18 36 d4   0..fC.........6.
    0070 - c0 70 ec 0e 1b ab ae bc-ab 9c 11 0b f4 ae 75 1e   .p............u.
    0080 - b1 b7 ef 60 5d 25 0e 8e-18 03 e7 91 89 2b 0c 78   ...`]%.......+.x
    0090 - 4a 15 fb 30 1c 9d 59 47-31 4b dc 3b f2 d3 70 9b   J..0..YG1K.;..p.
    00a0 - 2a 62 6e 76 2d c3 29 e5-f8 69 67 2f 2b 6c 9a a7   *bnv-.)..ig/+l..
    00b0 - d8 98 0f b3 df 52 2b a9-66 f5 70 f0 cd 98 15 0a   .....R+.f.p.....
    00c0 - e3 c7 46 69 ba 01 c9 69-23 95 94 59 9d 2c ae 1a   ..Fi...i#..Y.,..

    Start Time: 1635604726
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK

```
In this mode, s_client will connect to the target server six times; it will create a new session on the first connection, then try to reuse the same session in the subsequent five connections.

Which parameters of the TLS session remain unchanged in successive connections and which ones change
instead? (verify)

```
→
colordiff ClientHello1.txt ClientHello2.txt
10c10
<             Client Random: 4d09c6d8b112d1b937be6f7e398206670c8650cfc8ff8fd9…
---
>             Client Random: 7a65fb265a53620b197868b1bf3cc3378740fcddccbe4f2f…
12c12
<             Session ID: d6037db93ec3ca1523921066cf144282f13a3a6ff38b3851…
---
>             Session ID: 8c02a9ae78f75805d64b1592e9b23b2b01f8e61d2d86b473…
162c162
<             Extension: key share: Key Exchange: 23dd0cc3af18f27da846fae7fea56180d0501e7f7b056bc8…
---
>             Extension: key share: Key Exchange: 32706432d1d7c1fd1e10b79ec4899483095f1258cc7b7f5f…

colordiff ServerHello1.txt ServerHello2.txt 
9c9
<         Server Random: 55c1275e8d28989914737a647938ee654f34b116956c657c…
---
>         Server Random: b70a8ffdd9bd8d238ba9748df6e9530d21e60088c4e01055…
11c11
<         Session ID: d6037db93ec3ca1523921066cf144282f13a3a6ff38b3851…
---
>         Session ID: 8c02a9ae78f75805d64b1592e9b23b2b01f8e61d2d86b473…
26c26
<         Extension: key share: Key Exchange: 7157da2a59321f39418b7928ebad6a32c57e9bbfb227d4d9…
---
>         Extension: key share: Key Exchange: 6c6d96869cf1e3dace8210dabe38bf9b438536eebd111086…
```
Now, stop the server and re-start it with the following command:
```
openssl s_server -www -key server_pkey.pem -cert server_cert.pem -no_ticket -no_cache
```
Execute again the followings client command, which opens up several consecutive connections by exploiting the session resumption:
```
(ALICE)
root@kali:~# openssl s_client -connect 10.0.2.10:4433 -state -CAfile /media/sf_Kali_Shared/Cybersecurity_Labs/CYB_lab01/cacert.pem -reconnect -tls1_2
CONNECTED(00000003)
SSL_connect:before SSL initialization
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS write client hello
Can't use SSL_get_servername
SSL_connect:SSLv3/TLS read server hello
depth=1 C = IT, ST = Some-State, O = Polito, CN = PolitoCA
verify return:1
depth=0 C = IT, ST = Some-State, O = Polito, CN = PolitoServer
verify return:1
SSL_connect:SSLv3/TLS read server certificate
SSL_connect:SSLv3/TLS read server key exchange
SSL_connect:SSLv3/TLS read server done
SSL_connect:SSLv3/TLS write client key exchange
SSL_connect:SSLv3/TLS write change cipher spec
SSL_connect:SSLv3/TLS write finished
SSL_connect:SSLv3/TLS write finished
SSL_connect:SSLv3/TLS read change cipher spec
SSL_connect:SSLv3/TLS read finished
---
Certificate chain
 0 s:C = IT, ST = Some-State, O = Polito, CN = PolitoServer
   i:C = IT, ST = Some-State, O = Polito, CN = PolitoCA
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIDmTCCAoGgAwIBAgIUGmyqoZijolQnuu7h7U4LKKAMCq0wDQYJKoZIhvcNAQEL
BQAwRjELMAkGA1UEBhMCSVQxEzARBgNVBAgMClNvbWUtU3RhdGUxDzANBgNVBAoM
BlBvbGl0bzERMA8GA1UEAwwIUG9saXRvQ0EwHhcNMjExMDIwMTY1NTQ0WhcNMjIx
MDIwMTY1NTQ0WjBKMQswCQYDVQQGEwJJVDETMBEGA1UECAwKU29tZS1TdGF0ZTEP
MA0GA1UECgwGUG9saXRvMRUwEwYDVQQDDAxQb2xpdG9TZXJ2ZXIwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8mNMJHULbWctZzkeuXWw3d4XJT9KRul9i
ZuLRB+n3pT39IyS67VDkRkbvtlmExJAyRnPzQ3XGDxAQuoJ2KS0Xm1/WDpiGH/u1
thUrq+xUY/+xNRnZZyheUli/62I5EWojx7HrexxGLZ8ghRXoDXqeaB9Jmdy5SDb5
CSogPDXSeMvNzc4zXjlIvm7SzkdzTVc8gHKMU8Uu1+o3566lgFtELRC7ph80CEDz
iOWtCKr+e1Ruh+mP2QfltXa3ysPq4Av3KFXr3KbBh59bGoRhyqGG2MBr0FhPzgWy
uqsosReB8mNAsAQTcSNFFxXFhv+y6IkhAdwGTO+b8Jdm+WbJHjMLAgMBAAGjezB5
MAkGA1UdEwQCMAAwLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENl
cnRpZmljYXRlMB0GA1UdDgQWBBTSLDHhWwOO45e9LDk2wD7Q4G9agjAfBgNVHSME                                                   
GDAWgBTRO5M6FGbnWMiQbpLAzq8UK/K/GTANBgkqhkiG9w0BAQsFAAOCAQEAPWgW                                                   
oHw+0OPQCzYRwFTCgQj/FYWdIfDkevduVUp1LQ0hEOGuJwOcTqV0XLSrI31QPFtP                                                   
TAbqCbsaevdEmnOLsBJSeKXdMwYd7OC6jK3jG+6rYp92k3dDpRBoLvceHvjhHqTg                                                   
exETkrtb8DeBDe5cIxyn1S2/qPY2+BIhy7cfrHhyv3mghbBK92fwvGbPyKX7TK7x                                                   
OTSnC7Z01X8Ouayu3njOMkAsps7eKQCl6CbyJK+mZ7tV3PW/msGqOap4g2D5TZ7t                                                   
hCchjuBgVHK85G7ZH8N4qDe1kS6YeY80bYB1mwWyTyLOcRfIP+xzRKx3z5XKZsoc                                                   
0h7mQPWE3MqDa8JRDQ==                                                                                               
-----END CERTIFICATE-----                                                                                          
subject=C = IT, ST = Some-State, O = Polito, CN = PolitoServer                                                     
                                                                                                                   
issuer=C = IT, ST = Some-State, O = Polito, CN = PolitoCA                                                          
                                                                                                                   
---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: RSA-PSS
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 1371 bytes and written 281 bytes
Verification: OK
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 
    Session-ID-ctx: 
    Master-Key: 778F178727C220540AD2C299E8DA8BD9A6C2504EC80CEE3A95AE82B5605BA30F72A1532B169582BDC51DF598B1D04621
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    Start Time: 1635606822
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: yes
---
drop connection and then reconnect
SSL3 alert write:warning:close notify
CONNECTED(00000003)
SSL_connect:before SSL initialization
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS write client hello
Can't use SSL_get_servername
SSL_connect:SSLv3/TLS read server hello
depth=1 C = IT, ST = Some-State, O = Polito, CN = PolitoCA
verify return:1
depth=0 C = IT, ST = Some-State, O = Polito, CN = PolitoServer
verify return:1
SSL_connect:SSLv3/TLS read server certificate
SSL_connect:SSLv3/TLS read server key exchange
SSL_connect:SSLv3/TLS read server done
SSL_connect:SSLv3/TLS write client key exchange
SSL_connect:SSLv3/TLS write change cipher spec
SSL_connect:SSLv3/TLS write finished
SSL_connect:SSLv3/TLS write finished
SSL_connect:SSLv3/TLS read change cipher spec
SSL_connect:SSLv3/TLS read finished
Verification: OK
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 
    Session-ID-ctx: 
    Master-Key: 7D0C44C003615CE8E84C0720AF7BEB2956C6E06182FD06E839E853CFDFF7BFB4D8A6085F905775F8F3CAB8B20F5720EF
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    Start Time: 1635606822
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: yes
---
drop connection and then reconnect
SSL3 alert write:warning:close notify
CONNECTED(00000003)
SSL_connect:before SSL initialization
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS write client hello
Can't use SSL_get_servername
SSL_connect:SSLv3/TLS read server hello
depth=1 C = IT, ST = Some-State, O = Polito, CN = PolitoCA
verify return:1
depth=0 C = IT, ST = Some-State, O = Polito, CN = PolitoServer
verify return:1
SSL_connect:SSLv3/TLS read server certificate
SSL_connect:SSLv3/TLS read server key exchange
SSL_connect:SSLv3/TLS read server done
SSL_connect:SSLv3/TLS write client key exchange
SSL_connect:SSLv3/TLS write change cipher spec
SSL_connect:SSLv3/TLS write finished
SSL_connect:SSLv3/TLS write finished
SSL_connect:SSLv3/TLS read change cipher spec
SSL_connect:SSLv3/TLS read finished
Verification: OK
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 
    Session-ID-ctx: 
    Master-Key: 231BE5232F362BC739DF885C36487EA80FC9103F30D8B425C8F4053AFF58388E5F9AF3DD472186E7C7C32CE580EFD494
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    Start Time: 1635606822
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: yes
---
drop connection and then reconnect
SSL3 alert write:warning:close notify
CONNECTED(00000003)
SSL_connect:before SSL initialization
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS write client hello
Can't use SSL_get_servername
SSL_connect:SSLv3/TLS read server hello
depth=1 C = IT, ST = Some-State, O = Polito, CN = PolitoCA
verify return:1
depth=0 C = IT, ST = Some-State, O = Polito, CN = PolitoServer
verify return:1
SSL_connect:SSLv3/TLS read server certificate
SSL_connect:SSLv3/TLS read server key exchange
SSL_connect:SSLv3/TLS read server done
SSL_connect:SSLv3/TLS write client key exchange
SSL_connect:SSLv3/TLS write change cipher spec
SSL_connect:SSLv3/TLS write finished
SSL_connect:SSLv3/TLS write finished
SSL_connect:SSLv3/TLS read change cipher spec
SSL_connect:SSLv3/TLS read finished
Verification: OK
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 
    Session-ID-ctx: 
    Master-Key: 7FD37BE7D2BF099A0A0B751CEF420D3B0608E6281A91642C9FE0372C81368D6DB53A0BC7335645B72BE7B5038DE8D631
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    Start Time: 1635606822
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: yes
---
drop connection and then reconnect
SSL3 alert write:warning:close notify
CONNECTED(00000003)
SSL_connect:before SSL initialization
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS write client hello
Can't use SSL_get_servername
SSL_connect:SSLv3/TLS read server hello
depth=1 C = IT, ST = Some-State, O = Polito, CN = PolitoCA
verify return:1
depth=0 C = IT, ST = Some-State, O = Polito, CN = PolitoServer
verify return:1
SSL_connect:SSLv3/TLS read server certificate
SSL_connect:SSLv3/TLS read server key exchange
SSL_connect:SSLv3/TLS read server done
SSL_connect:SSLv3/TLS write client key exchange
SSL_connect:SSLv3/TLS write change cipher spec
SSL_connect:SSLv3/TLS write finished
SSL_connect:SSLv3/TLS write finished
SSL_connect:SSLv3/TLS read change cipher spec
SSL_connect:SSLv3/TLS read finished
Verification: OK
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 
    Session-ID-ctx: 
    Master-Key: 381C44697594E9AC43E50E6CF68DB142A278F32EAA2F784392D707D218FC92390045476CECC0354EDCB983C37FC1357D
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    Start Time: 1635606822
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: yes
---
drop connection and then reconnect
SSL3 alert write:warning:close notify
CONNECTED(00000003)
SSL_connect:before SSL initialization
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS write client hello
Can't use SSL_get_servername
SSL_connect:SSLv3/TLS read server hello
depth=1 C = IT, ST = Some-State, O = Polito, CN = PolitoCA
verify return:1
depth=0 C = IT, ST = Some-State, O = Polito, CN = PolitoServer
verify return:1
SSL_connect:SSLv3/TLS read server certificate
SSL_connect:SSLv3/TLS read server key exchange
SSL_connect:SSLv3/TLS read server done
SSL_connect:SSLv3/TLS write client key exchange
SSL_connect:SSLv3/TLS write change cipher spec
SSL_connect:SSLv3/TLS write finished
SSL_connect:SSLv3/TLS write finished
SSL_connect:SSLv3/TLS read change cipher spec
SSL_connect:SSLv3/TLS read finished
Verification: OK
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 
    Session-ID-ctx: 
    Master-Key: 74281185217AF34F00F98AE77C77DE3124C1329077C85146408BA60F15459C4DE2A744CA3284D1294F72B82CD8A320FD
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    Start Time: 1635606822
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: yes
---

```
Check out again the output on the s_client. What do you notice?

```
→ colordiff ClientReconnect1.txt ClientReconnect2.txt
< Secure Renegotiation IS NOT supported
---
> Secure Renegotiation IS supported
```
1.2.3 Analysing the TLS 1.3 handshake messages

Now, stop the server and re-start it with the following command:


```
openssl s_server -www -key server_pkey.pem -cert server_cert.pem -tls1_3
```
Try to connect with s_client and check out the result:

```
root@kali:~# openssl s_client -connect 10.0.2.10:4433 -state -showcerts -CAfile /media/sf_Kali_Shared/Cybersecurity_Labs/CYB_lab01/cacert.pem -tls1_3
CONNECTED(00000003)
SSL_connect:before SSL initialization
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS read server hello
Can't use SSL_get_servername
SSL_connect:TLSv1.3 read encrypted extensions
depth=1 C = IT, ST = Some-State, O = Polito, CN = PolitoCA
verify return:1
depth=0 C = IT, ST = Some-State, O = Polito, CN = PolitoServer
verify return:1
SSL_connect:SSLv3/TLS read server certificate
SSL_connect:TLSv1.3 read server certificate verify
SSL_connect:SSLv3/TLS read finished
SSL_connect:SSLv3/TLS write change cipher spec
SSL_connect:SSLv3/TLS write finished
---
Certificate chain
 0 s:C = IT, ST = Some-State, O = Polito, CN = PolitoServer
   i:C = IT, ST = Some-State, O = Polito, CN = PolitoCA
-----BEGIN CERTIFICATE-----
MIIDmTCCAoGgAwIBAgIUGmyqoZijolQnuu7h7U4LKKAMCq0wDQYJKoZIhvcNAQEL
BQAwRjELMAkGA1UEBhMCSVQxEzARBgNVBAgMClNvbWUtU3RhdGUxDzANBgNVBAoM
BlBvbGl0bzERMA8GA1UEAwwIUG9saXRvQ0EwHhcNMjExMDIwMTY1NTQ0WhcNMjIx
MDIwMTY1NTQ0WjBKMQswCQYDVQQGEwJJVDETMBEGA1UECAwKU29tZS1TdGF0ZTEP
MA0GA1UECgwGUG9saXRvMRUwEwYDVQQDDAxQb2xpdG9TZXJ2ZXIwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8mNMJHULbWctZzkeuXWw3d4XJT9KRul9i
ZuLRB+n3pT39IyS67VDkRkbvtlmExJAyRnPzQ3XGDxAQuoJ2KS0Xm1/WDpiGH/u1
thUrq+xUY/+xNRnZZyheUli/62I5EWojx7HrexxGLZ8ghRXoDXqeaB9Jmdy5SDb5
CSogPDXSeMvNzc4zXjlIvm7SzkdzTVc8gHKMU8Uu1+o3566lgFtELRC7ph80CEDz
iOWtCKr+e1Ruh+mP2QfltXa3ysPq4Av3KFXr3KbBh59bGoRhyqGG2MBr0FhPzgWy
uqsosReB8mNAsAQTcSNFFxXFhv+y6IkhAdwGTO+b8Jdm+WbJHjMLAgMBAAGjezB5
MAkGA1UdEwQCMAAwLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENl
cnRpZmljYXRlMB0GA1UdDgQWBBTSLDHhWwOO45e9LDk2wD7Q4G9agjAfBgNVHSME
GDAWgBTRO5M6FGbnWMiQbpLAzq8UK/K/GTANBgkqhkiG9w0BAQsFAAOCAQEAPWgW
oHw+0OPQCzYRwFTCgQj/FYWdIfDkevduVUp1LQ0hEOGuJwOcTqV0XLSrI31QPFtP
TAbqCbsaevdEmnOLsBJSeKXdMwYd7OC6jK3jG+6rYp92k3dDpRBoLvceHvjhHqTg
exETkrtb8DeBDe5cIxyn1S2/qPY2+BIhy7cfrHhyv3mghbBK92fwvGbPyKX7TK7x
OTSnC7Z01X8Ouayu3njOMkAsps7eKQCl6CbyJK+mZ7tV3PW/msGqOap4g2D5TZ7t
hCchjuBgVHK85G7ZH8N4qDe1kS6YeY80bYB1mwWyTyLOcRfIP+xzRKx3z5XKZsoc
0h7mQPWE3MqDa8JRDQ==
-----END CERTIFICATE-----
---
Server certificate
subject=C = IT, ST = Some-State, O = Polito, CN = PolitoServer

issuer=C = IT, ST = Some-State, O = Polito, CN = PolitoCA

---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: RSA-PSS
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 1481 bytes and written 295 bytes
Verification: OK
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Server public key is 2048 bit
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 4C04864296565A7C81377D94A065B49369B83BA1ED361BC7733675285C8FD8F6
    Session-ID-ctx: 
    Resumption PSK: F904A8F6F2E1F01E1BEC649CA56F2133CBC930116B4DBF5D307FFB58429DDE925309F5066613A5FECF2BC8C6CF2426A9
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 62 de 32 09 d0 42 70 aa-3e 04 06 dd 22 e5 76 6d   b.2..Bp.>...".vm
    0010 - 76 ed 4b a2 15 26 9a 3b-49 28 75 ae 60 c3 ca c5   v.K..&.;I(u.`...
    0020 - 3e d8 c5 8e 51 c3 fe cb-07 53 ad 75 cc 54 2c 54   >...Q....S.u.T,T
    0030 - a5 f3 e9 f7 28 71 c1 0a-5c fb e9 ed ce 86 13 df   ....(q..\.......
    0040 - bb cc 3e 41 18 fe 89 5f-a5 8a 1c ed 26 f7 c5 c8   ..>A..._....&...
    0050 - 7d 9a f1 7a 10 d8 64 7d-d7 be c3 68 a8 5b f4 b2   }..z..d}...h.[..
    0060 - f7 8c c8 32 18 b8 f0 2b-50 a0 c3 ef 06 a5 12 2d   ...2...+P......-
    0070 - 7d 4e 6c e0 7b ca d6 4f-2c c6 7b 69 3b 4c e6 a7   }Nl.{..O,.{i;L..
    0080 - b4 e9 6c 70 0e 37 e6 23-17 9e c5 be c1 7f e6 c7   ..lp.7.#........
    0090 - 1e 4b 82 93 2c 15 38 23-25 53 02 64 07 54 4e b5   .K..,.8#%S.d.TN.
    00a0 - 2a 5e 1d d9 7f 37 e3 9a-ab b2 e7 dc 52 81 b4 00   *^...7......R...
    00b0 - 0a 5a de e0 dc 03 05 ef-ee 61 f5 1b 5e b3 cf 2e   .Z.......a..^...
    00c0 - af e6 48 a8 c9 62 1a c5-67 5a ec 9a d4 9b b7 c1   ..H..b..gZ......

    Start Time: 1635842402
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: E081B24FDD7DE39AE57718FCF5C1358647DC40CB689B4F9644306C77AE7B42C0
    Session-ID-ctx: 
    Resumption PSK: 06A47B91CC9163CA5E12F6A2EB8139C8C149A96698665BF4B2FD13AEF75D0F4AE4FCFB682FBD680EA49E7A17FAD139A7
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 62 de 32 09 d0 42 70 aa-3e 04 06 dd 22 e5 76 6d   b.2..Bp.>...".vm
    0010 - 4a 07 4b 0f b0 e1 f3 a9-42 dd d1 76 3f 14 73 b1   J.K.....B..v?.s.
    0020 - 60 91 0c a2 62 c1 7e 94-c8 53 7b 4e a9 ae 91 05   `...b.~..S{N....
    0030 - e3 5f bd e9 30 cf 91 e3-74 59 37 d7 9d 4e 28 6d   ._..0...tY7..N(m
    0040 - db ef c2 66 7e 84 04 fe-47 6a 00 5d a7 d4 1a 59   ...f~...Gj.]...Y
    0050 - 73 37 b6 18 fd 18 16 9d-44 bd 32 8c f9 69 79 7d   s7......D.2..iy}
    0060 - 54 f8 86 50 f0 ba 9d 7d-7a 09 f0 2d 31 3e 3f 37   T..P...}z..-1>?7
    0070 - f5 8f a1 6d 0b a9 dd f1-fd 9d 55 07 32 8a d0 26   ...m......U.2..&
    0080 - 43 63 58 f3 45 41 79 53-b0 3e 38 47 af 82 b7 df   CcX.EAyS.>8G....
    0090 - af 6e e9 43 7c 0e 93 cb-be b1 9e d3 0b d2 43 e2   .n.C|.........C.
    00a0 - d2 35 7f 35 d7 e5 b1 c3-fe 9d 41 5f 85 fa 8c 96   .5.5......A_....
    00b0 - 5e 51 1c 6b 54 29 3c 7d-2e 25 7c 2a 4d 75 08 55   ^Q.kT)<}.%|*Mu.U
    00c0 - b4 17 e7 76 b3 69 6a 18-74 b6 f3 55 0b 16 2f bd   ...v.ij.t..U../.

    Start Time: 1635842402
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
```
In a separate window, open a terminal (emulator) and start Wireshark:
```
wireshark
```
Select “eth0” and “Loopback:lo” and then click on the blu symbol (places up, left position, under “File”) corresponding to “Start capturing packets”.
Run the s_client with the command above and intercept the TLS handshake communication messages exchanged between the s_clientand the s_server. You should be able to view the captured messages in a dedicated window in Wireshark.
Now respond at the following questions:
How many RTTs do you see? Write them down in the following box:

```
→ 1 RTT (C-S):
(1. TCP SYN - TCP ACK)
2. TCP ACK+Client Hello - TCP ACK+Server Hello, Change Cipher Spec, Application Data
(3. TCP ACK+Change Cipher Spec, Application Data - Application Data)

Now connection is established and the client can start sending Application Data

The destruction of the connection takes 2 RTTs, as for any TCP protocol:
1. TCP FIN ACK - TCP FIN ACK
2. TCP ACK
```
Which ciphersuite has been negotiated?

```
→ Cipher Suite: TLS_AES_256_GCM_SHA384 (0x1302)
```
1.2.4 Client authentication in TLS

Now try to configure an SSL/TLS server with client authentication. What do you need in the first place?

Prerequisites In case you cannot access the material provided for this laboratory or if you simply want to
recreate it on your own, we remind you can generate a client certificate with OpenSSL in the following way:

1. create a certificate request for the client certificate:
    openssl req -new -keyout clientpkey.pem -out clientcreq.pem
2. issue a new certificate:
    openssl ca -in clientcreq.pem -out clientcert.pem

Configure now s_server so that to request client authentication during the handshake phase of the SSL/TLS protocol:

```
root@kali:~/Desktop# openssl s_server -www -key server_pkey.pem -cert server_cert.pem -Verify 0
verify depth is 0, must return a certificate
Enter pass phrase for server_pkey.pem:
Using default temp DH parameters
ACCEPT
```
Run the s_client command necessary to connect to the s_server started above:

```
root@kali:~# openssl s_client -connect 10.0.2.10:4433 -state -showcerts -CAfile /media/sf_Kali_Shared/Cybersecurity_Labs/CYB_lab01/cacert.pem -tls1_2
140028147938624:error:14094410:SSL routines:ssl3_read_bytes:sslv3 alert handshake failure:../ssl/record/rec_layer_s3.c:1543:SSL alert number 40

root@kali:~# openssl s_client -connect 10.0.2.10:4433 -state -showcerts -CAfile /media/sf_Kali_Shared/Cybersecurity_Labs/CYB_lab01/cacert.pem -cert /media/sf_Kali_Shared/Cybersecurity_Labs/CYB_lab01/client_cert.pem -key /media/sf_Kali_Shared/Cybersecurity_Labs/CYB_lab01/client_pkey.pem -tls1_2
Enter pass phrase for /media/sf_Kali_Shared/Cybersecurity_Labs/CYB_lab01/client_pkey.pem:
CONNECTED(00000003)
SSL_connect:before SSL initialization
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS write client hello
Can't use SSL_get_servername
SSL_connect:SSLv3/TLS read server hello
depth=1 C = IT, ST = Some-State, O = Polito, CN = PolitoCA
verify return:1
depth=0 C = IT, ST = Some-State, O = Polito, CN = PolitoServer
verify return:1
SSL_connect:SSLv3/TLS read server certificate
SSL_connect:SSLv3/TLS read server key exchange
SSL_connect:SSLv3/TLS read server certificate request
SSL_connect:SSLv3/TLS read server done
SSL_connect:SSLv3/TLS write client certificate
SSL_connect:SSLv3/TLS write client key exchange
SSL_connect:SSLv3/TLS write certificate verify
SSL_connect:SSLv3/TLS write change cipher spec
SSL_connect:SSLv3/TLS write finished
SSL_connect:SSLv3/TLS write finished
SSL_connect:SSLv3/TLS read server session ticket
SSL_connect:SSLv3/TLS read change cipher spec
SSL_connect:SSLv3/TLS read finished
---
Certificate chain
 0 s:C = IT, ST = Some-State, O = Polito, CN = PolitoServer
   i:C = IT, ST = Some-State, O = Polito, CN = PolitoCA
-----BEGIN CERTIFICATE-----
MIIDmTCCAoGgAwIBAgIUGmyqoZijolQnuu7h7U4LKKAMCq0wDQYJKoZIhvcNAQEL
BQAwRjELMAkGA1UEBhMCSVQxEzARBgNVBAgMClNvbWUtU3RhdGUxDzANBgNVBAoM
BlBvbGl0bzERMA8GA1UEAwwIUG9saXRvQ0EwHhcNMjExMDIwMTY1NTQ0WhcNMjIx
MDIwMTY1NTQ0WjBKMQswCQYDVQQGEwJJVDETMBEGA1UECAwKU29tZS1TdGF0ZTEP
MA0GA1UECgwGUG9saXRvMRUwEwYDVQQDDAxQb2xpdG9TZXJ2ZXIwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8mNMJHULbWctZzkeuXWw3d4XJT9KRul9i
ZuLRB+n3pT39IyS67VDkRkbvtlmExJAyRnPzQ3XGDxAQuoJ2KS0Xm1/WDpiGH/u1
thUrq+xUY/+xNRnZZyheUli/62I5EWojx7HrexxGLZ8ghRXoDXqeaB9Jmdy5SDb5
CSogPDXSeMvNzc4zXjlIvm7SzkdzTVc8gHKMU8Uu1+o3566lgFtELRC7ph80CEDz
iOWtCKr+e1Ruh+mP2QfltXa3ysPq4Av3KFXr3KbBh59bGoRhyqGG2MBr0FhPzgWy
uqsosReB8mNAsAQTcSNFFxXFhv+y6IkhAdwGTO+b8Jdm+WbJHjMLAgMBAAGjezB5
MAkGA1UdEwQCMAAwLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENl
cnRpZmljYXRlMB0GA1UdDgQWBBTSLDHhWwOO45e9LDk2wD7Q4G9agjAfBgNVHSME
GDAWgBTRO5M6FGbnWMiQbpLAzq8UK/K/GTANBgkqhkiG9w0BAQsFAAOCAQEAPWgW
oHw+0OPQCzYRwFTCgQj/FYWdIfDkevduVUp1LQ0hEOGuJwOcTqV0XLSrI31QPFtP
TAbqCbsaevdEmnOLsBJSeKXdMwYd7OC6jK3jG+6rYp92k3dDpRBoLvceHvjhHqTg
exETkrtb8DeBDe5cIxyn1S2/qPY2+BIhy7cfrHhyv3mghbBK92fwvGbPyKX7TK7x
OTSnC7Z01X8Ouayu3njOMkAsps7eKQCl6CbyJK+mZ7tV3PW/msGqOap4g2D5TZ7t
hCchjuBgVHK85G7ZH8N4qDe1kS6YeY80bYB1mwWyTyLOcRfIP+xzRKx3z5XKZsoc
0h7mQPWE3MqDa8JRDQ==
-----END CERTIFICATE-----
---
Server certificate
subject=C = IT, ST = Some-State, O = Polito, CN = PolitoServer

issuer=C = IT, ST = Some-State, O = Polito, CN = PolitoCA

---
No client certificate CA names sent
Client Certificate Types: RSA sign, DSA sign, ECDSA sign
Requested Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224:DSA+SHA224:DSA+SHA256:DSA+SHA384:DSA+SHA512
Shared Requested Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224:DSA+SHA224:DSA+SHA256:DSA+SHA384:DSA+SHA512
Peer signing digest: SHA256
Peer signature type: RSA-PSS
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 2535 bytes and written 1482 bytes
Verification: OK
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 17EBEC2409DFFB5FD246132BFC27A99A539BB0C6931F32E9116E985EF1A3439A
    Session-ID-ctx: 
    Master-Key: DFC55E32D293AC46BCE1D7F59C3F29A6BD8F81FE84E29D4324D66FC5770BC6DF4519152478A861C0937862016D9DDBC5
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - aa ba 5d 65 5d 57 ca 5b-bf 39 8a b5 cb a5 e8 42   ..]e]W.[.9.....B
    0010 - 7a e1 58 21 41 76 28 68-a1 5d 60 5a 52 08 0c b0   z.X!Av(h.]`ZR...
    0020 - 30 a6 3d 68 61 d8 1e 59-b3 df 0c 6f f6 b5 86 fd   0.=ha..Y...o....
    0030 - 1f d2 51 0f f6 6b c8 22-df 0b 92 0e 38 ab 32 8b   ..Q..k."....8.2.
    0040 - d9 46 a1 df 30 38 4a fe-40 82 de 32 2a e8 84 8d   .F..08J.@..2*...
    0050 - 9c 37 f1 30 45 df 09 b5-13 0e 3a dd 7e cb dd 96   .7.0E.....:.~...
    0060 - 55 5f 6a c9 1e 31 82 a3-06 c0 ca 93 11 62 97 71   U_j..1.......b.q
    0070 - a8 2d 5d 85 83 5e fd 78-67 02 c8 62 93 a5 b9 4e   .-]..^.xg..b...N
    0080 - f9 25 b3 3c 29 10 8d 34-56 2f 0d 29 0b ac 54 44   .%.<)..4V/.)..TD
    0090 - 8a e5 6c 96 17 4f 35 fb-09 a7 f9 e8 34 17 93 ba   ..l..O5.....4...
    00a0 - 51 b3 fd cc fd 12 ea 1d-b1 c8 af f0 9d 9c 2c 9f   Q.............,.
    00b0 - e6 c0 9a e6 e5 17 aa 8e-27 9e 2a ca b0 38 95 c4   ........'.*..8..
    00c0 - f0 d3 d6 bf 50 73 56 25-22 30 d2 4c 65 55 9e 9e   ....PsV%"0.LeU..
    00d0 - 9f 1d 6f 59 10 d9 64 95-9e 92 62 a4 ec 4d d7 cf   ..oY..d...b..M..
    00e0 - 2d cc ce 98 72 11 d3 f2-69 4b 8b 90 4f ae d7 4e   -...r...iK..O..N
    00f0 - a4 ac 9c e8 e6 53 a3 1b-ae 10 2c 4b 2c ae ab 25   .....S....,K,..%
    0100 - 2d 8f 51 ee 65 c1 bf 50-34 1a 6c 24 e7 8f 7e 0b   -.Q.e..P4.l$..~.
    0110 - 61 a4 75 6f a9 e3 6d 61-a5 3b 54 86 15 50 18 de   a.uo..ma.;T..P..
    0120 - 38 04 1e 8c a8 f6 3a c8-83 ad 13 84 1a 7f e3 d3   8.....:.........
    0130 - e2 9e d7 17 d0 11 81 10-9d ff c0 a5 d6 db d1 5a   ...............Z
    0140 - 0f 2e 20 99 82 bd 86 3e-ca 5e ee 48 d9 59 aa 19   .. ....>.^.H.Y..
    0150 - d6 6c a2 46 40 74 35 f7-23 51 16 2b 5c 6b e8 0a   .l.F@t5.#Q.+\k..
    0160 - 12 43 be a4 b5 87 2d 46-22 88 5e 26 48 37 ad c6   .C....-F".^&H7..
    0170 - 58 75 b7 93 52 5f 0a 1d-63 41 c1 45 6a 16 ad e6   Xu..R_..cA.Ej...
    0180 - b2 f7 84 ab e6 42 dd 5f-2d 5c 70 17 6f 06 99 b4   .....B._-\p.o...
    0190 - 28 5b 70 48 85 51 f1 c1-6f 42 bf 0b 37 e1 81 ac   ([pH.Q..oB..7...
    01a0 - a8 ef 2f 5d b2 ac 77 01-1f 82 dc ad ec 2d ce 2b   ../]..w......-.+
    01b0 - 18 5b 15 74 3f 8c 6e d8-80 84 b3 6e 2b 16 aa 6d   .[.t?.n....n+..m
    01c0 - 8f c9 e2 14 56 89 9d c6-76 6f ef f4 f6 6e 25 bd   ....V...vo...n%.
    01d0 - 05 c0 4d 75 bd 34 21 bb-19 d1 1c 04 21 eb 6e 89   ..Mu.4!.....!.n.
    01e0 - a9 93 67 c0 90 3e e6 cc-d3 48 f5 4e 7b e1 fa 30   ..g..>...H.N{..0
    01f0 - e6 2a 4c b1 15 13 d6 5f-1b db 8b 66 a7 fd 62 0d   .*L...._...f..b.
    0200 - 9b 51 46 20 9f 99 db b8-d2 12 91 c3 ac 99 4a ba   .QF ..........J.
    0210 - fc 84 9a ac e8 41 ee 6e-b6 6a ad 74 fa f2 80 1a   .....A.n.j.t....
    0220 - 8c 92 78 6e 39 f0 50 12-2c 19 ae a9 e9 57 db 86   ..xn9.P.,....W..
    0230 - 45 a2 10 94 04 65 25 b2-6d bc fc 91 20 b1 8c 7b   E....e%.m... ..{
    0240 - e6 44 b1 73 b9 94 13 86-7e 7b c9 e9 b0 0e 1f 36   .D.s....~{.....6
    0250 - e8 b9 10 50 13 b2 eb 23-37 d0 1b d0 f3 43 aa 4d   ...P...#7....C.M
    0260 - c2 8d 3c 65 ca 6a 23 d6-82 4d 8e 6c c9 dd d4 cf   ..<e.j#..M.l....
    0270 - 06 14 93 db 52 6b af 0c-5b 8c d7 52 7b d5 e1 50   ....Rk..[..R{..P
    0280 - 4f fb 79 6b e4 28 d0 05-a5 4e 31 fa 3b 41 ed c9   O.yk.(...N1.;A..
    0290 - cd c6 6e bd 58 5d 8e c3-ed 7c 1d 4e 52 c3 d5 3a   ..n.X]...|.NR..:
    02a0 - 6e d2 aa 0d 45 3e d7 f7-a8 77 0c 29 c9 34 49 f2   n...E>...w.).4I.
    02b0 - b7 22 15 40 06 22 e1 dc-72 42 fa 2b fe 5c 9f 05   .".@."..rB.+.\..
    02c0 - 4b 28 a1 d6 db 78 2a 2e-de 2d e3 6b b4 36 b5 f7   K(...x*..-.k.6..
    02d0 - 6a fd 36 5e 34 18 11 0d-26 90 6b 3d e3 aa 10 e9   j.6^4...&.k=....
    02e0 - ab 72 56 a0 ea 8d 0f 55-61 b7 56 89 36 ea ac 34   .rV....Ua.V.6..4
    02f0 - 0b cd 62 dc d4 46 c5 46-4a 2c 8d 08 00 90 1b a8   ..b..F.FJ,......
    0300 - 29 50 68 0e 70 ca c0 9b-57 dc 8c 44 9a 31 24 20   )Ph.p...W..D.1$ 
    0310 - 99 f4 51 ea 0d 46 5b 34-ac 20 58 3d 9a 22 88 63   ..Q..F[4. X=.".c
    0320 - 84 3f 75 31 91 57 5f 7d-96 f9 1e 9b 16 52 a1 f2   .?u1.W_}.....R..
    0330 - 14 18 44 b8 6e e9 5f 22-47 fc cc ea f3 da 84 8e   ..D.n._"G.......
    0340 - 57 71 08 1a 3c 65 04 c3-91 20 ac 72 be 8c 53 ad   Wq..<e... .r..S.
    0350 - 5d f6 c4 fc 3a 73 f9 54-1c 53 86 a0 f1 dd b9 66   ]...:s.T.S.....f
    0360 - 3f a4 75 c3 2e a3 ad 5c-ac 9c f5 d1 91 60 71 e3   ?.u....\.....`q.
    0370 - cc 8f 80 ca af 54 1d d4-04 c3 f3 b9 3d ac 6f 68   .....T......=.oh
    0380 - 54 b0 5e 40 37 91 c2 af-09 57 9c 18 81 e3 75 74   T.^@7....W....ut
    0390 - 23 39 cf a0 bf b1 59 23-22 b5 c4 26 b7 84 53 63   #9....Y#"..&..Sc
    03a0 - 8e 4a 87 9f f0 53 66 43-4e 5e 25 ed 5b b9 3f e9   .J...SfCN^%.[.?.
    03b0 - aa 3d f9 87 61 92 0e 08-b8 a2 7a ab 15 f6 68 8d   .=..a.....z...h.
    03c0 - 66 bb 8c 80 8e 1b 22 d3-33 7a b6 b0 0f c5 0a ce   f.....".3z......
    03d0 - c4 46 ae 32 74 f3 fa e4-dc 35 15 bb 13 e0 df 72   .F.2t....5.....r
    03e0 - 15 13 0b 77 3c 46 f1 7d-90 66 3a 00 7e d5 8b 7a   ...w<F.}.f:.~..z
    03f0 - 56 3b 92 c7 e0 79 2a d5-df ba d8 10 51 3d 25 96   V;...y*.....Q=%.
    0400 - d4 8a bf 10 1d a2 bb 7a-85 11 79 20 b5 da 7a 56   .......z..y ..zV
    0410 - bc 73 fc b4 da 5b 2e f2-e1 51 6e 16 f0 f0 f3 dd   .s...[...Qn.....
    0420 - fb 13 e7 b3 fb d6 64 18-08 69 0f 9e a9 f0 db 58   ......d..i.....X
    0430 - 3e eb c3 23 d6 31 74 9a-8d ef c9 c6 fc dc 34 7f   >..#.1t.......4.

    Start Time: 1635843663
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: yes
---

```

By using wireshark, identify the TLS handshake messages that have changed in the handshake phase of the
SSL/TLS protocol. Write them down in the following box:

```
→ 2 RTT (C-S):
(1. TCP SYN - TCP ACK)
2. TCP ACK+Client Hello - TCP ACK+Server Hello, Certificate, Server Key Exchange, CERTIFICATE REQUEST, Server Hello Done
3. TCP ACK+CERTIFICATE, Client Key Exchange, CERTIFICATE VERIFY, Change Cipher Spec, Encrypted Handshake Message - TCP ACK + New Session Ticket, Change Cipher Spec, Encrypted Handshake Message
```

In which TLS handshake message is placed the information about the CA accepted by the server (for the client
certificates)?

```
→ TLSv1.2 Record Layer: Handshake Protocol: Certificate Request
    Content Type: Handshake (22)
    Version: TLS 1.2 (0x0303)
    Length: 52
    Handshake Protocol: Certificate Request
        Handshake Type: Certificate Request (13)
        Length: 48
        Certificate types count: 3
        Certificate types (3 types)
            Certificate type: RSA Sign (1)
            Certificate type: DSS Sign (2)
            Certificate type: ECDSA Sign (64)
        Signature Hash Algorithms Length: 40
        Signature Hash Algorithms (20 algorithms)
            Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)
                Signature Hash Algorithm Hash: SHA256 (4)
                Signature Hash Algorithm Signature: ECDSA (3)
            Signature Algorithm: ecdsa_secp384r1_sha384 (0x0503)
                Signature Hash Algorithm Hash: SHA384 (5)
                Signature Hash Algorithm Signature: ECDSA (3)
            Signature Algorithm: ecdsa_secp521r1_sha512 (0x0603)
                Signature Hash Algorithm Hash: SHA512 (6)
                Signature Hash Algorithm Signature: ECDSA (3)
            Signature Algorithm: ed25519 (0x0807)
                Signature Hash Algorithm Hash: Unknown (8)
                Signature Hash Algorithm Signature: Unknown (7)
            Signature Algorithm: ed448 (0x0808)
                Signature Hash Algorithm Hash: Unknown (8)
                Signature Hash Algorithm Signature: Unknown (8)
            Signature Algorithm: rsa_pss_pss_sha256 (0x0809)
                Signature Hash Algorithm Hash: Unknown (8)
                Signature Hash Algorithm Signature: Unknown (9)
            Signature Algorithm: rsa_pss_pss_sha384 (0x080a)
                Signature Hash Algorithm Hash: Unknown (8)
                Signature Hash Algorithm Signature: Unknown (10)
            Signature Algorithm: rsa_pss_pss_sha512 (0x080b)
                Signature Hash Algorithm Hash: Unknown (8)
                Signature Hash Algorithm Signature: Unknown (11)
            Signature Algorithm: rsa_pss_rsae_sha256 (0x0804)
                Signature Hash Algorithm Hash: Unknown (8)
                Signature Hash Algorithm Signature: Unknown (4)
            Signature Algorithm: rsa_pss_rsae_sha384 (0x0805)
                Signature Hash Algorithm Hash: Unknown (8)
                Signature Hash Algorithm Signature: Unknown (5)
            Signature Algorithm: rsa_pss_rsae_sha512 (0x0806)
                Signature Hash Algorithm Hash: Unknown (8)
                Signature Hash Algorithm Signature: Unknown (6)
            Signature Algorithm: rsa_pkcs1_sha256 (0x0401)
                Signature Hash Algorithm Hash: SHA256 (4)
                Signature Hash Algorithm Signature: RSA (1)
            Signature Algorithm: rsa_pkcs1_sha384 (0x0501)
                Signature Hash Algorithm Hash: SHA384 (5)
                Signature Hash Algorithm Signature: RSA (1)
            Signature Algorithm: rsa_pkcs1_sha512 (0x0601)
                Signature Hash Algorithm Hash: SHA512 (6)
                Signature Hash Algorithm Signature: RSA (1)
            Signature Algorithm: SHA224 ECDSA (0x0303)
                Signature Hash Algorithm Hash: SHA224 (3)
                Signature Hash Algorithm Signature: ECDSA (3)
            Signature Algorithm: SHA224 RSA (0x0301)
                Signature Hash Algorithm Hash: SHA224 (3)
                Signature Hash Algorithm Signature: RSA (1)
            Signature Algorithm: SHA224 DSA (0x0302)
                Signature Hash Algorithm Hash: SHA224 (3)
                Signature Hash Algorithm Signature: DSA (2)
            Signature Algorithm: SHA256 DSA (0x0402)
                Signature Hash Algorithm Hash: SHA256 (4)
                Signature Hash Algorithm Signature: DSA (2)
            Signature Algorithm: SHA384 DSA (0x0502)
                Signature Hash Algorithm Hash: SHA384 (5)
                Signature Hash Algorithm Signature: DSA (2)
            Signature Algorithm: SHA512 DSA (0x0602)
                Signature Hash Algorithm Hash: SHA512 (6)
                Signature Hash Algorithm Signature: DSA (2)
        Distinguished Names Length: 0

The list of supported CAs is "Distinguished Names", which in this case is empty since only polito CA is supported.
```
### 1.3 Enabling TLS in Apache Web Server

The scope of this exercise is to allow you to configure the Apache HTTP server with support for TLS.

Prerequisites. First of all, we need a certificate for the HTTP server. We have issued a server certificate by the demoCA used in the previous exercises. The certificate contains the DNS name “myexample.com” in the field “Common Name”. The password used to protect the private key is: “ciao”. You need to configure the DNS name in the/etc/hosts. Open the file and insert the following association:

```
127.0.0.2 myexample.com
```
For simplicity, we provide also the Apache configuration filedefault-ssl.confused in tests. You can find
all this stuff in the archiveCYBlab01support.zipavailable in the same folder of this text.

At this point, you can proceed as follows.

1. Activate the Apache web server, with server authentication:
    - run the following command to enable the SSL module of Apache:
    ```
    root@kali:~/Desktop# a2enmod ssl
    Considering dependency setenvif for ssl:
    Module setenvif already enabled
    Considering dependency mime for ssl:
    Module mime already enabled
    Considering dependency socache_shmcb for ssl:
    Enabling module socache_shmcb.                                                                                                                                                                                                             
    Enabling module ssl.                                                                                                                                                                                                                       
    See /usr/share/doc/apache2/README.Debian.gz on how to configure SSL and create self-signed certificates.                                                                                                                                   
    To activate the new configuration, you need to run:                                                                                                                                                                                        
    systemctl restart apache2    
    ```
    - use the following command to enable the Apache SSL site:
        ```
        a2ensite default-ssl
        ```
    - copy the files myexamplecert.pem and demoCA/cacert.pem in the directory/etc/ssl/certs and the file myexamplepkey.pem in the folder/etc/ssl/private. Note:/etc/ssl is the (default) Apache directory for the SSL configuration.
    - modify the following directives in the file/etc/apache2/sites-enabled/default-ssl.conf:
       SSLCertificateFile /etc/ssl/certs/myexamplecert.pem
       SSLCertificateKeyFile /etc/ssl/private/myexamplepkey.pem

```
SSLCACertificateFile /etc/ssl/certs/cacert.pem
```
```
SSLVerifyClient none
```
Which certificates and key file have been configured?
```
The server certificate and the trusted CA certificate
```

- restart the Apache web server, by using the command:
    systemctl restart apache2
- for testing purposes, you try to connect to the Apache web server with the OpenSSL sclient, by using the command:

```
root@kali:~# openssl s_client -connect myexample.com:443
CONNECTED(00000003)
depth=1 C = IT, ST = Some-State, O = Polito, CN = Test CA
verify error:num=19:self signed certificate in certificate chain
verify return:1
depth=1 C = IT, ST = Some-State, O = Polito, CN = Test CA
verify return:1
depth=0 C = IT, ST = Some-State, O = Polito, CN = myexample.com
verify return:1
---
Certificate chain
 0 s:C = IT, ST = Some-State, O = Polito, CN = myexample.com
   i:C = IT, ST = Some-State, O = Polito, CN = Test CA
 1 s:C = IT, ST = Some-State, O = Polito, CN = Test CA
   i:C = IT, ST = Some-State, O = Polito, CN = Test CA
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIDmTCCAoGgAwIBAgIUQZJTksfN9XZxsBAWYa05ronFqKMwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCSVQxEzARBgNVBAgMClNvbWUtU3RhdGUxDzANBgNVBAoM
BlBvbGl0bzEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yMTEwMDkwNzU1MzNaFw0yMjEw
MDkwNzU1MzNaMEsxCzAJBgNVBAYTAklUMRMwEQYDVQQIDApTb21lLVN0YXRlMQ8w
DQYDVQQKDAZQb2xpdG8xFjAUBgNVBAMMDW15ZXhhbXBsZS5jb20wggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2zslcer7Y0um2ATVQULe88cnC3dne1xx2
BuFNhw22AE2HQnsW32rIFFfY4Qc7cKOBmgp8XjTaHK3zPPVKx4Kkf3nuCYi8ag3m
T3zVLCQbK0zWcaQaJYPMN/fO0NT+S13EI2OQgZPxx0Lmx/2WCcjMLs6MGHrUCIsO
IkQHEbDlxVCuR7xRbuzh/amL3hVPtDcit7pMZ627oiOy34hfAaRK13MHdPVUm14L
Z+iA9TtLokGG5cCn5f+QoV/nXLPrLnUI/usG2Bl9NIdfh9utaKXlilSl3cZCBD2r                                                   
EbcSDsW2DMd0NPUHIPzvPVeONJGxDk5YbFjjybqnQdMaeOlRFxKZAgMBAAGjezB5                                                   
MAkGA1UdEwQCMAAwLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENl                                                   
cnRpZmljYXRlMB0GA1UdDgQWBBT7KpfSVMSidD2ykqN2NlPD+NSdVDAfBgNVHSME                                                   
GDAWgBTNxJ8kiVDqPJ0noQHmIEpTrZbzhjANBgkqhkiG9w0BAQsFAAOCAQEAuWYj                                                   
AJwzNDisRyip2WC6Kfj85vWYeLN9CILxVCbNQn7Fkw4Ph+vvVKgbJ/IdnkMVaPDM                                                   
Jp1qHYhS9iyKmk+6Ww14sPwplWIrH9kKkFDeJwf232jex6RPeHXrjpDRRnkSLg3x                                                   
+kMLr3G82ccTRJnAL6xrEJW+PWD9OFOf+qby27yvisIo/ZsviP2mtJqL4kSgema8                                                   
TrrLkBU71VeoGTCZVjBvR4nQBU7tIW8HJuj3teNurD9KEw8fxt+ynagQXbKqZGL9                                                   
g4JhjChan6Hoi07iJC0uL2ItomvmvAuPbLgx7fGhOEBjs6+zECBLSFMtr2a5QQQi                                                   
KTI3uRRk3D9J1gdZVA==                                                                                               
-----END CERTIFICATE-----                                                                                          
subject=C = IT, ST = Some-State, O = Polito, CN = myexample.com                                                    

issuer=C = IT, ST = Some-State, O = Polito, CN = Test CA

---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: RSA-PSS
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 2365 bytes and written 385 bytes
Verification error: self signed certificate in certificate chain
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Server public key is 2048 bit
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 19 (self signed certificate in certificate chain)
---
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: BDE64A5A55D8CB94E1FF31682642B4BA35FF8C6B9777FEAFBFDD8BA2294F869B
    Session-ID-ctx: 
    Resumption PSK: C6A7D862C93AA1B4CC6F2338FD617F053DF53FEA56086DA3FFF1C2F982C72CA31888F0CD34254FC52C3DF64742B69CD6
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 300 (seconds)
    TLS session ticket:
    0000 - ed 47 50 55 cd 19 17 07-ab 43 5e 32 04 dd ac e1   .GPU.....C^2....
    0010 - 50 ca 68 50 87 db 6e 95-0c 38 aa 95 0a bb 20 ba   P.hP..n..8.... .
    0020 - e4 58 47 5b 95 91 e7 a9-1f ce d3 37 45 e1 8a fb   .XG[.......7E...
    0030 - 99 ac 01 35 da d6 6a d6-25 b9 d9 11 0a 6a 08 b3   ...5..j.%....j..
    0040 - 7c 27 38 75 5b 6a ab eb-11 87 74 f7 d4 da 5d 63   |'8u[j....t...]c
    0050 - fa db b0 78 4b b0 b0 9e-ea a8 0a d7 38 31 6e ca   ...xK.......81n.
    0060 - 60 6f 77 e9 74 8c 90 8e-36 ed 7f 1a 0c 77 cb 2c   `ow.t...6....w.,
    0070 - 35 64 2b 98 18 3e 84 da-33 34 e9 bb ae ba e1 36   5d+..>..34.....6
    0080 - c7 3d f3 66 3d 8c 90 f0-e3 cb f1 36 55 47 f8 1d   .=.f=......6UG..
    0090 - 0a 8b 0b c1 2b ad b0 1b-ad aa 6e 28 44 87 c6 45   ....+.....n(D..E
    00a0 - 32 67 0e 84 05 61 f9 dc-32 da ff b5 47 c7 4b e2   2g...a..2...G.K.
    00b0 - 30 46 70 c4 78 a9 19 77-41 4d de b3 08 7f d4 d4   0Fp.x..wAM......
    00c0 - 5f 4d 07 bb 7f 7d c1 f5-79 de f2 7f a6 34 70 ce   _M...}..y....4p.
    00d0 - 83 8a f4 19 ff 3d 3c fc-0f 5d 5f 60 97 bf 42 29   .....=<..]_`..B)

    Start Time: 1635846392
    Timeout   : 7200 (sec)
    Verify return code: 19 (self signed certificate in certificate chain)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 3C22B9460BC80518916C986874693CC39684723C4423CB06E2479BDE8BF5B38D
    Session-ID-ctx: 
    Resumption PSK: 06009690728455B2B66DAD8FD738BEDBAE8AAF7CF1189CDD11EDC4FAC9D1EE8F41AC72677908B326F5777D8B57EF12C1
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 300 (seconds)
    TLS session ticket:
    0000 - ed 47 50 55 cd 19 17 07-ab 43 5e 32 04 dd ac e1   .GPU.....C^2....
    0010 - 8c 5f 4e 05 76 2d 42 71-45 d8 21 ed d7 0d 0f 05   ._N.v-BqE.!.....
    0020 - c0 56 fa 42 12 e1 f6 de-55 32 b4 c9 48 90 a9 aa   .V.B....U2..H...
    0030 - 38 c1 ee 37 63 84 26 b3-a2 9c d4 bb 9e 80 b1 f0   8..7c.&.........
    0040 - 1b 2c 20 5f 40 af 7b a8-6e fe 70 fb 8b 6c 00 45   ., _@.{.n.p..l.E
    0050 - 33 dc 60 99 c4 c0 3d 53-0e cd 9e 03 67 fa b7 1c   3.`...=S....g...
    0060 - 6f 0f 9c 98 b6 95 51 b4-62 a0 0b 5b 25 ed 3b 12   o.....Q.b..[%.;.
    0070 - 3e 7e d5 5c 9a 66 15 45-5b 4c da c0 18 96 d1 fe   >~.\.f.E[L......
    0080 - a5 94 76 ad ce ad 03 34-a4 90 d8 cb 8f 10 41 e7   ..v....4......A.
    0090 - 24 3a e4 28 ad db 3c f0-55 c6 43 47 9a 5c c4 ed   $:.(..<.U.CG.\..
    00a0 - c0 4b 95 69 db 3a 12 98-5a 48 13 5c 01 82 cf 52   .K.i.:..ZH.\...R
    00b0 - ce e1 04 a1 c4 36 fa 1e-23 27 35 e9 5e 4d 52 f4   .....6..#'5.^MR.
    00c0 - 63 5a f3 67 43 e3 d0 aa-4a 0d e3 94 92 44 4c 0f   cZ.gC...J....DL.
    00d0 - d1 a0 99 17 57 95 12 ee-d1 f6 20 31 03 d1 08 99   ....W..... 1....

    Start Time: 1635846392
    Timeout   : 7200 (sec)
    Verify return code: 19 (self signed certificate in certificate chain)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
closed
```
Check out the output of the s_client: which protocol version has been used?
```
TLS1.3
```
Now connect again to the Apache web server with the OpenSSL sclient, by using the command:
```
root@kali:~# openssl s_client -connect myexample.com:443 -tls1_2
CONNECTED(00000003)
depth=1 C = IT, ST = Some-State, O = Polito, CN = Test CA
verify error:num=19:self signed certificate in certificate chain
verify return:1
depth=1 C = IT, ST = Some-State, O = Polito, CN = Test CA
verify return:1
depth=0 C = IT, ST = Some-State, O = Polito, CN = myexample.com
verify return:1
---
Certificate chain
 0 s:C = IT, ST = Some-State, O = Polito, CN = myexample.com
   i:C = IT, ST = Some-State, O = Polito, CN = Test CA
 1 s:C = IT, ST = Some-State, O = Polito, CN = Test CA
   i:C = IT, ST = Some-State, O = Polito, CN = Test CA
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIDmTCCAoGgAwIBAgIUQZJTksfN9XZxsBAWYa05ronFqKMwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCSVQxEzARBgNVBAgMClNvbWUtU3RhdGUxDzANBgNVBAoM
BlBvbGl0bzEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yMTEwMDkwNzU1MzNaFw0yMjEw
MDkwNzU1MzNaMEsxCzAJBgNVBAYTAklUMRMwEQYDVQQIDApTb21lLVN0YXRlMQ8w
DQYDVQQKDAZQb2xpdG8xFjAUBgNVBAMMDW15ZXhhbXBsZS5jb20wggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2zslcer7Y0um2ATVQULe88cnC3dne1xx2
BuFNhw22AE2HQnsW32rIFFfY4Qc7cKOBmgp8XjTaHK3zPPVKx4Kkf3nuCYi8ag3m
T3zVLCQbK0zWcaQaJYPMN/fO0NT+S13EI2OQgZPxx0Lmx/2WCcjMLs6MGHrUCIsO
IkQHEbDlxVCuR7xRbuzh/amL3hVPtDcit7pMZ627oiOy34hfAaRK13MHdPVUm14L
Z+iA9TtLokGG5cCn5f+QoV/nXLPrLnUI/usG2Bl9NIdfh9utaKXlilSl3cZCBD2r
EbcSDsW2DMd0NPUHIPzvPVeONJGxDk5YbFjjybqnQdMaeOlRFxKZAgMBAAGjezB5
MAkGA1UdEwQCMAAwLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENl
cnRpZmljYXRlMB0GA1UdDgQWBBT7KpfSVMSidD2ykqN2NlPD+NSdVDAfBgNVHSME
GDAWgBTNxJ8kiVDqPJ0noQHmIEpTrZbzhjANBgkqhkiG9w0BAQsFAAOCAQEAuWYj
AJwzNDisRyip2WC6Kfj85vWYeLN9CILxVCbNQn7Fkw4Ph+vvVKgbJ/IdnkMVaPDM
Jp1qHYhS9iyKmk+6Ww14sPwplWIrH9kKkFDeJwf232jex6RPeHXrjpDRRnkSLg3x
+kMLr3G82ccTRJnAL6xrEJW+PWD9OFOf+qby27yvisIo/ZsviP2mtJqL4kSgema8
TrrLkBU71VeoGTCZVjBvR4nQBU7tIW8HJuj3teNurD9KEw8fxt+ynagQXbKqZGL9
g4JhjChan6Hoi07iJC0uL2ItomvmvAuPbLgx7fGhOEBjs6+zECBLSFMtr2a5QQQi
KTI3uRRk3D9J1gdZVA==
-----END CERTIFICATE-----
subject=C = IT, ST = Some-State, O = Polito, CN = myexample.com

issuer=C = IT, ST = Some-State, O = Polito, CN = Test CA

---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: RSA-PSS
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 2464 bytes and written 303 bytes
Verification error: self signed certificate in certificate chain
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 892F378EDE0CD81137F2846CBB5F8CF3A8ED74C59119D6F82956F68748C2C938
    Session-ID-ctx: 
    Master-Key: 84EB98E2AA9CD8AB6CDC7BBCF3C0EE14FBA00F9C2E414329638E989BE3A5FA17D962FD4922C596544E8D3335DDF1B6D0
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 300 (seconds)
    TLS session ticket:
    0000 - ed 47 50 55 cd 19 17 07-ab 43 5e 32 04 dd ac e1   .GPU.....C^2....
    0010 - 54 86 a8 c4 1f 7b 85 1a-cc 65 1a 43 1a e8 69 d9   T....{...e.C..i.
    0020 - 49 6d 19 26 d4 22 d8 07-65 7b 9c 8a f6 68 5a c3   Im.&."..e{...hZ.
    0030 - e4 2a 55 64 b4 a9 ed b6-16 68 d3 bf 15 79 d0 3d   .*Ud.....h...y.=
    0040 - 8f 9a 56 0b 8f fd d9 21-53 f7 d5 04 2c e8 80 a7   ..V....!S...,...
    0050 - 8d 6b 61 2e 39 63 50 cf-49 4a c8 a8 39 90 18 df   .ka.9cP.IJ..9...
    0060 - 91 f0 3b 33 e3 4b 6c 03-87 b2 d1 59 5d 4e 35 e9   ..;3.Kl....Y]N5.
    0070 - 34 d1 11 ab bf 91 1a fd-1c cf f8 85 2b b8 e0 0c   4...........+...
    0080 - 0b 93 22 76 5c b1 ba ca-cf 89 72 49 6b 00 d7 37   .."v\.....rIk..7
    0090 - e2 e1 80 51 34 c6 0a 3a-98 61 f6 0c a3 11 45 cb   ...Q4..:.a....E.
    00a0 - 42 0a b8 f7 74 cf 6f f1-04 cf 50 4e cc f1 58 35   B...t.o...PN..X5
    00b0 - 1e cd 70 19 e9 95 bb e8-8c 0d 4b cb 86 05 5c 7e   ..p.......K...\~

    Start Time: 1635846559
    Timeout   : 7200 (sec)
    Verify return code: 19 (self signed certificate in certificate chain)
    Extended master secret: yes
---

```
Which are the differences you observe on the output of the sclient with respect to the output you
have obtained in the previous command?
```
→ TLS1.3 - TLS1.2
53c53
< New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
---
> New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
55c55
< Secure Renegotiation IS NOT supported
---
> Secure Renegotiation IS supported

< Post-Handshake New Session Ticket arrived:

<     Resumption PSK: 06009690728455B2B66DAD8FD738BEDBAE8AAF7CF1189CDD11EDC4FAC9D1EE8F41AC72677908B326F5777D8B57EF12C1
---
>     Master-Key: 84EB98E2AA9CD8AB6CDC7BBCF3C0EE14FBA00F9C2E414329638E989BE3A5FA17D962FD4922C596544E8D3335DDF1B6D0
<     Extended master secret: no
<     Max Early Data: 0
---
>     Extended master secret: yes
```
- next, try to connect with the Firefox browser to (your own) Apache web server. Open Firefox and
    insert in the address bar:
       https://myexample.com:
    You should be able to see the “Apache2 Debian Default Page”.

### 1.4 Enabling client authentication

To enable the client authentication, you need to perform two steps:

- import the (client) certificate in the browser. Additionally, if you use the OpenSSL sclient for testing the connection to the TLS web server, you need to specify the client certificate among the options (otherwise you’ll see an error);
- configure the Apache server to ask for client authentication.

1.4.1 Configure the TLS server for client authentication

In the Apache server, you enable the client authentication in TLS by changing in the file

/etc/apache2/sites-enabled/default-ssl.conf

the directive:

```
SSLVerifyClient none
```
with the directives:

```
SSLVerifyClient require
SSLVerifyDepth 10
```
Next, restart Apache with the command:

```
systemctl restart apache2
```
For testing purposes, try to connect with the following command to the Apache web server:

```
root@kali:~# openssl s_client -connect myexample.com:443 -state -showcerts -CAfile /media/sf_Kali_Shared/Cybersecurity_Labs/CYB_lab01/cacert.pem -cert /media/sf_Kali_Shared/Cybersecurity_Labs/CYB_lab01/client_cert.pem -key /media/sf_Kali_Shared/Cybersecurity_Labs/CYB_lab01/client_pkey.pem -tls1_2
Enter pass phrase for /media/sf_Kali_Shared/Cybersecurity_Labs/CYB_lab01/client_pkey.pem:
CONNECTED(00000003)
SSL_connect:before SSL initialization
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS read server hello
depth=1 C = IT, ST = Some-State, O = Polito, CN = Test CA
verify error:num=19:self signed certificate in certificate chain
verify return:1
depth=1 C = IT, ST = Some-State, O = Polito, CN = Test CA
verify return:1
depth=0 C = IT, ST = Some-State, O = Polito, CN = myexample.com
verify return:1
SSL_connect:SSLv3/TLS read server certificate
SSL_connect:SSLv3/TLS read server key exchange
SSL_connect:SSLv3/TLS read server certificate request
SSL_connect:SSLv3/TLS read server done
SSL_connect:SSLv3/TLS write client certificate
SSL_connect:SSLv3/TLS write client key exchange
SSL_connect:SSLv3/TLS write certificate verify
SSL_connect:SSLv3/TLS write change cipher spec
SSL_connect:SSLv3/TLS write finished
SSL_connect:SSLv3/TLS write finished
SSL_connect:SSLv3/TLS read server session ticket
SSL_connect:SSLv3/TLS read change cipher spec
SSL_connect:SSLv3/TLS read finished
---
Certificate chain
 0 s:C = IT, ST = Some-State, O = Polito, CN = myexample.com
   i:C = IT, ST = Some-State, O = Polito, CN = Test CA
-----BEGIN CERTIFICATE-----
MIIDmTCCAoGgAwIBAgIUQZJTksfN9XZxsBAWYa05ronFqKMwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCSVQxEzARBgNVBAgMClNvbWUtU3RhdGUxDzANBgNVBAoM
BlBvbGl0bzEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yMTEwMDkwNzU1MzNaFw0yMjEw
MDkwNzU1MzNaMEsxCzAJBgNVBAYTAklUMRMwEQYDVQQIDApTb21lLVN0YXRlMQ8w
DQYDVQQKDAZQb2xpdG8xFjAUBgNVBAMMDW15ZXhhbXBsZS5jb20wggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2zslcer7Y0um2ATVQULe88cnC3dne1xx2
BuFNhw22AE2HQnsW32rIFFfY4Qc7cKOBmgp8XjTaHK3zPPVKx4Kkf3nuCYi8ag3m
T3zVLCQbK0zWcaQaJYPMN/fO0NT+S13EI2OQgZPxx0Lmx/2WCcjMLs6MGHrUCIsO                                                   
IkQHEbDlxVCuR7xRbuzh/amL3hVPtDcit7pMZ627oiOy34hfAaRK13MHdPVUm14L                                                   
Z+iA9TtLokGG5cCn5f+QoV/nXLPrLnUI/usG2Bl9NIdfh9utaKXlilSl3cZCBD2r                                                   
EbcSDsW2DMd0NPUHIPzvPVeONJGxDk5YbFjjybqnQdMaeOlRFxKZAgMBAAGjezB5                                                   
MAkGA1UdEwQCMAAwLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENl                                                   
cnRpZmljYXRlMB0GA1UdDgQWBBT7KpfSVMSidD2ykqN2NlPD+NSdVDAfBgNVHSME                                                   
GDAWgBTNxJ8kiVDqPJ0noQHmIEpTrZbzhjANBgkqhkiG9w0BAQsFAAOCAQEAuWYj                                                   
AJwzNDisRyip2WC6Kfj85vWYeLN9CILxVCbNQn7Fkw4Ph+vvVKgbJ/IdnkMVaPDM                                                   
Jp1qHYhS9iyKmk+6Ww14sPwplWIrH9kKkFDeJwf232jex6RPeHXrjpDRRnkSLg3x                                                   
+kMLr3G82ccTRJnAL6xrEJW+PWD9OFOf+qby27yvisIo/ZsviP2mtJqL4kSgema8                                                   
TrrLkBU71VeoGTCZVjBvR4nQBU7tIW8HJuj3teNurD9KEw8fxt+ynagQXbKqZGL9                                                   
g4JhjChan6Hoi07iJC0uL2ItomvmvAuPbLgx7fGhOEBjs6+zECBLSFMtr2a5QQQi                                                   
KTI3uRRk3D9J1gdZVA==                                                                                               
-----END CERTIFICATE-----
 1 s:C = IT, ST = Some-State, O = Polito, CN = Test CA
   i:C = IT, ST = Some-State, O = Polito, CN = Test CA
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUQZJTksfN9XZxsBAWYa05ronFqJ0wDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCSVQxEzARBgNVBAgMClNvbWUtU3RhdGUxDzANBgNVBAoM
BlBvbGl0bzEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yMDEwMDUxMjI1NTVaFw0yMzEw
MDUxMjI1NTVaMEUxCzAJBgNVBAYTAklUMRMwEQYDVQQIDApTb21lLVN0YXRlMQ8w
DQYDVQQKDAZQb2xpdG8xEDAOBgNVBAMMB1Rlc3QgQ0EwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC7rHhjOp0kMehdAbKTFcotJN8lrK68hGBu6IpOPDpF
b6SSummPTPRKv1mxEegJQ3Iftms6TJxfS+NzWUTSdRp4BvNCDqtmNBc/ISMEz2Li
Vi+Mw8hWthDiCkVom+ugaRLttgcSV215H5FaOihp2DZ90ZOzUMgBKZdwk6cxTeoz
jhlKTYKlCafOk4luY4rVnEGU0xKu38va8aieoBqmCsCOQMFnWW+6+O5Sf1OwegPn
/4ufEelX7HhZgy1Reaa1GEvpYSUALXZUDJPtmXAW598gBk7Rq6jcyuUpNl9TwAKO
dj01v9tT6he9SIKWNKoKHevGOPunbxaW3buzG8Vn21WxAgMBAAGjUzBRMB0GA1Ud
DgQWBBTNxJ8kiVDqPJ0noQHmIEpTrZbzhjAfBgNVHSMEGDAWgBTNxJ8kiVDqPJ0n
oQHmIEpTrZbzhjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBk
gsc4bqkpIw8lKh5i8aD/wqlBH3OcAjRlfGeG6sWUYM3+6qjocqdxAmMHdVK80h7o
4HlZLnXFDDIjjVz5fyzVm0TIHosDPbjnujefJviHH5Ffmk3HEM/w/K3mPXyrdRFG
l/y+2BebCiY0hxSNgAIK0Ca2LERT+GPUhNj/G+tcsfDVOgNkeqRgw/Miwa6yRZEN
KGqp1X2UoQYd3mWDl5qT6UWpQ3FLIwlRLO4JEoxeDbEDlydUOo6HC70LwuHjegJo
f4+/8YFWPJJaVsVrlVK7Dr812EjLl17vWMjDRXF7J3+mmlG562BaATsyH2ihOBkh
ISRb3sEME8Sr8jcwHq7h
-----END CERTIFICATE-----
---
Server certificate
subject=C = IT, ST = Some-State, O = Polito, CN = myexample.com

issuer=C = IT, ST = Some-State, O = Polito, CN = Test CA

---
Acceptable client certificate CA names
C = IT, ST = Some-State, O = Polito, CN = Test CA
Client Certificate Types: RSA sign, DSA sign, ECDSA sign
Requested Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224:DSA+SHA224:DSA+SHA256:DSA+SHA384:DSA+SHA512
Shared Requested Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224:DSA+SHA224:DSA+SHA256:DSA+SHA384:DSA+SHA512
Peer signing digest: SHA256
Peer signature type: RSA-PSS
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 3522 bytes and written 1504 bytes
Verification error: self signed certificate in certificate chain
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 5A6EB2E5606CC908EA77C1F85860833AC54A6B06E142B6BB022BE4D77A63B475
    Session-ID-ctx: 
    Master-Key: 5FF55CB3EB5D03E782D57C4589DB77C6B581ED85558654A599CDD1027579C4AF77C0C7FC78D96E1D1E2497632441552A
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 300 (seconds)
    TLS session ticket:
    0000 - 93 ca fb 67 5c 3c d7 87-c2 ac 44 a6 f8 ae 78 01   ...g\<....D...x.
    0010 - 66 2d 55 71 28 96 99 a5-d1 e6 57 9e f9 2f af ed   f-Uq(.....W../..
    0020 - a6 27 ca 62 42 4b 83 c9-c0 f8 35 07 43 1b 70 8a   .'.bBK....5.C.p.
    0030 - eb 7c 3e 88 7c c1 b1 6e-c2 54 c9 af 91 70 ab 7d   .|>.|..n.T...p.}
    0040 - b5 26 f6 59 de 95 cb b1-28 d6 82 e8 3e 51 93 cf   .&.Y....(...>Q..
    0050 - 0d 50 23 57 39 98 c1 ab-c4 d4 b3 1a 7f 2e 41 67   .P#W9.........Ag
    0060 - 3e f7 4e 5e 80 24 1a 06-0b f9 9c f9 f4 2a 44 e8   >.N^.$.......*D.
    0070 - 6a 8c 07 45 77 92 b6 78-3d e9 5a b6 60 f7 fa c9   j..Ew..x=.Z.`...
    0080 - d1 69 cf 00 22 dc 4d 2d-a7 db 8e 11 c8 02 fb fd   .i..".M-........
    0090 - d0 c2 34 32 bd 53 98 1d-8b 3c 30 c2 12 f8 59 25   ..42.S...<0...Y%
    00a0 - 99 07 3f 16 07 36 db 21-02 47 73 1b 01 77 39 d1   ..?..6.!.Gs..w9.
    00b0 - fc c7 a1 22 57 19 50 98-6b a4 2f 2e 0e d8 ff a9   ..."W.P.k./.....
    00c0 - b2 89 77 15 59 84 db 75-e7 32 dd bc 26 59 45 68   ..w.Y..u.2..&YEh
    00d0 - 4d be ea dc 09 c9 26 51-1c a2 6e 1f 16 36 89 b0   M.....&Q..n..6..
    00e0 - d8 31 3c 75 7d 31 32 b1-b9 59 c1 d8 df f1 22 7f   .1<u}12..Y....".
    00f0 - 2a ca c9 e1 7d 7a fc 83-eb 9c 0e 1e 45 2c d0 91   *...}z......E,..
    0100 - 75 3d 07 d8 de 26 b5 2c-b9 c1 c5 ad 98 8a f1 77   u=...&.,.......w
    0110 - 47 7a d4 81 c9 c9 a1 2f-c6 c7 08 ce 4d 18 92 36   Gz...../....M..6
    0120 - 6a 78 56 ec a9 d3 6f 15-c3 68 dd 3f b9 a5 b6 75   jxV...o..h.?...u
    0130 - 42 43 43 15 01 0b ab b9-41 73 18 6d 9b ba 55 47   BCC.....As.m..UG
    0140 - 75 55 1d 21 ff 7d bc 5d-cc 12 b7 e2 cc 5a d9 0f   uU.!.}.].....Z..
    0150 - e9 e6 a7 46 ca ca 69 d1-95 a8 8e 82 84 fa 76 03   ...F..i.......v.
    0160 - 3c 5b dd a2 05 9e de 71-f8 e9 25 75 26 b7 f0 0b   <[.....q..%u&...
    0170 - ce ee 89 23 47 79 d6 c4-6b 12 ed 3b 77 70 f7 73   ...#Gy..k..;wp.s
    0180 - cc f0 20 85 36 3c 3d 82-2b 09 cb dc 08 aa 6d 84   .. .6<=.+.....m.
    0190 - c1 15 d6 18 40 02 5e 87-28 09 99 e9 a1 46 b0 5b   ....@.^.(....F.[
    01a0 - 7f ea 2c 62 f7 6c 08 43-7a 95 c0 f6 7d d5 1d 3b   ..,b.l.Cz...}..;
    01b0 - 84 9b c8 0a 28 20 43 51-bf 37 7b f3 34 b3 19 70   ....( CQ.7{.4..p
    01c0 - e7 df 13 48 f7 51 c4 29-15 69 9f 4b 63 5c 3b 75   ...H.Q.).i.Kc\;u
    01d0 - 4d 76 60 32 e3 37 4d 5f-bf 57 64 13 a2 b2 32 f2   Mv`2.7M_.Wd...2.
    01e0 - 0e 3e 52 e3 51 bf 35 3f-6b f5 1f 99 ce eb 4e 88   .>R.Q.5?k.....N.
    01f0 - ff 69 c7 ea 4f ae ef db-f7 ba 11 ae d0 3c b5 03   .i..O........<..
    0200 - ff fb 3e 2b 91 11 f8 64-c4 84 d5 de a0 8a 6d 33   ..>+...d......m3
    0210 - a0 9b ac 57 ca 89 bd 7d-c8 4d da f8 5d b9 88 43   ...W...}.M..]..C
    0220 - ed 3b 6a 28 ac c2 35 f0-b6 fe 00 f4 76 1f c8 d5   .;j(..5.....v...
    0230 - 0b 32 4c d0 56 35 91 f6-dc 0a cb c9 81 b7 b5 f2   .2L.V5..........
    0240 - ca d4 aa 59 fc d6 2d b5-53 79 c1 b6 61 f8 7a c0   ...Y..-.Sy..a.z.
    0250 - 5f b3 45 6e f3 9b ef ca-17 13 f3 fd ff 04 c1 b7   _.En............
    0260 - e1 c0 40 a3 06 8a aa 63-84 ab fc 1d bd ae 74 f0   ..@....c......t.
    0270 - e5 ea a7 c3 7b 16 08 4a-34 6e 00 28 c5 21 d4 73   ....{..J4n.(.!.s
    0280 - ea 42 8e ac 7e 8a 02 68-a6 89 10 90 ba 6b ae 90   .B..~..h.....k..
    0290 - b0 3d 33 57 21 b4 89 22-ef 98 c8 6e 8d a2 ad d7   .=3W!.."...n....
    02a0 - 53 33 8f 53 f9 e9 d7 81-c0 95 11 e6 05 06 86 6e   S3.S...........n
    02b0 - 89 1f 8f 29 75 6f fb bd-e4 4f 98 b1 c7 4f ec 12   ...)uo...O...O..
    02c0 - c2 45 e9 17 1c cc 11 dd-3e 38 44 b9 6c 18 91 65   .E......>8D.l..e
    02d0 - 24 d8 4e a2 73 0c f9 ed-18 df ba 17 bf 32 76 78   $.N.s........2vx
    02e0 - 45 16 12 6b 7a f3 0a a5-ab 18 fa ea 7a 5e 8b 32   E..kz.......z^.2
    02f0 - 57 f4 9c 77 f8 b8 26 61-a3 c2 1f 76 ff 02 9e ce   W..w..&a...v....
    0300 - b4 18 51 50 e0 ec b6 e7-8e 91 34 28 fc 83 5f 00   ..QP......4(.._.
    0310 - 85 7e 47 b8 b8 1c c5 bd-1c 5b 2d bf 6b fe eb c9   .~G......[-.k...
    0320 - 83 a2 ac a3 1c d0 20 a7-04 55 96 b1 6b 2e c6 ff   ...... ..U..k...
    0330 - d6 f6 26 05 fc 33 e3 ef-47 9a 95 78 df 48 64 78   ..&..3..G..x.Hdx
    0340 - 19 b0 7d 4b be 05 c0 28-18 be 90 7f e1 1a f0 99   ..}K...(........
    0350 - 26 07 15 45 7b 2e 67 40-50 c0 5f 04 db b0 28 3a   &..E{.g@P._...(:
    0360 - d3 be 3b 18 2c 50 29 a6-71 5b c4 e7 e2 94 0c 83   ..;.,P).q[......
    0370 - 2b 80 b8 ce fb 0d f8 a7-79 1d 58 33 bd 01 79 b0   +.......y.X3..y.
    0380 - 11 b4 00 aa c8 82 1b 45-b7 ae c4 79 f2 13 ce ec   .......E...y....
    0390 - a4 5a 4d 6d 09 b9 d5 e0-cb d6 35 a8 d2 77 36 bc   .ZMm......5..w6.
    03a0 - 2e 8f e7 c0 0e b6 bd 2a-2b 2b e4 8e 74 83 a2 11   .......*++..t...
    03b0 - 0c 0e 35 64 a2 04 34 d0-18 00 83 e0 fb 68 e7 65   ..5d..4......h.e
    03c0 - 70 db f7 45 56 a2 5a e7-5c a4 cc c5 c9 06 84 e3   p..EV.Z.\.......
    03d0 - fb a6 84 53 22 71 f6 8d-86 9d ca e6 55 af 09 db   ...S"q......U...
    03e0 - 2e 94 10 fa 08 ef b8 c6-d7 07 95 9d 9f 63 f1 e8   .............c..
    03f0 - de 0f a0 07 2e 89 ec d3-0d 65 9d a1 43 b7 06 d1   .........e..C...
    0400 - ff c3 49 d3 65 a3 24 0f-d7 df 8e ec 3f de 7f 70   ..I.e.$.....?..p
    0410 - 87 9c 61 fc aa d7 ad 91-25 80 0f d2 e1 a6 06 07   ..a.....%.......
    0420 - c7 74 51 23 d2 d6 9d 17-cf 06 1e b5 16 56 92 c7   .tQ#.........V..
    0430 - 6c 9e 6c 55 9a 4e cc 01-e8 fe c0 c4 04 a8 6f fe   l.lU.N........o.
    0440 - ef 06 e8 42 30 56 5e 39-63 1d 5b 30 28 10 ed f5   ...B0V^9c.[0(...
    0450 - 18 7a 41 53 a7 9c 41 8d-cc da db f9 82 e2 fa 42   .zAS..A........B

    Start Time: 1635850660
    Timeout   : 7200 (sec)
    Verify return code: 19 (self signed certificate in certificate chain)
    Extended master secret: yes
---
SSL3 alert read:warning:close notify
closed
SSL3 alert write:warning:close notify
```
You should be able to see the output providing information on the TLS connection that has been just established.

1.4.2 Importing the client certificate in the browser

To import the client certificate in the browser, you need the PKCS#12 fil eclient_cert.p12.

It was generated by with the following command:

```
root@kali:~# openssl pkcs12 -export -in /media/sf_Kali_Shared/Cybersecurity_Labs/CYB_lab01/client_cert.pem -inkey /media/sf_Kali_Shared/Cybersecurity_Labs/CYB_lab01/client_pkey.pem -name client_certificate -certfile /media/sf_Kali_Shared/Cybersecurity_Labs/CYB_lab01/demoCA/cacert.pem -out client_cert.p12
Enter pass phrase for /media/sf_Kali_Shared/Cybersecurity_Labs/CYB_lab01/client_pkey.pem:
Enter Export Password: ciao
Verifying - Enter Export Password: ciao
```
Then, to import it into the browser, for example in Firefox, you need to select “Preferences”→“Privacy &
Security”→. In the “Security” are, under “Certificates” you need to click “View Certificates”, then select
“Your Certificates”, click “Import” and then select the “client_cert.p12”. When asked, you need to insert the
password you have used to protect the private key and the export bag (“ciao” in the provided material.)

Next, open a browser and insert in the address bar:

```
https://myexample.com
```
You should be asked to select a browser certificate (of the client). After choosing the client certificate, you
should be able to see the “Apache2 Debian Default Page”.
```
Codice di errore: SEC_ERROR_UNKNOWN_ISSUER
```

1.4.3 Enabling certificate revocation checking in Apache web server

In this exercise, you will see how to enable certificate revocation checking with CRL in the Apache web server.

Prerequisites You need a revoked client certificate and the corresponding CRL. We have generated both of
them with the demoCA, in the filebobcert.pemyou find the revoked certificate, and in the filemycrl.pem
you find the CRL.

In case you don’t access the material provided for this laboratory or if you want to recreate it, we remind you
the steps below so that you can re-create them on your own (if needed).

To generate a certificate (for Bob):

```
openssl req -new -keyout bobpkey.pem -out bobcreq.pem
```
```
openssl ca -in bobcreq.pem -out bobcert.pem
```
To generate a CRL:

```
openssl ca -revoke demoCA/newcerts/serialnumberofBobcertificate.pem
```
```
openssl ca -gencrl -out mycrl.pem
```
Next, you need to create a directory namedssl.crlin /etc/apache2/ssl.crl and copy the CRL filemycrl.pem
in the directoryssl.crl.

Finally, you need to configure the Apache web server to check the CRLs.

In the/etc/apache2/sites-enabled/default-ssl.conf, insert the following directives:

```
SSLCARevocationPath /etc/apache2/ssl.crl/
SSLCARevocationFile /etc/apache2/ssl.crl/mycrl.pem
SSLCARevocationCheck chain
```
Next, restart the Apache web server with the command:

```
systemctl restart apache
```
Try to connect with the following command to the Apache web server:

```
openssl sclient -connect myexample.com:443 -state -showcerts -CAfile
demoCA/cacert.pem -cert bobcert.pem -key bobpkey.pem -tls1 3
```
You should see an error: “SSL3 alert read:fatal:certificate revoked”.


### 1.5 Performance measurement

The scope of this exercise is to measure up the times required to transfer data over a channel protected with
SSL/TLS.

Try to download first a file of small size, over a channel with no TLS protection. For example, you can use:

```
wget http://myexample.com/
```
Next, try to download the same file over a TLS protected channel, e.g. by using the command:

```
wget --ca-certificate demoCA/cacert.pem https://myexample.com --secure-protocol=TLSv1_3
```
What do you note?

```
→
```
Now, generate different files of various sizes, i.e. 10 kB, 100 kB, 1 MB, 10 MB and 100 MB. For this purpose,
you can use the following command of OpenSSL:

```
openssl rand -out r.txt sizeinbytes
```
Copy them in the directory/var/www/html/and then restart Apache.

Download them with wget as above, and note down differences in the speed and time. Change the TLS protocol version and use different ciphers and perform the same evaluations as above.

| Size of site | Protocol used | Speed (10 tries)            | Time (10 tries)     |
| ------------ | ------------- | --------------------------- | ------------------- |
| 10kB         | no protection | ``` 2.86MB/s - 44.5MB/s ``` | ``` 0s - 0.004s ``` |
| 10kB         | TLS 1.2       | ``` 11.9MB/s - 44.1MB/s```  | ``` 0s - 0.004s ``` |
| 10kB         | TLS 1.3       | ``` 2.46MB/s - 53.1MB/s```  | ``` 0s - 0.004s ``` |
| 100MB        | no protection | ``` 50.5MB/s - 74.5MB/s```  | ``` 1.3s - 1.9s ``` |
| 100MB        | TLS 1.2       | ``` 39.9MB/s - 48.9MB/s ``` | ``` 1.9s - 2.4s ``` |
| 100MB        | TLS 1.3       | ``` 37.6MB/s - 72.4MB/s ``` | ``` 1.3s - 2.5s ``` |

## 2 SSH

### 2.1 Connecting through a secure channel

SSH protocol is based on asymmetric cryptography, but for a basic usage complex operation related to the
private/public cryptography can run behind the scene, and allow users a simple and user-friendly experience

One basic tool that takes advantage of SSH is the OpenSSH client

```
man ssh
```
The commandsshis a secure replacement for the ancienttelnetandrshprogram for logging into a remote machine and obtain a command shell. Contrarily to those old programs, SSH provides secure encrypted
communication between two untrusted hosts over an insecure network.

The basic usage is through a username/password authentication.

To experiment this basic usage, form a couple (let’s say Alice and Bob), on two different VMs.

Now we want to grant Alice access to Bob’s machine. For doing so, first of all Bob creates a new user named
aliceon his machine (adduser aliceand associate to the user a password (password alice)). After that, what operations should they perform to allow Alice the possibility of having a secure command shell on Bob’s machine? Make
your hypothesis and write them down!

```
→ 
```

Then check your guesses you can adopt the following command on the Bob machine, an SSH server must be
up and running, check with:

```
[B] systemctl status ssh
```
Now, Alice and Bob cooperate to check OOB the fingerprint of the Bob host key.

First, Alice ask for Bob’s host key sha256 fingerprint:

```
(-o=options)
[A] ssh -o FingerprintHash=sha256 10.0.2.10
The authenticity of host '10.0.2.10 (10.0.2.10)' can't be established.
ECDSA key fingerprint is SHA256:6BG5gZly5/CP7X2dx/yqzrxH+0IMK9w9o7QJAotMknQ.
Are you sure you want to continue connecting (yes/no/[fingerprint])? 
```
```
BEWARE
Alice must wait before accepting the key and adding it in her permanent store until she has checked the correspondence with the one on Bob machine (e.g. by comparing the fingerprint).
```
Meanwhile, Bob can display it on the command line:

```
(-l Show fingerprint of specified public key file.
-f filename of the key file
-E fingerprint_hash Specifies the hash algorithm used when displaying key
             fingerprints.  Valid options are: “md5” and “sha256”.  The
             default is “sha256”.)
[B] ssh-keygen -l -E sha256 -f /etc/ssh/ssh_host_ecdsa_key
256 SHA256:6BG5gZly5/CP7X2dx/yqzrxH+0IMK9w9o7QJAotMknQ root@kali (ECDSA) 
```
```
NOTE
By default, the SSH server keys are located in/etc/ssh, and in particular the default one for Kali
is in/etc/ssh/sshhostecdsakey. You can change it modifying the ssh server configuration in
/etc/ssh/sshdconfig, particularly theHostKeydirective
```
After that, Bob can send the sha256 fingerprint to Alice OOB (e.g. on a private chat among them, or through a
physical meeting)

If the two fingerprints correspond (they correspond!), then Alice can store it permanently in her file system (answering yes to the
previously suspended question)
```
Warning: Permanently added '10.0.2.10' (ECDSA) to the list of known hosts.
```

```
NOTE
After the positive answer, the public key of Bob’s ssh server will be stored in $HOME/.ssh/knownhosts file. If a public key would become no longer trusted, it can be simply removed from this file
```
.

Finally, Alice can connect to Bob’s machine through the ssh client:

```
[A] ssh alice@BobIP
```
To better understand the exchange described before, before emitting the different operations, run wireshark and use it to familiarise with the ssh protocol and identify different parameters of the secure channel that has
been created by ssh. In particular:

- identify the client and server software version;
```
Client: Protocol: SSH-2.0-OpenSSH_8.3p1 Debian-1
Server: Protocol: SSH-2.0-OpenSSH_8.3p1 Debian-1
```
- identify the available encryption and mac algorithms;
```
Server: Key Exchange Init
SSH Version 2 (encryption:chacha20-poly1305@openssh.com mac:<implicit> compression:none)
    Packet Length: 1052
    Padding Length: 10
    Key Exchange
        Message Code: Key Exchange Init (20)
        Algorithms
            Cookie: d453a2e84c9cdacc07b1d638c4ceb7f3
            kex_algorithms length: 230
            kex_algorithms string [truncated]: curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,di
            server_host_key_algorithms length: 65
            server_host_key_algorithms string: rsa-sha2-512,rsa-sha2-256,ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519
            encryption_algorithms_client_to_server length: 108
            encryption_algorithms_client_to_server string: chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
            encryption_algorithms_server_to_client length: 108
            encryption_algorithms_server_to_client string: chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
            mac_algorithms_client_to_server length: 213
            mac_algorithms_client_to_server string [truncated]: umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-
            mac_algorithms_server_to_client length: 213
            mac_algorithms_server_to_client string [truncated]: umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-
            compression_algorithms_client_to_server length: 21
            compression_algorithms_client_to_server string: none,zlib@openssh.com
            compression_algorithms_server_to_client length: 21
            compression_algorithms_server_to_client string: none,zlib@openssh.com
            languages_client_to_server length: 0
            languages_client_to_server string: [Empty]
            languages_server_to_client length: 0
            languages_server_to_client string: [Empty]
            First KEX Packet Follows: 0
            Reserved: 00000000
    Padding String: 00000000000000000000

Client: Key Exchange Init
SSH Version 2 (encryption:chacha20-poly1305@openssh.com mac:<implicit> compression:none)
    Packet Length: 1508
    Padding Length: 10
    Key Exchange
        Message Code: Key Exchange Init (20)
        Algorithms
            Cookie: a1616f54568f63cb27bebc5b5395c1b6
            kex_algorithms length: 241
            kex_algorithms string [truncated]: curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,di
            server_host_key_algorithms length: 500
            server_host_key_algorithms string [truncated]: ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ecdsa
            encryption_algorithms_client_to_server length: 108
            encryption_algorithms_client_to_server string: chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
            encryption_algorithms_server_to_client length: 108
            encryption_algorithms_server_to_client string: chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
            mac_algorithms_client_to_server length: 213
            mac_algorithms_client_to_server string [truncated]: umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-
            mac_algorithms_server_to_client length: 213
            mac_algorithms_server_to_client string [truncated]: umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-
            compression_algorithms_client_to_server length: 26
            compression_algorithms_client_to_server string: none,zlib@openssh.com,zlib
            compression_algorithms_server_to_client length: 26
            compression_algorithms_server_to_client string: none,zlib@openssh.com,zlib
            languages_client_to_server length: 0
            languages_client_to_server string: [Empty]
            languages_server_to_client length: 0
            languages_server_to_client string: [Empty]
            First KEX Packet Follows: 0
            Reserved: 00000000
    Padding String: 00000000000000000000

```
- identify the chosen algorithms;
```
encryption:chacha20-poly1305@openssh.com mac:<implicit> compression:none
```
- identify the password used by Alice to connect to the Bob’s host.

```
→ 
   Note that even though the cleartext password is transmitted in the
   packet, the entire packet is encrypted by the transport layer.  Both
   the server and the client should check whether the underlying
   transport layer provides confidentiality (i.e., if encryption is
   being used).  If no confidentiality is provided ("none" cipher),
   password authentication SHOULD be disabled.
   SSH_MSG_USERAUTH_REQUEST?
   SSH Protocol
    Packet Length (encrypted): df5f329c
    Encrypted Packet: 8712318c3f9caaec80ed78e16d2343c61e3e6189130b6bf1…
    [Direction: client-to-server]

```

#### NOTE

```
openssh allows for visualisation of the host key through ASCII art. This could be used to make more
“human-friendly” the comparison of the fingerprint. In order to do so you can use the following com-
mands:
[A] ssh -o VisualHostKey=yes -o FingerprintHash=sha256 10.0.2.10
+---[ECDSA 256]---+
|                 |
|  . E+ .         |
| ..o* =          |
|  oo.=.=    .    |
|   + .*oS. . =   |                                                                                                                                                                                                                        
|    o..=. + + B  |                                                                                                                                                                                                                        
|      o o. + B B |                                                                                                                                                                                                                        
|       . . o= * +|                                                                                                                                                                                                                        
|        . .o*+.=+|                                                                                                                                                                                                                        
+----[SHA256]-----+
```
```
[B] ssh-keygen -l -v -E sha256 -f /etc/ssh/ssh_host_ecdsa_key
+---[ECDSA 256]---+
|                 |
|  . E+ .         |
| ..o* =          |
|  oo.=.=    .    |
|   + .*oS. . =   |
|    o..=. + + B  |
|      o o. + B B |
|       . . o= * +|
|        . .o*+.=+|
+----[SHA256]-----+

```
### 2.2 Passwordless access

We are going to repeat the same scenario (Alice wants to run a command shell on the Bob machine) but
removing the need to send to Bob a password to authenticate. This will be substituted by using the Alice
private key for authentication.

Since SSH protocol is based on asymmetric cryptography, Alice needs a key pair, a private key (for the client
machine) and a public key (for the server machine). SSH allows this creation using the ssh-keygen tool to produce it. For example, it can create an RSA key with the following command:

```
[A] ssh-keygen -t rsa
root@kali:~/.ssh# ssh-keygen -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /root/.ssh/id_rsa
Your public key has been saved in /root/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:FKh1wcoYvX4tXE/MYyj8/hd7rf0lXAbhTkpV/hmCE+w root@kali
The key's randomart image is:
+---[RSA 3072]----+
|     . oo...  o..|
|    . + o. .oo o |
|     * =. .*..+..|
|    o +.o oEB+..+|                                                                                                                                                                                                                        
|     . .S= +....+|                                                                                                                                                                                                                        
|      . + o ...o |                                                                                                                                                                                                                        
|       . o    ooo|                                                                                                                                                                                                                        
|          .   oo+|                                                                                                                                                                                                                        
|           ....o+|                                                                                                                                                                                                                        
+----[SHA256]-----+ 
```
Keep note of the key position (by default it is in the $HOME directory in the file $HOME/.ssh/id_rsa)

Have a look at the files in the mentioned directory, what can you find in there?

```
→ known hosts, private ssh key, public ssh key
```
#### NOTE

```
If you emit again the same command as before (and do not change any default) and answer ’yes’, what
would be the result? In particular, would you still be capable of authenticating with the previous key? 
→ No
```

After the creation of the key pair, Alice needs to move the public key to Bob’s host, and she needs to place it in the /.ssh/authorizedkeys

First, she copies the public key on Bob’s host

```
[A] scp ∼/.ssh/id_rsa.pub alice@BobIP:∼/.ssh/id_rsa_alice.pub
```
Then, she opens securely a command shell on Bob’s host (as seen previously) and then she appends the key
with the following command

```
[B] cat ∼/.ssh/id_rsa_alice.pub >> ∼/.ssh/authorizedkeys
```
And then can check if it works (to do so, she may exit from the command shell on Bob’s machine, and then try
to re-open one)

In modern ssh installation, it is possible to take advantage of the ssh-copy-id command, which copies the
public key and stores it in the appropriate place in just one command

```
[A] ssh-copy-id BobIP
```
Why passwordless access improves overall security?

```
→ No risk of forgetting password/storing it in unsafe places/using weak password
```

Do you know any remaining issue for this kind of configuration?

```
→ OOB server authentication (manual check of the public key/trust on first use) is tedious since it is not automatic like with PKI.
```

### 2.3 Tunnelling

SSH provides different forms of tunnelling, i.e. direct, local, and remote, to transport higher-layer protocols
inside a secure channel.

2.3.1 Direct tunnelling

SSH can carry a higher layer protocol inside a secure channel. This is pretty intriguing in the case of the X
protocol, which is a communication protocol adopted under Linux to transfer from one host to another window
and graphic components. By itself, the X11 protocol provides no channel protection.

The purpose now is that Alice connects to the Bob machine, and then run a graphical application (e.g. a
browser), and navigate on the internet, exploiting a web browser running on Bob machine.

First, Alice connect to the Bob machine, enabling the tunnelling of X11 protocol with the option-X

```
[A] ssh -X alice@BobIP
```
then, through the command shell on Bob machine run an available browser (like firefox or google-chrome)
and so the browser will be executed on the Bob machine, but the graphic result will be transferred and displayed
on the Alice machine through the X11 protocol, in a secure way since the X11 protocol will be and all the traffic
transferred from Bob’s machine to Alice’s host (through the X11 protocol).

Alice now can navigate on the Internet.

Running Wireshark on the Bob machine, what kind of traffic do you expect to see?

```
→ TCP,TLS,X11 (no http because it is encrypted inside the ssh)
```
2.3.2 Local tunnelling

Now we will establish a secure tunnel towards a mail server. For doing so we exploit the exim4 SMTP server, telnet, a command-line tool that allows a bidirectional and interactive text-oriented communication facility over a non-protected channel, and of course SSH to create a SSH tunnel

So first of all Bob has to configure the SMTP server:

```
[B] dpkg-reconfigure exim4-config
```
then Bob selects the parameters in the following manner:

1. General type of mail configuration: Internet site; mail is sent and received directly using SMTP.
2. System mail name: kali
3. IP-addresses to listen on for incoming SMTP connections:// leave blank (delete data if present)
4. Other destinations for which mail is accepted: kali
5. Domains to relay mail for:// leave blank (delete data if present)
6. Machines to relay mail for:// leave blank (delete data if present)
7. Keep number of DNS-queries minimal (Dial-on-Demand) ?: No
8. Delivery method for local mail: mbox format in /var/mail
9. Split configuration into small files? : No
10. Root and postmaster mail recipient:// leave blank (delete data if present)

Subsequently, he starts the server with the command:

```
systemctl start exim
```
Then Alice can open an ssh tunnel to the ssh server

```
[A] ssh -L localhost:1234:10.0.2.10:25 alice@10.0.2.10
```
```
NOTE
the above command starts a listening port (1234) on the localhost (client). The connection attempted to this port, if originating from localhost, will be forwarded to the BobIP address (thanks to the alice@BobIP part of the command) to the port 22 (ssh). At this point the SSH server will forward this traffic IN CLEAR to the mail server at the port 25. Since in this case the ssh server IS the mail server, the traffic does not exit BOB machine in clear! (BobIP:25 part)
```
.

```
NOTE
as consequence of the command, Alice will open a command shell on Bob’s host. This is not relevant for the exercise, but leave it open to permit to the tunnel to persist (e.g. open another command shell to
test the tunnel)
```
Then, Bob sniff the network thanks to Wireshark on Bob’s machine, while Alice can try to connect to the SMTP
server directly

```
[A] telnetBobIP 25
```
and just typeHELP(which is an SMTP command that lists the available SMTP command from the mail server
perspective)

In another command shell, Alice take advantage of telnet to connect to the SMTP server through the SSH tunnel

```
[A] telnet localhost 1234
```
and again just type HELP

What can you notice on the sniffed traffic in Wireshark?

```
→ The SMTP help command received by Alice cannot be seen from the communication with alice, but it can be seen in clear sent from BobIP to BobIP in wireshark.
```
2.3.3 Remote tunnelling

Now we will establish a secure tunnel towards a web server. For doing so we exploit the Apache HTTP server,
a browser, and of course SSH to create a secure tunnel.

Bob starts the HTTP server with the command:

```
[B] systemctl start apache
```

Then Bob can open a tunnel to the SSH server
```
-R
[bind_address:]port:host:hostport
Specifies that the given port on the remote (server) host is to be forwarded to the given host and port on the local side. This works by allocating a socket to listen to port on the remote side, and whenever a connection is made to this port, the connection is forwarded over the secure channel, and a connection is made to host port hostport from the local machine.

Port forwardings can also be specified in the configuration file. Privileged ports can be forwarded only when logging in as root on the remote machine. IPv6 addresses can be specified by enclosing the address in square braces or using an alternative syntax:
[bind_address/]host/port/hostport.

By default, the listening socket on the server will be bound to the loopback interface only. This may be overridden by specifying a bind_address. An empty bind_address, or the address '*', indicates that the remote socket should listen on all interfaces. Specifying a remote bind_address will only succeed if the server's GatewayPorts option is enabled (see sshd_config(5)).

If the port argument is '0', the listen port will be dynamically allocated on the server and reported to the client at run time.
[B] ssh -R 8000:BobIP:80 bob@BobIP
```
.

However, in order to work, the SSH server must have the remote port forwarding enabled, and this is done by
setting the GatewayPorts directive in the /etc/ssh/sshd_config file to yes(otherwise, it will forward only packets coming from localhost). Remember to restart the SSH server after the configuration change.

Also, Bob activates Wireshark to see the ongoing traffic.

Then, Alice can starts a web browser (e.g. Firefox) and then connect directly to the webserver (to Bob’s host,
on the default port 80) and then to the web server through the SSH tunnel.

Difficult configuration!

Which differences can be appreciated in the network traffic?

```
→ 
```

