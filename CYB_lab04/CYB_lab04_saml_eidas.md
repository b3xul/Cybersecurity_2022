# SAML and eIDAS

### Laboratory for the class “Cybersecurity” (01UDR)

### Politecnico di Torino – AA 2021/

### Prof. Antonio Lioy

### prepared by:

### Diana Berbecaru (diana.berbecaru@polito.it)

### Andrea Atzeni (andrea.atzeni@polito.it)

### v. 2.0 (17/11/2021)

## Contents

1 Purpose of this laboratory 1

#### 2 SAML 2

#### 3 SPID 4

```
3.1 SPID exchange.......................................... 4
3.2 SPID student authentication (optional).............................. 6
```
4 eIDAS 6

```
4.1 eIDAS messages......................................... 6
4.2 eIDAS (SAML) Metadata..................................... 11
```
5 OpenID Connect 14

```
5.1 Example of an OpenID Connect flow............................... 15
```
## 1 Purpose of this laboratory

In this laboratory, you will perform exercises aimed to experiment with SAML and eIDAS.

To perform the proposed exercises, you will need to use a PC with connection to Internet and a browser, such
as Google Chrome or Mozilla Firefox.

To analyse the SAML message content, you will need to install in your browser some add-ons that capture and
visualise SAML messages embedded in HTTP.

For example, you can use theSAML-traceradd-on, which is available at the following links (respectively for
Firefox and Chrome):

https://addons.mozilla.org/it/firefox/addon/saml-tracer/

https://chrome.google.com/webstore/detail/saml-tracer/mpdajninpobndbfcldcmbpnnbhibjmch

Once you have installed the SAML-tracer add-on, you will see a dedicated icon in upright position of the tool
bar, as shown in Fig. 1.

If you click on the icon, you will see a window as shown in Fig. 2.


```
Figure 1: SAML-tracer add on icon in Firefox browser toolbar.
```
```
Figure 2: SAML-tracer window.
```
## 2 SAML

To experiment with SAML messages, we will start with the Login service at our university, which actually uses
a SAML-based solution to authenticate students and academic staff to provide them access to the services.

Start fromhttps://www.polito.it, start theSAML-traceradd-on in the browser, and click on the “Login”
button in the page (the button is located in the up right area of the page).

In the Login page, perform the login with the solution that you normally use, e.g. with your username and
password, or with a digital certificate.

Next, go to theSAML-tracerwindow and analyse the content of the messages you have just captured. You
should see two orange “SAML” labels indicating that your browser has conveyed two SAML messages (a
Request and a Response). The SAML request is shown in Fig. 3, while the SAML response is shown in Fig. 4.

How are the SAML Request and Response messages related to each other (which field indicates that the re-


```
Figure 3: SAML Request message generated when performing Login at Politecnico di Torino.
```
```
Figure 4: SAML Response message generated when performing Login at Politecnico di Torino.
```
sponse corresponds to a particular request)?

SAML protocol request:
```xml
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    AssertionConsumerServiceURL="https://login.didattica.polito.it/Shibboleth.sso/SAML2/POST"
                    Destination="https://idp.polito.it/idp/profile/SAML2/Redirect/SSO"
                    ID="_9eb24a5cc93885978706c326774df0b9"
                    IssueInstant="2021-11-30T15:40:04Z"
                    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    Version="2.0"
                    >
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://login.didattica.polito.it/shibboleth</saml:Issuer>
    <samlp:NameIDPolicy AllowCreate="1" />
</samlp:AuthnRequest>
```
SAML protocol response:
```xml
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                 xmlns:xs="http://www.w3.org/2001/XMLSchema"
                 Destination="https://login.didattica.polito.it/Shibboleth.sso/SAML2/POST"
                 ID="_b0213dcbf7aa951c03069edede2630a4"
                 InResponseTo="_9eb24a5cc93885978706c326774df0b9"
                 IssueInstant="2021-11-30T15:40:09.585Z"
                 Version="2.0"
                 >
    <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                  Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
                  >https://idp.polito.it/idp/shibboleth</saml2:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
            <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
            <ds:Reference URI="#_b0213dcbf7aa951c03069edede2630a4">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
                        <ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"
                                                PrefixList="xs"
                                                />
                    </ds:Transform>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
                <ds:DigestValue>NaInhMyi2mKk7JYxdJzO+70cQMA=</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>NidrzNWx7/tTuaZZApfV7lHHQuTKlsnzOzNdwFVxT5dgCnZv8JaZ7E6aI4l4yNuKlgsjuE51ac05TCZ/kcnvqoD5wMwkGhp/15AK+WpX8Gsg2V4PcYgV4UjPYFp0IImrvNmvFXTekMwKPgmuzk7hGZdVuIz9CwUUMgm3HXLytrL259nSsT/Onk28aZFMT1oVf7+6qhAC1ZF0P1q1ROtmzGkpQCdga0vkbKreN+Fxc5Us4Yfx5hE0c6ELVqLnWMLtagoHXkXuqkbhCnmoPWelSt6sJzY38liNwsrgbso1T7vCVkqm4y8dI2YD2sfTDaCsiHAMxomAMBIMWzpPKUguaA==</ds:SignatureValue>
        <ds:KeyInfo>
            <ds:X509Data>
                <ds:X509Certificate>MIIDHzCCAgegAwIBAgIUUjgf+uLNFJJcgzn0xvTjmaKHwMAwDQYJKoZIhvcNAQEFBQAwGDEWMBQG
A1UEAwwNaWRwLnBvbGl0by5pdDAeFw0xNDEyMTUxMzE0MDdaFw0zNDEyMTUxMzE0MDdaMBgxFjAU
BgNVBAMMDWlkcC5wb2xpdG8uaXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdvKxQ
DFqGjKZYTgXZWp9q/kx/lgnwfYB+BDOnD3JtA/Y93DNky2A7/zAwzh8VRjVgS3pzbeG48XCmGsKS
V3aN2GTaP28ZDajiF+fHSPW7hlzYqezGmTj+yDIW0Uc1GuS0/YBNQ1aOtVOSfLDGS6k05n5usftF
q8DWuR79c63pmaAxUkDTsvEHUho3+AvQLm4IbikG7tzxSYWgb7zIHPBuWI123/vsvg251hBjHPW+
TFEeiTgU9TufnsubgntyECIDRNJOS4fLBSj9o238Er97MPGG/eQAZLGy9cgR3jbxuSC7IPT0Mvgx
yxUvDNOrDQipflnnCpqczHK27+RgPK1HAgMBAAGjYTBfMB0GA1UdDgQWBBQZI+4NPlpY0nVNnHQ7
+cMOtYhymTA+BgNVHREENzA1gg1pZHAucG9saXRvLml0hiRodHRwczovL2lkcC5wb2xpdG8uaXQv
aWRwL3NoaWJib2xldGgwDQYJKoZIhvcNAQEFBQADggEBAGPQUvNcZcY96g2rT0NSVxBYSwh/YcpC
wfruwY0n1Z/jKLhAYO1cVJf8o4nNQCu4L370HDhIDEO8d+oiDAbwMWoCL0yPR+xUyogOVtexnKQ+
tF1FDHXisrJfj917afOZvLnJyNLtrcpZFxlJzc2nh9n1OesgE/ZkGAcWHUb+ivi4bSqIFLLEJ8Rn
4Pkdy6lGwxDGodYXWhkPb39RKfuITf0cbgOOnucvGWFio4hoMAA5qZCDLe5uC8vBvvICBHhN+Qtq
qkxS3rSNMD7d+xPAoJJTKlfT1FkJ8SljJMn1xfsMLuhbvHLJzWGWes0z1rFmTDTEq0paEFMrQ79r
3Xnwa+w=</ds:X509Certificate>
            </ds:X509Data>
        </ds:KeyInfo>
    </ds:Signature>
    <saml2p:Status>
        <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
    </saml2p:Status>
    <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                     ID="_9f1015ffc9e54ccada88acaa3681910a"
                     IssueInstant="2021-11-30T15:40:09.585Z"
                     Version="2.0"
                     >
        <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://idp.polito.it/idp/shibboleth</saml2:Issuer>
        <saml2:Subject>
            <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
                          NameQualifier="https://idp.polito.it/idp/shibboleth"
                          SPNameQualifier="https://login.didattica.polito.it/shibboleth"
                          >s290158@studenti.polito.it</saml2:NameID>
            <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml2:SubjectConfirmationData Address="188.216.0.126"
                                               InResponseTo="_9eb24a5cc93885978706c326774df0b9"
                                               NotOnOrAfter="2021-11-30T15:45:09.585Z"
                                               Recipient="https://login.didattica.polito.it/Shibboleth.sso/SAML2/POST"
                                               />
            </saml2:SubjectConfirmation>
        </saml2:Subject>
        <saml2:Conditions NotBefore="2021-11-30T15:40:09.585Z"
                          NotOnOrAfter="2021-11-30T15:45:09.585Z"
                          >
            <saml2:AudienceRestriction>
                <saml2:Audience>https://login.didattica.polito.it/shibboleth</saml2:Audience>
            </saml2:AudienceRestriction>
        </saml2:Conditions>
        <saml2:AuthnStatement AuthnInstant="2021-11-30T15:40:09.443Z"
                              SessionIndex="_13f492a723f0cb12d6f1c87e48a3c98c"
                              >
            <saml2:SubjectLocality Address="188.216.0.126" />
            <saml2:AuthnContext>
                <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
            </saml2:AuthnContext>
        </saml2:AuthnStatement>
        <saml2:AttributeStatement>
            <saml2:Attribute FriendlyName="eduPersonAffiliation"
                             Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.1"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                             >
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xsi:type="xs:string"
                                      >GG-POLITO-Studenti</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute FriendlyName="sn"
                             Name="urn:oid:2.5.4.4"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                             >
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xsi:type="xs:string"
                                      >Sattolo</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute FriendlyName="lCn"
                             Name="urn:oid:1.3.6.1.4.1.2786.10.28"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                             >
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xsi:type="xs:string"
                                      >S290158</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute FriendlyName="eduPersonNickname"
                             Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.2"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                             >
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xsi:type="xs:string"
                                      >s290158@studenti.polito.it</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute FriendlyName="Hivebrite-UID"
                             Name="uid"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                             >
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xsi:type="xs:string"
                                      >STTFNC97P19C627F</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute FriendlyName="eduPersonUniqueId"
                             Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.13"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                             >
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xsi:type="xs:string"
                                      >s290158@studenti.polito.it</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute FriendlyName="o"
                             Name="urn:oid:2.5.4.10"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                             >
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xsi:type="xs:string"
                                      >Politecnico Di Torino</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute FriendlyName="givenName"
                             Name="urn:oid:2.5.4.42"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                             >
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xsi:type="xs:string"
                                      >Francesco</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute FriendlyName="eduPersonPrincipalNamePrior"
                             Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.12"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                             >
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xsi:type="xs:string"
                                      >s290158@studenti.polito.it</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute FriendlyName="ou"
                             Name="urn:oid:2.5.4.11"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                             >
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xsi:type="xs:string"
                                      >Studenti</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute FriendlyName="uid"
                             Name="urn:oid:0.9.2342.19200300.100.1.1"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                             >
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xsi:type="xs:string"
                                      >STTFNC97P19C627F</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute FriendlyName="employeeType"
                             Name="urn:oid:2.16.840.1.113730.3.1.4"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                             >
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xsi:type="xs:string"
                                      >S290158</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute FriendlyName="mail"
                             Name="urn:oid:0.9.2342.19200300.100.1.3"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                             >
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xsi:type="xs:string"
                                      >s290158@studenti.polito.it</saml2:AttributeValue>
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xsi:type="xs:string"
                                      >s235280@studenti.polito.it</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute FriendlyName="cf"
                             Name="urn:oid:1.3.6.1.4.1.2786.10.27"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                             >
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xsi:type="xs:string"
                                      >STTFNC97P19C627F</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute FriendlyName="eduPersonPrincipalName"
                             Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                             >
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xsi:type="xs:string"
                                      >S290158@studenti.polito.it</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute FriendlyName="Shib-Identita-CodiceFiscale"
                             Name="urn:oid:2.4.5.43.4.5.80Shib-Identita-CodiceFiscale"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                             >
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xsi:type="xs:string"
                                      >STTFNC97P19C627F</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute FriendlyName="eIdentifier"
                             Name="http://www.stork.gov.eu/1.0/eIdentifier"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                             >
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xsi:type="xs:string"
                                      >STTFNC97P19C627F</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute FriendlyName="cn"
                             Name="urn:oid:2.5.4.3"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                             >
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                          #### →
            xsi:type="xs:string"
                                      >S290158</saml2:AttributeValue>
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xsi:type="xs:string"
                                      >S235280</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute FriendlyName="employeeNumber"
                             Name="urn:oid:2.16.840.1.113730.3.1.3"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                             >
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xsi:type="xs:string"
                                      >S290158</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute FriendlyName="displayName"
                             Name="urn:oid:2.16.840.1.113730.3.1.241"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                             >
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xsi:type="xs:string"
                                      >Francesco Sattolo</saml2:AttributeValue>
            </saml2:Attribute>
        </saml2:AttributeStatement>
    </saml2:Assertion>
</saml2p:Response>
```
The common field between request and response are:
```xml
    <samlp:AuthnRequest ID="_9eb24a5cc93885978706c326774df0b9">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://login.didattica.polito.it/shibboleth</saml:Issuer>

    <saml2p:Response InResponseTo="_9eb24a5cc93885978706c326774df0b9">
    <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                  Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://idp.polito.it/idp/shibboleth</saml2:Issuer>
        <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://idp.polito.it/idp/shibboleth</saml2:Issuer>
```


Check out the content of the SAML Response message and answer the following questions:

Which certificate is used (by the IdP) for signing the SAML Response?

```xml
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
            <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
            <ds:Reference URI="#_b0213dcbf7aa951c03069edede2630a4">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
                        <ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"
                                                PrefixList="xs"
                                                />
                    </ds:Transform>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
                <ds:DigestValue>NaInhMyi2mKk7JYxdJzO+70cQMA=</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>NidrzNWx7/tTuaZZApfV7lHHQuTKlsnzOzNdwFVxT5dgCnZv8JaZ7E6aI4l4yNuKlgsjuE51ac05TCZ/kcnvqoD5wMwkGhp/15AK+WpX8Gsg2V4PcYgV4UjPYFp0IImrvNmvFXTekMwKPgmuzk7hGZdVuIz9CwUUMgm3HXLytrL259nSsT/Onk28aZFMT1oVf7+6qhAC1ZF0P1q1ROtmzGkpQCdga0vkbKreN+Fxc5Us4Yfx5hE0c6ELVqLnWMLtagoHXkXuqkbhCnmoPWelSt6sJzY38liNwsrgbso1T7vCVkqm4y8dI2YD2sfTDaCsiHAMxomAMBIMWzpPKUguaA==</ds:SignatureValue>
        <ds:KeyInfo>
            <ds:X509Data>
                <ds:X509Certificate>MIIDHzCCAgegAwIBAgIUUjgf+uLNFJJcgzn0xvTjmaKHwMAwDQYJKoZIhvcNAQEFBQAwGDEWMBQG
A1UEAwwNaWRwLnBvbGl0by5pdDAeFw0xNDEyMTUxMzE0MDdaFw0zNDEyMTUxMzE0MDdaMBgxFjAU
BgNVBAMMDWlkcC5wb2xpdG8uaXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdvKxQ
DFqGjKZYTgXZWp9q/kx/lgnwfYB+BDOnD3JtA/Y93DNky2A7/zAwzh8VRjVgS3pzbeG48XCmGsKS
V3aN2GTaP28ZDajiF+fHSPW7hlzYqezGmTj+yDIW0Uc1GuS0/YBNQ1aOtVOSfLDGS6k05n5usftF
q8DWuR79c63pmaAxUkDTsvEHUho3+AvQLm4IbikG7tzxSYWgb7zIHPBuWI123/vsvg251hBjHPW+
TFEeiTgU9TufnsubgntyECIDRNJOS4fLBSj9o238Er97MPGG/eQAZLGy9cgR3jbxuSC7IPT0Mvgx
yxUvDNOrDQipflnnCpqczHK27+RgPK1HAgMBAAGjYTBfMB0GA1UdDgQWBBQZI+4NPlpY0nVNnHQ7
+cMOtYhymTA+BgNVHREENzA1gg1pZHAucG9saXRvLml0hiRodHRwczovL2lkcC5wb2xpdG8uaXQv
aWRwL3NoaWJib2xldGgwDQYJKoZIhvcNAQEFBQADggEBAGPQUvNcZcY96g2rT0NSVxBYSwh/YcpC
wfruwY0n1Z/jKLhAYO1cVJf8o4nNQCu4L370HDhIDEO8d+oiDAbwMWoCL0yPR+xUyogOVtexnKQ+
tF1FDHXisrJfj917afOZvLnJyNLtrcpZFxlJzc2nh9n1OesgE/ZkGAcWHUb+ivi4bSqIFLLEJ8Rn
4Pkdy6lGwxDGodYXWhkPb39RKfuITf0cbgOOnucvGWFio4hoMAA5qZCDLe5uC8vBvvICBHhN+Qtq
qkxS3rSNMD7d+xPAoJJTKlfT1FkJ8SljJMn1xfsMLuhbvHLJzWGWes0z1rFmTDTEq0paEFMrQ79r
3Xnwa+w=</ds:X509Certificate>
            </ds:X509Data>
        </ds:KeyInfo>
    </ds:Signature>
    
Common Name: idp.polito.it
Subject Alternative Names: idp.polito.it, URI:https://idp.polito.it/idp/shibboleth
Valid From: December 15, 2014
Valid To: December 15, 2034
Serial Number: 52381ffae2cd14925c8339f4c6f4e399a287c0c0
```
To which URL is sent the SAML Response? Which field in the SAML Request has been used by the SP to
indicate this URL (to the IdP)?

SAML protocol request:
```xml
<samlp:AuthnRequest AssertionConsumerServiceURL="https://login.didattica.polito.it/Shibboleth.sso/SAML2/POST"
```
SAML protocol response:
```xml
<saml2p:Response Destination="https://login.didattica.polito.it/Shibboleth.sso/SAML2/POST"
```
## 3 SPID

The Sistema Pubblico di Identita Digitale (SPID) addresses e-ID interoperability at the national level. It is`
composed by a set of trusted private and public services that can handle authentication of Italian citizens and
companies for the public administration. SPID credentials are required to access public services, simplifying
the interaction between entities and increasing security of the user authentication. Various credentials can
be used, ranging from traditional ones based on smart-cards (e.g. the citizens’ service card, in short CNS) to
modern systems (e.g. one-time password generators, implemented as smartphone applications or via a hardware
device). SPID components interact with each other using the SAML 2.0 language, for whom a specific profile
has been defined.

### 3.1 SPID exchange

In the supporting files for this lab, you can find four SAML packets belonging to a full round of authentication
with SPID (captured with SAML tracer as shown in Fig. 5).

```
Figure 5: Capture of authentication with SPID on Politecnico di Torino portal.
```
By examining the packets answer to the following points:

What is the chronological sequence of the packets?

1. B: Relying Party Request (https://www.polito.it/shibboleth-sp): _1d7b8de86fcb46ca2ec8f318071637f4 (IssueIstant 17:08)
2. C: IdP Response (https://idp.polito.it/idp/shibboleth) _7569b37d6f3aeaa1f1688e0248b88f01 (IssueIstant 17:10:16) in response to B
3. D: 2nd RP Request (https://spididp.polito.it/shibboleth) _425b4e256833aa087ce6c57c09d443fe (IssueIstant 17:09) in response to C
4. A: 2nd IdP Response (https://identity.sieltecloud.it) _e8cff043154c6b62860039287d654331652fb64784 (IssueIstant 17:10:14) in response to D

B->D->A->C

What is the protocol version?
```xml
B: <samlp:AuthnRequest Version="2.0">
```
What is the adopted binding?
```xml
B: <samlp:AuthnRequest ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
```
Identify the relying party (from where the workflow has started).
```xml
B: <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://www.polito.it/shibboleth-sp</saml:Issuer>
```
Identify the involved identity providers.
```xml
B: <samlp:AuthnRequest Destination="https://idp.polito.it/idp/profile/SAML2/Redirect/SSO"> -> C: <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://idp.polito.it/idp/shibboleth</saml2:Issuer>
D: <samlp:AuthnRequest Destination="https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php"> -> A: <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://identity.sieltecloud.it</saml:Issuer>
```

What is the validity period of the SAML answers?
```xml
A: <saml:Conditions NotBefore="2021-11-17T17:10:14Z"
                         NotOnOrAfter="2021-11-17T17:15:14Z"
                         >
            <saml:AudienceRestriction>
                <saml:Audience>https://spididp.polito.it/shibboleth</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions> 
C:         <saml2:Conditions NotBefore="2021-11-17T17:10:16.653Z"
                          NotOnOrAfter="2021-11-17T17:15:16.653Z"
                          >
            <saml2:AudienceRestriction>
                <saml2:Audience>https://www.polito.it/shibboleth-sp</saml2:Audience>
            </saml2:AudienceRestriction>
        </saml2:Conditions>
```
Who is the subject of the SAML-C certificates?
```xml
<saml2:Subject>
    <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
                  NameQualifier="https://idp.polito.it/idp/shibboleth"
                  SPNameQualifier="https://www.polito.it/shibboleth-sp"
                  >diana.berbecaru@polito.it</saml2:NameID>
    <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData Address="130.192.1.66"
                                       InResponseTo="_1d7b8de86fcb46ca2ec8f318071637f4"
                                       NotOnOrAfter="2021-11-17T17:15:16.653Z"
                                       Recipient="https://www.polito.it/Shibboleth.sso/SAML2/POST"
                                       />
    </saml2:SubjectConfirmation>
</saml2:Subject>
```   
Where do you find information about the user who has been authenticated?
```xml
C:
<saml:Assertion>
    <saml2:AttributeStatement>
        <saml2:Attribute FriendlyName="SPID-Shib-Handler"
                         Name="SPID-Shib-Handler"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >https://spididp.polito.it/Shibboleth.sso</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="SPID-name"
                         Name="SPID-name"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >Diana Gratiela</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="sn"
                         Name="urn:oid:2.5.4.4"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >Berbecaru</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="eduPersonNickname"
                         Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.2"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >diana.berbecaru@polito.it</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="SPID-Shib-Authentication-Instant"
                         Name="SPID-Shib-Authentication-Instant"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >2021-11-17 17:10:14.0</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="o"
                         Name="urn:oid:2.5.4.10"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >Politecnico di Torino</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="givenName"
                         Name="urn:oid:2.5.4.42"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >Diana Gratiela</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="ou"
                         Name="urn:oid:2.5.4.11"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >Docenti</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="SPID-Shib-AuthnContext-Class"
                         Name="SPID-Shib-AuthnContext-Class"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >https://www.spid.gov.it/SpidL2</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="SPID-Shib-Session-ID"
                         Name="SPID-Shib-Session-ID"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >_9ddadbda6dc45aeda9fbe6e724b27b07</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="SPID-Shib-Application-ID"
                         Name="SPID-Shib-Application-ID"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >Spid</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="SPID-Shib-Identity-Provider"
                         Name="SPID-Shib-Identity-Provider"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >https://identity.sieltecloud.it</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="SPID-Shib-Authentication-Method"
                         Name="SPID-Shib-Authentication-Method"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >https://www.spid.gov.it/SpidL2</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="SPID-familyName"
                         Name="SPID-familyName"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >Berbecaru</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="displayName"
                         Name="urn:oid:2.16.840.1.113730.3.1.241"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >Diana Gratiela Berbecaru</saml2:AttributeValue>
        </saml2:Attribute>
    </saml2:AttributeStatement>
</saml:Assertion>
A:
<saml:Assertion>
    <saml2:AttributeStatement>
        <saml2:Attribute FriendlyName="SPID-Shib-Handler"
                         Name="SPID-Shib-Handler"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >https://spididp.polito.it/Shibboleth.sso</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="SPID-name"
                         Name="SPID-name"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >Diana Gratiela</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="sn"
                         Name="urn:oid:2.5.4.4"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >Berbecaru</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="eduPersonNickname"
                         Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.2"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >diana.berbecaru@polito.it</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="SPID-Shib-Authentication-Instant"
                         Name="SPID-Shib-Authentication-Instant"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >2021-11-17 17:10:14.0</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="o"
                         Name="urn:oid:2.5.4.10"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >Politecnico di Torino</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="givenName"
                         Name="urn:oid:2.5.4.42"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >Diana Gratiela</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="ou"
                         Name="urn:oid:2.5.4.11"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >Docenti</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="SPID-Shib-AuthnContext-Class"
                         Name="SPID-Shib-AuthnContext-Class"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >https://www.spid.gov.it/SpidL2</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="SPID-Shib-Session-ID"
                         Name="SPID-Shib-Session-ID"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >_9ddadbda6dc45aeda9fbe6e724b27b07</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="SPID-Shib-Application-ID"
                         Name="SPID-Shib-Application-ID"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >Spid</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="SPID-Shib-Identity-Provider"
                         Name="SPID-Shib-Identity-Provider"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >https://identity.sieltecloud.it</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="SPID-Shib-Authentication-Method"
                         Name="SPID-Shib-Authentication-Method"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >https://www.spid.gov.it/SpidL2</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="SPID-familyName"
                         Name="SPID-familyName"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >Berbecaru</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute FriendlyName="displayName"
                         Name="urn:oid:2.16.840.1.113730.3.1.241"
                         NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                         >
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                  xsi:type="xs:string"
                                  >Diana Gratiela Berbecaru</saml2:AttributeValue>
        </saml2:Attribute>
    </saml2:AttributeStatement>
</saml:Assertion>
```
What do you think is the “high-level” process?

User -> polito.it -> idp.polito.it -> spididp.polito.it/shibboleth -> identity.sieltecloud.it and back.


Do you think the involvment of SPID improves the security?

Yes from the point of view of associating an account to a real person. Yes because spid services should be well protected. No because it increase by a little the possible attack surface.

The authentication is finally successful?

Yes:
```xml
A:
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
    </samlp:Status>
C:
    <saml2p:Status>
        <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
    </saml2p:Status>
```
### 3.2 SPID student authentication (optional)

If you have a SPID digital identity, try to authenticate to “portale della didattica” with SPID and identify the
SAML packets exchanged by your browser. Do you notice any particular difference with the packets exchanged
in the previous point?

B vs 1
```xml
                    AssertionConsumerServiceURL="https://login.didattica.polito.it/Shibboleth.sso/SAML2/POST"
                    AssertionConsumerServiceURL="https://www.polito.it/Shibboleth.sso/SAML2/POST"
```
D=2

In A these informations are missing:
```xml
        <saml:AttributeStatement>
            <saml:Attribute Name="spidCode"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">SIEL20MP74C0N8</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="name"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">Francesco</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="familyName"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">Sattolo</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="fiscalNumber"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">TINIT-STTFNC97P19C627F</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
```
```xml
C: 
<saml2:Attribute FriendlyName="ou"
                 Name="urn:oid:2.5.4.11"
                 NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                 >
    <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                          xsi:type="xs:string"
                          >Docenti</saml2:AttributeValue>
</saml2:Attribute>
vs
4:
<saml2:SubjectLocality Address="188.216.0.126" />

<saml2:AttributeStatement>
<saml2:Attribute FriendlyName="ou"
                 Name="urn:oid:2.5.4.11"
                 NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                 >
    <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                          xsi:type="xs:string"
                          >Studenti</saml2:AttributeValue>
</saml2:Attribute>


<saml2:Attribute FriendlyName="eduPersonAffiliation"
                 Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.1"
                 NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                 >
    <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                          xsi:type="xs:string"
                          >GG-POLITO-Studenti</saml2:AttributeValue>
</saml2:Attribute>

<saml2:Attribute FriendlyName="lCn"
                 Name="urn:oid:1.3.6.1.4.1.2786.10.28"
                 NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                 >
    <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                          xsi:type="xs:string"
                          >S290158</saml2:AttributeValue>
</saml2:Attribute>

<saml2:Attribute FriendlyName="Hivebrite-UID"
                 Name="uid"
                 NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                 >
    <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                          xsi:type="xs:string"
                          >STTFNC97P19C627F</saml2:AttributeValue>
</saml2:Attribute>
<saml2:Attribute FriendlyName="SPID-fiscalNumber"
                 Name="SPID-fiscalNumber"
                 NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                 >
    <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                          xsi:type="xs:string"
                          >TINIT-STTFNC97P19C627F</saml2:AttributeValue>
</saml2:Attribute>
<saml2:Attribute FriendlyName="eduPersonUniqueId"
                 Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.13"
                 NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                 >
    <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                          xsi:type="xs:string"
                          >s290158@studenti.polito.it</saml2:AttributeValue>
</saml2:Attribute>
```
And other personal info..
  
## 4 eIDAS

### 4.1 eIDAS messages

In this exercise you will experiment with the messages exchanged by the eIDAS protocol, which are SAML-
based messages extended to support the attributes defined in eIDAS, such as the ones for the natural person
(FirstName, FamilyName, DateOfBirth, PersonIdentifier, ...).

We suppose to start from a so-calledDemo SP, which will redirect the user to a so-calledDemo IdPfor authen-
tication. Since we are using the eIDAS infrastructure (in test environment), the messages are redirected from
the Demo SP to the Demo IdP via two additional elements: theeIDAS Connectorand theeIDAS Proxy.

Start from the link:(http://demo-sp-test-eid4u.polito.it/. You should see the window shown in
Fig. 6.

```
Figure 6: Initial page of the eIDAS-enabled Demo Service Provider (SP).
```

Select “IT” for the “SP COUNTRY”, then “IT” for the “CITIZEN COUNTRY”. In the part “REQUESTED
CORE ATTRIBUTES”, select “DO NOT REQUEST”. Next, click on “SHOW” close to “NATURAL PERSON
ATTRIBUTES”. You will see a list of attributes. Select as “MANDATORY” the 4 ones indicated with a (*),
that is CurrentFamilyName, CurrentGivenName, DateOfBirth, PersonIdentifier.

Start the SAML-tracer, by clicking on the dedicated icon in the tool bar.

Then, in the Demo-SP page, press “SUBMIT”. You should see a window as illustrated in Fig. 7. In this page
you can see the SAML Request in eIDAS format that has been generated.

```
Figure 7: SAML Request (in eIDAS format) viewed in the Demo SP.
```
Next, press “SUBMIT”. You should see a window as shown in Fig. 8. At the next step you should see a window
as shown in Fig. 9.

```
Figure 8: eIDAS attributes requested.
```
Then, click “NEXT”. At this point you land on the authentication page, as shown in Fig. 10. Click on “Entra
con SPID”, then click on the button “Torsec - Polito SPID Demo IdP” in the page as shown in Fig. 11.

Use the following authentication credentials:

- the username:test


```
Figure 9: User consent page for the eIDAS attributes requested.
```
- the password:test

You should see a page as shown in Fig. 12. In this page you see already the SAML Response that has been
generated, but we will analyze it better with the SAML-tracer later on. Then click “Invia”. You should see a
page with the valued attributes as shown in Fig. 13. Next, click on “SUBMIT”. You will see a page as shown
in Fig. 14, where you can see (already) the SAML Response (encoded in Base64), the encrypted response and
the decrypted SAML Assertion. Then click “SUBMIT, and you should see the last page (as shown in Fig. 15)
illustrating the valued attributes.

```
Figure 10: Authentication page allowing the selection of the Demo IdP.
```
At this point, we will start to analyze all the SAML messages captured in the above workflow with the SAML-
tracer.

If you check theSAML-tracerwindow, you should observe the SAML messages that have been captured by
the browser while executing the above steps (as shown in Fig. 16).

If you select the first row with an orange “SAML”, then click on the “SAML” tab (in the lower part of the
window): you can see the details of the SAML Request sent by the Demo SP to the element called eIDAS Con-
nector (at the urlhttps://connector-test-eid4u.polito.it/EidasNode/ServiceProvider) as shown
in Fig. 17.

```
Logical infrastructure:
user-> demo foreign Service Provider -> foreign eIDAS Connector -> italian eIDAS Service (Proxy) -> Italian Identity (+ Attributes) Provider
demo foreign Service Provider: https://demo-sp-test-eid4u.polito.it/SP
foreign eIDAS Connector: https://connector-test-eid4u.polito.it/EidasNode
italian eIDAS Service (Proxy): https://idp-proxy-test-eid4u.polito.it/idpproxy
Italian Identity (+ Attributes) Provider: https://demo-idp-test-eid4u.polito.it
```
```xml
<saml2p:AuthnRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     xmlns:eidas="http://eidas.europa.eu/saml-extensions"
                     xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                     Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified"
                     Destination="https://connector-test-eid4u.polito.it/EidasNode/ServiceProvider"
                     ForceAuthn="true"
                     ID="_j4xqx1hZmvubqvnC9MLYOtADjNZW0U2OMpaDPwaKc3G--QD_s446VTkQeAIWDNE"
                     IsPassive="false"
                     IssueInstant="2021-11-30T18:54:38.815Z"
                     ProviderName="DEMO-SP"
                     Version="2.0"
                     >
    <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://demo-sp-test-eid4u.polito.it/SP/metadata</saml2:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512" />
            <ds:Reference URI="#_j4xqx1hZmvubqvnC9MLYOtADjNZW0U2OMpaDPwaKc3G--QD_s446VTkQeAIWDNE">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512" />
                <ds:DigestValue>Ja+VTGT51oFvOYz/nRERycNuOEcRguhN7KSTBNelE9GKeKyMNMX7yj6UDGs0TQaXsD/HOUokZCBpIbyVRRiKgg==</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>y9ukmlbXz5SKXgXgS0Eswb1S67ALClVO3g+zYfca09orSAmHq34g7zGPsFWQ1B7jNsUZ3OxWVgcR0SMjVNqV8eRxC407D66XOJ04+n6t1NVtRgxqiZSfFs4Sj7Pb6NdR</ds:SignatureValue>
        <ds:KeyInfo>
            <ds:X509Data>
                <ds:X509Certificate>MIICVTCCAdqgAwIBAgIUIUaO80NcGY7ITfvR/XDn/Rqn+IcwCgYIKoZIzj0EAwIwfDELMAkGA1UE
BhMCSVQxDzANBgNVBAoMBlBvbGl0bzEtMCsGA1UECwwkSXRhbGlhbiBlSUQ0VSBUZXN0aW5nIElu
ZnJhc3RydWN0dXJlMS0wKwYDVQQDDCRJdGFsaWFuIGVJRDRVIERlbW8gU1AgU0FNTCBTaWduYXR1
cmUwHhcNMTkwNTEwMDkzMjU0WhcNMjkwNTA3MDkzMjU0WjB8MQswCQYDVQQGEwJJVDEPMA0GA1UE
CgwGUG9saXRvMS0wKwYDVQQLDCRJdGFsaWFuIGVJRDRVIFRlc3RpbmcgSW5mcmFzdHJ1Y3R1cmUx
LTArBgNVBAMMJEl0YWxpYW4gZUlENFUgRGVtbyBTUCBTQU1MIFNpZ25hdHVyZTB2MBAGByqGSM49
AgEGBSuBBAAiA2IABDkZlY486NLnXerWSxVlEiI1c1xyCjsA9GdAojLSk9AW8LTT0+awXUY+tPXJ
XmpNbuVp1oh1I245iHHQr30bf2EQshMWvUe19om5d1Fn9j1fP1HPECe0CqNfHeVjgb81y6MdMBsw
DAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBsAwCgYIKoZIzj0EAwIDaQAwZgIxANemgIk0CyTmUig+
mMnfxOPfAGnlzPobsR7SBLFSADWCXvYbQbHNLJXmAv486iRpzQIxAKODWbR+ZysM+fVH8le1V78a
LIgs4wTRV/PzBbvZ01lCy/x9GVzkWH/B1jkEQRhbPg==</ds:X509Certificate>
            </ds:X509Data>
        </ds:KeyInfo>
    </ds:Signature>
    <saml2p:Extensions>
        <eidas:SPType>public</eidas:SPType>
        <eidas:RequestedAttributes>
            <eidas:RequestedAttribute FriendlyName="FamilyName"
                                      Name="http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName"
                                      NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                                      isRequired="true"
                                      />
            <eidas:RequestedAttribute FriendlyName="FirstName"
                                      Name="http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName"
                                      NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                                      isRequired="true"
                                      />
            <eidas:RequestedAttribute FriendlyName="DateOfBirth"
                                      Name="http://eidas.europa.eu/attributes/naturalperson/DateOfBirth"
                                      NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                                      isRequired="true"
                                      />
            <eidas:RequestedAttribute FriendlyName="PersonIdentifier"
                                      Name="http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier"
                                      NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                                      isRequired="true"
                                      />
        </eidas:RequestedAttributes>
    </saml2p:Extensions>
    <saml2p:NameIDPolicy AllowCreate="true"
                         Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
                         />
    <saml2p:RequestedAuthnContext Comparison="minimum">
        <saml2:AuthnContextClassRef>http://eidas.europa.eu/LoA/low</saml2:AuthnContextClassRef>
    </saml2p:RequestedAuthnContext>
</saml2p:AuthnRequest>
```
```
Figure 11: Authentication with SPID (in Demo IdP).
```
```
Figure 12: User consent on the valued eIDAS attributes.
```
Respond at the question:

Where is the indication of the URL (of the eIDAS Connector) where the SAML Request will be sent?
```xml
<saml2p:AuthnRequest Destination="https://connector-test-eid4u.polito.it/EidasNode/ServiceProvider">
```
Where are placed in the SAML Request the (natural person) attributes requested?
```xml
<saml2p:Extensions>
        <eidas:SPType>public</eidas:SPType>
        <eidas:RequestedAttributes>
            <eidas:RequestedAttribute FriendlyName="FamilyName"
                                      Name="http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName"
                                      NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                                      isRequired="true"
                                      />
            <eidas:RequestedAttribute FriendlyName="FirstName"
                                      Name="http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName"
                                      NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                                      isRequired="true"
                                      />
            <eidas:RequestedAttribute FriendlyName="DateOfBirth"
                                      Name="http://eidas.europa.eu/attributes/naturalperson/DateOfBirth"
                                      NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                                      isRequired="true"
                                      />
            <eidas:RequestedAttribute FriendlyName="PersonIdentifier"
                                      Name="http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier"
                                      NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                                      isRequired="true"
                                      />
        </eidas:RequestedAttributes>
</saml2p:Extensions>
```
Which algorithm has been used to digitally sign the SAML Request? ecdsa-sha512
```xml
<ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512" />
            <ds:Reference URI="#_j4xqx1hZmvubqvnC9MLYOtADjNZW0U2OMpaDPwaKc3G--QD_s446VTkQeAIWDNE">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512" />
                <ds:DigestValue>Ja+VTGT51oFvOYz/nRERycNuOEcRguhN7KSTBNelE9GKeKyMNMX7yj6UDGs0TQaXsD/HOUokZCBpIbyVRRiKgg==</ds:DigestValue>
            </ds:Reference>
</ds:SignedInfo>
```
```
Figure 13: Valued eIDAS attributes.
```
```
Figure 14: SAML Response (in eIDAS format) viewed in the Demo SP.
```

If you select the last row with an orange “SAML”, the click on the SAML tab (in the lower part of the window):
you can see the details of the SAML Response sent by the eIDAS Connector to the Demo SP, as shown in
Fig. 18.
```xml
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                 xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                 xmlns:eidas="http://eidas.europa.eu/attributes/naturalperson"
                 xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                 Consent="urn:oasis:names:tc:SAML:2.0:consent:obtained"
                 Destination="https://demo-sp-test-eid4u.polito.it/SP/ReturnPage"
                 ID="_qGIQhlm8IiTw27t9D8nZ_zk0o0s2BGpGRSIt96TEk1ERf5ofRSerLTiQXz5ZvSe"
                 InResponseTo="_j4xqx1hZmvubqvnC9MLYOtADjNZW0U2OMpaDPwaKc3G--QD_s446VTkQeAIWDNE"
                 IssueInstant="2021-11-30T18:57:51.661Z"
                 Version="2.0"
                 >
    <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                  Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
                  >https://connector-test-eid4u.polito.it/EidasNode/ConnectorResponderMetadata</saml2:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512" />
            <ds:Reference URI="#_qGIQhlm8IiTw27t9D8nZ_zk0o0s2BGpGRSIt96TEk1ERf5ofRSerLTiQXz5ZvSe">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512" />
                <ds:DigestValue>yNG6yb0q5Z/fbqcmbTpnroWC7lmkAa8rOojYxKa9DEEJhDC1CAP+ocyc2psl3aUwVyNipf3+OyGRYGRjQQL7rg==</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>cCNiUpCRY/2Dz9vAqGhN+iAOWIgOPOKcuYiHxmc8wnSg0l0Psz4k1UjXXzmrAF1zPaTzY7oRJzT2jUTbBz07fB9Nw8QXl7dP5fB3Br/eGHBtAqnS/J65s6/Wz6cuj3VN</ds:SignatureValue>
        <ds:KeyInfo>
            <ds:X509Data>
                <ds:X509Certificate>MIICkTCCAhegAwIBAgIJAMIxa5EPQZdFMAoGCCqGSM49BAMEMIGfMQswCQYDVQQGEwJJVDEtMCsG
A1UECgwkQWdlbnppYSBwZXIgbCdJdGFsaWEgRGlnaXRhbGUgKEFnSUQpMS0wKwYDVQQLDCRJdGFs
aWFuIGVJREFTIFRlc3RpbmcgSW5mcmFzdHJ1Y3R1cmUxMjAwBgNVBAMMKUl0YWxpYW4gZUlEQVMg
Q29ubmVjdG9yIFBBIFNBTUwgU2lnbmF0dXJlMB4XDTE3MTAyNDEyNTUxNloXDTI3MTAyMjEyNTUx
NlowgZ8xCzAJBgNVBAYTAklUMS0wKwYDVQQKDCRBZ2VuemlhIHBlciBsJ0l0YWxpYSBEaWdpdGFs
ZSAoQWdJRCkxLTArBgNVBAsMJEl0YWxpYW4gZUlEQVMgVGVzdGluZyBJbmZyYXN0cnVjdHVyZTEy
MDAGA1UEAwwpSXRhbGlhbiBlSURBUyBDb25uZWN0b3IgUEEgU0FNTCBTaWduYXR1cmUwdjAQBgcq
hkjOPQIBBgUrgQQAIgNiAATOJQ3QEejdnbyXFVCPD/q01Rn4HG3OmVmR8DG/LMzeGaJxMxBXKD60
wDGPuOTxwnEvjIJRN1Cty2qxfPi0ti+5Def6Y5DymTP3z+S3HsBdOsp8hoagd4zMoHBNt5rbb9yj
HTAbMAwGA1UdEwEB/wQCMAAwCwYDVR0PBAQDAgbAMAoGCCqGSM49BAMEA2gAMGUCMQDMkFfDoumm
E8Q4wF79YvmUpnuU0L227TgcL0zgw1Abd70lbfO5mpXdcmD/OOfB1AACMFmsOmxPzurWWwcPRYLq
Qij5SGAPTjOK1xertT5W5xIKP225l8LbVTpYnHEB8ORHag==</ds:X509Certificate>
            </ds:X509Data>
        </ds:KeyInfo>
    </ds:Signature>
    <saml2p:Status xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">
        <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
        <saml2p:StatusMessage>urn:oasis:names:tc:SAML:2.0:status:Success</saml2p:StatusMessage>
    </saml2p:Status>
    <saml2:EncryptedAssertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
        <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
                            Id="_f87ec48526bd50b6cc651309741c4f6b"
                            Type="http://www.w3.org/2001/04/xmlenc#Element"
                            >
            <xenc:EncryptionMethod xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
                                   Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"
                                   />
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
                                   Id="_5bf060e2e7f3155b44fda917d03b8c52"
                                   >
                    <xenc:EncryptionMethod xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
                                           Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
                                           >
                        <ds:DigestMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                                         Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"
                                         />
                    </xenc:EncryptionMethod>
                    <ds:KeyInfo>
                        <ds:X509Data>
                            <ds:X509Certificate>MIIDpTCCAo2gAwIBAgIUGgHekyRLMQGfGKrUaKpP2NqYtNswDQYJKoZIhvcNAQELBQAwfTELMAkG
A1UEBhMCSVQxDzANBgNVBAoMBlBvbGl0bzEtMCsGA1UECwwkSXRhbGlhbiBlSUQ0VSBUZXN0aW5n
IEluZnJhc3RydWN0dXJlMS4wLAYDVQQDDCVJdGFsaWFuIGVJRDRVIERlbW8gU1AgU0FNTCBFbmNy
eXB0aW9uMB4XDTE5MDUxMDA5MzI1NFoXDTI5MDUwNzA5MzI1NFowfTELMAkGA1UEBhMCSVQxDzAN
BgNVBAoMBlBvbGl0bzEtMCsGA1UECwwkSXRhbGlhbiBlSUQ0VSBUZXN0aW5nIEluZnJhc3RydWN0
dXJlMS4wLAYDVQQDDCVJdGFsaWFuIGVJRDRVIERlbW8gU1AgU0FNTCBFbmNyeXB0aW9uMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAroht2Uxh7ZH3/CKs5nX1RWb/ijcoWtsN+DQh5oBm
JpsTzV0QlmFqMn3hoTiQkh9FB6gjivHuUNq5Wzb2FVYUnYlC13vZxh1+uTanPD36fOVJoAwOX0i9
vlmIelH4fMvDMlR+Ff0JZbpMuFd6t1G6ZjKbSDS7Jw518sXP5R3/2UR6MPQefVHdPKGO3pEe5vuw
UCJ6NJX8PTVeT0G8WKDesW17AKPMvswyoB1I3MQYvXtY0xazAcT6Aqzqt1bU+5NSHGbj8TFaHGEj
lm7ZOiJNTgOJQScMWIUfZnQ/ItGmAa82tWmO1n4oKqH0En/bYHORkNsKsT6QXAZNiJeAT7jZwwID
AQABox0wGzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIFIDANBgkqhkiG9w0BAQsFAAOCAQEAEoM2
SR2Y2NuawuIH5P2dbWnkcu9tATloB38N8yhRKbzuyxXXQEyknFZym4sPeQYrj0XoFiDyskj9IC3k
jMTnN2uKRZ6M+exbfgxjnSwFRdXx50ZJLqWPuE1zKnIZiYfykWFwlHAWdKj9Nex/QXkH4L8wjIGc
W8mu2H9mc7djBD2se+4jMrc32Y5/fr+V1MGXzb+6kpWOhoSpXpcSwd+9Z/c6QyGQpFYT7iPesiq5
wzBy2J1H4yqlnmb/UnanEPxgLGFhmmqoUCxmyvsP3U4h+CD0wGXauoXEOZrlN8JbV5K8rfyvM3H8
YKfIc1e6nmBpEDaPL40PCKrhGjWvbYOsjw==</ds:X509Certificate>
                        </ds:X509Data>
                    </ds:KeyInfo>
                    <xenc:CipherData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
                        <xenc:CipherValue>VNMxeSkB1Sodq/Nc8GnGWv83yO6jW5c+BDQ0GNdAmmon8ewMqSMIt/ncy/wHZ14yBsonjt96t8OBOGFey9ngCHdrjLTsrrhPSEzuu4rjyFRTXGH1gF8WLue4G14UOV0Vsw3VeE9St9yJFMBlDFaA3qVj0zHN8ettsxrbgGBzZrWuT9cSTc8R+BPsoiKb0t3OssSdYirabGPMEK7KaK23wGeCd8HSN/M4v8eRC2Eoq05J+E+0QR/DlbcmUUnc1zvER5eOZewAld41dn+gBJ6z2xr7yaXGteaGIeUCzvy2nmnOthjH7p6GkarmkjGKUeM549X7KccVNJJnbvpuuv52xA==</xenc:CipherValue>
                    </xenc:CipherData>
                </xenc:EncryptedKey>
            </ds:KeyInfo>
            <xenc:CipherData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
                <xenc:CipherValue>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</xenc:CipherValue>
            </xenc:CipherData>
        </xenc:EncryptedData>
    </saml2:EncryptedAssertion>
</saml2p:Response>
```
The SAML Response from the eIDAS Connector to the demo SP conveys an <saml2:EncryptedAssertion>
element. In this element, there is an <ds:X509Certificate>.

Respond to the question: In your opinion, for what purpose is used the above certificate?
```
Encryption certificate: certificate used to digitally sign the encrypted key which will be used to decrypt the data?

Common Name: Italian eID4U Demo SP SAML Encryption
Organization: Polito
Organization Unit: Italian eID4U Testing Infrastructure
Country: IT
Valid From: May 10, 2019
Valid To: May 7, 2029
Issuer: Italian eID4U Demo SP SAML Encryption, Polito
Serial Number: 1a01de93244b31019f18aad468aa4fd8da98b4db
```

```
Figure 15: Final page of eIDAS-enabled Demo SP.
```
```
Figure 16: SAML messages captured in the SAML-tracer.
```
### 4.2 eIDAS (SAML) Metadata

To securely interoperate, all the actors in the above workflow (Demo SP, eIDAS Connector, eIDAS Proxy and
the demo IdP) must share SAML metadata.

For simplicity, we will analyze only the SAML metadata for the communication between the demo SP and the
eIDAS Connector, where the demo SP acts as an SP (in federation) and the eIDAS Connector acts an IdP (in
a federation). Note however that SAML metadata must exist also for the communication between the eIDAS
Connector and the eIDAS Proxy, and for the communication between the eIDAS Proxy and the Demo IdP.

The SAML Metadata of the Demo SP is available at the URL:

https://demo-sp-test-eid4u.polito.it/SP/metadata
```xml
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://demo-sp-test-eid4u.polito.it/SP/metadata" validUntil="2021-12-02T14:31:04.395Z">
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"/>
<ds:Reference URI="">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
<ds:DigestValue>579xUP+GK6W3xO98PLd49/MzjimvgJZz/Q7ZerTFJWEVB04rmrXU/1y2Q0LtTDIdsIEAMExoloh8dN5nmWcmVA==</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue>2BF08JJAm/NbK0XNqqH0tlIgvTC3n/slXY0jANNErgCnzHx2je9ZQc9k9IYoU6Jkwm77SH6zXRQTa2iiyqQkIc4BkrpgeK6YB1f7iJcRaUBo+ZQHEAg2DNV+oBNSnWbw</ds:SignatureValue>
<ds:KeyInfo>
<ds:X509Data>
<ds:X509Certificate>MIICaDCCAe6gAwIBAgIUK8gJyEO2ADMjbNQVYqZ+CcovuEgwCgYIKoZIzj0EAwIwgYUxCzAJBgNV BAYTAklUMQ8wDQYDVQQKDAZQb2xpdG8xLTArBgNVBAsMJEl0YWxpYW4gZUlENFUgVGVzdGluZyBJ bmZyYXN0cnVjdHVyZTE2MDQGA1UEAwwtSXRhbGlhbiBlSUQ0VSBEZW1vIFNQIFNBTUwgTWV0YWRh dGEgU2lnbmF0dXJlMB4XDTE5MDUxMDA5MzI1NFoXDTI5MDUwNzA5MzI1NFowgYUxCzAJBgNVBAYT AklUMQ8wDQYDVQQKDAZQb2xpdG8xLTArBgNVBAsMJEl0YWxpYW4gZUlENFUgVGVzdGluZyBJbmZy YXN0cnVjdHVyZTE2MDQGA1UEAwwtSXRhbGlhbiBlSUQ0VSBEZW1vIFNQIFNBTUwgTWV0YWRhdGEg U2lnbmF0dXJlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEK2gShfChIOdiy/akRQQmKnHjIQW5r3U+ FjqR1WwsHkKr7V1/2HuyV7baXLhpHMbe+mIE92btYIdr6NVq2NTd/TG6oaCl2pg4V2iVsBd+fNga ALj81M1i2plVyaSvJNByox0wGzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIGwDAKBggqhkjOPQQD AgNoADBlAjA+Xmv31CQ6HgQrgHaE+X/oTqA4s7eGys/PW+YmbuEWLuCl73gN4VrG5QOfc9tJBbIC MQDxpK0qpIU6Dtk6j75ELQ5PZqXRFh16Uyhk54eq1mqiz1VzRrz91fprwP+6n6Jdqag=</ds:X509Certificate>
</ds:X509Data>
</ds:KeyInfo>
</ds:Signature>
<md:Extensions>
<eidas:SPType xmlns:eidas="http://eidas.europa.eu/saml-extensions">public</eidas:SPType>
<alg:DigestMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="http://www.w3.org/2001/04/xmldsig-more#sha384"/>
<alg:DigestMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
<alg:DigestMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"/>
<alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>
<alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160"/>
<alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"/>
<alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"/>
<alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1"/>
<alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"/>
</md:Extensions>
<md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<md:KeyDescriptor use="signing">
<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:X509Data>
<ds:X509Certificate>MIICVTCCAdqgAwIBAgIUIUaO80NcGY7ITfvR/XDn/Rqn+IcwCgYIKoZIzj0EAwIwfDELMAkGA1UE BhMCSVQxDzANBgNVBAoMBlBvbGl0bzEtMCsGA1UECwwkSXRhbGlhbiBlSUQ0VSBUZXN0aW5nIElu ZnJhc3RydWN0dXJlMS0wKwYDVQQDDCRJdGFsaWFuIGVJRDRVIERlbW8gU1AgU0FNTCBTaWduYXR1 cmUwHhcNMTkwNTEwMDkzMjU0WhcNMjkwNTA3MDkzMjU0WjB8MQswCQYDVQQGEwJJVDEPMA0GA1UE CgwGUG9saXRvMS0wKwYDVQQLDCRJdGFsaWFuIGVJRDRVIFRlc3RpbmcgSW5mcmFzdHJ1Y3R1cmUx LTArBgNVBAMMJEl0YWxpYW4gZUlENFUgRGVtbyBTUCBTQU1MIFNpZ25hdHVyZTB2MBAGByqGSM49 AgEGBSuBBAAiA2IABDkZlY486NLnXerWSxVlEiI1c1xyCjsA9GdAojLSk9AW8LTT0+awXUY+tPXJ XmpNbuVp1oh1I245iHHQr30bf2EQshMWvUe19om5d1Fn9j1fP1HPECe0CqNfHeVjgb81y6MdMBsw DAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBsAwCgYIKoZIzj0EAwIDaQAwZgIxANemgIk0CyTmUig+ mMnfxOPfAGnlzPobsR7SBLFSADWCXvYbQbHNLJXmAv486iRpzQIxAKODWbR+ZysM+fVH8le1V78a LIgs4wTRV/PzBbvZ01lCy/x9GVzkWH/B1jkEQRhbPg==</ds:X509Certificate>
</ds:X509Data>
</ds:KeyInfo>
</md:KeyDescriptor>
<md:KeyDescriptor use="encryption">
<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:X509Data>
<ds:X509Certificate>MIIDpTCCAo2gAwIBAgIUGgHekyRLMQGfGKrUaKpP2NqYtNswDQYJKoZIhvcNAQELBQAwfTELMAkG A1UEBhMCSVQxDzANBgNVBAoMBlBvbGl0bzEtMCsGA1UECwwkSXRhbGlhbiBlSUQ0VSBUZXN0aW5n IEluZnJhc3RydWN0dXJlMS4wLAYDVQQDDCVJdGFsaWFuIGVJRDRVIERlbW8gU1AgU0FNTCBFbmNy eXB0aW9uMB4XDTE5MDUxMDA5MzI1NFoXDTI5MDUwNzA5MzI1NFowfTELMAkGA1UEBhMCSVQxDzAN BgNVBAoMBlBvbGl0bzEtMCsGA1UECwwkSXRhbGlhbiBlSUQ0VSBUZXN0aW5nIEluZnJhc3RydWN0 dXJlMS4wLAYDVQQDDCVJdGFsaWFuIGVJRDRVIERlbW8gU1AgU0FNTCBFbmNyeXB0aW9uMIIBIjAN BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAroht2Uxh7ZH3/CKs5nX1RWb/ijcoWtsN+DQh5oBm JpsTzV0QlmFqMn3hoTiQkh9FB6gjivHuUNq5Wzb2FVYUnYlC13vZxh1+uTanPD36fOVJoAwOX0i9 vlmIelH4fMvDMlR+Ff0JZbpMuFd6t1G6ZjKbSDS7Jw518sXP5R3/2UR6MPQefVHdPKGO3pEe5vuw UCJ6NJX8PTVeT0G8WKDesW17AKPMvswyoB1I3MQYvXtY0xazAcT6Aqzqt1bU+5NSHGbj8TFaHGEj lm7ZOiJNTgOJQScMWIUfZnQ/ItGmAa82tWmO1n4oKqH0En/bYHORkNsKsT6QXAZNiJeAT7jZwwID AQABox0wGzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIFIDANBgkqhkiG9w0BAQsFAAOCAQEAEoM2 SR2Y2NuawuIH5P2dbWnkcu9tATloB38N8yhRKbzuyxXXQEyknFZym4sPeQYrj0XoFiDyskj9IC3k jMTnN2uKRZ6M+exbfgxjnSwFRdXx50ZJLqWPuE1zKnIZiYfykWFwlHAWdKj9Nex/QXkH4L8wjIGc W8mu2H9mc7djBD2se+4jMrc32Y5/fr+V1MGXzb+6kpWOhoSpXpcSwd+9Z/c6QyGQpFYT7iPesiq5 wzBy2J1H4yqlnmb/UnanEPxgLGFhmmqoUCxmyvsP3U4h+CD0wGXauoXEOZrlN8JbV5K8rfyvM3H8 YKfIc1e6nmBpEDaPL40PCKrhGjWvbYOsjw==</ds:X509Certificate>
</ds:X509Data>
</ds:KeyInfo>
<md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes192-gcm"/>
<md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
<md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>
</md:KeyDescriptor>
<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://demo-sp-test-eid4u.polito.it/SP/ReturnPage" index="0" isDefault="true"/>
</md:SPSSODescriptor>
<md:Organization>
<md:OrganizationName xml:lang="en">DEMO-SP</md:OrganizationName>
<md:OrganizationDisplayName xml:lang="en">Sample SP</md:OrganizationDisplayName>
<md:OrganizationURL xml:lang="en">https://sp.sample/info</md:OrganizationURL>
</md:Organization>
<md:ContactPerson contactType="support">
<md:Company>eIDAS SP Operator</md:Company>
<md:GivenName>Jean-Michel</md:GivenName>
<md:SurName>Folon</md:SurName>
<md:EmailAddress>contact.support@sp.eu</md:EmailAddress>
<md:TelephoneNumber>+555 123456</md:TelephoneNumber>
</md:ContactPerson>
<md:ContactPerson contactType="technical">
<md:Company>eIDAS SP Operator</md:Company>
<md:GivenName>Alphonse</md:GivenName>
<md:SurName>Michaux</md:SurName>
<md:EmailAddress>contact.support@sp.eu</md:EmailAddress>
<md:TelephoneNumber>+555 123456</md:TelephoneNumber>
</md:ContactPerson>
</md:EntityDescriptor>
```
The SAML Metadata of the eIDAS Connector necessary for the communication with the Demo SP is available


```
Figure 17: SAML Request captured in the SAML-tracer, sent from the Demo SP to the eIDAS Connector.
```
```
Figure 18: SAML Response captured in the SAML-tracer, sent from the eIDAS Connector to the Demo SP.
```
at the URL:

https://connector-test-eid4u.polito.it/EidasNode/ConnectorResponderMetadata.
```xml
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://demo-sp-test-eid4u.polito.it/SP/metadata" validUntil="2021-12-02T14:31:04.395Z">
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"/>
<ds:Reference URI="">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
<ds:DigestValue>579xUP+GK6W3xO98PLd49/MzjimvgJZz/Q7ZerTFJWEVB04rmrXU/1y2Q0LtTDIdsIEAMExoloh8dN5nmWcmVA==</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue>2BF08JJAm/NbK0XNqqH0tlIgvTC3n/slXY0jANNErgCnzHx2je9ZQc9k9IYoU6Jkwm77SH6zXRQTa2iiyqQkIc4BkrpgeK6YB1f7iJcRaUBo+ZQHEAg2DNV+oBNSnWbw</ds:SignatureValue>
<ds:KeyInfo>
<ds:X509Data>
<ds:X509Certificate>MIICaDCCAe6gAwIBAgIUK8gJyEO2ADMjbNQVYqZ+CcovuEgwCgYIKoZIzj0EAwIwgYUxCzAJBgNV BAYTAklUMQ8wDQYDVQQKDAZQb2xpdG8xLTArBgNVBAsMJEl0YWxpYW4gZUlENFUgVGVzdGluZyBJ bmZyYXN0cnVjdHVyZTE2MDQGA1UEAwwtSXRhbGlhbiBlSUQ0VSBEZW1vIFNQIFNBTUwgTWV0YWRh dGEgU2lnbmF0dXJlMB4XDTE5MDUxMDA5MzI1NFoXDTI5MDUwNzA5MzI1NFowgYUxCzAJBgNVBAYT AklUMQ8wDQYDVQQKDAZQb2xpdG8xLTArBgNVBAsMJEl0YWxpYW4gZUlENFUgVGVzdGluZyBJbmZy YXN0cnVjdHVyZTE2MDQGA1UEAwwtSXRhbGlhbiBlSUQ0VSBEZW1vIFNQIFNBTUwgTWV0YWRhdGEg U2lnbmF0dXJlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEK2gShfChIOdiy/akRQQmKnHjIQW5r3U+ FjqR1WwsHkKr7V1/2HuyV7baXLhpHMbe+mIE92btYIdr6NVq2NTd/TG6oaCl2pg4V2iVsBd+fNga ALj81M1i2plVyaSvJNByox0wGzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIGwDAKBggqhkjOPQQD AgNoADBlAjA+Xmv31CQ6HgQrgHaE+X/oTqA4s7eGys/PW+YmbuEWLuCl73gN4VrG5QOfc9tJBbIC MQDxpK0qpIU6Dtk6j75ELQ5PZqXRFh16Uyhk54eq1mqiz1VzRrz91fprwP+6n6Jdqag=</ds:X509Certificate>
</ds:X509Data>
</ds:KeyInfo>
</ds:Signature>
<md:Extensions>
<eidas:SPType xmlns:eidas="http://eidas.europa.eu/saml-extensions">public</eidas:SPType>
<alg:DigestMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="http://www.w3.org/2001/04/xmldsig-more#sha384"/>
<alg:DigestMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
<alg:DigestMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"/>
<alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>
<alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160"/>
<alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"/>
<alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"/>
<alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1"/>
<alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"/>
</md:Extensions>
<md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<md:KeyDescriptor use="signing">
<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:X509Data>
<ds:X509Certificate>MIICVTCCAdqgAwIBAgIUIUaO80NcGY7ITfvR/XDn/Rqn+IcwCgYIKoZIzj0EAwIwfDELMAkGA1UE BhMCSVQxDzANBgNVBAoMBlBvbGl0bzEtMCsGA1UECwwkSXRhbGlhbiBlSUQ0VSBUZXN0aW5nIElu ZnJhc3RydWN0dXJlMS0wKwYDVQQDDCRJdGFsaWFuIGVJRDRVIERlbW8gU1AgU0FNTCBTaWduYXR1 cmUwHhcNMTkwNTEwMDkzMjU0WhcNMjkwNTA3MDkzMjU0WjB8MQswCQYDVQQGEwJJVDEPMA0GA1UE CgwGUG9saXRvMS0wKwYDVQQLDCRJdGFsaWFuIGVJRDRVIFRlc3RpbmcgSW5mcmFzdHJ1Y3R1cmUx LTArBgNVBAMMJEl0YWxpYW4gZUlENFUgRGVtbyBTUCBTQU1MIFNpZ25hdHVyZTB2MBAGByqGSM49 AgEGBSuBBAAiA2IABDkZlY486NLnXerWSxVlEiI1c1xyCjsA9GdAojLSk9AW8LTT0+awXUY+tPXJ XmpNbuVp1oh1I245iHHQr30bf2EQshMWvUe19om5d1Fn9j1fP1HPECe0CqNfHeVjgb81y6MdMBsw DAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBsAwCgYIKoZIzj0EAwIDaQAwZgIxANemgIk0CyTmUig+ mMnfxOPfAGnlzPobsR7SBLFSADWCXvYbQbHNLJXmAv486iRpzQIxAKODWbR+ZysM+fVH8le1V78a LIgs4wTRV/PzBbvZ01lCy/x9GVzkWH/B1jkEQRhbPg==</ds:X509Certificate>
</ds:X509Data>
</ds:KeyInfo>
</md:KeyDescriptor>
<md:KeyDescriptor use="encryption">
<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:X509Data>
<ds:X509Certificate>MIIDpTCCAo2gAwIBAgIUGgHekyRLMQGfGKrUaKpP2NqYtNswDQYJKoZIhvcNAQELBQAwfTELMAkG A1UEBhMCSVQxDzANBgNVBAoMBlBvbGl0bzEtMCsGA1UECwwkSXRhbGlhbiBlSUQ0VSBUZXN0aW5n IEluZnJhc3RydWN0dXJlMS4wLAYDVQQDDCVJdGFsaWFuIGVJRDRVIERlbW8gU1AgU0FNTCBFbmNy eXB0aW9uMB4XDTE5MDUxMDA5MzI1NFoXDTI5MDUwNzA5MzI1NFowfTELMAkGA1UEBhMCSVQxDzAN BgNVBAoMBlBvbGl0bzEtMCsGA1UECwwkSXRhbGlhbiBlSUQ0VSBUZXN0aW5nIEluZnJhc3RydWN0 dXJlMS4wLAYDVQQDDCVJdGFsaWFuIGVJRDRVIERlbW8gU1AgU0FNTCBFbmNyeXB0aW9uMIIBIjAN BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAroht2Uxh7ZH3/CKs5nX1RWb/ijcoWtsN+DQh5oBm JpsTzV0QlmFqMn3hoTiQkh9FB6gjivHuUNq5Wzb2FVYUnYlC13vZxh1+uTanPD36fOVJoAwOX0i9 vlmIelH4fMvDMlR+Ff0JZbpMuFd6t1G6ZjKbSDS7Jw518sXP5R3/2UR6MPQefVHdPKGO3pEe5vuw UCJ6NJX8PTVeT0G8WKDesW17AKPMvswyoB1I3MQYvXtY0xazAcT6Aqzqt1bU+5NSHGbj8TFaHGEj lm7ZOiJNTgOJQScMWIUfZnQ/ItGmAa82tWmO1n4oKqH0En/bYHORkNsKsT6QXAZNiJeAT7jZwwID AQABox0wGzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIFIDANBgkqhkiG9w0BAQsFAAOCAQEAEoM2 SR2Y2NuawuIH5P2dbWnkcu9tATloB38N8yhRKbzuyxXXQEyknFZym4sPeQYrj0XoFiDyskj9IC3k jMTnN2uKRZ6M+exbfgxjnSwFRdXx50ZJLqWPuE1zKnIZiYfykWFwlHAWdKj9Nex/QXkH4L8wjIGc W8mu2H9mc7djBD2se+4jMrc32Y5/fr+V1MGXzb+6kpWOhoSpXpcSwd+9Z/c6QyGQpFYT7iPesiq5 wzBy2J1H4yqlnmb/UnanEPxgLGFhmmqoUCxmyvsP3U4h+CD0wGXauoXEOZrlN8JbV5K8rfyvM3H8 YKfIc1e6nmBpEDaPL40PCKrhGjWvbYOsjw==
</ds:X509Data>
</ds:KeyInfo>
<md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes192-gcm"/>
<md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
<md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>
</md:KeyDescriptor>
<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://demo-sp-test-eid4u.polito.it/SP/ReturnPage" index="0" isDefault="true"/>
</md:SPSSODescriptor>
<md:Organization>
<md:OrganizationName xml:lang="en">DEMO-SP</md:OrganizationName>
<md:OrganizationDisplayName xml:lang="en">Sample SP</md:OrganizationDisplayName>
<md:OrganizationURL xml:lang="en">https://sp.sample/info</md:OrganizationURL>
</md:Organization>
<md:ContactPerson contactType="support">
<md:Company>eIDAS SP Operator</md:Company>
<md:GivenName>Jean-Michel</md:GivenName>
<md:SurName>Folon</md:SurName>
<md:EmailAddress>contact.support@sp.eu</md:EmailAddress>
<md:TelephoneNumber>+555 123456</md:TelephoneNumber>
</md:ContactPerson>
<md:ContactPerson contactType="technical">
<md:Company>eIDAS SP Operator</md:Company>
<md:GivenName>Alphonse</md:GivenName>
<md:SurName>Michaux</md:SurName>
<md:EmailAddress>contact.support@sp.eu</md:EmailAddress>
<md:TelephoneNumber>+555 123456</md:TelephoneNumber>
</md:ContactPerson>
</md:EntityDescriptor>
```
We will analyze next which part(s) of these two SAML Metadata files are used:

1. when the Demo SP sends the SAML Request to the eIDAS Connector.
2. when the eIDAS Connector sends back the SAML Response to the demo SP.


Open the SAML Metadata of the Demo SP and analyze its content:

1. You should observe that the file starts with anEntityDescriptorelement, having the entityID=”https://demo-
sp-test-eid4u.polito.it/SP/metadata”. The entityID is like an identifier for the demo SP. In fact, you can see it
in the<saml2:Issuer>element of the SAML Request of the Demo SP (<saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://demo-sp-test-eid4u.polito.it/SP/metadata</saml2:Issuer>), which is sent from the Demo SP to the eIDAS Con-
nector. Note also that there is avalidUntil=”..”’ which indicates the time limit until the SAML metadata is
valid.
2. Next, you should see a<ds:Signature>element. This indicates that the SAML Metadata file (of the
Demo SP) is digitally signed. Moreover, it indicates also which X.509 certificate needs to be used to verify
the signature on the SAML Metadata file. The certificate is found in<ds:X509Certificate>element. Note
that the eIDAS Connector must obtain this certificate through an OOB manner and configure it in a (local) trust
store.
```
Common Name: Italian eID4U Demo SP SAML Metadata Signature<ds:X509Certificate>
Organization: Polito
Organization Unit: Italian eID4U Testing Infrastructure
Country: IT
Valid From: May 10, 2019
Valid To: May 7, 2029
Issuer: Italian eID4U Demo SP SAML Metadata Signature, Polito
Serial Number: 2bc809c843b60033236cd41562a67e09ca2fb848
```
3. In the<md:SPSSODescriptor>you should note the element<md:KeyDescriptor use="signing”>.
This element contains an X.509 certificate which must be used by the eIDAS Connector to verify the signature
on the SAML Requests received from the demo SP.
```
Common Name: Italian eID4U Demo SP SAML Signature
Organization: Polito
Organization Unit: Italian eID4U Testing Infrastructure
Country: IT
Valid From: May 10, 2019
Valid To: May 7, 2029
Issuer: Italian eID4U Demo SP SAML Signature, Polito
Serial Number: 21468ef3435c198ec84dfbd1fd70e7fd1aa7f887
```
In fact, if you check (in the SAML-tracer) the SAML Request sent by the demo SP to the eIDAS Connector (that
is the first raw tagged with an orange “SAML”), you should note that there is a<ds:X509Certificate>ele-
ment which has the same value with the one indicated in the<ds:X509Certificate>in the<md:KeyDescriptor
use="signing">of the Demo-SP SAML metadata file, i.e ”MIICVTCCAdqgAwIB...”. Note that the certifi-
cate is Base 64 encoded.

4. In the<md:SPSSODescriptor>you should note the element<md:KeyDescriptor use="encryption”>.
This element contains an X.509certificate which must be used by the eIDAS Connector to protect the assertion
sent in the SAML Response to the demo SP.
```
Common Name: Italian eID4U Demo SP SAML Encryption
Organization: Polito
Organization Unit: Italian eID4U Testing Infrastructure
Country: IT
Valid From: May 10, 2019
Valid To: May 7, 2029
Issuer: Italian eID4U Demo SP SAML Encryption, Polito
Serial Number: 1a01de93244b31019f18aad468aa4fd8da98b4db
```
In fact, if you check in the SAML-tracer the SAML Response sent by the eIDAS Connector to the demo SP
(that is the last raw tagged with an orange “SAML”), you should see an<saml2:EncryptedAssertion>el-
ement. In this element, the<ds:X509Certificate>contains a certificate whose value is equal to the one in
the element<md:KeyDescriptor use="encryption">of the demo SP SAML Metadata, i.e. ”MIIDpTC-
CAo2g..”. Note that the certificate is Base 64 encoded.

Respond to the following questions.

Which algorithms are supported by the Demo SP for the decryption of the encryption assertion sent to him by
the eIDAS Connector? Which element in the Demo SP’s SAML Metadata contains such indication?

```xml
<md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes192-gcm"/>
<md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
<md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>
```
Which encryption algorithms has been actually used by the eIDAS Connector for the protection of the eIDAS
Response sent to the demo-SP?

```xml
<xenc:EncryptionMethod xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
                                   Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"
                                   />
```
5. Note also theAssertionConsumerServiceelement:

<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://demo-sp-test-eid4u.polito.it/SP/ReturnPage">

What is its meaning?

```
The user, after the eIDas authentication procedure have been completed, will need to do a post request to the provided Location.
```

Now open the SAML Metadata file of the eIDAS Connector (at the url mentioned above) and respond to the
questions:

What is meaning of the X.509 certificate in the<md:KeyDescriptor use="signing">? Indicate in which
message (captured with SAML-tracer) you find this certificate.

```
Common Name: Italian eIDAS Connector PA SAML Signature
Organization: Agenzia per l'Italia Digitale (AgID)
Organization Unit: Italian eIDAS Testing Infrastructure
Country: IT
Valid From: October 24, 2017
Valid To: October 22, 2027
Issuer: Italian eIDAS Connector PA SAML Signature, Agenzia per l'Italia Digitale (AgID)
Serial Number: c2316b910f419745
```
This element contains an X.509 certificate which must be used by the Demo SP to verify the signature
on the SAML Requests received from the eIDAS Connector.
It can be found in the final message destined to the SP in the field:
```xml
<ds:KeyInfo>
            <ds:X509Data>
                <ds:X509Certificate>
```

What is the meaning of the X.509 certificate in the<md:KeyDescriptor use="encryption">? Indicate in
which message (captured withSAML-tracer) you find this certificate.
```xml
<md:KeyDescriptor use="encryption">
```
```
Common Name: Italian eID4U Demo SP SAML Encryption
Organization: Polito
Organization Unit: Italian eID4U Testing Infrastructure
Country: IT
Valid From: May 10, 2019
Valid To: May 7, 2029
Issuer: Italian eID4U Demo SP SAML Encryption, Polito
Serial Number: 1a01de93244b31019f18aad468aa4fd8da98b4db
```
This element contains an X.509certificate which must be used by the demo SP to protect the assertion
sent in the SAML Response to the eIDAS Connector.


Refresh the web browser page in which you see the SAML Metadata of the Demo SP (or of the eIDAS Con-
nector). Do you note any difference? Can you figure out why?
```xml
< <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://demo-sp-test-eid4u.polito.it/SP/metadata" validUntil="2021-12-02T15:22:30.593Z">
---
> <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://demo-sp-test-eid4u.polito.it/SP/metadata" validUntil="2021-12-02T14:31:04.395Z">
13c12
< <ds:DigestValue>ViD6xDxB7V0gPQ2j1JmTJatZsZZQuvsyk/F9U4SGR8bOFi7pgw27Q1zX++DiUU2x4c+h5mpeXL+3lH06vP9hPQ==</ds:DigestValue>
---
> <ds:DigestValue>579xUP+GK6W3xO98PLd49/MzjimvgJZz/Q7ZerTFJWEVB04rmrXU/1y2Q0LtTDIdsIEAMExoloh8dN5nmWcmVA==</ds:DigestValue>
16c15
< <ds:SignatureValue>h9ddGuK+/30cCYxLjPrUDKqWl91ftjnMTjbvqBiqUsxPARmRSPw/fWPM26mf7p54194GWf9RciigR0AYSxEULF4waHox3m2r83p2K3z1tWhGJRR2iKfjSxZ+AbMlG6R3</ds:SignatureValue>
---
> <ds:SignatureValue>2BF08JJAm/NbK0XNqqH0tlIgvTC3n/slXY0jANNErgCnzHx2je9ZQc9k9IYoU6Jkwm77SH6zXRQTa2iiyqQkIc4BkrpgeK6YB1f7iJcRaUBo+ZQHEAg2DNV+oBNSnWbw</ds:SignatureValue>
```
## 5 OpenID Connect

OpenID Connect(OIDC) is a protocol built on top ofOAuth2to provide a complete solution for both authen-
tication and authorization. It allows OAuth2 clients (usually, a service provider from end-user/resource owner
perspective) to check the identity of an end-user entity thanks to an authentication performed on a third com-
ponent, in order to authorize the OAuth2 consent. A nice security outcome, is that the OAuth2 client does not
need to store or manage any password. In fact, the user delegates authority for the OAuth2 client application
(i.e. application server from end user perspective) to access some protected resource on their behalf. Such
a resource might be anything (e.g. Google profile information, Facebook friend list). Delegating access to
this resource gives the client application the means of verifying the end-user’s identity without ever seeing his
credentials

The OAuth2 standard allows for a number of differentflows(i.e. message exchange schemas). The most
used, and suggested for its security properties, is theAuthZ Code Grantone. In this flow the response to the
Relaying party is not in the form of the actual OAuth2 ticket (i.e., the credentials in OAuth2 terminology), but
in the form of a “code”, not containing the user credentials but allowing the relying party to check if the end-
user has been successfully authenticated. In fact, the presence of a OAuth2 value of type “tocken” or “code”
allows to distinguish between theimplicitflow (a simpler but more insecure one, which allow the end-user
credential to flow among the actors, which should be always avoided) and the preferred Authz Code Grant
flow. In the following scenario, the AuthZ code is delivered by an AuthZ Server. The AuthZ server acts like
a broker between the client and the resource owner. The server authenticates the resource owner and obtains
authorization before redirecting it back to the client with the AuthZ code. As pointed out, the resource owner
only authenticates versus the authorization server.

A brief description of this flow follows:


1. The flow starts with the client that builds the URI with the necessary parameters and redirects the user
    on the AuthZ Server dedicated endpoint. The user logs in and accepts/denies to give authorization to the
    client. Peculiar to OIDC scenario, a subset of the following OpenID Connect scopes is requested:
       - openid: it means that the client is making an OIDC request
       - profile: this requests access to the user’s profile information
       - email: this requests access to the user’s e-mail address
       - address: this requests access to the user’s address information
       - phone: this requests access to the user’s phone number
    the presence of them (in particularopenidis an indication of an ongoing OIDC exchange
2. If the user accepts, the AuthZ Server redirects the user back to the client with an AuthZ code. OIDC
    defines optional parameters (e.g. nonce,prompt) for managing the authentication. The server check
    the parameters and in case of a valid login request, the user is presented with the usual consent screen.
    The user MAY authorizes the relying party (OAuth2 client) to authenticate it. In this case, he will be
    redirected back to the client application via the redirection endpoint, along with the authorization code.
3. the client (without user intervention) requests the access token by sending the token request with the
    AuthZ code to the AuthZ Server. The server can verify the correct relation of the AuthZ Code and the
    OIDC authentication request by checking the clientid. It builds up theidtokenthat is a JWT which
    contains private claims about the authenticated user (e.g.name) and other claims like, for exampleiss
    that represents the issuer andsubthat represents a unique identifier of the authenticated user.
4. The AuthZ Server respond with the access token, as the propertyaccesstoken). However, it will
    contain the additional token known as anID token(as the propertyidtoken). The client MUST
    decrypt the token by using the specified cryptographic operations contained in the JOSE Header, validate
    the JWT ID Token, and retrieve the claims (e.g. the user and the issuer. Finally, the user identity provided
    by the AuthZ Server is verified. Now the client can use the access token for accessing resources on a
    dedicated resource server.

### 5.1 Example of an OpenID Connect flow

In the following is described a simple example of the flow. The scenario is composed of a user (web) application
listening on http://localhost:9090(Fig. 19), and an application server (also known as relying party and
OAuth2 client) listening onhttp://localhost:8080.
User-Agent = http://localhost:9090
OID Client = http://localhost:8080
OP = Server Google

In this example the goal is just to retrieve (only read) basic user information (name and email, that in the
OAuth2 flow can be identified in thescopeparameter) from the Google profile by using the OIDC on top of
the Authorization Grant flow.

1. From the “Login” page (onhttp://localhost:9090) (Fig. 20), the user clicks on “Login With Google”
    and a first redirection starts with the requested parameters. The capture of the HTTP header is present in
    theOIDC-1.httpfile. Analising the capture, are you able to identify where the redirection will go, i.e.
    the application server endpoint?

```
User-Agent -> Client : redirect_uri is the URL where the User-Agent will later be redirected

10.6.  Authorization Code Redirection URI Manipulation
   When requesting authorization using the authorization code grant
   type, the OIDClient can specify a redirection URI via the "redirect_uri"
   parameter.

GET http://localhost:8080/oauth2/authorize/google?redirect_uri=http://localhost:9090/oauth2/redirect
```

```
Client -> User-Agent : Location is the URL where the User-Agent is now taken
The Location response header indicates the URL to redirect a page to. It only provides a meaning when served with a 3xx (redirection) or 201 (created) status response.
In cases of redirection, the HTTP method used to make the new request to fetch the page pointed to by Location depends on the original method and the kind of redirection:
HTTP/1.1 302
Location: https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=758485046783-75l03cv59at80qnvfjhtppadp3bksgn0.apps.googleusercontent.com&scope=email%20profile%20https://www.googleapis.com/auth/contacts.readonly&state=nORfJ5TjhQjKvPoA2iAwOCjrfly4HdrS5SSPPyr_EtM%3D&redirect_uri=http://localhost:8080/oauth2/callback/google
```

2. the application server (OID Client) creates the state parameter, takes the info from the configuration and redirects the
    user to the Google OAuth2 page. The capture of the HTTP header is present in the OIDC-2.http file.
    Are you able to identify the google OAuth2 page endpoint?

```
google OAuth2 endpoint=https://accounts.google.com/o/oauth2/v2/auth

User-Agent -> OP
GET https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=758485046783-75l03cv59at80qnvfjhtppadp3bksgn0.apps.googleusercontent.com&scope=email%20profile%20https://www.googleapis.com/auth/contacts.readonly&state=nORfJ5TjhQjKvPoA2iAwOCjrfly4HdrS5SSPPyr_EtM%3D&redirect_uri=http://localhost:8080/oauth2/callback/google HTTP/1.1

OP -> User-Agent
HTTP/1.1 200
```

```
Figure 19: Starting page of the end-user app for the sample OIDC flow.
```
3. The user logs exploiting Google as AuthZ server (Fig. 21) and accepts or denies the AuthZs scopes.
    After the user acceptance, Google redirects it back on the app server with the AuthZ Code
4. the app server checks that the state is the same and prepares a HTTP GET to the Google Token endpoint
    (OIDC-3.http)
```
User-Agent -> OP
GET https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=758485046783-75l03cv59at80qnvfjhtppadp3bksgn0.apps.googleusercontent.com&scope=email%20profile%20https://www.googleapis.com/auth/contacts.readonly&state=nORfJ5TjhQjKvPoA2iAwOCjrfly4HdrS5SSPPyr_EtM%3D&redirect_uri=http://localhost:8080/oauth2/callback/google

OP -> User-Agent
Redirect user to OID Client
HTTP/1.1 302
location: http://localhost:8080/oauth2/callback/google?state=nORfJ5TjhQjKvPoA2iAwOCjrfly4HdrS5SSPPyr_EtM%3D&code=4%2F0AY0e-g5mTJUdRlajL-hQH1PF9abiLRF0brpgnZrY3mbHJhBWJgPeXNon97tkqmGfNleu2g&scope=email+profile+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.profile+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcontacts.readonly+openid&authuser=0&prompt=consent
```
5. Google checks code and secrets, and gives a JWT access token to the app server (OID Client)
6. the app server sends an HTTP GET to the Google endpoint by inserting the access token in the autho-
    rization header. The Google API server checks the token and prepares the response as JSON, ending the
    OAuth2 exchange (OIDC-4.http).
```
OID Client -> OP
GET http://localhost:8080/oauth2/callback/google?state=nORfJ5TjhQjKvPoA2iAwOCjrfly4HdrS5SSPPyr_EtM%3D&code=4%2F0AY0e-g5mTJUdRlajL-hQH1PF9abiLRF0brpgnZrY3mbHJhBWJgPeXNon97tkqmGfNleu2g&scope=email+profile+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.profile+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcontacts.readonly+openid&authuser=0&prompt=consent# HTTP/1.1

OP -> OID Client
HTTP/1.1 302
Location: http://localhost:9090/oauth2/redirect?token=eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiIxIiwiaWF0IjoxNjA1OTk4MTA1LCJleHAiOjE2MDY4NjIxMDV9.8zH_eAO4zfuRUK-ELgVmBUYXVsRFbHuakDjSAwCItFny44TBBPm1C9ESooC_Vsmxbewm9XTgItchuzToftHt1w
```
7. finally, the user app displays the information of the logged user (Fig. 20).

Answer to the following questions:

Analysing the first message (i.e.OIDC-1.http) can you identify the authorization server?

```
https://accounts.google.com/o/oauth2/v2/auth
```
Analysing the second message, (i.e.OIDC-2.http) can you identify the type of OAuth2 adopted flow?

```
In the GET request there is scope=email
```
Can you identify the objects of the authorization requests?

```
Cookie: oauth2_auth_request=....

https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9-_',true)Encode_text('UTF-7%20(65000)')

+AKw-+AO0-+AAA-+AAU-sr+AAA-Lorg.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest+AAA-+AAA-+AAA-+AAA-+AAA-+AAA-+AAI-+AAg-+AAI-+AAA-+AAo-L+AAA-+ABQ-additionalParameterst+AAA-+AA8-Ljava/util/Map+ADs-L+AAA-+AAo-attributesq+AAA-+AH4-+AAA-+AAE-L+AAA-+ABY-authorizationGrantTypet+AAA-ALorg/springframework/security/oauth2/core/AuthorizationGrantType+ADs-L+AAA-+ABc-authorizationRequestUrit+AAA-+ABI-Ljava/lang/String+ADs-L+AAA-+ABA-authorizationUriq+AAA-+AH4-+AAA-+AAM-L+AAA-+AAg-clientIdq+AAA-+AH4-+AAA-+AAM-L+AAA-+AAs-redirectUriq+AAA-+AH4-+AAA-+AAM-L+AAA-+AAw-responseTypet+AAA-SLorg/springframework/security/oauth2/core/endpoint/OAuth2AuthorizationResponseType+ADs-L+AAA-+AAY-scopest+AAA-+AA8-Ljava/util/Set+ADs-L+AAA-+AAU-stateq+AAA-+AH4-+AAA-+AAM-xpsr+AAA-+ACU-java.util.Collections+ACQ-UnmodifiableMap+APE-+AKU-+AKg-+AP4-t+APU-+AAc-B+AAI-+AAA-+AAE-L+AAA-+AAE-mq+AAA-+AH4-+AAA-+AAE-xpsr+AAA-+AB4-java.util.Collections+ACQ-EmptyMapY6+ABQ-+AIU-Z+ANw-+AOc-+ANA-+AAI-+AAA-+AAA-xpsq+AAA-+AH4-+AAA-+AAc-sr+AAA-+ABc-java.util.LinkedHashMap4+AMA-N+AFw-+ABA-l+AMA-+APs-+AAI-+AAA-+AAE-Z+AAA-+AAs-accessOrderxr+AAA-+ABE-java.util.HashMap+AAU-+AAc-+ANo-+AME-+AMM-+ABY-+AGA-+ANE-+AAM-+AAA-+AAI-F+AAA-+AAo-loadFactorI+AAA-+AAk-thresholdxp?+AEA-+AAA-+AAA-+AAA-+AAA-+AAA-+AAE-w+AAg-+AAA-+AAA-+AAA-+AAI-+AAA-+AAA-+AAA-+AAE-t+AAA-+AA8-registration+AF8-idt+AAA-+AAY-googlex+AAA-sr+AAA-?org.springframework.security.oauth2.core.AuthorizationGrantType+AAA-+AAA-+AAA-+AAA-+AAA-+AAA-+AAI-+AAg-+AAI-+AAA-+AAE-L+AAA-+AAU-valueq+AAA-+AH4-+AAA-+AAM-xpt+AAA-+ABI-authorization+AF8-codet+AAE-Khttps://accounts.google.com/o/oauth2/v2/auth?response+AF8-type+AD0-code+ACY-client+AF8-id+AD0-758485046783-75l03cv59at80qnvfjhtppadp3bksgn0.apps.googleusercontent.com+ACY-scope+AD0-email+ACU-20profile+ACU-20https://www.googleapis.com/auth/contacts.readonly+ACY-state+AD0-nORfJ5TjhQjKvPoA2iAwOCjrfly4HdrS5SSPPyr+AF8-EtM+ACU-3D+ACY-redirect+AF8-uri+AD0-http://localhost:8080/oauth2/callback/googlet+AAA-,https://accounts.google.com/o/oauth2/v2/autht+AAA-H758485046783-75l03cv59at80qnvfjhtppadp3bksgn0.apps.googleusercontent.comt+AAA-,http://localhost:8080/oauth2/callback/googlesr+AAA-Qorg.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType+AAA-+AAA-+AAA-+AAA-+AAA-+AAA-+AAI-+AAg-+AAI-+AAA-+AAE-L+AAA-+AAU-valueq+AAA-+AH4-+AAA-+AAM-xpt+AAA-+AAQ-codesr+AAA-+ACU-java.util.Collections+ACQ-UnmodifiableSet+AIA-+AB0-+AJI-+ANE-+AI8-+AJs-+AIA-U+AAI-+AAA-+AAA-xr+AAA-,java.util.Collections+ACQ-UnmodifiableCollection+ABk-B+AAA-+AIA-+AMs-+AF4-+APc-+AB4-+AAI-+AAA-+AAE-L+AAA-+AAE-ct+AAA-+ABY-Ljava/util/Collection+ADs-xpsr+AAA-+ABc-java.util.LinkedHashSet+ANg-l+ANc-Z+AJU-+AN0-+ACo-+AB4-+AAI-+AAA-+AAA-xr+AAA-+ABE-java.util.HashSet+ALo-D+AIU-+AJU-+AJY-+ALg-+ALc-4+AAM-+AAA-+AAA-xpw+AAw-+AAA-+AAA-+AAA-+ABA-?+AEA-+AAA-+AAA-+AAA-+AAA-+AAA-+AAM-t+AAA-+AAU-emailt+AAA-+AAc-profilet+AAA-1https://www.googleapis.com/auth/contacts.readonlyxt+AAA-,nORfJ5TjhQjKvPoA2iAwOCjrfly4HdrS5SSPPyr+AF8-EtM+AD0-

```

```
Figure 20: Login page of the end-user app for the sample OIDC flow.
```
```
Figure 21: Google login page
```

Figure 22: Data shown at the end of the sample OIDC flow.


