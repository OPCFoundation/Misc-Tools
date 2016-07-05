# Misc-Tools #
Miscellaneous utilities

## Certificate Generator ##
A tool to create OPC UA compliance certificates built with the OpenSSL library.

It is a command line utility with the following arguments:

-command or -cmd <issue | revoke | unrevoke | convert | replace | request | process> The action to perform (default = issue).

* issue: create a new certificate.
* revoke: revoke a certificate.
* unrevoke: unrevoke a certificate.
* convert: convert a private key file.
* replace: update the certificates in a PFX file.
* request: create a new certificate signing request.
* process: create a new certificate from a new certificate signing request.

-storePath or -sp <filepath>                The directory of the certificate store (must be writeable).
-applicationName or -an <name>              The name of the application.
-applicationUri or -au <uri>                The URI for the appplication.
-subjectName or -sn <DN>                    The distinguished subject name, fields seperated by a / (i.e. CN=Hello/O=World).
-organization or -o <name>                  The organization.
-domainNames or -dn <name>,<name>           A list of domain names seperated by commas
-password or -pw <password>                 The password for the new private key file.
-issuerCertificate or -icf <filepath>       The path to the issuer certificate file.
-issuerKeyFilePath or -ikf <filepath>       The path to the issuer private key file.
-issuerKeyPassword or -ikp <password>       The password for the issuer private key file.
-keySize or -ks <bits>                      The size of key as a multiple of 1024 (default = 1024).
-hashSize or -hs <bits>                     The size of hash <160 | 256 | 512> (default = 256).
-startTime or -st <nanoseconds>             The start time for the validity period (nanoseconds from 1600-01-01).
-lifetimeInMonths or -lm <months>           The lifetime in months (default = 60).
-publicKeyFilePath or -pbf <filepath>       The path to the certificate to renew or revoke (a DER file).
-privateKeyFilePath or -pvf <filepath>      The path to an existing private key to reuse or convert.
-privateKeyPassword or -pvp <password>      The password for the existing private key.
-reuseKey or -rk <true | false>             Whether to reuse an existing public key (default = false).
-ca <true | false>                          Whether to create a CA certificate (default = false).
-pemInput <true | false>                    Whether the privateKeyFilePath is in PEM format (default = PFX).
-pem <true | false>                         Whether to output in the PEM format (default = PFX).
-requestFilePath or -rfp <filepath>         The path to certificate signing request.
-inlineOutput or -io <filepath>             Write all output as a hexadecimal string instead of saving to a file.


All input file arguments can be a valid directory path or a hexadecimal string.
All output files are written to output as hexadecimal strings if -inlineOutput true is specified.

Create a self-signed Application Certificate: -cmd issue -sp . -an MyApp -au urn:MyHostMyCompany:MyApp -o MyCompany -dn MyHost -pw MyCertFilePassword
Create a CA Certificate: -cmd issue -sp . -sn CN=MyCA/O=Acme -ca true
Issue an Application Certificate: -cmd issue -sp . -an MyApp -ikf CaKeyFile -ikp CaPassword
Renew a Certificate: -cmd issue -sp . -pbf MyCertFile -ikf CaKeyFile -ikp CaPassword
Revoke a Certificate: -cmd revoke -sp . -pbf MyCertFile -ikf CaKeyFile -ikp CaPassword
Unrevoke a Certificate: -cmd unrevoke -sp . -pbf MyCertFile -ikf CaKeyFile -ikp CaPassword
Convert key format: -cmd convert -pvf MyKeyFile -pvp oldpassword -pem true -pw newpassword
Create a certificate request: -cmd request -pbf MyCertFile.der -pvf MyCertFile.pfx -pvp MyCertFilePassword -rfp MyRequest.csr
Process a certificate request: -cmd process -rfp MyRequest.csr -ikf CaKeyFile -ikp CaPassword -pbf MyCertFile.der
