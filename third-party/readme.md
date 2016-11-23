# UA-MiscTools Third Party Library Readme #
## Overview ##
This directory contains references to other GitHub projects which the samples depend on.
For each project there is BATCH file which builds and installes the headers and libs in the third-party directory.
The source respository must be cloned first.

## openssl ##
An open source cryptography library.
The respository is here: https://github.com/openssl/openssl.git

The command to clone is:

```
cd src
git clone https://github.com/openssl/openssl.git
cd openssl
git checkout tags/OpenSSL_1_0_2h
```

As new versions are published the tag reference in the command above should be adjusted accordingly.

Once the OpenSSL repository is cloned it can be built from a VS2015 command prompt with build_openssl.bat.

