# UA-MiscTools Third Party Library Readme #
## Overview ##
This directory contains references to other GitHub projects which the samples depend on.
For each project there is BATCH file which builds and installes the headers and libs in the third-party directory.
The source respository must be cloned first.

After cloning the repository the subprojects in the third-party directory need to be fetched using this command:
```
cd third-party
git submodule update --init --recursive
```

## openssl ##
An open source cryptography library.
The respository is here: https://github.com/openssl/openssl.git

The command to clone is:

```
cd src
git clone https://github.com/openssl/openssl.git
cd openssl
git checkout tags/OpenSSL_1_1_1a
```

As new versions are published the tag reference in the command above should be adjusted accordingly.
Note that the git submodule update --init --recursive command should eliminate the need for the steps above.

Once the OpenSSL repository is cloned it can be built from a VS2015 command prompt with *build_openssl.bat*.

