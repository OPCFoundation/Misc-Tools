@ECHO off
REM ****************************************************************************************************************
REM ** This script builds the CertificateGenerator.
REM ** This must be run from a Visual Studio command line.
REM ****************************************************************************************************************
SETLOCAL

set SRCDIR=%~dp0
set INSTALLDIR=%~dp0
SET ZIP="C:\Program Files\7-zip\7z.exe"
set GIT=C:\Program Files (x86)\Git\bin\git.exe
set SIGNTOOL=C:\Build\sign_output.bat

set GIT=C:\Program Files\Git\bin\git.exe
IF NOT EXIST %GIT% set GIT=C:\Program Files (x86)\Git\bin\git.exe

IF "%1"=="no-clean" GOTO noClean
ECHO STEP 1) Deleting Output Directories
IF EXIST %INSTALLDIR%\bin rmdir /s /q %INSTALLDIR%\bin
IF EXIST %INSTALLDIR%\build rmdir /s /q %INSTALLDIR%\build
IF EXIST %INSTALLDIR%\third-party\openssl rmdir /s /q %INSTALLDIR%\third-party\openssl

IF NOT EXIST %INSTALLDIR%\bin MKDIR %INSTALLDIR%\bin
IF NOT EXIST %INSTALLDIR%\build MKDIR %INSTALLDIR%\build
IF NOT EXIST %INSTALLDIR%\third-party\openssl MKDIR %INSTALLDIR%\third-party\openssl

ECHO STEP 2) Fetch from Source Control
cd %SRCDIR%
"%GIT%" checkout master
"%GIT%" reset --hard
"%GIT%" submodule update --init --recursive
"%GIT%" pull

ECHO STEP 3) Building OpenSSL
cd %SRCDIR%\third-party
CALL build_openssl.bat
:noClean

ECHO STEP 4) Building CertificateGenerator
cd %SRCDIR%
IF %BUILD_NUMBER% GTR 0 ECHO #define BUILD_NUMBER %BUILD_NUMBER% > CertificateGenerator\BuildVersion.h
msbuild "CertificateGenerator Solution.sln" /p:Configuration=Release 

ECHO STEP 5) Sign the Binaries
IF EXIST "%SIGNTOOL%" CALL "%SIGNTOOL%" %INSTALLDIR%\bin\*.exe /dual

ECHO STEP 6) ZIP the Binaries
CD %INSTALLDIR%\bin
%ZIP% a "CertificateGenerator 1.1.342.%BUILD_NUMBER%.zip" "*.exe"

CD ECHO *** ALL DONE ***
GOTO theEnd

:theEnd
ENDLOCAL