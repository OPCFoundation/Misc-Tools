@ECHO off
REM ****************************************************************************************************************
REM ** This script builds the CertificateGenerator.
REM ** This must be run from a Visual Studio command line.
REM ****************************************************************************************************************
SETLOCAL

set SRCDIR=%~dp0
set INSTALLDIR=%~dp0

IF "%1"=="no-clean" GOTO noClean
ECHO STEP 1) Deleting old projects.
IF EXIST %INSTALLDIR%\bin rmdir /s /q %INSTALLDIR%\bin
IF EXIST .\build rmdir /s /q .\build
:noClean

IF NOT EXIST .\build MKDIR .\build

ECHO STEP 1) Running CMAKE...
set OPENSSL_ROOT_DIR=%INSTALLDIR%..\..\third-party\openssl
cd .\build
%CMAKEEXE% .. -DCMAKE_INSTALL_PREFIX=%INSTALLDIR%

ECHO STEP 2) Building project...
msbuild "CertificateGenerator Solution.sln" /p:Configuration=Release 

ECHO STEP 3) Install Binaries...

ECHO STEP 4) Sign the Binaries
IF EXIST C:\Build\sign_output.bat C:\Build\sign_output %INSTALLDIR%\bin\*.exe /sha1

ECHO *** ALL DONE ***
GOTO theEnd

:theEnd
ENDLOCAL