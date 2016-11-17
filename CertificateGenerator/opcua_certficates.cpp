/* ========================================================================
 * Copyright (c) 2005-2011 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Reciprocal Community License ("RCL") Version 1.00
 *
 * Unless explicitly acquired and licensed from Licensor under another
 * license, the contents of this file are subject to the Reciprocal
 * Community License ("RCL") Version 1.00, or subsequent versions as
 * allowed by the RCL, and You may not copy or use this file in either
 * source code or executable form, except in compliance with the terms and
 * conditions of the RCL.
 *
 * All software distributed under the RCL is provided strictly on an
 * "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED,
 * AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT
 * LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RCL for specific
 * language governing rights and limitations under the RCL.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/RCL/1.00/
 * ======================================================================*/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <Ws2tcpip.h>
#include <mbstring.h>
#include <string>
#include <vector>
#include <direct.h>
#include <opcua.h>
#include <opcua_core.h>
#include <opcua_certificates.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/conf.h>

static char OID_AUTHORITY_KEY_IDENTIFIER[] = { 85, 29, 1 };
static char OID_SUBJECT_ALT_NAME[] = { 85, 29, 7 };

/*============================================================================
* CreateGuid
*===========================================================================*/
OpcUa_Guid* OpcUa_P_Guid_Create(OpcUa_Guid* Guid);

/*============================================================================
* Calculate DateTime Difference In Seconds (Rounded)
*===========================================================================*/
OpcUa_StatusCode OpcUa_P_GetDateTimeDiffInSeconds32(
	OpcUa_DateTime  a_Value1,
	OpcUa_DateTime  a_Value2,
	OpcUa_Int32*    a_pDifference);

/*============================================================================
* The OpcUa_UtcNow function (returns the time in OpcUa_DateTime format)
*===========================================================================*/
OpcUa_DateTime OpcUa_P_DateTime_UtcNow();

/*============================================================================
 * OpcUa_StringToUnicode
 *===========================================================================*/
OpcUa_StatusCode OpcUa_StringToUnicode(
    OpcUa_StringA a_sSource,
    OpcUa_Char**  a_pUnicode)
{

OpcUa_InitializeStatus(OpcUa_Module_Utilities, "OpcUa_StringToUnicode");

    OpcUa_ReturnErrorIfArgumentNull(a_pUnicode);

    *a_pUnicode = OpcUa_Null;

    if (a_sSource == OpcUa_Null)
    {
        return OpcUa_Good;
    }

	int iLength = MultiByteToWideChar(
	   GetACP(), // CP_UTF8,
       0,
       a_sSource,
       -1,
       NULL,
       0);

    if (iLength == 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadOutOfMemory);
    }

    *a_pUnicode = (OpcUa_Char*)OpcUa_Alloc(sizeof(OpcUa_Char)*(iLength+1));

	iLength = MultiByteToWideChar(
	   GetACP(), // CP_UTF8,
       0,
       a_sSource,
       -1,
       (LPWSTR)*a_pUnicode,
       iLength+1);

    if (iLength == 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadOutOfMemory);
    }

    (*a_pUnicode)[iLength] = L'\0';

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (*a_pUnicode != OpcUa_Null)
    {
        OpcUa_Free(*a_pUnicode);
        *a_pUnicode = OpcUa_Null;
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_UnicodeToString
 *===========================================================================*/
OpcUa_StatusCode OpcUa_UnicodeToString(
    OpcUa_Char*  a_pUnicode,
    OpcUa_StringA* a_sString)
{

OpcUa_InitializeStatus(OpcUa_Module_Utilities, "OpcUa_UnicodeToString");

    OpcUa_ReturnErrorIfArgumentNull(a_sString);

    *a_sString = OpcUa_Null;

    if (a_pUnicode == OpcUa_Null)
    {
        return OpcUa_Good;
    }

    int iLength = WideCharToMultiByte(
	   GetACP(), // CP_UTF8,
       0,
       (LPWSTR)a_pUnicode,
       -1,
       NULL,
       0,
       0,
       0);

    if (iLength == 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadOutOfMemory);
    }

    *a_sString = (OpcUa_CharA*)OpcUa_Alloc(sizeof(OpcUa_CharA)*(iLength+1));

	iLength = WideCharToMultiByte(
       GetACP(), // CP_UTF8,
       0,
       (LPWSTR)a_pUnicode,
       -1,
       (LPSTR)*a_sString,
       iLength+1,
       0,
       0);

    if (iLength == 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadOutOfMemory);
    }

    (*a_sString)[iLength] = '\0';

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (*a_sString != OpcUa_Null)
    {
        OpcUa_Free(*a_sString);
        *a_sString = OpcUa_Null;
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_ReadFile
 *===========================================================================*/
OpcUa_StatusCode OpcUa_MakeDir(OpcUa_StringA sFilePath)
{
    OpcUa_Char* wszFilePath = 0;
    OpcUa_StatusCode uStatus = OpcUa_StringToUnicode(sFilePath, &wszFilePath);
   
    if (OpcUa_IsBad(uStatus))
    {
        return uStatus;
    }

    // create the store.
    int result = _wmkdir((wchar_t*)wszFilePath);

    if (result != 0)
    {
        result = errno;
    }

    OpcUa_Free(wszFilePath);
    wszFilePath = 0;

    if (result != 0 && result != EEXIST)
    {
        return OpcUa_BadUserAccessDenied;
    }

    return OpcUa_Good;
}

/*============================================================================
 * OpcUa_ReadFile
 *===========================================================================*/
OpcUa_StatusCode OpcUa_ReadFile(
    OpcUa_StringA     a_sFilePath,
    OpcUa_ByteString* a_pBuffer)
{
    FILE* pFile = NULL;
    BYTE* pBuffer = NULL;
    OpcUa_Char* wsBuffer = 0;

OpcUa_InitializeStatus(OpcUa_Module_Utilities, "OpcUa_ReadFile");

    OpcUa_ReturnErrorIfArgumentNull(a_sFilePath);
    OpcUa_ReturnErrorIfArgumentNull(a_pBuffer);

    OpcUa_ByteString_Initialize(a_pBuffer);

    uStatus = OpcUa_StringToUnicode(a_sFilePath, &wsBuffer);

    if (OpcUa_IsBad(uStatus))
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
    }

    // read the file.
    int iResult = _wfopen_s(&pFile, (wchar_t*)wsBuffer, L"rb");

    OpcUa_Free(wsBuffer);
    wsBuffer = 0;

    if (iResult != 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
    }

    // get the length,
    fpos_t iLength = 0;

    iResult = fseek(pFile, 0, SEEK_END);

    if (iResult == 0)
    {
        iResult = fgetpos(pFile, &iLength);

        if (iResult != 0)
        {
            OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
        }

        fseek(pFile, 0, SEEK_SET);
    }

    // allocate buffer.
    pBuffer = (BYTE*)OpcUa_Alloc((OpcUa_UInt32)iLength);
    memset(pBuffer, 0, (size_t)iLength);

    // read blocks.
    BYTE* pPosition = pBuffer;

    while (pFile != NULL)
    {
        iResult = fread(pPosition, 1, (size_t)(iLength-(pPosition-pBuffer)), pFile);

        if (iResult <= 0)
        {
            break;
        }

        pPosition += iResult;
    }

    fclose(pFile);
    pFile = NULL;

    a_pBuffer->Data   = pBuffer;
    a_pBuffer->Length = pPosition - pBuffer;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pFile != OpcUa_Null)
    {
        fclose(pFile);
    }

    if (pBuffer != OpcUa_Null)
    {
        OpcUa_Free(pBuffer);
    }

    OpcUa_ByteString_Initialize(a_pBuffer);

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WriteFile
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WriteFile(
    const char*  a_sFilePath,
    OpcUa_Byte*  a_pBuffer,
    OpcUa_UInt32 a_uBufferLength)
{
    FILE* pFile = NULL;
    OpcUa_Char* wsBuffer = 0;

OpcUa_InitializeStatus(OpcUa_Module_Utilities, "OpcUa_WriteFile");

    OpcUa_ReturnErrorIfArgumentNull(a_sFilePath);
    OpcUa_ReturnErrorIfArgumentNull(a_pBuffer);

	uStatus = OpcUa_StringToUnicode((OpcUa_StringA)a_sFilePath, &wsBuffer);

    if (OpcUa_IsBad(uStatus))
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
    }

    int iResult = _wfopen_s(&pFile, (wchar_t*)wsBuffer, L"wb");

    if (iResult != 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
    }

    iResult = fwrite(a_pBuffer, 1, (size_t)a_uBufferLength, pFile);

    OpcUa_Free(wsBuffer);
    wsBuffer = 0;

    if (iResult <= 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
    }

    fclose(pFile);
    pFile = NULL;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pFile != OpcUa_Null)
    {
        fclose(pFile);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_CopyStrings
 *===========================================================================*/
static OpcUa_StatusCode OpcUa_Certificate_CopyStrings(
    std::vector<std::string> src,
    OpcUa_StringA**          pStrings,
    OpcUa_UInt32*            pNoOfStrings)
{
OpcUa_InitializeStatus(OpcUa_Module_Utilities, "OpcUa_Certificate_CopyStrings");

    OpcUa_ReturnErrorIfArgumentNull(pStrings);
    OpcUa_ReturnErrorIfArgumentNull(pNoOfStrings);

    *pStrings = NULL;
    *pNoOfStrings = src.size();

    int iLength = src.size()*sizeof(OpcUa_StringA);
    *pStrings = (OpcUa_StringA*)OpcUa_Alloc(iLength);
    OpcUa_GotoErrorIfAllocFailed(*pStrings);
    OpcUa_MemSet(*pStrings, 0, iLength);

    for (unsigned int ii = 0; ii < src.size(); ii++)
    {
        iLength = src[ii].size()+1;
        (*pStrings)[ii] = (OpcUa_StringA)OpcUa_Alloc(iLength);
        OpcUa_GotoErrorIfAllocFailed((*pStrings)[ii]);
        strcpy_s((*pStrings)[ii], iLength, src[ii].c_str());
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (*pStrings != NULL)
    {
        for (unsigned int ii = 0; ii < *pNoOfStrings; ii++)
        {
            OpcUa_Free((*pStrings)[ii]);
        }

        OpcUa_Free(*pStrings);
        *pStrings = NULL;
        *pNoOfStrings = 0;
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_CreateCryptoProviders
 *===========================================================================*/
static OpcUa_StatusCode OpcUa_Certificate_CreateCryptoProviders(
    OpcUa_PKIProvider* a_pPkiProvider,
    OpcUa_CryptoProvider* a_pCryptoProvider)
{
    OpcUa_P_OpenSSL_CertificateStore_Config tPkiConfiguration;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_FindCertificateInWindowsStore");

    OpcUa_ReturnErrorIfArgumentNull(a_pPkiProvider);
    OpcUa_ReturnErrorIfArgumentNull(a_pCryptoProvider);

    OpcUa_MemSet(a_pPkiProvider, 0, sizeof(OpcUa_PKIProvider));
    OpcUa_MemSet(a_pCryptoProvider, 0, sizeof(OpcUa_CryptoProvider));

    // create the certificate in an OpenSSL store.
    tPkiConfiguration.PkiType						    = OpcUa_OpenSSL_PKI;
    tPkiConfiguration.Flags							    = 0;
    tPkiConfiguration.TrustedCertificateStorePath	    = NULL;
    tPkiConfiguration.IssuerCertificateStorePath        = NULL;

    uStatus = OpcUa_PKIProvider_Create(&tPkiConfiguration, a_pPkiProvider);
    OpcUa_GotoErrorIfBad(uStatus);

    // create the provider.
    uStatus = OpcUa_CryptoProvider_Create(OpcUa_SecurityPolicy_Basic128Rsa15, a_pCryptoProvider);
    OpcUa_GotoErrorIfBad(uStatus);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_CryptoProvider_Delete(a_pCryptoProvider);
    OpcUa_PKIProvider_Delete(a_pPkiProvider);

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_DeleteCryptoProviders
 *===========================================================================*/
static OpcUa_StatusCode OpcUa_Certificate_DeleteCryptoProviders(
    OpcUa_PKIProvider* a_pPkiProvider,
    OpcUa_CryptoProvider* a_pCryptoProvider)
{
OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_DeleteCryptoProviders");

    OpcUa_ReturnErrorIfArgumentNull(a_pPkiProvider);
    OpcUa_ReturnErrorIfArgumentNull(a_pCryptoProvider);

    OpcUa_CryptoProvider_Delete(a_pCryptoProvider);
    OpcUa_PKIProvider_Delete(a_pPkiProvider);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    // nothing to do.

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_GetFilePathForCertificate
 *===========================================================================*/
static std::string OpcUa_Certificate_GetFilePathForCertificate(
    OpcUa_StringA      a_sStorePath,
    OpcUa_ByteString*  a_pCertificate,
    OpcUa_P_FileFormat a_eFileFormat,
    OpcUa_Boolean      a_bCreateAlways)
{
    OpcUa_StringA sCommonName;
    OpcUa_StringA sThumbprint;
    std::string filePath;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_GetFilePathForCertificate");

    OpcUa_GotoErrorIfArgumentNull(a_sStorePath);
    OpcUa_GotoErrorIfArgumentNull(a_pCertificate);

    uStatus = OpcUa_Certificate_GetCommonName(a_pCertificate, &sCommonName);
    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = OpcUa_Certificate_GetThumbprint(a_pCertificate, &sThumbprint);
    OpcUa_GotoErrorIfBad(uStatus);

    // build file path.
    filePath = a_sStorePath;

    if (a_eFileFormat == OpcUa_Crypto_Encoding_DER)
    {
        filePath += "\\certs\\";
    }
    else
    {
        filePath += "\\private\\";
    }

    if (a_bCreateAlways)
    {
        for (unsigned int ii = 0; ii < filePath.size(); ii++)
        {
            char ch = filePath[ii];

            if (ch != '/' && ch != '\\')
            {
                continue;
            }

            std::string parent = filePath.substr(0, ii);

            if (parent.empty() || parent.size() <= 0 || parent[parent.size()-1] == ':')
            {
                continue;
            }

            uStatus = OpcUa_MakeDir((OpcUa_StringA)parent.c_str());
            OpcUa_GotoErrorIfBad(uStatus);
        }
    }

    // remove any special characters.
    char* pPos = sCommonName;

    while (*pPos != '\0')
    {
        char* pMatch = "<>:\"/\\|?*";

        while (*pMatch != '\0')
        {
            if (*pMatch == *pPos)
            {
                *pPos = '+';
                break;
            }

            pMatch++;
        }

        pPos++;
    }

    filePath += sCommonName;
    filePath += " [";
    filePath += sThumbprint;
    filePath += "]";

    // select the appropriate extension.
    switch(a_eFileFormat)
    {
        case OpcUa_Crypto_Encoding_DER:
        {
            filePath += ".der";
            break;
        }

        case OpcUa_Crypto_Encoding_PEM:
        {
            filePath += ".pem";
            break;
        }

        case OpcUa_Crypto_Encoding_PKCS12:
        {
            filePath += ".pfx";
            break;
        }

        default:
        {
            OpcUa_GotoErrorWithStatus(OpcUa_BadNotSupported);
        }
    }

    OpcUa_Free(sCommonName);
    OpcUa_Free(sThumbprint);

    return filePath;

OpcUa_BeginErrorHandling;

    OpcUa_Free(sCommonName);
    OpcUa_Free(sThumbprint);

    return filePath;
}

static OpcUa_StringA g_ValidSubjectNameComponents[] =
{
    "CN", "DC", "O", "OU", "C", "L", "ST", "SN", "GN", NULL
};

/*============================================================================
 * OpcUa_Certificate_GetStoreName
 *===========================================================================*/
static std::string OpcUa_Certificate_GetStoreName(
    OpcUa_StringA a_sStorePath,
    OpcUa_Boolean* a_pUseMachineStore)
{
    std::string storePath;
    std::string storeName;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_GetStoreName");

    OpcUa_GotoErrorIfArgumentNull(a_sStorePath);
    OpcUa_GotoErrorIfArgumentNull(a_pUseMachineStore);

    *a_pUseMachineStore = OpcUa_False;

    storePath = a_sStorePath;

    for (unsigned int ii = 0; ii < storePath.size(); ii++)
    {
        char ch = storePath[ii];

        if (ch == '\\')
        {
            std::string storeType = storePath.substr(0, ii);
            std::string localMachine = "LocalMachine";

            if (_stricmp(localMachine.c_str(), storeType.c_str()) != 0)
            {
                std::string currentUser = "CurrentUser";

                if (_stricmp(currentUser.c_str(), storeType.c_str()) != 0)
                {
                    break;
                }
            }
            else
            {
                *a_pUseMachineStore = OpcUa_True;
            }

            while (storePath[ii++] != '\\');

            storeName = storePath.substr(ii);
            break;
        }
    }

    return storeName;

OpcUa_BeginErrorHandling;

    return storeName;
}

/*============================================================================
 * OpcUa_Certificate_SavePrivateKeyInWindowsStore
 *===========================================================================*/
static OpcUa_StatusCode OpcUa_Certificate_SavePrivateKeyInWindowsStore(
    OpcUa_Boolean      a_bUseMachineStore,
    std::string        a_sStoreName,
    OpcUa_StringA      a_sPassword,
    OpcUa_ByteString*  a_pCertificate,
    OpcUa_Key*         a_pPrivateKey)
{
    RSA* pRsaPrivateKey = OpcUa_Null;
    EVP_PKEY* pEvpKey = OpcUa_Null;
    X509* pX509Certificate = OpcUa_Null;
    PKCS12* pPkcs12 = OpcUa_Null;
    OpcUa_StringA sCommonName = OpcUa_Null;
    CRYPT_DATA_BLOB tCertificateData;
    HCERTSTORE hCertificateStore = 0;
    HCERTSTORE hFileStore = 0;
    LPWSTR wszStoreName = NULL;
    const CERT_CONTEXT* pCertContext = 0;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_SavePrivateKeyInWindowsStore");

    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
    OpcUa_ReturnErrorIfArgumentNull(a_pPrivateKey);

    tCertificateData.pbData = OpcUa_Null;

    // check for supported key type.
    if (a_pPrivateKey->Type != OpcUa_Crypto_Rsa_Alg_Id && a_pPrivateKey->Type != OpcUa_Crypto_KeyType_Rsa_Private)
    {
        return OpcUa_BadInvalidArgument;
    }

    // convert DER encoded data to RSA data.
    const unsigned char* pPos = a_pPrivateKey->Key.Data;
    pRsaPrivateKey = d2i_RSAPrivateKey(NULL, &pPos, a_pPrivateKey->Key.Length);
    OpcUa_GotoErrorIfAllocFailed(pRsaPrivateKey);

    pEvpKey = EVP_PKEY_new();

    // convert to intermediary openssl struct
    if (!EVP_PKEY_set1_RSA(pEvpKey, pRsaPrivateKey))
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
    }

    // convert public key to X509 structure.
    BYTE* pPosition = a_pCertificate->Data;
    pX509Certificate = d2i_X509((X509**)OpcUa_Null, (const unsigned char**)&pPosition, a_pCertificate->Length);
    OpcUa_GotoErrorIfNull(pX509Certificate, OpcUa_Bad);

    // use the common name as the friendly name.
    uStatus = OpcUa_Certificate_GetCommonName(a_pCertificate, &sCommonName);
    OpcUa_GotoErrorIfBad(uStatus);

    // create certificate.
    pPkcs12 = PKCS12_create(
        a_sPassword,
        sCommonName,
        pEvpKey,
        pX509Certificate,
        0,
        0,
        0,
        0,
        0,
        0);

    OpcUa_GotoErrorIfNull(pPkcs12, OpcUa_Bad);

    // convert to DER.
    tCertificateData.cbData = i2d_PKCS12(pPkcs12, &tCertificateData.pbData);

    if (tCertificateData.cbData <= 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
    }

    // free certificate.
    PKCS12_free(pPkcs12);
    pPkcs12 = NULL;

    // import DER data to temporary store
    hFileStore = PFXImportCertStore(
        &tCertificateData,
        0,
        CRYPT_EXPORTABLE | (a_bUseMachineStore) ? CRYPT_MACHINE_KEYSET : CRYPT_USER_KEYSET);

    if (hFileStore == 0)
    {
        if (a_sPassword != NULL && strlen(a_sPassword) == 0)
        {
            // free the DER blob.
            OPENSSL_free(tCertificateData.pbData);
            tCertificateData.pbData = 0;

            // create certificate.
            pPkcs12 = PKCS12_create(
                NULL,
                sCommonName,
                pEvpKey,
                pX509Certificate,
                0,
                0,
                0,
                0,
                0,
                0);

            OpcUa_GotoErrorIfNull(pPkcs12, OpcUa_Bad);

            // convert to DER.
            tCertificateData.cbData = i2d_PKCS12(pPkcs12, &tCertificateData.pbData);

            if (tCertificateData.cbData <= 0)
            {
                OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
            }

            // free certificate.
            PKCS12_free(pPkcs12);
            pPkcs12 = NULL;

            // import DER data to temporary store
            hFileStore = PFXImportCertStore(
                &tCertificateData,
                0,
                CRYPT_EXPORTABLE | (a_bUseMachineStore) ? CRYPT_MACHINE_KEYSET : CRYPT_USER_KEYSET);
        }

        if (hFileStore == 0)
        {
            OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
        }
    }

    // free the DER blob.
    OPENSSL_free(tCertificateData.pbData);
    tCertificateData.pbData = 0;

    uStatus = OpcUa_StringToUnicode((OpcUa_StringA)a_sStoreName.c_str(), (OpcUa_Char**)&wszStoreName);
    OpcUa_GotoErrorIfBad(uStatus);

    int flags = CERT_STORE_OPEN_EXISTING_FLAG;
    flags |= (a_bUseMachineStore)?CERT_SYSTEM_STORE_LOCAL_MACHINE:CERT_SYSTEM_STORE_CURRENT_USER;

    // try to open existing store
    hCertificateStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,
        0,
        0,
        flags,
        wszStoreName);

    if (hCertificateStore == 0)
    {
        flags = CERT_STORE_CREATE_NEW_FLAG;
        flags |= (a_bUseMachineStore)?CERT_SYSTEM_STORE_LOCAL_MACHINE:CERT_SYSTEM_STORE_CURRENT_USER;

        // try to create the store
        hCertificateStore = CertOpenStore(
            CERT_STORE_PROV_SYSTEM,
            0,
            0,
            flags,
            wszStoreName);

        if (hCertificateStore == 0)
        {
            OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
        }
    }

    OpcUa_Free(wszStoreName);
    wszStoreName = NULL;

    // fetch the context from the temporary file store.
    pCertContext = CertEnumCertificatesInStore(hFileStore, NULL);

    if (pCertContext == 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
    }

    // add certificate to store.
    BOOL bResult = CertAddCertificateContextToStore(
        hCertificateStore,
        pCertContext,
        CERT_STORE_ADD_REPLACE_EXISTING,
        0);

    if (!bResult)
    {
        if (GetLastError() == ERROR_ACCESS_DENIED)
        {
            OpcUa_GotoErrorWithStatus(OpcUa_BadUserAccessDenied);
        }

        OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
    }

    CertFreeCertificateContext(pCertContext);
    pCertContext = 0;

    // free memory.
    CertCloseStore(hCertificateStore, 0);
    hCertificateStore = 0;

    CertCloseStore(hFileStore, 0);
    hFileStore = 0;

    X509_free(pX509Certificate);
    OpcUa_Free(sCommonName);
    RSA_free(pRsaPrivateKey);
    EVP_PKEY_free(pEvpKey);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pRsaPrivateKey != NULL)
    {
        RSA_free(pRsaPrivateKey);
    }

    if (pEvpKey != NULL)
    {
        EVP_PKEY_free(pEvpKey);
    }

    if (pX509Certificate != NULL)
    {
        X509_free(pX509Certificate);
    }

    if (pPkcs12 != NULL)
    {
        PKCS12_free(pPkcs12);
    }

    if (sCommonName != NULL)
    {
        OpcUa_Free(sCommonName);
    }

    if (tCertificateData.pbData != NULL)
    {
        OPENSSL_free(tCertificateData.pbData);
    }

    if (hCertificateStore != 0)
    {
        CertCloseStore(hCertificateStore, 0);
    }

    if (hFileStore != 0)
    {
        CertCloseStore(hFileStore, 0);
    }

    if (wszStoreName != NULL)
    {
        OpcUa_Free(wszStoreName);
    }

    if (pCertContext != NULL)
    {
        CertFreeCertificateContext(pCertContext);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
* OpcUa_Certificate_ParseSubjectName
*===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_ParseSubjectName(
	const char* a_sSubjectName,
	std::vector<std::string>* a_pFieldNames,
	std::vector<std::string>* m_pFieldValues)
{
	int start = 0;
	int end = 0;
	bool nameExtracted = false;
	std::string name;
	std::string value;
	std::string subjectName = a_sSubjectName;
	X509_NAME_ENTRY* pEntry = OpcUa_Null;
	bool commonNameFound = false;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_ParseSubjectName");

	OpcUa_ReturnErrorIfArgumentNull(a_sSubjectName);
	OpcUa_ReturnErrorIfArgumentNull(a_pFieldNames);
	OpcUa_ReturnErrorIfArgumentNull(m_pFieldValues);

	int length = strlen(a_sSubjectName);

	for (int ii = 0; ii < length;)
	{
		// check if the start of name found.
		if (!nameExtracted)
		{
			// skip leading white space.
			while (ii < length && _ismbcspace(a_sSubjectName[ii]))
			{
				ii++;
			}

			start = ii;

			// read name.
			while (ii < length && (isalnum(a_sSubjectName[ii]) || a_sSubjectName[ii] == '.'))
			{
				ii++;
			}

			if (start == ii)
			{
				OpcUa_GotoErrorWithStatus(OpcUa_BadSyntaxError);
			}

			end = ii;

			if (end > start)
			{
				name = subjectName.substr(start, end - start);

				// skip trailing white space.
				while (ii < length && _ismbcspace(a_sSubjectName[ii]))
				{
					ii++;
				}

				// move past equal.
				if (ii < length)
				{
					if (a_sSubjectName[ii] != '=')
					{
						OpcUa_GotoErrorWithStatus(OpcUa_BadSyntaxError);
					}

					ii++;
				}

				nameExtracted = true;

				if (name == "CN")
				{
					commonNameFound = true;
				}
			}
		}

		else
		{
			// skip leading white space.
			while (ii < length && _ismbcspace(a_sSubjectName[ii]))
			{
				ii++;
			}

			bool quoted = false;

			// check for quote.
			if (ii < length && a_sSubjectName[ii] == '"')
			{
				ii++;
				quoted = true;
			}

			start = ii;

			if (quoted)
			{
				// check for end quote.
				while (ii < length && a_sSubjectName[ii] != '"')
				{
					ii++;
				}

				end = ii;

				// skip trailing white space.
				while (ii < length && _ismbcspace(a_sSubjectName[ii]))
				{
					ii++;
				}
			}

			// check for end separator.
			while (ii < length && a_sSubjectName[ii] != '/')
			{
				ii++;
			}

			if (!quoted)
			{
				end = ii;
			}

			if (end > start)
			{
				value = subjectName.substr(start, end - start);

				// check that the name is supported.
				bool found = false;

				for (int jj = 0; g_ValidSubjectNameComponents[jj] != OpcUa_Null; jj++)
				{
					if (name == g_ValidSubjectNameComponents[jj])
					{
						a_pFieldNames->push_back(name);
						found = true;
						break;
					}
				}

				if (!found)
				{
					// a hack to deal with OpenSSL using the wrong letter.
					if (name == "S")
					{
						a_pFieldNames->push_back("ST");
					}

					// check if an OID.
					else
					{
						for (UINT jj = 0; jj < name.size(); jj++)
						{
							if (isdigit(name[jj]) || name[jj] == '.')
							{
								continue;
							}

							OpcUa_GotoErrorWithStatus(OpcUa_BadSyntaxError);
						}

						a_pFieldNames->push_back(name);
					}
				}

				m_pFieldValues->push_back(value);
				nameExtracted = false;
			}

			ii++;
		}
	}

	if (!commonNameFound)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadSyntaxError);
	}

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_Create
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_Certificate_Create(
    OpcUa_StringA      a_sStorePath,
    OpcUa_StringA      a_sApplicationName,
    OpcUa_StringA      a_sApplicationUri,
    OpcUa_StringA      a_sOrganization,
    OpcUa_StringA      a_sSubjectName,
    OpcUa_UInt32       a_uNoOfDomainNames,
    OpcUa_StringA*     a_pDomainNames,
    OpcUa_UInt32       a_uKeyType,
    OpcUa_UInt32       a_uKeySize,
    OpcUa_Int64        a_iStartOfValidityPeriod,
    OpcUa_UInt32       a_uLifetimeInMonths,
    OpcUa_UInt16       a_uSignatureHashInBits,
    OpcUa_Boolean      a_bIsCA,
    OpcUa_Boolean      a_bReuseKey,
    OpcUa_P_FileFormat a_eFileFormat,
    OpcUa_ByteString*  a_pIssuerCertificate,
    OpcUa_Key*         a_pIssuerPrivateKey,
    OpcUa_StringA      a_sPassword,
    OpcUa_ByteString*  a_pCertificate,
    OpcUa_StringA*     a_pCertificateFilePath,
    OpcUa_Key*         a_pPrivateKey,
    OpcUa_StringA*     a_pPrivateKeyFilePath)
{
    OpcUa_CryptoProvider tCryptoProvider;
    OpcUa_PKIProvider tPkiProvider;
    OpcUa_DateTime tValidFrom;
    OpcUa_DateTime tValidTo;
    OpcUa_Key tPublicKey;
    OpcUa_Crypto_NameEntry* pSubjectNameFields = OpcUa_Null;
    OpcUa_Crypto_Extension pExtensions[10];
    OpcUa_Certificate* pX509Certificate = OpcUa_Null;
    OpcUa_Certificate* pX509IssuerCertificate = OpcUa_Null;
    OpcUa_StringA pDomainName = OpcUa_Null;

    std::string domainName;
    std::string applicationUri;
    std::string subjectAltName;
    std::vector<std::string> domainNames;
    std::vector<std::string> fieldNames;
    std::vector<std::string> fieldValues;
    std::string subjectName;
    std::string storeName;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_Create");

    OpcUa_ReturnErrorIfArgumentNull(a_sStorePath);
    OpcUa_ReturnErrorIfArgumentNull(a_sApplicationName)
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
    OpcUa_ReturnErrorIfArgumentNull(a_pPrivateKey);

    if (a_pCertificateFilePath != NULL) *a_pCertificateFilePath = NULL;
    if (a_pPrivateKeyFilePath != NULL) *a_pPrivateKeyFilePath = NULL;

    OpcUa_MemSet(&tCryptoProvider, 0, sizeof(OpcUa_CryptoProvider));
    OpcUa_MemSet(&tPkiProvider, 0, sizeof(OpcUa_PKIProvider));
    OpcUa_Key_Initialize(&tPublicKey);
    OpcUa_MemSet(&pExtensions, 0, sizeof(pExtensions));

    // set a suitable default.
    switch (a_uSignatureHashInBits)
    {
        case OPCUA_P_SHA_224:
        case OPCUA_P_SHA_256:
        {
            break;
        }

        default:
        {
            a_uSignatureHashInBits = OPCUA_P_SHA_160;
            break;
        }
    }

    if (!a_bReuseKey)
    {
        OpcUa_ByteString_Initialize(a_pCertificate);
        OpcUa_Key_Initialize(a_pPrivateKey);
    }

    // set default key type.
    if (a_uKeyType == 0)
    {
        a_uKeyType = OpcUa_Crypto_Rsa_Id;
    }

    // fill in list of host names.
    if (a_uNoOfDomainNames > 0)
    {
        for (unsigned int ii = 0; ii < a_uNoOfDomainNames; ii++)
        {
            if (a_pDomainNames[ii] != OpcUa_Null)
            {
                domainNames.push_back(a_pDomainNames[ii]);
            }
        }
    }

    // generate an application uri.
    if (a_sApplicationUri == NULL || strlen(a_sApplicationUri) <= 0)
    {
        applicationUri = "urn:";
		
		if (domainNames.size() > 0)
		{
			applicationUri += domainNames[0];
		    applicationUri += ":";
		}
        
        applicationUri += a_sApplicationName;
    }
    else
    {
        applicationUri = a_sApplicationUri;
    }

    // remove invalid chars from uri.
    if (applicationUri.size() > 0)
    {
        int length = applicationUri.size();
        std::string updated;

        for (int ii = 0; ii < length; ii++)
        {
            unsigned char ch = applicationUri[ii];

            bool escape = !isprint(ch) || ch == '%' || ch == ',';

            if (escape)
            {
                char szBuf[4];
                sprintf_s(szBuf, 4, "%%%2X", ch);
                updated += szBuf;
            }
            else
            {
                if (_ismbcspace(ch))
                {
                    updated += ' ';
                }
                else
                {
                    updated += ch;
                }
            }
        }

        applicationUri = updated;
    }

    // parse the subject name.
    if (a_sSubjectName != OpcUa_Null && strlen(a_sSubjectName) > 0)
	{
		uStatus = OpcUa_Certificate_ParseSubjectName(a_sSubjectName, &fieldNames, &fieldValues);
		OpcUa_GotoErrorIfBad(uStatus);
    }

    // create a default subject name.
    if (fieldNames.size() == 0)
    {
        fieldNames.push_back("CN");
        fieldValues.push_back(a_sApplicationName);

        // ensure organization is present.
        if (a_sOrganization != NULL && strlen(a_sOrganization) > 0)
        {
            fieldNames.push_back("O");
            fieldValues.push_back(a_sOrganization);
        }

        // ensure domain is present.
        if (!a_bIsCA)
        {
			if (domainNames.size() > 0)
			{
				fieldNames.push_back("DC");
				fieldValues.push_back(domainNames[0]);
			}
        }
    }

    // create the provider.
    uStatus = OpcUa_Certificate_CreateCryptoProviders(&tPkiProvider, &tCryptoProvider);
    OpcUa_GotoErrorIfBad(uStatus);

    // set the current date as the start of the validity period.
    tValidFrom = OpcUa_DateTime_UtcNow();

    if (a_iStartOfValidityPeriod != 0)
    {
        *((LONGLONG*)&tValidFrom) = a_iStartOfValidityPeriod;
    }

    // ensure the valid from date is in the future.
    LONGLONG llNow = *((LONGLONG*)&tValidFrom);
    tValidFrom = *((OpcUa_DateTime*)(&llNow));

    // add the lifetime to the current time.
    llNow += 30*24*3600*(LONGLONG)a_uLifetimeInMonths*10000000;
    tValidTo = *((OpcUa_DateTime*)(&llNow));

    if (a_bReuseKey)
    {
        // determine size of public key.
        uStatus = OpcUa_Crypto_GetPublicKeyFromCert(
            &tCryptoProvider,
            a_pCertificate,
            OpcUa_Null,
            &tPublicKey);

        OpcUa_GotoErrorIfBad(uStatus);

        // allocate public key buffer.
        tPublicKey.Key.Data = (OpcUa_Byte*)OpcUa_Alloc(tPublicKey.Key.Length);
        OpcUa_GotoErrorIfAllocFailed(tPublicKey.Key.Data);

        // extract public key.
        uStatus = OpcUa_Crypto_GetPublicKeyFromCert(
            &tCryptoProvider,
            a_pCertificate,
            OpcUa_Null,
            &tPublicKey);

        OpcUa_GotoErrorIfBad(uStatus);

        // hack to get around the fact that the load key and the create key functions use different ids.
        if (tPublicKey.Key.Length > 0 && tPublicKey.Type == OpcUa_Crypto_Rsa_OAEP_Id)
        {
            tPublicKey.Type  = OpcUa_Crypto_Rsa_Alg_Id;
        }
    }
    else
    {
        // determine size of public key.
        uStatus = OpcUa_Crypto_GenerateAsymmetricKeypair(
            &tCryptoProvider,
            a_uKeyType,
            a_uKeySize,
            &tPublicKey,
            a_pPrivateKey);

        OpcUa_GotoErrorIfBad(uStatus);

        // allocate public key buffer.
        tPublicKey.Key.Data = (OpcUa_Byte*)OpcUa_Alloc(tPublicKey.Key.Length);
        OpcUa_GotoErrorIfAllocFailed(tPublicKey.Key.Data);

        // determine size of private key.
        uStatus = OpcUa_Crypto_GenerateAsymmetricKeypair(
            &tCryptoProvider,
            a_uKeyType,
            a_uKeySize,
            &tPublicKey,
            a_pPrivateKey);

        OpcUa_GotoErrorIfBad(uStatus);

        // allocate private key buffer.
        a_pPrivateKey->Key.Data = (OpcUa_Byte*)OpcUa_Alloc(a_pPrivateKey->Key.Length);
        OpcUa_GotoErrorIfAllocFailed(a_pPrivateKey->Key.Data);

        // generate a new key pair.
        uStatus = OpcUa_Crypto_GenerateAsymmetricKeypair(
            &tCryptoProvider,
            a_uKeyType,
            a_uKeySize,
            &tPublicKey,
            a_pPrivateKey);

        OpcUa_GotoErrorIfBad(uStatus);
    }

    // create the subject name fields.
    pSubjectNameFields = (OpcUa_Crypto_NameEntry*)OpcUa_Alloc(fieldNames.size()*sizeof(OpcUa_Crypto_NameEntry));
    OpcUa_GotoErrorIfAllocFailed(pSubjectNameFields);
    memset(pSubjectNameFields, 0, fieldNames.size()*sizeof(OpcUa_Crypto_NameEntry));

    // reverse order.
    for (int ii = (int)fieldNames.size()-1; ii >= 0; ii--)
    {
        int index = (int)fieldNames.size()-1-ii;
        pSubjectNameFields[index].key = (char*)fieldNames[ii].c_str();
        pSubjectNameFields[index].value = (char*)fieldValues[ii].c_str();
    }

    pExtensions[0].key = SN_subject_key_identifier;
    pExtensions[0].value = "hash";

    pExtensions[1].key = SN_authority_key_identifier;
    pExtensions[1].value = "keyid, issuer:always";

    if (!a_bIsCA)
    {
        pExtensions[2].key = SN_basic_constraints;
        pExtensions[2].value = "critical, CA:TRUE, pathlen:0";

        pExtensions[3].key = SN_key_usage;
        pExtensions[3].value = "critical, nonRepudiation, digitalSignature, keyEncipherment, dataEncipherment, keyCertSign";

        pExtensions[4].key = SN_ext_key_usage;
        pExtensions[4].value = "critical, serverAuth, clientAuth";

        // Add the subject alternate name extension.
        subjectAltName += "URI:";
        subjectAltName += applicationUri;

        for (DWORD ii = 0; ii < domainNames.size(); ii++)
        {
            std::string domainName = domainNames[ii];

            int iResult = inet_addr(domainName.c_str());

            if (iResult != INADDR_NONE)
            {
                subjectAltName += ",IP:";
            }
            else
            {
                subjectAltName += ",DNS:";
            }

            subjectAltName += domainName;
        }

        pExtensions[5].key = SN_subject_alt_name;
        pExtensions[5].value = (LPSTR)subjectAltName.c_str();
    }
    else
    {
        pExtensions[2].key = SN_basic_constraints;
		pExtensions[2].value = "critical, CA:TRUE";

        pExtensions[3].key = SN_key_usage;
        pExtensions[3].value = "critical, digitalSignature, keyCertSign, cRLSign";
    }

    OpcUa_Byte* pPosition = NULL;
    OpcUa_Key* pPrivateKey = a_pPrivateKey;

    // decode the issuer certificate.
    if (a_pIssuerCertificate != NULL && a_pIssuerCertificate->Length > 0)
    {
        pPosition = a_pIssuerCertificate->Data;
        pX509IssuerCertificate = (OpcUa_Certificate*)d2i_X509(NULL, (const unsigned char**)&pPosition, a_pIssuerCertificate->Length);

        if (pX509IssuerCertificate == NULL)
        {
            OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
        }

        if (a_pIssuerPrivateKey != NULL && a_pIssuerPrivateKey->Key.Length > 0)
        {
            // hack to get around the fact that the load private key and the create key functions use
            // different constants to identify the RS public keys.
            a_pIssuerPrivateKey->Type = OpcUa_Crypto_Rsa_Alg_Id;

            // use the issuer key for signing.
            pPrivateKey = a_pIssuerPrivateKey;
        }
    }

    // check for a valid private key.
    if (pPrivateKey == NULL)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
    }

    // create the certificate.
    uStatus = OpcUa_Crypto_CreateCertificate(
        &tCryptoProvider,
        0,
        tValidFrom,
        tValidTo,
        pSubjectNameFields,
        fieldNames.size(),
        tPublicKey,
        pExtensions,
        (a_bIsCA)?4:6,
        a_uSignatureHashInBits,
        pX509IssuerCertificate,
        *pPrivateKey,
        &pX509Certificate);

    OpcUa_GotoErrorIfBad(uStatus);

    // clear existing certificate.
    OpcUa_ByteString_Clear(a_pCertificate);

    // need to convert to DER encoded certificate.
    a_pCertificate->Length = i2d_X509((X509*)pX509Certificate, NULL);

    if (a_pCertificate->Length <= 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
    }

    a_pCertificate->Data = (OpcUa_Byte*)OpcUa_Alloc(a_pCertificate->Length);
    OpcUa_GotoErrorIfAllocFailed(a_pCertificate->Data);

    // OpenSSL likes to modify input parameters.
    pPosition = a_pCertificate->Data;
    int iResult = i2d_X509((X509*)pX509Certificate, &pPosition);

    if (iResult <= 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
    }

    // get the store name from the path.
    OpcUa_Boolean bUseMachineStore = OpcUa_False;

    storeName = OpcUa_Certificate_GetStoreName(a_sStorePath, &bUseMachineStore);

    // save certificate in windows based store.
    if (!storeName.empty())
    {
        uStatus = OpcUa_Certificate_SavePrivateKeyInWindowsStore(
            bUseMachineStore,
            storeName,
            a_sPassword,
            a_pCertificate,
            a_pPrivateKey);

        OpcUa_GotoErrorIfBad(uStatus);

        std::string filePath = a_sStorePath;

        *a_pCertificateFilePath = (OpcUa_StringA)OpcUa_Alloc(filePath.size()+1);
        OpcUa_GotoErrorIfAllocFailed(*a_pCertificateFilePath);
        strcpy_s(*a_pCertificateFilePath, filePath.size()+1, filePath.c_str());

        *a_pPrivateKeyFilePath = (OpcUa_StringA)OpcUa_Alloc(filePath.size()+1);
        OpcUa_GotoErrorIfAllocFailed(*a_pPrivateKeyFilePath);
        strcpy_s(*a_pPrivateKeyFilePath, filePath.size()+1, filePath.c_str());
    }

    // save certificate in file based store.
    else
    {
        // save the certificate.
		if (a_pPrivateKey != NULL && a_pPrivateKey->Key.Length > 0)
        {
            uStatus = OpcUa_Certificate_SavePrivateKeyInStore(
                a_sStorePath,
                a_eFileFormat,
                a_sPassword,
                a_pCertificate,
                a_pPrivateKey,
                a_pPrivateKeyFilePath);

            OpcUa_GotoErrorIfBad(uStatus);
        }

        // save the public key certificate.
        uStatus = OpcUa_Certificate_SavePublicKeyInStore(
            a_sStorePath,
            a_pCertificate,
            a_pCertificateFilePath);

        OpcUa_GotoErrorIfBad(uStatus);
    }

    // clean up.
    X509_free((X509*)pX509IssuerCertificate);
    X509_free((X509*)pX509Certificate);
    OpcUa_Free(pSubjectNameFields);
    OpcUa_Key_Clear(&tPublicKey);
    OpcUa_Certificate_DeleteCryptoProviders(&tPkiProvider, &tCryptoProvider);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pX509IssuerCertificate != NULL)
    {
        X509_free((X509*)pX509IssuerCertificate);
    }

    if (pX509Certificate != NULL)
    {
        X509_free((X509*)pX509Certificate);
    }

    OpcUa_Free(pSubjectNameFields);
    OpcUa_Key_Clear(a_pPrivateKey);
    OpcUa_ByteString_Clear(a_pCertificate);
    OpcUa_Key_Clear(&tPublicKey);
    OpcUa_Certificate_DeleteCryptoProviders(&tPkiProvider, &tCryptoProvider);

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_GetInfo
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_GetInfo(
    OpcUa_ByteString* a_pCertificate,
    OpcUa_StringA**   a_psNameEntries,
    OpcUa_UInt32*     a_puNoOfNameEntries,
    OpcUa_StringA*    a_psCommonName,
    OpcUa_StringA*    a_psThumbprint,
    OpcUa_StringA*    a_psApplicationUri,
    OpcUa_StringA**   a_psDomains,
    OpcUa_UInt32*     a_puNoOfDomains)
{

    OpcUa_Byte pThumbprint[SHA_DIGEST_LENGTH];
    OpcUa_CharA sBuffer[MAX_PATH*10];
    X509* pCertificate = NULL;
    const unsigned char* pPosition = NULL;
    std::vector<std::string> entries;
    std::string fullName;
    STACK_OF(CONF_VALUE)* subjectAltNameEntries = NULL;
    GENERAL_NAMES* subjectAltName = NULL;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_GetThumbprint");

    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);

    // initialize output parameters.
    if (a_psNameEntries != NULL)
    {
        OpcUa_GotoErrorIfArgumentNull(a_puNoOfNameEntries);
        *a_psNameEntries = NULL;
        *a_puNoOfNameEntries = 0;
    }

    if (a_psDomains != NULL)
    {
        OpcUa_GotoErrorIfArgumentNull(a_puNoOfDomains);
        *a_psDomains = NULL;
        *a_puNoOfDomains = 0;
    }

    if (a_psCommonName != NULL)
    {
        *a_psCommonName = NULL;
    }

    if (a_psThumbprint != NULL)
    {
        *a_psThumbprint = NULL;
    }

    if (a_psApplicationUri != NULL)
    {
        *a_psApplicationUri = NULL;
    }

    // initialize local storage.
    OpcUa_MemSet(pThumbprint, 0, SHA_DIGEST_LENGTH);
    OpcUa_MemSet(sBuffer, 0, sizeof(sBuffer));

    // decode the certifcate.
    pPosition = a_pCertificate->Data;
    pCertificate = d2i_X509(NULL, &pPosition, a_pCertificate->Length);

    if (pCertificate == NULL)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
    }

    if (a_psThumbprint != NULL)
    {
        // compute the hash.
        SHA1(a_pCertificate->Data, a_pCertificate->Length, pThumbprint);

        // allocate string to return.
        int iLength = (2*SHA_DIGEST_LENGTH+1)*sizeof(OpcUa_CharA);
        *a_psThumbprint = (OpcUa_StringA)OpcUa_Alloc(iLength);
        OpcUa_MemSet(*a_psThumbprint, 0, iLength);

        // convert to a string.
        for (int ii = 0; ii < SHA_DIGEST_LENGTH; ii++)
        {
            sprintf_s(*a_psThumbprint+ii*2, iLength-ii*2, "%02X", pThumbprint[ii]);
        }
    }

    if (a_psNameEntries != NULL || a_psCommonName != NULL)
    {
        // get the subject name.
        X509_name_st* pName = X509_get_subject_name(pCertificate);

        if (pName == NULL)
        {
            OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
        }

        X509_NAME_oneline(pName, sBuffer, sizeof(sBuffer));

        // parse the fields.
        fullName = sBuffer;

        int iStart = 0;
        int iEnd = fullName.find_first_of('/');

        do
        {
            if (iEnd == std::string::npos)
            {
                if (iStart < (int)fullName.size())
                {
                    entries.push_back(fullName.substr(iStart));
                }

                break;
            }

            if (iEnd > iStart)
            {
                entries.push_back(fullName.substr(iStart, iEnd-iStart));
            }

            iStart = iEnd+1;
            iEnd = fullName.find_first_of('/', iStart);
        }
        while (iStart != std::string::npos);

        // extract the name entries.
        if (a_psNameEntries != NULL)
        {
            uStatus = OpcUa_Certificate_CopyStrings(entries, a_psNameEntries, a_puNoOfNameEntries);
            OpcUa_GotoErrorIfBad(uStatus);
        }

        // extract the common name.
        if (a_psCommonName != NULL)
        {
            for (unsigned int ii = 0; ii < entries.size(); ii++)
            {
                std::string entry(entries[ii]);

                if (entry.find("CN=") == 0)
                {
                    int iLength = entry.size()+1;
                    *a_psCommonName = (OpcUa_StringA)OpcUa_Alloc(iLength);
                    OpcUa_GotoErrorIfAllocFailed(*a_psCommonName);
                    strcpy_s(*a_psCommonName, iLength, entry.substr(3).c_str());
                    break;
                }
            }
        }
    }

    if (a_psApplicationUri != NULL || a_psDomains != NULL)
    {
        // find the subject alt name extension.
        STACK_OF(X509_EXTENSION)* pExtensions = pCertificate->cert_info->extensions;

        for (int ii = 0; ii < sk_X509_EXTENSION_num(pExtensions); ii++)
        {
            X509_EXTENSION* pExtension = sk_X509_EXTENSION_value(pExtensions, ii);

            // get the internal id for the extension.
            int nid = OBJ_obj2nid(pExtension->object);

            if (nid == 0)
            {
                // check for obsolete name.
                ASN1_OBJECT* oid = (ASN1_OBJECT*)pExtension->object;

                if (memcmp(oid->data, ::OID_SUBJECT_ALT_NAME, 3) == 0)
                {
                    oid->nid = nid = NID_subject_alt_name;
                }
            }

            if (nid == NID_subject_alt_name)
            {
                subjectAltName = (GENERAL_NAMES*)X509V3_EXT_d2i(pExtension);
            }
        }

        // extract the fields from the subject alt name extension.
        if (subjectAltName != NULL)
        {
            entries.clear();
            subjectAltNameEntries = i2v_GENERAL_NAMES(NULL, subjectAltName, NULL);

            for (int ii = 0; ii < sk_CONF_VALUE_num(subjectAltNameEntries); ii++)
            {
                CONF_VALUE* conf = sk_CONF_VALUE_value(subjectAltNameEntries, ii);

                if (conf == NULL)
                {
                    continue;
                }

                // check for URI.
                if (a_psApplicationUri != NULL)
                {
                    // copy the application uri.
                    if (*a_psApplicationUri == NULL && strcmp(conf->name, "URI") == 0)
                    {
                        int iLength = strlen(conf->value)+1;
                        *a_psApplicationUri = (OpcUa_StringA)OpcUa_Alloc(iLength);
                        OpcUa_GotoErrorIfAllocFailed(*a_psApplicationUri);
                        strcpy_s(*a_psApplicationUri, iLength, conf->value);
                    }
                }

                // check for domain.
                if (a_psDomains != NULL)
                {
                    if (strcmp(conf->name, "DNS") == 0)
                    {
                        entries.push_back(conf->value);
                    }

                    if (strcmp(conf->name, "IP Address") == 0)
                    {
                        entries.push_back(conf->value);
                    }
                }
            }

            sk_CONF_VALUE_pop_free(subjectAltNameEntries, X509V3_conf_free);
            subjectAltNameEntries = NULL;

            sk_GENERAL_NAME_pop_free(subjectAltName, GENERAL_NAME_free);
            subjectAltName = NULL;

            // copy domains.
            if (a_psDomains != NULL)
            {
                uStatus = OpcUa_Certificate_CopyStrings(entries, a_psDomains, a_puNoOfDomains);
                OpcUa_GotoErrorIfBad(uStatus);
            }
        }
    }

    X509_free(pCertificate);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pCertificate != NULL)
    {
        X509_free(pCertificate);
    }

    if (subjectAltNameEntries != NULL)
    {
        sk_CONF_VALUE_pop_free(subjectAltNameEntries, X509V3_conf_free);
    }

    if (subjectAltName != NULL)
    {
        sk_GENERAL_NAME_pop_free(subjectAltName, GENERAL_NAME_free);
    }

    if (a_psNameEntries != NULL && *a_psNameEntries != NULL)
    {
        for (unsigned int ii = 0; ii < *a_puNoOfNameEntries; ii++)
        {
            OpcUa_Free((*a_psNameEntries)[ii]);
        }

        OpcUa_Free(*a_psNameEntries);
        *a_psNameEntries = NULL;
    }

    if (a_psCommonName != NULL && *a_psCommonName != NULL)
    {
        OpcUa_Free(*a_psCommonName);
        *a_psCommonName = NULL;
    }

    if (a_psThumbprint != NULL && *a_psThumbprint != NULL)
    {
        OpcUa_Free(*a_psThumbprint);
        *a_psThumbprint = NULL;
    }

    if (a_psApplicationUri != NULL && *a_psApplicationUri != NULL)
    {
        OpcUa_Free(*a_psApplicationUri);
        *a_psApplicationUri = NULL;
    }

    if (a_psDomains != NULL && *a_psDomains != NULL)
    {
        for (unsigned int ii = 0; ii < *a_puNoOfDomains; ii++)
        {
            OpcUa_Free((*a_psDomains)[ii]);
        }

        OpcUa_Free(*a_psDomains);
        *a_psDomains = NULL;
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_GetThumbprint
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_GetThumbprint(
    OpcUa_ByteString* a_pCertificate,
    OpcUa_StringA*    a_pThumbprint)
{
    return OpcUa_Certificate_GetInfo(a_pCertificate, NULL, NULL, NULL, a_pThumbprint, NULL, NULL, NULL);
}

/*============================================================================
 * OpcUa_Certificate_GetCommonName
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_GetCommonName(
    OpcUa_ByteString* a_pCertificate,
    OpcUa_StringA*    m_pCommonName)
{
    return OpcUa_Certificate_GetInfo(a_pCertificate, NULL, NULL, m_pCommonName, NULL, NULL, NULL, NULL);
}

/*============================================================================
 * OpcUa_Certificate_SavePublicKeyInStore
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_SavePublicKeyInStore(
    OpcUa_StringA     a_sStorePath,
    OpcUa_ByteString* a_pCertificate,
    OpcUa_StringA*    a_pFilePath)
{
    std::string filePath;
    BIO* pPublicKeyFile = OpcUa_Null;
    OpcUa_Char* wszFilePath = 0;
    FILE* fp = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_SavePublicKeyInStore");

    OpcUa_ReturnErrorIfArgumentNull(a_sStorePath);
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);

    if (a_pFilePath != NULL) *a_pFilePath = NULL;

    // get the file name for the certificate.
    filePath = OpcUa_Certificate_GetFilePathForCertificate(
        a_sStorePath,
        a_pCertificate,
        OpcUa_Crypto_Encoding_DER,
        OpcUa_True);

    if (filePath.empty())
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadNotSupported);
    }
    
    uStatus = OpcUa_StringToUnicode((OpcUa_StringA)filePath.c_str(), &wszFilePath);
    OpcUa_GotoErrorIfBad(uStatus);

    if (_wfopen_s(&fp, (wchar_t*)wszFilePath, L"wb") != 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadUserAccessDenied);
    }

    pPublicKeyFile = BIO_new_fp(fp, 0);
    OpcUa_GotoErrorIfNull(pPublicKeyFile, OpcUa_BadUserAccessDenied);

    int iResult = BIO_write(pPublicKeyFile, a_pCertificate->Data, a_pCertificate->Length);

    if (iResult == 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
    }

    // return the file path.
    if (a_pFilePath != NULL)
    {
        *a_pFilePath = (OpcUa_StringA)OpcUa_Alloc(filePath.size()+1);
        OpcUa_GotoErrorIfAllocFailed(*a_pFilePath);
        strcpy_s(*a_pFilePath, filePath.size()+1, filePath.c_str());
    }

    // clean up.
    BIO_free(pPublicKeyFile);
    OpcUa_Free(wszFilePath);
    wszFilePath = 0;
    fclose(fp);
    fp = 0;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pPublicKeyFile != NULL)
    {
        BIO_free(pPublicKeyFile);
    }

    if (wszFilePath != 0)
    {
        OpcUa_Free(wszFilePath);
        wszFilePath = 0;
    }

    if (fp != 0)
    {
        fclose(fp);
        fp = 0;
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_SavePrivateKeyInStore2
 *===========================================================================*/
static OpcUa_StatusCode OpcUa_Certificate_SavePrivateKeyInStore2(
    OpcUa_StringA      a_sStorePath,
    OpcUa_P_FileFormat a_eFileFormat,
    OpcUa_StringA      a_sPassword,
    OpcUa_ByteString*  a_pCertificate,
    EVP_PKEY*		   a_pEvpKey,
    OpcUa_StringA*     a_pFilePath)
{
    BIO* pPrivateKeyFile = OpcUa_Null;
    X509* pX509Certificate = OpcUa_Null;
    std::string filePath;
    OpcUa_StringA sCommonName = OpcUa_Null;
    OpcUa_Char* wszFilePath = 0;
    FILE* fp = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_SavePrivateKeyInStore2");

    OpcUa_ReturnErrorIfArgumentNull(a_sStorePath);
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
    OpcUa_ReturnErrorIfArgumentNull(a_pEvpKey);

    if (a_pFilePath != NULL) *a_pFilePath = NULL;

    // check for supported format.
    if (a_eFileFormat == OpcUa_Crypto_Encoding_Invalid)
    {
        return OpcUa_BadInvalidArgument;
    }

    // get the file name for the certificate.
    filePath = OpcUa_Certificate_GetFilePathForCertificate(
        a_sStorePath,
        a_pCertificate,
        a_eFileFormat,
        OpcUa_True);

    if (filePath.empty())
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadNotSupported);
    }

    uStatus = OpcUa_StringToUnicode((OpcUa_StringA)filePath.c_str(), &wszFilePath);
    OpcUa_GotoErrorIfBad(uStatus);

    if (_wfopen_s(&fp, (wchar_t*)wszFilePath, L"wb") != 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadUserAccessDenied);
    }

    pPrivateKeyFile = BIO_new_fp(fp, 0);
    OpcUa_GotoErrorIfNull(pPrivateKeyFile, OpcUa_BadUserAccessDenied);

    // convert public key to X509 structure.
    BYTE* pPosition = a_pCertificate->Data;
    pX509Certificate = d2i_X509((X509**)OpcUa_Null, (const unsigned char**)&pPosition, a_pCertificate->Length);
    OpcUa_GotoErrorIfNull(pX509Certificate, OpcUa_Bad);

    switch(a_eFileFormat)
    {
        case OpcUa_Crypto_Encoding_PEM:
        {
            // select encryption algorithm.
            const EVP_CIPHER* pCipher = NULL;
            char* pPassword = NULL;

            if (a_sPassword != NULL && strlen(a_sPassword) > 0)
            {
                pCipher = EVP_des_ede3_cbc();
                pPassword = a_sPassword;
            }

            // write to file.
			int iResult = PEM_write_bio_PKCS8PrivateKey(
                pPrivateKeyFile,
                a_pEvpKey,
                pCipher,
                NULL,
                0,
                0,
                pPassword);

            if (iResult == 0)
            {
                OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
            }

            break;
        }

        case OpcUa_Crypto_Encoding_PKCS12:
        {
            // use the common name as the friendly name.
            uStatus = OpcUa_Certificate_GetCommonName(a_pCertificate, &sCommonName);
            OpcUa_GotoErrorIfBad(uStatus);

            // create certificate.
            PKCS12* pPkcs12 = PKCS12_create(
                a_sPassword,
                sCommonName,
                a_pEvpKey,
                pX509Certificate,
                0,
                0,
                0,
                0,
                0,
                0);

            OpcUa_GotoErrorIfNull(pPkcs12, OpcUa_Bad);

            // write to file.
            int iResult = i2d_PKCS12_bio(pPrivateKeyFile, pPkcs12);

            // free certificate.
            PKCS12_free(pPkcs12);

            if (iResult == 0)
            {
                OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
            }

            break;
        }

        case OpcUa_Crypto_Encoding_DER:
        default:
        {
            uStatus = OpcUa_BadNotSupported;
            OpcUa_GotoError;
        }
    }

    // return the file path.
    if (a_pFilePath != NULL)
    {
        *a_pFilePath = (OpcUa_StringA)OpcUa_Alloc(filePath.size()+1);
        OpcUa_GotoErrorIfAllocFailed(*a_pFilePath);
        strcpy_s(*a_pFilePath, filePath.size()+1, filePath.c_str());
    }

    // free memory.
    BIO_free(pPrivateKeyFile);
    X509_free(pX509Certificate);
    OpcUa_Free(sCommonName);
    OpcUa_Free(wszFilePath);
    wszFilePath = 0;
    fclose(fp);
    fp = 0;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pPrivateKeyFile != NULL)
    {
        BIO_free(pPrivateKeyFile);
    }

    if (pX509Certificate != NULL)
    {
        X509_free(pX509Certificate);
    }

    if (sCommonName != NULL)
    {
        OpcUa_Free(sCommonName);
    }

    if (wszFilePath != 0)
    {
        OpcUa_Free(wszFilePath);
        wszFilePath = 0;
    }

    if (fp != 0)
    {
        fclose(fp);
        fp = 0;
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_SavePrivateKeyInStore
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_SavePrivateKeyInStore(
    OpcUa_StringA      a_sStorePath,
    OpcUa_P_FileFormat a_eFileFormat,
    OpcUa_StringA      a_sPassword,
    OpcUa_ByteString*  a_pCertificate,
    OpcUa_Key*         a_pPrivateKey,
    OpcUa_StringA*     a_pFilePath)
{
    RSA* pRsaPrivateKey = OpcUa_Null;
    EVP_PKEY* pEvpKey = OpcUa_Null;
    std::string filePath;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_SavePrivateKeyInStore");

    OpcUa_ReturnErrorIfArgumentNull(a_sStorePath);
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
    OpcUa_ReturnErrorIfArgumentNull(a_pPrivateKey);

    // check for supported key type.
    if (a_pPrivateKey->Type != OpcUa_Crypto_Rsa_Alg_Id && a_pPrivateKey->Type != OpcUa_Crypto_KeyType_Rsa_Private)
    {
        return OpcUa_BadInvalidArgument;
    }

    // convert DER encoded data to RSA data.
    const unsigned char* pPos = a_pPrivateKey->Key.Data;
    pRsaPrivateKey = d2i_RSAPrivateKey(NULL, &pPos, a_pPrivateKey->Key.Length);
    OpcUa_GotoErrorIfAllocFailed(pRsaPrivateKey);

    pEvpKey = EVP_PKEY_new();

    // convert to intermediary openssl struct
    if (!EVP_PKEY_set1_RSA(pEvpKey, pRsaPrivateKey))
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
    }

    uStatus = OpcUa_Certificate_SavePrivateKeyInStore2(
        a_sStorePath,
        a_eFileFormat,
        a_sPassword,
        a_pCertificate,
        pEvpKey,
        a_pFilePath);

    OpcUa_GotoErrorIfBad(uStatus);

    RSA_free(pRsaPrivateKey);
    EVP_PKEY_free(pEvpKey);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pRsaPrivateKey != NULL)
    {
        RSA_free(pRsaPrivateKey);
    }

    if (pEvpKey != NULL)
    {
        EVP_PKEY_free(pEvpKey);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_LoadPrivateKeyFromFile
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_LoadPrivateKeyFromFile(
    OpcUa_StringA      a_sFilePath,
	OpcUa_P_FileFormat a_eFileFormat,
	const char*        a_sPassword,
    OpcUa_ByteString*  a_pCertificate,
    OpcUa_Key*         a_pPrivateKey)
{
    BIO* pPrivateKeyFile = OpcUa_Null;
    RSA* pRsaPrivateKey = OpcUa_Null;
    EVP_PKEY* pEvpKey = OpcUa_Null;
    PKCS12* pPkcs12 = OpcUa_Null;
    X509* pX509 = OpcUa_Null;
    OpcUa_Char* wszFilePath = 0;
    FILE* fp = OpcUa_Null;
    int iResult = 0;
	const char* password = 0;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_LoadPrivateKeyFromFile");

    OpcUa_ReturnErrorIfArgumentNull(a_sFilePath);
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
    OpcUa_ReturnErrorIfArgumentNull(a_pPrivateKey);

    OpcUa_ByteString_Initialize(a_pCertificate);
    OpcUa_Key_Initialize(a_pPrivateKey);

    // check for supported format.
    if (a_eFileFormat == OpcUa_Crypto_Encoding_Invalid)
    {
        return OpcUa_BadInvalidArgument;
    }

	password = a_sPassword;

	if (a_sPassword != 0 && strlen(a_sPassword) == 0)
	{
		password = 0;
	}

    uStatus = OpcUa_StringToUnicode(a_sFilePath, &wszFilePath);
    OpcUa_GotoErrorIfBad(uStatus);

    if (_wfopen_s(&fp, (wchar_t*)wszFilePath, L"rb") != 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadUserAccessDenied);
    }

    pPrivateKeyFile = BIO_new_fp(fp, 0);
    OpcUa_GotoErrorIfNull(pPrivateKeyFile, OpcUa_BadUserAccessDenied);

    switch(a_eFileFormat)
    {
        case OpcUa_Crypto_Encoding_PEM:
        {
            // read from file.
            pEvpKey = PEM_read_bio_PrivateKey(
                pPrivateKeyFile,
                NULL,
                0,
				(void*)password);

			OpcUa_GotoErrorIfNull(pEvpKey, OpcUa_Bad);
            break;
        }

        case OpcUa_Crypto_Encoding_PKCS12:
        {
            // read from file.
            PKCS12* pPkcs12 = d2i_PKCS12_bio(pPrivateKeyFile, NULL);

            if (pPkcs12 == 0)
            {
                OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
            }

            // parse the certificate.
			iResult = PKCS12_parse(pPkcs12, password, &pEvpKey, &pX509, NULL);

            if (iResult == 0)
            {
                OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
            }

            // free certificate.
            PKCS12_free(pPkcs12);
            pPkcs12 = NULL;
            break;
        }

        case OpcUa_Crypto_Encoding_DER:
        default:
        {
            uStatus = OpcUa_BadNotSupported;
            OpcUa_GotoError;
        }
    }

    // get the certificate embedded with the private key.
    if (pX509 != NULL)
    {
        // need to convert to DER encoded certificate.
        a_pCertificate->Length = i2d_X509((X509*)pX509, NULL);

        if (a_pCertificate->Length <= 0)
        {
            OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
        }

        a_pCertificate->Data = (OpcUa_Byte*)OpcUa_Alloc(a_pCertificate->Length);
        OpcUa_GotoErrorIfAllocFailed(a_pCertificate->Data);

        // OpenSSL likes to modify input parameters.
        OpcUa_Byte* pPosition = a_pCertificate->Data;
        int iResult = i2d_X509((X509*)pX509, &pPosition);

        if (iResult <= 0)
        {
            OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
        }

        X509_free((X509*)pX509);
        pX509 = NULL;
    }

    // get the private key.
    pRsaPrivateKey = EVP_PKEY_get1_RSA(pEvpKey);
    OpcUa_GotoErrorIfNull(pRsaPrivateKey, OpcUa_Bad);

    // convert DER encoded data to RSA data.
    a_pPrivateKey->Type = OpcUa_Crypto_KeyType_Rsa_Private;
    a_pPrivateKey->Key.Length = i2d_RSAPrivateKey(pRsaPrivateKey, NULL);

    if (a_pPrivateKey->Key.Length <= 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
    }

    // allocate key.
    a_pPrivateKey->Key.Data = (OpcUa_Byte*)OpcUa_Alloc(a_pPrivateKey->Key.Length);
    OpcUa_GotoErrorIfAllocFailed(a_pPrivateKey->Key.Data);
    memset(a_pPrivateKey->Key.Data, 0, a_pPrivateKey->Key.Length);

    BYTE* pPosition = a_pPrivateKey->Key.Data;
    iResult = i2d_RSAPrivateKey(pRsaPrivateKey, &pPosition);

    if (iResult <= 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
    }

    // free memory.
    EVP_PKEY_free(pEvpKey);
    RSA_free(pRsaPrivateKey);
    BIO_free(pPrivateKeyFile);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_ByteString_Clear(a_pCertificate);
    OpcUa_Key_Clear(a_pPrivateKey);

    if (pPrivateKeyFile != NULL)
    {
        BIO_free(pPrivateKeyFile);
    }

    if (pEvpKey != NULL)
    {
        EVP_PKEY_free(pEvpKey);
    }

    if (pX509 != NULL)
    {
        X509_free((X509*)pX509);
    }

    if (pRsaPrivateKey != NULL)
    {
        RSA_free(pRsaPrivateKey);
    }

    if (pPkcs12 != NULL)
    {
        PKCS12_free(pPkcs12);
    }

    if (wszFilePath != 0)
    {
        OpcUa_Free(wszFilePath);
        wszFilePath = 0;
    }

    if (fp != 0)
    {
        fclose(fp);
        fp = 0;
    }

OpcUa_FinishErrorHandling;
}

static int PasswordCallback(char* buf, int size, int rwflag, void* userdata)
{
	char* password = 0;
	int length = -1;

	if (userdata != 0 && *((char*)userdata) != 0)
	{
		password = (char*)userdata;
	}
	else
	{
		password = "nonnull";
	}

	length = strlen(password);

	if (length > size)
	{
		length = size;
	}

	memcpy(buf, password, length);

	return length;
}

/*============================================================================
* OpcUa_Certificate_LoadPrivateKey
*===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_LoadPrivateKey(
	OpcUa_ByteString*   a_pBuffer,
	OpcUa_P_FileFormat  a_eFileFormat,
	const char*         a_sPassword,
	OpcUa_ByteString*   a_pCertificate,
	OpcUa_Key*          a_pPrivateKey)
{
	int iResult = 0;
	BIO* pPrivateKeyFile = OpcUa_Null;
	RSA* pRsaPrivateKey = OpcUa_Null;
	EVP_PKEY* pEvpKey = OpcUa_Null;
	PKCS12* pPkcs12 = OpcUa_Null;
	X509* pX509 = OpcUa_Null;
	OpcUa_Char* wszFilePath = 0;
	FILE* fp = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_LoadPrivateKey");

	OpcUa_ReturnErrorIfArgumentNull(a_pBuffer);
	OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
	OpcUa_ReturnErrorIfArgumentNull(a_pPrivateKey);

	OpcUa_ByteString_Initialize(a_pCertificate);
	OpcUa_Key_Initialize(a_pPrivateKey);

	// check for supported format.
	if (a_eFileFormat != OpcUa_Crypto_Encoding_PEM && a_eFileFormat != OpcUa_Crypto_Encoding_PKCS12)
	{
		return OpcUa_BadInvalidArgument;
	}

	pPrivateKeyFile = BIO_new_mem_buf(a_pBuffer->Data, a_pBuffer->Length);
	OpcUa_GotoErrorIfNull(pPrivateKeyFile, OpcUa_BadUserAccessDenied);

	if (a_sPassword != 0 && a_sPassword[0] == 0)
	{
		a_sPassword = 0;
	}

	switch (a_eFileFormat)
	{
		case OpcUa_Crypto_Encoding_PEM:
		{
			// read from file.
			pEvpKey = PEM_read_bio_PrivateKey(
				pPrivateKeyFile,
				NULL,
				PasswordCallback,
				(void*)a_sPassword);

			OpcUa_GotoErrorIfNull(pEvpKey, OpcUa_BadDecodingError);
			break;
		}

		case OpcUa_Crypto_Encoding_PKCS12:
		{
			// read from file.
			PKCS12* pPkcs12 = d2i_PKCS12_bio(pPrivateKeyFile, NULL);

			if (pPkcs12 == 0)
			{
				OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
			}

			// parse the certificate.
			iResult = PKCS12_parse(pPkcs12, a_sPassword, &pEvpKey, &pX509, NULL);

			if (iResult == 0)
			{
				OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
			}

			// free certificate.
			PKCS12_free(pPkcs12);
			pPkcs12 = NULL;
			break;
		}
	}

	// get the certificate embedded with the private key.
	if (pX509 != NULL)
	{
		// need to convert to DER encoded certificate.
		a_pCertificate->Length = i2d_X509((X509*)pX509, NULL);

		if (a_pCertificate->Length <= 0)
		{
			OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
		}

		a_pCertificate->Data = (OpcUa_Byte*)OpcUa_Alloc(a_pCertificate->Length);
		OpcUa_GotoErrorIfAllocFailed(a_pCertificate->Data);

		// OpenSSL likes to modify input parameters.
		OpcUa_Byte* pPosition = a_pCertificate->Data;
		int iResult = i2d_X509((X509*)pX509, &pPosition);

		if (iResult <= 0)
		{
			OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
		}

		X509_free((X509*)pX509);
		pX509 = NULL;
	}

	// get the private key.
	pRsaPrivateKey = EVP_PKEY_get1_RSA(pEvpKey);
	OpcUa_GotoErrorIfNull(pRsaPrivateKey, OpcUa_Bad);

	// convert DER encoded data to RSA data.
	a_pPrivateKey->Type = OpcUa_Crypto_KeyType_Rsa_Private;
	a_pPrivateKey->Key.Length = i2d_RSAPrivateKey(pRsaPrivateKey, NULL);

	if (a_pPrivateKey->Key.Length <= 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
	}

	// allocate key.
	a_pPrivateKey->Key.Data = (OpcUa_Byte*)OpcUa_Alloc(a_pPrivateKey->Key.Length);
	OpcUa_GotoErrorIfAllocFailed(a_pPrivateKey->Key.Data);
	memset(a_pPrivateKey->Key.Data, 0, a_pPrivateKey->Key.Length);

	BYTE* pPosition = a_pPrivateKey->Key.Data;
	iResult = i2d_RSAPrivateKey(pRsaPrivateKey, &pPosition);

	if (iResult <= 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
	}

	// free memory.
	EVP_PKEY_free(pEvpKey);
	RSA_free(pRsaPrivateKey);
	BIO_free(pPrivateKeyFile);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	OpcUa_ByteString_Clear(a_pCertificate);
	OpcUa_Key_Clear(a_pPrivateKey);

	if (pPrivateKeyFile != NULL)
	{
		BIO_free(pPrivateKeyFile);
	}

	if (pEvpKey != NULL)
	{
		EVP_PKEY_free(pEvpKey);
	}

	if (pX509 != NULL)
	{
		X509_free((X509*)pX509);
	}

	if (pRsaPrivateKey != NULL)
	{
		RSA_free(pRsaPrivateKey);
	}

	if (pPkcs12 != NULL)
	{
		PKCS12_free(pPkcs12);
	}

	if (wszFilePath != 0)
	{
		OpcUa_Free(wszFilePath);
		wszFilePath = 0;
	}

	if (fp != 0)
	{
		fclose(fp);
		fp = 0;
	}

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_LoadPrivateKeyFromStore
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_LoadPrivateKeyFromStore(
    OpcUa_StringA      a_sStorePath,
    OpcUa_P_FileFormat a_eFileFormat,
    OpcUa_StringA      a_sPassword,
    OpcUa_ByteString*  a_pCertificate,
    OpcUa_Key*         a_pPrivateKey)
{
    std::string filePath;
    OpcUa_ByteString tCertificate;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_LoadPrivateKeyFromStore");

    OpcUa_ReturnErrorIfArgumentNull(a_sStorePath);
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
    OpcUa_ReturnErrorIfArgumentNull(a_pPrivateKey);

    OpcUa_ByteString_Initialize(&tCertificate);
    OpcUa_Key_Initialize(a_pPrivateKey);

    // check for supported format.
    if (a_eFileFormat == OpcUa_Crypto_Encoding_Invalid)
    {
        return OpcUa_BadInvalidArgument;
    }

    // get the file name for the certificate.
    filePath = OpcUa_Certificate_GetFilePathForCertificate(
        a_sStorePath,
        a_pCertificate,
        a_eFileFormat,
        OpcUa_False);

    if (filePath.empty())
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadNotSupported);
    }

    // load from file.
    uStatus = OpcUa_Certificate_LoadPrivateKeyFromFile(
        (OpcUa_StringA)filePath.c_str(),
        a_eFileFormat,
        a_sPassword,
        &tCertificate,
        a_pPrivateKey);

    OpcUa_GotoErrorIfBad(uStatus);
    OpcUa_ByteString_Clear(&tCertificate);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_ByteString_Clear(&tCertificate);
    OpcUa_Key_Clear(a_pPrivateKey);

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_FindContext
 *===========================================================================*/
struct OpcUa_Certificate_FindContext
{
    HCERTSTORE Store;
    HANDLE File;
    PCCERT_CONTEXT Context;
};

/*============================================================================
 * OpcUa_Certificate_CheckForMatch
 *===========================================================================*/
bool OpcUa_Certificate_CheckForMatch(
    OpcUa_ByteString* a_pCertificate,
    OpcUa_StringA     a_sCommonName,
    OpcUa_StringA     a_sThumbprint)
{
    bool match = true;
    OpcUa_StringA sMatchString = NULL;

    // check for a match on the thumbprint.
    if (a_sThumbprint != NULL && strlen(a_sThumbprint) > 0)
    {
        OpcUa_StatusCode uStatus = OpcUa_Certificate_GetThumbprint(a_pCertificate, &sMatchString);

        if (OpcUa_IsBad(uStatus))
        {
            return false;
        }

        if (_stricmp(sMatchString, a_sThumbprint) != 0)
        {
            match = false;
        }

        OpcUa_Free(sMatchString);
        sMatchString = NULL;
    }

    // check for a match on the common name.
    if (match && a_sCommonName != NULL && strlen(a_sCommonName) > 0)
    {
        OpcUa_StatusCode uStatus = OpcUa_Certificate_GetCommonName(a_pCertificate, &sMatchString);

        if (OpcUa_IsBad(uStatus))
        {
            return false;
        }

        if (_stricmp(sMatchString, a_sCommonName) != 0)
        {
            match = false;
        }

        OpcUa_Free(sMatchString);
        sMatchString = NULL;
    }

    return match;
}

/*============================================================================
 * OpcUa_Certificate_FindCertificateInWindowsStore
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_FindCertificateInWindowsStore(
    OpcUa_Handle*     a_pContext,
    OpcUa_Boolean     a_bUseMachineStore,
    OpcUa_StringA     a_sStoreName,
    OpcUa_StringA     a_sCommonName,
    OpcUa_StringA     a_sThumbprint,
    OpcUa_ByteString* a_pCertificate)
{
    LPWSTR wszStoreName = NULL;
    OpcUa_Certificate_FindContext* pContext = NULL;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_FindCertificateInWindowsStore");

    OpcUa_ReturnErrorIfArgumentNull(a_pContext);
    OpcUa_ReturnErrorIfArgumentNull(a_sStoreName);
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);

    OpcUa_ByteString_Initialize(a_pCertificate);

    if (*a_pContext != NULL)
    {
        pContext = (OpcUa_Certificate_FindContext*)*a_pContext;
    }

    // create a new context.
    if (pContext == NULL)
    {
        uStatus = OpcUa_StringToUnicode(a_sStoreName, (OpcUa_Char**)&wszStoreName);
        OpcUa_GotoErrorIfBad(uStatus);

        pContext = new OpcUa_Certificate_FindContext();

        // open the certificate store.
        DWORD dwFlags = 0;

        if (a_bUseMachineStore)
        {
            dwFlags |= CERT_SYSTEM_STORE_LOCAL_MACHINE;
        }
        else
        {
            dwFlags |= CERT_SYSTEM_STORE_CURRENT_USER;
        }

        // open the store.
        pContext->Store = CertOpenStore(
           CERT_STORE_PROV_SYSTEM,
           0,
           0,
           dwFlags,
           wszStoreName);

        if (pContext->Store == 0)
        {
            OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
        }

        OpcUa_Free(wszStoreName);
    }

    // Find the certificates in the system store.
    while (pContext->Context = CertEnumCertificatesInStore(pContext->Store, pContext->Context))
    {
        OpcUa_ByteString tCertificate;
        tCertificate.Data = pContext->Context->pbCertEncoded;
        tCertificate.Length = pContext->Context->cbCertEncoded;

        // check for match.
        bool match = OpcUa_Certificate_CheckForMatch(&tCertificate, a_sCommonName, a_sThumbprint);

        // copy certificate if match found.
        if (match)
        {
            a_pCertificate->Data = (OpcUa_Byte*)OpcUa_Alloc(tCertificate.Length);
            OpcUa_GotoErrorIfAllocFailed(a_pCertificate->Data);
            OpcUa_MemCpy(a_pCertificate->Data, tCertificate.Length, tCertificate.Data, tCertificate.Length);
            a_pCertificate->Length = tCertificate.Length;
            break;
        }
    }

    // check if nothing found.
    if (pContext->Context == NULL)
    {
        CertCloseStore(pContext->Store, 0);
        delete pContext;
        *a_pContext = NULL;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_ByteString_Clear(a_pCertificate);
    OpcUa_Certificate_FreeFindContext((OpcUa_Handle*)&pContext);

    if (wszStoreName != NULL)
    {
        OpcUa_Free(wszStoreName);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_FindCertificateInStore
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_FindCertificateInStore(
    OpcUa_Handle*     a_pContext,
    OpcUa_StringA     a_sStorePath,
    OpcUa_Boolean     a_sHasPrivateKey,
    OpcUa_StringA     a_sPassword,
    OpcUa_StringA     a_sCommonName,
    OpcUa_StringA     a_sThumbprint,
    OpcUa_ByteString* a_pCertificate,
    OpcUa_Key*        a_pPrivateKey)
{
    OpcUa_Certificate_FindContext* pContext = NULL;
    WIN32_FIND_DATA tFindFileData;
    std::string filePath;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_FindCertificateInStore");

    OpcUa_ReturnErrorIfArgumentNull(a_sStorePath);
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
    OpcUa_ReturnErrorIfArgumentNull(a_pPrivateKey);

    OpcUa_ByteString_Initialize(a_pCertificate);
    OpcUa_Key_Initialize(a_pPrivateKey);
    OpcUa_MemSet(&tFindFileData, 0, sizeof(tFindFileData));

    if (a_pContext != NULL && *a_pContext != NULL)
    {
        pContext = (OpcUa_Certificate_FindContext*)*a_pContext;
    }

    // create a new context.
    if (pContext == NULL)
    {
        pContext = new OpcUa_Certificate_FindContext();

        // specify the search criteria.
        filePath = a_sStorePath;

        if (a_sHasPrivateKey)
        {
            filePath += "\\private\\*.pfx";
        }
        else
        {
            filePath += "\\certs\\*.der";
        }

        pContext->File = FindFirstFile(filePath.c_str(), &tFindFileData);

        if (INVALID_HANDLE_VALUE == pContext->File)
        {
            delete pContext;
            return OpcUa_Good;
        }
    }

    // process existing context.
    else
    {
        if (!FindNextFile(pContext->File, &tFindFileData))
        {
            FindClose(pContext->File);
            delete pContext;
            return OpcUa_Good;
        }
    }

    bool match = false;

    do
    {
        // build target path.
        std::string targetPath = a_sStorePath;

        if (a_sHasPrivateKey)
        {
            targetPath += "\\private\\";
        }
        else
        {
            targetPath += "\\certs\\";
        }

        targetPath += tFindFileData.cFileName;

        // load private key from file.
        if (a_sHasPrivateKey)
        {
            uStatus = OpcUa_Certificate_LoadPrivateKeyFromFile(
                (OpcUa_StringA)targetPath.c_str(),
                OpcUa_Crypto_Encoding_PKCS12,
                a_sPassword,
                a_pCertificate,
                a_pPrivateKey);

            if (OpcUa_IsBad(uStatus))
            {
                continue;
            }
        }

        // load public key from file.
        else
        {
            uStatus = OpcUa_ReadFile((OpcUa_StringA)targetPath.c_str(), a_pCertificate);

            if (OpcUa_IsBad(uStatus))
            {
                continue;
            }
        }

        // check for match.
        match = OpcUa_Certificate_CheckForMatch(a_pCertificate, a_sCommonName, a_sThumbprint);

        if (match)
        {
            break;
        }

        OpcUa_ByteString_Clear(a_pCertificate);
        OpcUa_Key_Clear(a_pPrivateKey);
    }
    while (FindNextFile(pContext->File, &tFindFileData));

    // check if nothing found.
    if (!match)
    {
        FindClose(pContext->File);
        delete pContext;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_ByteString_Clear(a_pCertificate);
    OpcUa_Key_Clear(a_pPrivateKey);
    OpcUa_Certificate_FreeFindContext((OpcUa_Handle*)&pContext);

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_FreeFindContext
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_FreeFindContext(
    OpcUa_Handle* a_pContext)
{
    OpcUa_Certificate_FindContext* pContext = NULL;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_FreeFindContext");

    OpcUa_ReturnErrorIfArgumentNull(a_pContext);

    if (*a_pContext != NULL)
    {
        pContext = (OpcUa_Certificate_FindContext*)*a_pContext;
    }

    if (pContext != NULL)
    {
        if (pContext->Context != NULL)
        {
            CertFreeCertificateContext(pContext->Context);
        }

        if (pContext->Store != NULL)
        {
            CertCloseStore(pContext->Store, 0);
        }

        if (pContext->File != NULL)
        {
            FindClose(pContext->File);
        }

        delete pContext;
    }

    *a_pContext = NULL;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    // nothing to do.

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_LoadPrivateKeyFromWindowsStore
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_LoadPrivateKeyFromWindowsStore(
    OpcUa_Boolean     a_bUseMachineStore,
    OpcUa_StringA     a_sStoreName,
    OpcUa_StringA     a_sThumbprint,
    OpcUa_StringA     a_sPassword,
    OpcUa_ByteString* a_pCertificate,
    OpcUa_Key*        a_pPrivateKey)
{
    HCERTSTORE hMemoryStore = NULL;
    HCERTSTORE hCertificateStore = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    PCCERT_CONTEXT pCertContext2 = NULL;
    LPWSTR wszStoreName = NULL;
    LPWSTR wszPassword = NULL;
    std::string privateKeyFile;
    std::string thumbprint;

    CRYPT_HASH_BLOB tThumbprint;
    CRYPT_DATA_BLOB tPfxData;
    OpcUa_Byte pHashBuffer[SHA_DIGEST_LENGTH];

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_LoadPrivateKeyFromWindowsStore");

    OpcUa_ReturnErrorIfArgumentNull(a_sStoreName);
    OpcUa_ReturnErrorIfArgumentNull(a_sThumbprint);
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
    OpcUa_ReturnErrorIfArgumentNull(a_pPrivateKey);

    memset(&tThumbprint, 0, sizeof(tThumbprint));
    memset(&tPfxData, 0, sizeof(tPfxData));
    memset(&pHashBuffer, 0, sizeof(pHashBuffer));
    OpcUa_Key_Initialize(a_pPrivateKey);

    thumbprint = a_sThumbprint;

    // open the certificate store.
    DWORD dwFlags = CERT_STORE_OPEN_EXISTING_FLAG;

    if (a_bUseMachineStore)
    {
        dwFlags |= CERT_SYSTEM_STORE_LOCAL_MACHINE;
    }
    else
    {
        dwFlags |= CERT_SYSTEM_STORE_CURRENT_USER;
    }

    uStatus = OpcUa_StringToUnicode(a_sStoreName, (OpcUa_Char**)&wszStoreName);
    OpcUa_GotoErrorIfBad(uStatus);

    // open the store.
    hCertificateStore = CertOpenStore(
       CERT_STORE_PROV_SYSTEM,
       0,
       0,
       dwFlags,
       wszStoreName);

    if (hCertificateStore == 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
    }

    // get the thumbprint.
    for (size_t ii = 0; ii < thumbprint.size(); ii++)
    {
        const char* pBuffer = thumbprint.substr(ii, 1).c_str();
        pHashBuffer[ii%2] = (OpcUa_Byte)strtol(pBuffer, (char**)&pBuffer, 16);
        pHashBuffer[ii%2] <<= 4;

        if (ii+1 >= thumbprint.size())
        {
            pBuffer = thumbprint.substr(ii+1, 1).c_str();
            pHashBuffer[ii%2] += (OpcUa_Byte)strtol(pBuffer, (char**)&pBuffer, 16);
        }
    }

    tThumbprint.pbData = pHashBuffer;
    tThumbprint.cbData = SHA_DIGEST_LENGTH;

    // find the certificate with the specified hash.
    pCertContext = CertFindCertificateInStore(
        hCertificateStore,
        X509_ASN_ENCODING,
        0,
        CERT_FIND_HASH,
        &tThumbprint,
        NULL);

    if (pCertContext == NULL)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadNotFound);
    }

    // create memory store.
    hMemoryStore = CertOpenStore(
        CERT_STORE_PROV_MEMORY,
        0,
        0,
        0,
        OpcUa_Null);

    if (hMemoryStore == NULL)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadNotFound);
    }

    // create a link to the original certificate.
    BOOL bResult = CertAddCertificateLinkToStore(
        hMemoryStore,
        pCertContext,
        CERT_STORE_ADD_REPLACE_EXISTING,
        &pCertContext2);

    if (!bResult)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
    }

    // convert the password to unicode.
    if (a_sPassword != NULL)
    {
        uStatus = OpcUa_StringToUnicode(a_sPassword, (OpcUa_Char**)&wszPassword);
        OpcUa_GotoErrorIfBad(uStatus);
    }

    // determine the size of the blob.
    bResult = PFXExportCertStoreEx(
        hMemoryStore,
        &tPfxData,
        wszPassword,
        0,
        EXPORT_PRIVATE_KEYS);

    if (!bResult)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
    }

    // allocate memory.
    tPfxData.pbData = (BYTE*)OpcUa_Alloc(tPfxData.cbData);
    OpcUa_GotoErrorIfAllocFailed(tPfxData.pbData);
    memset(tPfxData.pbData, 0, tPfxData.cbData);

    // export the PFX blob.
    bResult = PFXExportCertStoreEx(
        hMemoryStore,
        &tPfxData,
        wszPassword,
        0,
        EXPORT_PRIVATE_KEYS);

    if (!bResult)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
    }

    /*
    // get the file name for the certificate.
    privateKeyFile = OpcUa_Certificate_GetFilePathForCertificate(
        a_sTargetStorePath,
        a_pCertificate,
        OpcUa_Crypto_Encoding_PKCS12,
        OpcUa_True);

    if (privateKeyFile.empty())
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
    }

    // write to the file.
    uStatus = OpcUa_WriteFile((OpcUa_StringA)privateKeyFile.c_str(), tPfxData.pbData, tPfxData.cbData);
    OpcUa_GotoErrorIfBad(uStatus);

    // load the certificate that was just saved.
    uStatus = OpcUa_Certificate_LoadPrivateKeyFromStore(
        a_sTargetStorePath,
        OpcUa_Crypto_Encoding_PKCS12,
        a_sPassword,
        a_pCertificate,
        a_pPrivateKey);

    OpcUa_GotoErrorIfBad(uStatus);
    */

    // clean up.
    CertCloseStore(hMemoryStore, 0);
    CertCloseStore(hCertificateStore, 0);
    OpcUa_Free(tPfxData.pbData);
    OpcUa_Free(wszStoreName);
    OpcUa_Free(wszPassword);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pCertContext != NULL)
    {
        CertFreeCertificateContext(pCertContext);
    }

    if (pCertContext2 != NULL)
    {
        CertFreeCertificateContext(pCertContext2);
    }

    if (hMemoryStore != NULL)
    {
        CertCloseStore(hMemoryStore, 0);
    }

    if (hCertificateStore != NULL)
    {
        CertCloseStore(hCertificateStore, 0);
    }

    OpcUa_Key_Clear(a_pPrivateKey);
    OpcUa_Free(tPfxData.pbData);
    OpcUa_Free(wszStoreName);
    OpcUa_Free(wszPassword);

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_ImportToWindowsStore
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_ImportToWindowsStore(
    OpcUa_ByteString* a_pCertificate,
    OpcUa_Boolean     a_bUseMachineStore,
    OpcUa_StringA     a_sStoreName)
{
    HCERTSTORE hCertificateStore = NULL;
    LPWSTR wszStoreName = NULL;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_ImportToWindowsStore");

    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);

    // import certificate.
    DWORD dwFlags = CERT_STORE_OPEN_EXISTING_FLAG;

    if (a_bUseMachineStore)
    {
        dwFlags |= CERT_SYSTEM_STORE_LOCAL_MACHINE;
    }
    else
    {
        dwFlags |= CERT_SYSTEM_STORE_CURRENT_USER;
    }

    uStatus = OpcUa_StringToUnicode(a_sStoreName, (OpcUa_Char**)&wszStoreName);
    OpcUa_GotoErrorIfBad(uStatus);

    // open the store.
    hCertificateStore = CertOpenStore(
       CERT_STORE_PROV_SYSTEM,
       0,
       0,
       dwFlags,
       wszStoreName);

    if (hCertificateStore == 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
    }

    // add certificate to store.
    BOOL bResult = CertAddEncodedCertificateToStore(
        hCertificateStore,
        X509_ASN_ENCODING,
        a_pCertificate->Data,
        a_pCertificate->Length,
        CERT_STORE_ADD_REPLACE_EXISTING,
        NULL);

    if (!bResult)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
    }

    // clean up.
    CertCloseStore(hCertificateStore, 0);
    OpcUa_Free(wszStoreName);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (hCertificateStore != NULL)
    {
        CertCloseStore(hCertificateStore, 0);
    }

    OpcUa_Free(wszStoreName);

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_ImportPrivateKeyToWindowsStore
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_ImportPrivateKeyToWindowsStore(
    OpcUa_StringA     a_sSourceStorePath,
    OpcUa_ByteString* a_pCertificate,
    OpcUa_StringA     a_sPassword,
    OpcUa_Boolean     a_bUseMachineStore,
    OpcUa_StringA     a_sStoreName)
{
    HCERTSTORE hFileStore = NULL;
    HCERTSTORE hCertificateStore = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    PCCERT_CONTEXT pCertContext2 = NULL;
    LPWSTR wszStoreName = NULL;
    LPWSTR wszPassword = NULL;
    CRYPT_DATA_BLOB tCertificateData;
    OpcUa_ByteString tFileData;
    std::string privateKeyFile;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_ImportPrivateKeyToWindowsStore");

    OpcUa_ReturnErrorIfArgumentNull(a_sSourceStorePath);

    memset(&tCertificateData, 0, sizeof(CRYPT_DATA_BLOB));
    OpcUa_ByteString_Initialize(&tFileData);

    // get the file name for the certificate.
    privateKeyFile = OpcUa_Certificate_GetFilePathForCertificate(
        a_sSourceStorePath,
        a_pCertificate,
        OpcUa_Crypto_Encoding_PKCS12,
        OpcUa_False);

    if (privateKeyFile.empty())
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
    }

    // read the certificate from disk.
    uStatus = OpcUa_ReadFile((OpcUa_StringA)privateKeyFile.c_str(), &tFileData);
    OpcUa_GotoErrorIfBad(uStatus);

    // import certificate.
    DWORD dwFlags = CRYPT_EXPORTABLE;

    if (a_bUseMachineStore)
    {
        dwFlags |= CRYPT_MACHINE_KEYSET;
    }
    else
    {
        dwFlags |= CRYPT_USER_KEYSET;
    }

    uStatus = OpcUa_StringToUnicode(a_sPassword, (OpcUa_Char**)&wszPassword);
    OpcUa_GotoErrorIfBad(uStatus);

    tCertificateData.pbData = tFileData.Data;
    tCertificateData.cbData = tFileData.Length;

    hFileStore = PFXImportCertStore(&tCertificateData, wszPassword, dwFlags);

    if (hFileStore == 0)
    {
        if (wszPassword == NULL)
        {
            hFileStore = PFXImportCertStore(&tCertificateData, L"", dwFlags);
        }
        else if (wszPassword[0] == '\0')
        {
            hFileStore = PFXImportCertStore(&tCertificateData, NULL, dwFlags);
        }

        if (hFileStore == 0)
        {
            OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
        }
    }

    // open the certificate store.
    dwFlags = 0;

    if (a_bUseMachineStore)
    {
        dwFlags |= CERT_SYSTEM_STORE_LOCAL_MACHINE;
    }
    else
    {
        dwFlags |= CERT_SYSTEM_STORE_CURRENT_USER;
    }

    uStatus = OpcUa_StringToUnicode(a_sStoreName, (OpcUa_Char**)&wszStoreName);
    OpcUa_GotoErrorIfBad(uStatus);

    // open the store.
    hCertificateStore = CertOpenStore(
       CERT_STORE_PROV_SYSTEM,
       0,
       0,
       dwFlags,
       wszStoreName);

    if (hCertificateStore == 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
    }

    // Find the certificates in the system store.
    while (pCertContext = CertEnumCertificatesInStore(hFileStore, pCertContext))
    {
        // add back into store.
        BOOL bResult = CertAddCertificateContextToStore(
            hCertificateStore,
            pCertContext,
            CERT_STORE_ADD_REPLACE_EXISTING,
            &pCertContext2);

        if (bResult == 0)
        {
            OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
        }

        CertFreeCertificateContext(pCertContext2);
        pCertContext2 = NULL;
    }

    // clean up.
    CertCloseStore(hFileStore, 0);
    CertCloseStore(hCertificateStore, 0);
    OpcUa_Free(tCertificateData.pbData);
    OpcUa_Free(wszStoreName);
    OpcUa_Free(wszPassword);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pCertContext != NULL)
    {
        CertFreeCertificateContext(pCertContext);
    }

    if (pCertContext2 != NULL)
    {
        CertFreeCertificateContext(pCertContext2);
    }

    if (hFileStore != NULL)
    {
        CertCloseStore(hFileStore, 0);
    }

    if (hCertificateStore != NULL)
    {
        CertCloseStore(hCertificateStore, 0);
    }

    OpcUa_Free(tCertificateData.pbData);
    OpcUa_Free(wszStoreName);
    OpcUa_Free(wszPassword);

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_LookupDomainName
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_LookupDomainName(
    OpcUa_StringA  a_sAddress,
    OpcUa_StringA* a_pDomainName)
{
    struct sockaddr_in tAddress;
    char sHostname[NI_MAXHOST];

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_FreeFindContext");

    OpcUa_ReturnErrorIfArgumentNull(a_sAddress);
    OpcUa_ReturnErrorIfArgumentNull(a_pDomainName);

    *a_pDomainName = NULL;

    OpcUa_MemSet(&tAddress, 0, sizeof(tAddress));
    OpcUa_MemSet(sHostname, 0, sizeof(sHostname));

    tAddress.sin_family = AF_INET;
    tAddress.sin_addr.s_addr = inet_addr(a_sAddress);
    tAddress.sin_port = htons(0);

    int iResult = getnameinfo(
        (struct sockaddr*)&tAddress,
        sizeof(sockaddr_in),
        sHostname,
        NI_MAXHOST,
        NULL,
        0,
        0);

    if (iResult != 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadCommunicationError);
    }

    int iLength = strlen(sHostname)+1;
    *a_pDomainName = (OpcUa_StringA)OpcUa_Alloc(iLength);
    OpcUa_GotoErrorIfAllocFailed(*a_pDomainName);
    strcpy_s(*a_pDomainName, iLength, sHostname);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    // nothing to do.

OpcUa_FinishErrorHandling;
}


/*============================================================================
 * OpcUa_Certificate_LookupLocalhostNames
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_LookupLocalhostNames(
    OpcUa_StringA** a_pHostNames,
    OpcUa_UInt32*   a_pNoOfHostNames)
{
    char sBuffer[NI_MAXHOST];
    std::vector<std::string> hostnames;
    struct addrinfo* pResult = NULL;
    struct addrinfo tHints;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "sDnsName");

    OpcUa_ReturnErrorIfArgumentNull(a_pHostNames);
    OpcUa_ReturnErrorIfArgumentNull(a_pNoOfHostNames);

    *a_pHostNames = NULL;
    *a_pNoOfHostNames = 0;

    memset(&tHints, 0, sizeof(tHints));

    if (gethostname(sBuffer, sizeof(sBuffer)) == SOCKET_ERROR)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadCommunicationError);
    }

    hostnames.push_back(sBuffer);

    tHints.ai_family = AF_UNSPEC;
    tHints.ai_socktype = SOCK_STREAM;
    tHints.ai_protocol = IPPROTO_TCP;

    int iResult = getaddrinfo(sBuffer, NULL, &tHints, &pResult);

    if (iResult != 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadCommunicationError);;
    }

    for (struct addrinfo* ptr = pResult; ptr != NULL ; ptr = ptr->ai_next)
    {
        if (ptr->ai_family == AF_INET)
        {
            struct sockaddr_in tAddress;
            memcpy(&tAddress, ptr->ai_addr, sizeof(struct sockaddr_in));
            hostnames.push_back(inet_ntoa(tAddress.sin_addr));
        }

        /*
        if (ptr->ai_family == AF_INET6)
        {
            struct sockaddr_in6 tAddress;
            memcpy(&tAddress, ptr->ai_addr, sizeof(struct sockaddr_in6));

            // enclose in [] so it can be used in a URL.
            sBuffer[0] = '[';
            InetNtop(AF_INET6, &tAddress.sin6_addr, sBuffer+1, NI_MAXHOST);

            int iEnd = strlen(sBuffer);
            sBuffer[iEnd] = ']';
            sBuffer[iEnd+1] = 0;

            hostnames.push_back(sBuffer);
        }
        */
    }

    freeaddrinfo(pResult);
    pResult = NULL;

    uStatus = OpcUa_Certificate_CopyStrings(hostnames, a_pHostNames, a_pNoOfHostNames);
    OpcUa_GotoErrorIfBad(uStatus);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pResult != NULL)
    {
        freeaddrinfo(pResult);
    }

OpcUa_FinishErrorHandling;
}


/*============================================================================
 * OpcUa_Certificate_LoadCRL
 *===========================================================================*/
static OpcUa_StatusCode OpcUa_Certificate_LoadCRL(
    OpcUa_StringA  a_sFilePath,
    X509_CRL**     a_ppCrl)
{
    BIO* pFile = OpcUa_Null;
    X509_CRL* pCrl = OpcUa_Null;
    OpcUa_Char* wszFilePath = 0;
    FILE* fp = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_LoadCRL");

    OpcUa_ReturnErrorIfArgumentNull(a_sFilePath);
    OpcUa_ReturnErrorIfArgumentNull(a_ppCrl);

    *a_ppCrl = OpcUa_Null;

    uStatus = OpcUa_StringToUnicode(a_sFilePath, &wszFilePath);
    OpcUa_GotoErrorIfBad(uStatus);

    if (_wfopen_s(&fp, (wchar_t*)wszFilePath, L"rb") != 0)
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Could not access CRL file: %s\n", a_sFilePath);
        OpcUa_GotoErrorWithStatus(OpcUa_BadUserAccessDenied);
    }

    pFile = BIO_new_fp(fp, 0);

    if (pFile == OpcUa_Null)
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Could not access CRL file: %s\n", a_sFilePath);
        OpcUa_GotoErrorWithStatus(OpcUa_Bad);
    }

    pCrl = d2i_X509_CRL_bio(pFile, OpcUa_Null);

    if (pCrl == NULL)
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Could not load CRL file: %s\n", a_sFilePath);
        OpcUa_GotoErrorWithStatus(OpcUa_Bad);
    }

    BIO_free(pFile);
    pFile = OpcUa_Null;
    OpcUa_Free(wszFilePath);
    wszFilePath = 0;
    fclose(fp);
    fp = 0;

    *a_ppCrl = pCrl;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pFile != OpcUa_Null)
    {
        BIO_free(pFile);
    }

    if (pCrl != OpcUa_Null)
    {
        X509_CRL_free(pCrl);
    }

OpcUa_FinishErrorHandling;
}

#ifdef NO_USED_MAY_FIND_A_USE_FOR_LATER
/*============================================================================
 * OpcUa_Certificate_FindCRLsForIssuer
 *===========================================================================*/
static OpcUa_StatusCode OpcUa_Certificate_FindCRLsForIssuer(
    OpcUa_StringA	    a_sStorePath,
    X509*               a_pIssuer,
    EVP_PKEY*           a_pIssuerKey,
    STACK_OF(X509_CRL)* a_pCrls)
{
    X509_CRL* pCrl = OpcUa_Null;
    OpcUa_CharA sCrlFindPattern[MAX_PATH];
    OpcUa_CharA sCrlFilePath[MAX_PATH];
    WIN32_FIND_DATAA tFindFileData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    X509_NAME* pTargetName = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_FindCRLsForIssuer");

    OpcUa_ReturnErrorIfArgumentNull(a_sStorePath);
    OpcUa_ReturnErrorIfArgumentNull(a_pIssuer);
    OpcUa_ReturnErrorIfArgumentNull(a_pIssuerKey);
    OpcUa_ReturnErrorIfArgumentNull(a_pCrls);

    /* find all CRLs in the certificate store. */
    OpcUa_StrnCpyA(sCrlFindPattern, MAX_PATH, a_sStorePath, MAX_PATH);
    OpcUa_StrnCatA(sCrlFindPattern, MAX_PATH, "\\crl\\*.crl", MAX_PATH);

    pTargetName = X509_get_subject_name(a_pIssuer);

    hFind = FindFirstFileA(sCrlFindPattern, &tFindFileData);

    while (hFind != INVALID_HANDLE_VALUE)
    {
        OpcUa_StrnCpyA(sCrlFilePath, MAX_PATH, a_sStorePath, MAX_PATH);
        OpcUa_StrnCatA(sCrlFilePath, MAX_PATH, "\\crl\\", MAX_PATH);
        OpcUa_StrnCatA(sCrlFilePath, MAX_PATH, tFindFileData.cFileName, MAX_PATH);

        uStatus = OpcUa_Certificate_LoadCRL(sCrlFilePath, &pCrl);
        OpcUa_GotoErrorIfBad(uStatus);

        /* only care about CRLs for the current issuer. */
        if (X509_NAME_cmp(X509_CRL_get_issuer(pCrl), pTargetName) == 0)
        {
            /* generate an error if someone has been mucking with the signatures. */
            if (X509_CRL_verify(pCrl, a_pIssuerKey) <= 0)
            {
                OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Invalid signature on CRL file: %s\n", sCrlFilePath);
                OpcUa_GotoErrorWithStatus(OpcUa_Bad);
            }

            sk_X509_CRL_push(a_pCrls, pCrl);
            pCrl = OpcUa_Null;
        }

        /* discard CRLs for other issuers */
        else
        {
            X509_CRL_free(pCrl);
            pCrl = OpcUa_Null;
        }

        if (!FindNextFileA(hFind, &tFindFileData))
        {
            break;
        }
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pCrl != OpcUa_Null)
    {
        X509_CRL_free(pCrl);
    }

OpcUa_FinishErrorHandling;
}
#endif

static const EVP_MD* GetDigestAlgorithm(OpcUa_UInt16 a_uHashSizeInBits)
{
	const EVP_MD* pDigest = 0;

	switch (a_uHashSizeInBits)
	{
	case 160: { pDigest = EVP_sha1();   break; }

	case 0:
	case 256: { pDigest = EVP_sha256(); break; }

	case 512: { pDigest = EVP_sha512(); break; }
	}

	return pDigest;
}

/*============================================================================
 * OpcUa_Certificate_CreateCRL
 *===========================================================================*/
static OpcUa_StatusCode OpcUa_Certificate_CreateCRL(
    OpcUa_StringA	    a_sStorePath,
    X509*               a_pIssuer,
    EVP_PKEY*           a_pIssuerKey,
	OpcUa_UInt16        a_uHashSizeInBits,
    X509*               a_pCertificate,
    OpcUa_Boolean       a_bUnrevoke,
    OpcUa_StringA       a_sCrlFilePath)
{
    X509_CRL* pNewCrl = OpcUa_Null;
    X509_CRL* pExistingCrl = OpcUa_Null;
    X509_REVOKED* pExistingEntry = OpcUa_Null;
    ASN1_TIME* pTime = OpcUa_Null;
    ASN1_INTEGER* pSerialNumber = OpcUa_Null;
    X509_REVOKED* pEntry = OpcUa_Null;
    const EVP_MD* pHashType = OpcUa_Null;
    BIO* pFile = OpcUa_Null;
    int ii = 0;
    int iResult = 0;
    OpcUa_Char* wszFilePath = 0;
    FILE* fp = OpcUa_Null;
	const EVP_MD* pDigest = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_CreateCRL");

    OpcUa_ReturnErrorIfArgumentNull(a_sStorePath);
    OpcUa_ReturnErrorIfArgumentNull(a_pIssuer);
    OpcUa_ReturnErrorIfArgumentNull(a_pIssuerKey);
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
    OpcUa_ReturnErrorIfArgumentNull(a_sCrlFilePath);

    /* create the new CRL */
    pNewCrl = X509_CRL_new();
    OpcUa_GotoErrorIfAllocFailed(pNewCrl);

    /* set the version */
    if (!X509_CRL_set_version(pNewCrl, 1))
    {
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Could not set version of CRL.\n");
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
    }

    /* set the issuer of the CRL */
    if (!X509_CRL_set_issuer_name(pNewCrl, X509_get_subject_name(a_pIssuer)))
    {
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Could not set issuer name in CRL.\n");
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
    }

	/* add extensions */
	X509_EXTENSION* pKeyId = OpcUa_Null;

	X509V3_CTX context;
	X509V3_set_ctx(&context, a_pIssuer, OpcUa_Null, OpcUa_Null, pNewCrl, 0);

	pKeyId = X509V3_EXT_conf_nid(NULL, &context, NID_authority_key_identifier, "keyid, issuer:always");

	if (pKeyId == 0)
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Could not create authority key id extension for CRL.\n");
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	X509_CRL_add_ext(pNewCrl, pKeyId, -1);
	X509_EXTENSION_free(pKeyId);

	/* set the time indicated when the CRL was generated */
    pTime = ASN1_TIME_new();
    OpcUa_GotoErrorIfAllocFailed(pTime);

    X509_gmtime_adj(pTime,0);
    X509_CRL_set_lastUpdate(pNewCrl, pTime);

    /* find the existing CRLs for the issuer */
    if (GetFileAttributes(a_sCrlFilePath) != INVALID_FILE_ATTRIBUTES)
    {
        uStatus = OpcUa_Certificate_LoadCRL(a_sCrlFilePath, &pExistingCrl);
        OpcUa_GotoErrorIfBad(uStatus);

        /* merge the CRLs into a single list */
        for (ii = 0; ii < sk_X509_REVOKED_num(pExistingCrl->crl->revoked); ii++)
        {
            X509_REVOKED* pRevoked = sk_X509_REVOKED_value(pExistingCrl->crl->revoked, ii);

            if (a_bUnrevoke)
            {
                pSerialNumber = X509_get_serialNumber(a_pCertificate);

                if (ASN1_INTEGER_cmp(pSerialNumber, pRevoked->serialNumber) == 0)
                {
                    continue;
                }
            }

            if (!X509_CRL_get0_by_serial(pNewCrl, &pExistingEntry, pRevoked->serialNumber))
            {
                pEntry = X509_REVOKED_new();
                OpcUa_GotoErrorIfAllocFailed(pEntry);

                X509_REVOKED_set_serialNumber(pEntry, pRevoked->serialNumber);
                X509_REVOKED_set_revocationDate(pEntry, pRevoked->revocationDate);

                X509_CRL_add0_revoked(pNewCrl, pEntry);
                pEntry = OpcUa_Null;
            }
        }

        X509_CRL_free(pExistingCrl);
        pExistingCrl = OpcUa_Null;
    }

    /* add the certificate to the revocation list */
    if (!a_bUnrevoke)
    {
        pSerialNumber = X509_get_serialNumber(a_pCertificate);

        if (!X509_CRL_get0_by_serial(pNewCrl, &pExistingEntry, pSerialNumber))
        {
            pEntry = X509_REVOKED_new();
            OpcUa_GotoErrorIfAllocFailed(pEntry);

            X509_REVOKED_set_serialNumber(pEntry, pSerialNumber);
            X509_REVOKED_set_revocationDate(pEntry, pTime);

            X509_CRL_add0_revoked(pNewCrl, pEntry);
            pEntry = OpcUa_Null;
        }
    }

    ASN1_TIME_free(pTime);
    pTime = OpcUa_Null;

    /* sort by serial number */
    X509_CRL_sort(pNewCrl);

	/* sign the digest with the private key */
	pDigest = GetDigestAlgorithm(a_uHashSizeInBits);

	if (pDigest == NULL)
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Could not get digest algorithm.\n");
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

    if (!X509_CRL_sign(pNewCrl, a_pIssuerKey, pDigest))
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Could not create signature on new CRL.\n");
        OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
    }

    /* write to disk */
    uStatus = OpcUa_StringToUnicode(a_sCrlFilePath, &wszFilePath);
    OpcUa_GotoErrorIfBad(uStatus);

    if (_wfopen_s(&fp, (wchar_t*)wszFilePath, L"wb") != 0)
    {
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Could not write CIRL to disk.\n");
        OpcUa_GotoErrorWithStatus(OpcUa_BadUserAccessDenied);
    }

    pFile = BIO_new_fp(fp, 0);
    OpcUa_ReturnErrorIfArgumentNull(pFile);

    iResult = i2d_X509_CRL_bio(pFile, pNewCrl);

    if (iResult < 1)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
    }

    BIO_free(pFile);
    pFile = NULL;
    OpcUa_Free(wszFilePath);
    wszFilePath = 0;
    fclose(fp);
    fp = 0;

    X509_CRL_free(pNewCrl);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pFile != OpcUa_Null)
    {
        BIO_free(pFile);
    }

    if (pNewCrl != OpcUa_Null)
    {
        X509_CRL_free(pNewCrl);
    }

    if (pExistingCrl != OpcUa_Null)
    {
        X509_CRL_free(pExistingCrl);
    }

    if (pTime != OpcUa_Null)
    {
        ASN1_TIME_free(pTime);
    }

    if (wszFilePath != 0)
    {
        OpcUa_Free(wszFilePath);
        wszFilePath = 0;
    }

    if (fp != 0)
    {
        fclose(fp);
        fp = 0;
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_Revoke
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_Revoke(
    OpcUa_StringA     a_sStorePath,
    OpcUa_ByteString* a_pCertificate,
    OpcUa_ByteString* a_pIssuerPrivateKey,
    OpcUa_StringA     a_sIssuerPassword,
	OpcUa_UInt16      a_uHashSizeInBits,
    OpcUa_Boolean     a_bUnrevoke,
    OpcUa_StringA*    a_pCrlFilePath)
{
    BYTE* pPosition = OpcUa_Null;
    X509* pCertificate = OpcUa_Null;
    X509* pIssuer = OpcUa_Null;
    PKCS12* pPkcs12 = OpcUa_Null;
    EVP_PKEY* pIssuerKey = OpcUa_Null;
    int iResult = 0;
    OpcUa_StringA sCommonName = OpcUa_Null;
    OpcUa_StringA sThumbprint = OpcUa_Null;
    OpcUa_CharA sCrlFilePath[MAX_PATH];
    OpcUa_ByteString tIssuerCertificate;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_Revoke");

    OpcUa_ReturnErrorIfArgumentNull(a_sStorePath);
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
    OpcUa_ReturnErrorIfArgumentNull(a_pIssuerPrivateKey);
    OpcUa_ReturnErrorIfArgumentNull(a_pCrlFilePath);

    OpcUa_ByteString_Initialize(&tIssuerCertificate);

    /* convert public key to X509 structure. */
    pPosition = a_pCertificate->Data;
    pCertificate = d2i_X509((X509**)OpcUa_Null, (const unsigned char**)&pPosition, a_pCertificate->Length);

    if (pCertificate == OpcUa_Null)
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Invalid certificate to revoke.\n");
        OpcUa_GotoErrorWithStatus(OpcUa_Bad);
    }

    /* convert private key to PKCS12 structure. */
    pPosition = a_pIssuerPrivateKey->Data;
    pPkcs12 = d2i_PKCS12((PKCS12**)OpcUa_Null, (const unsigned char**)&pPosition, a_pIssuerPrivateKey->Length);
    OpcUa_GotoErrorIfAllocFailed(pPkcs12);

    /* parse the certificate. */
    iResult = PKCS12_parse(pPkcs12, a_sIssuerPassword, &pIssuerKey, &pIssuer, NULL);

    if (iResult == 0)
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Could not parse issuer's PKCS#12 file.\n");
        OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
    }

    PKCS12_free(pPkcs12);
    pPkcs12 = NULL;

    /* check consistency */
    if (X509_NAME_cmp(X509_get_subject_name(pIssuer), X509_get_issuer_name(pCertificate)) != 0)
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Certificate cannot be revoked because it was not issued by the provided issuer certificate.\n");
        OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
    }

    /* convert to DER form to use this utility function */
    tIssuerCertificate.Length = i2d_X509(pIssuer, OpcUa_Null);
    tIssuerCertificate.Data = (OpcUa_Byte*)OpcUa_Alloc(tIssuerCertificate.Length);
    OpcUa_GotoErrorIfAllocFailed(tIssuerCertificate.Data);

    pPosition = tIssuerCertificate.Data;
    i2d_X509(pIssuer, &pPosition);

    /* construct the CRL file name */
    uStatus = OpcUa_Certificate_GetInfo(
        &tIssuerCertificate,
        OpcUa_Null,
        OpcUa_Null,
        &sCommonName,
        &sThumbprint,
        OpcUa_Null,
        OpcUa_Null,
        OpcUa_Null);

    OpcUa_GotoErrorIfBad(uStatus);

    OpcUa_ByteString_Clear(&tIssuerCertificate);

    OpcUa_StrnCpyA(sCrlFilePath, MAX_PATH, a_sStorePath, MAX_PATH);
    OpcUa_StrnCatA(sCrlFilePath, MAX_PATH, "\\crl", MAX_PATH);

    uStatus = OpcUa_MakeDir(sCrlFilePath);
    OpcUa_GotoErrorIfBad(uStatus);

    OpcUa_StrnCatA(sCrlFilePath, MAX_PATH, "\\", MAX_PATH);
    OpcUa_StrnCatA(sCrlFilePath, MAX_PATH, sCommonName, MAX_PATH);
    OpcUa_StrnCatA(sCrlFilePath, MAX_PATH, " [", MAX_PATH);
    OpcUa_StrnCatA(sCrlFilePath, MAX_PATH, sThumbprint, MAX_PATH);
    OpcUa_StrnCatA(sCrlFilePath, MAX_PATH, "].crl", MAX_PATH);

    OpcUa_Free(sThumbprint);
    sThumbprint = 0; 

    OpcUa_Free(sCommonName);
    sCommonName = 0;

    /* create the CRL file */
    uStatus = OpcUa_Certificate_CreateCRL(
        a_sStorePath,
        pIssuer,
        pIssuerKey,
		a_uHashSizeInBits,
        pCertificate,
        a_bUnrevoke,
        sCrlFilePath);

    OpcUa_GotoErrorIfBad(uStatus);

    iResult = OpcUa_StrLenA(sCrlFilePath)+1;
    *a_pCrlFilePath = (OpcUa_StringA)OpcUa_Alloc(iResult);
    OpcUa_GotoErrorIfAllocFailed(*a_pCrlFilePath);
    OpcUa_StrnCpyA(*a_pCrlFilePath, iResult, sCrlFilePath, iResult-1);

    X509_free(pCertificate);
    X509_free(pIssuer);
    EVP_PKEY_free(pIssuerKey);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_ByteString_Clear(&tIssuerCertificate);

    if (pCertificate != OpcUa_Null)
    {
        X509_free(pCertificate);
    }

    if (pIssuer != OpcUa_Null)
    {
        X509_free(pIssuer);
    }

    if (pIssuerKey != OpcUa_Null)
    {
        EVP_PKEY_free(pIssuerKey);
    }

    if (pPkcs12 != OpcUa_Null)
    {
        PKCS12_free(pPkcs12);
    }

    if (sCommonName != OpcUa_Null)
    {
        OpcUa_Free(sCommonName);
    }

    if (sThumbprint != OpcUa_Null)
    {
        OpcUa_Free(sThumbprint);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Certificate_Convert
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_Convert(
    OpcUa_ByteString*  a_pCertificate,
    OpcUa_ByteString*  a_pPrivateKey,
    OpcUa_StringA      a_sInputPassword,
    OpcUa_P_FileFormat a_eInputFormat,
    OpcUa_StringA      a_sOutputPassword,
    OpcUa_P_FileFormat a_eOutputFormat,
	OpcUa_ByteString*  a_pNewCertificate,
	OpcUa_ByteString*  a_pNewPrivateKey)
{
    BYTE* pPosition = OpcUa_Null;
	X509* pX509Certificate = OpcUa_Null;
    PKCS12* pPkcs12 = OpcUa_Null;
    EVP_PKEY* pInputKey = OpcUa_Null;
    int iResult = 0;
    BIO* pBuffer = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_Convert");

    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
    OpcUa_ReturnErrorIfArgumentNull(a_pPrivateKey);
	OpcUa_ReturnErrorIfArgumentNull(a_pNewCertificate);
	OpcUa_ReturnErrorIfArgumentNull(a_pNewPrivateKey);

	OpcUa_ByteString_Initialize(a_pNewCertificate);
	OpcUa_ByteString_Initialize(a_pNewPrivateKey);

	if (a_sInputPassword != 0 && a_sInputPassword[0] == 0)
	{
		a_sInputPassword = 0;
	}

    if (a_eInputFormat == OpcUa_Crypto_Encoding_PKCS12)
    {
        /* convert private key to PKCS12 structure. */
        pPosition = a_pPrivateKey->Data;
        pPkcs12 = d2i_PKCS12((PKCS12**)OpcUa_Null, (const unsigned char**)&pPosition, a_pPrivateKey->Length);
        OpcUa_GotoErrorIfAllocFailed(pPkcs12);

        /* parse the certificate. */
		iResult = PKCS12_parse(pPkcs12, a_sInputPassword, &pInputKey, &pX509Certificate, NULL);

        if (iResult == 0)
        {
            OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Could not parse input PKCS#12 file.\n");
			OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
        }

        PKCS12_free(pPkcs12);
		pPkcs12 = NULL;

		/* convert the certificate back. */
		pPosition = a_pNewCertificate->Data;
		a_pNewCertificate->Length = i2d_X509(pX509Certificate, OpcUa_Null);
		a_pNewCertificate->Data = (OpcUa_Byte*)OpcUa_Alloc(a_pNewCertificate->Length);
		OpcUa_GotoErrorIfAllocFailed(a_pNewCertificate->Data);

		pPosition = a_pNewCertificate->Data;
		int result = i2d_X509(pX509Certificate, &pPosition);

		if (iResult <= 0)
		{
			OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
		}
    }

    else if (a_eInputFormat == OpcUa_Crypto_Encoding_PEM)
    {
        pBuffer = BIO_new_mem_buf(a_pPrivateKey->Data, a_pPrivateKey->Length);
        OpcUa_GotoErrorIfAllocFailed(pBuffer);

        /* read key */
        pInputKey = PEM_read_bio_PrivateKey(
            pBuffer,
            NULL,
            0,
            a_sInputPassword);

        if (pInputKey == 0)
        {
            OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Could not parse input PEM file.\n");
			OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
        }

        BIO_free(pBuffer);
		pBuffer = NULL;

		/* convert the certificate back. */
		a_pNewCertificate->Length = a_pCertificate->Length;
		a_pNewCertificate->Data = (OpcUa_Byte*)OpcUa_Alloc(a_pNewCertificate->Length);
		OpcUa_GotoErrorIfAllocFailed(a_pNewCertificate->Data);
		OpcUa_MemCpy(a_pNewCertificate->Data, a_pNewCertificate->Length, a_pCertificate->Data, a_pCertificate->Length);

		/* decode the existing certificate. */
		pPosition = a_pCertificate->Data;
		pX509Certificate = d2i_X509(NULL, (const unsigned char**)&pPosition, a_pCertificate->Length);

		if (pX509Certificate == NULL)
		{
			OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
		}
    }
    else
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Input format is not supported.\n");
        OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
	}

	if (a_sOutputPassword != 0 && a_sOutputPassword[0] == 0)
	{
		a_sOutputPassword = 0;
	}

	pBuffer = BIO_new(BIO_s_mem());
	OpcUa_GotoErrorIfNull(pBuffer, OpcUa_BadUserAccessDenied);

	switch (a_eOutputFormat)
	{
		case OpcUa_Crypto_Encoding_PEM:
		{
			// select encryption algorithm.
			const EVP_CIPHER* pCipher = NULL;
			char* pPassword = NULL;

			if (a_sOutputPassword != NULL && strlen(a_sOutputPassword) > 0)
			{
				pCipher = EVP_des_ede3_cbc();
				pPassword = a_sOutputPassword;
			}

			// write to file.
			int iResult = PEM_write_bio_PrivateKey(
				pBuffer,
				pInputKey,
				pCipher,
				NULL,
				0,
				0,
				pPassword);

			if (iResult == 0)
			{
				OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
			}

			break;
		}

		case OpcUa_Crypto_Encoding_PKCS12:
		{
			// create certificate.
			PKCS12* pPkcs12 = PKCS12_create(
				a_sOutputPassword,
				0,
				pInputKey,
				pX509Certificate,
				0,
				0,
				0,
				0,
				0,
				0);

			OpcUa_GotoErrorIfNull(pPkcs12, OpcUa_BadEncodingError);

			// write to file.
			int iResult = i2d_PKCS12_bio(pBuffer, pPkcs12);

			// free certificate.
			PKCS12_free(pPkcs12);

			if (iResult == 0)
			{
				OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
			}

			break;
		}

		case OpcUa_Crypto_Encoding_DER:
		default:
		{
			uStatus = OpcUa_BadNotSupported;
			OpcUa_GotoError;
		}
	}

	char* pData = 0;
	int size = BIO_get_mem_data(pBuffer, &pData);

	if (size == 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	a_pNewPrivateKey->Length = size;
	a_pNewPrivateKey->Data = (OpcUa_Byte*)OpcUa_Alloc(a_pNewPrivateKey->Length);
	OpcUa_GotoErrorIfAllocFailed(a_pNewPrivateKey->Data);
	memcpy(a_pNewPrivateKey->Data, pData, size);

	BIO_free(pBuffer);
	pBuffer = NULL;
	X509_free(pX509Certificate);
    EVP_PKEY_free(pInputKey);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_ByteString_Clear(a_pNewCertificate);
	OpcUa_ByteString_Clear(a_pNewPrivateKey);

	if (pX509Certificate != OpcUa_Null)
    {
		X509_free(pX509Certificate);
    }

    if (pInputKey != OpcUa_Null)
    {
        EVP_PKEY_free(pInputKey);
    }

    if (pPkcs12 != OpcUa_Null)
    {
        PKCS12_free(pPkcs12);
    }

    if (pBuffer != OpcUa_Null)
    {
        BIO_free(pBuffer);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
* OpcUa_Certificate_Replace
*===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_Replace(
	OpcUa_ByteString*  a_pCertificate,
	OpcUa_ByteString*  a_pPrivateKey,
	OpcUa_StringA      a_sInputPassword,
	OpcUa_StringA      a_sOutputPassword,
	OpcUa_ByteString*  a_pNewPrivateKey)
{
	BYTE* pPosition = OpcUa_Null;
	X509* pX509Certificate = OpcUa_Null;
	PKCS12* pPkcs12 = OpcUa_Null;
	EVP_PKEY* pInputKey = OpcUa_Null;
	int iResult = 0;
	BIO* pBuffer = OpcUa_Null;

	OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_Convert");

	OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
	OpcUa_ReturnErrorIfArgumentNull(a_pPrivateKey);
	OpcUa_ReturnErrorIfArgumentNull(a_pNewPrivateKey);

	OpcUa_ByteString_Initialize(a_pNewPrivateKey);

	if (a_sInputPassword != 0 && a_sInputPassword[0] == 0)
	{
		a_sInputPassword = 0;
	}

	/* convert private key to PKCS12 structure. */
	pPosition = a_pPrivateKey->Data;
	pPkcs12 = d2i_PKCS12((PKCS12**)OpcUa_Null, (const unsigned char**)&pPosition, a_pPrivateKey->Length);

	if (pPkcs12 == 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
	}

	/* parse the certificate. */
	iResult = PKCS12_parse(pPkcs12, a_sInputPassword, &pInputKey, &pX509Certificate, NULL);

	if (iResult == 0)
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Could not parse input PKCS#12 file.\n");
		OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
	}

	PKCS12_free(pPkcs12);
	pPkcs12 = NULL;

	if (pX509Certificate != OpcUa_Null)
	{
		X509_free(pX509Certificate);
		pX509Certificate = 0;
	}

	/* get the new certificate */
	pPosition = a_pCertificate->Data;
	pX509Certificate = d2i_X509(0, (const unsigned char**)&pPosition, a_pCertificate->Length);

	if (pX509Certificate == 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
	}

	if (a_sOutputPassword != 0 && a_sOutputPassword[0] == 0)
	{
		a_sOutputPassword = 0;
	}

	pBuffer = BIO_new(BIO_s_mem());
	OpcUa_GotoErrorIfNull(pBuffer, OpcUa_BadOutOfMemory);

	// create certificate.
	pPkcs12 = PKCS12_create(
		a_sOutputPassword,
		0,
		pInputKey,
		pX509Certificate,
		0,
		0,
		0,
		0,
		0,
		0);

	OpcUa_GotoErrorIfNull(pPkcs12, OpcUa_BadEncodingError);

	// write to file.
	iResult = i2d_PKCS12_bio(pBuffer, pPkcs12);

	// free certificate.
	PKCS12_free(pPkcs12);
	pPkcs12 = 0;

	if (iResult == 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	char* pData = 0;
	int size = BIO_get_mem_data(pBuffer, &pData);

	if (size == 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	a_pNewPrivateKey->Length = size;
	a_pNewPrivateKey->Data = (OpcUa_Byte*)OpcUa_Alloc(a_pNewPrivateKey->Length);
	OpcUa_GotoErrorIfAllocFailed(a_pNewPrivateKey->Data);
	memcpy(a_pNewPrivateKey->Data, pData, size);

	BIO_free(pBuffer);
	pBuffer = NULL;
	X509_free(pX509Certificate);
	EVP_PKEY_free(pInputKey);

	OpcUa_ReturnStatusCode;
	OpcUa_BeginErrorHandling;

	OpcUa_ByteString_Clear(a_pNewPrivateKey);

	if (pX509Certificate != OpcUa_Null)
	{
		X509_free(pX509Certificate);
	}

	if (pInputKey != OpcUa_Null)
	{
		EVP_PKEY_free(pInputKey);
	}

	if (pPkcs12 != OpcUa_Null)
	{
		PKCS12_free(pPkcs12);
	}

	if (pBuffer != OpcUa_Null)
	{
		BIO_free(pBuffer);
	}

	OpcUa_FinishErrorHandling;
}

/*============================================================================
* OpcUa_P_OpenSSL_X509_Name_AddEntry
*===========================================================================*/
OpcUa_Int OpcUa_P_OpenSSL_X509_Name_AddEntry(
	X509_NAME**               a_ppX509Name,
	OpcUa_Crypto_NameEntry*   a_pNameEntry)
{
	X509_NAME_ENTRY* pEntry = OpcUa_Null;
	OpcUa_Int nid = 0;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_CreateCSR");

	OpcUa_ReturnErrorIfArgumentNull(a_pNameEntry);

	if ((nid = OBJ_txt2nid(a_pNameEntry->key)) == NID_undef)
	{
		uStatus = OpcUa_BadNotSupported;
		OpcUa_GotoErrorIfBad(uStatus);
	}

	if (!(pEntry = X509_NAME_ENTRY_create_by_NID(OpcUa_Null, nid, MBSTRING_ASC, (unsigned char*)a_pNameEntry->value, -1)))
	{
		uStatus = OpcUa_Bad;
		OpcUa_GotoErrorIfBad(uStatus);
	}

	if (X509_NAME_add_entry(*a_ppX509Name, pEntry, -1, 0) != 1)
		uStatus = OpcUa_Bad;

	if (pEntry != OpcUa_Null)
	{
		X509_NAME_ENTRY_free(pEntry);
		pEntry = OpcUa_Null;
	}

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

OpcUa_Boolean AddDistiguishedNameEntry(
	X509_NAME* pName,
	const char* sKey,
	const char* sValue)
{
	OpcUa_Int nid = 0;
	X509_NAME_ENTRY* pEntry = OpcUa_Null;

	if ((nid = OBJ_txt2nid(sKey)) == NID_undef)
	{
		return OpcUa_False;
	}

	pEntry = X509_NAME_ENTRY_create_by_NID(OpcUa_Null, nid, MBSTRING_ASC, (unsigned char*)sValue, -1);

	if (pEntry == 0)
	{
		return OpcUa_False;
	}

	int result = X509_NAME_add_entry(pName, pEntry, -1, 0);

	if (pEntry != OpcUa_Null)
	{
		X509_NAME_ENTRY_free(pEntry);
		pEntry = OpcUa_Null;
	}

	if (!result)
	{
		return OpcUa_False;
	}

	return OpcUa_True;
}

static OpcUa_StatusCode CreateDistiguishedName(
	X509_NAME* pName,
	std::string subjectName,
	std::string applicationName,
	std::string organization,
	std::string domainName)
{
	OpcUa_StatusCode uStatus = 0;
	std::vector<std::string> fieldNames;
	std::vector<std::string> fieldValues;

	/* parse the subject name. */
	if (!subjectName.empty())
	{
		uStatus = OpcUa_Certificate_ParseSubjectName(subjectName.c_str(), &fieldNames, &fieldValues);
		OpcUa_ReturnErrorIfBad(uStatus);
	}

	/* create a default subject name. */
	if (fieldNames.size() == 0)
	{
		if (applicationName.empty())
		{
			return OpcUa_BadInvalidArgument;
		}

		fieldNames.push_back("CN");
		fieldValues.push_back(applicationName);

		if (!organization.empty())
		{
			fieldNames.push_back("O");
			fieldValues.push_back(organization);
		}

		if (!domainName.empty())
		{
			fieldNames.push_back("DC");
			fieldValues.push_back(domainName);
		}
	}

	if (fieldNames.size() == 0)
	{
		return OpcUa_BadInvalidArgument;
	}

	for (OpcUa_Int32 ii = fieldNames.size() - 1; ii >= 0; ii--)
	{
		if (!AddDistiguishedNameEntry(pName, fieldNames[ii].c_str(), fieldValues[ii].c_str()))
		{
			return OpcUa_BadInvalidArgument;
		}
	}

	return OpcUa_Good;
}

static EVP_PKEY* GetPrivateKey(OpcUa_Key* a_pPrivateKey)
{
	EVP_PKEY* pPrivateKey = 0;
	const OpcUa_Byte* pPosition = a_pPrivateKey->Key.Data;

	switch (a_pPrivateKey->Type)
	{
		case OpcUa_Crypto_Rsa_Alg_Id:
		case OpcUa_Crypto_Rsa_OAEP_Id:
			pPrivateKey = d2i_PrivateKey(EVP_PKEY_RSA, OpcUa_Null, &pPosition, a_pPrivateKey->Key.Length);
			break;

		case OpcUa_Crypto_Ecc_Alg_Id:
			pPrivateKey = d2i_PrivateKey(EVP_PKEY_EC, OpcUa_Null, &pPosition, a_pPrivateKey->Key.Length);
			break;

		default:
			break;
	}

	return pPrivateKey;
}

static OpcUa_StatusCode GetCertificate(X509* pX509, OpcUa_ByteString* a_pCertificate)
{
	OpcUa_ByteString_Initialize(a_pCertificate);
	OpcUa_Byte* pPosition = 0;

	a_pCertificate->Length = i2d_X509(pX509, NULL);

	if (a_pCertificate->Length <= 0)
	{
		return OpcUa_BadEncodingError;
	}

	a_pCertificate->Data = (OpcUa_Byte*)OpcUa_Alloc(a_pCertificate->Length);

	if (a_pCertificate->Length <= 0)
	{
		return OpcUa_BadOutOfMemory;
	}

	pPosition = a_pCertificate->Data;
	int iResult = i2d_X509(pX509, &pPosition);

	if (iResult <= 0)
	{
		return OpcUa_BadEncodingError;
	}

	return OpcUa_Good;
}

static OpcUa_StatusCode GetRequest(X509_REQ* pX509, OpcUa_ByteString* a_pRequest)
{
	OpcUa_ByteString_Initialize(a_pRequest);
	OpcUa_Byte* pPosition = 0;

	a_pRequest->Length = i2d_X509_REQ(pX509, NULL);

	if (a_pRequest->Length <= 0)
	{
		return OpcUa_BadEncodingError;
	}

	a_pRequest->Data = (OpcUa_Byte*)OpcUa_Alloc(a_pRequest->Length);

	if (a_pRequest->Length <= 0)
	{
		return OpcUa_BadOutOfMemory;
	}

	pPosition = a_pRequest->Data;
	int iResult = i2d_X509_REQ(pX509, &pPosition);

	if (iResult <= 0)
	{
		return OpcUa_BadEncodingError;
	}

	return OpcUa_Good;
}

static std::string ValidateApplicationUri(char* sApplicationUri)
{
	std::string applicationUri;

	if (sApplicationUri == 0 || strlen(sApplicationUri) == 0)
	{
		return applicationUri;
	}

	int length = strlen(sApplicationUri);

	for (int ii = 0; ii < length; ii++)
	{
		unsigned char ch = sApplicationUri[ii];

		bool escape = !isprint(ch) || ch == '%' || ch == ',';

		if (escape)
		{
			char szBuf[4];
			sprintf_s(szBuf, 4, "%%%2X", ch);
			applicationUri += szBuf;
		}
		else
		{
			if (_ismbcspace(ch))
			{
				applicationUri += ' ';
			}
			else
			{
				applicationUri += ch;
			}
		}
	}

	return applicationUri;
}

static std::string ValidateDomainName(char* sDomainName)
{
	std::string domainName;

	if (sDomainName == 0 && strlen(sDomainName) == 0)
	{
		return domainName;
	}

	int length = strlen(sDomainName);

	for (int ii = 0; ii < length; ii++)
	{
		unsigned char ch = sDomainName[ii];

		bool escape = !isalnum(ch) && ch != '.' && ch != '-';

		if (escape)
		{
			char szBuf[4];
			sprintf_s(szBuf, 4, "0x%2X", ch);
			domainName += szBuf;
		}
		else
		{
			domainName += ch;
		}
	}

	return domainName;
}

static std::vector<std::string> ValidateDomainNames(char** pDomainNames, unsigned int count)
{
	std::vector<std::string> domainNames;

	if (pDomainNames == 0 || count == 0)
	{
		return domainNames;
	}

	for (unsigned int ii = 0; ii < count; ii ++)
	{
		std::string domainName = ValidateDomainName(pDomainNames[ii]);

		if (!domainName.empty())
		{
			domainNames.push_back(domainName);
		}
	}

	return domainNames;
}

static OpcUa_Boolean AddExtension(
	X509V3_CTX* pContext,
	STACK_OF(X509_EXTENSION)* pExtensions,
	int iKey,
	const OpcUa_StringA sValue)
{
	X509_EXTENSION* pNewExtension = OpcUa_Null;

	pNewExtension = X509V3_EXT_conf_nid(NULL, pContext, iKey, sValue);

	if (pNewExtension == 0)
	{
		return OpcUa_False;
	}

	sk_X509_EXTENSION_push(pExtensions, pNewExtension);

	return OpcUa_True;
}

static STACK_OF(X509_EXTENSION)* CreateExtensions(
	X509V3_CTX* pContext,
	OpcUa_StringA sApplicationUri,
	OpcUa_StringA* pDomains,
	OpcUa_UInt32 uNoOfDomains,
	OpcUa_Boolean bIsCA,
	OpcUa_Boolean bIsRequest)
{
	std::string subjectAltName;
	std::string applicationUri;
	std::vector<std::string> domainNames;
	STACK_OF(X509_EXTENSION)* pExtensions = 0;

	pExtensions = sk_X509_EXTENSION_new_null();

	if (!AddExtension(pContext, pExtensions, NID_subject_key_identifier, "hash"))
	{
		return OpcUa_Null;
	}

	if (!bIsRequest)
	{
		if (!AddExtension(pContext, pExtensions, NID_authority_key_identifier, "keyid, issuer:always"))
		{
			return OpcUa_Null;
		}
	}

	if (bIsCA)
	{
		if (!AddExtension(pContext, pExtensions, NID_basic_constraints, "critical, CA:TRUE"))
		{
			return OpcUa_Null;
		}

		if (!AddExtension(pContext, pExtensions, NID_key_usage, "critical, digitalSignature, keyCertSign, cRLSign"))
		{
			return OpcUa_Null;
		}

		return pExtensions;
	}

	if (!AddExtension(pContext, pExtensions, NID_basic_constraints, "critical, CA:FALSE"))
	{
		return OpcUa_Null;
	}

	if (!AddExtension(pContext, pExtensions, NID_key_usage, "critical, nonRepudiation, digitalSignature, keyEncipherment, dataEncipherment, keyCertSign"))
	{
		return OpcUa_Null;
	}

	if (!AddExtension(pContext, pExtensions, NID_ext_key_usage, "critical, serverAuth, clientAuth"))
	{
		return OpcUa_Null;
	}

	applicationUri = ValidateApplicationUri(sApplicationUri);

	if (!applicationUri.empty())
	{
		subjectAltName += "URI:";
		subjectAltName += sApplicationUri;
	}

	domainNames = ValidateDomainNames(pDomains, uNoOfDomains);

	if (domainNames.size() > 0)
	{
		for (std::size_t ii = 0; ii < domainNames.size(); ii++)
		{
			int iResult = inet_addr(domainNames[ii].c_str());

			if (iResult != INADDR_NONE)
			{
				subjectAltName += ",IP:";
			}
			else
			{
				subjectAltName += ",DNS:";
			}

			subjectAltName += domainNames[ii];
		}
	}

	if (subjectAltName.size() > 0)
	{
		if (!AddExtension(pContext, pExtensions, NID_subject_alt_name, (OpcUa_StringA)subjectAltName.c_str()))
		{
			return OpcUa_Null;
		}
	}

	return pExtensions;
}

/*============================================================================
* OpcUa_Certificate_CreateCSR
*===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_CreateCSR(
	OpcUa_StringA      a_sApplicationName,
	OpcUa_StringA      a_sOrganization,
	OpcUa_StringA      a_sSubjectName,
	OpcUa_StringA      a_sApplicationUri,
	OpcUa_StringA*     a_pDomains,
	OpcUa_UInt32       a_uNoOfDomains,
	OpcUa_Boolean      a_bIsCA,
	OpcUa_UInt16       a_uHashSizeInBits,
	OpcUa_ByteString*  a_pCertificate,
	OpcUa_Key*         a_pPrivateKey,
	OpcUa_ByteString*  a_pRequest)
{
	X509_REQ* pRequest = OpcUa_Null;
	X509_NAME* pSubjectName = OpcUa_Null;
	X509* pX509Certificate = OpcUa_Null;
	EVP_PKEY* pPrivateKey = OpcUa_Null;
	const OpcUa_Byte* pPosition = OpcUa_Null;
	const EVP_MD* pDigest = OpcUa_Null;
	STACK_OF(X509_EXTENSION)* pExtensions = OpcUa_Null;
	OpcUa_DateTime now = OpcUa_P_DateTime_UtcNow();
	OpcUa_StringA sCurrentApplicationUri = 0;
	OpcUa_StringA* pCurrentDomains = 0;
	OpcUa_UInt32 uNoOfCurrentDomains = 0;

	OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_CreateCSR");

	OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
	OpcUa_ReturnErrorIfArgumentNull(a_pPrivateKey);
	OpcUa_ReturnErrorIfArgumentNull(a_pRequest);

	OpcUa_ByteString_Initialize(a_pRequest);

	/* get the subject alt name from the existing certificate */
	uStatus = OpcUa_Certificate_GetInfo(
		a_pCertificate,
		0,
		0,
		0,
		0,
		&sCurrentApplicationUri,
		&pCurrentDomains,
		&uNoOfCurrentDomains);

	OpcUa_GotoErrorIfBad(uStatus);

	/* set the application uri. */
	if (a_sApplicationUri == 0 || strlen(a_sApplicationUri) == 0)
	{
		a_sApplicationUri = sCurrentApplicationUri;
	}

	/* set the domain names. */
	if (a_pDomains == 0 || a_uNoOfDomains == 0)
	{
		a_pDomains = pCurrentDomains;
		a_uNoOfDomains = uNoOfCurrentDomains;
	}
	
	/* decode the existing certificate. */
	pPosition = a_pCertificate->Data;
	pX509Certificate = d2i_X509(NULL, &pPosition, a_pCertificate->Length);

	if (pX509Certificate == NULL)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
	}

	pPrivateKey = GetPrivateKey(a_pPrivateKey);

	if (pPrivateKey == 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
	}

	/* create request. */
	pRequest = X509_REQ_new();

	// set the version.
	int result = X509_REQ_set_version(pRequest, 1);

	if (result != 1)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	/* set the subject name. */
	if (a_sSubjectName != 0 && strlen(a_sSubjectName) > 0)
	{
		pSubjectName = X509_REQ_get_subject_name(pRequest);

		uStatus = CreateDistiguishedName(
			pSubjectName,
			a_sSubjectName,
			a_sApplicationName,
			a_sOrganization,
			(a_uNoOfDomains > 0) ? a_pDomains[0] : NULL);

		OpcUa_GotoErrorIfBad(uStatus);
	}
	else
	{
		pSubjectName = X509_get_subject_name(pX509Certificate);
		X509_REQ_set_subject_name(pRequest, pSubjectName);
	}

	/* set public key. */
	result = X509_REQ_set_pubkey(pRequest, X509_get_pubkey(pX509Certificate));

	if (result != 1)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	/* add extensions */
	X509V3_CTX context;
	X509V3_set_ctx(&context, pX509Certificate, pX509Certificate, pRequest, OpcUa_Null, 0);

	pExtensions = CreateExtensions(&context, a_sApplicationUri, a_pDomains, a_uNoOfDomains, a_bIsCA, OpcUa_True);

	if (pExtensions == 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	X509_REQ_add_extensions(pRequest, pExtensions);

	/* sign the request with the private key */
	pDigest = GetDigestAlgorithm(a_uHashSizeInBits);

	if (pDigest == NULL)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	result = X509_REQ_sign(pRequest, pPrivateKey, pDigest);

	if (result <= 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	result = X509_REQ_verify(pRequest, X509_REQ_get_pubkey(pRequest));

	if (result <= 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadCertificateInvalid);
	}

	// need to convert to DER.
	uStatus = GetRequest(pRequest, a_pRequest);
	OpcUa_GotoErrorIfBad(uStatus);

	/* clean up */
	if (sCurrentApplicationUri != 0)
	{
		OpcUa_Free(sCurrentApplicationUri);
		sCurrentApplicationUri = 0;
	}

	if (pCurrentDomains != 0)
	{
		for (OpcUa_UInt32 ii = 0; ii < uNoOfCurrentDomains; ii++)
		{
			OpcUa_Free(pCurrentDomains[ii]);
		}

		OpcUa_Free(pCurrentDomains);
		pCurrentDomains = 0;
	}

	if (pRequest != OpcUa_Null)
	{
		X509_REQ_free(pRequest);
		pRequest = OpcUa_Null;
	}

	if (pX509Certificate != OpcUa_Null)
	{
		X509_free(pX509Certificate);
		pX509Certificate = OpcUa_Null;
	}

	if (pPrivateKey != OpcUa_Null)
	{
		EVP_PKEY_free(pPrivateKey);
		pPrivateKey = OpcUa_Null;
	}

	if (pExtensions != OpcUa_Null)
	{
		sk_X509_EXTENSION_pop_free(pExtensions, X509_EXTENSION_free);
		pExtensions = OpcUa_Null;
	}

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	if (sCurrentApplicationUri != 0)
	{
		OpcUa_Free(sCurrentApplicationUri);
		sCurrentApplicationUri = 0;
	}

	if (pCurrentDomains != 0)
	{
		for (OpcUa_UInt32 ii = 0; ii < uNoOfCurrentDomains; ii++)
		{
			OpcUa_Free(pCurrentDomains[ii]);
		}

		OpcUa_Free(pCurrentDomains);
		pCurrentDomains = 0; 
	}

	if (pRequest != 0)
	{
		X509_REQ_free(pRequest);
		pRequest = 0;
	}

	if (pX509Certificate != OpcUa_Null)
	{
		X509_free(pX509Certificate);
		pX509Certificate = OpcUa_Null;
	}

	if (pPrivateKey != OpcUa_Null)
	{
		EVP_PKEY_free(pPrivateKey);
		pPrivateKey = OpcUa_Null;
	}

	if (pExtensions != OpcUa_Null)
	{
		sk_X509_EXTENSION_pop_free(pExtensions, X509_EXTENSION_free);
		pExtensions = OpcUa_Null;
	}

OpcUa_FinishErrorHandling;
}

/*============================================================================
* OpcUa_Certificate_CreateFromCSR
*===========================================================================*/
OpcUa_StatusCode OpcUa_Certificate_CreateFromCSR(
	OpcUa_ByteString*  a_pRequest,
	OpcUa_UInt16       a_uHashSizeInBits,
	OpcUa_DateTime*    a_pStartTime,
	OpcUa_UInt16       a_uLifetimeInMonths,
	OpcUa_ByteString*  a_pIssuerCertificate,
	OpcUa_Key*         a_pIssuerPrivateKey,
	OpcUa_ByteString*  a_pCertificate)
{
	X509_NAME* pSubj = OpcUa_Null;
	const EVP_MD* pDigest = OpcUa_Null;
	X509* pIssuerX509 = OpcUa_Null;
	EVP_PKEY* pIssuerPrivateKey = OpcUa_Null;
	X509_REQ* pRequest = OpcUa_Null;
	X509* pNewX509 = OpcUa_Null;
	const OpcUa_Byte* pPosition = OpcUa_Null;
	OpcUa_DateTime now;
	OpcUa_DateTime startTime;
	OpcUa_Int32 validFromInSec = 0;
	OpcUa_Int32 validToInSec = 0;
	int result = 0;

OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_CreateFromCSR");

	OpcUa_ReturnErrorIfArgumentNull(a_pRequest);
	OpcUa_ReturnErrorIfArgumentNull(a_pRequest->Length);
	OpcUa_ReturnErrorIfArgumentNull(a_pIssuerCertificate);
	OpcUa_ReturnErrorIfArgumentNull(a_pIssuerCertificate->Length);
	OpcUa_ReturnErrorIfArgumentNull(a_pIssuerPrivateKey);
	OpcUa_ReturnErrorIfArgumentNull(a_pIssuerPrivateKey->Key.Length);
	OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
	
	OpcUa_ByteString_Initialize(a_pCertificate);

	/* convert to internal format.  */
	pPosition = a_pRequest->Data;
	pRequest = d2i_X509_REQ(0, &pPosition, a_pRequest->Length);

	if (pRequest == 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadCertificateInvalid);
	}

	result = X509_REQ_verify(pRequest, X509_REQ_get_pubkey(pRequest));

	if (result <= 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadCertificateInvalid);
	}

	/* get issuer  */
	pPosition = a_pIssuerCertificate->Data;
	pIssuerX509 = d2i_X509(0, &pPosition, a_pIssuerCertificate->Length);

	if (pIssuerX509 == 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
	}

	/* get issuer private key. */
	pIssuerPrivateKey = GetPrivateKey(a_pIssuerPrivateKey);

	if (pIssuerPrivateKey == 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
	}

	pNewX509 = X509_new();
	
	if (pNewX509  == NULL)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadOutOfMemory);
	}

	/* set version of certificate (V3 since internal representation starts versioning from 0) */
	if (X509_set_version(pNewX509, 2L) != 1)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	if (X509_set_subject_name(pNewX509, X509_REQ_get_subject_name(pRequest)) == 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	if (X509_set_issuer_name(pNewX509, X509_get_subject_name(pIssuerX509)) == 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	if (X509_set_pubkey(pNewX509, X509_REQ_get_pubkey(pRequest)) == 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	/* generate a unique number for a serial number if none provided. */
	ASN1_INTEGER* pSerialNumber = X509_get_serialNumber(pNewX509);

	pSerialNumber->type = V_ASN1_INTEGER;
	pSerialNumber->data = (unsigned char*)OPENSSL_realloc(pSerialNumber->data, 16);
	pSerialNumber->length = 16;

	OpcUa_P_Guid_Create((OpcUa_Guid*)pSerialNumber->data);
	
	now = OpcUa_P_DateTime_UtcNow();
	startTime = now;

	/* set validFrom for the certificate */
	if (a_pStartTime != 0 && a_pStartTime->dwHighDateTime != 0 && a_pStartTime->dwLowDateTime != 0)
	{
		startTime = *a_pStartTime;
	}

	uStatus = OpcUa_P_GetDateTimeDiffInSeconds32(now, startTime, &validFromInSec);
	OpcUa_GotoErrorIfBad(uStatus);

	if (!X509_gmtime_adj(X509_get_notBefore(pNewX509), validFromInSec))
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	/* set validTo for the certificate */
	if (a_uLifetimeInMonths == 0)
	{
		a_uLifetimeInMonths = 1;
	}

	validFromInSec += a_uLifetimeInMonths * 30 * 24 * 3600;

	if (!X509_gmtime_adj(X509_get_notAfter(pNewX509), validFromInSec))
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	/* add extensions */
	STACK_OF(X509_EXTENSION)* pExtensions = X509_REQ_get_extensions(pRequest);

	X509V3_CTX context;
	X509V3_set_ctx(&context, pIssuerX509, pNewX509, pRequest, OpcUa_Null, 0);

	if (!AddExtension(&context, pExtensions, NID_authority_key_identifier, "keyid, issuer:always"))
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	for (int ii = 0; ii < sk_X509_EXTENSION_num(pExtensions); ii++)
	{
		X509_EXTENSION* pExtension = sk_X509_EXTENSION_value(pExtensions, ii);
		
		if (!X509_add_ext(pNewX509, pExtension, -1))
		{
			OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
		}
	}

	/* sign certificate with the CA private key */
	pDigest = GetDigestAlgorithm(a_uHashSizeInBits);

	if (pDigest == NULL)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	if (!X509_sign(pNewX509, pIssuerPrivateKey, pDigest))
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	if (X509_verify(pNewX509, pIssuerPrivateKey) <= 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	/* need to convert to DER. */
	uStatus = GetCertificate(pNewX509, a_pCertificate);
	OpcUa_GotoErrorIfBad(uStatus);

	/* clean up. */
	if (pRequest != OpcUa_Null)
	{
		X509_REQ_free(pRequest);
		pRequest = OpcUa_Null;
	}

	if (pIssuerX509 != OpcUa_Null)
	{
		X509_free(pIssuerX509);
		pIssuerX509 = OpcUa_Null;
	}
	
	if (pIssuerPrivateKey != OpcUa_Null)
	{
		EVP_PKEY_free(pIssuerPrivateKey);
		pIssuerPrivateKey = OpcUa_Null;
	}

	if (pNewX509 != OpcUa_Null)
	{
		X509_free(pNewX509);
		pNewX509 = OpcUa_Null;
	}
	
#ifdef XXX
	switch (a_pSubjectPublicKey.Type)
	{
	case OpcUa_Crypto_Rsa_Alg_Id:
	case OpcUa_Crypto_Rsa_OAEP_Id:
		pSubjectPublicKey = d2i_PublicKey(EVP_PKEY_RSA, OpcUa_Null, ((const unsigned char**)&(a_pSubjectPublicKey.Key.Data)), a_pSubjectPublicKey.Key.Length);
		break;
	case OpcUa_Crypto_Ecc_Alg_Id:
		pSubjectPublicKey = d2i_PublicKey(EVP_PKEY_EC, OpcUa_Null, ((const unsigned char**)&(a_pSubjectPublicKey.Key.Data)), a_pSubjectPublicKey.Key.Length);
		break;
	default:
		return OpcUa_BadInvalidArgument;
	}

	switch (a_pIssuerPrivateKey->Type)
	{
	case OpcUa_Crypto_Rsa_Alg_Id:
	case OpcUa_Crypto_Rsa_OAEP_Id:
		pIssuerPrivateKey = d2i_PrivateKey(EVP_PKEY_RSA, OpcUa_Null, ((const unsigned char**)&(a_pIssuerPrivateKey.Key.Data)), a_pIssuerPrivateKey.Key.Length);
		break;
	case OpcUa_Crypto_Ecc_Alg_Id:
		pIssuerPrivateKey = d2i_PrivateKey(EVP_PKEY_EC, OpcUa_Null, ((const unsigned char**)&(a_pIssuerPrivateKey.Key.Data)), a_pIssuerPrivateKey.Key.Length);
		break;
	default:
		return OpcUa_BadInvalidArgument;
	}

	/* create new certificate object */
	if (!(*((X509**)a_ppCertificate) = X509_new()))
	{
		uStatus = OpcUa_Bad;
		OpcUa_GotoErrorIfBad(uStatus);
	}

	/* set the certificate as the issuer if creating a self-signed certificate. */
	if (a_pIssuerCertificate == OpcUa_Null)
	{
		a_pIssuerCertificate = *a_ppCertificate;
	}

	/* set version of certificate (V3 since internal representation starts versioning from 0) */
	if (X509_set_version(*((X509**)a_ppCertificate), 2L) != 1)
	{
		uStatus = OpcUa_Bad;
		OpcUa_GotoErrorIfBad(uStatus);
	}

	/* generate a unique number for a serial number if none provided. */
	if (a_serialNumber == 0)
	{
		ASN1_INTEGER* pSerialNumber = X509_get_serialNumber(*((X509**)a_ppCertificate));

		pSerialNumber->type = V_ASN1_INTEGER;
		pSerialNumber->data = OPENSSL_realloc(pSerialNumber->data, 16);
		pSerialNumber->length = 16;

		OpcUa_P_Guid_Create((OpcUa_Guid*)pSerialNumber->data);
	}

	/* use the integer passed in - note the API should not be using a 32-bit integer - must fix sometime */
	else if (ASN1_INTEGER_set(X509_get_serialNumber(*((X509**)a_ppCertificate)), a_serialNumber) == 0)
	{
		uStatus = OpcUa_Bad;
		OpcUa_GotoErrorIfBad(uStatus);
	}

	/* add key to the request */
	if (X509_set_pubkey(*((X509**)a_ppCertificate), pSubjectPublicKey) != 1)
	{
		uStatus = OpcUa_Bad;
		OpcUa_GotoErrorIfBad(uStatus);
	}

	if (pSubjectPublicKey != OpcUa_Null)
	{
		EVP_PKEY_free(pSubjectPublicKey);
		pSubjectPublicKey = OpcUa_Null;
	}

	/* assign the subject name */
	if (!(pSubj = X509_NAME_new()))
	{
		uStatus = OpcUa_Bad;
		OpcUa_GotoErrorIfBad(uStatus);
	}

	/* create and add entries to subject name */
	for (i = 0; i<a_nameEntriesCount; i++)
	{
		if (OpcUa_P_OpenSSL_X509_Name_AddEntry(&pSubj, a_pNameEntries + i) <0)
		{
			uStatus = OpcUa_Bad;
			OpcUa_GotoErrorIfBad(uStatus);
		}
	}

	/* set subject name in request */
	if (X509_set_subject_name(*((X509**)a_ppCertificate), pSubj) != 1)
	{
		uStatus = OpcUa_Bad;
		OpcUa_GotoErrorIfBad(uStatus);
	}

	/* set name of issuer (CA) */
	if (X509_set_issuer_name(*((X509**)a_ppCertificate), X509_get_subject_name((X509*)a_pIssuerCertificate)) != 1)
	{
		uStatus = OpcUa_Bad;
		OpcUa_GotoErrorIfBad(uStatus);
	}

	now = OpcUa_P_DateTime_UtcNow();

	validFromInSec = 0;

	/* need to convert validFrom to an offset from now */
	if (*((OpcUa_Int64*)&now) < *((OpcUa_Int64*)&a_validFrom))
	{
		uStatus = OpcUa_P_GetDateTimeDiffInSeconds32(now, a_validFrom, &validFromInSec);
		OpcUa_GotoErrorIfBad(uStatus);
	}
	else
	{
		uStatus = OpcUa_P_GetDateTimeDiffInSeconds32(a_validFrom, now, &validFromInSec);
		OpcUa_GotoErrorIfBad(uStatus);
		validFromInSec = -validFromInSec;
	}

	/* set validFrom for the certificate */
	if (!(X509_gmtime_adj(X509_get_notBefore(*((X509**)a_ppCertificate)), validFromInSec)))
	{
		uStatus = OpcUa_Bad;
		OpcUa_GotoErrorIfBad(uStatus);
	}

	/* need to convert validTo to an offset from now */
	if (*((OpcUa_Int64*)&now) < *((OpcUa_Int64*)&a_validTo))
	{
		uStatus = OpcUa_P_GetDateTimeDiffInSeconds32(now, a_validTo, &validToInSec);
		OpcUa_GotoErrorIfBad(uStatus);
	}
	else
	{
		uStatus = OpcUa_P_GetDateTimeDiffInSeconds32(a_validTo, now, &validFromInSec);
		OpcUa_GotoErrorIfBad(uStatus);
		validFromInSec = -validFromInSec;
	}

	/* set validTo for the certificate */
	if (!(X509_gmtime_adj(X509_get_notAfter(*((X509**)a_ppCertificate)), validToInSec)))
	{
		uStatus = OpcUa_Bad;
		OpcUa_GotoErrorIfBad(uStatus);
	}

	/* add x509v3 extensions */
	X509V3_set_ctx(&ctx,
		(X509*)a_pIssuerCertificate,
		*((X509**)a_ppCertificate),
		OpcUa_Null,
		OpcUa_Null,
		0);

	for (i = 0; i<a_extensionsCount; i++)
	{
		if (OpcUa_P_OpenSSL_X509_AddCustomExtension((X509**)a_ppCertificate, a_pExtensions + i, &ctx) <0)
		{
			uStatus = OpcUa_Bad;
			OpcUa_GotoErrorIfBad(uStatus);
		}
	}

	/* sign certificate with the CA private key */
	switch (a_signatureHashAlgorithm)
	{
	case OPCUA_P_SHA_160:
		pDigest = EVP_sha1();
		break;
	case OPCUA_P_SHA_224:
		pDigest = EVP_sha224();
		break;
	case OPCUA_P_SHA_256:
		pDigest = EVP_sha256();
		break;
	case OPCUA_P_SHA_384:
		pDigest = EVP_sha384();
		break;
	case OPCUA_P_SHA_512:
		pDigest = EVP_sha512();
		break;
	default:
		uStatus = OpcUa_BadNotSupported;
		OpcUa_GotoErrorIfBad(uStatus);
	}

	if (!(X509_sign(*((X509**)a_ppCertificate), pIssuerPrivateKey, pDigest)))
	{
		uStatus = OpcUa_Bad;
		OpcUa_GotoErrorIfBad(uStatus);
	}

	if (X509_verify(*((X509**)a_ppCertificate), pIssuerPrivateKey) <= 0)
	{
		uStatus = OpcUa_Bad;
		OpcUa_GotoErrorIfBad(uStatus);
	}

	if (pIssuerPrivateKey != OpcUa_Null)
	{
		EVP_PKEY_free(pIssuerPrivateKey);
		pIssuerPrivateKey = OpcUa_Null;
	}

	if (pSubj != OpcUa_Null)
	{
		X509_NAME_free(pSubj);
		pSubj = OpcUa_Null;
	}

	OpcUa_ReturnStatusCode;

	OpcUa_BeginErrorHandling;

	OpcUa_P_Memory_Free(*a_ppCertificate);
	*a_ppCertificate = OpcUa_Null;

	if (pSubjectPublicKey != OpcUa_Null)
	{
		EVP_PKEY_free(pSubjectPublicKey);
		pSubjectPublicKey = OpcUa_Null;
	}

	if (pIssuerPrivateKey != OpcUa_Null)
	{
		EVP_PKEY_free(pIssuerPrivateKey);
		pIssuerPrivateKey = OpcUa_Null;
	}

	if (pSubj != OpcUa_Null)
	{
		X509_NAME_free(pSubj);
		pSubj = OpcUa_Null;
	}

	OpcUa_FinishErrorHandling;

	OpcUa_CryptoProvider tCryptoProvider;
	OpcUa_PKIProvider tPkiProvider;
	OpcUa_Key tPublicKey;
	OpcUa_Crypto_NameEntry* pSubjectNameFields = OpcUa_Null;
	OpcUa_UInt32* uNoIfSubjectNameFields = 0;
	OpcUa_Certificate* pX509Certificate = OpcUa_Null;
	X509_NAME* pSubjectName = OpcUa_Null;
	const EVP_MD* pDigest = OpcUa_Null;
	EVP_PKEY* pSubjectPublicKey = OpcUa_Null;
	EVP_PKEY* pIssuerPrivateKey = OpcUa_Null;
	X509_REQ* pRequest = OpcUa_Null;
	RSA* pRSA = OpcUa_Null;

	OpcUa_StringA* pNameFields = 0;
	OpcUa_UInt32 uNoOfNameFields = 0;
	OpcUa_StringA sApplicationUri = 0;
	OpcUa_StringA* pDomains = 0;
	OpcUa_UInt32 uNoOfDomains = 0;

	std::vector<std::string> fieldNames;
	std::vector<std::string> fieldValues;
	std::string subjectName;
	std::string storeName;

	OpcUa_InitializeStatus(OpcUa_Module_Crypto, "OpcUa_Certificate_CreateFromCSR");

	OpcUa_ReturnErrorIfArgumentNull(a_pRequest);
	OpcUa_ReturnErrorIfArgumentNull(a_pIssuerCertificate);
	OpcUa_ReturnErrorIfArgumentNull(a_pIssuerPrivateKey);
	OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);

	OpcUa_MemSet(&tCryptoProvider, 0, sizeof(OpcUa_CryptoProvider));
	OpcUa_MemSet(&tPkiProvider, 0, sizeof(OpcUa_PKIProvider));
	OpcUa_Key_Initialize(&tPublicKey);
	OpcUa_ByteString_Initialize(a_pRequest);

	// get info from certificate.
	uStatus = OpcUa_Certificate_GetInfo(
		a_pCertificate,
		&pNameFields,
		&uNoOfNameFields,
		0,
		0,
		&sApplicationUri,
		&pDomains,
		&uNoOfDomains);

	// parse the subject name.
	if (a_sSubjectName != OpcUa_Null && strlen(a_sSubjectName) > 0)
	{
		uStatus = OpcUa_Certificate_ParseSubjectName(a_sSubjectName, &fieldNames, &fieldValues);
		OpcUa_GotoErrorIfBad(uStatus);
	}
	else
	{
		std::string subjectName;

		for (OpcUa_UInt32 ii = 0; ii < uNoOfNameFields; ii++)
		{
			if (ii > 0)
			{
				subjectName += "/";
			}

			subjectName += pNameFields[ii];
		}

		uStatus = OpcUa_Certificate_ParseSubjectName((OpcUa_StringA)subjectName.c_str(), &fieldNames, &fieldValues);
		OpcUa_GotoErrorIfBad(uStatus);
	}

	// create the provider.
	uStatus = OpcUa_Certificate_CreateCryptoProviders(&tPkiProvider, &tCryptoProvider);
	OpcUa_GotoErrorIfBad(uStatus);

	// determine size of public key.
	uStatus = OpcUa_Crypto_GetPublicKeyFromCert(
		&tCryptoProvider,
		a_pCertificate,
		OpcUa_Null,
		&tPublicKey);

	OpcUa_GotoErrorIfBad(uStatus);

	// allocate public key buffer.
	tPublicKey.Key.Data = (OpcUa_Byte*)OpcUa_Alloc(tPublicKey.Key.Length);
	OpcUa_GotoErrorIfAllocFailed(tPublicKey.Key.Data);

	// extract public key.
	uStatus = OpcUa_Crypto_GetPublicKeyFromCert(
		&tCryptoProvider,
		a_pCertificate,
		OpcUa_Null,
		&tPublicKey);

	OpcUa_GotoErrorIfBad(uStatus);

	// hack to get around the fact that the load key and the create key functions use different ids.
	if (tPublicKey.Key.Length > 0 && tPublicKey.Type == OpcUa_Crypto_Rsa_OAEP_Id)
	{
		tPublicKey.Type = OpcUa_Crypto_Rsa_Alg_Id;
	}

	// create the subject name fields.
	pSubjectNameFields = (OpcUa_Crypto_NameEntry*)OpcUa_Alloc(fieldNames.size()*sizeof(OpcUa_Crypto_NameEntry));
	OpcUa_GotoErrorIfAllocFailed(pSubjectNameFields);
	memset(pSubjectNameFields, 0, fieldNames.size()*sizeof(OpcUa_Crypto_NameEntry));

	// reverse order.
	for (int ii = (int)fieldNames.size() - 1; ii >= 0; ii--)
	{
		int index = (int)fieldNames.size() - 1 - ii;
		pSubjectNameFields[index].key = (char*)fieldNames[ii].c_str();
		pSubjectNameFields[index].value = (char*)fieldValues[ii].c_str();
	}

	OpcUa_Byte* pPosition = NULL;
	OpcUa_Key* pPrivateKey = a_pPrivateKey;

	// decode the issuer certificate.
	pPosition = a_pCertificate->Data;
	pX509Certificate = (OpcUa_Certificate*)d2i_X509(NULL, (const unsigned char**)&pPosition, a_pCertificate->Length);

	if (pX509Certificate == NULL)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
	}

	if (a_pPrivateKey != NULL && a_pPrivateKey->Key.Length > 0)
	{
		// hack to get around the fact that the load private key and the create key functions use
		// different constants to identify the RSA public keys.
		a_pPrivateKey->Type = OpcUa_Crypto_Rsa_Alg_Id;

		// use the issuer key for signing.
		pPrivateKey = a_pPrivateKey;
	}

	// check for a valid private key.
	if (pPrivateKey == NULL)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	switch (tPublicKey.Type)
	{
	case OpcUa_Crypto_Rsa_Alg_Id:
	case OpcUa_Crypto_Rsa_OAEP_Id:
		pSubjectPublicKey = d2i_PublicKey(EVP_PKEY_RSA, OpcUa_Null, ((const unsigned char**)&(tPublicKey.Key.Data)), tPublicKey.Key.Length);
		break;
	case OpcUa_Crypto_Ecc_Alg_Id:
		pSubjectPublicKey = d2i_PublicKey(EVP_PKEY_EC, OpcUa_Null, ((const unsigned char**)&(tPublicKey.Key.Data)), tPublicKey.Key.Length);
		break;
	default:
		return OpcUa_BadInvalidArgument;
	}

	switch (a_pPrivateKey->Type)
	{
	case OpcUa_Crypto_Rsa_Alg_Id:
	case OpcUa_Crypto_Rsa_OAEP_Id:
		pIssuerPrivateKey = d2i_PrivateKey(EVP_PKEY_RSA, OpcUa_Null, ((const unsigned char**)&(a_pPrivateKey->Key.Data)), a_pPrivateKey->Key.Length);
		break;
	case OpcUa_Crypto_Ecc_Alg_Id:
		pIssuerPrivateKey = d2i_PrivateKey(EVP_PKEY_EC, OpcUa_Null, ((const unsigned char**)&(a_pPrivateKey->Key.Data)), a_pPrivateKey->Key.Length);
		break;
	default:
		return OpcUa_BadInvalidArgument;
	}

	// create request.
	pRequest = X509_REQ_new();

	// set the version.
	int result = X509_REQ_set_version(pRequest, 1);

	if (result != 1)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	// set the subject name.
	pSubjectName = X509_REQ_get_subject_name(pRequest);

	for (std::size_t ii = 0; ii < fieldNames.size(); ii++)
	{
		if (OpcUa_P_OpenSSL_X509_Name_AddEntry(&pSubjectName, pSubjectNameFields + ii) < 0)
		{
			OpcUa_GotoErrorWithStatus(OpcUa_Bad);
		}
	}

	// set public key.
	// pKey = EVP_PKEY_new();
	// EVP_PKEY_assign_RSA(pKey, r);
	//r = NULL;   // will be free rsa when EVP_PKEY_free(pKey)

	// EVP_PKEY_assign_RSA(pSubjectPublicKey, pRSA);
	//pRSA = NULL; // will be free rsa when EVP_PKEY_free(pKey)

	result = X509_REQ_set_pubkey(pRequest, pSubjectPublicKey);

	if (result != 1)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_Bad);
	}

	/*
	exts = sk_X509_EXTENSION_new_null();
	add_ext(exts, NID_subject_alt_name, "email:steve@openssl.org");
	X509_REQ_add_extensions(x, exts);
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
	The add_ext is implemented like this:

	int add_ext(STACK_OF(X509_EXTENSION) *sk, int nid, char *value) {
	X509_EXTENSION *ex;
	ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
	if (!ex)
	return 0;
	sk_X509_EXTENSION_push(sk, ex);
	return 1;
	}*/

	// select the signature algorithm.
	switch (a_uSignatureHashInBits)
	{
	default:
	case OPCUA_P_SHA_160:
		pDigest = EVP_sha1();
		break;
	case OPCUA_P_SHA_224:
		pDigest = EVP_sha224();
		break;
	case OPCUA_P_SHA_256:
		pDigest = EVP_sha256();
		break;
	case OPCUA_P_SHA_384:
		pDigest = EVP_sha384();
		break;
	case OPCUA_P_SHA_512:
		pDigest = EVP_sha512();
		break;
	}

	result = X509_REQ_sign(pRequest, pIssuerPrivateKey, pDigest);  // return x509_req->signature->length

	if (result <= 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_Bad);
	}

	// clear existing certificate.
	OpcUa_ByteString_Clear(a_pRequest);

	// need to convert to DER encoded certificate.
	a_pRequest->Length = i2d_X509_REQ(pRequest, NULL);

	if (a_pRequest->Length <= 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}

	a_pRequest->Data = (OpcUa_Byte*)OpcUa_Alloc(a_pRequest->Length);
	OpcUa_GotoErrorIfAllocFailed(a_pRequest->Data);

	// OpenSSL likes to modify input parameters.
	pPosition = a_pRequest->Data;
	int iResult = i2d_X509_REQ(pRequest, &pPosition);

	if (iResult <= 0)
	{
		OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
	}
#endif

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	if (pRequest != OpcUa_Null)
	{
		X509_REQ_free(pRequest);
		pRequest = OpcUa_Null;
	}

	if (pIssuerX509 != OpcUa_Null)
	{
		X509_free(pIssuerX509);
		pIssuerX509 = OpcUa_Null;
	}
	
	if (pIssuerPrivateKey != OpcUa_Null)
	{
		EVP_PKEY_free(pIssuerPrivateKey);
		pIssuerPrivateKey = OpcUa_Null;
	}

	if (pNewX509 != OpcUa_Null)
	{
		X509_free(pNewX509);
		pNewX509 = OpcUa_Null;
	}

OpcUa_FinishErrorHandling;
}

/*
bool OpcUa_Certificate_CreateCSR()
{
	int             ret = 0;
	RSA             *r = NULL;
	BIGNUM          *bne = NULL;

	int             nVersion = 1;
	int             bits = 2048;
	unsigned long   e = RSA_F4;

	X509_REQ        *x509_req = NULL;
	X509_NAME       *x509_name = NULL;
	EVP_PKEY        *pKey = NULL;
	RSA             *tem = NULL;
	BIO             *out = NULL, *bio_err = NULL;

	const char      *szCountry = "CA";
	const char      *szProvince = "BC";
	const char      *szCity = "Vancouver";
	const char      *szOrganization = "Dynamsoft";
	const char      *szCommon = "localhost";

	const char      *szPath = "x509Req.pem";

	// 1. generate rsa key
	bne = BN_new();
	ret = BN_set_word(bne, e);

	if (ret != 1)
	{
		goto free_all;
	}

	r = RSA_new();
	ret = RSA_generate_key_ex(r, bits, bne, NULL);
	if (ret != 1){
		goto free_all;
	}

	// 2. set version of x509 req
	x509_req = X509_REQ_new();
	ret = X509_REQ_set_version(x509_req, nVersion);
	if (ret != 1){
		goto free_all;
	}

	// 3. set subject of x509 req
	x509_name = X509_REQ_get_subject_name(x509_req);

	ret = X509_NAME_add_entry_by_txt(x509_name, "C", MBSTRING_ASC, (const unsigned char*)szCountry, -1, -1, 0);
	if (ret != 1){
		goto free_all;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name, "ST", MBSTRING_ASC, (const unsigned char*)szProvince, -1, -1, 0);
	if (ret != 1){
		goto free_all;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name, "L", MBSTRING_ASC, (const unsigned char*)szCity, -1, -1, 0);
	if (ret != 1){
		goto free_all;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name, "O", MBSTRING_ASC, (const unsigned char*)szOrganization, -1, -1, 0);
	if (ret != 1){
		goto free_all;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name, "CN", MBSTRING_ASC, (const unsigned char*)szCommon, -1, -1, 0);
	if (ret != 1){
		goto free_all;
	}

	// 4. set public key of x509 req
	pKey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pKey, r);
	r = NULL;   // will be free rsa when EVP_PKEY_free(pKey)

	ret = X509_REQ_set_pubkey(x509_req, pKey);
	if (ret != 1){
		goto free_all;
	}

	// 5. set sign key of x509 req
	ret = X509_REQ_sign(x509_req, pKey, EVP_sha1());    // return x509_req->signature->length
	if (ret <= 0){
		goto free_all;
	}

	out = BIO_new_file(szPath, "w");
	ret = PEM_write_bio_X509_REQ(out, x509_req);

	// 6. free
free_all:
	X509_REQ_free(x509_req);
	BIO_free_all(out);

	EVP_PKEY_free(pKey);
	BN_free(bne);

	return (ret == 1);
}
*/