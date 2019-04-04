/* ========================================================================
 * Copyright (c) 2005-2011 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Foundation MIT License 1.00
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/MIT/1.00/
 * ======================================================================*/

/* UA platform definitions */
#include <opcua_p_internal.h>
#include <opcua_p_memory.h>

#if OPCUA_REQUIRE_OPENSSL

#ifndef _CRT_SECURE_NO_DEPRECATE
    #define _CRT_SECURE_NO_DEPRECATE
#endif /* _CRT_SECURE_NO_DEPRECATE */

#pragma warning( disable : 4985 )

/* System Headers */
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/bio.h>
#include <openssl/err.h>

/* Stack Headers */
#include <opcua_p_string.h>

/* own headers */
#include <opcua_p_openssl_pki.h>

/* WORKAROUND */
#include <windows.h>
#include <string.h>
#include <stdio.h>

/* Prototypes */
OpcUa_Void OpcUa_P_ByteString_Initialize(OpcUa_ByteString* a_pValue);
OpcUa_Void OpcUa_P_ByteString_Clear(OpcUa_ByteString* a_pValue);

#ifdef _MSC_VER
#pragma warning(disable:4748) /* suppress /GS can not protect parameters and local variables from local buffer overrun because optimizations are disabled in function */
#endif /* _MSC_VER */

/*============================================================================
 * path utility
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_BuildFullPath( /*  in */ char*         a_pPath,
                                                /*  in */ char*         a_pFileName,
                                                /*  in */ unsigned int  a_uiFullPathBufferLength,
                                                /* out */ char*         a_pFullPath)
{
    unsigned int uiPathLength = 0;
    unsigned int uiFileLength = 0;

    OpcUa_ReturnErrorIfArgumentNull(a_pPath);
    OpcUa_ReturnErrorIfArgumentNull(a_pFileName);
    OpcUa_ReturnErrorIfArgumentNull(a_pFullPath);

    uiPathLength = (unsigned int)strlen((const char*)a_pPath);
    uiFileLength = (unsigned int)strlen(a_pFileName);

    if((uiPathLength + uiFileLength + 3) > a_uiFullPathBufferLength)
    {
        return OpcUa_BadInvalidArgument;
    }

#if OPCUA_USE_SAFE_FUNCTIONS
    strncpy_s(a_pFullPath, a_uiFullPathBufferLength-1, (const char*)a_pPath, uiPathLength + 1);
    strncat_s(a_pFullPath, a_uiFullPathBufferLength-1, "\\", 2);
    strncat_s(a_pFullPath, a_uiFullPathBufferLength-1, a_pFileName, uiFileLength);
#else /* OPCUA_USE_SAFE_FUNCTIONS */
    strncpy(a_pFullPath, (const char*)a_pPath, uiPathLength + 1);
    strncat(a_pFullPath, "\\", 2);
    strncat(a_pFullPath, a_pFileName, uiFileLength);
#endif /* OPCUA_USE_SAFE_FUNCTIONS */


    return OpcUa_Good;
}

/*============================================================================
 * verify_callback
 *===========================================================================*/
OpcUa_Int OpcUa_P_OpenSSL_CertificateStore_Verify_Callback(int a_ok, X509_STORE_CTX* a_pStore)
{
    OpcUa_ReferenceParameter(a_pStore);

    if(a_ok == 0)
    {
        /* certificate not ok */
        char    buf[256];
        X509*   err_cert    = NULL;
        int     err         = 0;
        int     depth       = 0;

        err_cert = X509_STORE_CTX_get_current_cert(a_pStore);
        err      = X509_STORE_CTX_get_error(a_pStore);
        depth    = X509_STORE_CTX_get_error_depth(a_pStore);

        /* This spurious error is generated while looking for CAs in a store. It must be ignored. */
        if (err == X509_V_ERR_SUBJECT_ISSUER_MISMATCH)
        {
            return a_ok;
        }

        X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "\nverify error:\n\tnum=%d:%s\n\tdepth=%d\n\t%s\n", err, X509_verify_cert_error_string(err), depth, buf);

        if (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)
        {
            X509_NAME_oneline(X509_get_issuer_name(X509_STORE_CTX_get_current_cert(a_pStore)), buf, 256);
            OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "\tissuer=%s\n", buf);
        }
    }

    return a_ok;
}

/* stores the locations of the trusted certificate and the untrusted CA certificates. */
typedef struct OpcUa_P_OpenSSL_CertificateThumbprint
{
    OpcUa_Byte Data[SHA_DIGEST_LENGTH];
}
OpcUa_P_OpenSSL_CertificateThumbprint;

/* stores the merged trust list and a list of explicitly trusted certificates. */
typedef struct OpcUa_P_OpenSSL_CertificateStore
{
    X509_STORE* MergedTrustList;
    OpcUa_P_OpenSSL_CertificateThumbprint* ExplicitTrustList;
    OpcUa_UInt32 ExplicitTrustListCount;
    OpcUa_UInt32 ExplicitTrustListCapacity;
}
OpcUa_P_OpenSSL_CertificateStore;

/* allocates a certificate store handle. */
static OpcUa_P_OpenSSL_CertificateStore* OpcUa_P_OpenSSL_CertificateStore_Alloc()
{
    OpcUa_P_OpenSSL_CertificateStore* pCertificateStore = OpcUa_Null;
    pCertificateStore = (OpcUa_P_OpenSSL_CertificateStore*)OpcUa_P_Memory_Alloc(sizeof(OpcUa_P_OpenSSL_CertificateStore));

    if (pCertificateStore != OpcUa_Null)
    {
        OpcUa_MemSet(pCertificateStore, 0, sizeof(OpcUa_P_OpenSSL_CertificateStore));
    }

    return pCertificateStore;
}

/* frees a certificate store handle. */
static void OpcUa_P_OpenSSL_CertificateStore_Free(OpcUa_P_OpenSSL_CertificateStore** a_ppCertificateStore)
{
    OpcUa_P_OpenSSL_CertificateStore* pCertificateStore = OpcUa_Null;

    if (a_ppCertificateStore != OpcUa_Null)
    {
        pCertificateStore = *a_ppCertificateStore;

        if (pCertificateStore->MergedTrustList != OpcUa_Null)
        {
            X509_STORE_free((X509_STORE*)pCertificateStore->MergedTrustList);
        }

        if(pCertificateStore->MergedTrustList != OpcUa_Null)
        {
            OpcUa_P_Memory_Free(pCertificateStore->ExplicitTrustList);
        }

        OpcUa_P_Memory_Free(pCertificateStore);
        *a_ppCertificateStore = OpcUa_Null;
    }
}

/* add a certificate to a store. */
static OpcUa_StatusCode OpcUa_P_OpenSSL_CertificateStore_AddCertificate(
    OpcUa_P_OpenSSL_CertificateStore* a_pStore,
    OpcUa_ByteString* a_pCertificate,
    OpcUa_Boolean a_bExplicitlyTrusted)
{
    OpcUa_Byte* pPosition = OpcUa_Null;
    X509* pX509Certificate = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "CertificateStore_AddCertificate");

    OpcUa_ReturnErrorIfArgumentNull(a_pStore)
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate)

    /* convert public key to X509 structure. */
    pPosition = a_pCertificate->Data;
    pX509Certificate = d2i_X509((X509**)OpcUa_Null, (const unsigned char**)&pPosition, a_pCertificate->Length);
    OpcUa_GotoErrorIfNull(pX509Certificate, OpcUa_Bad);

    /* add to store */
    X509_STORE_add_cert(a_pStore->MergedTrustList, pX509Certificate);

    /* release certificate */
    X509_free(pX509Certificate);

    /* add to trustlist */
    if (a_bExplicitlyTrusted)
    {
        if (a_pStore->ExplicitTrustListCount == a_pStore->ExplicitTrustListCapacity)
        {
            OpcUa_P_OpenSSL_CertificateThumbprint* pTrustList = OpcUa_Null;
            a_pStore->ExplicitTrustListCapacity += 10;
            pTrustList = OpcUa_P_Memory_ReAlloc(a_pStore->ExplicitTrustList, sizeof(OpcUa_P_OpenSSL_CertificateThumbprint)*a_pStore->ExplicitTrustListCapacity);
            OpcUa_GotoErrorIfAllocFailed(pTrustList);
            a_pStore->ExplicitTrustList = pTrustList;
        }

        SHA1(a_pCertificate->Data, a_pCertificate->Length, a_pStore->ExplicitTrustList[a_pStore->ExplicitTrustListCount++].Data);
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

/* checks if the certificate is explicitly trusted. */
static OpcUa_StatusCode OpcUa_P_OpenSSL_CertificateStore_IsExplicitlyTrusted(
    OpcUa_P_OpenSSL_CertificateStore* a_pStore,
    X509_STORE_CTX* a_pX509Context,
    X509* a_pX509Certificate,
    OpcUa_Boolean* a_pExplicitlyTrusted)
{
    X509* x = a_pX509Certificate;
    X509* xtmp = OpcUa_Null;
    int iResult = 0;
    OpcUa_UInt32 jj = 0;
    OpcUa_ByteString tBuffer;
    OpcUa_Byte* pPosition = OpcUa_Null;
    OpcUa_P_OpenSSL_CertificateThumbprint tThumbprint;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "CertificateStore_IsExplicitlyTrusted");

    OpcUa_ReturnErrorIfArgumentNull(a_pStore);
    OpcUa_ReturnErrorIfArgumentNull(a_pX509Context);
    OpcUa_ReturnErrorIfArgumentNull(a_pX509Certificate);
    OpcUa_ReturnErrorIfArgumentNull(a_pExplicitlyTrusted);

    OpcUa_P_ByteString_Initialize(&tBuffer);

    *a_pExplicitlyTrusted = OpcUa_False;

    /* follow the trust chain. */
    while (!*a_pExplicitlyTrusted)
    {
        /* need to convert to DER encoded certificate. */
        int iLength = i2d_X509(x, NULL);

        if (iLength > tBuffer.Length)
        {
            tBuffer.Length = iLength;
            tBuffer.Data = OpcUa_P_Memory_ReAlloc(tBuffer.Data, iLength);
            OpcUa_GotoErrorIfAllocFailed(tBuffer.Data);
        }

        pPosition = tBuffer.Data;
        iResult = i2d_X509((X509*)x, &pPosition);

        if (iResult <= 0)
        {
            OpcUa_GotoErrorWithStatus(OpcUa_BadEncodingError);
        }

        /* compute the hash */
        SHA1(tBuffer.Data, iLength, tThumbprint.Data);

        /* check for thumbprint in explicit trust list. */
        for (jj = 0; jj < a_pStore->ExplicitTrustListCount; jj++)
        {
            if (OpcUa_MemCmp(a_pStore->ExplicitTrustList[jj].Data, tThumbprint.Data, SHA_DIGEST_LENGTH) == 0)
            {
                *a_pExplicitlyTrusted = OpcUa_True;
                break;
            }
        }

        if (*a_pExplicitlyTrusted)
        {
            break;
        }

        /* end of chain if self signed. */
        if (X509_STORE_CTX_get_check_issued(a_pX509Context)(a_pX509Context, x, x))
        {
            break;
        }

        /* look in the store for the issuer. */
        iResult = X509_STORE_CTX_get_get_issuer(a_pX509Context)(&xtmp, a_pX509Context, x);

        if (iResult == 0)
        {
            break;
        }

        /* oops - unexpected error */
        if (iResult < 0)
        {
            OpcUa_GotoErrorWithStatus(OpcUa_Bad);
        }

        /* goto next link in chain. */
        x = xtmp;
        X509_free(xtmp);
    }

    OpcUa_P_ByteString_Clear(&tBuffer);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_P_ByteString_Clear(&tBuffer);

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_ReadFile
 *===========================================================================*/
static OpcUa_StatusCode OpcUa_P_OpenSSL_ReadFile(
    OpcUa_StringA     a_sFilePath,
    OpcUa_ByteString* a_pBuffer)
{
    FILE* pFile = OpcUa_Null;
    BYTE* pBuffer = OpcUa_Null;
    int iResult = 0;
    fpos_t iLength = 0;
    BYTE* pPosition = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "ReadFile");

    OpcUa_ReturnErrorIfArgumentNull(a_sFilePath);
    OpcUa_ReturnErrorIfArgumentNull(a_pBuffer);

    OpcUa_P_ByteString_Initialize(a_pBuffer);

    /* read the file. */
    iResult = fopen_s(&pFile, (const char*)a_sFilePath, "rb");

    if (iResult != 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
    }

    /* get the length. */
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

    /* allocate buffer. */
    pBuffer = (BYTE*)OpcUa_P_Memory_Alloc((OpcUa_UInt32)iLength);
    memset(pBuffer, 0, (size_t)iLength);

    /* read blocks. */
    pPosition = pBuffer;

    while (pFile != NULL)
    {
        iResult = (int)fread(pPosition, 1, (size_t)(iLength-(pPosition-pBuffer)), pFile);

        if (iResult <= 0)
        {
            break;
        }

        pPosition += iResult;
    }

    fclose(pFile);
    pFile = NULL;

    a_pBuffer->Data   = pBuffer;
    a_pBuffer->Length = (OpcUa_Int32)(pPosition - pBuffer);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pFile != OpcUa_Null)
    {
        fclose(pFile);
    }

    if (pBuffer != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(pBuffer);
    }

    OpcUa_P_ByteString_Initialize(a_pBuffer);

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_CertificateStore_PopulateStore
 *===========================================================================*/
static OpcUa_StatusCode OpcUa_P_OpenSSL_CertificateStore_PopulateStore(
    OpcUa_P_OpenSSL_CertificateStore* a_pStore,
    OpcUa_CharA* a_pStorePath,
    OpcUa_Boolean a_bIsExplicitlyTrusted)
{
    /* ToDo: THIS IS A WORKAROUND->Better solution has to be found */
    HANDLE hFind = INVALID_HANDLE_VALUE;
    char DirSpec[MAX_PATH];
    char CertFile[MAX_PATH];
    DWORD dwError;
    int iLen;
    WIN32_FIND_DATAA FindFileData;
    OpcUa_ByteString tBuffer;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "CertificateStore_PopulateStore");

    OpcUa_ReturnErrorIfArgumentNull(a_pStorePath);

    OpcUa_P_ByteString_Initialize(&tBuffer);

    /* ToDo: THIS IS A WORKAROUND->Better solution has to be found, since X509_LOOKUP_add_dir does not work properly */
    OpcUa_P_String_strncpy(DirSpec, MAX_PATH-1, a_pStorePath, strlen(a_pStorePath));

    iLen = (int)strlen(DirSpec);

    if (a_pStorePath[iLen-1] == '\\')
    {
        OpcUa_P_String_strncat(DirSpec, MAX_PATH-1, "*.der", MAX_PATH-1);
    }
    else
    {
        OpcUa_P_String_strncat(DirSpec, MAX_PATH-1, "\\*.der", MAX_PATH-1);
    }

    hFind = FindFirstFileA(DirSpec, &FindFileData);

    if (hFind != INVALID_HANDLE_VALUE)
    {
        uStatus = OpcUa_P_OpenSSL_BuildFullPath(a_pStorePath, FindFileData.cFileName, MAX_PATH, CertFile);
        OpcUa_GotoErrorIfBad(uStatus);

        uStatus = OpcUa_P_OpenSSL_ReadFile(CertFile, &tBuffer);
        OpcUa_GotoErrorIfBad(uStatus);

        uStatus = OpcUa_P_OpenSSL_CertificateStore_AddCertificate(a_pStore, &tBuffer, a_bIsExplicitlyTrusted);
        OpcUa_GotoErrorIfBad(uStatus);

        OpcUa_P_ByteString_Clear(&tBuffer);

        while (FindNextFileA(hFind, &FindFileData) != 0)
        {
            uStatus = OpcUa_P_OpenSSL_BuildFullPath(a_pStorePath, FindFileData.cFileName, MAX_PATH, CertFile);
            OpcUa_GotoErrorIfBad(uStatus);

            uStatus = OpcUa_P_OpenSSL_ReadFile(CertFile, &tBuffer);
            OpcUa_GotoErrorIfBad(uStatus);

            uStatus = OpcUa_P_OpenSSL_CertificateStore_AddCertificate(a_pStore, &tBuffer, a_bIsExplicitlyTrusted);
            OpcUa_GotoErrorIfBad(uStatus);

            OpcUa_P_ByteString_Clear(&tBuffer);
        }

        dwError = GetLastError();
        FindClose(hFind);

        if (dwError != ERROR_NO_MORE_FILES)
        {
            OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "unexpected error loading certificates! %d\n", dwError);
            OpcUa_GotoErrorWithStatus(OpcUa_Bad);
        }
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_P_ByteString_Clear(&tBuffer);

OpcUa_FinishErrorHandling;
}


/*============================================================================
 * OpcUa_P_OpenSSL_CertificateStore_LoadCRLs
 *===========================================================================*/
static OpcUa_StatusCode OpcUa_P_OpenSSL_CertificateStore_LoadCRLs(
    X509_LOOKUP* pLookup,
    OpcUa_CharA* a_pCrlPath)
{
    HANDLE hFind = INVALID_HANDLE_VALUE;
    char DirSpec[MAX_PATH];
    char CertFile[MAX_PATH];
    DWORD dwError;
    int iLen;
    WIN32_FIND_DATAA FindFileData;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "CertificateStore_LoadCRLs");

    OpcUa_ReturnErrorIfArgumentNull(a_pCrlPath);

    OpcUa_P_String_strncpy(DirSpec, MAX_PATH-1, a_pCrlPath, MAX_PATH);

    iLen = (int)strlen(DirSpec);

    if (a_pCrlPath[iLen-1] == '\\')
    {
        OpcUa_P_String_strncat(DirSpec, MAX_PATH-1, "*.crl", MAX_PATH-1);
    }
    else
    {
        OpcUa_P_String_strncat(DirSpec, MAX_PATH-1, "\\*.crl", MAX_PATH-1);
    }

    hFind = FindFirstFileA(DirSpec, &FindFileData);

    if (hFind != INVALID_HANDLE_VALUE)
    {
        uStatus = OpcUa_P_OpenSSL_BuildFullPath(a_pCrlPath, FindFileData.cFileName, MAX_PATH, CertFile);
        OpcUa_GotoErrorIfBad(uStatus);

        if (X509_load_crl_file(pLookup, CertFile, X509_FILETYPE_ASN1) != 1)
        {
            OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "unexpected error X509_load_crl_file! %s\n", CertFile);
            OpcUa_GotoErrorWithStatus(OpcUa_Bad);
        }

        while (FindNextFileA(hFind, &FindFileData) != 0)
        {
            uStatus = OpcUa_P_OpenSSL_BuildFullPath(a_pCrlPath, FindFileData.cFileName, MAX_PATH, CertFile);
            OpcUa_GotoErrorIfBad(uStatus);

            if (X509_load_crl_file(pLookup, CertFile, X509_FILETYPE_ASN1) != 1)
            {
                OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "unexpected error X509_load_crl_file! %s\n", CertFile);
                OpcUa_GotoErrorWithStatus(OpcUa_Bad);
            }
        }

        dwError = GetLastError();
        FindClose(hFind);

        if (dwError != ERROR_NO_MORE_FILES)
        {
            OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "unexpected error loading CRL files! %d\n", dwError);
            OpcUa_GotoErrorWithStatus(OpcUa_Bad);
        }
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_CertificateStore_Open
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_PKI_OpenCertificateStore(
    OpcUa_PKIProvider*          a_pProvider,
    OpcUa_Void**                a_ppCertificateStore)
{
    X509_LOOKUP* pLookup = OpcUa_Null; /* files or hash dirs */
    OpcUa_P_OpenSSL_CertificateStore_Config* pCertificateStoreCfg = OpcUa_Null;
    OpcUa_P_OpenSSL_CertificateStore* pCertificateStore  = OpcUa_Null;

    OpcUa_CharA pTrustedCertificateStorePath[MAX_PATH];
    OpcUa_CharA pTrustedCertificateCrlPath[MAX_PATH];
    OpcUa_CharA pIssuerCertificateStorePath[MAX_PATH];
    OpcUa_CharA pIssuerCertificateCrlPath[MAX_PATH];
    OpcUa_Int32 nRootPathLength = 0;
    OpcUa_Int32 iFlags = 0;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "PKI_OpenCertificateStore");

    OpcUa_ReturnErrorIfArgumentNull(a_pProvider);
    OpcUa_ReturnErrorIfArgumentNull(a_pProvider->Handle);

    *a_ppCertificateStore = OpcUa_Null;

    pTrustedCertificateStorePath[0] = '\0';
	pTrustedCertificateCrlPath[0] = '\0';
    pIssuerCertificateStorePath[0] = '\0';
	pIssuerCertificateCrlPath[0] = '\0';

    pCertificateStoreCfg = (OpcUa_P_OpenSSL_CertificateStore_Config*)a_pProvider->Handle;

    /* check the path length. */
	nRootPathLength = (OpcUa_Int32)strlen(pCertificateStoreCfg->TrustedCertificateStorePath);

    if (nRootPathLength >= MAX_PATH-6)
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Certificate store file path length is too long: %d!\n", nRootPathLength);
        OpcUa_GotoErrorWithStatus(OpcUa_Bad);
    }

	OpcUa_P_String_strncpy(pTrustedCertificateStorePath, MAX_PATH-1, pCertificateStoreCfg->TrustedCertificateStorePath, nRootPathLength);

    /* remove any trailing slashes */
    while(pTrustedCertificateStorePath[nRootPathLength-1] == '\\' && nRootPathLength > 0)
    {
        pTrustedCertificateStorePath[--nRootPathLength] = '\0';
    }

	OpcUa_P_String_strncat(pTrustedCertificateStorePath, MAX_PATH-1, "\\certs", 6);
	OpcUa_P_String_strncpy(pTrustedCertificateCrlPath, MAX_PATH-1, pCertificateStoreCfg->TrustedCertificateStorePath, nRootPathLength);
	OpcUa_P_String_strncat(pTrustedCertificateCrlPath, MAX_PATH-1, "\\crl", 4);

	if (pCertificateStoreCfg->IssuerCertificateStorePath != OpcUa_Null)
	{
		OpcUa_Int32 nLength = (OpcUa_Int32)strlen(pCertificateStoreCfg->IssuerCertificateStorePath);
		OpcUa_P_String_strncpy(pIssuerCertificateStorePath, MAX_PATH-1, pCertificateStoreCfg->IssuerCertificateStorePath, nLength);

		/* remove any trailing slashes */
		while(pIssuerCertificateStorePath[nLength-1] == '\\' && nLength > 0)
		{
			pIssuerCertificateStorePath[--nLength] = '\0';
		}

		OpcUa_P_String_strncat(pIssuerCertificateStorePath, MAX_PATH-1, "\\certs", 6);
		OpcUa_P_String_strncpy(pIssuerCertificateCrlPath, MAX_PATH-1, pCertificateStoreCfg->IssuerCertificateStorePath, nLength);
		OpcUa_P_String_strncat(pIssuerCertificateCrlPath, MAX_PATH-1, "\\crl", 4);
	}

    /* allocate the handle. */
    pCertificateStore = OpcUa_P_OpenSSL_CertificateStore_Alloc();
    OpcUa_GotoErrorIfAllocFailed(pCertificateStore);

    /* create a new store */
    if(!(pCertificateStore->MergedTrustList = X509_STORE_new()))
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "error at X509_STORE_new!\n");
        OpcUa_GotoErrorWithStatus(OpcUa_Bad);
    }

    /* set the verification callback */
    X509_STORE_set_verify_cb_func(pCertificateStore->MergedTrustList, OpcUa_P_OpenSSL_CertificateStore_Verify_Callback);

    if(X509_STORE_set_default_paths(pCertificateStore->MergedTrustList) != 1)
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "error at X509_STORE_set_default_paths!\n");
        OpcUa_GotoErrorWithStatus(OpcUa_Bad);
    }

    /* how to search for certificate & CRLs */
    if(!(pLookup = X509_STORE_add_lookup(pCertificateStore->MergedTrustList, X509_LOOKUP_file())))
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "error at X509_STORE_add_lookup!\n");
        OpcUa_GotoErrorWithStatus(OpcUa_Bad);
    }

    /* open the trusted certificates store. */
    uStatus = OpcUa_P_OpenSSL_CertificateStore_PopulateStore(pCertificateStore, pTrustedCertificateStorePath, OpcUa_True);
    OpcUa_GotoErrorIfBad(uStatus);

    /* open the untrusted CA certificates store. */
    if (pIssuerCertificateStorePath != OpcUa_Null && pIssuerCertificateStorePath[0] != '\0')
    {
        uStatus = OpcUa_P_OpenSSL_CertificateStore_PopulateStore(pCertificateStore, pIssuerCertificateStorePath, OpcUa_False);
        OpcUa_GotoErrorIfBad(uStatus);
    }

    /* how to search for certificate & CRLs */
    if(!(pLookup = X509_STORE_add_lookup(pCertificateStore->MergedTrustList, X509_LOOKUP_hash_dir())))
    {
        uStatus = OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    /* add CTL lookup */
    if(X509_LOOKUP_add_dir(pLookup, pTrustedCertificateStorePath, X509_FILETYPE_ASN1) != 1)
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "unexpected error at X509_LOOKUP_add_dir!\n");
        OpcUa_GotoErrorWithStatus(OpcUa_Bad);
    }

    /* how to search for certificate & CRLs */
    if(!(pLookup = X509_STORE_add_lookup(pCertificateStore->MergedTrustList, X509_LOOKUP_file())))
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "unexpected error X509_STORE_add_lookup!\n");
        OpcUa_GotoErrorWithStatus(OpcUa_Bad);
    }

	iFlags = X509_V_FLAG_CB_ISSUER_CHECK;

    /* add CRL lookup */
	if ((pCertificateStoreCfg->Flags & OpcUa_PKI_CheckRevocationStatus) == OpcUa_PKI_CheckRevocationStatus)
	{
		iFlags |= X509_V_FLAG_CRL_CHECK;

		if (pTrustedCertificateCrlPath != OpcUa_Null && pTrustedCertificateCrlPath[0] != '\0')
		{
			uStatus = OpcUa_P_OpenSSL_CertificateStore_LoadCRLs(pLookup, pTrustedCertificateCrlPath);
			OpcUa_GotoErrorIfBad(uStatus);
		}

		if (pIssuerCertificateCrlPath != OpcUa_Null && pIssuerCertificateCrlPath[0] != '\0')
		{
			uStatus = OpcUa_P_OpenSSL_CertificateStore_LoadCRLs(pLookup, pIssuerCertificateCrlPath);
			OpcUa_GotoErrorIfBad(uStatus);
		}
	}

    /* set the flags of the store so that CRLs are consulted */
    /* ToDo: Time check fails: X509_V_FLAG_USE_CHECK_TIME ==> X509_V_ERR_CERT_NOT_YET_VALID */
    if(X509_STORE_set_flags(pCertificateStore->MergedTrustList, iFlags) != 1)
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "unexpected X509_STORE_set_flags X509_load_crl_file!\n");
        OpcUa_GotoErrorWithStatus(OpcUa_Bad);
    }

    /* clean up */
    pLookup = OpcUa_Null;

    *a_ppCertificateStore = pCertificateStore;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_P_OpenSSL_CertificateStore_Free(&pCertificateStore);
    pLookup = OpcUa_Null;

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_CertificateStore_Close
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_PKI_CloseCertificateStore(
    OpcUa_PKIProvider*          a_pProvider,
    OpcUa_Void**                a_ppCertificateStore) /* type depends on store implementation */
{
OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "PKI_CloseCertificateStore");

    OpcUa_ReferenceParameter(a_pProvider);

    OpcUa_P_OpenSSL_CertificateStore_Free((OpcUa_P_OpenSSL_CertificateStore**)a_ppCertificateStore);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_PKI_ValidateCertificate
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_PKI_ValidateCertificate(
    OpcUa_PKIProvider*          a_pProvider,
    OpcUa_ByteString*           a_pCertificate,
    OpcUa_Void*                 a_pCertificateStore,
    OpcUa_Int*                  a_pValidationCode /* Validation return codes from OpenSSL */
)
{
    OpcUa_Byte* pPosition = OpcUa_Null;
    OpcUa_P_OpenSSL_CertificateStore* pStore = OpcUa_Null;
    OpcUa_Boolean bExplicitlyTrusted = OpcUa_False;

    X509* pX509Certificate = OpcUa_Null;
    X509_STORE* pX509Store = OpcUa_Null;
    X509_STORE_CTX* pContext = OpcUa_Null;    /* holds data used during verification process */

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "PKI_ValidateCertificate");

    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificateStore);
    OpcUa_ReturnErrorIfArgumentNull(a_pValidationCode);

    pStore = (OpcUa_P_OpenSSL_CertificateStore*)a_pCertificateStore;
    pX509Store = pStore->MergedTrustList;

    /* convert public key to X509 structure. */
    pPosition = a_pCertificate->Data;
    pX509Certificate = d2i_X509((X509**)OpcUa_Null, (const unsigned char**)&pPosition, a_pCertificate->Length);
    OpcUa_GotoErrorIfNull(pX509Certificate, OpcUa_Bad);

    /* create verification context and initialize it. */
    if(!(pContext = X509_STORE_CTX_new()))
    {
        OpcUa_GotoErrorWithStatus(OpcUa_Bad);
    }

#if (OPENSSL_VERSION_NUMBER > 0x00907000L)
    if(X509_STORE_CTX_init(pContext, pX509Store, pX509Certificate, NULL) != 1)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_Bad);
    }
#else
    X509_STORE_CTX_init(pContext,store,cert,NULL);
#endif

    /* verify the certificate */
    if(((*a_pValidationCode = X509_verify_cert(pContext)) <= 0))
    {
        switch(X509_STORE_CTX_get_error(pContext))
        {
            case X509_V_ERR_CERT_HAS_EXPIRED:
            case X509_V_ERR_CERT_NOT_YET_VALID:
            case X509_V_ERR_CRL_NOT_YET_VALID:
            case X509_V_ERR_CRL_HAS_EXPIRED:
            case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
            case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
            case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
            case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
            {
                uStatus = OpcUa_BadCertificateTimeInvalid;
                break;
            }

            case X509_V_ERR_CERT_REVOKED:
            {
                uStatus = OpcUa_BadCertificateRevoked;
                break;
            }

            case X509_V_ERR_CERT_UNTRUSTED:
            case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
            {
                uStatus = OpcUa_BadCertificateUntrusted;
                break;
            }

            case X509_V_ERR_CERT_SIGNATURE_FAILURE:
            {
                uStatus = OpcUa_BadSecurityChecksFailed;
                break;
            }

            default:
            {
                uStatus = OpcUa_BadCertificateInvalid;
            }
        }
    }

    /* now must verify that certificate has been explicitly trusted */
    if(OpcUa_IsGood(uStatus) || uStatus == OpcUa_BadCertificateUntrusted)
    {
        uStatus = OpcUa_P_OpenSSL_CertificateStore_IsExplicitlyTrusted(pStore, pContext, pX509Certificate, &bExplicitlyTrusted);
        OpcUa_GotoErrorIfBad(uStatus);

        if (!bExplicitlyTrusted)
        {
            uStatus = OpcUa_BadCertificateUntrusted;
        }
    }

    X509_STORE_CTX_free(pContext);
    X509_free(pX509Certificate);

    ERR_remove_state(0);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(pContext != OpcUa_Null)
    {
        X509_STORE_CTX_free(pContext);
    }

    if(pX509Certificate != OpcUa_Null)
    {
        X509_free(pX509Certificate);
    }

    ERR_remove_state(0);

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_PKI_SaveCertificate
 *===========================================================================*/
/*
    ToDo:   Create Access to OpenSSL certificate store
            => Only API to In-Memory-Store is available for version 0.9.8x
            => Wait until Directory- and/or File-Store is available
*/
OpcUa_StatusCode OpcUa_P_OpenSSL_PKI_SaveCertificate(
    OpcUa_PKIProvider*          a_pProvider,
    OpcUa_ByteString*           a_pCertificate,
    OpcUa_Void*                 a_pCertificateStore,
    OpcUa_Void*                 a_pSaveHandle)      /* Index or number within store/destination filepath */
{
    X509*                                       pX509Certificate        = OpcUa_Null;
    BIO*                                        pCertificateFile        = OpcUa_Null;
    OpcUa_ByteString                            derEncodedCertificate   = OPCUA_BYTESTRING_STATICINITIALIZER;
    OpcUa_UInt32                                i;
    OpcUa_P_OpenSSL_CertificateStore_Config*    pCertificateStoreCfg    = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "PKI_SaveCertificate");

    OpcUa_ReturnErrorIfArgumentNull(a_pProvider);
    OpcUa_ReturnErrorIfArgumentNull(a_pProvider->Handle);
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificateStore);
    OpcUa_ReturnErrorIfArgumentNull(a_pSaveHandle);

    pCertificateStoreCfg = (OpcUa_P_OpenSSL_CertificateStore_Config*)a_pProvider->Handle;

    /* copy DER encoded certificate, since d2i_X509 modifies the passed buffer */
    derEncodedCertificate.Length = a_pCertificate->Length;
    derEncodedCertificate.Data = (OpcUa_Byte*)OpcUa_P_Memory_Alloc(derEncodedCertificate.Length*sizeof(OpcUa_Byte));
    OpcUa_GotoErrorIfAllocFailed(derEncodedCertificate.Data);

    uStatus = OpcUa_P_Memory_MemCpy(derEncodedCertificate.Data, derEncodedCertificate.Length, a_pCertificate->Data, derEncodedCertificate.Length);
    OpcUa_GotoErrorIfBad(uStatus);

    /* convert openssl X509 certificate to DER encoded bytestring certificate */
    if(!(pX509Certificate = d2i_X509((X509**)OpcUa_Null, (unsigned const char**)&derEncodedCertificate.Data, derEncodedCertificate.Length)))
    {
        uStatus = OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    /* save DER certificate */
    pCertificateFile = BIO_new_file((const char*)a_pSaveHandle, "w");
    OpcUa_ReturnErrorIfArgumentNull(pCertificateFile);

    i = i2d_X509_bio(pCertificateFile, pX509Certificate);

    if(i < 1)
    {
        uStatus =  OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    if(BIO_free (pCertificateFile) == 0)
    {
        uStatus =  OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    pCertificateFile = NULL;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(derEncodedCertificate.Data != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(derEncodedCertificate.Data);
        derEncodedCertificate.Length = -1;
        derEncodedCertificate.Data = OpcUa_Null;
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_CertificateStore_Certificate_Load
 *===========================================================================*/
/*
    ToDo:   Create Access to OpenSSL certificate store
            => Only API to In-Memory-Store is available for version 0.9.8x
            => Wait until Directory- and/or File-Store is available
*/
OpcUa_StatusCode OpcUa_P_OpenSSL_PKI_LoadCertificate(
    OpcUa_PKIProvider*          a_pProvider,
    OpcUa_Void*                 a_pLoadHandle,
    OpcUa_Void*                 a_pCertificateStore,
    OpcUa_ByteString*           a_pCertificate)
{
    OpcUa_Byte*     buf                 = OpcUa_Null;
    OpcUa_Byte*     p                   = OpcUa_Null;
    BIO*            pCertificateFile    = OpcUa_Null;
    X509*           pTmpCert            = OpcUa_Null;

    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "PKI_LoadCertificate");

    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_pCertificateStore);

    OpcUa_ReturnErrorIfArgumentNull(a_pLoadHandle);
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);

    /* read DER certificates */
    pCertificateFile = BIO_new_file((const char*)a_pLoadHandle, "r");
    OpcUa_ReturnErrorIfArgumentNull(pCertificateFile);

    if (!(pTmpCert = d2i_X509_bio(pCertificateFile, (X509**)OpcUa_Null)))
    {
        uStatus = OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    BIO_free(pCertificateFile);

    a_pCertificate->Length = i2d_X509(pTmpCert, NULL);
    buf = (OpcUa_Byte*)OpcUa_P_Memory_Alloc(a_pCertificate->Length);
    OpcUa_GotoErrorIfAllocFailed(buf);
    p = buf;
    i2d_X509(pTmpCert, &p);

    a_pCertificate->Data = (OpcUa_Byte*)OpcUa_P_Memory_Alloc(a_pCertificate->Length*sizeof(OpcUa_Byte));
    OpcUa_GotoErrorIfAllocFailed(a_pCertificate->Data);

    uStatus = OpcUa_P_Memory_MemCpy(a_pCertificate->Data, a_pCertificate->Length, buf, a_pCertificate->Length);
    OpcUa_GotoErrorIfBad(uStatus);

    if(pTmpCert != OpcUa_Null)
    {
        X509_free(pTmpCert);
        pTmpCert = OpcUa_Null;
    }

    if(buf != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(buf);
        buf = OpcUa_Null;
        p = OpcUa_Null;
    }

    pCertificateFile = NULL;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(pTmpCert != OpcUa_Null)
    {
        X509_free(pTmpCert);
        pTmpCert = OpcUa_Null;
    }

    if(a_pCertificate != OpcUa_Null)
    {
        if(a_pCertificate->Data != OpcUa_Null)
        {
            OpcUa_P_Memory_Free(a_pCertificate->Data);
            a_pCertificate->Data = OpcUa_Null;
            a_pCertificate->Length = -1;
        }
    }

    if(buf != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(buf);
        buf = OpcUa_Null;
        p = OpcUa_Null;
    }

OpcUa_FinishErrorHandling;
}

#endif /* OPCUA_REQUIRE_OPENSSL */
