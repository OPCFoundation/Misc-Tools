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

#ifndef _CRT_SECURE_NO_DEPRECATE
    #define _CRT_SECURE_NO_DEPRECATE
#endif /* _CRT_SECURE_NO_DEPRECATE */

/* System Headers */
#include <windows.h>
#include <Wincrypt.h>

/* UA platform definitions */
#include <opcua_p_internal.h>
#include <opcua_p_memory.h>
#include <opcua_p_string.h>

#if OPCUA_SUPPORT_PKI

#if OPCUA_SUPPORT_PKI_WIN32

#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

/* own headers */
#include <opcua_p_win32_pki.h>

OpcUa_Void OpcUa_P_ByteString_Clear(OpcUa_ByteString* pValue);

/*============================================================================
 * OpcUa_P_Win32_OpcUaPkiFlags2Win32PkiFlags
 *===========================================================================*/
OpcUa_UInt32 OpcUa_P_Win32_OpcUaPkiFlags2Win32PkiFlags(OpcUa_UInt32 opcUaFlags)
{
    OpcUa_UInt32 win32Flags = 0;

    if((opcUaFlags & WIN32_PKI_USERSTORE) == WIN32_PKI_USERSTORE)
    {
        win32Flags = CERT_SYSTEM_STORE_CURRENT_USER;
    }

    if((opcUaFlags & WIN32_PKI_MACHINESTORE) == WIN32_PKI_MACHINESTORE)
    {
        win32Flags = win32Flags | CERT_SYSTEM_STORE_LOCAL_MACHINE;
    }

    if((opcUaFlags & WIN32_PKI_SERVICESSTORE) == WIN32_PKI_SERVICESSTORE)
    {
        win32Flags = win32Flags | CERT_SYSTEM_STORE_SERVICES;
    }

    return win32Flags;
}

/*============================================================================
 * OpcUa_P_Win32_CertificateStore_Open
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Win32_PKI_OpenCertificateStore(
    OpcUa_PKIProvider*          a_pProvider,
    OpcUa_Void**                a_ppCertificateStore)
{
    OpcUa_Char*                                 pStoreName              = OpcUa_Null;
    OpcUa_P_OpenSSL_CertificateStore_Config*    pCertificateStoreCfg    = OpcUa_Null;
    OpcUa_UInt32                                win32PKIFlags           = 0;

OpcUa_InitializeStatus(OpcUa_Module_P_Win32, "PKI_OpenCertificateStore");

    OpcUa_ReturnErrorIfArgumentNull(a_pProvider);
    OpcUa_ReturnErrorIfArgumentNull(a_pProvider->Handle);

    *a_ppCertificateStore = OpcUa_Null;

    pCertificateStoreCfg = (OpcUa_P_OpenSSL_CertificateStore_Config*)a_pProvider->Handle;

    if(pCertificateStoreCfg)
    {
        /* translate common OPC UA PKI flags to specific win32 PKI flags */
        win32PKIFlags = OpcUa_P_Win32_OpcUaPkiFlags2Win32PkiFlags(pCertificateStoreCfg->Flags);
    }

	pStoreName = OpcUa_P_Win32_MultiByteToWideChar(pCertificateStoreCfg->TrustedCertificateStorePath);

    /*** OPEN CERTIFICATE STORE ***/
    if(!(*a_ppCertificateStore = CertOpenStore(
                                            CERT_STORE_PROV_SYSTEM,
                                            0,
                                            (HCRYPTPROV)OpcUa_Null,
                                            win32PKIFlags | CERT_STORE_OPEN_EXISTING_FLAG,
                                            pStoreName)))
    {
       uStatus = OpcUa_Bad;
    }

    if (pStoreName != OpcUa_Null)
    {
        free(pStoreName);
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Win32_CertificateStore_Close
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Win32_PKI_CloseCertificateStore(
    OpcUa_PKIProvider*          a_pProvider,
    OpcUa_Void**                a_ppCertificateStore)
{

OpcUa_InitializeStatus(OpcUa_Module_P_Win32, "PKI_CloseCertificateStore");

    OpcUa_ReferenceParameter(a_pProvider);

    if(a_ppCertificateStore != OpcUa_Null)
    {
        if(*a_ppCertificateStore)
        {
            /*** CLOSE CERTIFICATE STORE ***/
            if (!CertCloseStore(*a_ppCertificateStore, CERT_CLOSE_STORE_FORCE_FLAG))
            {
                uStatus = OpcUa_Bad;
            }
        }
        *a_ppCertificateStore = OpcUa_Null;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Win32_PKI_ValidateCertificate
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Win32_PKI_ValidateCertificate(
    OpcUa_PKIProvider*          a_pProvider,
    OpcUa_ByteString*           a_pCertificate,
    OpcUa_Void*                 a_pCertificateStore,
    OpcUa_Int*                  a_pValidationCode /* Validation return codes from Win32 */
    )
{
    PCCERT_CHAIN_CONTEXT     pChainContext  = OpcUa_Null;
    CERT_ENHKEY_USAGE        EnhkeyUsage;
    CERT_USAGE_MATCH         CertUsage;
    CERT_CHAIN_PARA          ChainPara;
    DWORD                    dwFlags        = CERT_CHAIN_CACHE_END_CERT;
    PCCERT_CONTEXT           pTargetCert    = OpcUa_Null;
    PCCERT_CONTEXT           pSearchCert    = OpcUa_Null;
    OpcUa_Boolean            foundCertificate = OpcUa_False;

OpcUa_InitializeStatus(OpcUa_Module_P_Win32, "PKI_ValidateCertificate");

    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificateStore);

    EnhkeyUsage.cUsageIdentifier        = 0;
    EnhkeyUsage.rgpszUsageIdentifier    = OpcUa_Null;

    CertUsage.dwType                    = USAGE_MATCH_TYPE_AND;
    CertUsage.Usage                     = EnhkeyUsage;

    ChainPara.cbSize                    = sizeof(CERT_CHAIN_PARA);
    ChainPara.RequestedUsage            = CertUsage;

    /*** CONVERT CERTIFICATE ***/
    pTargetCert = CertCreateCertificateContext(X509_ASN_ENCODING, a_pCertificate->Data, a_pCertificate->Length);
    OpcUa_ReturnErrorIfArgumentNull(pTargetCert);

    /*** BUILD CERTIFICATE CHAIN ***/
    if(!CertGetCertificateChain(
        HCCE_LOCAL_MACHINE,     // use the default chain engine
        pTargetCert,            // pointer to the end certificate
        OpcUa_Null,             // use the default time
        a_pCertificateStore,    // Use the store opened
        &ChainPara,             // use AND logic and enhanced key usage
                                //  as indicated in the ChainPara
                                //  data structure
        dwFlags,                // ==>REVOCATION CONFIGURATION
        OpcUa_Null,             // currently reserved
        &pChainContext))        // return a pointer to the chain created
    {
        // The certificate chain could not be created!
        OpcUa_GotoErrorWithStatus(OpcUa_Bad);   // Todo: new statuscode should be defined: CertificateValidationFailed
    }

    if(a_pValidationCode)
    {
        *a_pValidationCode = pChainContext->TrustStatus.dwErrorStatus;
    }

    /*** CHECK ERROR STATUS OF THE CERTIFICATE CHAIN ***/
    switch(pChainContext->TrustStatus.dwErrorStatus)
    {
    case CERT_TRUST_NO_ERROR :
         // Todo Trace: No error found for this certificate or chain.
         break;
    case CERT_TRUST_IS_NOT_TIME_VALID:
         // Todo Trace: This certificate or one of the certificates in the certificate chain is not time-valid.
         OpcUa_GotoErrorWithStatus(OpcUa_BadCertificateTimeInvalid); // or OpcUa_BadCertificateIssuerTimeInvalid
         break;
    case CERT_TRUST_IS_NOT_TIME_NESTED:
         // Todo Trace: Certificates in the chain are not properly time-nested.
         OpcUa_GotoErrorWithStatus(OpcUa_BadCertificateTimeInvalid);
         break;
    case CERT_TRUST_IS_REVOKED:
         // Todo Trace: Trust for this certificate or one of the certificates in the certificate chain has been revoked.
         OpcUa_GotoErrorWithStatus(OpcUa_BadCertificateRevoked);
         break;
    case CERT_TRUST_IS_NOT_SIGNATURE_VALID:
         // Todo Trace: The certificate or one of the certificates in the certificate chain does not have a valid signature.
         OpcUa_GotoErrorWithStatus(OpcUa_BadCertificateInvalid); //Todo: we need a statuscode like: CertificateSignatureInvalid
         break;
    case CERT_TRUST_IS_NOT_VALID_FOR_USAGE:
         // Todo Trace: The certificate or certificate chain is not valid in its proposed usage.
         OpcUa_GotoErrorWithStatus(OpcUa_BadCertificateUseNotAllowed);
         break;
    case CERT_TRUST_IS_UNTRUSTED_ROOT:
         // Todo Trace: The certificate or certificate chain is based on an untrusted root.
         // OpcUa_GotoErrorWithStatus(OpcUa_BadCertificateUntrusted);
         break;
    case CERT_TRUST_REVOCATION_STATUS_UNKNOWN:
         // Todo Trace: The revocation status of the certificate or one of the certificates in the certificate chain is unknown.
         OpcUa_GotoErrorWithStatus(OpcUa_BadCertificateRevocationUnknown);
         break;
    case CERT_TRUST_IS_CYCLIC:
         // Todo Trace: One of the certificates in the chain was issued by a certification authority that the original certificate had certified.
         OpcUa_GotoErrorWithStatus(OpcUa_BadCertificateUntrusted); //Todo: we need a statuscode like: CyclicCertificateChain
         break;
    case CERT_TRUST_IS_PARTIAL_CHAIN:
         // Todo Trace: The certificate chain is not complete.
         OpcUa_GotoErrorWithStatus(OpcUa_BadCertificateUntrusted); //Todo: we need a statuscode like: PartialCertificateChain
         break;
    default:
         // Todo Trace: Unknown error code.
         OpcUa_GotoErrorWithStatus(OpcUa_BadCertificateUntrusted);
         break;
    } // End switch

    /*** CHECK INFO STATUS OF THE CERTIFICATE CHAIN ***/
    switch(pChainContext->TrustStatus.dwInfoStatus)
    {
    case 0:
         break;
    case CERT_TRUST_HAS_EXACT_MATCH_ISSUER :
         // Todo Trace: An exact match issuer certificate has been found for this certificate.
         break;
    case CERT_TRUST_HAS_KEY_MATCH_ISSUER:
        // Todo Trace: A key match issuer certificate has been found for this certificate.
         break;
    case CERT_TRUST_HAS_NAME_MATCH_ISSUER:
        // Todo Trace: A name match issuer certificate has been found for this certificate.
         break;
    case CERT_TRUST_IS_SELF_SIGNED:
         // Todo Trace: This certificate is self-signed.
         break;
    case CERT_TRUST_IS_COMPLEX_CHAIN:
         // Todo Trace: The certificate chain created is a complex chain.
         break;
    } // end switch

    // Check if the certificate is in the store if untrusted root
    if ( pChainContext->TrustStatus.dwErrorStatus == CERT_TRUST_IS_UNTRUSTED_ROOT )
    {
        while (pSearchCert = CertEnumCertificatesInStore(a_pCertificateStore, pSearchCert))
        {
            if ( pTargetCert->cbCertEncoded == pSearchCert->cbCertEncoded )
            {
                if ( OpcUa_MemCmp(pTargetCert->pbCertEncoded, pSearchCert->pbCertEncoded, pTargetCert->cbCertEncoded) == 0 )
                {
                    foundCertificate = OpcUa_True;
                    break;
                }
            }
        }

        if ( foundCertificate == OpcUa_False )
        {
            OpcUa_GotoErrorWithStatus(OpcUa_BadCertificateUntrusted);
        }
    }

    /*** FREE RESOURCES ***/

    if (pTargetCert)
    {
        CertFreeCertificateContext(pTargetCert);
        pTargetCert = OpcUa_Null;
    }

    if(pChainContext)
    {
        CertFreeCertificateChain(pChainContext);
        pChainContext = OpcUa_Null;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pTargetCert)
    {
        CertFreeCertificateContext(pTargetCert);
        pTargetCert = OpcUa_Null;
    }

    if(pChainContext)
    {
        CertFreeCertificateChain(pChainContext);
        pChainContext = OpcUa_Null;
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Win32_PKI_SaveCertificate
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Win32_PKI_SaveCertificate(
    OpcUa_PKIProvider*          a_pProvider,
    OpcUa_ByteString*           a_pCertificate,
    OpcUa_Void*                 a_pCertificateStore,
    OpcUa_Void*                 a_pSaveHandle)      /* Index or number within store/destination filepath */
{

    //OpcUa_P_Win32_CertificateStore_Config*    pCertificateStoreCfg    = OpcUa_Null;

    HCERTSTORE      hSystemStore = OpcUa_Null;

    OpcUa_InitializeStatus(OpcUa_Module_P_Win32, "PKI_SaveCertificate");

    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_pSaveHandle);

    OpcUa_ReturnErrorIfArgumentNull(a_pProvider);
    OpcUa_ReturnErrorIfArgumentNull(a_pProvider->Handle);
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificateStore);
    //OpcUa_ReturnErrorIfArgumentNull(a_pSaveHandle);

    //pCertificateStoreCfg = (OpcUa_P_Win32_CertificateStore_Config*)a_pProvider->Handle;

    hSystemStore = (HCERTSTORE)a_pCertificateStore;

    /*** ADD CERTIFICATE TO SPECIFIED CERTIFICATE STORE ***/
    /// Destination is defined by OpenCertificateStore function parameters
    if(CertAddEncodedCertificateToStore(
                                    hSystemStore,
                                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                    a_pCertificate->Data,
                                    a_pCertificate->Length,
                                    CERT_STORE_ADD_REPLACE_EXISTING, //has to be configurable => SaveHandle or StoreConfig??
                                    NULL))
    {
        //Trace: certificate added to store
    }
    else
    {
        uStatus = OpcUa_Bad;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Win32_CertificateStore_Certificate_Load
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Win32_PKI_LoadCertificate(
    OpcUa_PKIProvider*          a_pProvider,
    OpcUa_Void*                 a_pLoadHandle,
    OpcUa_Void*                 a_pCertificateStore,
    OpcUa_ByteString*           a_pCertificate)
{
    PCCERT_CONTEXT  pTargetCert  = OpcUa_Null;
    HCERTSTORE      hSystemStore = OpcUa_Null;
    OpcUa_Char*     pSubjectName = OpcUa_Null;

    OpcUa_InitializeStatus(OpcUa_Module_P_Win32, "PKI_LoadCertificate");

    OpcUa_ReferenceParameter(a_pProvider);

    OpcUa_ReturnErrorIfArgumentNull(a_pCertificateStore);
    OpcUa_ReturnErrorIfArgumentNull(a_pLoadHandle);
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);

    hSystemStore = (HCERTSTORE)a_pCertificateStore;
    pSubjectName = OpcUa_P_Win32_MultiByteToWideChar(a_pLoadHandle);

    /*** FIND CERTIFICATE IN SYSTEM STORE ***/
    if(pTargetCert = CertFindCertificateInStore(
                                              hSystemStore,                             // Store handle.
                                              PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,  // Encoding type.
                                              0,                                        // Not used.
                                              CERT_FIND_SUBJECT_STR,                    // Find type. Find a string in the certificate's subject.
                                              pSubjectName,                             // The string to be searched for.
                                              pTargetCert))                             // Previous context.
    {
        // certificate found
        a_pCertificate->Length = pTargetCert->cbCertEncoded;
        a_pCertificate->Data = (OpcUa_Byte*)OpcUa_P_Memory_Alloc(a_pCertificate->Length*sizeof(OpcUa_Byte));

        uStatus = OpcUa_P_Memory_MemCpy(a_pCertificate->Data, a_pCertificate->Length, pTargetCert->pbCertEncoded, a_pCertificate->Length);
        OpcUa_GotoErrorIfBad(uStatus);
    }
    else
    {
        // specified certificate could not be found in certificate store
        OpcUa_GotoErrorWithStatus(OpcUa_BadNotFound);
    }


    /*** FREE RESOURCES ***/
    if (pTargetCert)
    {
        CertFreeCertificateContext(pTargetCert);
        pTargetCert = OpcUa_Null;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /*** FREE RESOURCES ***/
    if (pTargetCert)
    {
        CertFreeCertificateContext(pTargetCert);
        pTargetCert = OpcUa_Null;
    }

    if(a_pCertificate)
    {
        OpcUa_P_ByteString_Clear(a_pCertificate);
    }

    if (pSubjectName != OpcUa_Null)
    {
        free(pSubjectName);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Win32_LoadPrivateKeyFromKeyStore
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Win32_LoadPrivateKeyFromKeyStore(
    OpcUa_StringA           a_privateKeyFile,
    OpcUa_P_FileFormat      a_fileFormat,       // Not used
    OpcUa_StringA           a_password,         // Not used
    OpcUa_ByteString*       a_pPrivateKey)
{
    HCERTSTORE        hSystemStore     = OpcUa_Null;
    HCERTSTORE        hMemoryStore     = OpcUa_Null;

    PCCERT_CONTEXT    pTempCertContext = OpcUa_Null;
    PCCERT_CONTEXT    pTargetCert      = OpcUa_Null;
    OpcUa_Char*       pSubjectName     = OpcUa_Null;

    CRYPT_DATA_BLOB   pfx              = {0, OpcUa_Null};

    BIO*              pBio             = OpcUa_Null;
    PKCS12*           pPKCS12          = OpcUa_Null;
    EVP_PKEY*         pEvpKey          = OpcUa_Null;
    X509*             pX509            = OpcUa_Null;
    STACK_OF(X509)*   pStack           = OpcUa_Null;
    int               i                = 0;
    RSA*              pRsaPrivateKey   = OpcUa_Null;
    unsigned char*    pData            = OpcUa_Null;

    OpcUa_InitializeStatus(OpcUa_Module_P_Win32, "PKI_LoadPrivateKey");

    OpcUa_ReturnErrorIfArgumentNull(a_privateKeyFile);
    OpcUa_ReturnErrorIfArgumentNull(a_pPrivateKey);

    OpcUa_ReferenceParameter(a_fileFormat);
    OpcUa_ReferenceParameter(a_password);

    /*** OPEN SYSTEM STORE ***/
    //// This has to move to OpenCertificateStore,
    //// but a parameter for PKIProvider has to be
    //// provided in the function declaration first!
    if(!(hSystemStore = CertOpenStore(
                                  CERT_STORE_PROV_SYSTEM,
                                  0,
                                  (HCRYPTPROV)OpcUa_Null,
                                  CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG,
                                  L"MY")))
    {
        // specified certificate store could not be opened!
        OpcUa_GotoErrorWithStatus(OpcUa_Bad);
    }

    pSubjectName = OpcUa_P_Win32_MultiByteToWideChar(a_privateKeyFile);

    /*** FIND CERTIFICATE OF DESIRED PRIVATE KEY IN SYSTEM STORE ***/
    if(!(pTargetCert = CertFindCertificateInStore(
                                  hSystemStore,                             // Store handle.
                                  PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,  // Encoding type.
                                  0,                                        // Not used.
                                  CERT_FIND_SUBJECT_STR,                  // Find type. Find a string in the certificate's subject.
                                  pSubjectName,                         // The string to be searched for.
                                  pTargetCert)))                            // Previous context.
    {
        // specified certificate could not be found in certificate store
        OpcUa_GotoErrorWithStatus(OpcUa_BadNotFound);
    }


    /*** OPEN MEMORY STORE ***/
    if(!(hMemoryStore = CertOpenStore(
                                    CERT_STORE_PROV_MEMORY,
                                    0,
                                    (HCRYPTPROV)OpcUa_Null,
                                    0,
                                    OpcUa_Null)))
    {
        // specified certificate store could not be opened!
        OpcUa_GotoErrorWithStatus(OpcUa_Bad);
    }


    /*** ADD LINK TO CERTIFICATE CONTEXT IN MEMORY STORE ***/
    if(!(CertAddCertificateLinkToStore(
                                    hMemoryStore,
                                    pTargetCert,
                                    CERT_STORE_ADD_REPLACE_EXISTING,
                                    &pTempCertContext)))
    {
        // specified certificate could not be added to memory store!
        OpcUa_GotoErrorWithStatus(OpcUa_Bad);
    }


    /*** EXPORT CERTIFICATE AND PRIVATE KEY FROM STORE (PFX) ***/
    ZeroMemory(&pfx, sizeof(pfx));
    if(PFXExportCertStoreEx(hMemoryStore, &pfx, OpcUa_Null, OpcUa_Null, EXPORT_PRIVATE_KEYS))
    {
        pfx.pbData = (BYTE *)CryptMemAlloc(sizeof(BYTE)*pfx.cbData);
        OpcUa_GotoErrorIfAllocFailed(pfx.pbData);
        if(!PFXExportCertStoreEx(hMemoryStore, &pfx, OpcUa_Null, OpcUa_Null, EXPORT_PRIVATE_KEYS))
        {
            // specified certificate could not be added to memory store!
            OpcUa_GotoErrorWithStatus(OpcUa_Bad);
        }
    }

    /*** CONVERT TO OPENSSL STRUCTURE FOR VERIFICATION ***/
    pBio = BIO_new(BIO_s_mem());
    BIO_write(pBio, pfx.pbData, pfx.cbData);
    pPKCS12 = d2i_PKCS12_bio(pBio, OpcUa_Null);
    i = PKCS12_parse(pPKCS12,OpcUa_Null,&pEvpKey,&pX509,&pStack);

    if((pEvpKey) && (i))
    {
        /* convert to intermediary openssl struct */
        pRsaPrivateKey = EVP_PKEY_get1_RSA(pEvpKey);
        EVP_PKEY_free(pEvpKey);
        pEvpKey = OpcUa_Null;
        OpcUa_GotoErrorIfNull(pRsaPrivateKey, OpcUa_Bad);

        /* get required length */
        a_pPrivateKey->Length = i2d_RSAPrivateKey(pRsaPrivateKey, OpcUa_Null);
        OpcUa_GotoErrorIfTrue((a_pPrivateKey->Length <= 0), OpcUa_Bad);

        /* allocate target buffer */
        a_pPrivateKey->Data = (OpcUa_Byte*)OpcUa_P_Memory_Alloc(a_pPrivateKey->Length);
        OpcUa_GotoErrorIfAllocFailed(a_pPrivateKey->Data);

        /* do real conversion */
        pData = a_pPrivateKey->Data;
        a_pPrivateKey->Length = i2d_RSAPrivateKey(pRsaPrivateKey, &pData);
        OpcUa_GotoErrorIfTrue((a_pPrivateKey->Length <= 0), OpcUa_Bad);
        RSA_free(pRsaPrivateKey);
        pRsaPrivateKey = OpcUa_Null;
    }
    else
    {
        // No private key information could be found
        OpcUa_GotoErrorWithStatus(OpcUa_BadNotFound);
    }

    /*** FREE RESOURCES ***/
    if(pBio)
    {
        BIO_free(pBio);
        pBio = OpcUa_Null;
    }

    if (pTempCertContext)
    {
        CertFreeCertificateContext(pTempCertContext);
        pTempCertContext = OpcUa_Null;
    }

    /*** Free CerificateContextHandles ***/
    if (pTargetCert)
    {
        CertFreeCertificateContext(pTargetCert);
        pTargetCert = OpcUa_Null;
    }

    /*** CLOSE MEMORY STORE ***/
    if(hMemoryStore)
    {
        if (!CertCloseStore(hMemoryStore, CERT_CLOSE_STORE_CHECK_FLAG))
        {
            // memory store could not be freed
            OpcUa_GotoErrorWithStatus(OpcUa_Bad);
        }
    }

    /*** CLOSE SYSTEM STORE ***/
    //// This has to move to CloseCertificateStore,
    //// but a parameter for PKIProvider has to be
    //// provided in the function declaration first!
    if(hSystemStore)
    {
        if (!CertCloseStore(hSystemStore, CERT_CLOSE_STORE_FORCE_FLAG))
        {
            // system store could not be freed
            OpcUa_GotoErrorWithStatus(OpcUa_Bad);
        }
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /*** FREE RESOURCES ***/
    if(pEvpKey)
    {
        EVP_PKEY_free(pEvpKey);
        pEvpKey = OpcUa_Null;
    }

    if(pRsaPrivateKey)
    {
        RSA_free(pRsaPrivateKey);
        pRsaPrivateKey = OpcUa_Null;
    }

    if(a_pPrivateKey)
    {
        OpcUa_P_ByteString_Clear(a_pPrivateKey);
        a_pPrivateKey = OpcUa_Null;
    }

    if(pBio)
    {
        BIO_free(pBio);
        pBio = OpcUa_Null;
    }

    if (pTempCertContext)
    {
        CertFreeCertificateContext(pTempCertContext);
        pTempCertContext = OpcUa_Null;
    }

    /*** Free CerificateContextHandles ***/
    if (pTargetCert)
    {
        CertFreeCertificateContext(pTargetCert);
        pTargetCert = OpcUa_Null;
    }

    /*** CLOSE MEMORY STORE ***/
    if(hMemoryStore)
    {
        if (!CertCloseStore(hMemoryStore, CERT_CLOSE_STORE_FORCE_FLAG))
        {
            // memory store could not be freed
            // trace??
        }
    }

    /*** CLOSE SYSTEM STORE ***/
    //// This has to move to CloseCertificateStore,
    //// but a parameter for PKIProvider has to be
    //// provided in the function declaration first!
    if(hSystemStore)
    {
        if (!CertCloseStore(hSystemStore, CERT_CLOSE_STORE_CHECK_FLAG))
        {
            // system store could not be freed
            // trace??
        }
    }

    if (pSubjectName != OpcUa_Null)
    {
        free(pSubjectName);
    }

OpcUa_FinishErrorHandling;
}

#endif /* OPCUA_SUPPORT_PKI_WIN32 */

#endif /* OPCUA_SUPPORT_PKI */
