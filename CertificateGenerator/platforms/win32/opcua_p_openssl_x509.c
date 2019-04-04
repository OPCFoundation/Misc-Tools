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
#include <opcua_p_datetime.h>
#include <opcua_p_memory.h>
#include <opcua_p_string.h>
#include <opcua_p_guid.h>

#if OPCUA_REQUIRE_OPENSSL

/* System Headers */
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>


/* own headers */
#include <opcua_p_openssl.h>

#define OpcUa_P_OpenSSL_X509_DAYS_TILL_EXPIRE 365
#define OpcUa_P_OpenSSL_X509_EXPIRE_SECS (60*60*24*OpcUa_P_OpenSSL_X509_DAYS_TILL_EXPIRE)

/**
  @brief Add a certificate name entry to a X.509 (X509) certificate.

  internal function!

  @param ppX509Name    [out]  The X509 Name Object.

  @param pNameEntry    [in]   The passed Name Entry Object.
*/
OpcUa_Int OpcUa_P_OpenSSL_X509_Name_AddEntry(
    X509_NAME               **ppX509Name,
    OpcUa_Crypto_NameEntry *pNameEntry);

/**
  @brief Add a certificate extension entry to a X.509 Version 3 (X509V3) certificate.

   internal function!

  @param ppCertificate    [out]  The certificate that gets the exxtension.

  @param pExtension       [in]   The Extension object.
  @param pX509V3Context   [in]   The passed X509V3 context.
*/
OpcUa_Int OpcUa_P_OpenSSL_X509_AddV3Extension(
    X509**                   ppCertificate,
    OpcUa_Crypto_Extension*  pExtension,
    X509V3_CTX*              pX509V3Context);

/*============================================================================
 * OpcUa_P_OpenSSL_X509_Name_AddEntry
 *===========================================================================*/
OpcUa_Int OpcUa_P_OpenSSL_X509_Name_AddEntry(
    X509_NAME**               a_ppX509Name,
    OpcUa_Crypto_NameEntry*   a_pNameEntry)
{
    X509_NAME_ENTRY*    pEntry  = OpcUa_Null;

    OpcUa_Int           nid;

    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "X509_Name_AddEntry");

    OpcUa_ReturnErrorIfArgumentNull(a_pNameEntry);

    if((nid = OBJ_txt2nid(a_pNameEntry->key)) == NID_undef)
    {
        uStatus =  OpcUa_BadNotSupported;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    if(!(pEntry = X509_NAME_ENTRY_create_by_NID(OpcUa_Null, nid, MBSTRING_ASC, (unsigned char*)a_pNameEntry->value, -1)))
    {
        uStatus =  OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    if(X509_NAME_add_entry(*a_ppX509Name, pEntry,-1,0) != 1)
        uStatus =  OpcUa_Bad;

    if(pEntry != OpcUa_Null)
    {
        X509_NAME_ENTRY_free(pEntry);
        pEntry = OpcUa_Null;
    }

OpcUa_ReturnStatusCode;

OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_X509_AddV3Extension
 *===========================================================================*/
OpcUa_Int OpcUa_P_OpenSSL_X509_AddV3Extension(
    X509**                   a_ppCertificate,
    OpcUa_Crypto_Extension*  a_pExtension,
    X509V3_CTX*              a_pX509V3Context)
{
    X509_EXTENSION*    pExtension   = OpcUa_Null;
    OpcUa_Byte*        pName        = OpcUa_Null;
    OpcUa_Byte*        pValue       = OpcUa_Null;

    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "X509_AddV3Extension");

    OpcUa_ReturnErrorIfArgumentNull(a_pX509V3Context);
    OpcUa_ReturnErrorIfArgumentNull(a_pExtension->key);
    OpcUa_ReturnErrorIfArgumentNull(a_pExtension->value);

    pName = (OpcUa_Byte*)a_pExtension->key;
    pValue = (OpcUa_Byte*)a_pExtension->value;

    if(!(pExtension = X509V3_EXT_conf(  OpcUa_Null,
                                        a_pX509V3Context,
                                        (char*)pName,
                                        (char*)pValue)))
    {
        uStatus =  OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    if(!X509_add_ext(*a_ppCertificate, pExtension, -1))
        uStatus =  OpcUa_Bad;

    if(pExtension != OpcUa_Null)
    {
        X509_EXTENSION_free(pExtension);
        pExtension = OpcUa_Null;
    }

OpcUa_ReturnStatusCode;

OpcUa_BeginErrorHandling;

    X509_EXTENSION_free(pExtension);
    pExtension = OpcUa_Null;

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_X509_AddCustomExtension
 *===========================================================================*/
OpcUa_Int OpcUa_P_OpenSSL_X509_AddCustomExtension(
    X509**                   a_ppCertificate,
    OpcUa_Crypto_Extension*  a_pExtension,
    X509V3_CTX*              a_pX509V3Context)
{
    X509_EXTENSION*     pExtension   = OpcUa_Null;
    OpcUa_SByte*        pName        = OpcUa_Null;
    OpcUa_SByte*        pValue       = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "X509_AddCustomExtension");

    OpcUa_ReturnErrorIfArgumentNull(a_pX509V3Context);
    OpcUa_ReturnErrorIfArgumentNull(a_pExtension->key);
    OpcUa_ReturnErrorIfArgumentNull(a_pExtension->value);

    pName = (OpcUa_SByte*)a_pExtension->key;
    pValue = (OpcUa_SByte*)a_pExtension->value;

    /* create the extension. */
    pExtension = X509V3_EXT_conf(  OpcUa_Null,
                                   a_pX509V3Context,
                                   (char*)pName,
                                   (char*)pValue);

    if (pExtension == OpcUa_Null)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_Bad);
    }

    /* add it to the certificate. */
    if (!X509_add_ext(*a_ppCertificate, pExtension, -1))
    {
        OpcUa_GotoErrorWithStatus(OpcUa_Bad);
    }

    /* free the extension. */
    X509_EXTENSION_free(pExtension);
    pExtension = OpcUa_Null;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(pExtension != OpcUa_Null)
    {
        X509_EXTENSION_free(pExtension);
        pExtension = OpcUa_Null;
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_X509_SelfSigned_Create
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_X509_SelfSigned_Create(
    OpcUa_CryptoProvider*       a_pProvider,
    const OpcUa_Int32           a_serialNumber,
    OpcUa_DateTime              a_validFrom,
    OpcUa_DateTime              a_validTo,
    OpcUa_Crypto_NameEntry*     a_pNameEntries,      /* will be used for issuer and subject thus it's selfigned cert */
    OpcUa_UInt                  a_nameEntriesCount,  /* will be used for issuer and subject thus it's selfigned cert */
    OpcUa_Key                   a_pSubjectPublicKey, /* EVP_PKEY* - type defines also public key algorithm */
    OpcUa_Crypto_Extension*     a_pExtensions,
    OpcUa_UInt                  a_extensionsCount,
    const OpcUa_UInt            a_signatureHashAlgorithm, /* EVP_sha1(),... */
    OpcUa_Certificate*          a_pIssuerCertificate,
    OpcUa_Key                   a_pIssuerPrivateKey, /* EVP_PKEY* - type defines also signature algorithm */
    OpcUa_Certificate**         a_ppCertificate)
{
    OpcUa_UInt          i;
    OpcUa_UInt32        validFromInSec      = 0;
    OpcUa_UInt32        validToInSec        = 0;
    OpcUa_DateTime      now;

    X509_NAME*          pSubj               = OpcUa_Null;
    X509V3_CTX          ctx;
    const EVP_MD*       pDigest             = OpcUa_Null;

    EVP_PKEY*           pSubjectPublicKey   = OpcUa_Null;
    EVP_PKEY*           pIssuerPrivateKey   = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "X509_SelfSigned_Create");

    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_pIssuerCertificate);

    OpcUa_ReturnErrorIfArgumentNull(a_pNameEntries);
    OpcUa_ReturnErrorIfArgumentNull(a_pExtensions);
    OpcUa_ReturnErrorIfArgumentNull(a_pIssuerPrivateKey.Key.Data);

    if(a_pSubjectPublicKey.Type != a_pIssuerPrivateKey.Type)
    {
        uStatus =  OpcUa_BadInvalidArgument;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    switch(a_pSubjectPublicKey.Type)
    {
    case OpcUa_Crypto_Rsa_Alg_Id:
        pSubjectPublicKey = d2i_PublicKey(EVP_PKEY_RSA,OpcUa_Null,((const unsigned char**)&(a_pSubjectPublicKey.Key.Data)),a_pSubjectPublicKey.Key.Length);
        pIssuerPrivateKey = d2i_PrivateKey(EVP_PKEY_RSA,OpcUa_Null,((const unsigned char**)&(a_pIssuerPrivateKey.Key.Data)),a_pIssuerPrivateKey.Key.Length);
        break;
    case OpcUa_Crypto_Ecc_Alg_Id:
        pSubjectPublicKey = d2i_PublicKey(EVP_PKEY_EC,OpcUa_Null,((const unsigned char**)&(a_pSubjectPublicKey.Key.Data)),a_pSubjectPublicKey.Key.Length);
        pIssuerPrivateKey = d2i_PrivateKey(EVP_PKEY_EC,OpcUa_Null,((const unsigned char**)&(a_pIssuerPrivateKey.Key.Data)),a_pIssuerPrivateKey.Key.Length);
        break;
    default:
        return OpcUa_BadInvalidArgument;
    }

    /* create new certificate object */
    if(!(*((X509**)a_ppCertificate) = X509_new()))
    {
        uStatus =  OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    /* set version of certificate (V3 since internal representation starts versioning from 0) */
    if(X509_set_version(*((X509**)a_ppCertificate), 2L) != 1)
    {
        uStatus =  OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    /* generate a unique number for a serial number if none provided. */
    if (a_serialNumber == 0)
    {
        ASN1_INTEGER* pSerialNumber = X509_get_serialNumber(*((X509**)a_ppCertificate));

        pSerialNumber->type   = V_ASN1_INTEGER;
        pSerialNumber->data   = OPENSSL_realloc(pSerialNumber->data, 16);
        pSerialNumber->length = 16;

        OpcUa_P_Guid_Create((OpcUa_Guid*)pSerialNumber->data);
    }

    /* use the integer passed in - note the API should not be using a 32-bit integer - must fix sometime */
    else if(ASN1_INTEGER_set(X509_get_serialNumber(*((X509**)a_ppCertificate)),a_serialNumber)==0)
    {
        uStatus =  OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    /* add key to the request */
    if(X509_set_pubkey(*((X509**)a_ppCertificate),pSubjectPublicKey) != 1)
    {
        uStatus =  OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    if(pSubjectPublicKey != OpcUa_Null)
    {
        EVP_PKEY_free(pSubjectPublicKey);
        pSubjectPublicKey = OpcUa_Null;
    }

    /* assign the subject name */
    if(!(pSubj = X509_NAME_new()))
    {
        uStatus =  OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    /* create and add entries to subject name */
    for(i=0; i<a_nameEntriesCount; i++)
    {
        if(OpcUa_P_OpenSSL_X509_Name_AddEntry(&pSubj, a_pNameEntries + i) <0)
        {
            uStatus =  OpcUa_Bad;
            OpcUa_GotoErrorIfBad(uStatus);
        }
    }

    /* set subject name in request */
    if(X509_set_subject_name(*((X509**)a_ppCertificate), pSubj) != 1)
    {
        uStatus =  OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    /* set name of issuer (CA) */
    if(X509_set_issuer_name(*((X509**)a_ppCertificate), pSubj) != 1)
    {
        uStatus =  OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    now = OpcUa_P_DateTime_UtcNow();


    uStatus = OpcUa_P_GetDateTimeDiffInSeconds32(now, a_validFrom, &validFromInSec);
    OpcUa_GotoErrorIfBad(uStatus);

    if(!(X509_gmtime_adj(X509_get_notBefore(*((X509**)a_ppCertificate)), validFromInSec)))
    {
        uStatus =  OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    uStatus = OpcUa_P_GetDateTimeDiffInSeconds32(now, a_validTo, &validToInSec);
    OpcUa_GotoErrorIfBad(uStatus);

    /* set ending time of the certificate*/
    if(!(X509_gmtime_adj(X509_get_notAfter(*((X509**)a_ppCertificate)), validToInSec/*OpcUa_P_OpenSSL_X509_EXPIRE_SECS*/)))
    {
        uStatus =  OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    /* add x509v3 extensions */
    X509V3_set_ctx( &ctx,
                    (X509*)*a_ppCertificate,
                    *((X509**)a_ppCertificate),
                    OpcUa_Null,
                    OpcUa_Null,
                    0);

    for(i=0; i<a_extensionsCount; i++)
    {
        if(OpcUa_P_OpenSSL_X509_AddV3Extension((X509**)a_ppCertificate, a_pExtensions+i, &ctx) <0)
        {
            uStatus =  OpcUa_Bad;
            OpcUa_GotoErrorIfBad(uStatus);
        }
    }

    /* sign certificate with the CA private key */
    switch(a_signatureHashAlgorithm)
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
        uStatus =  OpcUa_BadNotSupported;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    if(!(X509_sign(*((X509**)a_ppCertificate), pIssuerPrivateKey, pDigest)))
    {
        uStatus =  OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    if(pIssuerPrivateKey != OpcUa_Null)
    {
        EVP_PKEY_free(pIssuerPrivateKey);
        pIssuerPrivateKey = OpcUa_Null;
    }

    if(pSubj != OpcUa_Null)
    {
        X509_NAME_free(pSubj);
        pSubj = OpcUa_Null;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_P_Memory_Free(*a_ppCertificate);
    *a_ppCertificate = OpcUa_Null;

    if(pSubjectPublicKey != OpcUa_Null)
    {
        EVP_PKEY_free(pSubjectPublicKey);
        pSubjectPublicKey = OpcUa_Null;
    }

    if(pIssuerPrivateKey != OpcUa_Null)
    {
        EVP_PKEY_free(pIssuerPrivateKey);
        pIssuerPrivateKey = OpcUa_Null;
    }

    if(pSubj != OpcUa_Null)
    {
        X509_NAME_free(pSubj);
        pSubj = OpcUa_Null;
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_X509_SelfSigned_Custom_Create
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_X509_SelfSigned_Custom_Create(
    OpcUa_CryptoProvider*       a_pProvider,
    const OpcUa_Int32           a_serialNumber,
    OpcUa_DateTime              a_validFrom,
    OpcUa_DateTime              a_validTo,
    OpcUa_Crypto_NameEntry*     a_pNameEntries,      /* will be used for issuer and subject thus it's selfigned cert */
    OpcUa_UInt                  a_nameEntriesCount,  /* will be used for issuer and subject thus it's selfigned cert */
    OpcUa_Key                   a_pSubjectPublicKey, /* EVP_PKEY* - type defines also public key algorithm */
    OpcUa_Crypto_Extension*     a_pExtensions,
    OpcUa_UInt                  a_extensionsCount,
    const OpcUa_UInt            a_signatureHashAlgorithm, /* EVP_sha1(),... */
    OpcUa_Certificate*          a_pIssuerCertificate,
    OpcUa_Key                   a_pIssuerPrivateKey, /* EVP_PKEY* - type defines also signature algorithm */
    OpcUa_Certificate**         a_ppCertificate)
{
    OpcUa_UInt          i;
    OpcUa_Int32         validFromInSec      = 0;
    OpcUa_Int32         validToInSec        = 0;
    OpcUa_DateTime      now;

    X509_NAME*          pSubj               = OpcUa_Null;
    X509V3_CTX          ctx;
    const EVP_MD*       pDigest             = OpcUa_Null;

    EVP_PKEY*           pSubjectPublicKey   = OpcUa_Null;
    EVP_PKEY*           pIssuerPrivateKey   = OpcUa_Null;

    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "X509_SelfSigned_Custom_Create");

    OpcUa_ReferenceParameter(a_pProvider);

    OpcUa_ReturnErrorIfArgumentNull(a_pNameEntries);
    OpcUa_ReturnErrorIfArgumentNull(a_pExtensions);
    OpcUa_ReturnErrorIfArgumentNull(a_pIssuerPrivateKey.Key.Data);

    switch(a_pSubjectPublicKey.Type)
    {
    case OpcUa_Crypto_Rsa_Alg_Id:
    case OpcUa_Crypto_Rsa_OAEP_Id:
        pSubjectPublicKey = d2i_PublicKey(EVP_PKEY_RSA,OpcUa_Null,((const unsigned char**)&(a_pSubjectPublicKey.Key.Data)),a_pSubjectPublicKey.Key.Length);
		OpcUa_GotoErrorIfNull(pSubjectPublicKey, OpcUa_BadInvalidArgument);
        break;
    case OpcUa_Crypto_Ecc_Alg_Id:
	case OpcUa_Crypto_KeyType_Ecc_Public:
	case OpcUa_Crypto_Ec_nistP256:
	case OpcUa_Crypto_Ec_nistP384:
	case OpcUa_Crypto_Ec_brainpoolP256r1:
	case OpcUa_Crypto_Ec_brainpoolP384r1:
  case OpcUa_Crypto_Ec_curve25519:
  case OpcUa_Crypto_KeyType_Ed25519_Public:
  case OpcUa_Crypto_Ec_curve448:
  case OpcUa_Crypto_KeyType_Ed448_Public:
    pSubjectPublicKey = d2i_PUBKEY(OpcUa_Null, ((const unsigned char**)&(a_pSubjectPublicKey.Key.Data)), a_pSubjectPublicKey.Key.Length);
		OpcUa_GotoErrorIfNull(pSubjectPublicKey, OpcUa_BadInvalidArgument);
        break;
    default:
        return OpcUa_BadInvalidArgument;
    }

    switch(a_pIssuerPrivateKey.Type)
    {
    case OpcUa_Crypto_Rsa_Alg_Id:
    case OpcUa_Crypto_Rsa_OAEP_Id:
        pIssuerPrivateKey = d2i_PrivateKey(EVP_PKEY_RSA,OpcUa_Null,((const unsigned char**)&(a_pIssuerPrivateKey.Key.Data)),a_pIssuerPrivateKey.Key.Length);
		OpcUa_GotoErrorIfNull(pIssuerPrivateKey, OpcUa_BadInvalidArgument);
        break;
    case OpcUa_Crypto_Ecc_Alg_Id:
	case OpcUa_Crypto_KeyType_Ecc_Private:
        pIssuerPrivateKey = d2i_PrivateKey(EVP_PKEY_EC,OpcUa_Null,((const unsigned char**)&(a_pIssuerPrivateKey.Key.Data)),a_pIssuerPrivateKey.Key.Length);
		OpcUa_GotoErrorIfNull(pIssuerPrivateKey, OpcUa_BadInvalidArgument);
        break;
  case OpcUa_Crypto_Ec_curve25519:
  case OpcUa_Crypto_KeyType_Ed25519_Private:
    pIssuerPrivateKey = d2i_PrivateKey(EVP_PKEY_ED25519, OpcUa_Null, ((const unsigned char**)&(a_pIssuerPrivateKey.Key.Data)), a_pIssuerPrivateKey.Key.Length);
    OpcUa_GotoErrorIfNull(pIssuerPrivateKey, OpcUa_BadInvalidArgument);
    break;
  case OpcUa_Crypto_Ec_curve448:
  case OpcUa_Crypto_KeyType_Ed448_Private:
    pIssuerPrivateKey = d2i_PrivateKey(EVP_PKEY_ED448, OpcUa_Null, ((const unsigned char**)&(a_pIssuerPrivateKey.Key.Data)), a_pIssuerPrivateKey.Key.Length);
    OpcUa_GotoErrorIfNull(pIssuerPrivateKey, OpcUa_BadInvalidArgument);
    break;
  default:
        return OpcUa_BadInvalidArgument;
    }

    /* create new certificate object */
    if(!(*((X509**)a_ppCertificate) = X509_new()))
    {
        uStatus =  OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

	/* set the certificate as the issuer if creating a self-signed certificate. */
	if (a_pIssuerCertificate == OpcUa_Null)
	{
		a_pIssuerCertificate = *a_ppCertificate;
	}

    /* set version of certificate (V3 since internal representation starts versioning from 0) */
    if(X509_set_version(*((X509**)a_ppCertificate), 2L) != 1)
    {
        uStatus =  OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    /* generate a unique number for a serial number if none provided. */
    if (a_serialNumber == 0)
    {
        ASN1_INTEGER* pSerialNumber = X509_get_serialNumber(*((X509**)a_ppCertificate));

        pSerialNumber->type   = V_ASN1_INTEGER;
        pSerialNumber->data   = OPENSSL_realloc(pSerialNumber->data, 16);
        pSerialNumber->length = 16;

        OpcUa_P_Guid_Create((OpcUa_Guid*)pSerialNumber->data);
    }

    /* use the integer passed in - note the API should not be using a 32-bit integer - must fix sometime */
    else if (ASN1_INTEGER_set(X509_get_serialNumber(*((X509**)a_ppCertificate)), a_serialNumber) == 0)
    {
        uStatus =  OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    /* add key to the request */
    if(X509_set_pubkey(*((X509**)a_ppCertificate),pSubjectPublicKey) != 1)
    {
        uStatus =  OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    if(pSubjectPublicKey != OpcUa_Null)
    {
        EVP_PKEY_free(pSubjectPublicKey);
        pSubjectPublicKey = OpcUa_Null;
    }

    /* assign the subject name */
    if(!(pSubj = X509_NAME_new()))
    {
        uStatus =  OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    /* create and add entries to subject name */
    for(i=0; i<a_nameEntriesCount; i++)
    {
        if(OpcUa_P_OpenSSL_X509_Name_AddEntry(&pSubj, a_pNameEntries + i) <0)
        {
            uStatus =  OpcUa_Bad;
            OpcUa_GotoErrorIfBad(uStatus);
        }
    }

    /* set subject name in request */
    if(X509_set_subject_name(*((X509**)a_ppCertificate), pSubj) != 1)
    {
        uStatus =  OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    /* set name of issuer (CA) */
	if(X509_set_issuer_name(*((X509**)a_ppCertificate), X509_get_subject_name((X509*)a_pIssuerCertificate)) != 1)
    {
        uStatus =  OpcUa_Bad;
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
    if(!(X509_gmtime_adj(X509_get_notBefore(*((X509**)a_ppCertificate)), validFromInSec)))
    {
        uStatus =  OpcUa_Bad;
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
    if(!(X509_gmtime_adj(X509_get_notAfter(*((X509**)a_ppCertificate)), validToInSec)))
    {
        uStatus =  OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    /* add x509v3 extensions */
    X509V3_set_ctx( &ctx,
					(X509*)a_pIssuerCertificate,
                    *((X509**)a_ppCertificate),
                    OpcUa_Null,
                    OpcUa_Null,
                    0);

    for(i=0; i<a_extensionsCount; i++)
    {
        if(OpcUa_P_OpenSSL_X509_AddCustomExtension((X509**)a_ppCertificate, a_pExtensions+i, &ctx) <0)
        {
            uStatus =  OpcUa_Bad;
            OpcUa_GotoErrorIfBad(uStatus);
        }
    }

    /* sign certificate with the CA private key */
    if (
      (OpcUa_Crypto_KeyType_Ed25519_Private != a_pIssuerPrivateKey.Type)
      &&
      (OpcUa_Crypto_KeyType_Ed448_Private != a_pIssuerPrivateKey.Type)
      )
    {
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
    }
    
    if(!(X509_sign(*((X509**)a_ppCertificate), pIssuerPrivateKey, pDigest)))
    {
        uStatus =  OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

	if (X509_verify(*((X509**)a_ppCertificate), pIssuerPrivateKey) <= 0)
	{
        uStatus =  OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
	}

    if(pIssuerPrivateKey != OpcUa_Null)
    {
        EVP_PKEY_free(pIssuerPrivateKey);
        pIssuerPrivateKey = OpcUa_Null;
    }

    if(pSubj != OpcUa_Null)
    {
        X509_NAME_free(pSubj);
        pSubj = OpcUa_Null;
    }

OpcUa_ReturnStatusCode;

OpcUa_BeginErrorHandling;

    OpcUa_P_Memory_Free(*a_ppCertificate);
    *a_ppCertificate = OpcUa_Null;

    if(pSubjectPublicKey != OpcUa_Null)
    {
        EVP_PKEY_free(pSubjectPublicKey);
        pSubjectPublicKey = OpcUa_Null;
    }

    if(pIssuerPrivateKey != OpcUa_Null)
    {
        EVP_PKEY_free(pIssuerPrivateKey);
        pIssuerPrivateKey = OpcUa_Null;
    }

    if(pSubj != OpcUa_Null)
    {
        X509_NAME_free(pSubj);
        pSubj = OpcUa_Null;
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_X509_SaveToFile
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_X509_SaveToFile(
    OpcUa_CryptoProvider*       a_pProvider,
    OpcUa_StringA               a_fileName,
    OpcUa_Certificate           a_certificate)
{
    BIO*         pCertFile  = OpcUa_Null;

    OpcUa_Int    i          = 0;

    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "X509_Save");

    OpcUa_ReferenceParameter(a_pProvider);

    OpcUa_ReturnErrorIfArgumentNull(a_certificate);

    if(OpcUa_P_String_strlen(a_fileName) < 1)
    {
        uStatus = OpcUa_BadInvalidArgument;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    pCertFile = BIO_new_file(a_fileName, "w");

    i = i2d_X509_bio(pCertFile, ((X509*)&a_certificate));

    if(i < 1)
    {
        uStatus =  OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    if(BIO_free (pCertFile) == 0)
    {
        uStatus =  OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

OpcUa_ReturnStatusCode;

OpcUa_BeginErrorHandling;

    if(pCertFile)
        if(BIO_free(pCertFile) == 0)
            return OpcUa_Bad;

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_X509_LoadFromFile
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_X509_LoadFromFile(
    OpcUa_StringA               a_fileName,
    OpcUa_P_FileFormat          a_fileFormat,
    OpcUa_StringA               a_sPassword,        /* optional: just for OpcUa_PKCS12 */
    OpcUa_ByteString*           a_pCertificate)
{
    BIO*            pCertFile       = OpcUa_Null;
    X509*           pCertX509       = OpcUa_Null;
    PKCS12*         pPKCS12Cert     = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "X509_LoadFromFile");

    /* check filename */
    if(OpcUa_P_String_strlen(a_fileName) < 1)
    {
        uStatus = OpcUa_BadInvalidArgument;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    /* import certificate from file by the given encoding type */
    pCertFile = BIO_new_file((const char*)a_fileName, "r");
    OpcUa_ReturnErrorIfArgumentNull(pCertFile);

    switch(a_fileFormat)
    {
    case OpcUa_Crypto_Encoding_DER:
        {

            pCertX509 = d2i_X509_bio(pCertFile,      /* sourcefile */
                                     (X509**)NULL);  /* target (if preallocated) */
            break;
        }
    case OpcUa_Crypto_Encoding_PEM:
        {

            pCertX509 = PEM_read_bio_X509(  pCertFile,          /* sourcefile */
                                            (X509**)OpcUa_Null, /* target (if preallocated) */
                                            OpcUa_Null,         /* password callback function */
                                            OpcUa_Null);        /* passphrase or callback data */
            break;
        }
    case OpcUa_Crypto_Encoding_PKCS12:
        {
            d2i_PKCS12_bio(pCertFile, &pPKCS12Cert);

            PKCS12_parse(pPKCS12Cert, a_sPassword, OpcUa_Null, &pCertX509, OpcUa_Null);

            if(pPKCS12Cert != OpcUa_Null)
            {
                PKCS12_free(pPKCS12Cert);
                /*OPENSSL_free(pPKCS12Cert);*/
            }

            break;
        }
    default:
        {
            BIO_free(pCertFile);
            return OpcUa_BadNotSupported;
        }
    }

    BIO_free(pCertFile);

    if(pCertX509 == OpcUa_Null)
    {
        /* error in OpenSSL - maybe certificate file was corrupt */
        return OpcUa_Bad;
    }

    /* prepare container */
    memset(a_pCertificate, 0, sizeof(OpcUa_ByteString));

    /* get required length for conversion target buffer */
    a_pCertificate->Length = i2d_X509(  pCertX509,
                                            NULL);

    if(a_pCertificate->Length <= 0)
    {
        /* conversion to DER not possible */
        uStatus = OpcUa_Bad;
    }

    /* allocate conversion target buffer */
    a_pCertificate->Data = (OpcUa_Byte*)OpcUa_P_Memory_Alloc(a_pCertificate->Length);
    OpcUa_GotoErrorIfAllocFailed(a_pCertificate->Data);

    /* convert into DER */
    a_pCertificate->Length = i2d_X509(  pCertX509,
                                            &(a_pCertificate->Data));
    if(a_pCertificate->Length <= 0)
    {
        /* conversion to DER not possible */
        uStatus = OpcUa_Bad;
    }
    else
    {
        /* correct pointer incrementation by i2d_X509() */
        a_pCertificate->Data -= a_pCertificate->Length;
    }

    X509_free(pCertX509);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(pCertX509 != OpcUa_Null)
    {
        X509_free(pCertX509);
    }

    if(pPKCS12Cert != OpcUa_Null)
    {
        OPENSSL_free(pPKCS12Cert);
    }

    if(a_pCertificate->Data != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(a_pCertificate->Data);
        a_pCertificate->Data = OpcUa_Null;
    }

    if(pCertFile != OpcUa_Null)
    {
        BIO_free(pCertFile);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_X509_GetPublicKey
 *===========================================================================*/
/*
NOTE:
i2d_PublicKey does not work properly with EC Key structures.
i2d_PUBKEY works but is not consistent.
*/
OpcUa_StatusCode OpcUa_P_OpenSSL_X509_GetPublicKey(
    OpcUa_CryptoProvider*       a_pProvider,
    OpcUa_ByteString*           a_pCertificate,
    OpcUa_StringA               a_password,             /* this could be optional */
    OpcUa_Key*                  a_pPublicKey)
{
    EVP_PKEY*           pPublicKey      = OpcUa_Null;
    RSA*                pRsaPublicKey   = OpcUa_Null;
    X509*               pCertificate    = OpcUa_Null;
    OpcUa_Byte*         pBuffer         = OpcUa_Null;
    OpcUa_ByteString*   pRawCertificate = OpcUa_Null;

    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "X509_GetPublicKey");

    OpcUa_ReferenceParameter(a_password);

    OpcUa_ReturnErrorIfArgumentNull(a_pProvider);
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate->Data);
    OpcUa_ReturnErrorIfArgumentNull(a_pPublicKey);

    /* copy certificate, since data will be changed */
    pRawCertificate = (OpcUa_ByteString*)OpcUa_P_Memory_Alloc(sizeof(OpcUa_ByteString));
    pRawCertificate->Length = a_pCertificate->Length;
    pRawCertificate->Data   = (OpcUa_Byte*)OpcUa_P_Memory_Alloc(pRawCertificate->Length*sizeof(OpcUa_Byte));
    OpcUa_P_Memory_MemCpy(pRawCertificate->Data, a_pCertificate->Length, a_pCertificate->Data, a_pCertificate->Length);

    /* copy pointer, since it will be changed by d2i_X509 */
    pBuffer = pRawCertificate->Data;

    /* convert bytestring certificate to X509 certificate */
    d2i_X509(&pCertificate, (const unsigned char**)&pBuffer, pRawCertificate->Length);
    pBuffer = OpcUa_Null;

    /* free certificate */
    if(pRawCertificate->Data)
    {
        OpcUa_P_Memory_Free(pRawCertificate->Data);
        pRawCertificate->Data = OpcUa_Null;
    }

    if(pRawCertificate)
    {
        OpcUa_P_Memory_Free(pRawCertificate);
        pRawCertificate = OpcUa_Null;
    }

    OpcUa_ReturnErrorIfArgumentNull(pCertificate);

    /* get EVP_PKEY from X509 certificate */
    pPublicKey = X509_get_pubkey(pCertificate);

    /* free X509 certificate, since not needed anymore */
    X509_free(pCertificate);

    switch(EVP_PKEY_base_id(pPublicKey))
    {
    case EVP_PKEY_RSA:

        /* allocate memory for RSA key */

        /* get RSA public key from EVP_PKEY */
        pRsaPublicKey = EVP_PKEY_get1_RSA(pPublicKey);

        /* allocate memory for DER encoded bytestring */
        a_pPublicKey->Key.Length = i2d_RSAPublicKey(pRsaPublicKey, OpcUa_Null);

        if(a_pPublicKey->Key.Data == OpcUa_Null)
        {
            RSA_free(pRsaPublicKey);
            pRsaPublicKey = OpcUa_Null;

            EVP_PKEY_free(pPublicKey);
            pPublicKey = OpcUa_Null;

            OpcUa_ReturnStatusCode;
        }

        /* convert RSA key to DER encoded bytestring */
        pBuffer = a_pPublicKey->Key.Data;
        a_pPublicKey->Key.Length = i2d_RSAPublicKey(pRsaPublicKey, &pBuffer);
        a_pPublicKey->Type = OpcUa_Crypto_Rsa_Alg_Id;

        /* free memory for RSA key */
        RSA_free(pRsaPublicKey);
        pRsaPublicKey = OpcUa_Null;

        break;

    case EVP_PKEY_EC:
        /*
         * EC doesn't offer a function for converting a EC public key into a DER encoded
         * format (Only plain octet strings). Therefore the abstract EVP_PKEY is used for
         * conversion.
         */
        a_pPublicKey->Key.Length = i2d_PublicKey(pPublicKey, OpcUa_Null);

        if(a_pPublicKey->Key.Data == OpcUa_Null)
        {
            EVP_PKEY_free(pPublicKey);
            pPublicKey = OpcUa_Null;

            OpcUa_ReturnStatusCode;
        }

        /* convert EC key to DER encoded bytestring */
        pBuffer = a_pPublicKey->Key.Data;
        a_pPublicKey->Key.Length = i2d_PublicKey(pPublicKey, &pBuffer);
        a_pPublicKey->Type = OpcUa_Crypto_Ecc_Alg_Id;

        break;

    case EVP_PKEY_DSA:
        uStatus =  OpcUa_BadNotSupported;
        OpcUa_GotoErrorIfBad(uStatus);

    case EVP_PKEY_DH:
        uStatus =  OpcUa_BadNotSupported;
        OpcUa_GotoErrorIfBad(uStatus);

    default:
        uStatus =  OpcUa_BadNotSupported;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    /*** clean up ***/
    EVP_PKEY_free(pPublicKey);
    pPublicKey = OpcUa_Null;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;


    EVP_PKEY_free(pPublicKey);
    pPublicKey = OpcUa_Null;

    if(pRawCertificate->Data)
    {
        OpcUa_P_Memory_Free(pRawCertificate->Data);
        pRawCertificate->Data = OpcUa_Null;
    }

    if(pRawCertificate)
    {
        OpcUa_P_Memory_Free(pRawCertificate);
        pRawCertificate = OpcUa_Null;
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_X509_GetPrivateKey
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_X509_GetPrivateKey(
    OpcUa_CryptoProvider*       a_pProvider,
    OpcUa_StringA               a_certificateFileName,
    OpcUa_StringA               a_password,             /* this is optional */
    OpcUa_Key*                  a_pPrivateKey)
{
    BIO*            pCertFile       = OpcUa_Null;
    PKCS12*         pPKCS12Cert     = OpcUa_Null;
    EVP_PKEY*       pPrivateKey     = OpcUa_Null;
    RSA*            pRsaPrivateKey  = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "X509_GetPrivateKey");

    OpcUa_ReferenceParameter(a_pProvider);

    OpcUa_ReturnErrorIfArgumentNull(a_pProvider);
    OpcUa_ReturnErrorIfArgumentNull(a_certificateFileName);
    OpcUa_ReturnErrorIfArgumentNull(a_pPrivateKey);

    /* import certificate from file by the given encoding type */
    pCertFile = BIO_new_file((const char*)a_certificateFileName, "r");
    OpcUa_ReturnErrorIfArgumentNull(pCertFile);

    /* convert certificate file handle to PKCS12 structure */
    d2i_PKCS12_bio(pCertFile, &pPKCS12Cert);

    /* close certificat file handle */
    BIO_free(pCertFile);

    if(pPKCS12Cert != OpcUa_Null)
    {
        /* get the private key from the PKCS12 structure*/
        PKCS12_parse(pPKCS12Cert, a_password, &pPrivateKey, OpcUa_Null, OpcUa_Null);
    }
    else
    {
        uStatus = OpcUa_Bad;
        OpcUa_ReturnStatusCode;
    }

    if(pPKCS12Cert != OpcUa_Null)
    {
        PKCS12_free(pPKCS12Cert);
        pPKCS12Cert = OpcUa_Null;
    }

    switch(EVP_PKEY_base_id(pPrivateKey))
    {
    case EVP_PKEY_RSA:
        {
            /* convert to intermediary openssl struct */
            pRsaPrivateKey = EVP_PKEY_get1_RSA(pPrivateKey);
            EVP_PKEY_free(pPrivateKey);
            OpcUa_GotoErrorIfNull(pRsaPrivateKey, OpcUa_Bad);

            /* get required length */
            a_pPrivateKey->Key.Length = i2d_RSAPrivateKey(pRsaPrivateKey, OpcUa_Null);
            OpcUa_GotoErrorIfTrue(a_pPrivateKey->Key.Length <= 0, OpcUa_Bad);

            if(a_pPrivateKey->Key.Data == OpcUa_Null)
            {
                OpcUa_ReturnStatusCode;
            }

            /* do real conversion */
            a_pPrivateKey->Key.Length = i2d_RSAPrivateKey(  pRsaPrivateKey,
                                                            &a_pPrivateKey->Key.Data);
            OpcUa_GotoErrorIfTrue(a_pPrivateKey->Key.Length <= 0, OpcUa_Bad);

            if(pRsaPrivateKey != OpcUa_Null)
            {
                RSA_free(pRsaPrivateKey);
                pRsaPrivateKey = OpcUa_Null;
            }

            /* correct buffer pointer */
            a_pPrivateKey->Key.Data -= a_pPrivateKey->Key.Length;

            a_pPrivateKey->Type = OpcUa_Crypto_KeyType_Rsa_Private;

            break;
        }
    case EVP_PKEY_EC:
    case EVP_PKEY_DSA:
    case EVP_PKEY_DH:
    default:
        {
            uStatus =  OpcUa_BadNotSupported;
            OpcUa_GotoErrorIfBad(uStatus);
        }
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(pPKCS12Cert != OpcUa_Null)
    {
        PKCS12_free(pPKCS12Cert);
        pPKCS12Cert = OpcUa_Null;
    }

    if(pRsaPrivateKey != OpcUa_Null)
    {
        RSA_free(pRsaPrivateKey);
    }

    if(pPrivateKey != OpcUa_Null)
    {
        EVP_PKEY_free(pPrivateKey);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_X509_GetSignature
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_X509_GetSignature(
    OpcUa_CryptoProvider*       a_pProvider,
    OpcUa_ByteString*           a_pCertificate,
    OpcUa_Signature*            a_pSignature)
{
    X509* pX509Certificate = OpcUa_Null;

    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "X509_GetSignature");

    OpcUa_ReferenceParameter(a_pProvider);

    OpcUa_ReturnErrorIfArgumentNull(a_pProvider);
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
    OpcUa_ReturnErrorIfArgumentNull(a_pSignature);

    d2i_X509(&pX509Certificate, (const unsigned char**)&a_pCertificate->Data, a_pCertificate->Length);

    if(pX509Certificate == OpcUa_Null)
    {
        uStatus = OpcUa_Bad;
        OpcUa_GotoError;
    }

    a_pCertificate->Data -= a_pCertificate->Length;

    ASN1_BIT_STRING *sig = OpcUa_Null;
    X509_ALGOR *alg = OpcUa_Null;

    X509_get0_signature(&sig, &alg, pX509Certificate);

    OpcUa_ReturnErrorIfArgumentNull(sig);
    OpcUa_ReturnErrorIfArgumentNull(alg);

    a_pSignature->Signature.Length = sig->length;

    if(a_pSignature->Signature.Data == OpcUa_Null)
    {
        OpcUa_ReturnStatusCode;
    }

    OpcUa_P_Memory_MemCpy(  a_pSignature->Signature.Data,
      sig->length,
      sig->data,
      sig->length);

    if(a_pSignature->Signature.Data == OpcUa_Null)
    {
        uStatus = OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    a_pSignature->Algorithm = OBJ_obj2nid(alg->algorithm);

    if(a_pSignature->Algorithm == NID_undef)
    {
        uStatus = OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    if(pX509Certificate != OpcUa_Null)
    {
        X509_free(pX509Certificate);
        pX509Certificate = OpcUa_Null;
    }

OpcUa_ReturnStatusCode;

OpcUa_BeginErrorHandling;

    if(pX509Certificate != OpcUa_Null)
    {
        X509_free(pX509Certificate);
        pX509Certificate = OpcUa_Null;
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_X509_GetCertificateThumbprint
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_X509_GetCertificateThumbprint(
    OpcUa_CryptoProvider*       a_pProvider,
    OpcUa_ByteString*           a_pCertificate,
    OpcUa_ByteString*           a_pCertificateThumbprint)
{
    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "X509_GetCertificateThumbprint");

    OpcUa_ReturnErrorIfArgumentNull(a_pProvider);
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificate);
    OpcUa_ReturnErrorIfArgumentNull(a_pCertificateThumbprint);

    /* SHA-1 produces 20 bytes */
    a_pCertificateThumbprint->Length = 20;

    if(a_pCertificateThumbprint->Data == OpcUa_Null)
    {
        OpcUa_ReturnStatusCode;
    }

    uStatus = OpcUa_P_OpenSSL_SHA1_Generate(a_pProvider, a_pCertificate->Data, a_pCertificate->Length, a_pCertificateThumbprint->Data);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

#endif /* OPCUA_REQUIRE_OPENSSL */
