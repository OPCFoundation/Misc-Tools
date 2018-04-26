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

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_ECDSA

/* System Headers */
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

/* own headers */
#include <opcua_p_openssl.h>

/*** ECDSA ASYMMETRIC SIGNATURE ***/

OpcUa_StatusCode OpcUa_P_OpenSSL_ECDSA_GenerateKeys(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_UInt32            a_bits,
    OpcUa_Key*              a_pPublicKey,
    OpcUa_Key*              a_pPrivateKey)
{
    EC_KEY*             pEcKey;
    EVP_PKEY*           pEvpKey;

    OpcUa_Byte*         pBuffer;

    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "ECDSA_GenerateKeys");

    OpcUa_ReturnErrorIfArgumentNull(a_pProvider);
    OpcUa_ReturnErrorIfArgumentNull(a_pPublicKey);
    OpcUa_ReturnErrorIfArgumentNull(a_pPrivateKey);

    OpcUa_ReferenceParameter(a_pProvider);

    /* Just 1024 or 2048 bytes should be allowed for compatibility reasons */
    if((a_bits != 1024)&&(a_bits != 2048))
    {
        uStatus = OpcUa_BadInvalidArgument;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    if(a_pPublicKey->Key.Data == OpcUa_Null)
    {
        a_pPublicKey->Key.Length = a_bits;
        OpcUa_ReturnStatusCode;
    }

    if(a_pPrivateKey->Key.Data == OpcUa_Null)
    {
        a_pPrivateKey->Key.Length = a_bits;
        OpcUa_ReturnStatusCode;
    }

    /*pEcKey = EC_KEY_new();*/
    pEcKey = EC_KEY_new_by_curve_name(NID_secp192k1);
    EC_KEY_generate_key(pEcKey);

    pEvpKey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(pEvpKey,pEcKey);

    pBuffer = a_pPublicKey->Key.Data;

    /* i2d_PublicKey does not work properly */
    /* publicKey.key.Length = i2d_PublicKey(pEvpKey, &pBuffer); */
    a_pPublicKey->Key.Length = i2d_PUBKEY(pEvpKey, &pBuffer);

    pBuffer = a_pPrivateKey->Key.Data;

    a_pPrivateKey->Key.Length = i2d_PrivateKey(pEvpKey, &pBuffer);

    a_pPublicKey->Type = OpcUa_Crypto_KeyType_Ecc_Public;
    a_pPrivateKey->Type = OpcUa_Crypto_KeyType_Ecc_Private;

    if(pEvpKey != OpcUa_Null)
    {
        EVP_PKEY_free(pEvpKey);
    }

    if(pEcKey != OpcUa_Null)
    {
        EC_KEY_free(pEcKey);
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_ECDSA_Private_Sign
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_ECDSA_Private_Sign(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_ByteString      a_data,
    OpcUa_Key*            a_privateKey,
    OpcUa_Int16           a_padding,       /* not used for ECDSA */
    OpcUa_ByteString*     a_pSignature)
{
    EVP_PKEY*        pPrivateKey;
    OpcUa_Int        ret;

    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "ECDSA_Private_Sign");

    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_padding);

    OpcUa_ReturnErrorIfArgumentNull(a_data.Data);
    OpcUa_ReturnErrorIfArgumentNull(a_privateKey);
    OpcUa_ReturnErrorIfArgumentNull(a_privateKey->Key.Data);

    if(a_privateKey->Type != OpcUa_Crypto_KeyType_Ecc_Private)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadInvalidArgument);
    }


    pPrivateKey = d2i_PrivateKey(EVP_PKEY_EC,OpcUa_Null,((const unsigned char**)&(a_privateKey->Key.Data)),a_privateKey->Key.Length);
    OpcUa_ReturnErrorIfArgumentNull(pPrivateKey);

    ret = ECDSA_sign((int)0, (const unsigned char*)a_data.Data,(int)a_data.Length, (unsigned char*)a_pSignature->Data, (unsigned int*)&(a_pSignature->Length), (EC_KEY*)pPrivateKey->pkey.ec);

    if(ret < 0)
        uStatus = OpcUa_Bad;

    pPrivateKey = OpcUa_Null;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    pPrivateKey = OpcUa_Null;

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_ECDSA_Public_Verify
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_ECDSA_Public_Verify(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_ByteString        a_data,
    OpcUa_Key*              a_publicKey,
    OpcUa_Int16             a_padding,   /* not used for ECDSA */
    OpcUa_ByteString        a_signature)
{
    EVP_PKEY*       pPublicKey;
    OpcUa_Int32     result      = -1;

    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "ECDSA_Private_Verify");

    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_padding);

    OpcUa_ReturnErrorIfArgumentNull(a_data.Data);
    OpcUa_ReturnErrorIfArgumentNull(a_publicKey);
    OpcUa_ReturnErrorIfArgumentNull(a_publicKey->Key.Data);

    if(a_publicKey->Type != OpcUa_Crypto_KeyType_Ecc_Public)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadInvalidArgument);
    }

    /* i2d_PublicKey does not work properly */
    /* pPublicKey = d2i_PublicKey(EVP_PKEY_EC,OpcUa_Null,((const unsigned char**)&(a_publicKey.key.Data)),a_publicKey.key.Length); */

    pPublicKey = d2i_PUBKEY(OpcUa_Null, ((const unsigned char**)&(a_publicKey->Key.Data)), a_publicKey->Key.Length);
    OpcUa_ReturnErrorIfArgumentNull(pPublicKey);

    result = ECDSA_verify(0,a_data.Data,a_data.Length,a_signature.Data, a_signature.Length, pPublicKey->pkey.ec);

    if(result == -1)
        uStatus = OpcUa_Bad;

OpcUa_ReturnStatusCode;

OpcUa_BeginErrorHandling;

    pPublicKey = OpcUa_Null;

OpcUa_FinishErrorHandling;
}

#else
  static int dummy = 0;
#endif /* OPENSSL_NO_ECDSA */

#endif /* OPCUA_REQUIRE_OPENSSL */
