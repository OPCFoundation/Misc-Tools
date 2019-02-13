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
#ifndef OPENSSL_NO_ED448

/* System Headers */
#include <openssl/evp.h>
#include <openssl/x509.h>

/* own headers */
#include <opcua_p_openssl.h>

/*** Ed448 ASYMMETRIC SIGNATURE ***/

OpcUa_StatusCode OpcUa_P_OpenSSL_Ed448_GenerateKeys(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_Key*              a_pPublicKey,
    OpcUa_Key*              a_pPrivateKey)
{
    EVP_PKEY*           pEvpKey;
    EVP_PKEY_CTX*       pctx;
    OpcUa_Byte*         pBuffer;

    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "Ed448_GenerateKeys");

    OpcUa_ReturnErrorIfArgumentNull(a_pProvider);
    OpcUa_ReturnErrorIfArgumentNull(a_pPublicKey);
    OpcUa_ReturnErrorIfArgumentNull(a_pPrivateKey);

    OpcUa_ReferenceParameter(a_pProvider);

    if(a_pPublicKey->Key.Data == OpcUa_Null)
    {
        a_pPublicKey->Key.Length = 448;
        OpcUa_ReturnStatusCode;
    }

    if(a_pPrivateKey->Key.Data == OpcUa_Null)
    {
        a_pPrivateKey->Key.Length = 448;
        OpcUa_ReturnStatusCode;
    }

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED448, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &pEvpKey);
    EVP_PKEY_CTX_free(pctx);

    pBuffer = a_pPublicKey->Key.Data;

    /* i2d_PublicKey does not work properly */
    /* publicKey.key.Length = i2d_PublicKey(pEvpKey, &pBuffer); */
    a_pPublicKey->Key.Length = i2d_PUBKEY(pEvpKey, &pBuffer);

    pBuffer = a_pPrivateKey->Key.Data;

    a_pPrivateKey->Key.Length = i2d_PrivateKey(pEvpKey, &pBuffer);

    a_pPublicKey->Type = OpcUa_Crypto_KeyType_Ed448_Public;
    a_pPrivateKey->Type = OpcUa_Crypto_KeyType_Ed448_Private;

    if(pEvpKey != OpcUa_Null)
    {
        EVP_PKEY_free(pEvpKey);
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_ECDSA_Private_Sign
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_Ed448_Private_Sign(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_ByteString      a_data,
    OpcUa_Key*            a_privateKey,
    OpcUa_Int16           a_padding,       /* not used for Ed448 */
    OpcUa_ByteString*     a_pSignature)
{
    EVP_PKEY*        pPrivateKey;
    EVP_MD_CTX*      ctx;
    EVP_PKEY_CTX*    pctx;
    OpcUa_Int        ret;

    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "Ed448_Private_Sign");

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

    ctx = EVP_MD_CTX_new();
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED448, NULL);

    ret = EVP_DigestSignInit(ctx, &pctx, NULL, NULL, pPrivateKey);
    if (ret < 1)
    {
      OpcUa_GotoErrorWithStatus(OpcUa_Bad);
    }

    ret = EVP_DigestSign(ctx, (unsigned char*)a_pSignature->Data, (unsigned int*)&(a_pSignature->Length), (const unsigned char*)a_data.Data, (int)a_data.Length);
    if (ret < 1)
    {
      OpcUa_GotoErrorWithStatus(OpcUa_Bad);
    }

OpcUa_BeginErrorHandling;

    pPrivateKey = OpcUa_Null;

    if (ctx != OpcUa_Null)
    {
      EVP_MD_CTX_free(ctx);
    }

    if (pctx != OpcUa_Null)
    {
      EVP_PKEY_CTX_free(pctx);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_ECDSA_Public_Verify
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_Ed448_Public_Verify(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_ByteString        a_data,
    OpcUa_Key*              a_publicKey,
    OpcUa_Int16             a_padding,   /* not used for Ed448 */
    OpcUa_ByteString        a_signature)
{
    EVP_PKEY*       pPublicKey;
    EVP_MD_CTX*      ctx;
    EVP_PKEY_CTX*    pctx;
    OpcUa_Int        ret;

    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "Ed448_Private_Verify");

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

    ctx = EVP_MD_CTX_new();
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED448, NULL);

    ret = EVP_DigestVerifyInit(ctx, &pctx, NULL, NULL, pPublicKey);
    if (ret < 1)
    {
      OpcUa_GotoErrorWithStatus(OpcUa_Bad);
    }

    ret = EVP_DigestVerify(ctx, (const unsigned char*)a_signature.Data, (size_t)a_signature.Length, (const unsigned char*)a_data.Data, (size_t)a_data.Length);
    if (ret < 1)
    {
      OpcUa_GotoErrorWithStatus(OpcUa_Bad);
    }

    OpcUa_BeginErrorHandling;

    pPublicKey = OpcUa_Null;

    if (ctx != OpcUa_Null)
    {
      EVP_MD_CTX_free(ctx);
    }

    if (pctx != OpcUa_Null)
    {
      EVP_PKEY_CTX_free(pctx);
    }

OpcUa_FinishErrorHandling;
}

#else
  static int dummy = 0;
#endif /* OPENSSL_NO_ED448 */

#endif /* OPCUA_REQUIRE_OPENSSL */
