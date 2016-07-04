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

/* System Headers */
#include <openssl/hmac.h>

/* own headers */
#include <opcua_p_openssl.h>

/*============================================================================
 * OpcUa_P_OpenSSL_HMAC_SHA1_Generate
 *===========================================================================*/
/* HMAC-SHA-1: 160 Bits output */
OpcUa_StatusCode OpcUa_P_OpenSSL_HMAC_SHA1_Generate(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_Byte*           a_pData,
    OpcUa_UInt32          a_dataLen,
    OpcUa_Key*            a_key,
    OpcUa_ByteString*     a_pMac)
{
    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "HMAC_SHA1_Generate");

    OpcUa_ReferenceParameter(a_pProvider);

    OpcUa_ReturnErrorIfArgumentNull(a_key);
    OpcUa_ReturnErrorIfArgumentNull(a_key->Key.Data);
    OpcUa_ReturnErrorIfArgumentNull(a_pMac);

    if(a_key->Key.Length < 1)
    {
        uStatus = OpcUa_BadInvalidArgument;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    if((OpcUa_Int32)a_dataLen < 1)
    {
        uStatus = OpcUa_BadInvalidArgument;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    if(a_pMac->Data == OpcUa_Null)
    {
        a_pMac->Length = 20;
        OpcUa_ReturnStatusCode;
    }

    HMAC(EVP_sha1(),a_key->Key.Data,a_key->Key.Length,a_pData,a_dataLen,a_pMac->Data,(unsigned int*)&(a_pMac->Length));

    if(a_pMac->Length <= 0)
        uStatus = OpcUa_Bad;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}


/*============================================================================
 * OpcUa_P_OpenSSL_HMAC_SHA1_160_Generate
 *===========================================================================*/
/* HMAC-SHA-2: 160 Bits output */
OpcUa_StatusCode OpcUa_P_OpenSSL_HMAC_SHA1_160_Generate(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_Byte*           a_pData,
    OpcUa_UInt32          a_dataLen,
    OpcUa_Key             a_key,
    OpcUa_ByteString*     a_pMac)
{
    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "HMAC_SHA160_Generate");

    OpcUa_ReferenceParameter(a_pProvider);

    OpcUa_ReturnErrorIfArgumentNull(a_key.Key.Data);
    OpcUa_ReturnErrorIfArgumentNull(a_pMac);

    if(a_pMac->Data == OpcUa_Null)
    {
        a_pMac->Length = 20;
        OpcUa_ReturnStatusCode;
    }

    HMAC(EVP_sha1(),a_key.Key.Data,a_key.Key.Length,a_pData,a_dataLen,a_pMac->Data,(unsigned int*)&(a_pMac->Length));

    if(a_pMac->Length <= 0)
        uStatus = OpcUa_Bad;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_HMAC_SHA2_224_Generate
 *===========================================================================*/
/* HMAC-SHA-2: 224 Bits output */
OpcUa_StatusCode OpcUa_P_OpenSSL_HMAC_SHA2_224_Generate(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_Byte*           a_pData,
    OpcUa_UInt32          a_dataLen,
    OpcUa_Key             a_key,
    OpcUa_ByteString*     a_pMac)
{
    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "HMAC_SHA224_Generate");

    OpcUa_ReferenceParameter(a_pProvider);

    OpcUa_ReturnErrorIfArgumentNull(a_key.Key.Data);
    OpcUa_ReturnErrorIfArgumentNull(a_pMac);

    if(a_pMac->Data == OpcUa_Null)
    {
        a_pMac->Length = 28;
        OpcUa_ReturnStatusCode;
    }

    HMAC(EVP_sha224(),a_key.Key.Data,a_key.Key.Length,a_pData,a_dataLen,a_pMac->Data,(unsigned int*)&(a_pMac->Length));

    if(a_pMac->Length <= 0)
        uStatus = OpcUa_Bad;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_HMAC_SHA2_256_Generate
 *===========================================================================*/
/* HMAC-SHA-2: 256 Bits output */
OpcUa_StatusCode OpcUa_P_OpenSSL_HMAC_SHA2_256_Generate(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_Byte*           a_pData,
    OpcUa_UInt32          a_dataLen,
    OpcUa_Key*            a_key,
    OpcUa_ByteString*     a_pMac)
{
    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "HMAC_SHA256_Generate");

    OpcUa_ReferenceParameter(a_pProvider);

    OpcUa_ReturnErrorIfArgumentNull(a_key);
    OpcUa_ReturnErrorIfArgumentNull(a_key->Key.Data);
    OpcUa_ReturnErrorIfArgumentNull(a_pMac);

    if(a_pMac->Data == OpcUa_Null)
    {
        a_pMac->Length = 32;
        OpcUa_ReturnStatusCode;
    }

    HMAC(EVP_sha256(),a_key->Key.Data,a_key->Key.Length,a_pData,a_dataLen,a_pMac->Data,(unsigned int*)&(a_pMac->Length));

    if(a_pMac->Length <= 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_Bad);
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_HMAC_SHA2_384_Generate
 *===========================================================================*/
/* HMAC-SHA-2: 384 Bits output */
OpcUa_StatusCode OpcUa_P_OpenSSL_HMAC_SHA2_384_Generate(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_Byte*           a_pData,
    OpcUa_UInt32          a_dataLen,
    OpcUa_Key             a_key,
    OpcUa_ByteString*     a_pMac)
{
    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "HMAC_SHA384_Generate");

    OpcUa_ReferenceParameter(a_pProvider);

    OpcUa_ReturnErrorIfArgumentNull(a_key.Key.Data);
    OpcUa_ReturnErrorIfArgumentNull(a_pMac);

    if(a_pMac->Data == OpcUa_Null)
    {
        a_pMac->Length = 48;
        OpcUa_ReturnStatusCode;
    }

    HMAC(EVP_sha384(),a_key.Key.Data,a_key.Key.Length,a_pData,a_dataLen,a_pMac->Data,(unsigned int*)&(a_pMac->Length));

    if(a_pMac->Length <= 0)
        uStatus = OpcUa_Bad;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_HMAC_SHA2_512_Generate
 *===========================================================================*/
/* HMAC-SHA-2: 512 Bits output */
OpcUa_StatusCode OpcUa_P_OpenSSL_HMAC_SHA2_512_Generate(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_Byte*           a_pData,
    OpcUa_UInt32          a_dataLen,
    OpcUa_Key             a_key,
    OpcUa_ByteString*     a_pMac)
{
    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "HMAC_SHA512_Generate");

    OpcUa_ReferenceParameter(a_pProvider);

    OpcUa_ReturnErrorIfArgumentNull(a_key.Key.Data);
    OpcUa_ReturnErrorIfArgumentNull(a_pMac);

    if(a_pMac->Data == OpcUa_Null)
    {
        a_pMac->Length = 64;
        OpcUa_ReturnStatusCode;
    }

    HMAC(EVP_sha512(),a_key.Key.Data,a_key.Key.Length,a_pData,a_dataLen,a_pMac->Data,(unsigned int*)&(a_pMac->Length));

    if(a_pMac->Length <= 0)
        uStatus = OpcUa_Bad;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

OpcUa_FinishErrorHandling;
}

#endif /* OPCUA_REQUIRE_OPENSSL */
