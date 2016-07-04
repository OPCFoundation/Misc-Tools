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
#include <openssl/sha.h>

/* own headers */
#include <opcua_p_openssl.h>

/*============================================================================
 * OpcUa_P_OpenSSL_SHA1_Generate
 *===========================================================================*/
/* SHA-1: 160 Bit output */
OpcUa_StatusCode OpcUa_P_OpenSSL_SHA1_Generate(
    OpcUa_CryptoProvider*         a_pProvider,
    OpcUa_Byte*                   a_pData,
    OpcUa_UInt32                  a_dataLen,
    OpcUa_Byte*                   a_pMessageDigest)
{
OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "SHA1_Generate");

    OpcUa_ReferenceParameter(a_pProvider);

    OpcUa_ReturnErrorIfArgumentNull(a_pData);

    SHA1(a_pData, a_dataLen, a_pMessageDigest);

    OpcUa_ReturnErrorIfNull(a_pMessageDigest,OpcUa_Bad);

OpcUa_ReturnStatusCode;

OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_SHA1_160_Generate
 *===========================================================================*/
/* SHA-2: 160 Bits output */
OpcUa_StatusCode OpcUa_P_OpenSSL_SHA1_160_Generate(
    OpcUa_CryptoProvider*         a_pProvider,
    OpcUa_Byte*                   a_pData,
    OpcUa_UInt32                  a_dataLen,
    OpcUa_Byte*                   a_pMessageDigest)
{
    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "SHA160_Generate");

    OpcUa_ReferenceParameter(a_pProvider);

    OpcUa_ReturnErrorIfArgumentNull(a_pData);

    SHA1(a_pData, a_dataLen, a_pMessageDigest);

    OpcUa_ReturnErrorIfNull(a_pMessageDigest,OpcUa_Bad);

OpcUa_ReturnStatusCode;

OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_SHA2_224_Generate
 *===========================================================================*/
/* SHA-2: 224 Bits output */
OpcUa_StatusCode OpcUa_P_OpenSSL_SHA2_224_Generate(
    OpcUa_CryptoProvider*         a_pProvider,
    OpcUa_Byte*                   a_pData,
    OpcUa_UInt32                  a_dataLen,
    OpcUa_Byte*                   a_pMessageDigest)
{
    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "SHA2_224_Generate");

    OpcUa_ReferenceParameter(a_pProvider);

    OpcUa_ReturnErrorIfArgumentNull(a_pData);

    SHA224(a_pData, a_dataLen, a_pMessageDigest);

    OpcUa_ReturnErrorIfNull(a_pMessageDigest,OpcUa_Bad);

OpcUa_ReturnStatusCode;

OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_SHA2_256_Generate
 *===========================================================================*/
/* SHA-2: 256 Bits output */
OpcUa_StatusCode OpcUa_P_OpenSSL_SHA2_256_Generate(
    OpcUa_CryptoProvider*         a_pProvider,
    OpcUa_Byte*                   a_pData,
    OpcUa_UInt32                  a_dataLen,
    OpcUa_Byte*                   a_pMessageDigest)
{
    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "SHA2_256_Generate");

    OpcUa_ReferenceParameter(a_pProvider);

    OpcUa_ReturnErrorIfArgumentNull(a_pData);

    SHA256(a_pData, a_dataLen, a_pMessageDigest);

    OpcUa_ReturnErrorIfNull(a_pMessageDigest,OpcUa_Bad);

OpcUa_ReturnStatusCode;

OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_SHA2_384_Generate
 *===========================================================================*/
/* SHA-2: 384 Bits output */
OpcUa_StatusCode OpcUa_P_OpenSSL_SHA2_384_Generate(
    OpcUa_CryptoProvider*         a_pProvider,
    OpcUa_Byte*                   a_pData,
    OpcUa_UInt32                  a_dataLen,
    OpcUa_Byte*                   a_pMessageDigest)
{
    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "SHA2_384_Generate");

    OpcUa_ReferenceParameter(a_pProvider);

    OpcUa_ReturnErrorIfArgumentNull(a_pData);

    SHA384(a_pData, a_dataLen, a_pMessageDigest);

    OpcUa_ReturnErrorIfNull(a_pMessageDigest,OpcUa_Bad);

OpcUa_ReturnStatusCode;

OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}


/*============================================================================
 * OpcUa_P_OpenSSL_SHA2_512_Generate
 *===========================================================================*/
/* SHA-2: 512 Bits output */
OpcUa_StatusCode OpcUa_P_OpenSSL_SHA2_512_Generate(
    OpcUa_CryptoProvider*         a_pProvider,
    OpcUa_Byte*                   a_pData,
    OpcUa_UInt32                  a_dataLen,
    OpcUa_Byte*                   a_pMessageDigest)
{
    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "SHA2_512_Generate");

    OpcUa_ReferenceParameter(a_pProvider);

    OpcUa_ReturnErrorIfArgumentNull(a_pData);

    SHA512(a_pData, a_dataLen, a_pMessageDigest);

    OpcUa_ReturnErrorIfNull(a_pMessageDigest,OpcUa_Bad);

OpcUa_ReturnStatusCode;

OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

#endif /* OPCUA_REQUIRE_OPENSSL */
