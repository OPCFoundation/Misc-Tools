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
#include <memory.h>
#include <openssl/aes.h>

/* own headers */
#include <opcua_p_openssl.h>

/*** AES SYMMETRIC ENCRYPTION ***/

/*============================================================================
 * OpcUa_P_OpenSSL_AES_CBC_Encrypt
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_AES_CBC_Encrypt(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_Byte*             a_pPlainText,
    OpcUa_UInt32            a_plainTextLen,
    OpcUa_Key*              a_key,
    OpcUa_Byte*             a_pInitalVector,
    OpcUa_Byte*             a_pCipherText,
    OpcUa_UInt32*           a_pCipherTextLen)
{
    AES_KEY         key;

    OpcUa_Byte*     pInitalVector = OpcUa_Null;
    OpcUa_UInt32    keyLenInBits  = 0;

    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "AES_CBC_Encrypt");

    OpcUa_ReferenceParameter(a_pProvider);

    OpcUa_ReturnErrorIfArgumentNull(a_pPlainText);
    OpcUa_ReturnErrorIfArgumentNull(a_key);
    OpcUa_ReturnErrorIfArgumentNull(a_key->Key.Data);
    OpcUa_ReturnErrorIfArgumentNull(a_pInitalVector);
    OpcUa_ReturnErrorIfArgumentNull(a_pCipherTextLen);

    if((((OpcUa_Int)a_plainTextLen) < 0) || (a_key->Key.Length < 0))
    {
        uStatus = OpcUa_BadInvalidArgument;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    keyLenInBits = (a_key->Key.Length*8);

    /* we have to pass the key length in bits instead of bytes */
    if(AES_set_encrypt_key(a_key->Key.Data, keyLenInBits, &key) < 0)
    {
        uStatus = OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    *a_pCipherTextLen = a_plainTextLen;

    /* if just the output length is needed for the caller of this function */
    if(a_pCipherText == OpcUa_Null)
    {
        OpcUa_ReturnStatusCode;
    }

    /* copy the IV because the AES_cbc_encrypt function overwrites it. */
    pInitalVector = (OpcUa_Byte*)OpcUa_P_Memory_Alloc(16);
    OpcUa_ReturnErrorIfAllocFailed(pInitalVector);
    OpcUa_P_Memory_MemCpy(pInitalVector, 16, a_pInitalVector, 16);

    /* encrypt data */
    AES_cbc_encrypt(    a_pPlainText,
                        a_pCipherText,
                        *a_pCipherTextLen,
                        &key,
                        pInitalVector,
                        AES_ENCRYPT);

    OpcUa_ReturnErrorIfNull(a_pCipherText, OpcUa_Bad);

    OpcUa_P_Memory_Free(pInitalVector);
    pInitalVector = OpcUa_Null;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_P_Memory_Free(pInitalVector);
    pInitalVector = OpcUa_Null;

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_AES_CBC_decrypt
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_AES_CBC_Decrypt(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_Byte*             a_pCipherText,
    OpcUa_UInt32            a_cipherTextLen,
    OpcUa_Key*              a_key,
    OpcUa_Byte*             a_pInitalVector,
    OpcUa_Byte*             a_pPlainText,
    OpcUa_UInt32*           a_pPlainTextLen)
{
    AES_KEY         key;
    OpcUa_Byte*     pInitalVector = OpcUa_Null;

    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "AES_CBC_Decrypt");

    OpcUa_ReferenceParameter(a_pProvider);

    OpcUa_ReturnErrorIfArgumentNull(a_pCipherText);
    OpcUa_ReturnErrorIfArgumentNull(a_key);
    OpcUa_ReturnErrorIfArgumentNull(a_key->Key.Data);
    OpcUa_ReturnErrorIfArgumentNull(a_pInitalVector);

    if(a_pPlainText == OpcUa_Null)
    {
        *a_pPlainTextLen = a_cipherTextLen;
        OpcUa_ReturnStatusCode;
    }

    /* we have to pass the key length in bits instead of bytes */
    if(AES_set_decrypt_key(a_key->Key.Data,(a_key->Key.Length*8),&key) < 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_Bad);
    }

    /* copy the IV because the AES_cbc_encrypt function overwrites it. */
    pInitalVector = (OpcUa_Byte*)OpcUa_P_Memory_Alloc(16);
    OpcUa_ReturnErrorIfAllocFailed(pInitalVector);
    OpcUa_P_Memory_MemCpy(pInitalVector, 16, a_pInitalVector, 16);

    /* decrypt ciphertext */
    AES_cbc_encrypt(    a_pCipherText,
                        a_pPlainText,
                        a_cipherTextLen,
                        &key,
                        pInitalVector,
                        AES_DECRYPT);

    /* get real message length */
    *a_pPlainTextLen = a_cipherTextLen;

    OpcUa_P_Memory_Free(pInitalVector);
    pInitalVector = OpcUa_Null;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_P_Memory_Free(pInitalVector);
    pInitalVector = OpcUa_Null;

OpcUa_FinishErrorHandling;
}

#endif /* OPCUA_REQUIRE_OPENSSL */
