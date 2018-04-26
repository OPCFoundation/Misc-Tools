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
#include <opcua_p_cryptofactory.h>
#include <opcua_p_mutex.h>
#include <opcua_p_thread.h>

#if OPCUA_REQUIRE_OPENSSL

/* System Headers */
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/* own headers */
#include <opcua_p_openssl.h>

#if OPCUA_MULTITHREADED

/*============================================================================
 * Variables used for OpenSSL thread synchronization
 *===========================================================================*/
int             OpcUa_P_OpenSSL_g_NoOfMutexes   = 0;
OpcUa_Mutex*    OpcUa_P_OpenSSL_g_MutexArray    = OpcUa_Null;

#endif /* OPCUA_MULTITHREADED */

/*============================================================================
 * OpcUa_P_ByteString_Initialize
 *===========================================================================*/
OpcUa_Void OpcUa_P_ByteString_Initialize(OpcUa_ByteString* a_pValue)
{
    if (a_pValue == OpcUa_Null)
    {
        return;
    }

    a_pValue->Length = -1;
    a_pValue->Data   = OpcUa_Null;
}

/*============================================================================
 * OpcUa_P_ByteString_Clear
 *===========================================================================*/
OpcUa_Void OpcUa_P_ByteString_Clear(OpcUa_ByteString* a_pValue)
{
    if (a_pValue == OpcUa_Null)
    {
        return;
    }

    a_pValue->Length = -1;

    if(a_pValue->Data != OpcUa_Null)
    {
        free(a_pValue->Data);
        a_pValue->Data = OpcUa_Null;
    }
}

/*============================================================================
 * OpcUa_Key_Clear
 *===========================================================================*/
OpcUa_Void OpcUa_P_Key_Clear(OpcUa_Key* a_pKey)
{
    OpcUa_P_ByteString_Clear(&a_pKey->Key);
    a_pKey->Type = 0;
}

#if OPCUA_MULTITHREADED

/*============================================================================
 * Function getting called by OpenSSL to request ThreadId
 *===========================================================================*/
unsigned long OpcUa_P_OpenSSL_IdCallback(void)
{
    return (unsigned long)OpcUa_P_Thread_GetCurrentThreadId();
}

/*============================================================================
 * Function getting called by OpenSSL to lock a certain mutex.
 *===========================================================================*/
void OpcUa_P_OpenSSL_LockCallback(  int         a_iMode,
                                    int         a_iLockNumber,
                                    const char* a_sFile,
                                    int         a_iLine)
{
    if(a_iLockNumber >= OpcUa_P_OpenSSL_g_NoOfMutexes)
    {
        /* that must be an internal error */
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OpcUa_P_OpenSSL_LockCallback: requested lock number (%i) is out of range! (File: %s, Line: %i)", a_iLockNumber, a_sFile, a_iLine);
        return;
    }

    if(CRYPTO_LOCK & a_iMode)
    {
        /* lock the mutex with id a_iLockNumber */
        OpcUa_P_Mutex_Lock(OpcUa_P_OpenSSL_g_MutexArray[a_iLockNumber]);
    }
    else
    {
        /* unlock the mutex with id a_iLockNumber */
        OpcUa_P_Mutex_Unlock(OpcUa_P_OpenSSL_g_MutexArray[a_iLockNumber]);
    }

    return;
}

#endif /* OPCUA_MULTITHREADED */

/*============================================================================
 * OpcUa_P_OpenSSL_Initialize
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_Initialize()
{
    OpcUa_StatusCode    uStatus         = OpcUa_Good;
    const char*         sVersionInfo    = OpcUa_Null;

#if OPCUA_MULTITHREADED

    /* prepare OpenSSL for multithread usage */
    OpcUa_P_OpenSSL_g_NoOfMutexes = CRYPTO_num_locks();

    if(OpcUa_P_OpenSSL_g_NoOfMutexes > 0)
    {
        int i = 0;

        OpcUa_P_OpenSSL_g_MutexArray = OpcUa_P_Memory_Alloc(OpcUa_P_OpenSSL_g_NoOfMutexes * sizeof(OpcUa_Mutex));
        if(OpcUa_P_OpenSSL_g_MutexArray == NULL)
        {
            OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OpcUa_P_OpenSSL_Initialize: Could not allocate memory for %u requested OpenSSL mutexes!\n", OpcUa_P_OpenSSL_g_NoOfMutexes);
            return OpcUa_BadOutOfMemory;
        }

        OpcUa_MemSet(OpcUa_P_OpenSSL_g_MutexArray, 0, OpcUa_P_OpenSSL_g_NoOfMutexes * sizeof(OpcUa_Mutex));

        for(i = 0; i < OpcUa_P_OpenSSL_g_NoOfMutexes; i++)
        {
            uStatus = OpcUa_P_Mutex_Create(&OpcUa_P_OpenSSL_g_MutexArray[i]);
            if(OpcUa_IsBad(uStatus))
            {
                OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OpcUa_P_OpenSSL_Initialize: Could not initialize all %u requested OpenSSL mutexes!\n", OpcUa_P_OpenSSL_g_NoOfMutexes);
                return uStatus;
            }
        }

        CRYPTO_set_locking_callback(OpcUa_P_OpenSSL_LockCallback);
        CRYPTO_set_id_callback(OpcUa_P_OpenSSL_IdCallback);
    }

#endif /* OPCUA_MULTITHREADED */

    /* initialize algorithms and seed random number generator */
    OpenSSL_add_all_algorithms();
    OpcUa_P_OpenSSL_SeedPRNG(0);

    /* SSLEAY_VERSION - The version of the OpenSSL library including the release date.*/
    sVersionInfo = SSLeay_version(SSLEAY_VERSION);
    OpcUa_P_VersionStringAppend(OpcUa_Null, sVersionInfo);

#if 1 /* additional information about the OpenSSL built, if wanted */
    /* SSLEAY_CFLAGS - The compiler flags set for the compilation process in the form ``compiler: ...'' if available or ``compiler: information not available'' otherwise. */
    sVersionInfo = SSLeay_version(SSLEAY_CFLAGS);
    OpcUa_P_VersionStringAppend("OpenSSL ", sVersionInfo);

    /* SSLEAY_BUILT_ON - The date of the build process in the form ``built on: ...'' if available or ``built on: date not available'' otherwise. */
    sVersionInfo = SSLeay_version(SSLEAY_BUILT_ON);
    OpcUa_P_VersionStringAppend("OpenSSL ", sVersionInfo);

    /* SSLEAY_PLATFORM - The ``Configure'' target of the library build in the form ``platform: ...'' if available or ``platform: information not available'' otherwise. */
    sVersionInfo = SSLeay_version(SSLEAY_PLATFORM);
    OpcUa_P_VersionStringAppend("OpenSSL built for ", sVersionInfo);

    /* SSLEAY_DIR - The ``OPENSSLDIR'' setting of the library build in the form ``OPENSSLDIR: ''...``'' if available or ``OPENSSLDIR: N/A'' otherwise. */
    sVersionInfo = SSLeay_version(SSLEAY_DIR);
    OpcUa_P_VersionStringAppend("OpenSSL built with ", sVersionInfo);
#endif

    return uStatus;
}

/*============================================================================
 * OpcUa_P_OpenSSL_Cleanup
 *===========================================================================*/
void OpcUa_P_OpenSSL_Cleanup()
{
#if OPCUA_MULTITHREADED
    int i = 0;
#endif /* OPCUA_MULTITHREADED */

    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data ();
    ERR_remove_state (0);
    ERR_free_strings ();

#if OPCUA_MULTITHREADED

    CRYPTO_set_locking_callback(OpcUa_Null);
    CRYPTO_set_id_callback(OpcUa_Null);

    /* cleanup openssl lock array at last */
    if(OpcUa_P_OpenSSL_g_MutexArray != OpcUa_Null)
    {
        for(i = 0; i < OpcUa_P_OpenSSL_g_NoOfMutexes; i++)
        {
            if(OpcUa_P_OpenSSL_g_MutexArray[i] != OpcUa_Null)
            {
                OpcUa_P_Mutex_Delete(&OpcUa_P_OpenSSL_g_MutexArray[i]);
            }
        }

        OpcUa_P_Memory_Free(OpcUa_P_OpenSSL_g_MutexArray);
        OpcUa_P_OpenSSL_g_MutexArray = OpcUa_Null;
    }

#endif /* OPCUA_MULTITHREADED */

    return;
}

/*============================================================================
 * OpcUa_P_OpenSSL_AES_128_CBC_Encrypt
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_AES_128_CBC_Encrypt(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_Byte*             a_pPlainText,
    OpcUa_UInt32            a_plainTextLen, /* message length = outputlength */
    OpcUa_Key*              a_key,
    OpcUa_Byte*             a_pInitalVector,
    OpcUa_Byte*             a_pCipherText,
    OpcUa_UInt32*           a_pCipherTextLen)
{
    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "AES_128_CBC_Encrypt");

    if(a_key->Key.Length == 16) /* check 128 bit key (16*8) */
    {
        uStatus = OpcUa_P_OpenSSL_AES_CBC_Encrypt(  a_pProvider,
                                                    a_pPlainText,
                                                    a_plainTextLen,
                                                    a_key,
                                                    a_pInitalVector,
                                                    a_pCipherText,
                                                    a_pCipherTextLen);
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
 * OpcUa_P_OpenSSL_AES_128_CBC_Decrypt
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_AES_128_CBC_Decrypt(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_Byte*             a_pCipherText,
    OpcUa_UInt32            a_cipherTextLen, /* cipher length */
    OpcUa_Key*              a_key,
    OpcUa_Byte*             a_pInitalVector,
    OpcUa_Byte*             a_pPlainText,
    OpcUa_UInt32*           a_pCipherTextLen)
{
    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "AES_128_CBC_Decrypt");

    if(a_key->Key.Length == 16) /* check 128 bit key (16*8) */
    {
        uStatus = OpcUa_P_OpenSSL_AES_CBC_Decrypt(  a_pProvider,
                                                    a_pCipherText,
                                                    a_cipherTextLen,
                                                    a_key,
                                                    a_pInitalVector,
                                                    a_pPlainText,
                                                    a_pCipherTextLen);
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
 * OpcUa_P_OpenSSL_AES_128_CBC_Encrypt
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_AES_256_CBC_Encrypt(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_Byte*             a_pPlainText,
    OpcUa_UInt32            a_plainTextLen, /* message length = outputlength */
    OpcUa_Key*              a_key,
    OpcUa_Byte*             a_pInitalVector,
    OpcUa_Byte*             a_pCipherText,
    OpcUa_UInt32*           a_pCipherTextLen)
{
    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "AES_256_CBC_Encrypt");

    if(a_key->Key.Length == 32) /* check 256 bit key (32*8) */
    {
        uStatus = OpcUa_P_OpenSSL_AES_CBC_Encrypt(  a_pProvider,
                                                    a_pPlainText,
                                                    a_plainTextLen,
                                                    a_key,
                                                    a_pInitalVector,
                                                    a_pCipherText,
                                                    a_pCipherTextLen);
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
 * OpcUa_P_OpenSSL_AES_256_CBC_Decrypt
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_AES_256_CBC_Decrypt(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_Byte*             a_pCipherText,
    OpcUa_UInt32            a_cipherTextLen, /* cipher length */
    OpcUa_Key*              a_key,
    OpcUa_Byte*             a_pInitalVector,
    OpcUa_Byte*             a_pPlainText,
    OpcUa_UInt32*           a_pCipherTextLen)
{
    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "AES_256_CBC_Decrypt");

    if(a_key->Key.Length == 32) /* check 256 bit key (32*8) */
    {
        uStatus = OpcUa_P_OpenSSL_AES_CBC_Decrypt(  a_pProvider,
                                                    a_pCipherText,
                                                    a_cipherTextLen,
                                                    a_key,
                                                    a_pInitalVector,
                                                    a_pPlainText,
                                                    a_pCipherTextLen);
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
 * OpcUa_P_OpenSSL_RSA_PKCS1_V15_Encrypt
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_RSA_PKCS1_V15_Encrypt(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_Byte*             a_pPlainText,
    OpcUa_UInt32            a_plainTextLen,
    OpcUa_Key*              a_publicKey,
    OpcUa_Byte*             a_pCipherText,
    OpcUa_UInt32*           a_pCipherTextLen)
{
    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "RSA_PKCS1_V15_Encrypt");

    uStatus = OpcUa_P_OpenSSL_RSA_Public_Encrypt(   a_pProvider,
                                                    a_pPlainText,
                                                    a_plainTextLen,
                                                    a_publicKey,
                                                    RSA_PKCS1_PADDING,
                                                    a_pCipherText,
                                                    a_pCipherTextLen);
OpcUa_ReturnStatusCode;

OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_RSA_PKCS1_V15_Decrypt
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_RSA_PKCS1_V15_Decrypt(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_Byte*             a_pCipherText,
    OpcUa_UInt32            a_cipherTextLen,
    OpcUa_Key*              a_privateKey,
    OpcUa_Byte*             a_pPlainText,
    OpcUa_UInt32*           a_pPlainTextLen)
{
    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "RSA_PKCS1_V15_Decrypt");

    uStatus =  OpcUa_P_OpenSSL_RSA_Private_Decrypt( a_pProvider,
                                                    a_pCipherText,
                                                    a_cipherTextLen,
                                                    a_privateKey,
                                                    RSA_PKCS1_PADDING,
                                                    a_pPlainText,
                                                    a_pPlainTextLen);
OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_RSA_OAEP_Encrypt
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_RSA_OAEP_Encrypt(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_Byte*             a_pPlainText,
    OpcUa_UInt32            a_plainTextLen,
    OpcUa_Key*              a_publicKey,
    OpcUa_Byte*             a_pCipherText,
    OpcUa_UInt32*           a_pCipherTextLen)
{
    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "RSA_OAEP_Encrypt");

    uStatus = OpcUa_P_OpenSSL_RSA_Public_Encrypt(   a_pProvider,
                                                    a_pPlainText,
                                                    a_plainTextLen,
                                                    a_publicKey,
                                                    RSA_PKCS1_OAEP_PADDING,
                                                    a_pCipherText,
                                                    a_pCipherTextLen);
OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_RSA_OAEP_Decrypt
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_RSA_OAEP_Decrypt(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_Byte*             a_pCipherText,
    OpcUa_UInt32            a_cipherTextLen,
    OpcUa_Key*              a_privateKey,
    OpcUa_Byte*             a_pPlainText,
    OpcUa_UInt32*           a_pPlainTextLen)
{
    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "RSA_OAEP_Decrypt");

    uStatus = OpcUa_P_OpenSSL_RSA_Private_Decrypt(  a_pProvider,
                                                    a_pCipherText,
                                                    a_cipherTextLen,
                                                    a_privateKey,
                                                    RSA_PKCS1_OAEP_PADDING,
                                                    a_pPlainText,
                                                    a_pPlainTextLen);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_HMAC_SHA1_Sign
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_HMAC_SHA1_Sign(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_Byte*           a_pData,
    OpcUa_UInt32          a_dataLen,
    OpcUa_Key*            a_key,
    OpcUa_ByteString*     a_pSignature)
{
    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "HMAC_SHA1_Sign");

    uStatus = OpcUa_P_OpenSSL_HMAC_SHA1_Generate(   a_pProvider,
                                                    a_pData,
                                                    a_dataLen,
                                                    a_key,
                                                    a_pSignature);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_HMAC_SHA1_Verify
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_HMAC_SHA1_Verify(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_Byte*           a_pData,
    OpcUa_UInt32          a_dataLen,
    OpcUa_Key*            a_key,
    OpcUa_ByteString*     a_pSignature)
{
    OpcUa_ByteString mac = OPCUA_BYTESTRING_STATICINITIALIZER;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "HMAC_SHA1_Verify");

    OpcUa_ReturnErrorIfArgumentNull(a_pSignature);
    OpcUa_ReturnErrorIfArgumentNull(a_key);
    OpcUa_ReturnErrorIfArgumentNull(a_key->Key.Data);

    OpcUa_MemSet(&mac, 0, sizeof(OpcUa_ByteString));
    mac.Length = -1;

    if(a_key->Key.Length < 1)
    {
        uStatus = OpcUa_BadInvalidArgument;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    if(a_pSignature->Length != 20)
    {
        uStatus = OpcUa_BadInvalidArgument;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    if((OpcUa_Int32)a_dataLen < 1)
    {
        uStatus = OpcUa_BadInvalidArgument;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    uStatus = OpcUa_P_OpenSSL_HMAC_SHA1_Generate(   a_pProvider,
                                                    a_pData,
                                                    a_dataLen,
                                                    a_key,
                                                    &mac);
    OpcUa_GotoErrorIfBad(uStatus);

    if(mac.Length > 0)
    {
        mac.Data = (OpcUa_Byte*)OpcUa_P_Memory_Alloc(mac.Length*sizeof(OpcUa_Byte));
        OpcUa_ReturnErrorIfAllocFailed(mac.Data);
    }
    else
    {
        uStatus = OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    uStatus = OpcUa_P_OpenSSL_HMAC_SHA1_Generate(   a_pProvider,
                                                    a_pData,
                                                    a_dataLen,
                                                    a_key,
                                                    &mac);
    OpcUa_GotoErrorIfBad(uStatus);

    if((OpcUa_MemCmp(mac.Data, a_pSignature->Data, mac.Length))==0)
    {
        uStatus = OpcUa_Good;
    }
    else
    {
        uStatus = OpcUa_BadSignatureInvalid;
    }

    if(mac.Data != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(mac.Data);
        mac.Data = (OpcUa_Byte*)OpcUa_Null;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(mac.Data != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(mac.Data);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_HMAC_SHA1_Sign
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_HMAC_SHA256_Sign(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_Byte*           a_pData,
    OpcUa_UInt32          a_dataLen,
    OpcUa_Key*            a_key,
    OpcUa_ByteString*     a_pSignature)
{
    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "HMAC_SHA256_Sign");

    uStatus = OpcUa_P_OpenSSL_HMAC_SHA2_256_Generate(   a_pProvider,
                                                        a_pData,
                                                        a_dataLen,
                                                        a_key,
                                                        a_pSignature);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_HMAC_SHA256_Verify
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_HMAC_SHA256_Verify(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_Byte*           a_pData,
    OpcUa_UInt32          a_dataLen,
    OpcUa_Key*            a_key,
    OpcUa_ByteString*     a_pSignature)
{
    OpcUa_ByteString mac = OPCUA_BYTESTRING_STATICINITIALIZER;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "HMAC_SHA256_Verify");

    OpcUa_ReturnErrorIfArgumentNull(a_pSignature);

    if(a_pSignature->Length != 32)
        uStatus = OpcUa_BadInvalidArgument;

    uStatus = OpcUa_P_OpenSSL_HMAC_SHA2_256_Generate(   a_pProvider,
                                                        a_pData,
                                                        a_dataLen,
                                                        a_key,
                                                        &mac);
    OpcUa_GotoErrorIfBad(uStatus);

    if(mac.Length > 0)
    {
        mac.Data = (OpcUa_Byte*)OpcUa_P_Memory_Alloc(mac.Length*sizeof(OpcUa_Byte));
        OpcUa_ReturnErrorIfAllocFailed(mac.Data);
    }
    else
    {
        uStatus = OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

    uStatus = OpcUa_P_OpenSSL_HMAC_SHA2_256_Generate(   a_pProvider,
                                                        a_pData,
                                                        a_dataLen,
                                                        a_key,
                                                        &mac);
    OpcUa_GotoErrorIfBad(uStatus);

    if((OpcUa_MemCmp(mac.Data, a_pSignature->Data, mac.Length))==0)
        uStatus = OpcUa_Good;
    else
        uStatus = OpcUa_BadSignatureInvalid;

    if(mac.Data != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(mac.Data);
        mac.Data = (OpcUa_Byte*)OpcUa_Null;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(mac.Data != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(mac.Data);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_RSA_PKCS1_V15_SHA1_Sign
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_RSA_PKCS1_V15_SHA1_Sign(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_ByteString        a_data,
    OpcUa_Key*              a_privateKey,
    OpcUa_ByteString*       a_pSignature)
{
    OpcUa_ByteString messageDigest = OPCUA_BYTESTRING_STATICINITIALIZER;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "RSA_PKCS1_V15_SHA1_Sign");

    messageDigest.Length = 20; /* 256 bit */

    if(a_data.Data != OpcUa_Null)
    {
        messageDigest.Data = (OpcUa_Byte*)OpcUa_P_Memory_Alloc(messageDigest.Length);

        uStatus = OpcUa_P_OpenSSL_SHA1_Generate(    a_pProvider,
                                                    a_data.Data,
                                                    a_data.Length,
                                                    messageDigest.Data);
        OpcUa_GotoErrorIfBad(uStatus);
    }

    uStatus = OpcUa_P_OpenSSL_RSA_Private_Sign( a_pProvider,
                                                messageDigest,
                                                a_privateKey,
                                                RSA_PKCS1_PADDING,
                                                a_pSignature);

    if(messageDigest.Data != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(messageDigest.Data);
        messageDigest.Data = OpcUa_Null;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(messageDigest.Data != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(messageDigest.Data);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_RSA_PKCS1_V15_SHA1_Verify
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_RSA_PKCS1_V15_SHA1_Verify(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_ByteString      a_data,
    OpcUa_Key*            a_publicKey,
    OpcUa_ByteString*     a_pSignature)
{
    OpcUa_ByteString messageDigest = OPCUA_BYTESTRING_STATICINITIALIZER;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "RSA_PKCS1_V15_SHA1_Verify");

    OpcUa_ReturnErrorIfArgumentNull(a_pSignature);

    messageDigest.Length = 20; /* 160 bit */
    messageDigest.Data = (OpcUa_Byte*)OpcUa_P_Memory_Alloc(messageDigest.Length*sizeof(OpcUa_Byte));

    uStatus = OpcUa_P_OpenSSL_SHA1_Generate(    a_pProvider,
                                                a_data.Data,
                                                a_data.Length,
                                                messageDigest.Data);
    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = OpcUa_P_OpenSSL_RSA_Public_Verify(    a_pProvider,
                                                    messageDigest,
                                                    a_publicKey,
                                                    RSA_PKCS1_PADDING,
                                                    a_pSignature);

    OpcUa_P_Memory_Free(messageDigest.Data);
    messageDigest.Data = OpcUa_Null;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(messageDigest.Data != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(messageDigest.Data);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_RSA_PKCS1_V15_SHA256_Sign
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_RSA_PKCS1_V15_SHA256_Sign(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_ByteString      a_data,
    OpcUa_Key*            a_privateKey,
    OpcUa_ByteString*     a_pSignature)
{
    OpcUa_ByteString messageDigest = OPCUA_BYTESTRING_STATICINITIALIZER;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "RSA_PKCS1_V15_SHA256_Sign");

    messageDigest.Length = 32; /* 256 bit */

    if(a_data.Data != OpcUa_Null)
    {
        messageDigest.Data = (OpcUa_Byte*)OpcUa_P_Memory_Alloc(messageDigest.Length * sizeof(OpcUa_Byte));

        uStatus = OpcUa_P_OpenSSL_SHA2_256_Generate(a_pProvider,
                                                    a_data.Data,
                                                    a_data.Length,
                                                    messageDigest.Data);
        OpcUa_GotoErrorIfBad(uStatus);
    }

    uStatus = OpcUa_P_OpenSSL_RSA_Private_Sign( a_pProvider,
                                                messageDigest,
                                                a_privateKey,
                                                RSA_PKCS1_PADDING,
                                                a_pSignature);

    if(messageDigest.Data != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(messageDigest.Data);
        messageDigest.Data = OpcUa_Null;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(messageDigest.Data != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(messageDigest.Data);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_RSA_PKCS1_V15_SHA256_Verify
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_RSA_PKCS1_V15_SHA256_Verify(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_ByteString      a_data,
    OpcUa_Key*            a_publicKey,
    OpcUa_ByteString*     a_pSignature)
{
    OpcUa_ByteString messageDigest = OPCUA_BYTESTRING_STATICINITIALIZER;

    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "RSA_PKCS1_V15_SHA256_Verify");

    OpcUa_ReturnErrorIfArgumentNull(a_pSignature);

    messageDigest.Length = 32; /* 256 bit */
    messageDigest.Data = (OpcUa_Byte*)OpcUa_P_Memory_Alloc(messageDigest.Length * sizeof(OpcUa_Byte));

    uStatus = OpcUa_P_OpenSSL_SHA2_256_Generate(a_pProvider,
                                                a_data.Data,
                                                a_data.Length,
                                                messageDigest.Data);
    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = OpcUa_P_OpenSSL_RSA_Public_Verify(a_pProvider,
                                                messageDigest,
                                                a_publicKey,
                                                RSA_PKCS1_PADDING,
                                                a_pSignature);

    OpcUa_P_Memory_Free(messageDigest.Data);
    messageDigest.Data = OpcUa_Null;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(messageDigest.Data != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(messageDigest.Data);
    }

OpcUa_FinishErrorHandling;
}
/*============================================================================
 * OpcUa_P_OpenSSL_RSA_PKCS1_OAEP_SHA1_Sign
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_RSA_PKCS1_OAEP_SHA1_Sign(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_ByteString      a_data,
    OpcUa_Key*            a_privateKey,
    OpcUa_ByteString*     a_pSignature)
{
    OpcUa_ByteString messageDigest = OPCUA_BYTESTRING_STATICINITIALIZER;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "RSA_PKCS1_OAEP_SHA1_Sign");

    messageDigest.Length = 20; /* 160 bit */

    if(a_data.Data != OpcUa_Null)
    {
        messageDigest.Data = (OpcUa_Byte*)OpcUa_P_Memory_Alloc(messageDigest.Length * sizeof(OpcUa_Byte));

        uStatus = OpcUa_P_OpenSSL_SHA1_Generate(a_pProvider,
                                                a_data.Data,
                                                a_data.Length,
                                                messageDigest.Data);
        OpcUa_GotoErrorIfBad(uStatus);
    }

    uStatus = OpcUa_P_OpenSSL_RSA_Private_Sign( a_pProvider,
                                                messageDigest,
                                                a_privateKey,
                                                RSA_PKCS1_OAEP_PADDING,
                                                a_pSignature);

    if(messageDigest.Data != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(messageDigest.Data);
        messageDigest.Data = OpcUa_Null;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(messageDigest.Data != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(messageDigest.Data);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_RSA_PKCS1_OAEP_SHA1_Verify
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_RSA_PKCS1_OAEP_SHA1_Verify(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_ByteString      a_data,
    OpcUa_Key*            a_publicKey,
    OpcUa_ByteString*     a_pSignature)
{
    OpcUa_ByteString messageDigest = OPCUA_BYTESTRING_STATICINITIALIZER;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "RSA_PKCS1_OAEP_SHA1_Verify");

    OpcUa_ReturnErrorIfArgumentNull(a_pSignature);

    messageDigest.Length = 20; /* 160 bit */
    messageDigest.Data = (OpcUa_Byte*)OpcUa_P_Memory_Alloc(messageDigest.Length * sizeof(OpcUa_Byte));

    uStatus = OpcUa_P_OpenSSL_SHA1_Generate(a_pProvider,
                                            a_data.Data,
                                            a_data.Length,
                                            messageDigest.Data);
    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = OpcUa_P_OpenSSL_RSA_Public_Verify(a_pProvider,
                                                messageDigest,
                                                a_publicKey,
                                                RSA_PKCS1_OAEP_PADDING,
                                                a_pSignature);

    OpcUa_P_Memory_Free(messageDigest.Data);
    messageDigest.Data = OpcUa_Null;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(messageDigest.Data != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(messageDigest.Data);
    }

OpcUa_FinishErrorHandling;
}
/*============================================================================
 * OpcUa_P_OpenSSL_RSA_PKCS1_OAEP_SHA256_Sign
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_RSA_PKCS1_OAEP_SHA256_Sign(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_ByteString      a_data,
    OpcUa_Key*            a_privateKey,
    OpcUa_ByteString*     a_pSignature)
{
    OpcUa_ByteString messageDigest = OPCUA_BYTESTRING_STATICINITIALIZER;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "RSA_PKCS1_OAEP_SHA256_Sign");

    messageDigest.Length = 32; /* 256 bit */

    if(a_data.Data != OpcUa_Null)
    {
        messageDigest.Data = (OpcUa_Byte*)OpcUa_P_Memory_Alloc(messageDigest.Length * sizeof(OpcUa_Byte));

        uStatus = OpcUa_P_OpenSSL_SHA2_256_Generate(a_pProvider,
                                                    a_data.Data,
                                                    a_data.Length,
                                                    messageDigest.Data);
        OpcUa_GotoErrorIfBad(uStatus);
    }

    uStatus = OpcUa_P_OpenSSL_RSA_Private_Sign( a_pProvider,
                                                messageDigest,
                                                a_privateKey,
                                                RSA_PKCS1_OAEP_PADDING,
                                                a_pSignature);

    if(messageDigest.Data != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(messageDigest.Data);
        messageDigest.Data = OpcUa_Null;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(messageDigest.Data != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(messageDigest.Data);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_RSA_PKCS1_OAEP_SHA256_Verify
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_RSA_PKCS1_OAEP_SHA256_Verify(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_ByteString      a_data,
    OpcUa_Key*            a_publicKey,
    OpcUa_ByteString*     a_pSignature)
{
    OpcUa_ByteString messageDigest = OPCUA_BYTESTRING_STATICINITIALIZER;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "RSA_PKCS1_OAEP_SHA256_Verify");

    OpcUa_ReturnErrorIfArgumentNull(a_pSignature);

    messageDigest.Length = 32; /* 256 bit */
    messageDigest.Data = (OpcUa_Byte*)OpcUa_P_Memory_Alloc(messageDigest.Length*sizeof(OpcUa_Byte));

    uStatus = OpcUa_P_OpenSSL_SHA2_256_Generate(a_pProvider, a_data.Data, a_data.Length, messageDigest.Data);
    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = OpcUa_P_OpenSSL_RSA_Public_Verify(a_pProvider,
                                                messageDigest,
                                                a_publicKey,
                                                RSA_PKCS1_OAEP_PADDING,
                                                a_pSignature);

    OpcUa_P_Memory_Free(messageDigest.Data);
    messageDigest.Data = OpcUa_Null;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(messageDigest.Data != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(messageDigest.Data);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_DeriveChannelKeyset
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_DeriveChannelKeyset(
    OpcUa_CryptoProvider*   a_pCryptoProvider,
    OpcUa_ByteString        a_remoteNonce,
    OpcUa_ByteString        a_localNonce,
    OpcUa_SecurityKeyset*   a_pKeyset)
{
    OpcUa_Key MasterKey;
    OpcUa_UInt32 uKeyDataSize = 0;
    OpcUa_Boolean bCalculateSizes = OpcUa_False;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "DeriveChannelKeyset");

    if (a_pKeyset->SigningKey.Key.Data == OpcUa_Null)
    {
        a_pKeyset->SigningKey.Key.Length = a_pCryptoProvider->DerivedSignatureKeyLength;
        bCalculateSizes = OpcUa_True;
    }

    uKeyDataSize += a_pKeyset->SigningKey.Key.Length;

    if (a_pKeyset->EncryptionKey.Key.Data == OpcUa_Null)
    {
        a_pKeyset->EncryptionKey.Key.Length = a_pCryptoProvider->DerivedEncryptionKeyLength;
        bCalculateSizes = OpcUa_True;
    }

    uKeyDataSize += a_pKeyset->EncryptionKey.Key.Length;

    if (a_pKeyset->InitializationVector.Key.Data == OpcUa_Null)
    {
        a_pKeyset->InitializationVector.Key.Length = a_pCryptoProvider->SymmetricKeyLength;
        bCalculateSizes = OpcUa_True;
    }

    uKeyDataSize += a_pKeyset->InitializationVector.Key.Length;

    if (bCalculateSizes)
    {
        OpcUa_ReturnStatusCode;
    }

    /************************************************************************************/

    /* preinitialize */
    MasterKey.Type = 0;
    /*MasterKey.fpClearHandle = OpcUa_Null;*/
    MasterKey.Key.Length = -1;
    MasterKey.Key.Data = OpcUa_Null;

    /* create the client master key */
    uStatus = a_pCryptoProvider->DeriveKey( a_pCryptoProvider,
                                            a_remoteNonce,
                                            a_localNonce,
                                            uKeyDataSize,
                                            &MasterKey);
    OpcUa_GotoErrorIfBad(uStatus);

    if(MasterKey.Key.Length <= 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
    }

    /* MasterKey */
    MasterKey.Key.Data = (OpcUa_Byte*)OpcUa_P_Memory_Alloc(MasterKey.Key.Length*sizeof(OpcUa_Byte));
    OpcUa_GotoErrorIfAllocFailed(MasterKey.Key.Data);
    uStatus = a_pCryptoProvider->DeriveKey( a_pCryptoProvider,
                                            a_remoteNonce,
                                            a_localNonce,
                                            uKeyDataSize,
                                            &MasterKey);
    OpcUa_GotoErrorIfBad(uStatus);

    /* SigningKey */
    uStatus = OpcUa_P_Memory_MemCpy(a_pKeyset->SigningKey.Key.Data,
                                    a_pKeyset->SigningKey.Key.Length,
                                    MasterKey.Key.Data,
                                    a_pKeyset->SigningKey.Key.Length);
    OpcUa_GotoErrorIfBad(uStatus);

    /* EncryptingKey */
    uStatus = OpcUa_P_Memory_MemCpy(a_pKeyset->EncryptionKey.Key.Data,
                                    a_pKeyset->EncryptionKey.Key.Length,
                                    MasterKey.Key.Data + a_pKeyset->SigningKey.Key.Length,
                                    a_pKeyset->EncryptionKey.Key.Length);

    OpcUa_GotoErrorIfBad(uStatus);

    /* InitializationVector */
    OpcUa_P_Memory_MemCpy(  a_pKeyset->InitializationVector.Key.Data,
                            a_pKeyset->InitializationVector.Key.Length,
                            MasterKey.Key.Data + a_pKeyset->SigningKey.Key.Length + a_pKeyset->EncryptionKey.Key.Length,
                            a_pKeyset->InitializationVector.Key.Length);

    OpcUa_GotoErrorIfBad(uStatus);

    /* cleanup */
    OpcUa_P_Key_Clear(&MasterKey);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_P_Key_Clear(&MasterKey);
    OpcUa_P_Key_Clear(&a_pKeyset->SigningKey);
    OpcUa_P_Key_Clear(&a_pKeyset->EncryptionKey);
    OpcUa_P_Key_Clear(&a_pKeyset->InitializationVector);

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_DeriveChannelKeysets
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_DeriveChannelKeysets(
    OpcUa_CryptoProvider*   a_pCryptoProvider,
    OpcUa_ByteString        a_clientNonce,
    OpcUa_ByteString        a_serverNonce,
    OpcUa_Int32             a_keySize,
    OpcUa_SecurityKeyset*   a_pClientKeyset,
    OpcUa_SecurityKeyset*   a_pServerKeyset)
{
OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "DeriveChannelKeysets");

    OpcUa_ReturnErrorIfArgumentNull(a_pCryptoProvider);
    OpcUa_ReturnErrorIfArgumentNull(a_clientNonce.Data);
    OpcUa_ReturnErrorIfArgumentNull(a_serverNonce.Data);
    OpcUa_ReturnErrorIfArgumentNull(a_pClientKeyset);
    OpcUa_ReturnErrorIfArgumentNull(a_pServerKeyset);

    OpcUa_ReferenceParameter(a_keySize);

    uStatus = OpcUa_P_OpenSSL_DeriveChannelKeyset(  a_pCryptoProvider,
                                                    a_serverNonce,
                                                    a_clientNonce,
                                                    a_pClientKeyset);
    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = OpcUa_P_OpenSSL_DeriveChannelKeyset(  a_pCryptoProvider,
                                                    a_clientNonce,
                                                    a_serverNonce,
                                                    a_pServerKeyset);
    OpcUa_GotoErrorIfBad(uStatus);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_GenerateAsymmetricKeyPair
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_GenerateAsymmetricKeyPair(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_UInt              a_type,
    OpcUa_UInt32            a_bits,
    OpcUa_Key*              a_pPublicKey,
    OpcUa_Key*              a_pPrivateKey)
{
    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "GenerateAsymmetricKeyPair");

    if(a_type == OpcUa_Crypto_Rsa_Id)
    {
        uStatus = OpcUa_P_OpenSSL_RSA_GenerateKeys( a_pProvider,
                                                    a_bits,
                                                    a_pPublicKey,
                                                    a_pPrivateKey);
    }
    else
    {
        uStatus = OpcUa_BadInvalidArgument;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

#endif /* OPCUA_REQUIRE_OPENSSL */
