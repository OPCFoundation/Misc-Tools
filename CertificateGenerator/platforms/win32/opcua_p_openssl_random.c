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

#if OPCUA_REQUIRE_OPENSSL

/* System Headers */
#include <openssl/rand.h>
#include <openssl/hmac.h>

/* own headers */
#include <opcua_p_openssl.h>

#define MAX_DERIVED_OUTPUT_LEN  512
#define MAX_GENERATED_OUTPUT_LEN  1024

/* offset macros */
#define OpcUa_P_OpenSSL_PSHA1_SEED(ctx)   ((ctx)->A+20)
#define OpcUa_P_OpenSSL_PSHA1_SECRET(ctx) ((ctx)->A+20+(ctx)->seed_len)

/** P_SHA1 Context */
struct OpcUa_P_OpenSSL_PSHA1_Ctx_
{
    OpcUa_Int secret_len;
    OpcUa_Int seed_len;
    OpcUa_SByte A[20]; /* 20 bytes of SHA1 output */
    /* pseudo elements:
     * char seed[seed_len];
     * char secret[secret_len];
     */
};

typedef struct OpcUa_P_OpenSSL_PSHA1_Ctx_ OpcUa_P_OpenSSL_PSHA1_Ctx;

/**
  @brief Initializes the pseudo-random function.

  -  returns a PRF context.

  internal!

  @param pSecret          [in]  The secret information for the PRF to create a PRF context.
  @param secretLen        [in]  The length of the secret information for the PRF to create a PRF context.
  @param pSeed            [in]  The seed to create the PRF context.
  @param secretLen        [in]  The length seed to create the PRF context.
*/
OpcUa_P_OpenSSL_PSHA1_Ctx* OpcUa_P_OpenSSL_PSHA1_Context_Create(
    OpcUa_Byte*         pSecret,
    OpcUa_UInt32        secretLen,
    OpcUa_Byte*         pSeed,
    OpcUa_Int32         seedLen);

/**
  @brief Add bytes of random data to the destination buffer.

  internal!

  @param pPsha1Context     [in]  The PRF context.

  @param pHash             [out] The destination buffer.
*/
OpcUa_StatusCode OpcUa_P_OpenSSL_PSHA1_Hash_Generate(
    OpcUa_P_OpenSSL_PSHA1_Ctx* pPsha1Context,
    OpcUa_Byte*              pHash);

/*============================================================================
 * OpcUa_P_OpenSSL_SeedPRNG
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_SeedPRNG(OpcUa_Int bytes)
{
    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "SeedPRNG");

    OpcUa_ReferenceParameter(bytes);

	RAND_poll();

    if(RAND_status () == 0)
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_WARNING, "P_OpenSSL - SeedPRNG: WARNING! PRNG has to be seeded!\n");
    }

OpcUa_ReturnStatusCode;

OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}


/*============================================================================
 * OpcUa_P_OpenSSL_PSHA1_Context_Create
 *===========================================================================*/
/** Implements P_SHA1 according to RFC 2246, section 5
* using OpenSSL HMAC function.
* P_SHA1_init creates a P_SHA1 context and initializes it with secret and seed.
* Use OpcUa_OpcUa_P_Memory_Free to clear the context.
* A(1) is calculated to use with OpcUa_P_OpenSSL_P_SHA1_update.
* @see OpcUa_P_OpenSSL_P_SHA1_update
*/

/* internal function */
OpcUa_P_OpenSSL_PSHA1_Ctx* OpcUa_P_OpenSSL_PSHA1_Context_Create(
    OpcUa_Byte*     a_pSecret,
    OpcUa_UInt32    a_secretLen,
    OpcUa_Byte*     a_pSeed,
    OpcUa_Int32     a_seedLen)
{
    OpcUa_P_OpenSSL_PSHA1_Ctx*  pCtx;
    OpcUa_Int                   size;

    if(a_pSecret == OpcUa_Null || a_pSeed   == OpcUa_Null)
        return OpcUa_Null;

    pCtx = OpcUa_Null;
    size = sizeof(OpcUa_P_OpenSSL_PSHA1_Ctx) + a_secretLen + a_seedLen;

    pCtx = (OpcUa_P_OpenSSL_PSHA1_Ctx*) OpcUa_P_Memory_Alloc(size);

    if (pCtx == OpcUa_Null)
        return OpcUa_Null;

    pCtx->secret_len = a_secretLen;
    pCtx->seed_len = a_seedLen;

    OpcUa_P_Memory_MemCpy(OpcUa_P_OpenSSL_PSHA1_SECRET(pCtx), a_secretLen, a_pSecret, a_secretLen);
    OpcUa_P_Memory_MemCpy(OpcUa_P_OpenSSL_PSHA1_SEED(pCtx), a_seedLen, a_pSeed, a_seedLen);

    /* A(0) = seed */
    /* A(i) = HMAC_SHA1(secret, A(i-1)) */
    /* Calculate A(1) = HMAC_SHA1(secret, seed) */
    HMAC(EVP_sha1(), a_pSecret, a_secretLen, a_pSeed, a_seedLen, (unsigned char*)pCtx->A, (unsigned int*)OpcUa_Null);

    return pCtx;
}

/*============================================================================
 * OpcUa_P_OpenSSL_PSHA1_Hash_Generate
 *===========================================================================*/
/** Implements P_SHA1 according to RFC 2246, section 5
* using OpenSSL HMAC function.
* P_SHA1_update calculates P_SHA1(n) and writes it to pDst.
* Call this function as often as you need to get the desired size of data.
* A(n+1) is caculated for the next run.
* @see OpcUa_P_OpenSSL_P_SHA1_init
*/

/* internal function */
OpcUa_StatusCode OpcUa_P_OpenSSL_PSHA1_Hash_Generate(
    OpcUa_P_OpenSSL_PSHA1_Ctx* a_pPsha1Context,
    OpcUa_Byte*              a_pHash)
{
OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "PSHA1_Hash_Generate");

    OpcUa_ReturnErrorIfArgumentNull(a_pPsha1Context);

    /* Calculate P_SHA1(n) = HMAC_SHA1(secret, A(n)+seed) */
    HMAC(EVP_sha1(), OpcUa_P_OpenSSL_PSHA1_SECRET(a_pPsha1Context), a_pPsha1Context->secret_len,
                     (unsigned char*)a_pPsha1Context->A, sizeof(a_pPsha1Context->A) + a_pPsha1Context->seed_len,
                     a_pHash, OpcUa_Null);

    /* Calculate A(n) = HMAC_SHA1(secret, A(n-1)) */
    HMAC(EVP_sha1(), OpcUa_P_OpenSSL_PSHA1_SECRET(a_pPsha1Context), a_pPsha1Context->secret_len, (const unsigned char*)a_pPsha1Context->A, sizeof(a_pPsha1Context->A), (unsigned char*)a_pPsha1Context->A, (unsigned int*)OpcUa_Null);

    OpcUa_ReturnErrorIfNull(a_pHash, OpcUa_Bad);

OpcUa_ReturnStatusCode;

OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_Random_Key_Derive
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_Random_Key_Derive(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_ByteString      a_secret, /* clientnonce | servernonce, servernonce | clientnonce */
    OpcUa_ByteString      a_seed,
    OpcUa_Int32           a_keyLen, /* output len */
    OpcUa_Key*            a_pKey)
{
    OpcUa_P_OpenSSL_PSHA1_Ctx*  pCtx            = OpcUa_Null;
    OpcUa_Byte*                 pBuffer         = OpcUa_Null;

    OpcUa_Int                   bufferlength;
    OpcUa_Int                   i;
    OpcUa_Int                   iterations;

    OpcUa_CryptoProviderConfig* pConfig         = OpcUa_Null;
    OpcUa_Int32                 keyLen          = 0;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "Random_Key_Derive");

    OpcUa_ReferenceParameter(a_pProvider);

    OpcUa_ReturnErrorIfArgumentNull(a_pProvider);
    OpcUa_ReturnErrorIfArgumentNull(a_secret.Data);
    OpcUa_ReturnErrorIfArgumentNull(a_seed.Data);
    OpcUa_ReturnErrorIfArgumentNull(a_pKey);

    keyLen = a_keyLen;

    if(keyLen < 0)
    {
        if(a_pProvider->Handle != OpcUa_Null)
        {
            /* get default configuration */
            pConfig = (OpcUa_CryptoProviderConfig*)a_pProvider->Handle;
            keyLen = pConfig->SymmetricKeyLength;
        }
        else
        {
            uStatus = OpcUa_BadInvalidArgument;
            OpcUa_GotoErrorIfBad(uStatus);
        }
    }
    else if(keyLen > MAX_DERIVED_OUTPUT_LEN)
    {
        uStatus = OpcUa_BadInvalidArgument;
        OpcUa_GotoErrorIfBad(uStatus);
    }
    else if(keyLen == 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadInvalidArgument);
    }

    if(a_pKey->Key.Data == OpcUa_Null)
    {
        a_pKey->Key.Length = keyLen;
        OpcUa_ReturnStatusCode;
    }

    a_pKey->Type = OpcUa_Crypto_KeyType_Random;

    /** start creating key **/

    pCtx = (OpcUa_P_OpenSSL_PSHA1_Ctx*)OpcUa_Null;

    iterations = keyLen/20 + (keyLen%20?1:0);
    bufferlength = iterations*20;

    pBuffer = (OpcUa_Byte *)OpcUa_P_Memory_Alloc(bufferlength * sizeof(OpcUa_Byte));

    pCtx = OpcUa_P_OpenSSL_PSHA1_Context_Create(a_secret.Data, a_secret.Length, a_seed.Data, a_seed.Length);

    for(i=0; i<iterations; i++)
    {
        /* SHA1 produces 20 Bytes of output for every iteration */
        uStatus = OpcUa_P_OpenSSL_PSHA1_Hash_Generate(pCtx, pBuffer + (i*20));
        OpcUa_GotoErrorIfBad(uStatus);
    }

    OpcUa_P_Memory_MemCpy(a_pKey->Key.Data, a_pKey->Key.Length, pBuffer, keyLen);

    if(pCtx != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(pCtx);
        pCtx = OpcUa_Null;
    }

    if(pBuffer != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(pBuffer);
        pBuffer = OpcUa_Null;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(pCtx != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(pCtx);
        pCtx = OpcUa_Null;
    }

    if(pBuffer != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(pBuffer);
        pBuffer = OpcUa_Null;
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_OpenSSL_Random_Key_Generate
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_Random_Key_Generate(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_Int32           a_keyLen,
    OpcUa_Key*            a_pKey)
{
    OpcUa_CryptoProviderConfig* pConfig = OpcUa_Null;
    OpcUa_Int32                 keyLen  = 0;

    OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "Random_Key_Generate");

    OpcUa_ReturnErrorIfArgumentNull(a_pProvider);
    OpcUa_ReturnErrorIfArgumentNull(a_pKey);

    OpcUa_ReferenceParameter(a_pProvider);

    keyLen = a_keyLen;

    if(keyLen < 0)
    {
        if(a_pProvider->Handle != OpcUa_Null)
        {
            /* get default configuration */
            pConfig = (OpcUa_CryptoProviderConfig*)a_pProvider->Handle;
            keyLen = pConfig->SymmetricKeyLength;
        }
        else
        {
            uStatus = OpcUa_BadInvalidArgument;
            OpcUa_GotoErrorIfBad(uStatus);
        }
    }
    else if(keyLen > MAX_GENERATED_OUTPUT_LEN)
    {
            uStatus = OpcUa_BadInvalidArgument;
            OpcUa_GotoErrorIfBad(uStatus);
    }

    a_pKey->Key.Length = keyLen;
    a_pKey->Type = OpcUa_Crypto_KeyType_Random;

    if(a_pKey->Key.Data == OpcUa_Null)
    {
        OpcUa_ReturnStatusCode;
    }

    uStatus = OpcUa_P_OpenSSL_SeedPRNG(a_keyLen);
    OpcUa_GotoErrorIfBad(uStatus);

    if(RAND_bytes(a_pKey->Key.Data, a_pKey->Key.Length) == 0)
    {
        uStatus = OpcUa_Bad;
        OpcUa_GotoErrorIfBad(uStatus);
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;


OpcUa_FinishErrorHandling;
}

#endif /* OPCUA_REQUIRE_OPENSSL */
