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

/* System Headers */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0400
#endif
#include <windows.h>
#include <wincrypt.h>

/* UA platform definitions */
#include <opcua_p_internal.h>
#include <opcua_p_memory.h>
#include <opcua_p_cryptofactory.h>

/* own headers */
#include <opcua_p_wincrypt.h>

#define MAX_GENERATED_OUTPUT_LEN  1024

HCRYPTPROV OpcUa_g_hCryptoProvider;


#ifdef UNICODE
#define OPCUA_P_CHAR_TYPE(xConstString) (LPCWSTR)L##xConstString
#else
#define OPCUA_P_CHAR_TYPE(xConstString) xConstString
#endif /* UNICODE */

/*============================================================================
 * OpcUa_P_WinCrypt_Random_Initialize
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_WinCrypt_Initialize()
{
    /*DWORD err = 0;*/

    OpcUa_InitializeStatus(OpcUa_Module_P_WinCrypt, "Initialize");

    if (!CryptAcquireContext(&OpcUa_g_hCryptoProvider, OPCUA_P_CHAR_TYPE("opcua_stack_cypto_container"), NULL, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET))
    {
        DWORD dwLastError = GetLastError();

#if 0
        printf("CryptAcquireContext LastError1 0x%X\n", dwLastError);
#endif

        if (dwLastError == NTE_BAD_KEYSET)
        {
            if (!CryptAcquireContext(&OpcUa_g_hCryptoProvider,
                OPCUA_P_CHAR_TYPE("opcua_stack_cypto_container"),
                NULL,
                PROV_RSA_FULL,
                CRYPT_NEWKEYSET | CRYPT_MACHINE_KEYSET))
            {
                dwLastError = GetLastError();
#if 0
                printf("CryptAcquireContext LastError2 0x%X\n", dwLastError);
#endif
                uStatus = OpcUa_Bad;
            }
#if 0
            else
            {
                printf("CryptAcquireContext OK\n");
            }
#endif
        }
        else
        {
            uStatus = OpcUa_Bad;
        }
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_WinCrypt_Random_Clean
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_WinCrypt_Cleanup()
{
    OpcUa_InitializeStatus(OpcUa_Module_P_WinCrypt, "Cleanup");

    OpcUa_ReturnErrorIfTrue(!CryptReleaseContext(OpcUa_g_hCryptoProvider, 0),OpcUa_Bad);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_WinCrypt_Random_Key_Generate
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_WinCrypt_Random_Key_Generate(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_Int32           a_keyLen,
    OpcUa_Key*            a_pKey)
{
    OpcUa_CryptoProviderConfig* pConfig = OpcUa_Null;
    OpcUa_Int32                 keyLen  = 0;

OpcUa_InitializeStatus(OpcUa_Module_P_WinCrypt, "Random_Key_Generate");

    OpcUa_ReturnErrorIfArgumentNull(a_pProvider);
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
    else if(keyLen > MAX_GENERATED_OUTPUT_LEN)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadInvalidArgument);
    }
    else if(keyLen == 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadInvalidArgument);
    }

    a_pKey->Key.Length = keyLen;
    a_pKey->Type = OpcUa_Crypto_KeyType_Random;

    if(a_pKey->Key.Data == OpcUa_Null)
    {
        OpcUa_ReturnStatusCode;
    }

    if (!CryptGenRandom(OpcUa_g_hCryptoProvider, a_pKey->Key.Length, a_pKey->Key.Data))
    {
        DWORD dwLastError = GetLastError();
        switch(dwLastError)
        {
        case ERROR_INVALID_HANDLE:
            {
                uStatus = OpcUa_BadInvalidArgument;
            }
        case ERROR_INVALID_PARAMETER:
            {
                uStatus = OpcUa_BadInvalidArgument;
            }
        case NTE_BAD_UID:
            {
                uStatus = OpcUa_BadInvalidArgument;
            }
        case NTE_FAIL:
            {
                uStatus = OpcUa_BadUnexpectedError;
            }
        default:
            {
                uStatus = OpcUa_Bad;
            }
        }
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

OpcUa_FinishErrorHandling;
}
