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

#ifndef _OpcUa_P_WinCrypt_H_
#define _OpcUa_P_WinCrypt_H_ 1

OPCUA_BEGIN_EXTERN_C

/**
  @brief Initializes the WinCrypt library.
*/
OpcUa_StatusCode OpcUa_P_WinCrypt_Initialize();

/**
  @brief Initializes the WinCrypt library.
*/
OpcUa_StatusCode OpcUa_P_WinCrypt_Cleanup();

/**
  @brief Adds random data to the destination buffer..

    if keyLen > 0 then random data of the given length is generated.
    if keyLen == 0 then nothing will be generated.
    if keyLen < 0 then default setting from the CryptoProvider is used.

    if there are no default settings then an error is returned.

  @param pProvider        [in]  The crypto provider handle.
  @param keyLen           [in]  The desired length of the random key.

  @param pKey             [out] The generated random key.
 */
OpcUa_StatusCode OpcUa_P_WinCrypt_Random_Key_Generate(  OpcUa_CryptoProvider* pProvider,
                                                        OpcUa_Int32           keyLen,
                                                        OpcUa_Key*            pKey);

OPCUA_END_EXTERN_C

#endif
