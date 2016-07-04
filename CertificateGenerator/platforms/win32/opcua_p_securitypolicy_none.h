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

#ifndef _OpcUa_P_SecurityPolicy_None_H_
#define _OpcUa_P_SecurityPolicy_None_H_ 1

OPCUA_BEGIN_EXTERN_C

/*** NO SECURITY PROTOTYPES ***/

/**
  @brief
*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_CreateCertificate(
    OpcUa_CryptoProvider*       pProvider,
    const OpcUa_Int32           serialNumber,
    OpcUa_DateTime              validFrom,
    OpcUa_DateTime              validTo,
    OpcUa_Crypto_NameEntry*     pNameEntries,
    OpcUa_UInt                  nameEntriesCount,
    OpcUa_Key                   pSubjectPublicKey,
    OpcUa_Crypto_Extension*     pExtensions,
    OpcUa_UInt                  extensionsCount,
    const OpcUa_UInt            signatureHashAlgorithm,
    OpcUa_Certificate*          pIssuerCertificate,
    OpcUa_Key                   pIssuerPrivateKey,
    OpcUa_Certificate**         ppCertificate);

/**
  @brief
*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_GetPrivateKeyFromCert(
    OpcUa_CryptoProvider*       pProvider,
    OpcUa_StringA               certificate,
    OpcUa_StringA               password,
    OpcUa_Key*                  pPrivateKey);

/**
  @brief
*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_GetPublicKeyFromCert(
    OpcUa_CryptoProvider*       pProvider,
    OpcUa_ByteString*           pCertificate,
    OpcUa_StringA               password,
    OpcUa_Key*                  pPublicKey);

/**
  @brief
*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_GetSignatureFromCert(
    OpcUa_CryptoProvider*       pProvider,
    OpcUa_ByteString*           pCertificate,
    OpcUa_Signature*            pSignature);

/**
  @brief
*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_GenerateAsymmetricKeyPair(
    OpcUa_CryptoProvider*   pProvider,
    OpcUa_UInt              type,
    OpcUa_UInt32            bytes,
    OpcUa_Key*              pPublicKey,
    OpcUa_Key*              pPrivateKey);

/**
  @brief
*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_DeriveChannelKeysets(
    struct _OpcUa_CryptoProvider*   pCryptoProvider,
    OpcUa_ByteString                clientNonce,
    OpcUa_ByteString                serverNonce,
    OpcUa_Int32                     keySize,
    struct _OpcUa_SecurityKeyset*   pClientKeyset,
    struct _OpcUa_SecurityKeyset*   pServerKeyset);

/**
  @brief
*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_DeriveKey(OpcUa_CryptoProvider* a_pProvider,
    OpcUa_ByteString      secret,
    OpcUa_ByteString      seed,
    OpcUa_Int32           keyLen,
    OpcUa_Key*            pKey);

/**
  @brief
*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_GenerateKey(
    OpcUa_CryptoProvider* pProvider,
    OpcUa_Int32           keyLen,
    OpcUa_Key*            pKey);

/**
  @brief
*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_SymmetricEncrypt(
    OpcUa_CryptoProvider*   pProvider,
    OpcUa_Byte*             pPlainText,
    OpcUa_UInt32            plainTextLen,
    OpcUa_Key*              key,
    OpcUa_Byte*             pInitalVector,
    OpcUa_Byte*             pCipherText,
    OpcUa_UInt32*           pCipherTextLen);

/**
  @brief
*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_SymmetricDecrypt(
    OpcUa_CryptoProvider*   pProvider,
    OpcUa_Byte*             pCipherText,
    OpcUa_UInt32            cipherTextLen,
    OpcUa_Key*              key,
    OpcUa_Byte*             pInitalVector,
    OpcUa_Byte*             pPlainText,
    OpcUa_UInt32*           pCipherTextLen);

/**
  @brief
*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_SymmetricSign(
    OpcUa_CryptoProvider* pProvider,
    OpcUa_Byte*           pData,
    OpcUa_UInt32          dataLen,
    OpcUa_Key*            key,
    OpcUa_ByteString*    ppSignature);

/**
  @brief
*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_SymmetricVerify(
    OpcUa_CryptoProvider* pProvider,
    OpcUa_Byte*           pData,
    OpcUa_UInt32          dataLen,
    OpcUa_Key*            key,
    OpcUa_ByteString*     pSignature);

/**
  @brief
*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_AsymmetricEncrypt(
    OpcUa_CryptoProvider*   pProvider,
    OpcUa_Byte*             pPlainText,
    OpcUa_UInt32            plainTextLen,
    OpcUa_Key*              publicKey,
    OpcUa_Byte*             pCipherText,
    OpcUa_UInt32*           pCipherTextLen);

/**
  @brief
*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_AsymmetricDecrypt(
    OpcUa_CryptoProvider*   pProvider,
    OpcUa_Byte*             pCipherText,
    OpcUa_UInt32            cipherTextLen,
    OpcUa_Key*              privateKey,
    OpcUa_Byte*             pPlainText,
    OpcUa_UInt32*           pPlainTextLen);

/**
  @brief
*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_AsymmetricSign(
    OpcUa_CryptoProvider* pProvider,
    OpcUa_ByteString      data,
    OpcUa_Key*            privateKey,
    OpcUa_ByteString*     pSignature);

/**
  @brief
*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_AsymmetricVerify(
    OpcUa_CryptoProvider* pProvider,
    OpcUa_ByteString      data,
    OpcUa_Key*            publicKey,
    OpcUa_ByteString*     pSignature);

/**
  @brief
*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_GetCertificateThumbprint(
    OpcUa_CryptoProvider*       a_pProvider,
    OpcUa_ByteString*           a_pCertificate,
    OpcUa_ByteString*           a_pCertificateThumbprint);

/**
  @brief
*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_GetAsymmetricKeyLength(
    OpcUa_CryptoProvider*   pProvider,
    OpcUa_Key               publicKey,
    OpcUa_UInt32*           pKeyLen);

OPCUA_END_EXTERN_C

#endif /* _OpcUa_P_SecurityPolicy_None_H_ */
