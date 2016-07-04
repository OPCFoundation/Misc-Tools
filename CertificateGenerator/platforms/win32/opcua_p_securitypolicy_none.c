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

/*============================================================================
 * OpcUa_P_Crypto_NoSecurity_CreateCertificate
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_CreateCertificate(
    OpcUa_CryptoProvider*       a_pProvider,
    const OpcUa_Int32           a_serialNumber,
    OpcUa_DateTime              a_validFrom,
    OpcUa_DateTime              a_validTo,
    OpcUa_Crypto_NameEntry*     a_pNameEntries,
    OpcUa_UInt                  a_nameEntriesCount,
    OpcUa_Key                   a_pSubjectPublicKey,
    OpcUa_Crypto_Extension*     a_pExtensions,
    OpcUa_UInt                  a_extensionsCount,
    const OpcUa_UInt            a_signatureHashAlgorithm,
    OpcUa_Certificate*          a_pIssuerCertificate,
    OpcUa_Key                   a_pIssuerPrivateKey,
    OpcUa_Certificate**         a_ppCertificate)
{
    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_serialNumber);
    OpcUa_ReferenceParameter(a_validFrom);
    OpcUa_ReferenceParameter(a_validTo);
    OpcUa_ReferenceParameter(a_pNameEntries);
    OpcUa_ReferenceParameter(a_nameEntriesCount);
    OpcUa_ReferenceParameter(a_pSubjectPublicKey);
    OpcUa_ReferenceParameter(a_pExtensions);
    OpcUa_ReferenceParameter(a_extensionsCount);
    OpcUa_ReferenceParameter(a_signatureHashAlgorithm);
    OpcUa_ReferenceParameter(a_pIssuerCertificate);
    OpcUa_ReferenceParameter(a_pIssuerPrivateKey);
    OpcUa_ReferenceParameter(a_ppCertificate);

    return OpcUa_BadNotSupported;
}

/*============================================================================
 * OpcUa_P_Crypto_NoSecurity_GetPrivateKeyFromCert
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_GetPrivateKeyFromCert(
    OpcUa_CryptoProvider*       a_pProvider,
    OpcUa_StringA               a_certificate,
    OpcUa_StringA               a_password,
    OpcUa_Key*                  a_pPrivateKey)
{
    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_certificate);
    OpcUa_ReferenceParameter(a_password);
    OpcUa_ReferenceParameter(a_pPrivateKey);

    return OpcUa_BadNotSupported;
}

/*============================================================================
 * OpcUa_P_Crypto_NoSecurity_GetPublicKeyFromCert
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_GetPublicKeyFromCert(
    OpcUa_CryptoProvider*       a_pProvider,
    OpcUa_ByteString*           a_pCertificate,
    OpcUa_StringA               a_password,
    OpcUa_Key*                  a_pPublicKey)
{
    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_pCertificate);
    OpcUa_ReferenceParameter(a_password);
    OpcUa_ReferenceParameter(a_pPublicKey);

    return OpcUa_BadNotSupported;
}

/*============================================================================
 * OpcUa_P_Crypto_NoSecurity_GetSignatureFromCert
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_GetSignatureFromCert(
    OpcUa_CryptoProvider*       a_pProvider,
    OpcUa_ByteString*           a_pCertificate,
    OpcUa_Signature*            a_pSignature)
{
    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_pCertificate);
    OpcUa_ReferenceParameter(a_pSignature);

    return OpcUa_BadNotSupported;
}

/*============================================================================
 * OpcUa_P_Crypto_NoSecurity_GenerateAsymmetricKeyPair
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_GenerateAsymmetricKeyPair(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_UInt              a_type,
    OpcUa_UInt32            a_bits,
    OpcUa_Key*              a_pPublicKey,
    OpcUa_Key*              a_pPrivateKey)
{
    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_type);
    OpcUa_ReferenceParameter(a_bits);
    OpcUa_ReferenceParameter(a_pPublicKey);
    OpcUa_ReferenceParameter(a_pPrivateKey);

    return OpcUa_BadNotSupported;
}

/*============================================================================
 * OpcUa_P_OpenSSL_NoSecurity_GetAsymmetricKeyLength
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_NoSecurity_GetAsymmetricKeyLength(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_Key               a_publicKey,
    OpcUa_UInt32*           a_pBits)
{
    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_publicKey);
    OpcUa_ReferenceParameter(a_pBits);

    return OpcUa_BadNotSupported;
}
/*============================================================================
 * OpcUa_P_Crypto_NoSecurity_DeriveChannelKeysets
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_DeriveChannelKeysets(
    OpcUa_CryptoProvider*           a_pCryptoProvider,
    OpcUa_ByteString                a_clientNonce,
    OpcUa_ByteString                a_serverNonce,
    OpcUa_Int32                     a_keySize,
    OpcUa_SecurityKeyset*           a_pClientKeyset,
    OpcUa_SecurityKeyset*           a_pServerKeyset)
{
    OpcUa_ReferenceParameter(a_pCryptoProvider);
    OpcUa_ReferenceParameter(a_clientNonce);
    OpcUa_ReferenceParameter(a_serverNonce);
    OpcUa_ReferenceParameter(a_keySize);
    OpcUa_ReferenceParameter(a_pClientKeyset);
    OpcUa_ReferenceParameter(a_pServerKeyset);

    return OpcUa_BadNotSupported;
}

/*============================================================================
 * OpcUa_P_Crypto_NoSecurity_DeriveKey
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_DeriveKey(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_ByteString      a_secret,
    OpcUa_ByteString      a_seed,
    OpcUa_Int32           a_keyLen,
    OpcUa_Key*            a_pKey)
{
    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_secret);
    OpcUa_ReferenceParameter(a_seed);
    OpcUa_ReferenceParameter(a_keyLen);
    OpcUa_ReferenceParameter(a_pKey);

    return OpcUa_BadNotSupported;
}

/*============================================================================
 * OpcUa_P_Crypto_NoSecurity_GenerateKey
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_GenerateKey(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_Int32           a_keyLen,
    OpcUa_Key*            a_pKey)
{
    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_keyLen);
    OpcUa_ReferenceParameter(a_pKey);

    return OpcUa_BadNotSupported;
}

/*============================================================================
 * OpcUa_P_Crypto_NoSecurity_SymmetricEncrypt
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_SymmetricEncrypt(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_Byte*             a_pPlainText,
    OpcUa_UInt32            a_plainTextLen,
    OpcUa_Key*              a_key,
    OpcUa_Byte*             a_pInitalVector,
    OpcUa_Byte*             a_pCipherText,
    OpcUa_UInt32*           a_pCipherTextLen)
{
    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_pPlainText);
    OpcUa_ReferenceParameter(a_plainTextLen);
    OpcUa_ReferenceParameter(a_key);
    OpcUa_ReferenceParameter(a_pInitalVector);
    OpcUa_ReferenceParameter(a_pCipherText);
    OpcUa_ReferenceParameter(a_pCipherTextLen);

    return OpcUa_BadNotSupported;
}

/*============================================================================
 * OpcUa_P_Crypto_NoSecurity_SymmetricDecrypt
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_SymmetricDecrypt(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_Byte*             a_pCipherText,
    OpcUa_UInt32            a_cipherTextLen,
    OpcUa_Key*              a_key,
    OpcUa_Byte*             a_pInitalVector,
    OpcUa_Byte*             a_pPlainText,
    OpcUa_UInt32*           a_pCipherTextLen)
{
    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_pCipherText);
    OpcUa_ReferenceParameter(a_cipherTextLen);
    OpcUa_ReferenceParameter(a_key);
    OpcUa_ReferenceParameter(a_pInitalVector);
    OpcUa_ReferenceParameter(a_pPlainText);
    OpcUa_ReferenceParameter(a_pCipherTextLen);

    return OpcUa_BadNotSupported;
}

/*============================================================================
 * OpcUa_P_Crypto_NoSecurity_SymmetricSign
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_SymmetricSign(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_Byte*           a_pData,
    OpcUa_UInt32          a_dataLen,
    OpcUa_Key*            a_key,
    OpcUa_ByteString*     a_pSignature)
{
    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_pData);
    OpcUa_ReferenceParameter(a_dataLen);
    OpcUa_ReferenceParameter(a_key);
    OpcUa_ReferenceParameter(a_pSignature);

    return OpcUa_BadNotSupported;
}

/*============================================================================
 * OpcUa_P_Crypto_NoSecurity_SymmetricVerify
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_SymmetricVerify(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_Byte*           a_pData,
    OpcUa_UInt32          a_dataLen,
    OpcUa_Key*            a_key,
    OpcUa_ByteString*     a_pSignature)
{
    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_pData);
    OpcUa_ReferenceParameter(a_dataLen);
    OpcUa_ReferenceParameter(a_key);
    OpcUa_ReferenceParameter(a_pSignature);

    return OpcUa_BadNotSupported;
}

/*============================================================================
 * OpcUa_P_Crypto_NoSecurity_AsymmetricEncrypt
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_AsymmetricEncrypt(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_Byte*             a_pPlainText,
    OpcUa_UInt32            a_plainTextLen,
    OpcUa_Key*              a_publicKey,
    OpcUa_Byte*             a_pCipherText,
    OpcUa_UInt32*           a_pCipherTextLen)
{
    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_pPlainText);
    OpcUa_ReferenceParameter(a_plainTextLen);
    OpcUa_ReferenceParameter(a_publicKey);
    OpcUa_ReferenceParameter(a_pCipherText);
    OpcUa_ReferenceParameter(a_pCipherTextLen);

    return OpcUa_BadNotSupported;
}

/*============================================================================
 * OpcUa_P_Crypto_NoSecurity_AsymmetricEncrypt
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_AsymmetricDecrypt(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_Byte*             a_pCipherText,
    OpcUa_UInt32            a_cipherTextLen,
    OpcUa_Key*              a_privateKey,
    OpcUa_Byte*             a_pPlainText,
    OpcUa_UInt32*           a_pPlainTextLen)
{
    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_pCipherText);
    OpcUa_ReferenceParameter(a_cipherTextLen);
    OpcUa_ReferenceParameter(a_privateKey);
    OpcUa_ReferenceParameter(a_pPlainText);
    OpcUa_ReferenceParameter(a_pPlainTextLen);

    return OpcUa_BadNotSupported;
}

/*============================================================================
 * OpcUa_P_Crypto_NoSecurity_AsymmetricSign
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_AsymmetricSign(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_ByteString      a_data,
    OpcUa_Key*            a_privateKey,
    OpcUa_ByteString*     a_pSignature)
{
    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_data);
    OpcUa_ReferenceParameter(a_privateKey);
    OpcUa_ReferenceParameter(a_pSignature);

    return OpcUa_BadNotSupported;
}

/*============================================================================
 * OpcUa_P_Crypto_NoSecurity_AsymmetricVerify
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_AsymmetricVerify(
    OpcUa_CryptoProvider* a_pProvider,
    OpcUa_ByteString      a_data,
    OpcUa_Key*            a_publicKey,
    OpcUa_ByteString*     a_pSignature)
{
    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_data);
    OpcUa_ReferenceParameter(a_publicKey);
    OpcUa_ReferenceParameter(a_pSignature);

    return OpcUa_BadNotSupported;
}

/*============================================================================
 * OpcUa_P_Crypto_NoSecurity_GetCertificateThumbprint
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_GetCertificateThumbprint(
    OpcUa_CryptoProvider*       a_pProvider,
    OpcUa_ByteString*           a_pCertificate,
    OpcUa_ByteString*           a_pCertificateThumbprint)
{
    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_pCertificate);
    OpcUa_ReferenceParameter(a_pCertificateThumbprint);

    return OpcUa_BadNotSupported;
}

/*============================================================================
 * OpcUa_P_Crypto_NoSecurity_GetAsymmetricKeyLength
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Crypto_NoSecurity_GetAsymmetricKeyLength(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_Key               a_publicKey,
    OpcUa_UInt32*           a_pKeyLen)
{
    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_publicKey);
    OpcUa_ReferenceParameter(a_pKeyLen);

    return OpcUa_BadNotSupported;
}
