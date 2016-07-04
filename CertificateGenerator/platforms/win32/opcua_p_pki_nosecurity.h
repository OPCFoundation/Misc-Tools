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

#ifndef _OpcUa_P_PKI_NoSecurity_H_
#define _OpcUa_P_PKI_NoSecurity_H_ 1

OPCUA_BEGIN_EXTERN_C

/**
  @brief Creates a certificate store object.

  @param pProvider                  [in]  The crypto provider handle.

  @param ppCertificateStore         [out] The handle to the certificate store. Type depends on store implementation.
*/
OpcUa_StatusCode OpcUa_P_PKI_NoSecurity_OpenCertificateStore(
    OpcUa_PKIProvider*          pProvider,
    OpcUa_Void**                ppCertificateStore);

/**
  @brief frees a certificate store object.

  @param pProvider             [in]  The crypto provider handle.
  @param ppCertificateStore    [in] The certificate store object. Type depends on store implementation.
*/
OpcUa_StatusCode OpcUa_P_PKI_NoSecurity_CloseCertificateStore(
    OpcUa_PKIProvider*          pProvider,
    OpcUa_Void**                ppCertificateStore);

/**
  @brief Validates a given X509 certificate object.

   Validation:
   - Subject/Issuer
   - Path
   - Certificate Revocation List (CRL)
   - Certificate Trust List (CTL)

  @param pProvider                [in]  The crypto provider handle.
  @param pCertificate             [in]  The certificate that should be validated.
  @param pCertificateStore        [in]  The certificate store that validates the passed in certificate.

  @param pValidationCode          [out] The validation code, that gives information about the validation result. Validation return codes from OpenSSL are used.
*/
OpcUa_StatusCode OpcUa_P_PKI_NoSecurity_ValidateCertificate(
    OpcUa_PKIProvider*          pProvider,
    OpcUa_ByteString*           pCertificate,
    OpcUa_Void*                 pCertificateStore,
    OpcUa_Int*                  pValidationCode /* Validation return codes from OpenSSL */);

/**
  @brief imports a given certificate into given certificate store.

  @param pProvider                [in]  The crypto provider handle.
  @param pCertificateStore        [in]  The certificate store that should store the passed in certificate.
  @param pCertificate             [in]  The certificate that should be stored in the certificate store.
  @param pSaveHandle              [out]  The handle that indicates the save location of the certificate within then certificate store.
*/
OpcUa_StatusCode OpcUa_P_PKI_NoSecurity_SaveCertificate(
    OpcUa_PKIProvider*          pProvider,
    OpcUa_ByteString*           pCertificate,
    OpcUa_Void*                 pCertificateStore,
    OpcUa_Void*                 pSaveHandle);

/**
  @brief exports a certain certificate from a given certificate store.

  @param pProvider                [in]  The crypto provider handle.
  @param pLoadHandle              [in]  The handle that indicates the load location of the certificate within then certificate store.
  @param ppCertificateStore       [in]  The certificate store that contains the desired certificate.

  @param pCertificate             [out] The desired certificate.
*/
OpcUa_StatusCode OpcUa_P_PKI_NoSecurity_LoadCertificate(
    OpcUa_PKIProvider*          pProvider,
    OpcUa_Void*                 pLoadHandle,
    OpcUa_Void*                 pCertificateStore,
    OpcUa_ByteString*           pCertificate);

/**
  @brief exports a certain certificate from a given certificate store.

  @param pProvider                [in]  Load handle of the key file (ie. path in directory based PKI's).
  @param pLoadHandle              [in]  The format in which the key is stored.
  @param ppCertificateStore       [in]  The password if the key file is password secured.

  @param pCertificate             [out] The desired private key.
*/
OpcUa_StatusCode OpcUa_P_PKI_NoSecurity_LoadPrivateKeyFromFile(
    OpcUa_StringA               privateKeyFile,
    OpcUa_P_FileFormat          fileFormat,
    OpcUa_StringA               password,
    OpcUa_ByteString*           pPrivateKey);

OPCUA_END_EXTERN_C

#endif /* _OpcUa_P_PKI_NoSecurity_H_ */
