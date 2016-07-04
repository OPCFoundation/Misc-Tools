/* ========================================================================
 * Copyright (c) 2005-2011 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Reciprocal Community License ("RCL") Version 1.00
 *
 * Unless explicitly acquired and licensed from Licensor under another
 * license, the contents of this file are subject to the Reciprocal
 * Community License ("RCL") Version 1.00, or subsequent versions as
 * allowed by the RCL, and You may not copy or use this file in either
 * source code or executable form, except in compliance with the terms and
 * conditions of the RCL.
 *
 * All software distributed under the RCL is provided strictly on an
 * "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED,
 * AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT
 * LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RCL for specific
 * language governing rights and limitations under the RCL.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/RCL/1.00/
 * ======================================================================*/

/* core */
#include <opcua.h>

/* own */
#include <opcua_pki.h>

/*============================================================================
 * OpcUa_PKIProvider_ValidateCertificate
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_PKIProvider_ValidateCertificate(
    struct _OpcUa_PKIProvider*  a_pPKI,
    OpcUa_ByteString*           a_pCertificate,
    OpcUa_Void*                 a_pCertificateStore,
    OpcUa_Int*                  a_pValidationCode) /* Validation return codes from OpenSSL */
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_PkiProvider);
    OpcUa_ReturnErrorIfArgumentNull(a_pPKI);
    OpcUa_ReturnErrorIfNull(a_pPKI->ValidateCertificate, OpcUa_BadNotSupported);

    return a_pPKI->ValidateCertificate(a_pPKI, a_pCertificate, a_pCertificateStore, a_pValidationCode);
}

/*============================================================================
 * OpcUa_PKIProvider_OpenCertificateStore
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_PKIProvider_OpenCertificateStore(
    struct _OpcUa_PKIProvider*  a_pPKI,
    OpcUa_Void**                a_ppCertificateStore)        /* type depends on store implementation */
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_PkiProvider);
    OpcUa_ReturnErrorIfArgumentNull(a_pPKI);
    OpcUa_ReturnErrorIfNull(a_pPKI->OpenCertificateStore, OpcUa_BadNotSupported);

    return a_pPKI->OpenCertificateStore(a_pPKI, a_ppCertificateStore);
}

/*============================================================================
 * OpcUa_PKIProvider_SaveCertificate
 *===========================================================================*/
OpcUa_StatusCode OpcUa_PKIProvider_LoadCertificate(
    struct _OpcUa_PKIProvider*  a_pPKI,
    OpcUa_Void*                 a_pLoadHandle,
    OpcUa_Void*                 a_pCertificateStore,
    OpcUa_ByteString*           a_pCertificate)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_PkiProvider);
    OpcUa_ReturnErrorIfArgumentNull(a_pPKI);
    OpcUa_ReturnErrorIfNull(a_pPKI->SaveCertificate, OpcUa_BadNotSupported);

    return a_pPKI->LoadCertificate(a_pPKI, a_pLoadHandle, a_pCertificateStore, a_pCertificate);
}

/*============================================================================
 * OpcUa_PKIProvider_SaveCertificate
 *===========================================================================*/
OpcUa_StatusCode OpcUa_PKIProvider_SaveCertificate(
    struct _OpcUa_PKIProvider*  a_pPKI,
    OpcUa_ByteString*           a_pCertificate,
    OpcUa_Void*                 a_pCertificateStore,
    OpcUa_Void*                 a_pSaveHandle)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_PkiProvider);
    OpcUa_ReturnErrorIfArgumentNull(a_pPKI);
    OpcUa_ReturnErrorIfNull(a_pPKI->SaveCertificate, OpcUa_BadNotSupported);

    return a_pPKI->SaveCertificate(a_pPKI, a_pCertificate, a_pCertificateStore, a_pSaveHandle);
}
/*============================================================================
 * OpcUa_PKIProvider_CloseCertificateStore
 *===========================================================================*/
OpcUa_StatusCode OpcUa_PKIProvider_CloseCertificateStore(
    struct _OpcUa_PKIProvider*   a_pPKI,
    OpcUa_Void**                 a_ppCertificateStore) /* type depends on store implementation */
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_PkiProvider);
    OpcUa_ReturnErrorIfArgumentNull(a_pPKI);
    OpcUa_ReturnErrorIfNull(a_pPKI->CloseCertificateStore, OpcUa_BadNotSupported);

    return a_pPKI->CloseCertificateStore(a_pPKI, a_ppCertificateStore);
}
