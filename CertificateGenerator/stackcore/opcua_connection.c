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

#include <opcua.h>
#include <opcua_mutex.h>
#include <opcua_semaphore.h>
#include <opcua_connection.h>
#include <opcua_statuscodes.h>

/*============================================================================
 * OpcUa_Connection_Connect
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Connection_Connect(
    OpcUa_Connection*               a_pConnection,
    OpcUa_String*                   a_sUrl,
    OpcUa_ClientCredential*         a_pCredentials,
    OpcUa_UInt32                    a_uTimeout,
    OpcUa_Connection_PfnOnNotify*   a_pCallback,
    OpcUa_Void*                     a_pCallbackData)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_Connection);
    OpcUa_ReturnErrorIfArgumentNull(a_pConnection);
    OpcUa_ReturnErrorIfArgumentNull(a_pConnection->Connect);

    return a_pConnection->Connect(a_pConnection, a_sUrl, a_pCredentials, a_uTimeout, a_pCallback, a_pCallbackData);
}

/*============================================================================
 * OpcUa_Connection_Disconnect
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Connection_Disconnect(
    struct _OpcUa_Connection* a_pConnection,
    OpcUa_Boolean             a_bNotifyOnComplete)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_Connection);
    OpcUa_ReturnErrorIfArgumentNull(a_pConnection);
    OpcUa_ReturnErrorIfArgumentNull(a_pConnection->Disconnect);

    return a_pConnection->Disconnect(a_pConnection, a_bNotifyOnComplete);
}

/*============================================================================
 * OpcUa_Connection_BeginSendRequest
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Connection_BeginSendRequest(
    OpcUa_Connection*    a_pConnection,
    OpcUa_OutputStream** a_ppOstrm)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_Connection);
    OpcUa_ReturnErrorIfArgumentNull(a_pConnection);
    OpcUa_ReturnErrorIfArgumentNull(a_pConnection->BeginSendRequest);

    return a_pConnection->BeginSendRequest(a_pConnection, a_ppOstrm);
}

/*============================================================================
 * OpcUa_Connection_EndSendRequest
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Connection_EndSendRequest(
    struct _OpcUa_Connection*       a_pConnection,
    OpcUa_OutputStream**            a_ppOstrm,
    OpcUa_UInt32                    a_uMsecTimeout,
    OpcUa_Connection_PfnOnResponse* a_pCallback,
    OpcUa_Void*                     a_pCallbackData)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_Connection);
    OpcUa_ReturnErrorIfArgumentNull(a_pConnection);
    OpcUa_ReturnErrorIfArgumentNull(a_pConnection->EndSendRequest);

    return a_pConnection->EndSendRequest(a_pConnection, a_ppOstrm, a_uMsecTimeout, a_pCallback, a_pCallbackData);
}

/*============================================================================
 * OpcUa_Connection_AbortSendRequest
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Connection_AbortSendRequest(
    struct _OpcUa_Connection*   a_pConnection,
    OpcUa_StatusCode            a_uStatus,
    OpcUa_String*               a_psReason,
    OpcUa_OutputStream**        a_ppOstrm)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_Connection);
    OpcUa_ReturnErrorIfArgumentNull(a_pConnection);
    OpcUa_ReturnErrorIfArgumentNull(a_pConnection->AbortSendRequest);

    return a_pConnection->AbortSendRequest(a_pConnection, a_uStatus, a_psReason, a_ppOstrm);
}

/*============================================================================
 * OpcUa_Connection_AbortSendRequest
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Connection_GetReceiveBufferSize(
    struct _OpcUa_Connection* a_pConnection,
    OpcUa_UInt32*             a_pBufferSize)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_Connection);
    OpcUa_ReturnErrorIfArgumentNull(a_pConnection);
    OpcUa_ReturnErrorIfArgumentNull(a_pConnection->GetReceiveBufferSize);

    return a_pConnection->GetReceiveBufferSize(a_pConnection, a_pBufferSize);
}

/*============================================================================
 * OpcUa_Connection_Delete
 *===========================================================================*/
OpcUa_Void OpcUa_Connection_Delete(OpcUa_Connection** a_ppConnection)
{
    if (a_ppConnection != OpcUa_Null && *a_ppConnection != OpcUa_Null)
    {
        (*a_ppConnection)->Delete(a_ppConnection);
    }
}
