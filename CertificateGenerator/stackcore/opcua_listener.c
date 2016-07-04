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
#include <opcua_listener.h>

/*============================================================================
 * OpcUa_Listener_Open
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Listener_Open(
    struct _OpcUa_Listener*     a_pListener,
    OpcUa_String*               a_sUrl,
    OpcUa_Listener_PfnOnNotify* a_pCallback,
    OpcUa_Void*                 a_pCallbackData)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_Listener);
    OpcUa_ReturnErrorIfArgumentNull(a_pListener);
    OpcUa_ReturnErrorIfArgumentNull(a_pListener->Open);
    OpcUa_ReturnErrorIfArgumentNull(a_pCallback);

    return a_pListener->Open(a_pListener, a_sUrl, a_pCallback, a_pCallbackData);
}

/*============================================================================
 * OpcUa_Listener_Close
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Listener_Close(OpcUa_Listener* a_pListener)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_Listener);
    OpcUa_ReturnErrorIfArgumentNull(a_pListener);
    OpcUa_ReturnErrorIfArgumentNull(a_pListener->Open);

    return a_pListener->Close(a_pListener);
}

/*============================================================================
 * OpcUa_Listener_BeginSendResponse
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Listener_BeginSendResponse(
    OpcUa_Listener*      a_pListener,
    OpcUa_Handle         a_hConnection,
    OpcUa_InputStream**  a_ppIstrm,
    OpcUa_OutputStream** a_ppOstrm)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_Listener);
    OpcUa_ReturnErrorIfArgumentNull(a_pListener);
    OpcUa_ReturnErrorIfArgumentNull(a_pListener->BeginSendResponse);

    return a_pListener->BeginSendResponse(a_pListener, a_hConnection, a_ppIstrm, a_ppOstrm);
}

/*============================================================================
 * OpcUa_Listener_EndSendResponse
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Listener_EndSendResponse(
    struct _OpcUa_Listener* a_pListener,
    OpcUa_StatusCode        a_uStatus,
    OpcUa_OutputStream**    a_ppOstrm)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_Listener);
    OpcUa_ReturnErrorIfArgumentNull(a_pListener);
    OpcUa_ReturnErrorIfArgumentNull(a_pListener->EndSendResponse);

    return a_pListener->EndSendResponse(a_pListener, a_uStatus, a_ppOstrm);
}

/*============================================================================
 * OpcUa_Listener_AbortSendResponse
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Listener_AbortSendResponse(
    struct _OpcUa_Listener* a_pListener,
    OpcUa_StatusCode        a_uStatus,
    OpcUa_String*           a_psReason,
    OpcUa_OutputStream**    a_ppOstrm)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_Listener);
    OpcUa_ReturnErrorIfArgumentNull(a_pListener);
    OpcUa_ReturnErrorIfArgumentNull(a_pListener->AbortSendResponse);

    return a_pListener->AbortSendResponse(a_pListener, a_uStatus, a_psReason, a_ppOstrm);
}

/*============================================================================
 * OpcUa_Listener_GetReceiveBufferSize
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_Listener_GetReceiveBufferSize(
    struct _OpcUa_Listener* a_pListener,
    OpcUa_Handle            a_hConnection,
    OpcUa_UInt32*           a_pBufferSize)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_Listener);
    OpcUa_ReturnErrorIfArgumentNull(a_pListener);
    OpcUa_ReturnErrorIfArgumentNull(a_pListener->GetReceiveBufferSize);

    return a_pListener->GetReceiveBufferSize(a_pListener, a_hConnection, a_pBufferSize);
}

/*============================================================================
 * OpcUa_Listener_Delete
 *===========================================================================*/
OpcUa_Void OpcUa_Listener_Delete(OpcUa_Listener** a_pListener)
{
    if (a_pListener != OpcUa_Null && *a_pListener != OpcUa_Null)
    {
        (*a_pListener)->Delete(a_pListener);
    }
}
