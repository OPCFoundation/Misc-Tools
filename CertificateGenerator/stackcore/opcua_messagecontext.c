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
#include <opcua_messagecontext.h>

/*============================================================================
 * OpcUa_MessageContext_Initialize
 *===========================================================================*/
OpcUa_Void OpcUa_MessageContext_Initialize(OpcUa_MessageContext* a_pContext)
{
    if (a_pContext != OpcUa_Null)
    {
        OpcUa_MemSet(a_pContext, 0, sizeof(OpcUa_MessageContext));

        a_pContext->MaxArrayLength      = OpcUa_ProxyStub_g_Configuration.iSerializer_MaxArrayLength;
        a_pContext->MaxStringLength     = OpcUa_ProxyStub_g_Configuration.iSerializer_MaxStringLength;
        a_pContext->MaxByteStringLength = OpcUa_ProxyStub_g_Configuration.iSerializer_MaxByteStringLength;
        a_pContext->MaxMessageLength    = OpcUa_ProxyStub_g_Configuration.iSerializer_MaxMessageSize;
    }
}

/*============================================================================
 * OpcUa_MessageContext_Initialize
 *===========================================================================*/
OpcUa_Void OpcUa_MessageContext_Clear(OpcUa_MessageContext* a_pContext)
{
    if (a_pContext != OpcUa_Null)
    {
        OpcUa_MemSet(a_pContext, 0, sizeof(OpcUa_MessageContext));
    }
}
