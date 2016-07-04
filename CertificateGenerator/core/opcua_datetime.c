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
#include <opcua_datetime.h>

#define OpcUa_P_DateTime_UtcNow                 OpcUa_ProxyStub_g_PlatformLayerCalltable->UtcNow
#define OpcUa_P_DateTime_GetTimeOfDay           OpcUa_ProxyStub_g_PlatformLayerCalltable->GetTimeOfDay
#define OpcUa_P_DateTime_GetDateTimeFromString  OpcUa_ProxyStub_g_PlatformLayerCalltable->GetDateTimeFromString
#define OpcUa_P_DateTime_GetStringFromDateTime  OpcUa_ProxyStub_g_PlatformLayerCalltable->GetStringFromDateTime

/*============================================================================*/
OpcUa_StatusCode OpcUa_DateTime_GetTimeOfDay(OpcUa_TimeVal* a_pValue)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_DateTime);
    OpcUa_ReturnErrorIfArgumentNull(a_pValue);

    OpcUa_P_DateTime_GetTimeOfDay(a_pValue);

    return OpcUa_Good;
}

/*============================================================================*/
OpcUa_StatusCode OpcUa_DateTime_GetDateTimeFromString(  OpcUa_StringA   a_pchDateTimeString,
                                                        OpcUa_DateTime* a_pDateTime)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_DateTime);
    OpcUa_ReturnErrorIfArgumentNull(a_pchDateTimeString);
    OpcUa_ReturnErrorIfArgumentNull(a_pDateTime);

    return OpcUa_P_DateTime_GetDateTimeFromString(a_pchDateTimeString, a_pDateTime);
}

/*============================================================================*/
OpcUa_StatusCode OpcUa_DateTime_GetStringFromDateTime(  OpcUa_DateTime  a_dateTime,
                                                        OpcUa_StringA   a_pBuffer,
                                                        OpcUa_UInt32    a_uLength)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_DateTime);
    OpcUa_ReturnErrorIfArgumentNull(a_pBuffer);

    if(a_uLength < 25)
    {
        return OpcUa_BadInvalidArgument;
    }

    return OpcUa_P_DateTime_GetStringFromDateTime(a_dateTime, a_pBuffer, a_uLength);
}
