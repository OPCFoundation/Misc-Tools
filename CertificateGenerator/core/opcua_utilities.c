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
#include <opcua_utilities.h>

#define OPCUA_P_QSORT           OpcUa_ProxyStub_g_PlatformLayerCalltable->qSort
#define OPCUA_P_BSEARCH         OpcUa_ProxyStub_g_PlatformLayerCalltable->bSearch
#define OPCUA_P_GETTICKCOUNT    OpcUa_ProxyStub_g_PlatformLayerCalltable->UtilGetTickCount
#define OPCUA_P_GETLASTERROR    OpcUa_ProxyStub_g_PlatformLayerCalltable->UtilGetLastError


/*============================================================================
 * Quick Sort
 *===========================================================================*/
OpcUa_StatusCode OpcUa_QSort(   OpcUa_Void*       a_pElements,
                                OpcUa_UInt32      a_nElementCount,
                                OpcUa_UInt32      a_nElementSize,
                                OpcUa_PfnCompare* a_pfnCompare,
                                OpcUa_Void*       a_pContext)
{
    if(     a_pElements     == OpcUa_Null
        ||  a_pfnCompare    == OpcUa_Null
        ||  a_nElementCount == 0
        ||  a_nElementSize  == 0)
    {
        return OpcUa_BadInvalidArgument;
    }

    OPCUA_P_QSORT(    a_pElements,
                      a_nElementCount,
                      a_nElementSize,
                      a_pfnCompare,
                      a_pContext);

    return OpcUa_Good;
}

/*============================================================================
 * Binary Search on sorted array
 *===========================================================================*/
OpcUa_Void* OpcUa_BSearch(  OpcUa_Void*       a_pKey,
                            OpcUa_Void*       a_pElements,
                            OpcUa_UInt32      a_nElementCount,
                            OpcUa_UInt32      a_nElementSize,
                            OpcUa_PfnCompare* a_pfnCompare,
                            OpcUa_Void*       a_pContext)
{
    if(     a_pElements     == OpcUa_Null
        ||  a_pKey          == OpcUa_Null
        ||  a_pfnCompare    == OpcUa_Null
        ||  a_nElementCount == 0
        ||  a_nElementSize  == 0)
    {
        return OpcUa_Null;
    }

    return OPCUA_P_BSEARCH( a_pKey,
                            a_pElements,
                            a_nElementCount,
                            a_nElementSize,
                            a_pfnCompare,
                            a_pContext);
}

/*============================================================================
 * Access to errno
 *===========================================================================*/
OpcUa_UInt32 OpcUa_GetLastError()
{
    return OPCUA_P_GETLASTERROR();
}

/*============================================================================
 * OpcUa_GetTickCount
 *===========================================================================*/
OpcUa_UInt32 OpcUa_GetTickCount()
{
    return OPCUA_P_GETTICKCOUNT();
}
