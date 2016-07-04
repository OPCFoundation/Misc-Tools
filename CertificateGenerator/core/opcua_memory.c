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
#include <opcua_trace.h>

#include <opcua_memory.h>

#define OPCUA_P_MEMORY_ALLOC    OpcUa_ProxyStub_g_PlatformLayerCalltable->MemAlloc
#define OPCUA_P_MEMORY_REALLOC  OpcUa_ProxyStub_g_PlatformLayerCalltable->MemReAlloc
#define OPCUA_P_MEMORY_FREE     OpcUa_ProxyStub_g_PlatformLayerCalltable->MemFree
#define OPCUA_P_MEMORY_MEMCPY   OpcUa_ProxyStub_g_PlatformLayerCalltable->MemCpy

/*============================================================================
 * OpcUa_Memory_Alloc
 *===========================================================================*/
OpcUa_Void* OPCUA_DLLCALL OpcUa_Memory_Alloc(OpcUa_UInt32 nSize)
{
    return OPCUA_P_MEMORY_ALLOC(nSize);
}

/*============================================================================
 * OpcUa_Memory_ReAlloc
 *===========================================================================*/
OpcUa_Void* OPCUA_DLLCALL OpcUa_Memory_ReAlloc(   OpcUa_Void*     a_pBuffer,
                                                  OpcUa_UInt32    a_nSize)
{
    return OPCUA_P_MEMORY_REALLOC(  a_pBuffer,
                                    a_nSize);
}

/*============================================================================
 * OpcUa_Memory_Free
 *===========================================================================*/
OpcUa_Void OPCUA_DLLCALL OpcUa_Memory_Free(OpcUa_Void* a_pBuffer)
{
    if(a_pBuffer != OpcUa_Null)
    {
        OPCUA_P_MEMORY_FREE(a_pBuffer);
    }
}

/*============================================================================
 * OpcUa_Memory_MemCpy
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_Memory_MemCpy(   OpcUa_Void*     a_pBuffer,
                                        OpcUa_UInt32    a_nSizeInBytes,
                                        OpcUa_Void*     a_pSource,
                                        OpcUa_UInt32    a_nCount)
{

    return OPCUA_P_MEMORY_MEMCPY(   a_pBuffer,
                                    a_nSizeInBytes,
                                    a_pSource,
                                    a_nCount);
}
