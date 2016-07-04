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
#include <opcua_thread.h>

#include <opcua_trace.h>

#define OPCUA_P_TRACE               OpcUa_ProxyStub_g_PlatformLayerCalltable->Trace
#define OPCUA_P_TRACE_INITIALIZE    OpcUa_ProxyStub_g_PlatformLayerCalltable->TraceInitialize
#define OPCUA_P_TRACE_CLEAR         OpcUa_ProxyStub_g_PlatformLayerCalltable->TraceClear

#define OPCUA_P_STRINGA_VSNPRINTF   OpcUa_ProxyStub_g_PlatformLayerCalltable->StrVsnPrintf

/*============================================================================
 * Trace Lock
 *===========================================================================*/
/**
* Global Trace Buffer.
*/
OpcUa_CharA OpcUa_Trace_g_aTraceBuffer[OPCUA_TRACE_MAXLENGTH];

#if OPCUA_TRACE_FILE_LINE_INFO
OpcUa_CharA OpcUa_Trace_g_aFormatBuffer[OPCUA_TRACE_MAXLENGTH];
#endif

/*============================================================================
 * Trace Lock
 *===========================================================================*/
/**
* Global Mutex to synchronize access to the trace device.
*/
#if OPCUA_USE_SYNCHRONISATION
OpcUa_Mutex OpcUa_Trace_s_pLock = OpcUa_Null;
#endif /* OPCUA_USE_SYNCHRONISATION */


/*============================================================================
 * Trace Initialize
 *===========================================================================*/
/**
* Initialize all ressources needed for tracing.
*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_Trace_Initialize(OpcUa_Void)
{
    OpcUa_StatusCode    uStatus = OpcUa_Good;

#if OPCUA_USE_SYNCHRONISATION
    uStatus = OPCUA_P_MUTEX_CREATE(&OpcUa_Trace_s_pLock);
    OpcUa_ReturnErrorIfBad(uStatus);
#endif /* OPCUA_USE_SYNCHRONISATION */

    uStatus = OPCUA_P_TRACE_INITIALIZE();

    return uStatus;
}

/*============================================================================
 * Trace Clear
 *===========================================================================*/
/**
* Clear all ressources needed for tracing.
*/
OpcUa_Void OPCUA_DLLCALL OpcUa_Trace_Clear(OpcUa_Void)
{
#if OPCUA_USE_SYNCHRONISATION
    OPCUA_P_MUTEX_DELETE(&OpcUa_Trace_s_pLock);
#endif /* OPCUA_USE_SYNCHRONISATION */
    OPCUA_P_TRACE_CLEAR();
}

/*============================================================================
 * Activate/Deactivate Trace
 *===========================================================================*/
/**
 * Activate or deactivate trace output during runtime.
 * @param a_bActive Description
 */
OpcUa_Void OPCUA_DLLCALL OpcUa_Trace_Toggle(OpcUa_Boolean a_bActive)
{
#if OPCUA_USE_SYNCHRONISATION
    if(OpcUa_Trace_s_pLock == OpcUa_Null)
    {
        return;
    }
    OPCUA_P_MUTEX_LOCK(OpcUa_Trace_s_pLock);
#endif /* OPCUA_USE_SYNCHRONISATION */

    /* check if app wants trace output */
    OpcUa_ProxyStub_g_Configuration.bProxyStub_Trace_Enabled = a_bActive;

#if OPCUA_USE_SYNCHRONISATION
    OPCUA_P_MUTEX_UNLOCK(OpcUa_Trace_s_pLock);
#endif /* OPCUA_USE_SYNCHRONISATION */

    return;
}

/*============================================================================
 * Change Trace Level
 *===========================================================================*/
/**
 * Activate or deactivate trace output during runtime.
 * @param a_uNewTraceLevel Description
 */
OpcUa_Void OPCUA_DLLCALL OpcUa_Trace_ChangeTraceLevel(OpcUa_UInt32 a_uNewTraceLevel)
{
#if OPCUA_USE_SYNCHRONISATION
    if(OpcUa_Trace_s_pLock == OpcUa_Null)
    {
        return;
    }
    OPCUA_P_MUTEX_LOCK(OpcUa_Trace_s_pLock);
#endif /* OPCUA_USE_SYNCHRONISATION */

    OpcUa_ProxyStub_g_Configuration.uProxyStub_Trace_Level = a_uNewTraceLevel;

#if OPCUA_USE_SYNCHRONISATION
    OPCUA_P_MUTEX_UNLOCK(OpcUa_Trace_s_pLock);
#endif /* OPCUA_USE_SYNCHRONISATION */

    return;
}

/*============================================================================
 * Tracefunction
 *===========================================================================*/
/**
* Writes the given string and the parameters to the trace device, if the given
* trace level is activated.
*/
OpcUa_Boolean OPCUA_DLLCALL OpcUa_Trace_Imp(OpcUa_UInt32       a_uTraceLevel,
                                            const OpcUa_CharA* a_sFormat,
#if OPCUA_TRACE_FILE_LINE_INFO
                                            const OpcUa_CharA* a_sFile,
                                            OpcUa_UInt32       a_sLine,
#endif /* OPCUA_TRACE_FILE_LINE_INFO */
                                            ...)
{
#if OPCUA_TRACE_ENABLE
    OpcUa_Boolean bTraced = OpcUa_False;

#if OPCUA_USE_SYNCHRONISATION
    if(OpcUa_Trace_s_pLock == OpcUa_Null)
    {
        return OpcUa_False;
    }
    OPCUA_P_MUTEX_LOCK(OpcUa_Trace_s_pLock);
#endif /* OPCUA_USE_SYNCHRONISATION */

    /* check if app wants trace output */
    if(OpcUa_ProxyStub_g_Configuration.bProxyStub_Trace_Enabled == OpcUa_False)
    {
#if OPCUA_USE_SYNCHRONISATION
        OPCUA_P_MUTEX_UNLOCK(OpcUa_Trace_s_pLock);
#endif /* OPCUA_USE_SYNCHRONISATION */
        return OpcUa_False;
    }

    if(a_uTraceLevel & OpcUa_ProxyStub_g_Configuration.uProxyStub_Trace_Level)
    {
        OpcUa_P_VA_List argumentList;
#if OPCUA_TRACE_FILE_LINE_INFO
        OpcUa_Int iLen = 0;
        OPCUA_P_VA_START(argumentList, a_sLine);
#else
        OPCUA_P_VA_START(argumentList, a_sFormat);
#endif /* OPCUA_TRACE_FILE_LINE_INFO */

#if OPCUA_TRACE_FILE_LINE_INFO
        iLen = OpcUa_SnPrintfA( OpcUa_Trace_g_aFormatBuffer,
                                OPCUA_TRACE_MAXLENGTH - 1,
#if OPCUA_TRACE_PREPEND_FILE_LINE
                                OPCUA_TRACE_FILE_LINE_INFO_FORMAT"%s",
#else /* OPCUA_TRACE_PREPEND_FILE_LINE */
                                "%s"OPCUA_TRACE_FILE_LINE_INFO_FORMAT,
#endif /* OPCUA_TRACE_PREPEND_FILE_LINE */
#if OPCUA_TRACE_FILE_LINE_ORDER
                                a_sFile, a_sLine,
#else /* OPCUA_TRACE_FILE_LINE_ORDER */
                                a_sLine, a_sFile,
#endif /* OPCUA_TRACE_FILE_LINE_ORDER */
                                a_sFormat);

        if(iLen > 0)
        {
#endif /* OPCUA_TRACE_FILE_LINE_INFO */
            /* write trace buffer */
            OPCUA_P_STRINGA_VSNPRINTF(  OpcUa_Trace_g_aTraceBuffer,
                                        OPCUA_TRACE_MAXLENGTH - 1,
#if OPCUA_TRACE_FILE_LINE_INFO
                                        OpcUa_Trace_g_aFormatBuffer,
#else /* OPCUA_TRACE_FILE_LINE_INFO */
                                        (const OpcUa_StringA)a_sFormat,
#endif /* OPCUA_TRACE_FILE_LINE_INFO */
                                        argumentList);

            OpcUa_Trace_g_aTraceBuffer[OPCUA_TRACE_MAXLENGTH - 1] = '\0';

            /* send trace buffer to platform trace device */
            OPCUA_P_TRACE(OpcUa_Trace_g_aTraceBuffer);

            bTraced = OpcUa_True;
#if OPCUA_TRACE_FILE_LINE_INFO
        }
#endif /* OPCUA_TRACE_FILE_LINE_INFO */

        OPCUA_P_VA_END(argumentList);
    }

#if OPCUA_USE_SYNCHRONISATION
        OPCUA_P_MUTEX_UNLOCK(OpcUa_Trace_s_pLock);
#endif /* OPCUA_USE_SYNCHRONISATION */

    return bTraced;

#else /* OPCUA_TRACE_ENABLE == NO */

    OpcUa_ReferenceParameter(a_uTraceLevel);
    OpcUa_ReferenceParameter(a_sFormat);

    return OpcUa_False;

#endif /* if OPCUA_TRACE_ENABLE == YES */
}
