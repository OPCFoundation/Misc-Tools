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

/******************************************************************************************************/
/* Platform Portability Layer                                                                         */
/* Modify the content of this file according to the guid implementation on your system or emulate     */
/* the uuid generation process in this file.                                                          */
/******************************************************************************************************/

/* base includes */
#include <opcua_p_internal.h>

/* all platform modules */
#include <opcua_p_datetime.h>
#include <opcua_p_guid.h>
#include <opcua_p_memory.h>
#include <opcua_p_mutex.h>
#include <opcua_p_semaphore.h>
#include <opcua_p_socket_interface.h>
#include <opcua_p_string.h>
#include <opcua_p_thread.h>
#include <opcua_p_trace.h>
#include <opcua_p_socket.h>
#include <opcua_p_timer.h>
#include <opcua_p_utilities.h>

#include <opcua_p_cryptofactory.h>
#include <opcua_p_pkifactory.h>

#if OPCUA_REQUIRE_OPENSSL
#include <opcua_p_openssl.h>
/* openssl version information */
#include <openssl/opensslv.h>
#endif /* OPCUA_REQUIRE_OPENSSL */

#include <opcua_p_wincrypt.h>

#ifdef OPCUA_HAVE_XMLAPI
#include <opcua_p_libxml2.h>
/* libxml2 version information */
#include <libxml/xmlversion.h>
#endif /* OPCUA_HAVE_XMLAPI */

#ifndef OPCUA_P_VERSIONSTRING
# define OPCUA_P_VERSIONSTRING "Win32_VersionNotSet"
#endif /* OPCUA_P_VERSIONSTRING */

#ifndef OPCUA_P_CONFIGSTRING
# define OPCUA_P_CONFIGSTRING "Win32_ConfigNotSet"
#endif /* OPCUA_P_CONFIGSTRING */

OpcUa_StringA OpcUa_P_g_VersionString       = OPCUA_P_VERSIONSTRING;
OpcUa_Boolean OpcUa_P_g_FreeVersionString   = OpcUa_False;

OpcUa_StringA OpcUa_P_g_ConfigString  = OPCUA_P_CONFIGSTRING;

/*============================================================================
 * g_OpcUa_Port_CallTable
 *===========================================================================*/
/** @brief static calltable for accessing platform layer functions. */
OpcUa_Port_CallTable g_OpcUa_Port_CallTable =
{
    0,                      /* version number */
    OpcUa_Null,

    /* Memory */
    OpcUa_P_Memory_Alloc,
    OpcUa_P_Memory_Free,
    OpcUa_P_Memory_ReAlloc,
    OpcUa_P_Memory_MemCpy,  /* OpcUa_P_Memory_MemCpy may be removed */
    OpcUa_Null,             /* OpcUa_P_Memory_MemSet may be removed */

    /* DateTime */
    OpcUa_P_DateTime_UtcNow,
    OpcUa_P_DateTime_GetTimeOfDay,
    OpcUa_P_DateTime_GetStringFromDateTime,
    OpcUa_P_DateTime_GetDateTimeFromString,

    /* Mutex */
    OpcUa_P_Mutex_CreateImp,
    OpcUa_P_Mutex_DeleteImp,
    OpcUa_P_Mutex_LockImp,
    OpcUa_P_Mutex_UnlockImp,

    /* Guid */
    OpcUa_P_Guid_Create,

    /* Semaphore */
    OpcUa_P_Semaphore_Create,
    OpcUa_P_Semaphore_Delete,
    OpcUa_P_Semaphore_Wait,
    OpcUa_P_Semaphore_TimedWait,
    OpcUa_P_Semaphore_Post,

    /* Thread */
    OpcUa_P_Thread_Create,
    OpcUa_P_Thread_Delete,
    OpcUa_P_Thread_Start,
    OpcUa_P_Thread_Sleep,
    OpcUa_P_Thread_GetCurrentThreadId,

    /* Trace */
    OpcUa_P_Trace,
    OpcUa_P_Trace_Initialize,
    OpcUa_P_Trace_Clear,

    /* String */
    OpcUa_P_String_strncpy,
    OpcUa_P_String_strncat,
    OpcUa_P_String_strlen,
    OpcUa_P_String_strncmp,
    OpcUa_P_String_strnicmp,
    OpcUa_P_String_vsnprintf,

    /* Utilities */
    OpcUa_P_QSort,
    OpcUa_P_BSearch,
    OpcUa_P_GetLastError,
    OpcUa_P_GetTickCount,
    OpcUa_P_CharAToInt,

    /* Network */
    OpcUa_P_Socket_InetAddr,
    OpcUa_P_SocketManager_Create,
    OpcUa_P_SocketManager_Delete,
    OpcUa_P_SocketManager_CreateServer,
    OpcUa_P_SocketManager_CreateClient,
    OpcUa_P_SocketManager_SignalEvent,
    OpcUa_P_SocketManager_ServeLoop,
    OpcUa_P_Socket_Read,
    OpcUa_P_Socket_Write,
    OpcUa_P_Socket_Close,
    OpcUa_P_Socket_GetPeerInfo,
    OpcUa_P_Socket_GetLastError,
    OpcUa_P_Socket_InitializeNetwork,
    OpcUa_P_Socket_CleanupNetwork,

    /* Security */
    OpcUa_P_CryptoFactory_CreateCryptoProvider,
    OpcUa_P_CryptoFactory_DeleteCryptoProvider,
    OpcUa_P_PKIFactory_CreatePKIProvider,
    OpcUa_P_PKIFactory_DeletePKIProvider,

    /* Timer */
    OpcUa_P_Timer_Create,
    OpcUa_P_Timer_Delete,
    OpcUa_P_Timer_CleanupTimers

    /* Xml */
#ifdef OPCUA_HAVE_XMLAPI
    ,
    OpcUa_P_Libxml2_XmlWriter_Create,
    OpcUa_P_Libxml2_XmlWriter_Delete,
    OpcUa_P_Libxml2_XmlReader_Create,
    OpcUa_P_Libxml2_XmlReader_Delete
#endif /* OPCUA_HAVE_XMLAPI */
};

/*============================================================================
 * OpcUa_P_Initialize
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_Initialize(OpcUa_Handle* a_pPlatformLayerHandle)
{
    OpcUa_StatusCode uStatus = OpcUa_Good;

    OpcUa_ReturnErrorIfArgumentNull(a_pPlatformLayerHandle);

    /* was this function called before */
    if(g_OpcUa_Port_CallTable.pReserved != OpcUa_Null)
    {
        return OpcUa_BadInvalidState;
    }

    /* marked as initialized */
    g_OpcUa_Port_CallTable.pReserved = (OpcUa_Void*)1;

    uStatus = OpcUa_P_InitializeTimers();
    OpcUa_ReturnErrorIfBad(uStatus);

#if OPCUA_REQUIRE_OPENSSL
    uStatus = OpcUa_P_OpenSSL_Initialize();
    OpcUa_ReturnErrorIfBad(uStatus);
#endif /* OPCUA_REQUIRE_OPENSSL */

    uStatus = OpcUa_P_WinCrypt_Initialize();
    // OpcUa_ReturnErrorIfBad(uStatus);
    uStatus = OpcUa_Good;

#ifdef OPCUA_HAVE_XMLAPI
    OpcUa_P_Libxml2_Initialize();
#endif /* OPCUA_HAVE_XMLAPI */

    /* assign call table */
    *a_pPlatformLayerHandle = (OpcUa_Handle)&g_OpcUa_Port_CallTable;

    return uStatus;
}

/*============================================================================
 * OpcUa_P_Clean
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_Clean(OpcUa_Handle* a_pPlatformLayerHandle)
{
    if(*a_pPlatformLayerHandle == OpcUa_Null)
    {
        return OpcUa_BadInvalidState;
    }

    if(*a_pPlatformLayerHandle != &g_OpcUa_Port_CallTable)
    {
        return OpcUa_BadInvalidArgument;
    }

    /* check if initialized */
    if(g_OpcUa_Port_CallTable.pReserved == OpcUa_Null)
    {
        return OpcUa_BadInvalidState;
    }

    if(OpcUa_P_g_FreeVersionString != OpcUa_False && OpcUa_P_g_VersionString != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(OpcUa_P_g_VersionString);
        OpcUa_P_g_VersionString = OpcUa_Null;
    }

    /* reset globals */
    OpcUa_P_g_FreeVersionString = OpcUa_False;
    OpcUa_P_g_VersionString = OPCUA_P_VERSIONSTRING;

#if OPCUA_REQUIRE_OPENSSL
    OpcUa_P_OpenSSL_Cleanup();
#endif /* OPCUA_REQUIRE_OPENSSL */

    OpcUa_P_WinCrypt_Cleanup();

#ifdef OPCUA_HAVE_XMLAPI
    OpcUa_P_Libxml2_Cleanup();
#endif /* OPCUA_HAVE_XMLAPI */

    /* marked as cleared */
    g_OpcUa_Port_CallTable.pReserved = OpcUa_Null;

    *a_pPlatformLayerHandle = OpcUa_Null;

    return OpcUa_Good;
}

/*============================================================================
 * OpcUa_P_GetVersion
 *===========================================================================*/
OpcUa_StringA OPCUA_DLLCALL OpcUa_P_GetVersion()
{
    return OpcUa_P_g_VersionString;
}

/*============================================================================
 * OpcUa_P_GetConfigString
 *===========================================================================*/
OpcUa_StringA OPCUA_DLLCALL OpcUa_P_GetConfigString()
{
    return OpcUa_P_g_ConfigString;
}
