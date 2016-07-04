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
#include <opcua_pkifactory.h>
#include <opcua_cryptofactory.h>
#include <opcua_core.h>

#if OPCUA_MUTEX_ERROR_CHECKING
#define OPCUA_MUTEX_ERROR_CHECKING_PARAMETERS ,__FILE__,__LINE__
#else
#define OPCUA_MUTEX_ERROR_CHECKING_PARAMETERS
#endif

/*********************************************************************************/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_Mutex_Create(          OpcUa_Mutex* phNewMutex)
{
#if OPCUA_USE_SYNCHRONISATION
    return OpcUa_ProxyStub_g_PlatformLayerCalltable->MutexCreate(phNewMutex OPCUA_MUTEX_ERROR_CHECKING_PARAMETERS);
#else
   return OpcUa_Good;
#endif
}

OpcUa_Void OPCUA_DLLCALL OpcUa_Mutex_Delete(                OpcUa_Mutex* phMutex)
{
#if OPCUA_USE_SYNCHRONISATION
    OpcUa_ProxyStub_g_PlatformLayerCalltable->MutexDelete(phMutex OPCUA_MUTEX_ERROR_CHECKING_PARAMETERS);
#endif
}

OpcUa_Void OPCUA_DLLCALL OpcUa_Mutex_Lock(                  OpcUa_Mutex hMutex)
{
#if OPCUA_USE_SYNCHRONISATION
    OpcUa_ProxyStub_g_PlatformLayerCalltable->MutexLock(hMutex OPCUA_MUTEX_ERROR_CHECKING_PARAMETERS);
#endif
}

OpcUa_Void OPCUA_DLLCALL OpcUa_Mutex_Unlock(                OpcUa_Mutex hMutex)
{
#if OPCUA_USE_SYNCHRONISATION
    OpcUa_ProxyStub_g_PlatformLayerCalltable->MutexUnlock(hMutex OPCUA_MUTEX_ERROR_CHECKING_PARAMETERS);
#endif
}

/*********************************************************************************/
OpcUa_DateTime OPCUA_DLLCALL OpcUa_DateTime_UtcNow(         OpcUa_Void)
{
    return OpcUa_ProxyStub_g_PlatformLayerCalltable->UtcNow();
}

OpcUa_UInt32 OPCUA_DLLCALL OpcUa_Utility_GetTickCount(      OpcUa_Void)
{
    return OpcUa_ProxyStub_g_PlatformLayerCalltable->UtilGetTickCount();
}

/*********************************************************************************/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_Semaphore_Create(      OpcUa_Semaphore*    phNewSemaphore,
                                                            OpcUa_UInt32        uInitalValue,
                                                            OpcUa_UInt32        uMaxRange)
{
#if OPCUA_USE_SYNCHRONISATION
    return OpcUa_ProxyStub_g_PlatformLayerCalltable->SemaphoreCreate(phNewSemaphore,
                                                                     uInitalValue,
                                                                     uMaxRange);
#else
    return OpcUa_Good;
#endif
}

OpcUa_Void OPCUA_DLLCALL OpcUa_Semaphore_Delete(            OpcUa_Semaphore* phSemaphore)
{
#if OPCUA_USE_SYNCHRONISATION
    OpcUa_ProxyStub_g_PlatformLayerCalltable->SemaphoreDelete(phSemaphore);
#endif
}

OpcUa_StatusCode OPCUA_DLLCALL OpcUa_Semaphore_Wait(        OpcUa_Semaphore hSemaphore)
{
#if OPCUA_USE_SYNCHRONISATION
    return OpcUa_ProxyStub_g_PlatformLayerCalltable->SemaphoreWait(hSemaphore);
#else
    return OpcUa_Good;
#endif
}

OpcUa_StatusCode OPCUA_DLLCALL OpcUa_Semaphore_TimedWait(   OpcUa_Semaphore     hSemaphore,
                                                            OpcUa_UInt32        msecTimeout)
{
#if OPCUA_USE_SYNCHRONISATION
    return OpcUa_ProxyStub_g_PlatformLayerCalltable->SemaphoreTimedWait(hSemaphore, msecTimeout);
#else
    return OpcUa_Good;
#endif
}

OpcUa_StatusCode OPCUA_DLLCALL OpcUa_Semaphore_Post(        OpcUa_Semaphore     hSemaphore,
                                                            OpcUa_UInt32        uReleaseCount)
{
#if OPCUA_USE_SYNCHRONISATION
    return OpcUa_ProxyStub_g_PlatformLayerCalltable->SemaphorePost(hSemaphore, uReleaseCount);
#else
    return OpcUa_Good;
#endif
}

/*********************************************************************************/

OpcUa_StatusCode OPCUA_DLLCALL OpcUa_SocketManager_Create(OpcUa_SocketManager*  ppSocketManager,
                                                          OpcUa_UInt32          nSockets,
                                                          OpcUa_UInt32          uintFlags)
{
    return OpcUa_ProxyStub_g_PlatformLayerCalltable->SocketManagerCreate(ppSocketManager,
        nSockets,
        uintFlags);
}


OpcUa_Void       OPCUA_DLLCALL OpcUa_SocketManager_Delete(OpcUa_SocketManager* pSocketManager)
{
    OpcUa_ProxyStub_g_PlatformLayerCalltable->SocketManagerDelete(pSocketManager);
}


OpcUa_StatusCode OPCUA_DLLCALL OpcUa_SocketManager_CreateServer(OpcUa_SocketManager         pSocketManager,
                                                                OpcUa_StringA               LocalAdress,
                                                                OpcUa_Socket_EventCallback  pfnSocketCallBack,
                                                                OpcUa_Void*                 pCookie,
                                                                OpcUa_Socket*               ppSocket)
{
    return OpcUa_ProxyStub_g_PlatformLayerCalltable->SocketManagerCreateServer(
        pSocketManager,
        LocalAdress,
        pfnSocketCallBack,
        pCookie,
        ppSocket);
}

OpcUa_StatusCode OPCUA_DLLCALL OpcUa_SocketManager_CreateClient(OpcUa_SocketManager         pSocketManager,
                                                                OpcUa_StringA               RemoteAdress,
                                                                OpcUa_UInt16                LocalPort,
                                                                OpcUa_Socket_EventCallback  pfnSocketCallBack,
                                                                OpcUa_Void*                 pCookie,
                                                                OpcUa_Socket*               ppSocket)
{
    return OpcUa_ProxyStub_g_PlatformLayerCalltable->SocketManagerCreateClient(
        pSocketManager,
        RemoteAdress,
        LocalPort,
        pfnSocketCallBack,
        pCookie,
        ppSocket);
}

OpcUa_StatusCode OPCUA_DLLCALL OpcUa_Socket_Close(  OpcUa_Socket pSocket)
{
    return OpcUa_ProxyStub_g_PlatformLayerCalltable->SocketClose(pSocket);
}

OpcUa_StatusCode OPCUA_DLLCALL OpcUa_Socket_Read(   OpcUa_Socket    pSocket,
                                                    OpcUa_Byte*     pBuffer,
                                                    OpcUa_UInt32    BufferSize,
                                                    OpcUa_UInt32*   puintBytesRead)
{
    return OpcUa_ProxyStub_g_PlatformLayerCalltable->SocketRead(    pSocket,
                                                                    pBuffer,
                                                                    BufferSize,
                                                                    puintBytesRead);
}

OpcUa_Int32      OPCUA_DLLCALL OpcUa_Socket_Write(  OpcUa_Socket    pSocket,
                                                    OpcUa_Byte*     pBuffer,
                                                    OpcUa_UInt32    BufferSize,
                                                    OpcUa_Boolean   bBlock)
{
    return OpcUa_ProxyStub_g_PlatformLayerCalltable->SocketWrite(   pSocket,
                                                                    pBuffer,
                                                                    BufferSize,
                                                                    bBlock);
}

OpcUa_StatusCode OPCUA_DLLCALL OpcUa_SocketManager_Loop(OpcUa_SocketManager pSocketManager,
                                                        OpcUa_UInt32        msecTimeout,
                                                        OpcUa_Boolean       bRunOnce)
{
    return OpcUa_ProxyStub_g_PlatformLayerCalltable->SocketManagerServeLoop(
        pSocketManager,
        msecTimeout,
        bRunOnce);
}

OpcUa_StatusCode OPCUA_DLLCALL OpcUa_SocketManager_SignalEvent(OpcUa_SocketManager pSocketManager,
                                                               OpcUa_UInt32        uintEvent,
                                                               OpcUa_Boolean       bAllLists)
{
    return OpcUa_ProxyStub_g_PlatformLayerCalltable->SocketManagerSignalEvent(
        pSocketManager,
        uintEvent,
        bAllLists);
}

/*********************************************************************************/

OpcUa_StatusCode OPCUA_DLLCALL OpcUa_PKIProvider_Create(    OpcUa_Void*         a_pCertificateStoreConfig,
                                                            OpcUa_PKIProvider*  a_pProvider)
{
    return OPCUA_P_PKIFACTORY_CREATEPKIPROVIDER(    a_pCertificateStoreConfig,
                                                    a_pProvider);
}

OpcUa_StatusCode OPCUA_DLLCALL OpcUa_PKIProvider_Delete(    OpcUa_PKIProvider*  a_pProvider)
{
    return OPCUA_P_PKIFACTORY_DELETEPKIPROVIDER(    a_pProvider);
}

/*********************************************************************************/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_CryptoProvider_Create( OpcUa_StringA           a_psSecurityProfileUri,
                                                            OpcUa_CryptoProvider*   a_pProvider)
{
    return OPCUA_P_CRYPTOFACTORY_CREATECRYPTOPROVIDER(  a_psSecurityProfileUri,
                                                        a_pProvider);
}

OpcUa_StatusCode OPCUA_DLLCALL OpcUa_CryptoProvider_Delete(OpcUa_CryptoProvider*   a_pProvider)
{
    return OPCUA_P_CRYPTOFACTORY_DELETECRYPTOPROVIDER(  a_pProvider);
}

/*********************************************************************************/
OpcUa_Int32 OPCUA_DLLCALL OpcUa_StringA_vsnprintf(  OpcUa_StringA               a_sDest,
                                                    OpcUa_UInt32                a_uCount,
                                                    const OpcUa_CharA*          a_sFormat,
                                                    OpcUa_P_VA_List             a_argptr)
{
    return OpcUa_ProxyStub_g_PlatformLayerCalltable->StrVsnPrintf(  a_sDest,
                                                                    a_uCount,
                                                                    (const OpcUa_StringA)a_sFormat,
                                                                    a_argptr);
}

/*********************************************************************************/
OpcUa_Int32 OPCUA_DLLCALL OpcUa_StringA_snprintf(   OpcUa_StringA               a_sDest,
                                                    OpcUa_UInt32                a_uCount,
                                                    const OpcUa_CharA*          a_sFormat,
                                                    ...)
{
    OpcUa_Int32 ret = 0;
    OpcUa_P_VA_List argumentList;

    if(a_sDest == OpcUa_Null || a_uCount == 0 || a_sFormat == OpcUa_Null)
    {
        return -1;
    }

    OPCUA_P_VA_START(argumentList, a_sFormat);

    ret = OpcUa_ProxyStub_g_PlatformLayerCalltable->StrVsnPrintf(   a_sDest,
                                                                    a_uCount,
                                                                    (const OpcUa_StringA)a_sFormat,
                                                                    argumentList);
    OPCUA_P_VA_END(argumentList);

    return ret;
}
