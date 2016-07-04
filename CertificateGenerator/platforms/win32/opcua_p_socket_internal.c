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
/* Modify the content of this file according to the socket implementation on your system.             */
/* Win32                                                                                              */
/******************************************************************************************************/

/* System Headers */
#include <windows.h>

/* UA platform definitions */
#include <opcua_p_internal.h>

/* additional UA dependencies */
#include <opcua_datetime.h>

/* platform layer includes */
#include <opcua_p_thread.h>
#include <opcua_p_mutex.h>
#include <opcua_p_semaphore.h>
#include <opcua_p_utilities.h>

/* own headers */
#include <opcua_p_socket.h>
#include <opcua_p_socket_internal.h>
#include <opcua_p_socket_interface.h>

/* platform layer includes */
#include <opcua_p_timer.h> /* for timered select */


#ifdef _MSC_VER
/* this pragma is for win32 */
#pragma warning(disable:4127) /* suppress "conditional expression is constant" in fdset macros */
#endif /* _MSC_VER */


#if OPCUA_MULTITHREADED
    extern OpcUa_InternalSocketManager* OpcUa_P_Socket_g_pSocketManagers[OPCUA_SOCKET_MAXMANAGERS];
    #if OPCUA_USE_SYNCHRONISATION
        extern OpcUa_Mutex  OpcUa_P_Socket_g_SocketManagersMutex;
        extern OpcUa_Mutex  OpcUa_P_Socket_g_ShutdownMutex;
        extern OpcUa_UInt32 OpcUa_P_Socket_g_uNuOfClientThreads;
    #endif /* OPCUA_USE_SYNCHRONISATION */
#endif /* OPCUA_MULTITHREADED */

extern OpcUa_InternalSocketManager OpcUa_Socket_g_SocketManager;
extern OpcUa_InternalSocket OpcUa_Socket_g_SocketArray[OPCUA_P_SOCKETMANAGER_NUMBEROFSOCKETS];



/*============================================================================
 * Allocate Socket Type
 *===========================================================================*/
OpcUa_Socket OpcUa_Socket_Alloc(OpcUa_Void)
{
    OpcUa_InternalSocket* pInternalSocket = OpcUa_Null;
    pInternalSocket = (OpcUa_InternalSocket*)malloc(sizeof(OpcUa_InternalSocket));
    OpcUa_Socket_Initialize((OpcUa_Socket)pInternalSocket);
    return (OpcUa_Socket)pInternalSocket;
}

/*============================================================================
 * Initialize Socket Type
 *===========================================================================*/
OpcUa_Void OpcUa_Socket_Initialize(OpcUa_Socket a_pSocket)
{
    OpcUa_InternalSocket* pInternalSocket = OpcUa_Null;

    if(a_pSocket == OpcUa_Null)
    {
        return;
    }

    pInternalSocket = (OpcUa_InternalSocket*)a_pSocket;

    OPCUA_SOCKET_INVALIDATE(pInternalSocket);

    pInternalSocket->rawSocket = (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID;

#if OPCUA_MULTITHREADED
    /* OpcUa_P_Mutex_Create(&(pInternalSocket->pMutex)); */
#endif /* OPCUA_MULTITHREADED */
}

/*============================================================================
 * Clear Socket Type
 *===========================================================================*/
OpcUa_Void OpcUa_Socket_Clear(OpcUa_Socket a_pSocket)
{
    OpcUa_InternalSocket* pInternalSocket = OpcUa_Null;

    if(a_pSocket == OpcUa_Null)
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OpcUa_Socket_Clear: Invalid handle!\n");
        return;
    }

    pInternalSocket = (OpcUa_InternalSocket*)a_pSocket;

    OPCUA_SOCKET_INVALIDATE(pInternalSocket);

    if(pInternalSocket->rawSocket != (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID)
    {
        pInternalSocket->rawSocket = (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID;
    }
#if OPCUA_MULTITHREADED
    /*OpcUa_P_Mutex_Delete(&(pInternalSocket->pMutex));*/
#endif /* OPCUA_MULTITHREADED */
}

/*============================================================================
 * Delete Socket Type
 *===========================================================================*/
OpcUa_Void OpcUa_Socket_Delete(OpcUa_Socket* a_ppSocket)
{
    OpcUa_InternalSocket* pInternalSocket = OpcUa_Null;

    if(a_ppSocket == OpcUa_Null)
    {
        return;
    }

    if(*a_ppSocket == OpcUa_Null)
    {
        return;
    }

    pInternalSocket = (OpcUa_InternalSocket*)*a_ppSocket;

    OpcUa_Socket_Clear(pInternalSocket);

    free(pInternalSocket);

    *a_ppSocket = OpcUa_Null;
}

/*============================================================================
 * Allocate SocketManager Type
 *===========================================================================*/
OpcUa_SocketManager OpcUa_SocketManager_Alloc(OpcUa_Void)
{
    OpcUa_InternalSocketManager*    pInternalSocketManager  = OpcUa_Null;

    pInternalSocketManager = (OpcUa_InternalSocketManager*)malloc(sizeof(OpcUa_InternalSocketManager));

    if(pInternalSocketManager == OpcUa_Null)
    {
        return OpcUa_Null;
    }

    return (OpcUa_SocketManager)pInternalSocketManager;
}

/*============================================================================
 * Initialize SocketManager Type
 *===========================================================================*/
OpcUa_Void OpcUa_SocketManager_Initialize(OpcUa_SocketManager a_pSocketManager)
{
    OpcUa_InternalSocketManager* pInternalSocketManager = OpcUa_Null;

    if(a_pSocketManager == OpcUa_Null)
    {
        return;
    }

    OpcUa_MemSet(a_pSocketManager, 0, sizeof(OpcUa_InternalSocketManager));

    pInternalSocketManager = (OpcUa_InternalSocketManager*)a_pSocketManager;

    pInternalSocketManager->pSockets                = OpcUa_Null;
    pInternalSocketManager->uintMaxSockets          = 0;
    pInternalSocketManager->pCookie                 = OpcUa_Null;
    pInternalSocketManager->uintLastExternalEvent   = OPCUA_SOCKET_NO_EVENT;
    pInternalSocketManager->pThread                 = OpcUa_Null;
    pInternalSocketManager->pMutex                  = OpcUa_Null;
}

/*============================================================================
 * Create the Sockets in the List
 *===========================================================================*/
OpcUa_StatusCode OpcUa_SocketManager_CreateSockets(
    OpcUa_SocketManager a_pSocketManager,
    OpcUa_UInt32        a_uMaxSockets)
{
    OpcUa_UInt32                 ntemp                  = 0;
    OpcUa_InternalSocketManager* pInternalSocketManager = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Socket, "CreateSockets");

    OpcUa_GotoErrorIfArgumentNull(a_pSocketManager);

    pInternalSocketManager = (OpcUa_InternalSocketManager*)a_pSocketManager;

    OpcUa_P_Mutex_Lock(pInternalSocketManager->pMutex);

    pInternalSocketManager->pSockets = (OpcUa_InternalSocket *)malloc(sizeof(OpcUa_InternalSocket) * a_uMaxSockets);
    OpcUa_GotoErrorIfAllocFailed(pInternalSocketManager->pSockets);

    /* initialize the whole socket list with zero */
    OpcUa_MemSet(pInternalSocketManager->pSockets, 0, sizeof(OpcUa_InternalSocket) * a_uMaxSockets);

    for(ntemp = 0; ntemp < a_uMaxSockets; ntemp++)
    {
        OpcUa_Socket_Initialize(&(pInternalSocketManager->pSockets[ntemp]));
    }

    pInternalSocketManager->uintMaxSockets = a_uMaxSockets;

    OpcUa_P_Mutex_Unlock(pInternalSocketManager->pMutex);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/************************* Internal Helper Functions *************************/
/*============================================================================
 * Internal helper function to create a server socket
 *===========================================================================*/
OpcUa_StatusCode OpcUa_SocketManager_InternalCreateServer(
    OpcUa_SocketManager         a_pSocketManager,
    OpcUa_UInt16                a_uPort,
    OpcUa_Socket_EventCallback  a_pfnSocketCallBack,
    OpcUa_Void*                 a_pCallbackData,
    OpcUa_Socket*               a_ppSocket)
{
    OpcUa_StatusCode                uStatus                 = OpcUa_Good;
    OpcUa_InternalSocket*           pSocket                 = OpcUa_Null;

    /* create the main server socket and raise error if no socket is found */
    pSocket = (OpcUa_InternalSocket *)OpcUa_SocketManager_FindFreeSocket(   a_pSocketManager,
                                                                            OpcUa_False);
    /* no free sockets, out of resources.. */
    OpcUa_GotoErrorIfNull(pSocket, OpcUa_BadMaxConnectionsReached);

    pSocket->rawSocket = OpcUa_P_Socket_CreateServer(a_uPort, &uStatus);

    if(OpcUa_IsBad(uStatus))
    {
        uStatus = OpcUa_BadCommunicationError;
        goto Error;
    }

#if OPCUA_USE_SYNCHRONISATION
    uStatus = OpcUa_P_Semaphore_Create( &pSocket->hSemaphore, 0, 1);
    if(OpcUa_IsBad(uStatus))
    {
        uStatus = OpcUa_BadCommunicationError;
        goto Error;
    }
#endif

    pSocket->pfnEventCallback       = a_pfnSocketCallBack;
    pSocket->pvUserData             = a_pCallbackData;
    OPCUA_SOCKET_SETVALID(pSocket);
    pSocket->Flags.bSocketIsInUse   = OpcUa_True;
    pSocket->Flags.bIsListenSocket  = OpcUa_True;
    pSocket->Flags.bOwnThread       = OpcUa_False;
    pSocket->Flags.EventMask        = OPCUA_SOCKET_READ_EVENT | OPCUA_SOCKET_EXCEPT_EVENT | OPCUA_SOCKET_ACCEPT_EVENT | OPCUA_SOCKET_CLOSE_EVENT | OPCUA_SOCKET_TIMEOUT_EVENT;
    pSocket->pSocketManager         = (OpcUa_InternalSocketManager *)a_pSocketManager;
    pSocket->usPort                 = a_uPort;

#if 0
#if OPCUA_MULTITHREADED
    if(pSocket->pMutex == OpcUa_Null) /* Guard this to prevent memory leaks. */
    {
        OpcUa_Mutex_Create(&(pSocket->pMutex));
    }
#endif
#endif

    *a_ppSocket = pSocket;

Error:
    return uStatus;
}

/*============================================================================
*
*===========================================================================*/
OpcUa_StatusCode OpcUa_Socket_HandleAcceptEvent(    OpcUa_Socket a_pListenSocket,
                                                    OpcUa_Socket a_pAcceptedSocket) /* this is allowed to be null */
{
    OpcUa_UInt32            uAddress                = 0;
    OpcUa_UInt16            uPort                   = 0;
    OpcUa_RawSocket         AcceptedRawSocket       = (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID;
    OpcUa_InternalSocket*   pListenInternalSocket   = (OpcUa_InternalSocket*)a_pListenSocket;
    OpcUa_InternalSocket*   pAcceptInternalSocket   = (OpcUa_InternalSocket*)a_pAcceptedSocket;

    OpcUa_ReturnErrorIfArgumentNull(a_pListenSocket);

    AcceptedRawSocket = OpcUa_P_RawSocket_Accept(   pListenInternalSocket->rawSocket,
                                                    &uPort,
                                                    &uAddress,
                                                    OpcUa_True,
                                                    OpcUa_False);

    if(AcceptedRawSocket == (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID)
    {
        int iLastError = WSAGetLastError();

        OpcUa_Trace(OPCUA_TRACE_LEVEL_WARNING, "OpcUa_Socket_HandleAcceptEvent: accepting failed with %i\n", iLastError);

        return OpcUa_BadCommunicationError;
    }

    /* accept but close if caller provided a null argument */
    if(a_pAcceptedSocket == OpcUa_Null)
    {
        OpcUa_P_RawSocket_Close(AcceptedRawSocket);
        AcceptedRawSocket = (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID;

        return OpcUa_BadMaxConnectionsReached;
    }
    else
    {
        pAcceptInternalSocket->rawSocket = AcceptedRawSocket;
    }

    if( pAcceptInternalSocket->rawSocket == (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID)
    {
        OPCUA_SOCKET_INVALIDATE(pAcceptInternalSocket);
        pAcceptInternalSocket->Flags.bSocketIsInUse   = OpcUa_False;

        return OpcUa_BadCommunicationError;
    }

    /* inherit from parent (listen) socket */
    pAcceptInternalSocket->pfnEventCallback       = pListenInternalSocket->pfnEventCallback;
    pAcceptInternalSocket->pvUserData             = pListenInternalSocket->pvUserData;
    OPCUA_SOCKET_SETVALID(pAcceptInternalSocket);
    pAcceptInternalSocket->Flags.bSocketIsInUse   = OpcUa_True;
    pAcceptInternalSocket->Flags.bIsListenSocket  = OpcUa_False;
    pAcceptInternalSocket->Flags.bOwnThread       = OpcUa_False;
    pAcceptInternalSocket->Flags.EventMask        =   OPCUA_SOCKET_READ_EVENT
                                                    | OPCUA_SOCKET_EXCEPT_EVENT
                                                    | OPCUA_SOCKET_ACCEPT_EVENT
                                                    | OPCUA_SOCKET_CLOSE_EVENT
                                                    | OPCUA_SOCKET_TIMEOUT_EVENT;
    pAcceptInternalSocket->pSocketManager         = pListenInternalSocket->pSocketManager;
    pAcceptInternalSocket->usPort                 = pListenInternalSocket->usPort;
    pAcceptInternalSocket->Flags.bSSL             = pListenInternalSocket->Flags.bSSL;

#ifdef OPCUA_SOCKET_USESSL
    pAcceptInternalSocket->pSSL                   = pSocket->pSSL;
#endif /* OPCUA_SOCKET_USESSL*/

    return OpcUa_Good;
}

#if OPCUA_MULTITHREADED
/*============================================================================
*
*===========================================================================*/
static OpcUa_Int32 OpcUa_SocketManager_GetSocketManagerSlot(OpcUa_InternalSocketManager* a_pSocketManager)
{
    OpcUa_Int32 iSlot = 0;

    OpcUa_P_Mutex_Lock(OpcUa_P_Socket_g_SocketManagersMutex);

    for(iSlot = 0; iSlot < OPCUA_P_SOCKETMANAGER_NUMBEROFSOCKETS; iSlot++)
    {
        if(OpcUa_P_Socket_g_pSocketManagers[iSlot] == OpcUa_Null)
        {
            OpcUa_P_Socket_g_pSocketManagers[iSlot] = a_pSocketManager;

            OpcUa_P_Mutex_Unlock(OpcUa_P_Socket_g_SocketManagersMutex);

            return iSlot;
        }
    }

    OpcUa_P_Mutex_Unlock(OpcUa_P_Socket_g_SocketManagersMutex);

    return -1;
}

/*============================================================================
*
*===========================================================================*/
static OpcUa_Void OpcUa_SocketManager_ReleaseSocketManagerSlot(OpcUa_UInt32 a_uSlot)
{
    OpcUa_P_Mutex_Lock(OpcUa_P_Socket_g_SocketManagersMutex);

    OpcUa_P_Socket_g_pSocketManagers[a_uSlot] = OpcUa_Null;

    OpcUa_P_Mutex_Unlock(OpcUa_P_Socket_g_SocketManagersMutex);

    return;
}

/*============================================================================
* Takes appropriate action based on an event on a certain socket.
*===========================================================================*/
OpcUa_Void OpcUa_SocketManager_AcceptHandlerThread(OpcUa_Void* a_pArgument)
{

    OpcUa_InternalSocket*       pInternalSocket     = (OpcUa_InternalSocket*)a_pArgument;
    OpcUa_StatusCode            uStatus             = OpcUa_Good;
    OpcUa_Boolean               bEndLoop            = OpcUa_False;
    OpcUa_Int32                 iSocketManagerSlot  = -1;
    OpcUa_UInt32                uEventOccured       = OPCUA_SOCKET_NO_EVENT;
    OpcUa_InternalSocket        ClientSocket[2]; /* one for the client, one for _signals_ */
    OpcUa_InternalSocketManager SpawnedSocketManager;


    memset(&ClientSocket, 0, sizeof(OpcUa_InternalSocket) * 2);
    memset(&SpawnedSocketManager, 0, sizeof(OpcUa_SocketManager));

    /* update global control */
    OpcUa_P_Mutex_Lock(OpcUa_P_Socket_g_ShutdownMutex);
    OpcUa_P_Socket_g_uNuOfClientThreads++;
    OpcUa_P_Mutex_Unlock(OpcUa_P_Socket_g_ShutdownMutex);

    /* TODO: Check shutdown before dispatching? */

    /* handle event */
    uStatus = OpcUa_Socket_HandleAcceptEvent(  pInternalSocket,    /* listen socket */
                                               &ClientSocket[0]);  /* accepted socket */

    ClientSocket[0].Flags.bOwnThread = 1;

    /* release spawn semaphore */
    if(pInternalSocket->hSemaphore != OpcUa_Null)
    {
        OpcUa_P_Semaphore_Post( pInternalSocket->hSemaphore,
                                1);
    }

    if(OpcUa_IsGood(uStatus))
    {
        /* obtain slot in global socket list array */
        iSocketManagerSlot = OpcUa_SocketManager_GetSocketManagerSlot(&SpawnedSocketManager);
        if(iSocketManagerSlot == -1 )
        {
            /* error, configuration maximum reached */
            OpcUa_P_Socket_Close(&ClientSocket[0]);

            OpcUa_P_Mutex_Lock(OpcUa_P_Socket_g_ShutdownMutex);
            OpcUa_P_Socket_g_uNuOfClientThreads--;
            OpcUa_P_Mutex_Unlock(OpcUa_P_Socket_g_ShutdownMutex);

            return;
        }

        /* slot obtained, go on */
        SpawnedSocketManager.pThread                    = OpcUa_Null;
        SpawnedSocketManager.uintMaxSockets             = 2;
        SpawnedSocketManager.pSockets                   = ClientSocket;
        SpawnedSocketManager.pCookie                    = OpcUa_Null;
        SpawnedSocketManager.uintLastExternalEvent      = OPCUA_SOCKET_NO_EVENT;

        OpcUa_P_Mutex_Create(&SpawnedSocketManager.pMutex);

        SpawnedSocketManager.Flags.bStopServerLoop      = 0;
        SpawnedSocketManager.Flags.bSpawnThreadOnAccept = 0;
        SpawnedSocketManager.Flags.bRejectOnThreadFail  = -1;

        ClientSocket[0].pSocketManager = &SpawnedSocketManager;

        /* fire accept event */
        ClientSocket[0].pfnEventCallback(   (OpcUa_Socket)&ClientSocket[0],
                                            OPCUA_SOCKET_ACCEPT_EVENT,
                                            ClientSocket[0].pvUserData,
                                            ClientSocket[0].usPort,
                                            (OpcUa_Boolean)ClientSocket[0].Flags.bSSL);
        bEndLoop = OpcUa_False;

        do
        {
            uStatus = OpcUa_P_SocketManager_ServeLoopInternal(  &SpawnedSocketManager,
                                                                OPCUA_INFINITE,
                                                                &ClientSocket[0],
                                                                OPCUA_SOCKET_NO_EVENT,
                                                                &uEventOccured);

            if ((uEventOccured & OPCUA_SOCKET_CLOSE_EVENT)    ||
                (uEventOccured & OPCUA_SOCKET_SHUTDOWN_EVENT) ||
                (uEventOccured & OPCUA_SOCKET_EXCEPT_EVENT)   ||
                OpcUa_IsEqual(OpcUa_GoodShutdownEvent))
            {
                bEndLoop = OpcUa_True;
            }
        } while (   (bEndLoop==OpcUa_False)
                  &&(OpcUa_IsGood(uStatus)));

        OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_SocketManager_AcceptHandlerThread: Client Handler shutting down! (0x%08X)\n", uStatus);

        OpcUa_P_Mutex_Lock(SpawnedSocketManager.pMutex);

        if(ClientSocket[0].Flags.bInvalidSocket == 0)
        {
            OpcUa_P_Socket_Close(&ClientSocket[0]);
        }
        if(ClientSocket[1].Flags.bInvalidSocket == 0)
        {
            OpcUa_P_Socket_Close(&ClientSocket[1]);
        }

        OpcUa_P_Mutex_Unlock(SpawnedSocketManager.pMutex);
        OpcUa_SocketManager_ReleaseSocketManagerSlot(iSocketManagerSlot);
        OpcUa_P_Mutex_Delete(&SpawnedSocketManager.pMutex);

        /* loop ended */
        OpcUa_P_Mutex_Lock(OpcUa_P_Socket_g_ShutdownMutex);
        OpcUa_P_Socket_g_uNuOfClientThreads--;
        OpcUa_P_Mutex_Unlock(OpcUa_P_Socket_g_ShutdownMutex);
    }
    else
    {
        OpcUa_P_Mutex_Lock(OpcUa_P_Socket_g_ShutdownMutex);
        OpcUa_P_Socket_g_uNuOfClientThreads--;
        OpcUa_P_Mutex_Unlock(OpcUa_P_Socket_g_ShutdownMutex);
    }

    return;
}
#endif /* OPCUA_MULTITHREADED */

/*============================================================================
* Takes appropriate action based on an event on a certain socket.
*===========================================================================*/
OpcUa_StatusCode OpcUa_Socket_HandleEvent(  OpcUa_Socket a_pSocket,
                                            OpcUa_UInt32 a_uEvent)
{
    OpcUa_Socket            pAcceptedSocket = OpcUa_Null;
    OpcUa_InternalSocket*   pInternalSocket = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Socket, "HandleEvent");

    OpcUa_GotoErrorIfArgumentNull(a_pSocket);

    pInternalSocket = (OpcUa_InternalSocket*)a_pSocket;

    /* update last access variable */
    pInternalSocket->uintLastAccess = OpcUa_P_GetTickCount()/1000;

    switch(a_uEvent)
    {
    case OPCUA_SOCKET_READ_EVENT:
        {
            if (pInternalSocket->pfnEventCallback!=OpcUa_Null)
            {
#if OPCUA_MULTITHREADED
                OpcUa_P_Mutex_Unlock(pInternalSocket->pSocketManager->pMutex);
#endif
                if(pInternalSocket->pfnEventCallback != OpcUa_Null)
                {
                    pInternalSocket->pfnEventCallback(a_pSocket, a_uEvent, pInternalSocket->pvUserData, pInternalSocket->usPort, (OpcUa_Boolean) pInternalSocket->Flags.bSSL);
                }
                else
                {
                    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_Socket_HandleEvent: pfnEventCallback is OpcUa_Null\n");
                }
#if OPCUA_MULTITHREADED
                OpcUa_P_Mutex_Lock(pInternalSocket->pSocketManager->pMutex);
#endif
            }

            return OpcUa_Good;
        }
    case OPCUA_SOCKET_WRITE_EVENT:
        {
#if OPCUA_MULTITHREADED
            OpcUa_P_Mutex_Unlock(pInternalSocket->pSocketManager->pMutex);
#endif
            if(pInternalSocket->pfnEventCallback != OpcUa_Null)
            {
                uStatus = pInternalSocket->pfnEventCallback(pInternalSocket, OPCUA_SOCKET_WRITE_EVENT, pInternalSocket->pvUserData, pInternalSocket->usPort, OpcUa_False);
            }
            else
            {
                OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_Socket_HandleEvent: pfnEventCallback is OpcUa_Null\n");
            }
#if OPCUA_MULTITHREADED
            OpcUa_P_Mutex_Lock(pInternalSocket->pSocketManager->pMutex);
#endif

            if(uStatus != OpcUa_GoodCallAgain)
            {
                pInternalSocket->Flags.EventMask &= (~OPCUA_SOCKET_WRITE_EVENT);
            }

            return OpcUa_Good;
        }
    case OPCUA_SOCKET_CONNECT_EVENT:
        {
            {
#if OPCUA_MULTITHREADED
                OpcUa_Mutex hSocketManagerMutex = pInternalSocket->pSocketManager->pMutex;
#endif
                OpcUa_P_RawSocket_GetLocalInfo(pInternalSocket->rawSocket, OpcUa_Null, &(pInternalSocket->usPort));
#if OPCUA_MULTITHREADED
                OpcUa_P_Mutex_Unlock(hSocketManagerMutex);
#endif
                if(pInternalSocket->pfnEventCallback != OpcUa_Null)
                {
                    uStatus = pInternalSocket->pfnEventCallback(a_pSocket, OPCUA_SOCKET_CONNECT_EVENT, pInternalSocket->pvUserData, pInternalSocket->usPort, (OpcUa_Boolean)pInternalSocket->Flags.bSSL);
                }
                else
                {
                    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_Socket_HandleEvent: pfnEventCallback is OpcUa_Null\n");
                }
#if OPCUA_MULTITHREADED
                OpcUa_P_Mutex_Lock(hSocketManagerMutex);
#endif
            }

            pInternalSocket->Flags.EventMask &= (~OPCUA_SOCKET_CONNECT_EVENT);

            return OpcUa_Good;
        }
    case OPCUA_SOCKET_CLOSE_EVENT:
        {
            /* OpcUa_Trace("OpcUa_Socket_HandleEvent: OPCUA_SOCKET_CLOSE_EVENT\n"); */
            break;
        }
    case OPCUA_SOCKET_TIMEOUT_EVENT:
        {
            /*OpcUa_Trace("OpcUa_Socket_HandleEvent: OPCUA_SOCKET_TIMEOUT_EVENT\n");*/
            break;
        }
    case OPCUA_SOCKET_EXCEPT_EVENT:
        {
            OpcUa_Int32 lastE = OpcUa_P_RawSocket_GetLastError(pInternalSocket->rawSocket);
            OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OpcUa_Socket_HandleEvent: OPCUA_SOCKET_EXCEPT_EVENT: %i\n", lastE);

            break;
        }
    case OPCUA_SOCKET_ACCEPT_EVENT:
        {
            /*OpcUa_Trace("OpcUa_Socket_HandleEvent: OPCUA_SOCKET_ACCEPT_EVENT\n");*/

#if OPCUA_MULTITHREADED

            if(pInternalSocket->pSocketManager->Flags.bSpawnThreadOnAccept != 0)
            {
                OpcUa_RawThread hThread = OpcUa_Null;

                OpcUa_P_Mutex_Lock(OpcUa_P_Socket_g_ShutdownMutex);
                OpcUa_P_Socket_g_uNuOfClientThreads++;
                OpcUa_P_Mutex_Unlock(OpcUa_P_Socket_g_ShutdownMutex);

                OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_Socket_HandleEvent: Spawning Client Connection thread.\n");

#if 0
                uStatus = OpcUa_P_Thread_Create(&hThread);
                uStatus = OpcUa_P_Thread_Start( hThread,                                /* handle */
                                                OpcUa_SocketManager_AcceptHandlerThread,/* handler */
                                                (OpcUa_Void*)pInternalSocket);          /* argument */
#endif

                hThread = CreateThread( NULL,
                                        0,
                                        (LPTHREAD_START_ROUTINE)OpcUa_SocketManager_AcceptHandlerThread,
                                        pInternalSocket,
                                        0,
                                        NULL);

#if 0
                if(OpcUa_IsGood(uStatus))
#endif
                if(hThread != NULL)
                {
                    if(pInternalSocket->hSemaphore != OpcUa_Null)
                    {
                        /* we must wait until the spawned thread handled the accept event */
                        OpcUa_P_Semaphore_TimedWait(pInternalSocket->hSemaphore,
                                                    OPCUA_INFINITE);
                    }

                    OpcUa_P_Mutex_Lock(OpcUa_P_Socket_g_ShutdownMutex);
                    OpcUa_P_Socket_g_uNuOfClientThreads--;
                    OpcUa_P_Mutex_Unlock(OpcUa_P_Socket_g_ShutdownMutex);

                    a_pSocket = OpcUa_Null; /* skip the following code */

                    CloseHandle((HANDLE)hThread);
                }
                else
                {
                    OpcUa_P_Mutex_Lock(OpcUa_P_Socket_g_ShutdownMutex);
                    OpcUa_P_Socket_g_uNuOfClientThreads--;
                    OpcUa_P_Mutex_Unlock(OpcUa_P_Socket_g_ShutdownMutex);

                    if(pInternalSocket->pSocketManager->Flags.bRejectOnThreadFail != 0)
                    {
                        OpcUa_Socket_HandleAcceptEvent(a_pSocket, pAcceptedSocket);
                        a_pSocket = OpcUa_Null; /* skip the following code */
                    }
                }
            }
#endif /* OPCUA_MULTITHREADED */
            if(a_pSocket != OpcUa_Null)
            {
                pAcceptedSocket = OpcUa_SocketManager_FindFreeSocket(pInternalSocket->pSocketManager, OpcUa_False);
                OpcUa_Socket_HandleAcceptEvent(a_pSocket, pAcceptedSocket);
                OpcUa_GotoErrorIfNull(pAcceptedSocket, OpcUa_BadMaxConnectionsReached);
                a_pSocket = pAcceptedSocket;
            }
            break;
        }
    default:
        {
            OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OpcUa_Socket_HandleEvent: Unknown event!\n");
            break;
        }

    }; /* end of event dispatcher */

    /* begin dispatching of remaining events */
    if(a_pSocket != OpcUa_Null)
    {
        if (pInternalSocket->pfnEventCallback != OpcUa_Null)
        {
#if OPCUA_MULTITHREADED
            OpcUa_P_Mutex_Unlock(pInternalSocket->pSocketManager->pMutex);
#endif
            if(pInternalSocket->pfnEventCallback != OpcUa_Null)
            {
                pInternalSocket->pfnEventCallback(a_pSocket, a_uEvent, pInternalSocket->pvUserData, pInternalSocket->usPort, (OpcUa_Boolean)pInternalSocket->Flags.bSSL);
            }
            else
            {
                OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_Socket_HandleEvent: pfnEventCallback is OpcUa_Null\n");
            }

            if(a_uEvent == OPCUA_SOCKET_EXCEPT_EVENT)
            {
                OpcUa_P_Socket_Close(a_pSocket);
            }
#if OPCUA_MULTITHREADED
            OpcUa_P_Mutex_Lock(pInternalSocket->pSocketManager->pMutex);
#endif
        }
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * Set the event mask for this socket.
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Socket_SetEventMask( OpcUa_Socket a_pSocket,
                                            OpcUa_UInt32 a_uEventMask)
{
OpcUa_InitializeStatus(OpcUa_Module_Socket, "SetEventMask");

    OpcUa_GotoErrorIfArgumentNull(a_pSocket);
    OpcUa_GotoErrorIfArgumentNull(((OpcUa_InternalSocket*)a_pSocket)->rawSocket);

    ((OpcUa_InternalSocket*)a_pSocket)->Flags.EventMask = (OpcUa_Int)a_uEventMask;

    OpcUa_P_SocketManager_SignalEvent(  ((OpcUa_InternalSocket*)a_pSocket)->pSocketManager,
                                        OPCUA_SOCKET_RENEWLOOP_EVENT,
                                        OpcUa_False);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * Get the currently set event mask for this socket.
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Socket_GetEventMask(
    OpcUa_Socket a_pSocket,
    OpcUa_UInt32* a_pEventMask)
{
OpcUa_InitializeStatus(OpcUa_Module_Socket, "GetEventMask");

    OpcUa_GotoErrorIfArgumentNull(a_pSocket);
    OpcUa_GotoErrorIfArgumentNull(((OpcUa_InternalSocket*)a_pSocket)->rawSocket);

    *a_pEventMask = (OpcUa_UInt32)((OpcUa_InternalSocket*)a_pSocket)->Flags.EventMask;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * Find a free socket in the given list.
 *===========================================================================*/
OpcUa_Socket OpcUa_SocketManager_FindFreeSocket(    OpcUa_SocketManager     a_pSocketManager,
                                                    OpcUa_Boolean           a_bIsSignalSocket)
{
    OpcUa_UInt32                 uIndex       = 0;
    OpcUa_Boolean                bFound       = OpcUa_False;
    OpcUa_InternalSocketManager* pInternalSocketManager  = (OpcUa_InternalSocketManager*)a_pSocketManager;

#if OPCUA_USE_SYNCHRONISATION
    OpcUa_P_Mutex_Lock(pInternalSocketManager->pMutex);
#endif /* OPCUA_USE_SYNCHRONISATION */

    for(uIndex = 0; uIndex < pInternalSocketManager->uintMaxSockets; uIndex++)
    {
        if(uIndex == 0 && !a_bIsSignalSocket)
        {
            continue;
        }

        if(pInternalSocketManager->pSockets[uIndex].Flags.bSocketIsInUse == OpcUa_False)
        {
#if OPCUA_USE_SYNCHRONISATION
            /*OpcUa_P_Mutex_Lock(pInternalSocketManager->pSockets[uIndex].pMutex);*/
#endif /* OPCUA_USE_SYNCHRONISATION */

            pInternalSocketManager->pSockets[uIndex].Flags.bSocketIsInUse   = OpcUa_True;
            OPCUA_SOCKET_INVALIDATE_S(pInternalSocketManager->pSockets[uIndex]);
            pInternalSocketManager->pSockets[uIndex].Flags.bIsListenSocket  = OpcUa_False;
            pInternalSocketManager->pSockets[uIndex].Flags.bOwnThread       = OpcUa_False;
            pInternalSocketManager->pSockets[uIndex].Flags.bSSL             = OpcUa_False;
            pInternalSocketManager->pSockets[uIndex].Flags.EventMask        = 0;
            pInternalSocketManager->pSockets[uIndex].uintTimeout            = 0;
            pInternalSocketManager->pSockets[uIndex].uintLastAccess         = 0;
            pInternalSocketManager->pSockets[uIndex].pvUserData             = OpcUa_Null;
            pInternalSocketManager->pSockets[uIndex].pfnEventCallback       = OpcUa_Null;
            /*pInternalSocketManager->pSockets[uIndex].pSocketManager         = OpcUa_Null;*/ /* That should stay! */
            pInternalSocketManager->pSockets[uIndex].rawSocket              = (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID;

#ifdef OPCUA_WITH_SSL
            /*a_pSocketManager->pSockets[uintIndex].pSSL                   = OpcUa_Null;*/
#endif /* OPCUA_WITH_SSL */

            bFound = OpcUa_True;

#if OPCUA_USE_SYNCHRONISATION
            /*OpcUa_P_Mutex_Unlock(pInternalSocketManager->pSockets[uIndex].pMutex);*/
#endif /* OPCUA_USE_SYNCHRONISATION */

            break; /* for loop */
        }
    }

#if OPCUA_USE_SYNCHRONISATION
    OpcUa_P_Mutex_Unlock(pInternalSocketManager->pMutex);
#endif /* OPCUA_USE_SYNCHRONISATION */

    if(bFound)
    {
        return &(pInternalSocketManager->pSockets[uIndex]);
    }
    else
    {
        return OpcUa_Null;
    }
}

/*============================================================================
 * Create a new socket list
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_SocketManager_NewSignalSocket(OpcUa_SocketManager a_pSocketManager)
{
    OpcUa_InternalSocket*           pIntSignalSocket = OpcUa_Null;
    OpcUa_InternalSocketManager*    pInternalSocketManager      = (OpcUa_InternalSocketManager*)a_pSocketManager;

OpcUa_InitializeStatus(OpcUa_Module_Socket, "NewSignalSocket");

    OpcUa_GotoErrorIfArgumentNull(a_pSocketManager);

    if(pInternalSocketManager->pCookie == OpcUa_Null)
    {
        pIntSignalSocket = (OpcUa_InternalSocket*)OpcUa_SocketManager_FindFreeSocket(a_pSocketManager, OpcUa_True);

        if(pIntSignalSocket == OpcUa_Null)
        {
            uStatus = OpcUa_BadResourceUnavailable;
            goto Error;
        }

        uStatus = OpcUa_P_RawSocket_Create(&pIntSignalSocket->rawSocket, OpcUa_True, OpcUa_False);

        if(OpcUa_IsBad(uStatus))
        {
            OPCUA_SOCKET_INVALIDATE(pIntSignalSocket);
            pIntSignalSocket->Flags.bSocketIsInUse = OpcUa_False;
            OpcUa_GotoError;
        }

        pIntSignalSocket->Flags.EventMask =   OPCUA_SOCKET_CLOSE_EVENT
                                            | OPCUA_SOCKET_EXCEPT_EVENT
                                            | OPCUA_SOCKET_TIMEOUT_EVENT;

        OPCUA_SOCKET_SETVALID(pIntSignalSocket);

        pInternalSocketManager->pCookie = (OpcUa_Void*)pIntSignalSocket;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
* Main socket based server loop.
*===========================================================================*/
OpcUa_StatusCode OpcUa_P_SocketManager_ServeLoopInternal(   OpcUa_SocketManager   a_pSocketManager,
                                                            OpcUa_UInt32          a_msecTimeout,
                                                            OpcUa_Socket          a_pSocket,
                                                            OpcUa_UInt32          a_uEvent,
                                                            OpcUa_UInt32*         a_puEventOccured)
{
    OpcUa_StatusCode                selectStatus            = OpcUa_Good;

    OpcUa_P_Socket_Array            readFdSet               = {0, {0}};
    OpcUa_P_Socket_Array            writeFdSet              = {0, {0}};
    OpcUa_P_Socket_Array            exceptFdSet             = {0, {0}};

    OpcUa_UInt32                    msecInterval            = 0;
    OpcUa_UInt32                    uintSocketEventOccured  = 0;
    OpcUa_UInt32                    uintPreviousEventMask   = 0;
    OpcUa_UInt32                    uintTimeDifference      = 0;
    OpcUa_UInt32                    uintReturnValue         = 0;

    OpcUa_Boolean                   bForcedByTimer          = OpcUa_False;
    /* more of a hack, since we always wait for shutdown, it shouldnt be given as parameter except when run once. */
    OpcUa_Boolean                   bEndloop                = (a_uEvent==OPCUA_SOCKET_SHUTDOWN_EVENT)?OpcUa_True:OpcUa_False;
    OpcUa_Boolean                   bWaitFlagSet            = OpcUa_False;

    OpcUa_TimeVal                   tmLocalTimeout;
    OpcUa_InternalSocket*           pLocalSocket            = OpcUa_Null;
    OpcUa_RawSocket                 RawSocket               = ((OpcUa_InternalSocket*)a_pSocket) ? ((OpcUa_InternalSocket*)a_pSocket)->rawSocket : OpcUa_Null;
    OpcUa_InternalSocketManager*    pInternalSocketManager  = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Socket, "P_ServeLoop");

    /* cap */
    if(a_msecTimeout > OPCUA_SOCKET_MAXLOOPTIME)
    {
        a_msecTimeout = OPCUA_SOCKET_MAXLOOPTIME;
    }

    /* No Socket List given, use default list */
    if(a_pSocketManager == OpcUa_Null)
    {
        pInternalSocketManager = &OpcUa_Socket_g_SocketManager;
    }
    else
    {
        pInternalSocketManager = (OpcUa_InternalSocketManager*)a_pSocketManager;
    }

    OpcUa_P_Mutex_Lock(pInternalSocketManager->pMutex);

    /* the serving loop */
    do
    {
        bForcedByTimer  = OpcUa_False;
        msecInterval    = a_msecTimeout;

        OpcUa_P_Mutex_Unlock(pInternalSocketManager->pMutex);

        /* map msec to timeval */
        tmLocalTimeout.uintSeconds      = a_msecTimeout / 1000;
        tmLocalTimeout.uintMicroSeconds = (OpcUa_UInt32)((a_msecTimeout - tmLocalTimeout.uintSeconds * 1000) * 1000);

        OpcUa_GotoErrorIfBad(uStatus);

        if(uStatus == OpcUa_GoodNonCriticalTimeout)
        {
            /* map timeval to msec */
            msecInterval    = (OpcUa_UInt32)(tmLocalTimeout.uintSeconds * 1000 + tmLocalTimeout.uintMicroSeconds / 1000);

            bForcedByTimer  = OpcUa_True;

            /* obey cap */
            if(msecInterval > OPCUA_SOCKET_MAXLOOPTIME)
            {
                msecInterval = OPCUA_SOCKET_MAXLOOPTIME;
            }

            if(a_msecTimeout != OPCUA_P_SOCKET_INFINITE)
            {
                /* calculate and store next registered timeout */
                a_msecTimeout = a_msecTimeout - msecInterval;
            }
        }


        OpcUa_P_Mutex_Lock(pInternalSocketManager->pMutex);

        /* check for signal socket */
        if(pInternalSocketManager->pCookie == OpcUa_Null)
        {
            /* we are missing the signal socket; create a new one */
            uStatus = OpcUa_P_SocketManager_NewSignalSocket(pInternalSocketManager);

            if(uStatus != OpcUa_Good)
            {
                goto Error;
            }
        }

        /* clear socket arrays */
        OPCUA_P_SOCKET_ARRAY_ZERO(&readFdSet);
        OPCUA_P_SOCKET_ARRAY_ZERO(&writeFdSet) ;
        OPCUA_P_SOCKET_ARRAY_ZERO(&exceptFdSet);

        /* fill fdsets with the sockets from the SocketManager */
        OpcUa_P_Socket_FillFdSet(pInternalSocketManager, &readFdSet,   OPCUA_SOCKET_READ_EVENT);
        OpcUa_P_Socket_FillFdSet(pInternalSocketManager, &writeFdSet, (OPCUA_SOCKET_WRITE_EVENT | OPCUA_SOCKET_CONNECT_EVENT));
        OpcUa_P_Socket_FillFdSet(pInternalSocketManager, &exceptFdSet, OPCUA_SOCKET_EXCEPT_EVENT);

        /* check for errors */
        if(     (readFdSet.uintNbSockets    == 0)
            &&  (writeFdSet.uintNbSockets   == 0)
            &&  (exceptFdSet.uintNbSockets  </*=*/ 1)) /* always contains the Signal Socket */
        {
            /* no valid socket in list -> exit list handling */
            uStatus = OpcUa_BadNotFound;

            /* in multithreading, we may have certain conditions when the loop is started before a user socket */
            /* is added to the list. It would not be ok to bail out in this case. */
            OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OpcUa_P_SocketManager_ServeLoop: socket list is empty!\n");
            goto Error;
        }

        /* check for external events (1) */
        /* right after possible loop reentry delay */
        uStatus = OpcUa_P_Socket_HandleExternalEvent(pInternalSocketManager, a_uEvent, a_puEventOccured);
        OpcUa_GotoErrorIfBad(uStatus);

        /* leave if a shutdown event was signalled */
        if(OpcUa_IsEqual(OpcUa_GoodShutdownEvent))
        {
            break;
        }

        OpcUa_P_Mutex_Unlock(pInternalSocketManager->pMutex);

        /* map msec timeout to timeval */
        /* TODO: This happens far too often; redesign this; use msec until raw select! */
        tmLocalTimeout.uintSeconds      =  (msecInterval / 1000);
        tmLocalTimeout.uintMicroSeconds = ((msecInterval % 1000) * 1000);


        /****************************************************************/
        /* This is the only point in the whole engine, where blocking   */
        /* of the current thread is allowed. Else, processing of        */
        /* network events is slowed down!                               */
#if OPCUA_MULTITHREADED
        selectStatus = OpcUa_P_RawSocket_Select(    0, /* ignore on win */
                                                    &readFdSet,
                                                    &writeFdSet,
                                                    &exceptFdSet,
                                                    &tmLocalTimeout);
#else
        /* if we're here, the processing socketmanager should better be the global one...! */
        /* maybe test this state here */
        /* The provided ST config implements lowres timers via the global socketmanager's select timeout ... yes, it's lame ... */
        /* Thanks to Andy Griffith for the TimeredSelect and the Timer implementation in general. */
        selectStatus = OpcUa_P_Socket_TimeredSelect(0, /* ignore on win */
                                                    &readFdSet,
                                                    &writeFdSet,
                                                    &exceptFdSet,
                                                    &tmLocalTimeout);
#endif
        /*                                                              */
        /****************************************************************/


        OpcUa_P_Mutex_Lock(pInternalSocketManager->pMutex);

        /* check for external events (2) */
        /* right after possible select delay */
        uStatus = OpcUa_P_Socket_HandleExternalEvent(pInternalSocketManager, a_uEvent, a_puEventOccured);
        OpcUa_GotoErrorIfBad(uStatus);

        /* leave if a shutdown event was signalled */
        if(OpcUa_IsEqual(OpcUa_GoodShutdownEvent))
        {
            break;
        }

        /* handle errors in select */
        if(     OpcUa_IsBad(selectStatus)
            && (selectStatus != OpcUa_BadTimeout)          /* ignore timer event */
            && (selectStatus != OpcUa_BadInvalidArgument)) /* ignore invalid socket handles */
        {
            /* check for renew event set externally in list */
            if(((pInternalSocketManager->uintLastExternalEvent) & OPCUA_SOCKET_RENEWLOOP_EVENT) != OPCUA_SOCKET_NO_EVENT)
            {
                /* loop has been interrupted externally to restart with the new/changed list */
                continue;
            }

            /* no renew -> error happened in select and is unexpected, stop server */
            uStatus = OpcUa_BadCommunicationError;
            goto Error;
        }


        /* test if waiting socket returned an event we are waiting for */
        if(     a_uEvent  != OPCUA_SOCKET_NO_EVENT
            &&  a_pSocket != OpcUa_Null)
        {
            uintReturnValue = 0;

            if(         (OPCUA_P_SOCKET_ARRAY_ISSET(RawSocket, &readFdSet))
                    &&  (a_uEvent & OPCUA_SOCKET_READ_EVENT))
            {
                uintReturnValue |= OPCUA_SOCKET_READ_EVENT;
            }
            else if(    (OPCUA_P_SOCKET_ARRAY_ISSET(RawSocket, &writeFdSet))
                    &&  (a_uEvent & OPCUA_SOCKET_WRITE_EVENT))
            {
                uintReturnValue |= OPCUA_SOCKET_WRITE_EVENT;
            }
            else if(    (OPCUA_P_SOCKET_ARRAY_ISSET(RawSocket, &exceptFdSet))
                    &&  (a_uEvent & OPCUA_SOCKET_EXCEPT_EVENT))
            {
                uintReturnValue |= OPCUA_SOCKET_EXCEPT_EVENT;
            }

            pLocalSocket = OpcUa_P_Socket_FindSocketEntry(pInternalSocketManager, RawSocket);
            if(pLocalSocket != OpcUa_Null)
            {
                if(uintReturnValue)
                {
                    uintSocketEventOccured = uintReturnValue;
                }

                /* test timeout waiting socket */
                if(pLocalSocket->uintTimeout !=0)
                {
                    /* check for Timeout too */
                    uintTimeDifference = (OpcUa_P_GetTickCount()/1000) - pLocalSocket->uintLastAccess;
                    if(uintTimeDifference > pLocalSocket->uintTimeout)
                    {
                        /* Socket timed out */
                        pLocalSocket->uintLastAccess = OpcUa_P_GetTickCount()/1000;

                        uintSocketEventOccured = OPCUA_SOCKET_TIMEOUT_EVENT;
                    }
                }
            }
            else
            {
                uintSocketEventOccured = OPCUA_SOCKET_EXCEPT_EVENT;
            }

            if(uintSocketEventOccured)
            {
                if (pLocalSocket)
                {
                    if(bWaitFlagSet) /* was an explicit wait (timer) */
                    {
                        OpcUa_P_Socket_ResetWaitingSocketEvent(pLocalSocket, uintPreviousEventMask);
                    }
                }

                if(a_puEventOccured != OpcUa_Null)
                {
                    *a_puEventOccured = uintSocketEventOccured;
                }

                uStatus = OpcUa_GoodCommunicationEvent;
            }
        }

        /* Handle Events by calling the registered callbacks (all sockets except the waiting socket) */
        OpcUa_P_Socket_HandleFdSet(pInternalSocketManager, &exceptFdSet,  OPCUA_SOCKET_EXCEPT_EVENT);
        OpcUa_P_Socket_HandleFdSet(pInternalSocketManager, &readFdSet,    OPCUA_SOCKET_READ_EVENT);
        OpcUa_P_Socket_HandleFdSet(pInternalSocketManager, &writeFdSet,  (OPCUA_SOCKET_WRITE_EVENT | OPCUA_SOCKET_CONNECT_EVENT));

        /* check for external events (3) */
        /* right after possible event handling delay (get the picture...) */
        uStatus = OpcUa_P_Socket_HandleExternalEvent(pInternalSocketManager, a_uEvent, a_puEventOccured);
        OpcUa_GotoErrorIfBad(uStatus);

        /* leave if a shutdown event was signalled */
        if(OpcUa_IsEqual(OpcUa_GoodShutdownEvent))
        {
            break;
        }

        /* check for timeout in select */
        if(     (selectStatus == OpcUa_BadTimeout)
            &&  (!bForcedByTimer))
        {
            if(bWaitFlagSet)
            {
                pLocalSocket = OpcUa_P_Socket_FindSocketEntry(pInternalSocketManager, RawSocket);
                if(pLocalSocket != OpcUa_Null)
                {
                    OpcUa_P_Socket_ResetWaitingSocketEvent(pLocalSocket, uintPreviousEventMask);
                }
            }

            uStatus = OpcUa_BadTimeout;
            goto Error;
        }
    } while(!bEndloop);

    OpcUa_P_Mutex_Unlock(pInternalSocketManager->pMutex);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_P_Mutex_Unlock(pInternalSocketManager->pMutex);

OpcUa_FinishErrorHandling;
}

/*============================================================================
* Reset the event mask of a waiting socket.
*===========================================================================*/
OpcUa_Boolean OpcUa_P_Socket_ResetWaitingSocketEvent(OpcUa_Socket pSocket, OpcUa_UInt32 uintPreviousEventMask)
{
    if((OpcUa_InternalSocket*)pSocket)
    {
        ((OpcUa_InternalSocket*)pSocket)->Flags.bInternalWait = OpcUa_False;

        if(uintPreviousEventMask)
        {
            ((OpcUa_InternalSocket*)pSocket)->Flags.EventMask = uintPreviousEventMask;
        }

        return OpcUa_True;
    }

    return OpcUa_False;
}

/*============================================================================
* SetWaitingSocketEvent
*===========================================================================*/
OpcUa_Boolean OpcUa_P_Socket_SetWaitingSocketEvent( OpcUa_Socket pSocket,
                                                    OpcUa_UInt32 uintEvent,
                                                    OpcUa_UInt32* puintPreviousEventMask)
{
    if(     (pSocket   != OpcUa_Null)
        &&  (uintEvent != 0))
    {
        ((OpcUa_InternalSocket*)pSocket)->Flags.bInternalWait = OpcUa_True;
        if(uintEvent != ((((OpcUa_InternalSocket*)pSocket)->Flags.EventMask) & (uintEvent)))
        {
            *puintPreviousEventMask = ((OpcUa_InternalSocket*)pSocket)->Flags.EventMask;
            ((OpcUa_InternalSocket*)pSocket)->Flags.EventMask |= uintEvent;
        }

        return OpcUa_True;
    }

    return OpcUa_False;
}

/*============================================================================
* FillFdSet
*===========================================================================*/
OpcUa_StatusCode OpcUa_P_Socket_FillFdSet(  OpcUa_SocketManager     pSocketManager,
                                            OpcUa_P_Socket_Array*   pSocketArray,
                                            OpcUa_UInt32            uintEvent)
{
    OpcUa_UInt32                    uintIndex               = 0;
    OpcUa_UInt32                    uintTempEvent           = 0;
    OpcUa_StatusCode                uStatus                 = OpcUa_BadInternalError;
    OpcUa_InternalSocketManager*    pInternalSocketManager  = (OpcUa_InternalSocketManager*)pSocketManager;

    OPCUA_P_SOCKET_ARRAY_ZERO(pSocketArray);

    OpcUa_ReturnErrorIfArgumentNull(pInternalSocketManager);

    for (uintIndex = 0; uintIndex < pInternalSocketManager->uintMaxSockets; uintIndex++)
    {
        uintTempEvent = uintEvent;

        /* if socket used and valid */
        if(     (pInternalSocketManager->pSockets[uintIndex].Flags.bSocketIsInUse  != OpcUa_False)
            &&  (OPCUA_SOCKET_ISVALID_S(pInternalSocketManager->pSockets[uintIndex])))
        {
            /* is connect event wished by caller? */
            if((uintTempEvent & OPCUA_SOCKET_CONNECT_EVENT) != 0)
            {
                /* and is connect event wished by socket? */
                if(((pInternalSocketManager->pSockets[uintIndex].Flags.EventMask) & OPCUA_SOCKET_CONNECT_EVENT) != 0)
                {
                    /* then set to connect only */
                    uintTempEvent = OPCUA_SOCKET_CONNECT_EVENT;
                }
                else
                {
                    /* else remove connect event */
                    uintTempEvent &= ~ OPCUA_SOCKET_CONNECT_EVENT;
                }
            }

            /* ignore application sockets */
            if(pInternalSocketManager->pSockets[uintIndex].Flags.bFromApplication == OpcUa_False)
            {
                /* if only uintTemp is wished, set the socket in the fd_set */
                if(((pInternalSocketManager->pSockets[uintIndex].Flags.EventMask) & uintTempEvent) == uintTempEvent)
                {
                    OPCUA_P_SOCKET_ARRAY_SET(pInternalSocketManager->pSockets[uintIndex].rawSocket, pSocketArray);
                    uStatus = OpcUa_Good;
                }
            }
        }
    }

    return uStatus;
}

/*============================================================================
* FindSocketEntry
*===========================================================================*/
/* find a socket in the socket list, identified by the raw socket handle. */
OpcUa_Socket OpcUa_P_Socket_FindSocketEntry(   OpcUa_SocketManager pSocketManager,
                                               OpcUa_RawSocket     RawSocket)
{
    OpcUa_StatusCode             uStatus                = OpcUa_Good;
    OpcUa_UInt32                 uintIndex              = 0;
    OpcUa_InternalSocketManager* pInternalSocketManager = pSocketManager;

    OpcUa_GotoErrorIfArgumentNull(pSocketManager);
    OpcUa_GotoErrorIfArgumentNull(RawSocket);

    for(uintIndex = 0; uintIndex < pInternalSocketManager->uintMaxSockets; uintIndex++)
    {
        if(pInternalSocketManager->pSockets[uintIndex].Flags.bSocketIsInUse != OpcUa_False)
        {
            if(pInternalSocketManager->pSockets[uintIndex].rawSocket == RawSocket)
            {
                return &pInternalSocketManager->pSockets[uintIndex];
            }
        }
    }

Error:
    return OpcUa_Null;
}

/*============================================================================
* CreateServer
*===========================================================================*/
/* create a socket and configure it as a server socket */
OpcUa_RawSocket OpcUa_P_Socket_CreateServer(    OpcUa_Int16         Port,
                                                OpcUa_StatusCode*   Status)
{
    OpcUa_StatusCode    uStatus      = OpcUa_Good;
    OpcUa_RawSocket     RawSocket   = (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID;

    OpcUa_ReferenceParameter(Port);

    uStatus = OpcUa_P_RawSocket_Create(     &RawSocket,
                                            OpcUa_True,     /* Nagle off */
                                            OpcUa_False);   /* No keep-alive */
    OpcUa_GotoErrorIfBad(uStatus);

#if 1
    OpcUa_GotoErrorIfTrue((RawSocket == (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID), OpcUa_BadCommunicationError);
#else
    if((RawSocket == (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID))
    {
        goto Error;
    }
#endif
    /* set nonblocking */
    uStatus = OpcUa_P_RawSocket_SetBlockMode(   RawSocket,
                                                OpcUa_False);
    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = OpcUa_P_RawSocket_Bind(RawSocket, Port);
    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = OpcUa_P_RawSocket_Listen(RawSocket);
    OpcUa_GotoErrorIfBad(uStatus);

    if(Status != OpcUa_Null)
    {
        *Status = OpcUa_P_RawSocket_GetLastError(RawSocket);
    }

    return RawSocket;

Error:
    if(Status != OpcUa_Null)
    {
        *Status = uStatus;
    }

    /* ignore errors which may happen, when RawSocket is invalid */
    OpcUa_P_RawSocket_Close(RawSocket);

    return (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID;
}

/*============================================================================
* HandleFdSet
*===========================================================================*/
OpcUa_Void OpcUa_P_Socket_HandleFdSet(  OpcUa_SocketManager     a_pSocketManager,
                                        OpcUa_P_Socket_Array*   a_pSocketArray,
                                        OpcUa_UInt32            a_uEvent)
{
    OpcUa_InternalSocketManager*    pInternalSocketManager         = (OpcUa_InternalSocketManager*)a_pSocketManager;
    OpcUa_UInt32                    uintIndex           = 0;
    OpcUa_UInt32                    uintLocalEvent      = 0;
    OpcUa_UInt32                    uintTimeDifference  = 0; /* seconds */

    if(pInternalSocketManager == OpcUa_Null)
    {
        return;
    }

    for(uintIndex = 0; uintIndex < pInternalSocketManager->uintMaxSockets; uintIndex++)
    {
        uintLocalEvent = a_uEvent;

        if (    (pInternalSocketManager->pSockets[uintIndex].Flags.bSocketIsInUse  != OpcUa_False)
            &&  (OPCUA_SOCKET_ISVALID_S(pInternalSocketManager->pSockets[uintIndex]))
            &&  (pInternalSocketManager->pSockets[uintIndex].Flags.bInternalWait   == OpcUa_False))
        {
            if(OPCUA_P_SOCKET_ARRAY_ISSET(pInternalSocketManager->pSockets[uintIndex].rawSocket, a_pSocketArray))
            {
                if( (uintLocalEvent == OPCUA_SOCKET_READ_EVENT) && (pInternalSocketManager->pSockets[uintIndex].Flags.bIsListenSocket != 0))
                {
                    uintLocalEvent = OPCUA_SOCKET_ACCEPT_EVENT;
                }

                if(0 != (uintLocalEvent & OPCUA_SOCKET_CONNECT_EVENT) )
                {
                    if(0 != ((pInternalSocketManager->pSockets[uintIndex].Flags.EventMask) & OPCUA_SOCKET_CONNECT_EVENT ))
                    {
                        uintLocalEvent = OPCUA_SOCKET_CONNECT_EVENT;
                    }
                    else
                    {
                        uintLocalEvent &=~ OPCUA_SOCKET_CONNECT_EVENT;
                    }
                }

                pInternalSocketManager->pSockets[uintIndex].Flags.bFromApplication = OpcUa_True;
#if 1 /* not sure about processing this further; would need to transport the information along; better access later or store in OpcUa_Socket->LastError? */
                /* the real reason for exception events is received through getsockopt with SO_ERROR */
                if(uintLocalEvent == OPCUA_SOCKET_EXCEPT_EVENT)
                {
                    OpcUa_Int apiResult = 0;
                    OpcUa_Int value     = 0;
                    OpcUa_Int size      = sizeof(value);
                    apiResult = getsockopt((SOCKET)(pInternalSocketManager->pSockets[uintIndex].rawSocket), SOL_SOCKET, SO_ERROR, (char*)&value, &size);
                    /* 10061 WSAECONNREFUSED OpcUa_BadSocketConnectionRejected */
                    apiResult = 0;
                }
#endif
                OpcUa_Socket_HandleEvent(&pInternalSocketManager->pSockets[uintIndex], uintLocalEvent);

                pInternalSocketManager->pSockets[uintIndex].Flags.bFromApplication = OpcUa_False;
            }

            if(uintLocalEvent == OPCUA_SOCKET_EXCEPT_EVENT)
            {
                /* Only check timeout, if a timeout value is set for the socket */
                if(pInternalSocketManager->pSockets[uintIndex].uintTimeout != 0)
                {
                    /* check for Timeout too */
                    uintTimeDifference = (OpcUa_P_GetTickCount()/1000) - pInternalSocketManager->pSockets[uintIndex].uintLastAccess;

                    if(uintTimeDifference > pInternalSocketManager->pSockets[uintIndex].uintTimeout)
                    {
                        /* the connection on this socket timed out */
                        pInternalSocketManager->pSockets[uintIndex].uintLastAccess         = OpcUa_P_GetTickCount()/1000;
                        pInternalSocketManager->pSockets[uintIndex].Flags.bFromApplication = OpcUa_True;

                        OpcUa_Socket_HandleEvent(&pInternalSocketManager->pSockets[uintIndex], OPCUA_SOCKET_TIMEOUT_EVENT);

                        pInternalSocketManager->pSockets[uintIndex].Flags.bFromApplication = OpcUa_False;
                    }
                }
            }
        }
    }

    return;
}

/*============================================================================
* HandleExternalEvent
*===========================================================================*/
OpcUa_StatusCode OpcUa_P_Socket_HandleExternalEvent(    OpcUa_SocketManager a_pSocketManager,
                                                        OpcUa_UInt32        a_uEvent,
                                                        OpcUa_UInt32*       a_puEventOccured)
{
    OpcUa_UInt32                 uExternalEvent         = OPCUA_SOCKET_NO_EVENT;
    OpcUa_InternalSocketManager* pInternalSocketManager = (OpcUa_InternalSocketManager*)a_pSocketManager;

OpcUa_InitializeStatus(OpcUa_Module_Socket, "P_HandleExternalEvent");

    OpcUa_GotoErrorIfArgumentNull(a_pSocketManager);

    if(pInternalSocketManager->uintLastExternalEvent != OPCUA_SOCKET_NO_EVENT)
    {
        uExternalEvent = pInternalSocketManager->uintLastExternalEvent;

        /* are we waiting on this certain event */
        if(   (a_puEventOccured             != OpcUa_Null)
           && ((a_uEvent & uExternalEvent)  != 0))
        {
            pInternalSocketManager->uintLastExternalEvent &= ~a_uEvent;
            *a_puEventOccured                        = uExternalEvent & a_uEvent;
            uStatus = OpcUa_GoodCommunicationEvent;
        }

        /* was this the Shutdown Event, raised by the system? */
        if((uExternalEvent & OPCUA_SOCKET_SHUTDOWN_EVENT) != OPCUA_SOCKET_NO_EVENT)
        {
            /* if uStatus !=  */
            uStatus = OpcUa_GoodShutdownEvent;
        }
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
*
*===========================================================================*/
OpcUa_RawSocket OpcUa_P_Socket_CreateClient(    OpcUa_UInt16        a_uPort,
                                                OpcUa_UInt16        a_uRemotePort,
                                                OpcUa_StringA       a_sRemoteAddress,
                                                OpcUa_StatusCode*   a_uStatus)
{
    OpcUa_StatusCode    uStatus      = OpcUa_Good;
    OpcUa_RawSocket     RawSocket   = (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID;

    uStatus = OpcUa_P_RawSocket_Create(    &RawSocket,
                                           OpcUa_True,     /* Nagle off        */
                                            OpcUa_False);   /* Keep alive off   */
    OpcUa_GotoErrorIfBad(uStatus);
    if(RawSocket == (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID)
    {
        goto Error;
    }

    /* set nonblocking */
    uStatus = OpcUa_P_RawSocket_SetBlockMode(   RawSocket,
                                                OpcUa_False);
    OpcUa_GotoErrorIfBad(uStatus);

    if(a_uPort != (OpcUa_UInt16)0)
    {
        uStatus = OpcUa_P_RawSocket_Bind(RawSocket, a_uPort);
        OpcUa_GotoErrorIfBad(uStatus);
    }

    if(a_uRemotePort != 0)
    {
        uStatus = OpcUa_P_RawSocket_Connect(    RawSocket,
                                                a_uRemotePort,
                                                a_sRemoteAddress);
        if(OpcUa_IsBad(uStatus))
        {
            /* we are nonblocking and would block is not an error in this mode */
            if(uStatus != OpcUa_BadWouldBlock)
            {
                goto Error;
            }
            else
            {
                uStatus = OpcUa_Good;
            }
        }
    }

    if(a_uStatus != OpcUa_Null)
    {
        *a_uStatus = uStatus;
    }

    return RawSocket;

Error:

    if(a_uStatus != OpcUa_Null)
    {
        if(OpcUa_IsBad(uStatus))
        {
            *a_uStatus = uStatus;
        }
    }

    OpcUa_P_RawSocket_Close(RawSocket); /* just in case */
    return (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID;
}

#if 0
/*============================================================================
 * Wait for a certain event to happen for a maximum of time.
 *===========================================================================*/
/* implicit call to the serveloop, but can be called without knowledge about the
   socketmanager. This stacks the serveloop. used for write all */
OpcUa_StatusCode OpcUa_Socket_WaitForEvent( OpcUa_Socket  a_pSocket,
                                            OpcUa_UInt32  a_uEvent,
                                            OpcUa_UInt32  a_msecTimeout,
                                            OpcUa_UInt32* a_pEventOccured)
{
    OpcUa_InternalSocket*   pIntSock                = (OpcUa_InternalSocket*)a_pSocket;
    OpcUa_Int               bFromApplicationSave    = OpcUa_False;

OpcUa_InitializeStatus(OpcUa_Module_Socket, "WaitForEvent");

    OpcUa_GotoErrorIfArgumentNull(a_pSocket);

    /* save old value */
    bFromApplicationSave = pIntSock->Flags.bFromApplication;

    /* we're stacked */
    pIntSock->Flags.bFromApplication = OpcUa_True;
    uStatus = OpcUa_P_SocketManager_ServeLoopInternal(  pIntSock->pSocketManager,
                                                        a_msecTimeout,
                                                        a_pSocket,
                                                        a_uEvent,
                                                        a_pEventOccured);

    /* restore old value */
    pIntSock->Flags.bFromApplication = OpcUa_False;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}
#endif
