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
/** @file platform indepented implementation of the socketmanager/socket architecture                 */
/******************************************************************************************************/

/* System Headers */
#include <windows.h>

/* UA platform definitions */
#include <opcua_p_internal.h>

/* UA platform definitions */
#include <opcua_datetime.h>

#include <opcua_p_semaphore.h>
#include <opcua_p_thread.h>
#include <opcua_p_mutex.h>
#include <opcua_p_utilities.h>
#include <opcua_p_memory.h>


/* own headers */
#include <opcua_p_socket.h>
#include <opcua_p_socket_internal.h>
#include <opcua_p_socket_interface.h>

#if OPCUA_MULTITHREADED
    OpcUa_InternalSocketManager* OpcUa_P_Socket_g_pSocketManagers[OPCUA_SOCKET_MAXMANAGERS];

    #if OPCUA_USE_SYNCHRONISATION
        OpcUa_Mutex  OpcUa_P_Socket_g_SocketManagersMutex;
        OpcUa_Mutex  OpcUa_P_Socket_g_ShutdownMutex;
        OpcUa_UInt32 OpcUa_P_Socket_g_uNuOfClientThreads = 0;
    #endif /* OPCUA_USE_SYNCHRONISATION */
#endif /* OPCUA_MULTITHREADED */

/** @brief The global socket manager, used in singlethreading configuration */
OpcUa_InternalSocketManager OpcUa_Socket_g_SocketManager;
/** @brief The array of sockets used by the global socket list. */
OpcUa_InternalSocket OpcUa_Socket_g_SocketArray[OPCUA_P_SOCKETMANAGER_NUMBEROFSOCKETS];

#if OPCUA_MULTITHREADED
/*============================================================================
 * This function serves a single socket manager in multithreading configuration.
 *===========================================================================*/
/* HINT: That is a thread entry point and wrapper for the real serverloop. */
 OpcUa_Void OpcUa_P_SocketManager_ServerLoopThread(OpcUa_Void* a_pArgument)
{
    OpcUa_StatusCode                uStatus                 = OpcUa_Good;                   /* only needed for internal reasons */
    OpcUa_InternalSocketManager*    pInternalSocketManager  = (OpcUa_InternalSocketManager*)a_pArgument;
    OpcUa_UInt32                    uintExternalEvent       = OPCUA_SOCKET_NO_EVENT;

    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_P_SocketManager_ServerLoopThread: Serving...\n");

    do
    {
        uStatus = OpcUa_P_SocketManager_ServeLoopInternal(  pInternalSocketManager,
                                                            OpcUa_UInt32_Max,
                                                            OpcUa_Null,
                                                            OPCUA_SOCKET_NO_EVENT,
                                                            &uintExternalEvent);

        if(OpcUa_IsEqual(OpcUa_GoodShutdownEvent))
        {
            /* leave this loop if a shutdown was signalled */
            pInternalSocketManager->Flags.bStopServerLoop = OpcUa_True;
        }
        else if(OpcUa_IsEqual(OpcUa_BadNotFound)) /* ignore empty list; TODO: works, but need to find a better way and block until the list gets changed. */
        {
            uStatus = OpcUa_Good;
        }

    } while((pInternalSocketManager->Flags.bStopServerLoop == OpcUa_False) && OpcUa_IsGood(uStatus));

    /* Debug Output */
    if(pInternalSocketManager->Flags.bStopServerLoop != OpcUa_False)
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_P_SocketManager_ServerLoopThread: Stop Serving due stop flag.\n");
    }
    else
    {
        if(OpcUa_IsEqual(OpcUa_BadNotFound))
        {
            /* should not be reached! */
            OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_P_SocketManager_ServerLoopThread: Stop Serving because no active sockets are in list.\n");
        }
        else
        {
            OpcUa_Trace(OPCUA_TRACE_LEVEL_WARNING, "OpcUa_P_SocketManager_ServerLoopThread: Stop Serving due bad status.\n");
        }
    }

    OpcUa_P_Semaphore_Post( pInternalSocketManager->pShutdownEvent,
                            1);

    return;
}
#endif /* OPCUA_MULTITHREADED */

/*============================================================================
 * Break server loop(s) and issue event(s).
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_SocketManager_InterruptLoop( OpcUa_SocketManager a_pSocketManager,
                                                                    OpcUa_UInt32        a_uEvent,
                                                                    OpcUa_Boolean       a_bAllManagers)
{
    OpcUa_InternalSocket*           pSignalSocket          = OpcUa_Null;
    OpcUa_InternalSocketManager*    pInternalSocketManager = OpcUa_Null;
#if OPCUA_MULTITHREADED
    OpcUa_UInt32                    uintSocketManagerIndex = 0;
#endif /* OPCUA_MULTITHREADED */

OpcUa_InitializeStatus(OpcUa_Module_Socket, "InterruptLoop");

    OpcUa_ReferenceParameter(a_bAllManagers);
#if OPCUA_MULTITHREADED
    OpcUa_ReferenceParameter(uintSocketManagerIndex);
#endif /* OPCUA_MULTITHREADED */

    if(a_uEvent == OPCUA_SOCKET_NO_EVENT)
    {
        uStatus = OpcUa_BadInternalError;
        goto Error;
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

#if OPCUA_MULTITHREADED
#if OPCUA_USE_SYNCHRONISATION
    OpcUa_P_Mutex_Lock(OpcUa_P_Socket_g_SocketManagersMutex);
#endif /* OPCUA_USE_SYNCHRONISATION */

    while(pInternalSocketManager != OpcUa_Null)
    {
#endif /* OPCUA_MULTITHREADED */
        /* get exclusive access to the list */
        if(pInternalSocketManager->pMutex != OpcUa_Null)
        {
            OpcUa_P_Mutex_Lock(pInternalSocketManager->pMutex);
        }


        /************ core begin ************/
        /* set event(s) */
        pInternalSocketManager->uintLastExternalEvent |= a_uEvent;

        /* get the signal socket, which is hidden as a cookie */
        if(pInternalSocketManager->pCookie != OpcUa_Null)
        {
            pSignalSocket = (OpcUa_InternalSocket*)pInternalSocketManager->pCookie;
            pInternalSocketManager->pCookie = OpcUa_Null;
        }

        /* if there, close it to break selects */
        if(pSignalSocket)
        {
            uStatus = OpcUa_P_Socket_Close((OpcUa_Socket)pSignalSocket);
            if(OpcUa_IsBad(uStatus))
            {
                /* something went wrong and we may not get our signal */
                goto Error;
            }
        }
        /************* core end *************/

        /* release exclusive access to the list */
        if(pInternalSocketManager->pMutex != OpcUa_Null)
        {
            OpcUa_P_Mutex_Unlock(pInternalSocketManager->pMutex);
        }

#if OPCUA_MULTITHREADED

        /* free vars */
        pSignalSocket           = OpcUa_Null;
        pInternalSocketManager  = OpcUa_Null;

        /* get next list */
        while(      (a_bAllManagers != OpcUa_False)
                &&  (pInternalSocketManager == OpcUa_Null)
                &&  (uintSocketManagerIndex < OPCUA_SOCKET_MAXMANAGERS))
        {
            pInternalSocketManager = OpcUa_P_Socket_g_pSocketManagers[uintSocketManagerIndex];

            if(OpcUa_P_Socket_g_pSocketManagers[uintSocketManagerIndex] != OpcUa_Null)
            {
                OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_P_SocketManager_InterruptLoop: Dyn. SocketManager gets notified!\n");
            }

            uintSocketManagerIndex++;
        }
    }
#if OPCUA_USE_SYNCHRONISATION
    OpcUa_P_Mutex_Unlock(OpcUa_P_Socket_g_SocketManagersMutex);
#endif /* OPCUA_USE_SYNCHRONISATION */
#else /* OPCUA_MULTITHREADED */
    /* free vars */
    pSignalSocket           = OpcUa_Null;
    pInternalSocketManager  = OpcUa_Null;
    OpcUa_ReferenceParameter(a_bAllManagers); /* unused when single threaded */
#endif /* OPCUA_MULTITHREADED */

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* release exclusive access to the list */
    OpcUa_P_Mutex_Unlock(pInternalSocketManager->pMutex);

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * Call the main serve loop for a certain socket list.
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_SocketManager_ServeLoop( OpcUa_SocketManager a_pSocketManager,
                                                                OpcUa_UInt32        a_msecTimeout,
                                                                OpcUa_Boolean       a_bRunOnce)
{
OpcUa_InitializeStatus(OpcUa_Module_Socket, "ServeLoop");

    uStatus =  OpcUa_P_SocketManager_ServeLoopInternal( a_pSocketManager,
                                                        a_msecTimeout,
                                                        OpcUa_Null,  /* socket */
                                                        a_bRunOnce!=OpcUa_False?OPCUA_SOCKET_SHUTDOWN_EVENT:OPCUA_SOCKET_NO_EVENT,
                                                        OpcUa_Null);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * Create a new socket manager or initialize the global one (OpcUa_Null first).
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_SocketManager_Create(OpcUa_SocketManager*    a_pSocketManager,
                                                            OpcUa_UInt32            a_nSockets,
                                                            OpcUa_UInt32            a_nFlags)
{
    OpcUa_InternalSocketManager*   pInternalSocketManager   = OpcUa_Null;
#if OPCUA_MULTITHREADED
    OpcUa_Boolean                   bCreateServerThread         = OpcUa_True;
#endif

OpcUa_InitializeStatus(OpcUa_Module_Socket, "SocketManager_Create");

    if(a_nFlags & 0xFFFFFFF8)
    {
        uStatus = OpcUa_BadInvalidArgument;
        OpcUa_GotoError;
    }

    a_nSockets += 1; /* add signal socket to requested sockets */

    if(a_nSockets > OPCUA_P_SOCKETMANAGER_NUMBEROFSOCKETS)
    {
        uStatus = OpcUa_BadInvalidArgument;
        OpcUa_GotoError;
    }

    /* set number of socket to maximum */
    if(a_nSockets == 0)
    {
        a_nSockets = OPCUA_P_SOCKETMANAGER_NUMBEROFSOCKETS;
    }

    if(a_pSocketManager != OpcUa_Null)
    {
        *a_pSocketManager = OpcUa_SocketManager_Alloc();
        OpcUa_GotoErrorIfAllocFailed(*a_pSocketManager);

        pInternalSocketManager = (OpcUa_InternalSocketManager*)*a_pSocketManager;

        OpcUa_SocketManager_Initialize(pInternalSocketManager);

        uStatus = OpcUa_P_Mutex_Create(&(pInternalSocketManager->pMutex));
        if(OpcUa_IsBad(uStatus))
        {
            free(pInternalSocketManager);
            return uStatus;
        }

        /* create a semaphore with no free ressources for which a host can wait to be signalled. */
        uStatus = OpcUa_P_Semaphore_Create( &(pInternalSocketManager->pShutdownEvent), 0, 1);
        if(OpcUa_IsBad(uStatus))
        {
            OpcUa_P_Mutex_Delete(&(pInternalSocketManager->pMutex));
            free(pInternalSocketManager);
            return uStatus;
        }

        /* preallocate socket structures for all possible sockets (maxsockets) */
        uStatus = OpcUa_SocketManager_CreateSockets((OpcUa_SocketManager)pInternalSocketManager, a_nSockets);
        OpcUa_GotoErrorIfBad(uStatus);
    }
    else /* if(a_ppSocketManager != OpcUa_Null) */
    {
        OpcUa_UInt32 ntemp = 0;
        /* no manager specified, use default manager */
        pInternalSocketManager = (OpcUa_InternalSocketManager*)&OpcUa_Socket_g_SocketManager;

        uStatus = OpcUa_P_Mutex_Create(&(pInternalSocketManager->pMutex));
        OpcUa_GotoErrorIfBad(uStatus);

        pInternalSocketManager->uintMaxSockets = a_nSockets;
        pInternalSocketManager->pSockets       = (OpcUa_Socket)&OpcUa_Socket_g_SocketArray;

        /* initialize sockets */
        OpcUa_MemSet(pInternalSocketManager->pSockets, 0, sizeof(OpcUa_InternalSocket) * a_nSockets);

        for(ntemp = 0; ntemp < pInternalSocketManager->uintMaxSockets; ntemp++)
        {
            OpcUa_Socket_Initialize(&(pInternalSocketManager->pSockets[ntemp]));
        }

#if OPCUA_MULTITHREADED
        /* the global socket list runs in the main thread */
        bCreateServerThread = OpcUa_False;
#endif  /*  OPCUA_MULTITHREADED */
    } /* if(a_ppSocketManager != OpcUa_Null) */

    pInternalSocketManager->uintLastExternalEvent  = OPCUA_SOCKET_NO_EVENT;


    /* set the behaviour flags */
    if((a_nFlags & OPCUA_SOCKET_SPAWN_THREAD_ON_ACCEPT)    != OPCUA_SOCKET_NO_FLAG)
    {
        pInternalSocketManager->Flags.bSpawnThreadOnAccept      = OpcUa_True;
    }

    if((a_nFlags & OPCUA_SOCKET_REJECT_ON_NO_THREAD)       != OPCUA_SOCKET_NO_FLAG)
    {
        pInternalSocketManager->Flags.bRejectOnThreadFail       = OpcUa_True;
    }

    if((a_nFlags & OPCUA_SOCKET_DONT_CLOSE_ON_EXCEPT)      != OPCUA_SOCKET_NO_FLAG)
    {
        pInternalSocketManager->Flags.bDontCloseOnExcept        = OpcUa_True;
    }

    /* Dont stop by default! */
    pInternalSocketManager->Flags.bStopServerLoop = OpcUa_False;

    /* if multithreaded, create and start the server thread if the list is not the global list. */
#if OPCUA_MULTITHREADED
    if(bCreateServerThread != OpcUa_False)
    {
        /* start a thread serving on the newly created port. */
        uStatus = OpcUa_P_Thread_Create(&(pInternalSocketManager->pThread)); /* make raw thread */
        uStatus = OpcUa_P_Thread_Start( pInternalSocketManager->pThread,
                                        OpcUa_P_SocketManager_ServerLoopThread,
                                        (OpcUa_Void*)pInternalSocketManager);
    }
#endif /* OPCUA_MULTITHREADED */

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * Delete SocketManager Type (closes all sockets)
 *===========================================================================*/
OpcUa_Void OPCUA_DLLCALL OpcUa_P_SocketManager_Delete(OpcUa_SocketManager* a_pSocketManager)
{
    OpcUa_InternalSocketManager* pInternalSocketManager = OpcUa_Null;
    OpcUa_Boolean                bStaticMemory          = OpcUa_False; /* prevents freeing of the static (global) list */
    OpcUa_UInt32                 uintIndex              = 0;


    if(a_pSocketManager == OpcUa_Null)
    {
        /* use global list */
        pInternalSocketManager = (OpcUa_InternalSocketManager*)&OpcUa_Socket_g_SocketManager;
        bStaticMemory = OpcUa_True;
    }
    else
    {
        /* use given list */
        pInternalSocketManager = (OpcUa_InternalSocketManager*)*a_pSocketManager;
    }

    pInternalSocketManager->Flags.bStopServerLoop = OpcUa_True;

    /* send shutdown event to serveloop */
    OpcUa_P_SocketManager_InterruptLoop((OpcUa_SocketManager)pInternalSocketManager, OPCUA_SOCKET_SHUTDOWN_EVENT, OpcUa_False);

    /* wait for the thread to stop if its not the global list. */
    if(pInternalSocketManager != ((OpcUa_InternalSocketManager*)&OpcUa_Socket_g_SocketManager))
    {
        if(pInternalSocketManager->pThread != OpcUa_Null)
        {
            OpcUa_P_Semaphore_Wait(pInternalSocketManager->pShutdownEvent);
            OpcUa_P_Mutex_Lock(pInternalSocketManager->pMutex);
            OpcUa_P_Thread_Delete(&(pInternalSocketManager->pThread));
            OpcUa_P_Semaphore_Delete(&(pInternalSocketManager->pShutdownEvent));
        }
        else
        {
            OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OpcUa_SocketManager_Delete: Invalid Thread Handle!\n");
            return;
        }
    }
    else
    {
        OpcUa_P_Mutex_Lock(pInternalSocketManager->pMutex);
    }

    /* handle the socket list content (close, cleanup, etc.) */
    if(pInternalSocketManager->pSockets != OpcUa_Null)
    {
        OpcUa_Socket pSocketTemp = OpcUa_Null;

        for(uintIndex = 0; uintIndex < pInternalSocketManager->uintMaxSockets; uintIndex++)
        {
            pSocketTemp = &(pInternalSocketManager->pSockets[uintIndex]);

            if(pInternalSocketManager->pSockets[uintIndex].rawSocket != (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID)
            {
                if(pInternalSocketManager->pSockets[uintIndex].Flags.bInvalidSocket == 0)
                {
                    OpcUa_P_Socket_Close(pSocketTemp);
                }
            }

            OpcUa_Socket_Clear(pSocketTemp);
        }

        if(bStaticMemory == OpcUa_False)
        {
            free(pInternalSocketManager->pSockets);
        }
    } /* if(pInternalSocketManager->pSockets != OpcUa_Null) */


    OpcUa_P_Mutex_Unlock(pInternalSocketManager->pMutex);
    OpcUa_P_Mutex_Delete(&(pInternalSocketManager->pMutex));


    if(bStaticMemory == OpcUa_False)
    {
        free(*a_pSocketManager);
        *a_pSocketManager = OpcUa_Null;
    }

    return;
}

/*============================================================================
 * Initialize the platform network interface
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_Socket_InitializeNetwork(OpcUa_Void)
{
OpcUa_InitializeStatus(OpcUa_Module_Socket, "InitializeNetwork");

    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = OpcUa_P_RawSocket_InitializeNetwork();

#if OPCUA_MULTITHREADED

    /* init SocketManager pointer array */
    memset( OpcUa_P_Socket_g_pSocketManagers,
            0,
            sizeof(OpcUa_P_Socket_g_pSocketManagers));

    /* init SocketManager pointer array mutex */
    uStatus = OpcUa_P_Mutex_Create(&OpcUa_P_Socket_g_SocketManagersMutex);
    OpcUa_GotoErrorIfBad(uStatus);

    /* init SocketManager pointer array mutex */
    uStatus = OpcUa_P_Mutex_Create(&OpcUa_P_Socket_g_ShutdownMutex);
    OpcUa_GotoErrorIfBad(uStatus);

    OpcUa_P_Socket_g_uNuOfClientThreads = 0;

#else /* OPCUA_MULTITHREADED */

    /* initialize the global socket list; no threads, of course */
    uStatus = OpcUa_P_SocketManager_Create( OpcUa_Null,
                                            OPCUA_P_SOCKETMANAGER_NUMBEROFSOCKETS - 1,
                                            OPCUA_SOCKET_REJECT_ON_NO_THREAD);
    OpcUa_GotoErrorIfBad(uStatus);

#endif /* OPCUA_MULTITHREADED */


OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* cleanup everything */
    OpcUa_P_Socket_CleanupNetwork();

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * Clean the platform network interface up.
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_Socket_CleanupNetwork(OpcUa_Void)
{
OpcUa_InitializeStatus(OpcUa_Module_Socket, "CleanupNetwork");

#if OPCUA_MULTITHREADED

    /* Notify all existing socket managers about shutdown. */
    OpcUa_P_SocketManager_InterruptLoop((OpcUa_SocketManager)OpcUa_Null,
                                        OPCUA_SOCKET_SHUTDOWN_EVENT,
                                        OpcUa_True);

    OpcUa_P_Mutex_Lock(OpcUa_P_Socket_g_ShutdownMutex);

    while(OpcUa_P_Socket_g_uNuOfClientThreads != 0)
    {
        OpcUa_P_Mutex_Unlock(OpcUa_P_Socket_g_ShutdownMutex);
        OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_P_Socket_CleanupNetwork: Waiting for client threads to come down!\n");
        OpcUa_P_Thread_Sleep(500);
        OpcUa_P_Mutex_Lock(OpcUa_P_Socket_g_ShutdownMutex);
    }

    OpcUa_P_Mutex_Unlock(OpcUa_P_Socket_g_ShutdownMutex);

    /* clean up global socketmanager array mutex */
    OpcUa_P_Mutex_Delete(&OpcUa_P_Socket_g_SocketManagersMutex);

    /* clean up global shutdown mutex */
    OpcUa_P_Mutex_Delete(&OpcUa_P_Socket_g_ShutdownMutex);

#else /* OPCUA_MULTITHREADED */

    /* clean up global socket list */
    OpcUa_P_SocketManager_Delete(OpcUa_Null);

#endif /* OPCUA_MULTITHREADED */

    /* cleanup platform networking */
    uStatus = OpcUa_P_RawSocket_CleanupNetwork();
    OpcUa_GotoErrorIfBad(uStatus);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * Create a server socket
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_SocketManager_CreateServer(  OpcUa_SocketManager         a_pSocketManager,
                                                                    OpcUa_StringA               a_sAddress,
                                                                    OpcUa_Socket_EventCallback  a_pfnSocketCallBack,
                                                                    OpcUa_Void*                 a_pCallbackData,
                                                                    OpcUa_Socket*               a_pSocket)
{
    OpcUa_InternalSocketManager*    pInternalSocketManager  = OpcUa_Null;
    OpcUa_UInt16                    uPort                   = 0;
    OpcUa_StringA                   sRemoteAdress           = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Socket, "CreateServer");

    OpcUa_ReturnErrorIfArgumentNull(a_pSocket);

    /* No Socket List given, use default list */
    if(a_pSocketManager == OpcUa_Null)
    {
        pInternalSocketManager = &OpcUa_Socket_g_SocketManager;
    }
    else
    {
        pInternalSocketManager = (OpcUa_InternalSocketManager*)a_pSocketManager;
    }

    /* parse address */
    uStatus = OpcUa_P_ParseUrl( a_sAddress,
                                &sRemoteAdress,
                                &uPort);

    if(sRemoteAdress != OpcUa_Null)
    {
        free(sRemoteAdress);
    }

    OpcUa_ReturnErrorIfBad(uStatus);

    OpcUa_P_Mutex_Lock(pInternalSocketManager->pMutex);

    uStatus = OpcUa_SocketManager_InternalCreateServer( pInternalSocketManager,
                                                        uPort,
                                                        a_pfnSocketCallBack,
                                                        a_pCallbackData,
                                                        a_pSocket);
    OpcUa_GotoErrorIfBad(uStatus);


    OpcUa_P_SocketManager_InterruptLoop(pInternalSocketManager,
                                        OPCUA_SOCKET_RENEWLOOP_EVENT,
                                        OpcUa_False);

    OpcUa_P_Mutex_Unlock(pInternalSocketManager->pMutex);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_P_Mutex_Unlock(pInternalSocketManager->pMutex);

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * Create a client socket
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_SocketManager_CreateClient(  OpcUa_SocketManager         a_hSocketManager,
                                                                    OpcUa_StringA               a_sRemoteAddress,
                                                                    OpcUa_UInt16                a_uLocalPort,
                                                                    OpcUa_Socket_EventCallback  a_pfnSocketCallBack,
                                                                    OpcUa_Void*                 a_pCallbackData,
                                                                    OpcUa_Socket*               a_pSocket)
{
    OpcUa_InternalSocket*        pNewClientSocket        = OpcUa_Null;
    OpcUa_InternalSocketManager* pInternalSocketManager  = OpcUa_Null;
    OpcUa_UInt16                 uPort                   = 0;
    OpcUa_StringA                sRemoteAdress           = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Socket, "CreateClient");

    OpcUa_ReturnErrorIfArgumentNull(a_pSocket);
    OpcUa_ReturnErrorIfArgumentNull(a_sRemoteAddress);

    /* parse address */
    uStatus = OpcUa_P_ParseUrl( a_sRemoteAddress,
                                &sRemoteAdress,
                                &uPort);
    OpcUa_ReturnErrorIfBad(uStatus);

    /* Fall back to global manager if no one is specified. */
    if(a_hSocketManager == OpcUa_Null)
    {
        pInternalSocketManager = &OpcUa_Socket_g_SocketManager;
    }
    else
    {
        pInternalSocketManager = (OpcUa_InternalSocketManager*)a_hSocketManager;
    }

    OpcUa_P_Mutex_Lock(pInternalSocketManager->pMutex);

    pNewClientSocket = (OpcUa_InternalSocket*)OpcUa_SocketManager_FindFreeSocket((OpcUa_SocketManager)pInternalSocketManager, OpcUa_False);
    OpcUa_GotoErrorIfNull(pNewClientSocket, OpcUa_BadMaxConnectionsReached); /* no socket left in the list. */

    /* Create client socket. */
    pNewClientSocket->rawSocket = OpcUa_P_Socket_CreateClient(  a_uLocalPort,
                                                                uPort,
                                                                sRemoteAdress,
                                                                &uStatus);

    OpcUa_P_Memory_Free(sRemoteAdress);
    sRemoteAdress = OpcUa_Null;


    if(pNewClientSocket->rawSocket == (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID)
    {
        uStatus = OpcUa_BadCommunicationError;
        goto Error;
    }

    pNewClientSocket->pfnEventCallback       = a_pfnSocketCallBack;
    pNewClientSocket->pvUserData             = a_pCallbackData;
    OPCUA_SOCKET_SETVALID(pNewClientSocket);
    pNewClientSocket->Flags.bSocketIsInUse   = OpcUa_True;
    pNewClientSocket->Flags.bIsListenSocket  = OpcUa_False;
    pNewClientSocket->Flags.bOwnThread       = OpcUa_False;
    pNewClientSocket->Flags.bSSL             = OpcUa_False;
    pNewClientSocket->pSocketManager         = (OpcUa_InternalSocketManager *)a_hSocketManager;
    pNewClientSocket->Flags.EventMask        = OPCUA_SOCKET_READ_EVENT
                                             | OPCUA_SOCKET_EXCEPT_EVENT
                                             | OPCUA_SOCKET_CONNECT_EVENT
                                             | OPCUA_SOCKET_TIMEOUT_EVENT;


    /* return the new client socket */
    *a_pSocket = pNewClientSocket;

    /* break loop to add new socket into eventing */
    uStatus = OpcUa_P_SocketManager_InterruptLoop(  a_hSocketManager,
                                                    OPCUA_SOCKET_RENEWLOOP_EVENT,
                                                    OpcUa_False);
    OpcUa_GotoErrorIfBad(uStatus);

    OpcUa_P_Mutex_Unlock(pInternalSocketManager->pMutex);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(pNewClientSocket)
    {
        if(pNewClientSocket->rawSocket != (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID)
        {
            OPCUA_SOCKET_INVALIDATE(pNewClientSocket);
            pNewClientSocket->Flags.bSocketIsInUse = OpcUa_False;
        }
    }

    if(pInternalSocketManager != OpcUa_Null)
    {
        OpcUa_P_Mutex_Unlock(pInternalSocketManager->pMutex);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * Get last socket error
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_Socket_GetLastError(OpcUa_Socket a_pSocket)
{
    OpcUa_InternalSocket*   pInternalSocket = (OpcUa_InternalSocket*)a_pSocket;
    OpcUa_Int32             iLastError = 0;

OpcUa_InitializeStatus(OpcUa_Module_Socket, "GetLastError");

    OpcUa_GotoErrorIfArgumentNull(a_pSocket);
    OpcUa_GotoErrorIfArgumentNull(pInternalSocket->rawSocket);

    iLastError = OpcUa_P_RawSocket_GetLastError(pInternalSocket->rawSocket);

    if(iLastError != 0)
    {
        /* TODO: Map errorcodes. */
        switch(iLastError)
        {
        case WSAEWOULDBLOCK:
            {
                uStatus = OpcUa_BadWouldBlock;
                break;
            }
        case WSAECONNABORTED:
        case WSAECONNRESET:
            {
                uStatus = OpcUa_BadDisconnect;
                break;
            }
        default:
            {
                OpcUa_Trace(OPCUA_TRACE_LEVEL_WARNING, "OpcUa_P_Socket_GetLastError: WSA Error 0x%08X\n", iLastError);
                uStatus = OpcUa_BadCommunicationError;
            }
        }
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * Signal a certain event on a socket.
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_SocketManager_SignalEvent(   OpcUa_SocketManager     a_pSocketManager,
                                                                    OpcUa_UInt32            a_uEvent,
                                                                    OpcUa_Boolean           a_bAllManagers)
{
OpcUa_InitializeStatus(OpcUa_Module_Socket, "SignalEvent");

    uStatus = OpcUa_P_SocketManager_InterruptLoop(a_pSocketManager, a_uEvent, a_bAllManagers);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * Read Socket.
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_Socket_Read( OpcUa_Socket    a_pSocket,
                                                    OpcUa_Byte*     a_pBuffer,
                                                    OpcUa_UInt32    a_nBufferSize,
                                                    OpcUa_UInt32*   a_pBytesRead)
{
    OpcUa_Int32 result = 0;
    OpcUa_InternalSocket*   pInternalSocket     = (OpcUa_InternalSocket*)a_pSocket;

OpcUa_InitializeStatus(OpcUa_Module_Socket, "Read");

    OpcUa_GotoErrorIfArgumentNull(a_pSocket);
    OpcUa_GotoErrorIfArgumentNull(a_pBuffer);
    OpcUa_GotoErrorIfArgumentNull(a_pBytesRead);

    /* returns the number of bytes received or 0 or a negative value in case of disconnect or error. */
    result = OpcUa_P_RawSocket_Read(    (OpcUa_RawSocket)(((OpcUa_InternalSocket*)a_pSocket)->rawSocket),
                                        a_pBuffer,
                                        a_nBufferSize);

    /* decide if the result is an error or the number of bytes read. */
    if(result > 0)
    {
        *a_pBytesRead = (OpcUa_UInt32)result;
    }
    else /* result <=0 (error or disconnect) */
    {
        *a_pBytesRead = 0;

        if(result == 0)
        {
            uStatus = OpcUa_BadDisconnect;
            OpcUa_P_Socket_Close(a_pSocket);
        }
        else
        {
            OpcUa_Int32 uLastError = OpcUa_P_RawSocket_GetLastError(pInternalSocket->rawSocket);

            switch(uLastError)
            {
            case WSAEWOULDBLOCK:
                {
                    uStatus = OpcUa_BadWouldBlock;
                    break;
                }
            case WSAECONNABORTED:
            case WSAECONNRESET:
                {
                    uStatus = OpcUa_BadDisconnect;
                    OpcUa_P_Socket_Close(a_pSocket);
                    break;
                }
            default:
                {
                    uStatus = OpcUa_BadCommunicationError;
                    OpcUa_P_Socket_Close(a_pSocket);
                }
            }
        }
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * Write Socket.
 *===========================================================================*/
/* returns number of bytes written to the socket */
OpcUa_Int32 OPCUA_DLLCALL OpcUa_P_Socket_Write( OpcUa_Socket    a_pSocket,
                                                OpcUa_Byte*     a_pBuffer,
                                                OpcUa_UInt32    a_uBufferSize,
                                                OpcUa_Boolean   a_bBlock)
{
    OpcUa_Int32             iBytesSend          = 0;
    OpcUa_Int32             iWSAError           = 0;
    OpcUa_Boolean           bError              = OpcUa_False;
    OpcUa_Byte*             pBuffer             = a_pBuffer;
    OpcUa_UInt32            RemainingBufferSize = a_uBufferSize;
    /*OpcUa_UInt32            uintEvent           = 0;*/
    OpcUa_InternalSocket*   pInternalSocket     = (OpcUa_InternalSocket*)a_pSocket;
    OpcUa_RawSocket         hRawSocket          = OpcUa_Null;

    /* check for errors */
    OpcUa_ReturnErrorIfNull(a_pSocket, OPCUA_SOCKET_ERROR);
    OpcUa_ReturnErrorIfNull(a_pBuffer, OPCUA_SOCKET_ERROR);

    if(a_uBufferSize == 0)
    {
        return OPCUA_SOCKET_ERROR;
    }

    if(     pInternalSocket->Flags.bSocketIsInUse == OpcUa_False
        ||  pInternalSocket->Flags.bInvalidSocket != OpcUa_False)
    {
        return OpcUa_BadDisconnect;
    }

    hRawSocket = pInternalSocket->rawSocket;

    /* reset access time */
    pInternalSocket->uintLastAccess = OpcUa_P_GetTickCount()/1000;

    /* send loop */
    do /* while no error and not all send */
    {
        /*****************************************************************/
#if 1 /* debug only */
        if(a_bBlock != OpcUa_False)
        {
            /* set blocking */
            OpcUa_P_RawSocket_SetBlockMode( hRawSocket,
                                            OpcUa_True);
        }
#endif
        /* send data */
        iBytesSend = OpcUa_P_RawSocket_Write(   hRawSocket,
                                                pBuffer,
                                                RemainingBufferSize);
#if 1 /* debug only */
        if(a_bBlock != OpcUa_False && iBytesSend != OPCUA_P_SOCKET_SOCKETERROR)
        {
            /* set non blocking */
            OpcUa_P_RawSocket_SetBlockMode( hRawSocket,
                                            OpcUa_False);
        }
#endif
        /*****************************************************************/

        /*****************************************************************/
        /* special treatment for wouldblock */
        if(iBytesSend == OPCUA_P_SOCKET_SOCKETERROR)
        {
#if 1
            iWSAError = OpcUa_P_RawSocket_GetLastError(hRawSocket);

            /* leave directly if unexpected error */
            if(iWSAError != WSAEWOULDBLOCK)
            {
                /* error, but no wouldblock */
                return iBytesSend;
            }
#endif
            /* socket would block */
            OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "EWOULDBLOCK loop\n");
            //return iBytesSend; /* return here to prevent looping over the socket */
        }
        else /* no error */
        {
            /* stop sending if one shot send */
            if(a_bBlock == OpcUa_False)
            {
                /* leave function after some calculation */
                RemainingBufferSize = 0;
                break;
            }

            if(iBytesSend == 0)
            {
                bError = OpcUa_True;
                iBytesSend = -1;
            }
            else
            {
                /* how much is left */
                RemainingBufferSize -= iBytesSend;

                /* move data pointer */
                pBuffer = pBuffer + iBytesSend;
            }
        }
        /*****************************************************************/
    } while(    (RemainingBufferSize >  0)
             && (bError              == OpcUa_False)); /* loop until all data sent or error occured */

    /* update size before returning */
    iBytesSend = a_uBufferSize - RemainingBufferSize;

    return iBytesSend;
}

/*============================================================================
 * Close Socket.
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_Socket_Close(OpcUa_Socket a_pSocket)
{
    OpcUa_InternalSocket* pInternalSocket = (OpcUa_InternalSocket*)a_pSocket;

OpcUa_InitializeStatus(OpcUa_Module_Socket, "Close");

    OpcUa_GotoErrorIfArgumentNull(a_pSocket);

    if(pInternalSocket->Flags.bInvalidSocket != 0)
    {
        /* caller tried to close an invalid socket, what may happen intentionally... */
        return OpcUa_Bad;
    }

    pInternalSocket->Flags.bInvalidSocket = -1;

#ifdef OPCUA_SOCKET_USESSL
        if(    pInternalSocket->Flags.bSSL  != 0
            && pInternalSocket->pSSL        != OpcUa_Null)
        {
            /* call SSL service to clean up */
            pInternalSocket->Flags.bSSL = 0;
            pInternalSocket->pSSL       = OpcUa_Null;
        }
#endif /* OPCUA_SOCKET_USESSL */

    pInternalSocket->Flags.bSocketIsInUse = 0;

    uStatus = OpcUa_P_RawSocket_Close(pInternalSocket->rawSocket);

#if OPCUA_USE_SYNCHRONISATION
    if(pInternalSocket->hSemaphore != OpcUa_Null)
    {
        OpcUa_P_Semaphore_Delete(&pInternalSocket->hSemaphore);
    }
#endif

    pInternalSocket->rawSocket = (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID;

#if OPCUA_MULTITHREADED
    /* the if this is a client connection in a own thread, the loop should be notified to shut down */
    if((pInternalSocket->Flags.bOwnThread != 0) && (pInternalSocket->pSocketManager != OpcUa_Null))
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_P_Socket_Close: Notifying SocketManager to shut down ... \n");
        OpcUa_P_SocketManager_InterruptLoop(    pInternalSocket->pSocketManager,
                                                OPCUA_SOCKET_SHUTDOWN_EVENT,
                                                OpcUa_False);
    }
#endif

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * Network Byte Order Conversion Helper Functions
 *===========================================================================*/
OpcUa_UInt32 OPCUA_DLLCALL OpcUa_P_Socket_NToHL(OpcUa_UInt32 a_netLong)
{
    return OpcUa_P_RawSocket_NToHL(a_netLong);
}

OpcUa_UInt16 OPCUA_DLLCALL OpcUa_P_Socket_NToHS(OpcUa_UInt16 a_netShort)
{
    return OpcUa_P_RawSocket_NToHS(a_netShort);
}

OpcUa_UInt32 OPCUA_DLLCALL OpcUa_P_Socket_HToNL(OpcUa_UInt32 a_hstLong)
{
    return OpcUa_P_RawSocket_HToNL(a_hstLong);
}

OpcUa_UInt16 OPCUA_DLLCALL OpcUa_P_Socket_HToNS(OpcUa_UInt16 a_hstShort)
{
    return OpcUa_P_RawSocket_HToNS(a_hstShort);
}


#if OPCUA_P_SOCKETGETPEERINFO_V2
/*============================================================================
 * Get IP Address and Port Number of the Peer
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_Socket_GetPeerInfo(  OpcUa_Socket a_pSocket,
                                                            OpcUa_CharA* a_achPeerInfoBuffer,
                                                            OpcUa_UInt32 a_uiPeerInfoBufferSize)
{
    OpcUa_InternalSocket* pInternalSocket = (OpcUa_InternalSocket*)a_pSocket;

OpcUa_InitializeStatus(OpcUa_Module_Socket, "GetPeerInfo");

    OpcUa_GotoErrorIfArgumentNull(a_pSocket);

    OpcUa_P_RawSocket_GetPeerInfo(pInternalSocket->rawSocket, a_achPeerInfoBuffer, a_uiPeerInfoBufferSize);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}
#else /* OPCUA_P_SOCKETGETPEERINFO_V2 */
/*============================================================================
 * Get IP Address and Port Number of the Peer
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_Socket_GetPeerInfo(  OpcUa_Socket a_pSocket,
                                                            OpcUa_UInt32* a_pIP,
                                                            OpcUa_UInt16* a_pPort)
{
    OpcUa_InternalSocket* pInternalSocket = (OpcUa_InternalSocket*)a_pSocket;

OpcUa_InitializeStatus(OpcUa_Module_Socket, "GetPeerInfo");

    OpcUa_GotoErrorIfArgumentNull(a_pSocket);
    OpcUa_GotoErrorIfArgumentNull(a_pIP);
    OpcUa_GotoErrorIfArgumentNull(a_pPort);

    if(pInternalSocket->rawSocket == (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID)
    {
        uStatus = OpcUa_BadInvalidArgument;
        OpcUa_GotoError;
    }

    *a_pIP   = 0;
    *a_pPort = 0;

    OpcUa_P_RawSocket_GetPeerInfo(pInternalSocket->rawSocket, a_pIP, a_pPort);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}
#endif /* OPCUA_P_SOCKETGETPEERINFO_V2 */

/*============================================================================
 * Convert OpcUa_StringA into binary ip address
 *===========================================================================*/
OpcUa_UInt32 OPCUA_DLLCALL OpcUa_P_Socket_InetAddr(OpcUa_StringA sRemoteAddress)
{
    return OpcUa_P_RawSocket_InetAddr(sRemoteAddress);
}

/*============================================================================
 * Get the name of the local host.
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_Socket_GetHostName( OpcUa_CharA* a_pBuffer,
                                                           OpcUa_UInt32 a_uiBufferLength)
{
    int iRet = gethostname( (char*)a_pBuffer,
                            (int)a_uiBufferLength);

    return (iRet==0)?OpcUa_Good:OpcUa_Bad;
}
