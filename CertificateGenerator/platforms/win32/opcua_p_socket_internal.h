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
/** @file Internally used definitions and types for the platform layer network implementation         */
/******************************************************************************************************/
#ifndef _OpcUa_Socket_Internal_H_
#define _OpcUa_Socket_Internal_H_ 1

OPCUA_BEGIN_EXTERN_C

/** @brief shutdown directions */
#define OPCUA_SOCKET_SD_RECEIVE 0x00
#define OPCUA_SOCKET_SD_SEND    0x01
#define OPCUA_SOCKET_SD_BOTH    0x02

/*============================================================================
 * The Socket Type
 *===========================================================================*/

/* forward definition of the OpcUa_Socket structure */
typedef struct _OpcUa_InternalSocket OpcUa_InternalSocket;

/* forward definition of the OpcUa_SocketManager structure */
typedef struct _OpcUa_InternalSocketManager OpcUa_InternalSocketManager;

/**
* Internal representation for a logical socket (client and server). Includes
* beside the system socket additional information for handling.
*/
struct _OpcUa_InternalSocket
{
    OpcUa_RawSocket              rawSocket;          /* system socket */
    OpcUa_Socket_EventCallback   pfnEventCallback;   /* function to call on event */
    OpcUa_Void*                  pvUserData;         /* data for callback */
    OpcUa_Void*                  pSSL;               /* SSL data (future use) */
    OpcUa_InternalSocketManager* pSocketManager;     /* the socket manager, this socket belongs to */
    OpcUa_UInt16                 usPort;             /* the socket port of this socket */
    struct _Flags
    {
        OpcUa_Int               EventMask:11;       /* mask and unmask eventhandling */
        OpcUa_Int               bIsListenSocket:1;  /* to distinguish between accept and read events */
        OpcUa_Int               bInvalidSocket:1;   /* is the socket usable */
        OpcUa_Int               bOwnThread:1;       /* if this socket is handled by an own thread */
        OpcUa_Int               bFromApplication:1; /* Application is explicitely waiting for an event on this socket. */
        OpcUa_Int               bSocketIsInUse:1;   /* true if this list member is currently connected or listening */
        OpcUa_Int               bInternalWait:1;    /* shows if this socket in an internal wait */
        OpcUa_Int               bSSL:1;             /* SSL used? */
    } Flags;
    OpcUa_UInt32                uintTimeout;        /* interval until connection is considered timed out */
    OpcUa_UInt32                uintLastAccess;     /* system tick count in seconds when last action on this socket took place */
#if OPCUA_USE_SYNCHRONISATION
    /*OpcUa_Mutex                 pMutex;*/             /* for multithreading */
    OpcUa_Semaphore             hSemaphore;         /*  */
#endif /* OPCUA_USE_SYNCHRONISATION */
};

/**
* List of sockets for one listening socket (included).
*/
struct _OpcUa_InternalSocketManager
{
    OpcUa_InternalSocket* pSockets;                 /* the sockets */
    OpcUa_UInt32          uintMaxSockets;           /* how many socket entries can this list hold at maximum. Mind the signal socket!  */
    OpcUa_Void*           pCookie;                  /* pointer to internal data */
    OpcUa_UInt32          uintLastExternalEvent;    /* the last occured event */
    OpcUa_Semaphore       pShutdownEvent;           /* wait on this semaphore to synchronize on shutdown */
    OpcUa_RawThread       pThread;                  /* each socket list has its own thread... */
    OpcUa_Mutex           pMutex;                   /* ... and therefore its own mutex! */
    struct _SocketManagerFlags
    {
        OpcUa_Int   bStopServerLoop     :1;         /* set to true to end mainloop thread */
        OpcUa_Int   bSpawnThreadOnAccept:1;         /* is a new thread spawned on a new connection accept? */
        OpcUa_Int   bRejectOnThreadFail :1;         /* reject an accept when there is no free thread? */
        OpcUa_Int   bDontCloseOnExcept  :1;         /* override default closing of a socket on except event */
    } Flags;
};

/*
* Sets a socket to invalid.
*/
#define OPCUA_SOCKET_INVALIDATE(a)      a->Flags.bInvalidSocket = -1
#define OPCUA_SOCKET_INVALIDATE_S(a)    a.Flags.bInvalidSocket = -1
#define OPCUA_SOCKET_SETVALID(a)        a->Flags.bInvalidSocket = 0
#define OPCUA_SOCKET_SETVALID_S(a)      a.Flags.bInvalidSocket = 0

/**
* Checks wether a socket is valid.
*/
#define OPCUA_SOCKET_ISVALID(a)         a->Flags.bInvalidSocket == 0
#define OPCUA_SOCKET_ISVALID_S(a)       a.Flags.bInvalidSocket == 0


/*============================================================================
 * Initialize Socket Type
 *===========================================================================*/
OpcUa_Void          OpcUa_Socket_Initialize(    OpcUa_Socket pSocket);

/*============================================================================
 * Clear Socket Type
 *===========================================================================*/
OpcUa_Void          OpcUa_Socket_Clear(         OpcUa_Socket pSocket);

/*============================================================================
 * Initialize Socket Type
 *===========================================================================*/
OpcUa_Void          OpcUa_Socket_Delete(        OpcUa_Socket* ppSocket);

/*============================================================================
 * Allocate Socket Type
 *===========================================================================*/
OpcUa_Socket       OpcUa_Socket_Alloc();


/**************************** The SocketManager Type ****************************/

/*============================================================================
 * Allocate SocketManager Type
 *===========================================================================*/
OpcUa_SocketManager OpcUa_SocketManager_Alloc();

/*============================================================================
 * Initialize SocketManager Type
 *===========================================================================*/
OpcUa_Void          OpcUa_SocketManager_Initialize(OpcUa_SocketManager pSocketManager);



/*============================================================================
 * Create the Sockets in the given list
 *===========================================================================*/
OpcUa_StatusCode    OpcUa_SocketManager_CreateSockets(  OpcUa_SocketManager     pSocketManager,
                                                        OpcUa_UInt32            uintMaxSockets);


/*============================================================================
 * Wait for a certain event to happen for a maximum of time.
 *===========================================================================*/
OpcUa_StatusCode    OpcUa_Socket_WaitForEvent(  OpcUa_Socket                pSocket,
                                                OpcUa_UInt32                uintEvent,
                                                OpcUa_UInt32                msecInterval,
                                                OpcUa_UInt32*               puintEventOccured);




/*============================================================================
 * Set the event mask for this socket.
 *===========================================================================*/
OpcUa_StatusCode    OpcUa_Socket_SetEventMask(  OpcUa_Socket                pSocket,
                                                OpcUa_UInt32                uintEventMask);

/*============================================================================
 * Get the currently set event mask for this socket.
 *===========================================================================*/
OpcUa_StatusCode    OpcUa_Socket_GetEventMask(  OpcUa_Socket                pSocket,
                                                OpcUa_UInt32*               puintEventMask);

/*============================================================================
 * Network Byte Order Conversion Helper Functions
 *===========================================================================*/
OpcUa_UInt32        OpcUa_Socket_NToHL(         OpcUa_UInt32 netLong);
OpcUa_UInt16        OpcUa_Socket_NToHS(         OpcUa_UInt16 netShort);

OpcUa_UInt32        OpcUa_Socket_HToNL(         OpcUa_UInt32 hstLong);
OpcUa_UInt16        OpcUa_Socket_HToNS(         OpcUa_UInt16 hstShort);


/*============================================================================
 * Find a free socket.
 *===========================================================================*/
OpcUa_Socket        OpcUa_SocketManager_FindFreeSocket( OpcUa_SocketManager pSocketManager,
                                                        OpcUa_Boolean       bIsSignalSocket);

/*============================================================================
 * Take action based on socket and event.
 *===========================================================================*/
OpcUa_StatusCode    OpcUa_Socket_HandleEvent(   OpcUa_Socket        pSocket,
                                                OpcUa_UInt32        uintEvent);

/*!
 * @brief Fill the socket array with sockets from the given socket list and selected based on the given event.
 *
 * @param pSocketManager   [in]    The source of the sockets.
 * @param pSocketArray  [out]   The sockets in this array get set based on the socket list.
 * @param Event         [in]    Only set sockets with this event set.
 *
 * @return A "Good" status code if no error occured, a "Bad" status code otherwise.
 */
OpcUa_StatusCode OpcUa_P_Socket_FillFdSet(OpcUa_SocketManager   SocketManager,
                                          OpcUa_P_Socket_Array* pSocketArray,
                                          OpcUa_UInt32          Event);


/*!
 * @brief Sets the given OpcUa_Socket to waiting.
 *
 * The given event is assigned and the previous event mask stored at the given position.
 *
 * @param pSocket               [in/out]    The target socket for the operation.
 * @param Event                 [in]        Which event should be waited on.
 * @param pPreviousEventMask    [out]       Receives the mask which was valid until now.
 *
 * @return OpcUa_True on success, OpcUa_False else.
 */
OpcUa_Boolean OpcUa_P_Socket_SetWaitingSocketEvent(OpcUa_Socket  pSocket,
                                                   OpcUa_UInt32  Event,
                                                   OpcUa_UInt32* pPreviousEventMask);



/*!
 * @brief Handle all signaled events in the socket array.
 *
 * @param pSocketManager   [in]    The list with the OpcUa_Sockets which store the handler routines.
 * @param pSocketArray  [in]    The array with the system sockets to be checked.
 * @param Event         [in]    Handle all sockets waiting for this event.
 */
OpcUa_Void OpcUa_P_Socket_HandleFdSet(OpcUa_SocketManager   SocketManager,
                                      OpcUa_P_Socket_Array* SocketArray,
                                      OpcUa_UInt32          Event);

/*!
 * @brief Handle an externally triggered event.
 *
 * @param pSocketManager   [in]    The current socket list.
 * @param Event         [in]    The awaited event.
 * @param pEventOccured [in]    The event, that occured.
 *
 * @return A "Good" status code if no error occured, a "Bad" status code otherwise.
 */
OpcUa_StatusCode OpcUa_P_Socket_HandleExternalEvent(OpcUa_SocketManager SocketManager,
                                                    OpcUa_UInt32        Event,
                                                    OpcUa_UInt32*       pEventOccured);

/*!
 * @brief Find the corresponding socket entry in the given socket list.
 *
 * @param pSocketManager [in]    The list to be searched in.
 * @param RawSocket      [in]    The target system socket to search for.
 *
 * @return A pointer to the found OpcUa_Socket, or OpcUa_Null if the search ended without success.
 */
OpcUa_Socket  OpcUa_P_Socket_FindSocketEntry(OpcUa_SocketManager SocketManager,
                                             OpcUa_RawSocket     RawSocket);

/*!
 * @brief Is the given system socket marked as set in the specified socket array?
 *
 * @param RawSocket     [in]    The system socket which gets checked.
 * @param pSocketArray  [in]    The file descriptor array to search in.
 *
 * @return Zero if not set, non zero otherwise.
 */
OpcUa_Int32 OPCUA_P_SOCKET_ARRAY_ISSET_F(OpcUa_RawSocket       RawSocket,
                                         OpcUa_P_Socket_Array* pSocketArray);

/*!
 * @brief Sets the given OpcUa_Socket to non-waiting and restores the event mask.
 *
 * @param pSocket           [in/out]    The target socket for the operation.
 * @param PreviousEventMask [in]        The mask to restore.
 *
 * @return OpcUa_True on success, OpcUa_False else.
 */
OpcUa_Boolean OpcUa_P_Socket_ResetWaitingSocketEvent(OpcUa_Socket  pSocket,
                                                     OpcUa_UInt32  PreviousEventMask);

/*!
 * @brief Create and initialize a listening OpcUa_Socket.
 *
 * @param Port      [in]    The port to listen on.
 * @param Status    [out]   How the operation went.
 *
 * @return The created system socket. An invalid socket in case of error.
 */
OpcUa_RawSocket OpcUa_P_Socket_CreateServer(OpcUa_Int16       Port,
                                            OpcUa_StatusCode* Status);

/*!
 * @brief Create a OpcUa_Socket and connect to specified network node.
 *
 * @param Port          [in]    Non zero to bind the socket locally.
 * @param RemotePort    [in]    The port on the server side.
 * @param RemoteAdress  [in]    The IP address of the server as string (ascii).
 * @param Status        [out]   Status how the operation finished.
 *
 * @return The created system socket. An invalid socket in case of error.
 */
OpcUa_RawSocket OpcUa_P_Socket_CreateClient(OpcUa_UInt16      Port,
                                            OpcUa_UInt16      RemotePort,
                                            OpcUa_StringA     RemoteAddress,
                                            OpcUa_StatusCode* Status);

/*!
 * @brief Check the socket list for events and handle them.
 *
 * @param pSocketManager [in]    The socket list holding the sockets for the select call.
 * @param msecTimeout    [in]    The maximum number of milliseconds, this function blocks the calling thread.
 * @param Socket         [in]    A specific socket, which waits for a event.
 * @param Event          [in]    The event which the socket is waiting for.
 * @param pEventOccured  [out]   Holds the events that occured during the call.
 *
 * @return A "Good" status code if no error occured, a "Bad" status code otherwise.
 */
OpcUa_StatusCode OpcUa_P_SocketManager_ServeLoopInternal(   OpcUa_SocketManager   SocketManager,
                                                            OpcUa_UInt32          msecTimeout,
                                                            OpcUa_Socket          Socket,
                                                            OpcUa_UInt32          Event,
                                                            OpcUa_UInt32*         pEventOccured);

/*!
 * @brief Interrupt server loop and signal an event.
 *
 * Unblocks the select function if called from another thread and sets the given event as
 * fired. The event counts as an external event and gets handled through handle external
 * event.
 *
 * @param pSocketManager    [in]    Pointer to the socket list, that should get interrupted.
 * @param Event             [in]    Signal this event with this operation.
 * @param AllManagers       [in]    Should all active managers be interrupted? Ignores first parameter if OpcUa_True.
 *
 * @return A "Good" status code if no error occured, a "Bad" status code otherwise.
 */
OpcUa_StatusCode OpcUa_P_SocketManager_InterruptLoopInternal(   OpcUa_SocketManager     SocketManager,
                                                                OpcUa_UInt32            Event,
                                                                OpcUa_Boolean           bAllManagers);


/*============================================================================
 * Network Byte Order Conversion Helper Functions
 *===========================================================================*/
OpcUa_UInt32 OpcUa_Socket_NToHL(OpcUa_UInt32 a_netLong);

OpcUa_UInt16 OpcUa_Socket_NToHS(OpcUa_UInt16 a_netShort);

OpcUa_UInt32 OpcUa_Socket_HToNL(OpcUa_UInt32 a_hstLong);

OpcUa_UInt16 OpcUa_Socket_HToNS(OpcUa_UInt16 a_hstShort);

/*============================================================================
 * Set socket to nonblocking mode
 *===========================================================================*/
OpcUa_StatusCode OpcUa_SocketManager_InternalCreateServer(  OpcUa_SocketManager         a_pSocketManager,
                                                            OpcUa_UInt16                a_uPort,
                                                            OpcUa_Socket_EventCallback  a_pfnSocketCallBack,
                                                            OpcUa_Void*                 a_pCallbackData,
                                                            OpcUa_Socket*               a_ppSocket);


OPCUA_END_EXTERN_C

#endif /* _OpcUa_Socket_Internal_H_ */
