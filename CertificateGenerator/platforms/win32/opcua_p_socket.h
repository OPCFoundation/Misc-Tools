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

/* HINT: There are currently two socket array/fd_set implementations in this module. */
/*       This is because of debugging and developing reasons.                        */

/**
* The internally used socket handle. Contains a raw socket in its system
* representation and a flag, indicating wether the socket is usable or not.
*/
typedef OpcUa_Void* OpcUa_RawSocket; /* pointer to a socket of the platform type */


/*! @brief Number of sockets in a socket array. */
#define OPCUA_P_SOCKET_ARRAY_SIZE               OPCUA_P_SOCKETMANAGER_NUMBEROFSOCKETS

/**
* @brief Internal representation for file descriptor sets.
*/
typedef struct _OpcUa_P_Socket_Array
{
    /*! @brief How many sockte entries are _set_. */
    OpcUa_UInt uintNbSockets;
    /*! @brief An array of raw (platform) sockets. */
    OpcUa_RawSocket SocketArray[OPCUA_P_SOCKET_ARRAY_SIZE];
} OpcUa_P_Socket_Array;


/*! @brief Symbol for stream oriented data transmission. */
#define OPCUA_P_SOCKET_STREAM                   (1u)

/*! @brief Symbol for packet oriented data transmission. */
#define OPCUA_P_SOCKET_DGRAM                    (2u)

/*! @brief Set all entries in a socket array to "not set". */
#define OPCUA_P_SOCKET_ARRAY_ZERO(pSA)          ((pSA)->uintNbSockets=0)

/*! @brief Checks if a specific entry in a socket array is set. */
#define OPCUA_P_SOCKET_ARRAY_ISSET(rawsck, pSA) OpcUa_P_RawSocket_FD_Isset((OpcUa_RawSocket)rawsck, (OpcUa_P_Socket_Array*)pSA)

/*! @brief Sets a specific socket in a socket array. */
#define OPCUA_P_SOCKET_ARRAY_SET(rawsck, pSA)   { \
    if ((pSA)->uintNbSockets < OPCUA_P_SOCKET_ARRAY_SIZE) \
        (pSA)->SocketArray[(pSA)->uintNbSockets++]=(OpcUa_RawSocket)(rawsck);}

#if 0
/*! @brief Operation would block. */
#define OPCUA_P_SOCKET_WOULDBLOCK 10035L /* WSAEWOULDBLOCK */

/*! @brief Operation is in progress. */
#define OPCUA_P_SOCKET_INPROGRESS 10036L /* WSAEINPROGRESS */
#endif

/*! @brief Value for an invalid raw socket. */
#define OPCUA_P_SOCKET_INVALID      (~0)

/*! @brief Wait for an infinite amount of time. */
#define OPCUA_P_SOCKET_INFINITE     0xffffffffL     /* wait infinite time */

/*! @brief Value returned by platform API if an error happened. */
#define OPCUA_P_SOCKET_SOCKETERROR  (-1)            /* platform representation of socket error */

/*============================================================================
 * Functions
 *===========================================================================*/

/*!
 * @brief Initialize the platform network interface. (interface)
 *
 * This function initializes all platform and functional resources used by the
 * p socket module. This includes static variables.
 *
 * @return Good if initialization went fine. A bad status code in any other case.
 */
OpcUa_StatusCode OpcUa_P_RawSocket_InitializeNetwork();


/*!
 * @brief Clean up the platform network interface.
 *
 * Cleans up all data allocated by the p socket module and shuts down the
 * platforms network system as far as possible/needed.
 *
 * @return Good if initialization went fine. A bad status code in any other case.
 */
OpcUa_StatusCode OpcUa_P_RawSocket_CleanupNetwork();


/*!
 * @brief Close a system socket.
 *
 * @param RawSocket [in] The system socket to be closed.
 *
 * @return A "Good" status code if no error occured, a "Bad" status code otherwise.
 */
OpcUa_StatusCode OpcUa_P_RawSocket_Close(OpcUa_RawSocket RawSocket);



/*!
 * @brief Connect the given system socket to the specified address.
 *
 * @param RawSocket [in]    The socket to connect.
 * @param Port      [in]    To which port should be connected.
 * @param Host      [in]    The server IP address in string representation.
 *
 * @return A "Good" status code if no error occured, a "Bad" status code otherwise.
 *         OpcUa_BadWouldBlock should not be handled as error, if non blocking sockets are used.
 */
OpcUa_StatusCode OpcUa_P_RawSocket_Connect( OpcUa_RawSocket RawSocket,
                                            OpcUa_Int16     Port,
                                            OpcUa_StringA   Host);

/*!
 * @brief Bind the giben system socket to the specified address.
 *
 * @param RawSocket [in]    The socket to bind.
 * @param Port      [in]    Bind the socket to this port.
 *
 * @return A "Good" status code if no error occured, a "Bad" status code otherwise.
 */
OpcUa_StatusCode OpcUa_P_RawSocket_Bind(OpcUa_RawSocket RawSocket,
                                        OpcUa_Int16     Port);

/*!
 * @brief Start listening on the given system socket.
 *
 * @param RawSocket [in]    The server socket, which should accept connect requests.
 *
 * @return A "Good" status code if no error occured, a "Bad" status code otherwise.
 */
OpcUa_StatusCode OpcUa_P_RawSocket_Listen(OpcUa_RawSocket RawSocket);

/*!
 * @brief Accept connections on the given system socket.
 *
 * Accepts a connection from another network node and returns the
 * port and address as well as the newly created system socket
 * for the connection.
 *
 * @param RawSocket     [in]    Accept connection requests on this socket.
 * @param Port          [out]   Will store the port of accepted connection.
 * @param Address       [out]   Will store the address of the connected client.
 * @param NagleOff      [in]    If the new connection has Nagling activated.
 * @param KeepAliveOn   [in]    If the new connection sends keep alive pakets.
 *
 * @return The created system socket. An invalid socket (OPCUA_P_SOCKET_INVALID) in case of error.
 */
OpcUa_RawSocket OpcUa_P_RawSocket_Accept(   OpcUa_RawSocket RawSocket,
                                            OpcUa_UInt16*   Port,
                                            OpcUa_UInt32*   Address,
                                            OpcUa_Boolean   NagleOff,
                                            OpcUa_Boolean   KeepAliveOn);

/*!
 * @brief Read data from the given system socket into a buffer.
 *
 * Tries to read data from the given system socket into the buffer.
 * The amount of the received data will fit into the given buffersize.
 *
 * @param RawSocket     [in]        The socket to read from.
 * @param Buffer        [in/out]    Will receive the read data.
 * @param BufferSize    [in]        Maximum number of bytes to receive.
 *
 * @return The number of bytes read, OPCUA_P_SOCKET_SOCKETERROR or 0 if the peer disconnected.
 */
OpcUa_Int32 OpcUa_P_RawSocket_Read( OpcUa_RawSocket RawSocket,
                                    OpcUa_Byte*     Buffer,
                                    OpcUa_UInt32    BufferSize);

/*!
 * @brief Write data over the given system socket.
 *
 * Send the given data in the buffer and size over the system socket.
 *
 * @param RawSocket     [in]    Socket to send the data over.
 * @param Buffer        [in]    Buffer holding the data to be sent.
 * @param BufferSize    [in]    How much data should be sent, in bytes.
 *
 * @return The number of bytes written, a OPCUA_P_SOCKET_SOCKETERROR
 */
OpcUa_Int32 OpcUa_P_RawSocket_Write(OpcUa_RawSocket RawSocket,
                                    OpcUa_Byte*     Buffer,
                                    OpcUa_UInt32    BufferSize);

/*!
 * @brief Set the system socket to non-blocking or mode.
 *
 * @param RawSocket [in]    The system socket descriptor.
 * @param bBlocking [in]    Socket will be set to block, if true, nonblocking else.
 *
 * @return A "Good" status code if no error occured, a "Bad" status code otherwise.
 */
OpcUa_StatusCode OpcUa_P_RawSocket_SetBlockMode(    OpcUa_RawSocket RawSocket,
                                                    OpcUa_Boolean   bBlocking);

/*!
 * @brief Convert the given value from network into host byte order.
 *
 * @param netLong   [in]    Value to be converted.
 *
 * @return The converted value.
 */
OpcUa_UInt32 OpcUa_P_RawSocket_NToHL(OpcUa_UInt32 netLong);

/*!
 * @brief Convert the given value from network into host byte order.
 *
 * @param netShort  [in]    Value to be converted.
 *
 * @return The converted value.
 */
OpcUa_UInt16 OpcUa_P_RawSocket_NToHS(OpcUa_UInt16 netShort);

/*!
 * @brief Convert the given value from host into network byte order.
 *
 * @param hstLong   [in]    Value to be converted.
 *
 * @return The converted value.
 */
OpcUa_UInt32 OpcUa_P_RawSocket_HToNL(OpcUa_UInt32 hstLong);

/*!
 * @brief Convert the given value from host into network byte order.
 *
 * @param hstShort  [in]    Value to be converted.
 *
 * @return The converted value.
 */
OpcUa_UInt16 OpcUa_P_RawSocket_HToNS(OpcUa_UInt16 hstShort);




/*!
 * @brief Set sockets in given file descriptor sets if a certain event occured.
 *
 * @param RawSocket         [in]        The maximum file descriptor. Ignored in win32.
 * @param FdSetRead         [in/out]    OpcUa_Socket_FdSet with all sockets set, that wait on read events. Holds all sockets where this event occured afterwards.
 * @param FdSetWrite        [in/out]    OpcUa_Socket_FdSet with all sockets set, that wait on write events. Holds all sockets where this event occured afterwards.
 * @param FdSetException    [in/out]    OpcUa_Socket_FdSet with all sockets set, that wait on exception events. Holds all sockets where this event occured afterwards.
 * @param Timeout           [in]        The maximume time to block at this call.
 *
 * @return A "Good" status code if no error occured, a "Bad" status code otherwise.
 */
OpcUa_StatusCode OpcUa_P_RawSocket_Select(  OpcUa_RawSocket         RawSocket,
                                            OpcUa_P_Socket_Array*   FdSetRead,
                                            OpcUa_P_Socket_Array*   FdSetWrite,
                                            OpcUa_P_Socket_Array*   FdSetException,
                                            OpcUa_TimeVal*          Timeout);


#if OPCUA_P_SOCKETGETPEERINFO_V2
/*!
 * @brief Get address information for the peer connected to the given socket socket handle.
 *
 * @param RawSocket             [in] Identifier for the connection.
 * @param achPeerInfoBuffer     [in] Where the address information gets stored.
 * @param uiPeerInfoBufferSize  [in] The size of the given buffer.
 *
 * @return A "Good" status code if no error occured, a "Bad" status code otherwise.
 */
OpcUa_StatusCode OpcUa_P_RawSocket_GetPeerInfo( OpcUa_Socket    RawSocket,
                                                OpcUa_CharA*    achPeerInfoBuffer,
                                                OpcUa_UInt32    uiPeerInfoBufferSize);
#else

/*!
 * @brief Get IP address and port number of the connected network node.
 *
 * @param RawSocket [in]    Identifier for the connection.
 * @param IP        [out]   Where the IP gets stored.
 * @param Port      [out]   Where the port gets stored.
 *
 * @return A "Good" status code if no error occured, a "Bad" status code otherwise.
 */
OpcUa_StatusCode OpcUa_P_RawSocket_GetPeerInfo( OpcUa_RawSocket RawSocket,
                                                OpcUa_UInt32*   IP,
                                                OpcUa_UInt16*   Port);
#endif

/*!
 * @brief Get IP address and port number of the local network node.
 *
 * @param RawSocket [in]    Identifier for the connection.
 * @param IP        [out]   Where the IP gets stored.
 * @param Port      [out]   Where the port gets stored.
 *
 * @return A "Good" status code if no error occured, a "Bad" status code otherwise.
 */
OpcUa_StatusCode OpcUa_P_RawSocket_GetLocalInfo(OpcUa_RawSocket RawSocket,
                                                OpcUa_UInt32*   IP,
                                                OpcUa_UInt16*   Port);

/*!
 * @brief Get last socket error that happened.
 *
 * This function is currently mostly for debugging reasons, since no real error
 * mapping exists, yet (and probably won't).
 *
 * @param RawSocket [in]    Identifier for the connection, which error code is requested.
 *
 * @return The raw error value.
 */
OpcUa_Int32 OpcUa_P_RawSocket_GetLastError(OpcUa_RawSocket RawSocket);

/*!
 * @brief Create a system socket.
 *
 * @param pRawSocket    [out]   Pointer to a system socket to store the new one.
 * @param NagleOff      [in]    Switch for Nagle algorithm.
 * @param KeepAliveOn   [in]    Switch for TCP keep alive packet.
 *
 * @return A "Good" status code if no error occured, a "Bad" status code otherwise.
 */
OpcUa_StatusCode OpcUa_P_RawSocket_Create(  OpcUa_RawSocket* pRawSocket,
                                            OpcUa_Boolean    NagleOff,
                                            OpcUa_Boolean    KeepAliveOn);


OpcUa_Boolean OpcUa_P_RawSocket_FD_Isset(   OpcUa_RawSocket         a_RawSocket,
                                            OpcUa_P_Socket_Array*   a_pFdSet);


OpcUa_UInt32 OpcUa_P_RawSocket_InetAddr(    OpcUa_StringA   sRemoteAddress);
