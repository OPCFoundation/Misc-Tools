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

/* own headers */
#include <opcua_p_socket.h>

#ifdef _MSC_VER
/* this pragma is for win32 */
#pragma warning(disable:4127) /* suppress "conditional expression is constant" in fdset macros */
#pragma warning(disable:4748) /* suppress /GS can not protect parameters and local variables from local buffer overrun because optimizations are disabled in function */
#endif /* _MSC_VER */

/*============================================================================
 * Initialize the platform network interface
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_RawSocket_InitializeNetwork(OpcUa_Void)
{
    WSADATA wsaData;
    int     apiResult   = 0;

    /* The return value is zero if the operation was successful.
       Otherwise, the value SOCKET_ERROR is returned, and a specific
       error number can be retrieved by calling WSAGetLastError. */
    apiResult = WSAStartup(0x202, &wsaData);

    if(apiResult == 0)
    {
        return OpcUa_Good;
    }
    return OpcUa_BadCommunicationError;
}

/*============================================================================
 * Clean the platform network interface up.
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_RawSocket_CleanupNetwork(OpcUa_Void)
{
    WSACleanup();
    return OpcUa_Good;
}

/*============================================================================
 * Close Socket.
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_RawSocket_Close(OpcUa_RawSocket a_RawSocket)
{
    SOCKET winSocket = (SOCKET)OPCUA_P_SOCKET_INVALID;

OpcUa_InitializeStatus(OpcUa_Module_Socket, "P_Close");

    winSocket = (SOCKET)a_RawSocket;

    /* close socket */
    shutdown(winSocket, 2);

    uStatus = closesocket(winSocket);

    /* check uStatus */
    if(uStatus == OPCUA_P_SOCKET_SOCKETERROR)
    {
        uStatus = OpcUa_BadCommunicationError;
        goto Error;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * Create Socket.
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_RawSocket_Create(  OpcUa_RawSocket*    a_pRawSocket,
                                            OpcUa_Boolean       a_bNagleOff,
                                            OpcUa_Boolean       a_bKeepAliveOn)
{
    OpcUa_StatusCode    uStatus     = OpcUa_Good;
    int                 iFlag       = 1;
    OpcUa_Int           apiResult   = 0;
    SOCKET              WinSocket   = (SOCKET)OPCUA_P_SOCKET_INVALID;

#if OPCUA_P_SOCKET_SETTCPRCVBUFFERSIZE || OPCUA_P_SOCKET_SETTCPSNDBUFFERSIZE
    OpcUa_Int           iBufferSize = OPCUA_P_TCPRCVBUFFERSIZE;
#endif /* OPCUA_P_SOCKET_SETTCPRCVBUFFERSIZE || OPCUA_P_SOCKET_SETTCPSNDBUFFERSIZE */

    OpcUa_GotoErrorIfArgumentNull(a_pRawSocket);

    /* create socket through platform API */
    WinSocket = socket(AF_INET, SOCK_STREAM, 0);
    apiResult = OpcUa_P_RawSocket_GetLastError((OpcUa_RawSocket)WinSocket);

    /* check if socket creation was successful */
    if(     WinSocket == OPCUA_P_SOCKET_INVALID
        ||  apiResult != 0)
    {
        uStatus = OpcUa_BadCommunicationError;
        goto Error;
    }

    /* set socketoptions */
    if(a_bNagleOff)
    {
        if(OPCUA_P_SOCKET_SOCKETERROR == setsockopt(WinSocket, IPPROTO_TCP, TCP_NODELAY, (const char*)&iFlag, sizeof(int)))
        {
            uStatus = OpcUa_BadCommunicationError;
            goto Error;
        }
    }
    if(a_bKeepAliveOn)
    {
        /* set socket options */
        if(OPCUA_P_SOCKET_SOCKETERROR == setsockopt(WinSocket, IPPROTO_TCP,  SO_KEEPALIVE, (const char*)&iFlag, sizeof(int)))
        {
            uStatus = OpcUa_BadCommunicationError;
            goto Error;
        }
    }

#if 0
    if(OPCUA_P_SOCKET_SOCKETERROR == getsockopt(WinSocket, SOL_SOCKET,  SO_RCVBUF, (char*)&iBufferSize, &temp))
    {
        int result = OpcUa_P_RawSocket_GetLastError((OpcUa_RawSocket)WinSocket);
        uStatus = OpcUa_BadCommunicationError;
        goto Error;
    }
#endif

#if OPCUA_P_SOCKET_SETTCPRCVBUFFERSIZE
    iBufferSize = OPCUA_P_TCPRCVBUFFERSIZE;
    if(OPCUA_P_SOCKET_SOCKETERROR == setsockopt(WinSocket, SOL_SOCKET,  SO_RCVBUF, (const char*)&iBufferSize, sizeof(int)))
    {
        /*int result = OpcUa_P_RawSocket_GetLastError((OpcUa_RawSocket)WinSocket);*/
        uStatus = OpcUa_BadCommunicationError;
        goto Error;
    }
#endif /* OPCUA_P_SOCKET_SETTCPRCVBUFFERSIZE */

#if OPCUA_P_SOCKET_SETTCPSNDBUFFERSIZE
    iBufferSize = OPCUA_P_TCPSNDBUFFERSIZE;
    if(OPCUA_P_SOCKET_SOCKETERROR == setsockopt(WinSocket, SOL_SOCKET,  SO_SNDBUF, (const char*)&iBufferSize, sizeof(int)))
    {
        /*int result = OpcUa_P_RawSocket_GetLastError((OpcUa_RawSocket)WinSocket);*/
        uStatus = OpcUa_BadCommunicationError;
        goto Error;
    }
#endif /* OPCUA_P_SOCKET_SETTCPSNDBUFFERSIZE */

    *a_pRawSocket = (OpcUa_RawSocket)WinSocket;

    return OpcUa_Good;

Error:

    if(WinSocket != OPCUA_P_SOCKET_INVALID)
    {
        OpcUa_P_RawSocket_Close((OpcUa_RawSocket)WinSocket);
        *a_pRawSocket = (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID;
    }

    return uStatus;
}

/*============================================================================
 * Connect Socket for Client.
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_RawSocket_Connect( OpcUa_RawSocket a_RawSocket,
                                            OpcUa_Int16     a_nPort,
                                            OpcUa_StringA   a_sHost)
{
    int                 intSize   = 0;
    SOCKET              winSocket = (SOCKET)OPCUA_P_SOCKET_INVALID;
    struct sockaddr     *pName;
    struct sockaddr_in  srv;
    char*               localhost = "127.0.0.1";

OpcUa_InitializeStatus(OpcUa_Module_Socket, "P_Connect");

    OpcUa_GotoErrorIfArgumentNull(a_RawSocket);
    winSocket = (SOCKET)a_RawSocket;

    intSize = sizeof(struct sockaddr_in);
    OpcUa_MemSet(&srv, 0, intSize);

    if(!strcmp("localhost", a_sHost))
    {
        a_sHost = localhost;
    }

    srv.sin_addr.s_addr = inet_addr(a_sHost);

    if(srv.sin_addr.s_addr == INADDR_NONE)
    {
        return OpcUa_BadInvalidArgument;
    }

    srv.sin_port   = htons(a_nPort);
    srv.sin_family = AF_INET;

    pName = (struct sockaddr *) &srv;

    if(connect(winSocket, pName, intSize) == OPCUA_P_SOCKET_SOCKETERROR)
    {
        int result = OpcUa_P_RawSocket_GetLastError((OpcUa_RawSocket)winSocket);

        /* a connect takes some time and this "error" is common with nonblocking sockets */
        if(result == WSAEWOULDBLOCK || result == WSAEINPROGRESS)
        {
            uStatus = OpcUa_BadWouldBlock;
        }
        else
        {
            uStatus = OpcUa_BadCommunicationError;
        }
        goto Error;
    }

    uStatus = OpcUa_Good;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * Bind to Socket
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_RawSocket_Bind(    OpcUa_RawSocket a_RawSocket,
                                            OpcUa_Int16     a_nPort)
{
    OpcUa_Int32         intSize    = 0;
    SOCKET              winSocket  = (SOCKET)OPCUA_P_SOCKET_INVALID;
    struct sockaddr_in  srv;
    struct sockaddr     *pName;

OpcUa_InitializeStatus(OpcUa_Module_Socket, "P_Bind");

    OpcUa_GotoErrorIfArgumentNull(a_RawSocket);
    winSocket = (SOCKET)a_RawSocket;

    intSize = sizeof(struct sockaddr_in);
    OpcUa_MemSet(&srv, 0, intSize);

    srv.sin_addr.s_addr = INADDR_ANY;
    srv.sin_port        = htons(a_nPort);
    srv.sin_family      = AF_INET;
    pName               = (struct sockaddr*)&srv;

    if(bind(winSocket, pName, intSize) == OPCUA_P_SOCKET_SOCKETERROR)
    {
        uStatus = OpcUa_BadCommunicationError;
        goto Error;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}


/*============================================================================
 * Bind to Socket and set to listen for Server.
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_RawSocket_Listen(OpcUa_RawSocket a_RawSocket)
{
    SOCKET winSocket  = (SOCKET)OPCUA_P_SOCKET_INVALID;

OpcUa_InitializeStatus(OpcUa_Module_Socket, "P_Listen");

    winSocket = (SOCKET)a_RawSocket;

    if(listen(winSocket, SOMAXCONN) == OPCUA_P_SOCKET_SOCKETERROR)
    {
        uStatus = OpcUa_BadCommunicationError;
        goto Error;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * Accept Socket connection from Client.
 *===========================================================================*/
OpcUa_RawSocket OpcUa_P_RawSocket_Accept(   OpcUa_RawSocket a_RawSocket,
                                            OpcUa_UInt16*   a_pPort,
                                            OpcUa_UInt32*   a_pAddress,
                                            OpcUa_Boolean   a_bNagleOff,
                                            OpcUa_Boolean   a_bKeepAliveOn)
{
    int                 cli_size        = 0;
    int                 iFlag           = 1;
    SOCKET              winSocketServer = (SOCKET)OPCUA_P_SOCKET_INVALID;
    SOCKET              winSocketClient = (SOCKET)OPCUA_P_SOCKET_INVALID;
    struct sockaddr_in  cli;

#if OPCUA_P_SOCKET_SETTCPRCVBUFFERSIZE || OPCUA_P_SOCKET_SETTCPSNDBUFFERSIZE
    OpcUa_Int           iBufferSize = OPCUA_P_TCPRCVBUFFERSIZE;
#endif /* OPCUA_P_SOCKET_SETTCPRCVBUFFERSIZE || OPCUA_P_SOCKET_SETTCPSNDBUFFERSIZE */

    if(a_RawSocket == (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID)
    {
        return OpcUa_Null;
    }

    winSocketServer = (SOCKET)a_RawSocket;

    cli_size = sizeof(cli);

    OpcUa_MemSet(&cli, 0, cli_size);

    winSocketClient = accept(winSocketServer,(struct sockaddr*) &cli, &cli_size);

    if(winSocketClient == OPCUA_P_SOCKET_INVALID)
    {
        /* accept failed */
        goto Error;
    }

    if(a_pPort != OpcUa_Null)
    {
        *a_pPort = ntohs((OpcUa_UInt16)((struct sockaddr_in*)(&cli))->sin_port);
    }

    if(a_pAddress != OpcUa_Null)
    {
        *a_pAddress = ((struct sockaddr_in*)(&cli))->sin_addr.s_addr;
    }

    if(a_bNagleOff)
    {
        /* set socket options */
        if(OPCUA_P_SOCKET_SOCKETERROR == setsockopt(winSocketClient, IPPROTO_TCP, TCP_NODELAY, (const char*)&iFlag, sizeof(int)))
        {
            goto Error;
        }
    }

    if(a_bKeepAliveOn)
    {
        /* set socket options */
        if(OPCUA_P_SOCKET_SOCKETERROR == setsockopt( winSocketClient, IPPROTO_TCP, SO_KEEPALIVE, (const char*)&iFlag, sizeof(int)))
        {
            goto Error;
        }
    }

#if OPCUA_P_SOCKET_SETTCPRCVBUFFERSIZE
    iBufferSize = OPCUA_P_TCPRCVBUFFERSIZE;
    if(OPCUA_P_SOCKET_SOCKETERROR == setsockopt(winSocketClient, SOL_SOCKET,  SO_RCVBUF, (const char*)&iBufferSize, sizeof(int)))
    {
        /*int result = OpcUa_P_RawSocket_GetLastError((OpcUa_RawSocket)winSocketClient);*/
        goto Error;
    }
#endif /* OPCUA_P_SOCKET_SETTCPRCVBUFFERSIZE */

#if OPCUA_P_SOCKET_SETTCPSNDBUFFERSIZE
    iBufferSize = OPCUA_P_TCPSNDBUFFERSIZE;
    if(OPCUA_P_SOCKET_SOCKETERROR == setsockopt(winSocketClient, SOL_SOCKET,  SO_SNDBUF, (const char*)&iBufferSize, sizeof(int)))
    {
        /*int result = OpcUa_P_RawSocket_GetLastError((OpcUa_RawSocket)winSocketClient);*/
        goto Error;
    }
#endif /* OPCUA_P_SOCKET_SETTCPSNDBUFFERSIZE */

    return (OpcUa_RawSocket)winSocketClient;

Error:

    if(winSocketClient == OPCUA_P_SOCKET_INVALID)
    {
        OpcUa_P_RawSocket_Close((OpcUa_RawSocket)winSocketClient);
    }

    return (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID;
}

/*============================================================================
 * Read Socket.
 *===========================================================================*/
OpcUa_Int32 OpcUa_P_RawSocket_Read( OpcUa_RawSocket a_RawSocket,
                                    OpcUa_Byte*     a_pBuffer,
                                    OpcUa_UInt32    a_nBufferSize)
{
    int     intBytesReceived    = 0;
    SOCKET  winSocket           = (SOCKET)OPCUA_P_SOCKET_INVALID;

    if(a_RawSocket == (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID)
    {
        return 0;
    }

    winSocket = (SOCKET)a_RawSocket;

    intBytesReceived = recv(winSocket, (char*)a_pBuffer, (int)a_nBufferSize, 0);

    return intBytesReceived;
}

/*============================================================================
 * Write Socket.
 *===========================================================================*/
OpcUa_Int32 OpcUa_P_RawSocket_Write(    OpcUa_RawSocket a_RawSocket,
                                        OpcUa_Byte*     a_pBuffer,
                                        OpcUa_UInt32    a_uBufferSize)
{
    int     intBytesSend    = 0;
    SOCKET  winSocket       = (SOCKET)OPCUA_P_SOCKET_INVALID;

    if(a_RawSocket == (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID)
    {
        return 0;
    }

    winSocket = (SOCKET)a_RawSocket;

    intBytesSend = send(winSocket, (char*)a_pBuffer, a_uBufferSize, 0);

    return intBytesSend;
}


/*============================================================================
 * Set socket to nonblocking mode
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_RawSocket_SetBlockMode(    OpcUa_RawSocket a_RawSocket,
                                                    OpcUa_Boolean   a_bBlocking)
{
    int              apiResult   = 0;
    SOCKET           winSocket   = (SOCKET)OPCUA_P_SOCKET_INVALID;
    OpcUa_StatusCode uStatus     = OpcUa_Good;
    u_long           uNonBlocking= (a_bBlocking==OpcUa_False)?1:0;

    if(a_RawSocket == (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID)
    {
        return 0;
    }

    winSocket = (SOCKET)a_RawSocket;

    apiResult = ioctlsocket(winSocket, FIONBIO, &uNonBlocking);

    if(apiResult != 0)
    {
        uStatus = OpcUa_BadCommunicationError;
    }

    return uStatus;
}


/*============================================================================
 * Network Byte Order Conversion Helper Functions
 *===========================================================================*/
OpcUa_UInt32 OpcUa_P_RawSocket_NToHL(OpcUa_UInt32 netLong)
{
    OpcUa_UInt32 retval = ntohl((unsigned long)netLong);
    return retval;
}

OpcUa_UInt16 OpcUa_P_RawSocket_NToHS(OpcUa_UInt16 netShort)
{
    OpcUa_UInt16 retval = ntohs((unsigned short)netShort);
    return retval;
}

OpcUa_UInt32 OpcUa_P_RawSocket_HToNL(OpcUa_UInt32 hstLong)
{
    OpcUa_UInt32 retval = htonl((unsigned long)hstLong);
    return retval;
}

OpcUa_UInt16 OpcUa_P_RawSocket_HToNS(OpcUa_UInt16 hstShort)
{
    OpcUa_UInt16 retval = htons((unsigned short)hstShort);
    return retval;
}

#if OPCUA_P_SOCKETGETPEERINFO_V2
/*============================================================================
 * Get address information about the peer
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_RawSocket_GetPeerInfo( OpcUa_Socket    a_RawSocket,
                                                OpcUa_CharA*    a_achPeerInfoBuffer,
                                                OpcUa_UInt32    a_uiPeerInfoBufferSize)
{
    int                 apiResult       = 0;
    struct sockaddr_in  sockAddrIn;
    size_t              TempLen         = sizeof(struct sockaddr_in);
    SOCKET              winSocket       = (SOCKET)OPCUA_P_SOCKET_INVALID;
    char*               pchAddrBuf      = OpcUa_Null;
    OpcUa_UInt16        usPort          = 0;

OpcUa_InitializeStatus(OpcUa_Module_Socket, "GetPeerInfo");

    /* initial parameter check */
    OpcUa_ReturnErrorIfTrue((a_RawSocket == (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID), OpcUa_BadInvalidArgument);
    OpcUa_ReturnErrorIfTrue((a_uiPeerInfoBufferSize < OPCUA_P_PEERINFO_MIN_SIZE), OpcUa_BadInvalidArgument);
    OpcUa_ReturnErrorIfArgumentNull(a_achPeerInfoBuffer);

    winSocket = (SOCKET)a_RawSocket;
    apiResult = getpeername(winSocket, (struct sockaddr*)&sockAddrIn, (int*)&TempLen);

    OpcUa_ReturnErrorIfTrue((apiResult != 0), OpcUa_BadInternalError);

    /* IP */
    pchAddrBuf = inet_ntoa(sockAddrIn.sin_addr);
    OpcUa_GotoErrorIfTrue(pchAddrBuf == OpcUa_Null, OpcUa_BadInternalError);

    /* Port */
    usPort = OpcUa_P_RawSocket_NToHS((OpcUa_UInt16)sockAddrIn.sin_port);

    /* build result string */
    TempLen = strlen(pchAddrBuf);

#if OPCUA_USE_SAFE_FUNCTIONS
    OpcUa_GotoErrorIfTrue((strncpy_s(a_achPeerInfoBuffer, a_uiPeerInfoBufferSize + 1, pchAddrBuf, TempLen) != 0), OpcUa_Bad);
    a_achPeerInfoBuffer[TempLen] = ':';
    TempLen++;
    sprintf_s(&a_achPeerInfoBuffer[TempLen], a_uiPeerInfoBufferSize - TempLen, "%u", usPort);
#else /* OPCUA_USE_SAFE_FUNCTIONS */
    OpcUa_GotoErrorIfTrue((strncpy(a_achPeerInfoBuffer, pchAddrBuf, TempLen) != a_achPeerInfoBuffer), OpcUa_Bad);
    a_achPeerInfoBuffer[TempLen] = ':';
    sprintf(&a_achPeerInfoBuffer[TempLen + 1], "%u", usPort);
#endif /* OPCUA_USE_SAFE_FUNCTIONS */

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}
#else /* OPCUA_P_SOCKETGETPEERINFO_V2 */
/*============================================================================
 * Get IP Address and Port Number of the Peer
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_RawSocket_GetPeerInfo( OpcUa_RawSocket a_RawSocket,
                                                OpcUa_UInt32*   a_pIP,
                                                OpcUa_UInt16*   a_pPort)
{
    int                 apiResult       = 0;
    struct sockaddr_in  sockAddrIn;
    size_t              sockAddrInLen   = sizeof(struct sockaddr_in);
    SOCKET              winSocket       = (SOCKET)OPCUA_P_SOCKET_INVALID;

OpcUa_InitializeStatus(OpcUa_Module_Socket, "GetPeerInfo");

    if(a_RawSocket == (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID)
    {
        return 0;
    }

    winSocket = (SOCKET)a_RawSocket;

    apiResult = getpeername(winSocket, (struct sockaddr*)&sockAddrIn, (int*)&sockAddrInLen);

    if(apiResult != 0)
    {
        uStatus = OpcUa_BadCommunicationError;
        goto Error;
    }

    if(a_pIP != OpcUa_Null)
    {
        *a_pIP   = OpcUa_P_RawSocket_NToHL((OpcUa_UInt32)sockAddrIn.sin_addr.s_addr);
    }

    if(a_pPort != OpcUa_Null)
    {
        *a_pPort = OpcUa_P_RawSocket_NToHS((OpcUa_UInt16)sockAddrIn.sin_port);
    }
OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}
#endif

/*============================================================================
 * Get IP Address and Port Number of the local connection
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_RawSocket_GetLocalInfo(    OpcUa_RawSocket a_RawSocket,
                                                    OpcUa_UInt32*   a_pIP,
                                                    OpcUa_UInt16*   a_pPort)
{
    int                 apiResult     = 0;
    struct sockaddr_in  sockAddrIn;
    size_t              sockAddrInLen = sizeof(struct sockaddr_in);
    SOCKET              winSocket     = (SOCKET)OPCUA_P_SOCKET_INVALID;

OpcUa_InitializeStatus(OpcUa_Module_Socket, "GetLocalInfo");

    if(a_RawSocket == (OpcUa_RawSocket)OPCUA_P_SOCKET_INVALID)
    {
        return 0;
    }

    winSocket = (SOCKET)a_RawSocket;

    apiResult = getsockname(winSocket, (struct sockaddr*)&sockAddrIn, (int*)&sockAddrInLen);

    if(apiResult != 0)
    {
        apiResult = OpcUa_P_RawSocket_GetLastError(a_RawSocket);
        uStatus = OpcUa_BadCommunicationError;
        goto Error;
    }

    if(a_pIP != OpcUa_Null)
    {
        *a_pIP   = OpcUa_P_RawSocket_NToHL((OpcUa_UInt32)sockAddrIn.sin_addr.s_addr);
    }

    if(a_pPort != OpcUa_Null)
    {
        *a_pPort = OpcUa_P_RawSocket_NToHS((OpcUa_UInt16)sockAddrIn.sin_port);
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * Select usable socket. (maxfds ignored in win32)
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_RawSocket_Select(  OpcUa_RawSocket         a_MaxFds,
                                            OpcUa_P_Socket_Array*   a_pFdSetRead,
                                            OpcUa_P_Socket_Array*   a_pFdSetWrite,
                                            OpcUa_P_Socket_Array*   a_pFdSetException,
                                            OpcUa_TimeVal*          a_pTimeout)
{
    int                 apiResult  = 0;
    struct timeval      timeout;

OpcUa_InitializeStatus(OpcUa_Module_Socket, "P_Select");

    OpcUa_ReferenceParameter(a_MaxFds);

    OpcUa_GotoErrorIfArgumentNull(a_pFdSetRead);
    OpcUa_GotoErrorIfArgumentNull(a_pFdSetWrite);
    OpcUa_GotoErrorIfArgumentNull(a_pFdSetException);

    timeout.tv_sec  = a_pTimeout->uintSeconds;
    timeout.tv_usec = a_pTimeout->uintMicroSeconds;

    apiResult = select( 0,
                        (fd_set*)a_pFdSetRead,
                        (fd_set*)a_pFdSetWrite,
                        (fd_set*)a_pFdSetException,
                        &timeout);

    if(apiResult == OPCUA_P_SOCKET_SOCKETERROR)
    {
        apiResult = WSAGetLastError();

        switch(apiResult)
        {
        case WSAENOTSOCK:
            {
                uStatus = OpcUa_BadInvalidArgument;
                break;
            }
        default:
            {
                uStatus = OpcUa_BadCommunicationError;
            }
        }
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * Get last socket error.
 *===========================================================================*/
OpcUa_Int32 OpcUa_P_RawSocket_GetLastError( OpcUa_RawSocket a_RawSocket)
{
    int lastError = 0;
    OpcUa_ReferenceParameter(a_RawSocket); /* Not needed in this implementation. */

    lastError = WSAGetLastError();

    return (OpcUa_Int32)lastError;
}

/*============================================================================
* OpcUa_P_RawSocket_FD_Isset
*===========================================================================*/
OpcUa_Boolean OpcUa_P_RawSocket_FD_Isset(   OpcUa_RawSocket         a_RawSocket,
                                            OpcUa_P_Socket_Array*   a_pFdSet)
{
    SOCKET WinSocket = (SOCKET)a_RawSocket;

    if(FD_ISSET(WinSocket, (fd_set*)a_pFdSet) == TRUE)
    {
        return OpcUa_True;
    }
    else
    {
        return OpcUa_False;
    }
}

/*============================================================================
 * Initialize the platform network interface
 *===========================================================================*/
OpcUa_UInt32 OpcUa_P_RawSocket_InetAddr(OpcUa_StringA sRemoteAddress)
{
    if(sRemoteAddress != OpcUa_Null)
    {
        return (OpcUa_UInt32)inet_addr(sRemoteAddress);
    }

    return 0;
}
