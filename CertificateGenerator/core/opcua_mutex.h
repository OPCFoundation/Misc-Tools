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

#if OPCUA_MUTEX_ERROR_CHECKING
    #define OPCUA_P_MUTEX_CREATE(xMutex)  OpcUa_ProxyStub_g_PlatformLayerCalltable->MutexCreate( xMutex, __FILE__, __LINE__)
    #define OPCUA_P_MUTEX_DELETE(xMutex)  OpcUa_ProxyStub_g_PlatformLayerCalltable->MutexDelete( xMutex, __FILE__, __LINE__)
    #define OPCUA_P_MUTEX_LOCK(xMutex)    OpcUa_ProxyStub_g_PlatformLayerCalltable->MutexLock(   xMutex, __FILE__, __LINE__)
    #define OPCUA_P_MUTEX_UNLOCK(xMutex)  OpcUa_ProxyStub_g_PlatformLayerCalltable->MutexUnlock( xMutex, __FILE__, __LINE__)
#else /* OPCUA_MUTEX_ERROR_CHECKING */
#if OPCUA_USE_SYNCHRONISATION
    #define OPCUA_P_MUTEX_CREATE OpcUa_ProxyStub_g_PlatformLayerCalltable->MutexCreate
    #define OPCUA_P_MUTEX_DELETE OpcUa_ProxyStub_g_PlatformLayerCalltable->MutexDelete
    #define OPCUA_P_MUTEX_LOCK   OpcUa_ProxyStub_g_PlatformLayerCalltable->MutexLock
    #define OPCUA_P_MUTEX_UNLOCK OpcUa_ProxyStub_g_PlatformLayerCalltable->MutexUnlock
#else /* OPCUA_USE_SYNCHRONISATION */
    #define OPCUA_P_MUTEX_CREATE(xMutex) OpcUa_Good
    #define OPCUA_P_MUTEX_DELETE(xMutex)
    #define OPCUA_P_MUTEX_LOCK(xMutex)
    #define OPCUA_P_MUTEX_UNLOCK(xMutex)
#endif /* OPCUA_USE_SYNCHRONISATION */
#endif /* OPCUA_MUTEX_ERROR_CHECKING */
