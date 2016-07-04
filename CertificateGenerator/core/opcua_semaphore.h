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

#if OPCUA_USE_SYNCHRONISATION
# define OPCUA_P_SEMAPHORE_CREATE    OpcUa_ProxyStub_g_PlatformLayerCalltable->SemaphoreCreate
# define OPCUA_P_SEMAPHORE_DELETE    OpcUa_ProxyStub_g_PlatformLayerCalltable->SemaphoreDelete
# define OPCUA_P_SEMAPHORE_WAIT      OpcUa_ProxyStub_g_PlatformLayerCalltable->SemaphoreWait
# define OPCUA_P_SEMAPHORE_TIMEDWAIT OpcUa_ProxyStub_g_PlatformLayerCalltable->SemaphoreTimedWait
# define OPCUA_P_SEMAPHORE_POST      OpcUa_ProxyStub_g_PlatformLayerCalltable->SemaphorePost
#else /* OPCUA_USE_SYNCHRONISATION */
# define OPCUA_P_SEMAPHORE_CREATE(a, b, c) OpcUa_Good;OpcUa_ReferenceParameter(a);OpcUa_ReferenceParameter(b);OpcUa_ReferenceParameter(c);
# define OPCUA_P_SEMAPHORE_DELETE(a) OpcUa_ReferenceParameter(a);
# define OPCUA_P_SEMAPHORE_WAIT(a) OpcUa_Good;OpcUa_ReferenceParameter(a);
# define OPCUA_P_SEMAPHORE_TIMEDWAIT(a, b) OpcUa_Good;OpcUa_ReferenceParameter(a);OpcUa_ReferenceParameter(b);
# define OPCUA_P_SEMAPHORE_POST(a, b) OpcUa_Good;OpcUa_ReferenceParameter(a);OpcUa_ReferenceParameter(b);
#endif /* OPCUA_USE_SYNCHRONISATION */
