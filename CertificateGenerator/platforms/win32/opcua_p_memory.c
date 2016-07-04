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
/******************************************************************************************************/

#include <windows.h>
#include <opcua.h>
#include <memory.h>
#include <errno.h>      /* for errornumbers when using save functions */
#include <opcua_p_memory.h>

/*============================================================================
 * OpcUa_Memory_Alloc
 *===========================================================================*/
OpcUa_Void* OPCUA_DLLCALL OpcUa_P_Memory_Alloc(OpcUa_UInt32 nSize)
{
    return malloc(nSize);
}

/*============================================================================
 * OpcUa_Memory_ReAlloc
 *===========================================================================*/
OpcUa_Void* OPCUA_DLLCALL OpcUa_P_Memory_ReAlloc(OpcUa_Void* pBuffer, OpcUa_UInt32 nSize)
{
    return realloc(pBuffer, nSize);
}

/*============================================================================
 * OpcUa_Memory_Free
 *===========================================================================*/
OpcUa_Void OPCUA_DLLCALL OpcUa_P_Memory_Free(OpcUa_Void* pBuffer)
{
    if(pBuffer != NULL)
    {
        free(pBuffer);
    }
}

/*============================================================================
 * OpcUa_Memory_MemCpy
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_Memory_MemCpy(
    OpcUa_Void*  pBuffer,
    OpcUa_UInt32 nSizeInBytes,
    OpcUa_Void*  pSource,
    OpcUa_UInt32 nCount)
{
#if _MSC_VER >= 1400
    errno_t result = 0;

    result = memcpy_s(pBuffer, nSizeInBytes, pSource, nCount);

    if(result == EINVAL)
    {
        return OpcUa_BadInvalidArgument;
    }

    if(result == ERANGE)
    {
        return OpcUa_BadOutOfRange;
    }

    return OpcUa_Good;
#else
    if(     pBuffer == OpcUa_Null
        ||  pSource == OpcUa_Null)
    {
        return OpcUa_BadInvalidArgument;
    }

    if(nSizeInBytes < nCount)
    {
        return OpcUa_BadOutOfRange;
    }

    if(memcpy(pBuffer, pSource, nCount) != pBuffer)
    {
        return OpcUa_BadInvalidArgument;
    }

    return OpcUa_Good;
#endif
}
