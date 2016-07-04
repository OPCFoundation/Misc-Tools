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
/******************************************************************************************************/

/* System Headers */
#include <windows.h>
#include <stdlib.h>

/* UA platform definitions */
#include <opcua_p_internal.h>
#include <opcua_p_memory.h>

/* own headers */
#include <opcua_p_utilities.h>

#ifdef _MSC_VER
#pragma warning(disable:4748) /* suppress /GS can not protect parameters and local variables from local buffer overrun because optimizations are disabled in function */
#endif /* _MSC_VER */

/* maximum number of characters per port including \0 */
#define MAX_PORT_LENGTH 16

/*============================================================================
 * Quick Sort
 *===========================================================================*/
OpcUa_Void OPCUA_DLLCALL OpcUa_P_QSort( OpcUa_Void*       pElements,
                                        OpcUa_UInt32      nElementCount,
                                        OpcUa_UInt32      nElementSize,
                                        OpcUa_PfnCompare* pfnCompare,
                                        OpcUa_Void*       pContext)
{
    /*qsort_s(pElements, nElementCount, nElementSize, pfnCompare, pContext);*/
    OpcUa_ReferenceParameter(pContext);
    qsort(pElements, nElementCount, nElementSize, pfnCompare);
}

/*============================================================================
 * Binary Search on sorted array
 *===========================================================================*/
OpcUa_Void* OPCUA_DLLCALL OpcUa_P_BSearch(  OpcUa_Void*       pKey,
                                            OpcUa_Void*       pElements,
                                            OpcUa_UInt32      nElementCount,
                                            OpcUa_UInt32      nElementSize,
                                            OpcUa_PfnCompare* pfnCompare,
                                            OpcUa_Void*       pContext)
{
    /*return bsearch_s(pKey, pElements, nElementCount, nElementSize, pfnCompare, pContext);*/
    OpcUa_ReferenceParameter(pContext);
    return bsearch(pKey, pElements, nElementCount, nElementSize, pfnCompare);
}

/*============================================================================
 * Access to errno
 *===========================================================================*/
OpcUa_UInt32 OPCUA_DLLCALL OpcUa_P_GetLastError()
{
    return errno;
}

/*============================================================================
 * OpcUa_GetTickCount
 *===========================================================================*/
OpcUa_UInt32 OPCUA_DLLCALL OpcUa_P_GetTickCount()
{
    return GetTickCount();
}

/*============================================================================
 * OpcUa_CharAToInt
 *===========================================================================*/
OpcUa_Int32 OPCUA_DLLCALL OpcUa_P_CharAToInt(OpcUa_StringA sValue)
{
    return (OpcUa_Int32)atoi(sValue);
}

/*============================================================================
 * OpcUa_P_ParseUrl
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_ParseUrl(  OpcUa_StringA   a_psUrl,
                                    OpcUa_StringA*  a_psIpAdress,
                                    OpcUa_UInt16*   a_puPort)
{
    OpcUa_UInt32    uUrlLength        = 0;

    OpcUa_StringA   sHostName         = OpcUa_Null;
    OpcUa_UInt32    uHostNameLength   = 0;

    OpcUa_CharA*    pcCursor          = OpcUa_Null;

    OpcUa_Int       nIndex1           = 0;
    OpcUa_Int       nIpStart          = 0;

    struct hostent* pHostEnt          = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Utilities, "P_ParseUrl");

    OpcUa_ReturnErrorIfArgumentNull(a_psUrl);
    OpcUa_ReturnErrorIfArgumentNull(a_psIpAdress);
    OpcUa_ReturnErrorIfArgumentNull(a_puPort);

    *a_psIpAdress = OpcUa_Null;

    uUrlLength = (OpcUa_UInt32)strlen(a_psUrl);

    /* check for // (end of protocol header) */
    pcCursor = strstr(a_psUrl, "//");

    if(pcCursor != OpcUa_Null)
    {
        /* begin of host address */
        pcCursor += 2;
        nIndex1 = (OpcUa_Int)(pcCursor - a_psUrl);
    }
    else
    {
        uStatus = OpcUa_BadSyntaxError;
        OpcUa_ReturnStatusCode;
    }

    /* skip protocol prefix and store beginning of ip adress */
    nIpStart = nIndex1;

    /* skip host address */
    while(      a_psUrl[nIndex1] != ':'
            &&  a_psUrl[nIndex1] != '/'
            &&  a_psUrl[nIndex1] != 0
            &&  nIndex1          <  (OpcUa_Int32)uUrlLength)
    {
        nIndex1++;
    }

    uHostNameLength = nIndex1 - nIpStart;
    sHostName       = (OpcUa_StringA)malloc(uHostNameLength + 1);
    if(sHostName == NULL)
    {
        return OpcUa_BadOutOfMemory;
    }

    memcpy(sHostName, &a_psUrl[nIpStart], uHostNameLength);
    sHostName[uHostNameLength] = '\0';

    pHostEnt = gethostbyname(sHostName);

    free(sHostName);

    if(pHostEnt == NULL)
    {
        /* hostname could not be resolved */
        return OpcUa_BadHostUnknown;
    }

    nIpStart = 0;
    *a_psIpAdress = (OpcUa_StringA)OpcUa_P_Memory_Alloc(16);
    memset(*a_psIpAdress, 0, 16);

#if OPCUA_USE_SAFE_FUNCTIONS
    nIpStart += sprintf_s(&(*a_psIpAdress)[0],         16,"%u", (unsigned char)(*((*pHostEnt).h_addr_list))[0]);
    (*a_psIpAdress)[nIpStart++] = '.';
    nIpStart += sprintf_s(&(*a_psIpAdress)[nIpStart],  12,"%u", (unsigned char)(*((*pHostEnt).h_addr_list))[1]);
    (*a_psIpAdress)[nIpStart++] = '.';
    nIpStart += sprintf_s(&(*a_psIpAdress)[nIpStart],   8,"%u", (unsigned char)(*((*pHostEnt).h_addr_list))[2]);
    (*a_psIpAdress)[nIpStart++] = '.';
    nIpStart += sprintf_s(&(*a_psIpAdress)[nIpStart],   4,"%u", (unsigned char)(*((*pHostEnt).h_addr_list))[3]);
#else /* OPCUA_USE_SAFE_FUNCTIONS */

    nIpStart += sprintf(&(*a_psIpAdress)[0], "%u", (unsigned char)(*((*pHostEnt).h_addr_list))[0]);
    (*a_psIpAdress)[nIpStart++] = '.';
    nIpStart += sprintf(&(*a_psIpAdress)[nIpStart], "%u", (unsigned char)(*((*pHostEnt).h_addr_list))[1]);
    (*a_psIpAdress)[nIpStart++] = '.';
    nIpStart += sprintf(&(*a_psIpAdress)[nIpStart], "%u", (unsigned char)(*((*pHostEnt).h_addr_list))[2]);
    (*a_psIpAdress)[nIpStart++] = '.';
    nIpStart += sprintf(&(*a_psIpAdress)[nIpStart], "%u", (unsigned char)(*((*pHostEnt).h_addr_list))[3]);
#endif /* OPCUA_USE_SAFE_FUNCTIONS */

    /* scan port */
    if(a_psUrl[nIndex1] == ':')
    {
        OpcUa_Int       nIndex2 = 0;
        OpcUa_CharA*    sPort   = OpcUa_Null;
        OpcUa_CharA sBuffer[MAX_PORT_LENGTH];

        /* skip delimiter */
        nIndex1++;

        /* store beginning of port */
        sPort = &a_psUrl[nIndex1];

        /* search for end of port */
        while(      a_psUrl[nIndex1] != '/'
                &&  a_psUrl[nIndex1] != 0
                &&  nIndex2          <  6)
        {
            nIndex1++;
            nIndex2++;
        }

        /* convert port */
        OpcUa_P_Memory_MemCpy(sBuffer, MAX_PORT_LENGTH-1, sPort, nIndex2);
        sBuffer[nIndex2] = 0;
        *a_puPort = (OpcUa_UInt16)OpcUa_P_CharAToInt(sBuffer);
    }
    else
    {
        /* return default port */
        if (strncmp(a_psUrl, "http:", 5) != 0)
        {
            *a_puPort = OPCUA_TCP_DEFAULT_PORT;
        }
        else
        {
            *a_puPort = OPCUA_HTTP_DEFAULT_PORT;
        }
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}
