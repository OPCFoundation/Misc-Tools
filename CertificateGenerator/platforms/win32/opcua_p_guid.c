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
/* Modify the content of this file according to the guid implementation on your system or emulate     */
/* the uuid generation process in this file.                                                          */
/******************************************************************************************************/

/* System Headers */
#include <windows.h>
#include <time.h>

/* UA platform definitions */
#include <opcua_p_internal.h>

/* own headers */
#include <opcua_guid.h>
#include <opcua_p_guid.h>
/*============================================================================
 * CreateGuid
 *===========================================================================*/
/**
* CreateGuid generates a global unique identifier. It calls the
* Win32 API function for doing this.
*/
OpcUa_Guid* OPCUA_DLLCALL OpcUa_P_Guid_Create(OpcUa_Guid* Guid)
{
#ifndef _GUID_CREATE_NOT_AVAILABLE
    if(UuidCreate((UUID*)Guid) != RPC_S_OK)
    {
        /* Error */
        Guid = OpcUa_Null;
        return OpcUa_Null;
    }

    /* Good */
    return Guid;
#else
    unsigned int *data = (unsigned int*)Guid;
    int chunks = 16 / sizeof(unsigned int);
    static const int intbits = sizeof(int)*8;
    static int randbits = 0;
    if (!randbits)
    {
        int max = RAND_MAX;
        do { ++randbits; } while ((max=max>>1));

        srand(_time32(NULL));

        rand(); /* Skip first */
    }

    while (chunks--)
    {
        unsigned int randNumber = 0;
        int filled;
        for (filled = 0; filled < intbits; filled += randbits)
            randNumber |= rand()<<filled;
         *(data+chunks) = randNumber;
    }

    Guid->Data4[0] = (Guid->Data4[0] & 0x3F) | 0x80; /* UV_DCE */
    Guid->Data3 = (Guid->Data3 & 0x0FFF) | 0x4000;   /* UV_Random */

    return Guid;
#endif
}
