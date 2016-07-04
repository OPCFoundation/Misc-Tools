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
/* P-Layer internal helper functions.                                                                 */
/******************************************************************************************************/

#ifdef _MSC_VER
/* Disables warning for non secure functions in visual studio 2005. Debug only! */
#pragma warning (disable:4996)
#endif /* _MSC_VER */

/* System Headers */
#include <windows.h>
#include <stdlib.h>

/* UA platform definitions */
#include <opcua_p_internal.h>
#include <opcua_p_memory.h>


extern OpcUa_StringA OpcUa_P_g_VersionString;
extern OpcUa_Boolean OpcUa_P_g_FreeVersionString;

/*============================================================================
 * Calculate DateTime Difference
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_GetDateTimeDiff( OpcUa_DateTime  a_Value1,
                                                        OpcUa_DateTime  a_Value2,
                                                        OpcUa_DateTime* a_pResult)
{
    UINT64 ullValue1 = 0;
    UINT64 ullValue2 = 0;
    UINT64 ullResult = 0;

    OpcUa_ReturnErrorIfArgumentNull(a_pResult);

    a_pResult->dwLowDateTime = (OpcUa_UInt32)0;
    a_pResult->dwHighDateTime = (OpcUa_UInt32)0;

    ullValue1 = a_Value1.dwHighDateTime;
    ullValue1 = (ullValue1 << 32) + a_Value1.dwLowDateTime;

    ullValue2 = a_Value2.dwHighDateTime;
    ullValue2 = (ullValue2 << 32) + a_Value2.dwLowDateTime;

    if(ullValue1 > ullValue2)
    {
        return OpcUa_BadInvalidArgument;
    }

    ullResult = ullValue2 - ullValue1;

    a_pResult->dwLowDateTime = (OpcUa_UInt32)(ullResult & 0x00000000FFFFFFFF);
    a_pResult->dwHighDateTime = (OpcUa_UInt32)((ullResult & 0xFFFFFFFF00000000ll) >> 32);

    return OpcUa_Good;
}

/*============================================================================
 * Calculate DateTime Difference In Seconds (Rounded)
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_GetDateTimeDiffInSeconds32(  OpcUa_DateTime  a_Value1,
                                                                    OpcUa_DateTime  a_Value2,
                                                                    OpcUa_UInt32*   a_puResult)
{
    UINT64 ullValue1 = 0;
    UINT64 ullValue2 = 0;
    UINT64 ullResult = 0;

    OpcUa_ReturnErrorIfArgumentNull(a_puResult);

    *a_puResult = (OpcUa_UInt32)0;

    ullValue1 = a_Value1.dwHighDateTime;
    ullValue1 = (ullValue1 << 32) + a_Value1.dwLowDateTime;

    ullValue2 = a_Value2.dwHighDateTime;
    ullValue2 = (ullValue2 << 32) + a_Value2.dwLowDateTime;

    if(ullValue1 > ullValue2)
	{
		ullResult = (UINT64)((ullValue1 - ullValue2 + 5000000) / 10000000);
    }
	else
	{
		ullResult = (UINT64)((ullValue2 - ullValue1 + 5000000) / 10000000);
	}

    if(ullResult > (UINT64)OpcUa_UInt32_Max)
    {
        return OpcUa_BadOutOfRange;
    }

    *a_puResult = (OpcUa_UInt32)(ullResult & 0x00000000FFFFFFFF);

    return OpcUa_Good;
}

/*============================================================================
 * Update Version String
 *===========================================================================*/
OpcUa_Void OpcUa_P_VersionStringAppend( const OpcUa_CharA* a_strVersionType,
                                        const OpcUa_CharA* a_strVersionInfo)
{
    OpcUa_StringA   strNew      = OpcUa_Null;
    OpcUa_UInt32    uiLenNew    = 0;

    if(a_strVersionInfo == OpcUa_Null)
    {
        return;
    }

    uiLenNew =  OpcUa_StrLenA(OPCUA_P_VERSIONSTRING_SEPARATOR);
    uiLenNew += OpcUa_StrLenA(OpcUa_P_g_VersionString) + OpcUa_StrLenA(a_strVersionInfo) + 1;

    if(a_strVersionType != OpcUa_Null)
    {
        uiLenNew += OpcUa_StrLenA(a_strVersionType);
    }

    strNew = (OpcUa_StringA)OpcUa_P_Memory_Alloc(uiLenNew);

    if(strNew == OpcUa_Null)
    {
        return;
    }

    OpcUa_MemSet(strNew, 0, uiLenNew);

    strcat(strNew, OpcUa_P_g_VersionString);
    strcat(strNew, OPCUA_P_VERSIONSTRING_SEPARATOR);

    if(a_strVersionType != OpcUa_Null)
    {
        strcat(strNew, a_strVersionType);
    }

    strcat(strNew, a_strVersionInfo);

    if(OpcUa_P_g_FreeVersionString != OpcUa_False)
    {
        OpcUa_P_Memory_Free(OpcUa_P_g_VersionString);
    }

    OpcUa_P_g_VersionString     = strNew;
    OpcUa_P_g_FreeVersionString = OpcUa_True;

    return;
}
