/* ========================================================================
 * Copyright (c) 2005-2011 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Reciprocal Community License ("RCL") Version 1.00
 *
 * Unless explicitly acquired and licensed from Licensor under another
 * license, the contents of this file are subject to the Reciprocal
 * Community License ("RCL") Version 1.00, or subsequent versions as
 * allowed by the RCL, and You may not copy or use this file in either
 * source code or executable form, except in compliance with the terms and
 * conditions of the RCL.
 *
 * All software distributed under the RCL is provided strictly on an
 * "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED,
 * AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT
 * LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RCL for specific
 * language governing rights and limitations under the RCL.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/RCL/1.00/
 * ======================================================================*/

#include <opcua.h>
#include <opcua_enumeratedtype.h>

/*============================================================================
 * OpcUa_EnumeratedType_FindName
 *===========================================================================*/
OpcUa_StatusCode OpcUa_EnumeratedType_FindName(
    OpcUa_EnumeratedType* a_pType,
    OpcUa_Int32           a_nValue,
    OpcUa_StringA*        a_pName)
{
    OpcUa_UInt32 ii = 0;

    OpcUa_InitializeStatus(OpcUa_Module_Serializer, "EnumeratedType_FindName");

    OpcUa_ReturnErrorIfArgumentNull(a_pType);
    OpcUa_ReturnErrorIfArgumentNull(a_pName);

    *a_pName = OpcUa_Null;

    for (ii = 0; a_pType->Values[ii].Name != OpcUa_Null; ii++)
    {
        if (a_pType->Values[ii].Value == a_nValue)
        {
            *a_pName = a_pType->Values[ii].Name;
            break;
        }
    }

    OpcUa_GotoErrorIfTrue(a_pType->Values[ii].Name == OpcUa_Null, OpcUa_BadInvalidArgument);

    OpcUa_ReturnStatusCode;
    OpcUa_BeginErrorHandling;

    /* nothing to do */

    OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_EnumeratedType_FindValue
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_EnumeratedType_FindValue(
    OpcUa_EnumeratedType* a_pType,
    OpcUa_StringA         a_sName,
    OpcUa_Int32*          a_pValue)
{
    OpcUa_UInt32 ii = 0;

    OpcUa_InitializeStatus(OpcUa_Module_Serializer, "EnumeratedType_FindValue");

    OpcUa_ReturnErrorIfArgumentNull(a_pType);
    OpcUa_ReturnErrorIfArgumentNull(a_sName);
    OpcUa_ReturnErrorIfArgumentNull(a_pValue);

    *a_pValue = 0;

    for (ii = 0; a_pType->Values[ii].Name != OpcUa_Null; ii++)
    {
        if (OpcUa_StrCmpA(a_pType->Values[ii].Name, a_sName) == 0)
        {
            *a_pValue = a_pType->Values[ii].Value;
            break;
        }
    }

    OpcUa_GotoErrorIfTrue(a_pType->Values[ii].Name == OpcUa_Null, OpcUa_BadInvalidArgument);

    OpcUa_ReturnStatusCode;
    OpcUa_BeginErrorHandling;

    /* nothing to do */

    OpcUa_FinishErrorHandling;
}
