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
#include <opcua_list.h>
#include <opcua_utilities.h>

#include <opcua_timer.h>

/*============================================================================
 * Delete A Timer
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_Timer_Delete(OpcUa_Timer* a_phTimer)
{
    return OPCUA_P_TIMER_DELETE(a_phTimer);
}


/*============================================================================
 * Create A Timer
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_Timer_Create(  OpcUa_Timer*            a_phTimer,
                                                    OpcUa_UInt32            a_msecInterval,
                                                    OpcUa_Timer_Callback*   a_fpTimerCallback,
                                                    OpcUa_Timer_Callback*   a_fpKillCallback,
                                                    OpcUa_Void*             a_pvCallbackData)
{
    return OPCUA_P_TIMER_CREATE(    a_phTimer,
                                    a_msecInterval,
                                    a_fpTimerCallback,
                                    a_fpKillCallback,
                                    a_pvCallbackData);
}
