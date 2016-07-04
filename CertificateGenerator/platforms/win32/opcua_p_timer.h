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

#ifndef _OpcUa_P_Timer_H_
#define _OpcUa_P_Timer_H_ 1

OPCUA_BEGIN_EXTERN_C

/*============================================================================
 * Defines
 *===========================================================================*/
/** @brief The maximum time between processing timers. */
#define OPCUA_P_TIMER_MAX_TIMER_WAIT 500

/** @brief The number of timers available to the system. */
#define OPCUA_P_TIMER_NO_OF_TIMERS    100

/*============================================================================
 * The Timer Type
 *===========================================================================*/
typedef struct _OpcUa_P_InternalTimer
{
    /** @brief  */
    OpcUa_Boolean           bUsed;
    /** @brief  */
    OpcUa_UInt32            msecInterval;
    /** @brief  */
    OpcUa_P_Timer_Callback* TimerCallback;
    /** @brief  */
    OpcUa_P_Timer_Callback* KillCallback;
    /** @brief  */
    OpcUa_Void*             CallbackData;
    /** @brief  */
    OpcUa_UInt32            uLastFired;
    /** @brief  */
    OpcUa_UInt32            uDueTime;

} OpcUa_P_InternalTimer;

/*============================================================================
 * Create A Timer
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_Timer_Create(    OpcUa_Timer*            phTimer,
                                                        OpcUa_UInt32            msecInterval,
                                                        OpcUa_P_Timer_Callback* fpTimerCallback,
                                                        OpcUa_P_Timer_Callback* fpKillCallback,
                                                        OpcUa_Void*             pvCallbackData);

/*============================================================================
 * Delete A Timer
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_Timer_Delete(    OpcUa_Timer*            phTimer);

/*============================================================================
 * Initialize the Timer System
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_InitializeTimers(void);

/*============================================================================
 * Cleanup the Timer System
 *===========================================================================*/
OpcUa_Void OPCUA_DLLCALL OpcUa_P_Timer_CleanupTimers(void);

#if !OPCUA_MULTITHREADED
/*============================================================================
 * Select wrapper used in singlethreaded configuration.
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Socket_TimeredSelect(          OpcUa_RawSocket         MaxFds,
                                                        OpcUa_P_Socket_Array*   pFdSetRead,
                                                        OpcUa_P_Socket_Array*   pFdSetWrite,
                                                        OpcUa_P_Socket_Array*   pFdSetException,
                                                        OpcUa_TimeVal*          pTimeout);
#endif /* OPCUA_MULTITHREADED */

OPCUA_END_EXTERN_C
#endif /* _OpcUa_P_Timer_H_ */
