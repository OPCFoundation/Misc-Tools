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
/* Modify the content of this file according to the timer implementation on your system.              */
/******************************************************************************************************/

#include <opcua_p_internal.h>
#include <opcua_p_memory.h>
#include <opcua_p_mutex.h>

#include <opcua_p_thread.h>
#include <opcua_p_semaphore.h>

#include <opcua_p_socket.h>
#include <opcua_p_utilities.h>
#include <opcua_p_timer.h>

/*============================================================================
 * Global Variables
 *===========================================================================*/
/* The timer list. */
OpcUa_P_InternalTimer   g_OpcUa_P_Timer_Timers[OPCUA_P_TIMER_NO_OF_TIMERS];

#if OPCUA_USE_SYNCHRONISATION
/* Synchronize access to the timer list. */
OpcUa_Mutex             g_OpcUa_P_Timer_pTimers_Mutex   = OpcUa_Null;
#endif /* OPCUA_USE_SYNCHRONISATION */

#if OPCUA_MULTITHREADED
/* In MT config, the timer is realized by a thread. */
OpcUa_RawThread         g_pTimerThread                  = OpcUa_Null;
OpcUa_Semaphore         g_hTimerThreadSemaphore         = OpcUa_Null;
OpcUa_UInt32            g_uActiveTimerCount             = 0;
OpcUa_Semaphore         g_hTimerAddedSemaphore          = OpcUa_Null;
OpcUa_Boolean           g_bStopTimerThread              = OpcUa_False;

OpcUa_Void OpcUa_P_Timer_Thread(OpcUa_Void* pArguments);
#endif /* OPCUA_MULTITHREADED */

/*============================================================================
 * Fire and recalculate timers.
 *===========================================================================*/
OpcUa_UInt32 OpcUa_P_Timer_ProcessTimers(OpcUa_Void)
{
    OpcUa_UInt16            uIndex          = 0;
    OpcUa_P_InternalTimer*  pInternalTimer  = OpcUa_Null;
    OpcUa_UInt32            uNow            = 0;
    OpcUa_UInt32            uProStart       = OpcUa_P_GetTickCount();
    OpcUa_UInt32            uElapsed        = 0;
    OpcUa_UInt32            uNearest        = 0;

#if OPCUA_USE_SYNCHRONISATION
    OpcUa_P_Mutex_Lock(g_OpcUa_P_Timer_pTimers_Mutex);
#endif /* OPCUA_USE_SYNCHRONISATION */

    for(uIndex = 0; uIndex < OPCUA_P_TIMER_NO_OF_TIMERS; uIndex++)
    {
        if(g_OpcUa_P_Timer_Timers[uIndex].bUsed != OpcUa_False)
        {
            pInternalTimer  = &g_OpcUa_P_Timer_Timers[uIndex];
            uNow            = OpcUa_P_GetTickCount();

            /* check for overflow of GetTickCount/uNow */
            if(uNow < pInternalTimer->uLastFired)
            {
                /* overflow */
                uElapsed = uNow + (OpcUa_UInt32_Max - pInternalTimer->uLastFired);
            }
            else
            {
                /* no overflow */
                uElapsed = uNow - pInternalTimer->uLastFired;
            }

            if(uElapsed >= pInternalTimer->msecInterval)
            {
                /* Fire Timer */
                pInternalTimer->uLastFired  = uNow;

                if(pInternalTimer->TimerCallback != OpcUa_Null)
                {
                    pInternalTimer->TimerCallback(  pInternalTimer->CallbackData,
                                                    pInternalTimer,
                                                    uElapsed);
                }

                /* update duetime */
                pInternalTimer->uDueTime = pInternalTimer->uLastFired + pInternalTimer->msecInterval;
            }

            /* calculate time to next fire event for the current timer */
            /* HINT: use uElapsed as helper only! */
            if(pInternalTimer->uDueTime < uProStart)
            {
                /* overflow */
                uElapsed = pInternalTimer->uDueTime + (OpcUa_UInt32_Max - uProStart);
            }
            else
            {
                /* no overflow */
                uElapsed = pInternalTimer->uDueTime - uProStart;
            }

            /* get the minimum */
            if((uElapsed < uNearest) || (uNearest == 0))
            {
                uNearest = uElapsed;
            }
        } /* if(g_OpcUa_P_Timer_Timers[uIndex].bUsed != OpcUa_False) */
    } /* for(uIndex = 0; uIndex < OPCUA_P_TIMER_NO_OF_TIMERS; uIndex++) */

#if OPCUA_USE_SYNCHRONISATION
    OpcUa_P_Mutex_Unlock(g_OpcUa_P_Timer_pTimers_Mutex);
#endif /* OPCUA_USE_SYNCHRONISATION */

    /* cap time to next fire event to max wait */
    if(uNearest > OPCUA_TIMER_MAX_WAIT)
    {
        uNearest = OPCUA_TIMER_MAX_WAIT;
    }

    return uNearest;
}


/*============================================================================
 * Initialize the Timer System
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_InitializeTimers(OpcUa_Void)
{
#if OPCUA_USE_SYNCHRONISATION
    OpcUa_StatusCode uStatus = OpcUa_Good;
    uStatus = OpcUa_P_Mutex_Create(&g_OpcUa_P_Timer_pTimers_Mutex);
    OpcUa_ReturnErrorIfBad(uStatus);
#endif /* OPCUA_USE_SYNCHRONISATION */

#if OPCUA_MULTITHREADED
    uStatus = OpcUa_P_Semaphore_Create( &g_hTimerThreadSemaphore,
                                        0,  /* not signalled */
                                        1); /* max 1 post */
    OpcUa_ReturnErrorIfBad(uStatus);

    uStatus = OpcUa_P_Semaphore_Create( &g_hTimerAddedSemaphore,
                                        0,  /* not signalled */
                                        1); /* max 1 post */
    OpcUa_ReturnErrorIfBad(uStatus);

    g_bStopTimerThread = OpcUa_False;

    uStatus = OpcUa_P_Thread_Create(&g_pTimerThread);
    OpcUa_ReturnErrorIfBad(uStatus);

    uStatus = OpcUa_P_Thread_Start( g_pTimerThread,
                                    OpcUa_P_Timer_Thread,
                                    OpcUa_Null);
    OpcUa_ReturnErrorIfBad(uStatus);
#endif /* OPCUA_MULTITHREADED */

    return OpcUa_Good;
}

/*============================================================================
 * Cleanup the Timer System
 *===========================================================================*/
OpcUa_Void OPCUA_DLLCALL OpcUa_P_Timer_CleanupTimers(OpcUa_Void)
{
    OpcUa_UInt32 uIndex = 0;

#if OPCUA_MULTITHREADED
    /* signal thread to stop */
    g_bStopTimerThread = OpcUa_True;
    OpcUa_P_Semaphore_Post(g_hTimerAddedSemaphore, 1);
    OpcUa_P_Semaphore_Wait(g_hTimerThreadSemaphore);

    OpcUa_P_Thread_Delete(&g_pTimerThread);
#endif /* OPCUA_MULTITHREADED */

#if OPCUA_USE_SYNCHRONISATION
    OpcUa_P_Mutex_Delete(&g_OpcUa_P_Timer_pTimers_Mutex);
#endif /* OPCUA_USE_SYNCHRONISATION */

    /* no other thread should access this list by now! */
    for(uIndex = 0; uIndex < OPCUA_P_TIMER_NO_OF_TIMERS; uIndex++)
    {
        if(g_OpcUa_P_Timer_Timers[uIndex].bUsed != OpcUa_False)
        {
            /* we should have a clear for this ... */
            OpcUa_P_InternalTimer* pInternalTimer = &g_OpcUa_P_Timer_Timers[uIndex];
            OpcUa_P_Timer_Delete((OpcUa_Timer*)&pInternalTimer);
        }
    }

#if OPCUA_MULTITHREADED
    OpcUa_P_Semaphore_Delete(&g_hTimerAddedSemaphore);
    OpcUa_P_Semaphore_Delete(&g_hTimerThreadSemaphore);
#endif /* OPCUA_MULTITHREADED */

    return;
}

/*============================================================================
 * Initialize A Timer
 *===========================================================================*/
static OpcUa_StatusCode OpcUa_P_Timer_Initialize(   OpcUa_P_InternalTimer*  a_pInternalTimer,
                                                    OpcUa_UInt32            a_msecInterval,
                                                    OpcUa_P_Timer_Callback* a_fpTimerCallback,
                                                    OpcUa_P_Timer_Callback* a_fpKillCallback,
                                                    OpcUa_Void*             a_pvCallbackData)
{
    OpcUa_ReturnErrorIfArgumentNull(a_pInternalTimer);
    OpcUa_ReturnErrorIfTrue((a_msecInterval == 0), OpcUa_BadInvalidArgument);

    a_pInternalTimer->bUsed         = OpcUa_False;
    a_pInternalTimer->CallbackData  = a_pvCallbackData;
    a_pInternalTimer->KillCallback  = a_fpKillCallback;
    a_pInternalTimer->TimerCallback = a_fpTimerCallback;
    a_pInternalTimer->msecInterval  = a_msecInterval;
    a_pInternalTimer->uLastFired    = OpcUa_P_GetTickCount();
    a_pInternalTimer->uDueTime      = a_pInternalTimer->uLastFired + a_msecInterval;

    return OpcUa_Good;
}

#if OPCUA_MULTITHREADED
/*============================================================================
 * The thread watching and triggering the timer events.
 *===========================================================================*/
OpcUa_Void OpcUa_P_Timer_Thread(OpcUa_Void* a_pvArguments)
{
    OpcUa_UInt32            uTimeout        = 0;

    OpcUa_ReferenceParameter(a_pvArguments);

    while(g_bStopTimerThread == OpcUa_False)
    {
        uTimeout = OpcUa_P_Timer_ProcessTimers();

        if(uTimeout == 0)
        {
            /* no timer exists - wait for add-event */
            OpcUa_P_Semaphore_Wait(g_hTimerAddedSemaphore);
        }
        else
        {
            /* wait for timeout */
            OpcUa_P_Thread_Sleep(uTimeout);
        }
    }

    /* emit thread finished signal */
    OpcUa_P_Semaphore_Post(g_hTimerThreadSemaphore, 1);

    return;
}

#else /* OPCUA_MULTITHREADED */
/*============================================================================
 * Timeout expired callback function
 *===========================================================================*/

OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_SocketTimerCallback( OpcUa_Void*     pData,
                                                            OpcUa_Timer*    pTimer,
                                                            OpcUa_UInt32    msecElapsed)
{
    OpcUa_ReferenceParameter(pData);
    OpcUa_ReferenceParameter(pTimer);
    OpcUa_ReferenceParameter(msecElapsed);

    return(OpcUa_Good);
}

/*============================================================================
 * Timeout deleted callback function
 *===========================================================================*/

OpcUa_StatusCode OPCUA_DLLCALL  OpcUa_P_SocketKillTimerCallback(OpcUa_Void*     pData,
                                                                OpcUa_Timer*    pTimer,
                                                                OpcUa_UInt32    msecElapsed)
{
    OpcUa_ReferenceParameter(pData);
    OpcUa_ReferenceParameter(pTimer);
    OpcUa_ReferenceParameter(msecElapsed);

    return(OpcUa_Good);
}

/*============================================================================
 * Select wrapper used in singlethreaded configuration.
 *===========================================================================*/
/* Standard select wrapper, which uses timers instead of timeout. */
OpcUa_StatusCode OpcUa_P_Socket_TimeredSelect(  OpcUa_RawSocket         a_MaxFds,
                                                OpcUa_P_Socket_Array*   a_pFdSetRead,
                                                OpcUa_P_Socket_Array*   a_pFdSetWrite,
                                                OpcUa_P_Socket_Array*   a_pFdSetException,
                                                OpcUa_TimeVal*          a_pTimeout)
{
    OpcUa_UInt32        uTimeout    = 0;
    OpcUa_UInt32        uNearest    = 0;
    OpcUa_Timer         pTimer      = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Socket, "P_Select");

    OpcUa_GotoErrorIfArgumentNull(a_pFdSetException);

    /* map given timeval to UInt32 */
    uTimeout = a_pTimeout->uintMicroSeconds / 1000;
    uTimeout = uTimeout + (a_pTimeout->uintSeconds * 1000);

    /* Set a timer as timeout for the following select. */
    uStatus = OpcUa_P_Timer_Create( &pTimer,
                                    uTimeout,
                                    OpcUa_P_SocketTimerCallback,    /* ignores event; just for debug */
                                    OpcUa_P_SocketKillTimerCallback,/* ignores event; just for debug */
                                    OpcUa_Null);

    if(pTimer == OpcUa_Null)
    {
        uStatus = OpcUa_BadOutOfMemory;
    }
    else
    {
        uNearest = OpcUa_P_Timer_ProcessTimers();

        /* map nearest timeout to TimeVal */
        a_pTimeout->uintSeconds      = uNearest / 1000;
        a_pTimeout->uintMicroSeconds = ((uNearest % 1000) * 1000);

        uStatus = OpcUa_P_RawSocket_Select( a_MaxFds,
                                            a_pFdSetRead,
                                            a_pFdSetWrite,
                                            a_pFdSetException,
                                            a_pTimeout);

        /* Kill the timer used for the last timeout. */
        OpcUa_P_Timer_Delete(&pTimer);
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}
#endif /* OPCUA_MULTITHREADED */

/*============================================================================
 * Create A Timer
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_Timer_Create(    OpcUa_Timer*            a_phTimer,
                                                        OpcUa_UInt32            a_msecInterval,
                                                        OpcUa_P_Timer_Callback* a_fpTimerCallback,
                                                        OpcUa_P_Timer_Callback* a_fpKillCallback,
                                                        OpcUa_Void*             a_pvCallbackData)
{
    OpcUa_P_InternalTimer*  pInternalTimer   = OpcUa_Null;
    OpcUa_StatusCode        uStatus          = OpcUa_Good;
    OpcUa_UInt16            uIndex           = 0;

    if(a_phTimer == OpcUa_Null)
    {
        return OpcUa_BadInvalidArgument;
    }

    *a_phTimer = OpcUa_Null;

#if OPCUA_USE_SYNCHRONISATION
    OpcUa_P_Mutex_Lock(g_OpcUa_P_Timer_pTimers_Mutex);
#endif /* OPCUA_USE_SYNCHRONISATION */

    /* look for free timer slot */
    for(uIndex = 0; uIndex < OPCUA_P_TIMER_NO_OF_TIMERS; uIndex++)
    {
        if(g_OpcUa_P_Timer_Timers[uIndex].bUsed == OpcUa_False)
        {
            pInternalTimer = &g_OpcUa_P_Timer_Timers[uIndex];
            pInternalTimer->bUsed = OpcUa_True;
            break;
        }
    }

    if(pInternalTimer == OpcUa_Null)
    {
#if OPCUA_USE_SYNCHRONISATION
        OpcUa_P_Mutex_Unlock(g_OpcUa_P_Timer_pTimers_Mutex);
#endif /* OPCUA_USE_SYNCHRONISATION */
        return OpcUa_BadResourceUnavailable;
    }

    uStatus = OpcUa_P_Timer_Initialize( pInternalTimer,
                                        a_msecInterval,
                                        a_fpTimerCallback,
                                        a_fpKillCallback,
                                        a_pvCallbackData);

    if(OpcUa_IsBad(uStatus))
    {
        pInternalTimer->bUsed = OpcUa_False;

#if OPCUA_USE_SYNCHRONISATION
        OpcUa_P_Mutex_Unlock(g_OpcUa_P_Timer_pTimers_Mutex);
#endif /* OPCUA_USE_SYNCHRONISATION */

        return uStatus;
    }

    pInternalTimer->bUsed = OpcUa_True;

#if OPCUA_MULTITHREADED
    /* increase timer count and trigger event if first timer entry. */
    if(g_uActiveTimerCount == 0)
    {
        OpcUa_P_Semaphore_Post(g_hTimerAddedSemaphore, 1);
    }

    ++g_uActiveTimerCount;
#endif /* OPCUA_MULTITHREADED */

    *a_phTimer = pInternalTimer;

#if OPCUA_USE_SYNCHRONISATION
    OpcUa_P_Mutex_Unlock(g_OpcUa_P_Timer_pTimers_Mutex);
#endif /* OPCUA_USE_SYNCHRONISATION */

    return OpcUa_Good;
}

/*============================================================================
 * Delete A Timer
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_Timer_Delete(OpcUa_Timer* a_phTimer)
{
    OpcUa_P_InternalTimer*  pInternalTimer  = OpcUa_Null;
    OpcUa_UInt32            uNow            = 0;
    OpcUa_UInt32            uElapsed        = 0;
    OpcUa_UInt16            uIndex          = 0;

    OpcUa_ReturnErrorIfArgumentNull(a_phTimer);
    OpcUa_ReturnErrorIfArgumentNull(*a_phTimer);

    pInternalTimer = (OpcUa_P_InternalTimer*)*a_phTimer;
    if(pInternalTimer->bUsed == OpcUa_False)
    {
        return OpcUa_BadInvalidArgument;
    }

    uNow     = OpcUa_P_GetTickCount();
    uElapsed = uNow - pInternalTimer->uLastFired;

#if OPCUA_USE_SYNCHRONISATION
    OpcUa_P_Mutex_Lock(g_OpcUa_P_Timer_pTimers_Mutex);
#endif /* OPCUA_USE_SYNCHRONISATION */

    /* notify about kill */
    if(pInternalTimer->KillCallback != OpcUa_Null)
    {
        pInternalTimer->KillCallback(   pInternalTimer->CallbackData,
                                        pInternalTimer,
                                        uElapsed);
    }

    /* look for matching timer slot and free it */
    for(uIndex = 0; uIndex < OPCUA_P_TIMER_NO_OF_TIMERS; uIndex++)
    {
        if(&g_OpcUa_P_Timer_Timers[uIndex] == pInternalTimer)
        {
            g_OpcUa_P_Timer_Timers[uIndex].bUsed = OpcUa_False;
#if OPCUA_MULTITHREADED
            g_uActiveTimerCount--;
#endif /* OPCUA_MULTITHREADED */
            break;
        }
    }

#if OPCUA_USE_SYNCHRONISATION
    OpcUa_P_Mutex_Unlock(g_OpcUa_P_Timer_pTimers_Mutex);
#endif /* OPCUA_USE_SYNCHRONISATION */

    *a_phTimer = OpcUa_Null;

    return OpcUa_Good;
}
