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

#ifdef _MSC_VER
/* Disables warning for non secure functions in visual studio 2005. Debug only! */
#pragma warning(disable:4996) /* safe_functions */
#endif /* _MSC_VER */

/* System Headers */
#include <windows.h>
#include <stdio.h>

/* UA platform definitions */
#include <opcua_p_internal.h>

/* additional UA dependencies */
#include <opcua_p_mutex.h>
#include <opcua_p_thread.h>

#if OPCUA_P_TRACE_ENABLE_TIME
  #include <opcua_p_datetime.h>
#endif /* OPCUA_P_TRACE_ENABLE_TIME */

/* own headers */
#include <opcua_p_trace.h>

OPCUA_EXPORT OpcUa_P_TraceHook g_OpcUa_P_TraceHook;

#define OpcUa_Rename  rename
// _MSC_VER 1300 = VS2003
// _MSC_VER 1400 = VS2005
#if _MSC_VER < 1400
#define OpcUa_Unlink  unlink
#else
#define OpcUa_Unlink  _unlink
#endif /* _MSC_VER < 1400 */

#ifdef _MSC_VER
#pragma warning(disable:4748) /* suppress /GS can not protect parameters and local variables from local buffer overrun because optimizations are disabled in function */
#endif /* _MSC_VER */

#if OPCUA_P_TRACE_TO_FILE
    FILE*           OpcUa_P_Trace_g_hOutFile                = NULL;
    unsigned int    OpcUa_P_Trace_g_hOutFileNoOfEntries     = 0;
    unsigned int    OpcUa_P_Trace_g_hOutFileNoOfEntriesMax  = OPCUA_P_TRACE_G_MAX_FILE_ENTRIES;
#endif /* OPCUA_P_TRACE_TO_FILE */

/*============================================================================
 * Trace Initialize
 *===========================================================================*/
/**
* Initialize all ressources needed for tracing.
*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_Trace_Initialize(OpcUa_Void)
{
#if OPCUA_P_TRACE_TO_FILE
    OpcUa_P_Trace_g_hOutFile = fopen(OPCUA_P_TRACE_G_OUTFILE, "w");
#endif /* OPCUA_P_TRACE_TO_FILE */

    return OpcUa_Good;
}

/*============================================================================
 * Trace Clear
 *===========================================================================*/
/**
* Clear all ressources needed for tracing.
*/
OpcUa_Void OPCUA_DLLCALL OpcUa_P_Trace_Clear(OpcUa_Void)
{
#if OPCUA_P_TRACE_TO_FILE
    fflush(OpcUa_P_Trace_g_hOutFile);
    fclose(OpcUa_P_Trace_g_hOutFile);
    OpcUa_P_Trace_g_hOutFile = NULL;
#endif /* OPCUA_P_TRACE_TO_FILE */

    return;
}

/*============================================================================
 * Tracefunction
 *===========================================================================*/
/**
 * Writes the given string to the trace device, if the given trace level is
 * activated in the header file.
 */
OpcUa_Void OPCUA_DLLCALL OpcUa_P_Trace(OpcUa_CharA* a_sMessage)
{
    /* send to tracehook if registered */
    if(g_OpcUa_P_TraceHook != OpcUa_Null)
    {
        g_OpcUa_P_TraceHook(a_sMessage);
    }
    else /* send to console */
    {
#ifdef OPCUA_P_ENABLE_VS_CONSOLE
        /* visual studio debug console output */
        char buffer[20];
#endif /* OPCUA_P_ENABLE_VS_CONSOLE */

#if OPCUA_P_TRACE_ENABLE_TIME
        char dtbuffer[26] = {'\0'};
#endif

#if OPCUA_P_TRACE_ENABLE_TIME
        OpcUa_P_DateTime_GetStringFromDateTime(OpcUa_P_DateTime_UtcNow(), dtbuffer, 25);
        dtbuffer[25] = '\0';
#endif /* OPCUA_P_TRACE_ENABLE_TIME */

#ifdef OPCUA_P_ENABLE_VS_CONSOLE
        /* visual studio debug console output */
        _snprintf(buffer, 20, "|%d| ", OpcUa_P_Thread_GetCurrentThreadId());
        buffer[19] = '\0';
#if OPCUA_P_TRACE_ENABLE_TIME
        OutputDebugStringA(dtbuffer);
#endif /* OPCUA_P_TRACE_ENABLE_TIME */
        OutputDebugStringA(buffer);
        OutputDebugStringA(a_sMessage);
#endif /* OPCUA_P_ENABLE_VS_CONSOLE */

#ifndef OPCUA_P_TRACE_ENABLE_TIME
        printf("|%d| %s", OpcUa_P_Thread_GetCurrentThreadId(), a_sMessage);
#else
        printf("|%d| %s %s", OpcUa_P_Thread_GetCurrentThreadId(), &dtbuffer[11], a_sMessage);
#endif /* OPCUA_P_TRACE_ENABLE_TIME */

#if OPCUA_P_TRACE_TO_FILE
        if(OpcUa_P_Trace_g_hOutFile != NULL)
        {
            fprintf(OpcUa_P_Trace_g_hOutFile, "|%d| %s %s", OpcUa_P_Thread_GetCurrentThreadId(), &dtbuffer[11], a_sMessage);
#if OPCUA_P_TRACE_FFLUSH_IMMEDIATELY
            fflush(OpcUa_P_Trace_g_hOutFile);
#endif
            OpcUa_P_Trace_g_hOutFileNoOfEntries++;
        }
        if(OpcUa_P_Trace_g_hOutFileNoOfEntries >= OpcUa_P_Trace_g_hOutFileNoOfEntriesMax)
        {
            /* delete backup store and rename current file and create new one */
            fflush(OpcUa_P_Trace_g_hOutFile);
            fclose(OpcUa_P_Trace_g_hOutFile);
            OpcUa_P_Trace_g_hOutFile = NULL;
            OpcUa_Unlink(OPCUA_P_TRACE_G_OUTFILE_BACKUP);
            OpcUa_Rename(OPCUA_P_TRACE_G_OUTFILE, OPCUA_P_TRACE_G_OUTFILE_BACKUP);
            OpcUa_P_Trace_g_hOutFile = fopen(OPCUA_P_TRACE_G_OUTFILE, "w");
            OpcUa_P_Trace_g_hOutFileNoOfEntries = 0;
        }
#endif /* OPCUA_P_TRACE_TO_FILE */
    }
}
