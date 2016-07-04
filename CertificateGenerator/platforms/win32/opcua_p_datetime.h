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
/* Modify the content of this file according to the event implementation on your system.              */
/* This is the win32 implementation                                                                   */
/******************************************************************************************************/

/**
 * @brief Returns the current time in UTC.
 */
OpcUa_DateTime OPCUA_DLLCALL OpcUa_P_DateTime_UtcNow(void);

/**
 * @brief Returns the time in OpcUa_TimeVal format.
 */
OpcUa_Void OPCUA_DLLCALL OpcUa_P_DateTime_GetTimeOfDay(OpcUa_TimeVal*  pValue);

/**
 * @brief Converts the given OpcUa_DateTime into a ascii string.
 *
 * @param DateTime   [in]        The DateTime value to convert.
 * @param Buffer     [in/out]    At least 25 bytes of buffer.
 * @param DateTime   [in]        The length of the given buffer.
 *
 * @return Error Code
 */
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_DateTime_GetStringFromDateTime(  OpcUa_DateTime datetime,
                                                                        OpcUa_StringA  buffer,
                                                                        OpcUa_UInt32   length);

/**
 * @brief Converts the given (ascii) string into OpcUa_DateTime format.
 *
 * @param DateTimeString [in]    Buffer containing the DateTime string. Must not be OpcUa_Null!
 * @param DateTime      [out]    Pointer to the OpcUa_DateTime value in which the converted value will be stored.
 *
 * @return Status Code.
 */
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_DateTime_GetDateTimeFromString(  OpcUa_StringA   DateTimeString,
                                                                        OpcUa_DateTime* DateTime);
