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

#ifndef _OpcUa_P_Binary_H_
#define _OpcUa_P_Binary_H_ 1


OPCUA_BEGIN_EXTERN_C


/*============================================================================
 * OpcUa_Boolean_P_NativeToWire
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_Boolean_P_NativeToWire(OpcUa_Boolean_Wire* wire, OpcUa_Boolean* native);

/*============================================================================
 * OpcUa_Boolean_P_WireToNative
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_Boolean_P_WireToNative(OpcUa_Boolean_Wire* native, OpcUa_Boolean_Wire* wire);

/*============================================================================
 * OpcUa_SByte_P_NativeToWire
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_SByte_P_NativeToWire(OpcUa_SByte_Wire* wire, OpcUa_SByte* native);

/*============================================================================
 * OpcUa_SByte_P_NativeToWire
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_SByte_P_WireToNative(OpcUa_SByte* native, OpcUa_SByte_Wire* wire);

/*============================================================================
 * OpcUa_Byte_P_NativeToWire
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_Byte_P_NativeToWire(OpcUa_Byte_Wire* wire, OpcUa_Byte* native);

/*============================================================================
 * OpcUa_Byte_P_WireToNative
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_Byte_P_WireToNative(OpcUa_Byte* native, OpcUa_Byte_Wire* wire);

/*============================================================================
 * OpcUa_Int16_P_NativeToWire
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_Int16_P_NativeToWire(OpcUa_Int16_Wire* wire, OpcUa_Int16* native);

/*============================================================================
 * OpcUa_Int16_P_WireToNative
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_Int16_P_WireToNative(OpcUa_Int16* native, OpcUa_Int16_Wire* wire);

/*============================================================================
 * OpcUa_UInt16_P_NativeToWire
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_UInt16_P_NativeToWire(OpcUa_UInt16_Wire* wire, OpcUa_UInt16* native);

/*============================================================================
 * OpcUa_UInt16_P_WireToNative
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_UInt16_P_WireToNative(OpcUa_UInt16* native, OpcUa_UInt16_Wire* wire);

/*============================================================================
 * OpcUa_Int32_P_NativeToWire
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_Int32_P_NativeToWire(OpcUa_Int32_Wire* wire, OpcUa_Int32* native);

/*============================================================================
 * OpcUa_Int32_P_WireToNative
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_Int32_P_WireToNative(OpcUa_Int32* native, OpcUa_Int32_Wire* wire);

/*============================================================================
 * OpcUa_UInt32_P_NativeToWire
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_UInt32_P_NativeToWire(OpcUa_UInt32_Wire* wire, OpcUa_UInt32* native);

/*============================================================================
 * OpcUa_UInt32_P_WireToNative
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_UInt32_P_WireToNative(OpcUa_UInt32* native, OpcUa_UInt32_Wire* wire);

/*============================================================================
 * OpcUa_Int64_P_NativeToWire
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_Int64_P_NativeToWire(OpcUa_Int64_Wire* wire, OpcUa_Int64* native);

/*============================================================================
 * OpcUa_Int64_P_WireToNative
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_Int64_P_WireToNative(OpcUa_Int64* native, OpcUa_Int64_Wire* wire);

/*============================================================================
 * OpcUa_UInt64_P_NativeToWire
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_UInt64_P_NativeToWire(OpcUa_UInt64_Wire* wire, OpcUa_UInt64* native);

/*============================================================================
 * OpcUa_UInt64_P_WireToNative
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_UInt64_P_WireToNative(OpcUa_UInt64* native, OpcUa_UInt64_Wire* wire);

/*============================================================================
 * OpcUa_Float_P_NativeToWire
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_Float_P_NativeToWire(OpcUa_Float_Wire* wire, OpcUa_Float* native);

/*============================================================================
 * OpcUa_Float_P_WireToNative
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_Float_P_WireToNative(OpcUa_Float* native, OpcUa_Float_Wire* wire);

/*============================================================================
 * OpcUa_Double_P_NativeToWire
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_Double_P_NativeToWire(OpcUa_Double_Wire* wire, OpcUa_Double* native);

/*============================================================================
 * OpcUa_Double_P_WireToNative
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_Double_P_WireToNative(OpcUa_Double* native, OpcUa_Double_Wire* wire);

/*============================================================================
 * OpcUa_String_P_NativeToWire
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_String_P_NativeToWire(OpcUa_String_Wire* wire, OpcUa_String* native);

/*============================================================================
 * OpcUa_String_P_WireToNative
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_String_P_WireToNative(OpcUa_String* native, OpcUa_String_Wire* wire);

/*============================================================================
 * OpcUa_DateTime_P_NativeToWire
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_DateTime_P_NativeToWire(OpcUa_DateTime_Wire* wire, OpcUa_DateTime* native);

/*============================================================================
 * OpcUa_DateTime_P_WireToNative
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_DateTime_P_WireToNative(OpcUa_DateTime* native, OpcUa_DateTime_Wire* wire);

/*============================================================================
 * OpcUa_Guid_P_NativeToWire
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_Guid_P_NativeToWire(OpcUa_Guid_Wire* wire, OpcUa_Guid* native);

/*============================================================================
 * OpcUa_Guid_P_WireToNative
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_Guid_P_WireToNative(OpcUa_Guid* native, OpcUa_Guid_Wire* wire);

OPCUA_END_EXTERN_C

#endif /* _OpcUa_P_Binary_H_ */
