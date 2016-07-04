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

#include <opcua_builtintypes.h>

#ifndef _OpcUa_BinaryEncoderInternal_H_
#define _OpcUa_BinaryEncoderInternal_H_ 1

OPCUA_BEGIN_EXTERN_C

/*============================================================================
 * OpcUa_NodeEncoding
 *===========================================================================*/
/** @brief Defines the possible node id encoding values. */
typedef enum _OpcUa_NodeEncoding
{
    OpcUa_NodeEncoding_TwoByte = 0x00,
    OpcUa_NodeEncoding_FourByte = 0x01,
    OpcUa_NodeEncoding_Numeric = 0x02,
    OpcUa_NodeEncoding_String = 0x03,
    OpcUa_NodeEncoding_Guid = 0x04,
    OpcUa_NodeEncoding_ByteString = 0x05,
    OpcUa_NodeEncoding_UriMask = 0x80,
    OpcUa_NodeEncoding_ServerIndexMask = 0x40,
    OpcUa_NodeEncoding_TypeMask = 0x3F,
}
OpcUa_NodeEncoding;

/*============================================================================
 * OpcUa_DiagnosticInfo_EncodingByte
 *===========================================================================*/
typedef enum _OpcUa_DiagnosticInfo_EncodingByte
{
    OpcUa_DiagnosticInfo_EncodingByte_SymbolicId = 0x01,
    OpcUa_DiagnosticInfo_EncodingByte_NamespaceUri = 0x02,
    OpcUa_DiagnosticInfo_EncodingByte_LocalizedText = 0x04,
    OpcUa_DiagnosticInfo_EncodingByte_Locale = 0x08,
    OpcUa_DiagnosticInfo_EncodingByte_AdditionalInfo = 0x10,
    OpcUa_DiagnosticInfo_EncodingByte_InnerStatusCode = 0x20,
    OpcUa_DiagnosticInfo_EncodingByte_InnerDiagnosticInfo = 0x40
}
OpcUa_DiagnosticInfo_EncodingByte;

/*============================================================================
 * OpcUa_LocalizedText_EncodingByte
 *===========================================================================*/
typedef enum _OpcUa_LocalizedText_EncodingByte
{
    OpcUa_LocalizedText_EncodingByte_Locale = 0x01,
    OpcUa_LocalizedText_EncodingByte_Text = 0x02
}
OpcUa_LocalizedText_EncodingByte;

/*============================================================================
 * OpcUa_DataValue_EncodingByte
 *===========================================================================*/
typedef enum _OpcUa_DataValue_EncodingByte
{
    OpcUa_DataValue_EncodingByte_Value = 0x01,
    OpcUa_DataValue_EncodingByte_StatusCode = 0x02,
    OpcUa_DataValue_EncodingByte_SourceTimestamp = 0x04,
    OpcUa_DataValue_EncodingByte_ServerTimestamp = 0x08,
    OpcUa_DataValue_EncodingByte_SourcePicoseconds = 0x10,
    OpcUa_DataValue_EncodingByte_ServerPicoseconds = 0x20
}
OpcUa_DataValue_EncodingByte;

/*============================================================================
 * Variant Encoding Constants
 *===========================================================================*/
#define OpcUa_Variant_ArrayMask 0x80
#define OpcUa_Variant_ArrayDimensionsMask 0x40
#define OpcUa_Variant_TypeMask 0x3F

OPCUA_END_EXTERN_C

#endif /* _OpcUa_BinaryEncoderInternal_H_ */
