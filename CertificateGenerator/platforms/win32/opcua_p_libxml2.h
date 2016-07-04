/*============================================================================
  @file opcua_p_libxml2.h

 (c) Copyright 2005-2008 The OPC Foundation
 ALL RIGHTS RESERVED.

 DISCLAIMER:
  This code is provided by the OPC Foundation solely to assist in
  understanding and use of the appropriate OPC Specification(s) and may be
  used as set forth in the License Grant section of the OPC Specification.
  This code is provided as-is and without warranty or support of any sort
  and is subject to the Warranty and Liability Disclaimers which appear
  in the printed OPC Specification.
*/

#ifndef _OpcUa_P_Libxml2_H_
#define _OpcUa_P_Libxml2_H_ 1

#ifdef OPCUA_HAVE_XMLAPI

OPCUA_BEGIN_EXTERN_C

/**
  @brief Initializes the libxm2 library.
 */
OpcUa_Void OpcUa_P_Libxml2_Initialize();

/**
  @brief Cleans up the libxml2 library.
 */
OpcUa_Void OpcUa_P_Libxml2_Cleanup();

/**
  @brief Creates the xml writer.
 */
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_Libxml2_XmlWriter_Create(
    OpcUa_Void*                         a_pWriteContext,
    OpcUa_XmlWriter_PfnWriteCallback*   a_pWriteCallback,
    OpcUa_XmlWriter_PfnCloseCallback*   a_pCloseCallback,
    struct _OpcUa_XmlWriter*            a_pXmlWriter);

/**
  @brief Deletes the xml writer.
 */
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_Libxml2_XmlWriter_Delete(
    struct _OpcUa_XmlWriter*            a_pXmlWriter);

/**
  @brief Creates the xml reader.
 */
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_Libxml2_XmlReader_Create(
    OpcUa_Void*                         a_pReadContext,
    OpcUa_XmlReader_PfnReadCallback*    a_pReadCallback,
    OpcUa_XmlReader_PfnCloseCallback*   a_pCloseCallback,
    struct _OpcUa_XmlReader*            a_pXmlReader);

/**
  @brief Deletes the xml reader.
 */
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_Libxml2_XmlReader_Delete(
    struct _OpcUa_XmlReader*            a_pXmlReader);

OpcUa_StatusCode OpcUa_P_Libxml2_XmlWriter_StartElement(
    struct _OpcUa_XmlWriter*    a_pXmlWriter,
    OpcUa_StringA               a_sNamespacePrefix,
    OpcUa_StringA               a_sElementName,
    OpcUa_StringA               a_sNamespaceUri);

OpcUa_StatusCode OpcUa_P_Libxml2_XmlWriter_EndElement(
    struct _OpcUa_XmlWriter*    a_pXmlWriter);

OpcUa_StatusCode OpcUa_P_Libxml2_XmlWriter_WriteAttribute(
    struct _OpcUa_XmlWriter*    a_pXmlWriter,
    OpcUa_StringA               a_sNamespacePrefix,
    OpcUa_StringA               a_sAttributeName,
    OpcUa_StringA               a_sNamespaceUri,
    OpcUa_StringA               a_sAttributeValue);

OpcUa_StatusCode OpcUa_P_Libxml2_XmlWriter_WriteString(
    struct _OpcUa_XmlWriter*    a_pXmlWriter,
    OpcUa_StringA               a_sValue);

OpcUa_StatusCode OpcUa_P_Libxml2_XmlWriter_WriteFormatted(
    struct _OpcUa_XmlWriter*    a_pXmlWriter,
    OpcUa_StringA               a_sFormat,
    OpcUa_P_VA_List             a_pArguments);

OpcUa_StatusCode OpcUa_P_Libxml2_XmlWriter_WriteRaw(
    struct _OpcUa_XmlWriter*    a_pXmlWriter,
    OpcUa_Byte*                 a_pRawData,
    OpcUa_UInt32                a_uDataLength);

OpcUa_StatusCode OpcUa_P_Libxml2_XmlWriter_WriteNode(
    struct _OpcUa_XmlWriter*    a_pXmlWriter,
    struct _OpcUa_XmlReader*    a_pXmlReader);

OpcUa_StatusCode OpcUa_P_Libxml2_XmlWriter_Flush(
    struct _OpcUa_XmlWriter*    a_pXmlWriter);

OpcUa_StatusCode OpcUa_P_Libxml2_XmlWriter_Close(
    struct _OpcUa_XmlWriter*    a_pXmlWriter);

OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_MoveToContent(
    struct _OpcUa_XmlReader*    a_pXmlReader,
    OpcUa_Int32*                a_pNodeType);

OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_MoveToElement(
    struct _OpcUa_XmlReader*    a_pXmlReader);

OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_MoveToFirstAttribute(
    struct _OpcUa_XmlReader*    a_pXmlReader);

OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_MoveToNextAttribute(
    struct _OpcUa_XmlReader*    a_pXmlReader);

OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_IsStartElement(
    struct _OpcUa_XmlReader*    a_pXmlReader,
    OpcUa_StringA               a_sLocalName,
    OpcUa_StringA               a_sNamespaceUri,
    OpcUa_Boolean*              a_pResult);

OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_IsEmptyElement(
    struct _OpcUa_XmlReader*    a_pXmlReader,
    OpcUa_Boolean*              a_pResult);

OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_HasAttributes(
    struct _OpcUa_XmlReader*    a_pXmlReader,
    OpcUa_Boolean*              a_pResult);

OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_IsDefault(
    struct _OpcUa_XmlReader*    a_pXmlReader,
    OpcUa_Boolean*              a_pResult);

OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_ReadStartElement(
    struct _OpcUa_XmlReader*    a_pXmlReader,
    OpcUa_StringA               a_sLocalName,
    OpcUa_StringA               a_sNamespaceUri);

OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_ReadEndElement(
    struct _OpcUa_XmlReader*    a_pXmlReader);

OpcUa_Int32 OpcUa_P_Libxml2_XmlReader_GetNodeType(
    struct _OpcUa_XmlReader*    a_pXmlReader);

OpcUa_Int32 OpcUa_P_Libxml2_XmlReader_GetDepth(
    struct _OpcUa_XmlReader*    a_pXmlReader);

OpcUa_StringA OpcUa_P_Libxml2_XmlReader_GetLocalName(
    struct _OpcUa_XmlReader*    a_pXmlReader);

OpcUa_StringA OpcUa_P_Libxml2_XmlReader_GetName(
    struct _OpcUa_XmlReader*     a_pXmlReader);

OpcUa_StringA OpcUa_P_Libxml2_XmlReader_GetNamespaceUri(
    struct _OpcUa_XmlReader*    a_pXmlReader);

OpcUa_StringA OpcUa_P_Libxml2_XmlReader_GetPrefix(
    struct _OpcUa_XmlReader*    a_pXmlReader);

OpcUa_StringA OpcUa_P_Libxml2_XmlReader_GetValue(
    struct _OpcUa_XmlReader*    a_pXmlReader);

OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_GetAttribute(
    struct _OpcUa_XmlReader*    a_pXmlReader,
    OpcUa_StringA               a_sAttributeName,
    OpcUa_StringA               a_sNamespaceUri,
    OpcUa_StringA               a_sAttributeValue,
    OpcUa_UInt32*               a_pValueLength);

OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_Read(
    struct _OpcUa_XmlReader*    a_pXmlReader);

OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_ReadString(
    struct _OpcUa_XmlReader*    a_pXmlReader,
    OpcUa_StringA*              a_pString);

OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_Skip(
    struct _OpcUa_XmlReader*    a_pXmlReader);

OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_Close(
    struct _OpcUa_XmlReader*    a_pXmlReader);

OPCUA_END_EXTERN_C

#endif /* OPCUA_HAVE_XMLAPI */
#endif /* _OpcUa_P_Libxml2_H_ */
