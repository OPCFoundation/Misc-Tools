/**
  (c) Copyright 2008 The OPC Foundation
  ALL RIGHTS RESERVED.

  DISCLAIMER:
  This code is provided by the OPC Foundation solely to assist in
  understanding and use of the appropriate OPC Specification(s) and may be
  used as set forth in the License Grant section of the OPC Specification.
  This code is provided as-is and without warranty or support of any sort
  and is subject to the Warranty and Liability Disclaimers which appear
  in the printed OPC Specification.
*/

/* UA platform definitions */
#include <opcua_p_internal.h>

#ifdef OPCUA_HAVE_XMLAPI

/* Libxml2 headers */
#include <libxml/xmlstring.h>
#include <libxml/xmlreader.h>

/* UA platform definitions */
#include <opcua_p_memory.h>
#include <opcua_p_string.h>

/* XML specific definitions */
#include <opcua_xmldefs.h>

/* XML reader interface */
#include <opcua_xmlreader.h>

/* own header */
#include <opcua_p_libxml2.h>

typedef struct _OpcUa_P_Libxml2_XmlReader
{
    OpcUa_Boolean                       Closed;
    OpcUa_Void*                         ReadContext;
    OpcUa_XmlReader_PfnReadCallback*    ReadCallback;
    OpcUa_XmlReader_PfnCloseCallback*   CloseCallback;
    xmlTextReaderPtr                    TextReader;
} OpcUa_P_Libxml2_XmlReader;

/*============================================================================
 * OpcUa_P_Libxml2_XmlReader_ReadCallback
 *===========================================================================*/
static OpcUa_Int OPCUA_CDECL OpcUa_P_Libxml2_XmlReader_ReadCallback(
    OpcUa_Void*     a_pCallbackContext,
    OpcUa_CharA*    a_pReadBuffer,
    OpcUa_Int       a_iBufferLength)
{
    OpcUa_P_Libxml2_XmlReader*  pReaderHandle   = OpcUa_Null;
    OpcUa_StatusCode            uCallbackStatus = OpcUa_Good;
    OpcUa_UInt32                uByteCount      = a_iBufferLength;

    OpcUa_ReturnErrorIfNull(a_pCallbackContext, -1);
    OpcUa_ReturnErrorIfNull(a_pReadBuffer, -1);

    pReaderHandle = (OpcUa_P_Libxml2_XmlReader*)((OpcUa_XmlReader*)a_pCallbackContext)->Handle;

    OpcUa_ReturnErrorIfNull(pReaderHandle, -1);
    OpcUa_ReturnErrorIfTrue(pReaderHandle->Closed, -1);

    if(pReaderHandle->ReadCallback != OpcUa_Null)
    {
        uCallbackStatus = pReaderHandle->ReadCallback((OpcUa_XmlReader*)a_pCallbackContext,
                                                      pReaderHandle->ReadContext,
                                                      (OpcUa_Byte*)a_pReadBuffer,
                                                      &uByteCount);
        if(OpcUa_IsGood(uCallbackStatus))
        {
            return (OpcUa_Int)uByteCount;
        }

        if(uCallbackStatus == OpcUa_BadEndOfStream && uByteCount == 0)
        {
            return 0;
        }
    }

    return -1;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlReader_CloseCallback
 *===========================================================================*/
static OpcUa_Int OPCUA_CDECL OpcUa_P_Libxml2_XmlReader_CloseCallback(
    OpcUa_Void* a_pCallbackContext)
{
    OpcUa_P_Libxml2_XmlReader* pReaderHandle = OpcUa_Null;

    OpcUa_ReturnErrorIfNull(a_pCallbackContext, -1);

    pReaderHandle = (OpcUa_P_Libxml2_XmlReader*)((OpcUa_XmlReader*)a_pCallbackContext)->Handle;

    OpcUa_ReturnErrorIfNull(pReaderHandle, -1);
    OpcUa_ReturnErrorIfTrue(pReaderHandle->Closed, -1);

    pReaderHandle->Closed = OpcUa_True;

    if(pReaderHandle->CloseCallback != OpcUa_Null)
    {
        if(OpcUa_IsBad(pReaderHandle->CloseCallback((OpcUa_XmlReader*)a_pCallbackContext,
                                                    pReaderHandle->ReadContext)))
        {
            return -1;
        }
    }

    return 0;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlReader_Create
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_Libxml2_XmlReader_Create(
    OpcUa_Void*                         a_pReadContext,
    OpcUa_XmlReader_PfnReadCallback*    a_pReadCallback,
    OpcUa_XmlReader_PfnCloseCallback*   a_pCloseCallback,
    struct _OpcUa_XmlReader*            a_pXmlReader)
{
    OpcUa_P_Libxml2_XmlReader* pReaderHandle = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlReader_Create");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlReader);

    pReaderHandle = (OpcUa_P_Libxml2_XmlReader*)OpcUa_P_Memory_Alloc(sizeof(OpcUa_P_Libxml2_XmlReader));
    OpcUa_GotoErrorIfAllocFailed(pReaderHandle);

    pReaderHandle->Closed               = OpcUa_False;
    pReaderHandle->ReadContext          = a_pReadContext;
    pReaderHandle->ReadCallback         = a_pReadCallback;
    pReaderHandle->CloseCallback        = a_pCloseCallback;

    /* the handle should be initialized before call of the xmlReaderForIO */
    a_pXmlReader->Handle                = pReaderHandle;

    /* Create an xmltextReader for an XML document from I/O functions and source */
    pReaderHandle->TextReader           = xmlReaderForIO(OpcUa_P_Libxml2_XmlReader_ReadCallback,
                                                         OpcUa_P_Libxml2_XmlReader_CloseCallback,
                                                         a_pXmlReader,
                                                         OpcUa_Null,
                                                         OpcUa_Null,
                                                         0);
    OpcUa_GotoErrorIfNull(pReaderHandle->TextReader, OpcUa_BadInternalError);

    a_pXmlReader->MoveToContent         = OpcUa_P_Libxml2_XmlReader_MoveToContent;
    a_pXmlReader->MoveToElement         = OpcUa_P_Libxml2_XmlReader_MoveToElement;
    a_pXmlReader->MoveToFirstAttribute  = OpcUa_P_Libxml2_XmlReader_MoveToFirstAttribute;
    a_pXmlReader->MoveToNextAttribute   = OpcUa_P_Libxml2_XmlReader_MoveToNextAttribute;
    a_pXmlReader->IsStartElement        = OpcUa_P_Libxml2_XmlReader_IsStartElement;
    a_pXmlReader->IsEmptyElement        = OpcUa_P_Libxml2_XmlReader_IsEmptyElement;
    a_pXmlReader->HasAttributes         = OpcUa_P_Libxml2_XmlReader_HasAttributes;
    a_pXmlReader->IsDefault             = OpcUa_P_Libxml2_XmlReader_IsDefault;
    a_pXmlReader->ReadStartElement      = OpcUa_P_Libxml2_XmlReader_ReadStartElement;
    a_pXmlReader->ReadEndElement        = OpcUa_P_Libxml2_XmlReader_ReadEndElement;
    a_pXmlReader->GetNodeType           = OpcUa_P_Libxml2_XmlReader_GetNodeType;
    a_pXmlReader->GetDepth              = OpcUa_P_Libxml2_XmlReader_GetDepth;
    a_pXmlReader->GetLocalName          = OpcUa_P_Libxml2_XmlReader_GetLocalName;
    a_pXmlReader->GetName               = OpcUa_P_Libxml2_XmlReader_GetName;
    a_pXmlReader->GetNamespaceUri       = OpcUa_P_Libxml2_XmlReader_GetNamespaceUri;
    a_pXmlReader->GetPrefix             = OpcUa_P_Libxml2_XmlReader_GetPrefix;
    a_pXmlReader->GetValue              = OpcUa_P_Libxml2_XmlReader_GetValue;
    a_pXmlReader->GetAttribute          = OpcUa_P_Libxml2_XmlReader_GetAttribute;
    a_pXmlReader->Read                  = OpcUa_P_Libxml2_XmlReader_Read;
    a_pXmlReader->Skip                  = OpcUa_P_Libxml2_XmlReader_Skip;
    a_pXmlReader->Close                 = OpcUa_P_Libxml2_XmlReader_Close;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(pReaderHandle != OpcUa_Null)
    {
        if(pReaderHandle->TextReader != OpcUa_Null)
        {
            xmlFreeTextReader(pReaderHandle->TextReader);
        }
    }

    OpcUa_P_Memory_Free(pReaderHandle);
    a_pXmlReader->Handle = OpcUa_Null;

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlReader_MoveToContent
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_MoveToContent(
    struct _OpcUa_XmlReader*    a_pXmlReader,
    OpcUa_Int32*                a_pNodeType)
{
    OpcUa_P_Libxml2_XmlReader*  pReaderHandle   = OpcUa_Null;
    OpcUa_Int32                 iResultCode     = 0;
    OpcUa_Int32                 iNodeType       = 0;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlReader_MoveToContent");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlReader);

    pReaderHandle = (OpcUa_P_Libxml2_XmlReader*)a_pXmlReader->Handle;

    OpcUa_ReturnErrorIfArgumentNull(pReaderHandle);
    OpcUa_ReturnErrorIfTrue(pReaderHandle->Closed, OpcUa_BadInvalidState);

    iNodeType = xmlTextReaderNodeType(pReaderHandle->TextReader);
    OpcUa_ReturnErrorIfTrue(iNodeType < 0, OpcUa_BadInternalError);

    switch(iNodeType)
    {
        case XML_READER_TYPE_ELEMENT:
        case XML_READER_TYPE_TEXT:
        case XML_READER_TYPE_CDATA:
        case XML_READER_TYPE_ENTITY_REFERENCE:
        case XML_READER_TYPE_END_ELEMENT:
        case XML_READER_TYPE_END_ENTITY:
        {
            break;
        }

        case XML_READER_TYPE_ATTRIBUTE:
        {
            OpcUa_ReturnErrorIfTrue(xmlTextReaderMoveToElement(pReaderHandle->TextReader) < 0,
                                    OpcUa_BadInternalError);
            break;
        }

        default:
        {
            iResultCode = xmlTextReaderRead(pReaderHandle->TextReader);
            OpcUa_ReturnErrorIfTrue(iResultCode < 0, OpcUa_BadInternalError);

            if(iResultCode > 0)
            {
                OpcUa_P_Libxml2_XmlReader_MoveToContent(a_pXmlReader, a_pNodeType);
            }

            break;
        }
    }

    if(a_pNodeType != OpcUa_Null)
    {
        *a_pNodeType = xmlTextReaderNodeType(pReaderHandle->TextReader);
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlReader_MoveToElement
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_MoveToElement(
    struct _OpcUa_XmlReader*    a_pXmlReader)
{
    OpcUa_P_Libxml2_XmlReader*  pReaderHandle   = OpcUa_Null;
    OpcUa_Int32                 iResultCode     = 0;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlReader_MoveToElement");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlReader);

    pReaderHandle = (OpcUa_P_Libxml2_XmlReader*)a_pXmlReader->Handle;

    OpcUa_ReturnErrorIfArgumentNull(pReaderHandle);
    OpcUa_ReturnErrorIfTrue(pReaderHandle->Closed, OpcUa_BadInvalidState);

    iResultCode = xmlTextReaderMoveToElement(pReaderHandle->TextReader);
    OpcUa_ReturnErrorIfTrue(iResultCode  < 0, OpcUa_BadInternalError);
    OpcUa_ReturnErrorIfTrue(iResultCode == 0, OpcUa_BadNoDataAvailable);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlReader_MoveToFirstAttribute
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_MoveToFirstAttribute(
    struct _OpcUa_XmlReader*    a_pXmlReader)
{
    OpcUa_P_Libxml2_XmlReader*  pReaderHandle   = OpcUa_Null;
    OpcUa_Int32                 iResultCode     = 0;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlReader_MoveToFirstAttribute");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlReader);

    pReaderHandle = (OpcUa_P_Libxml2_XmlReader*)a_pXmlReader->Handle;

    OpcUa_ReturnErrorIfArgumentNull(pReaderHandle);
    OpcUa_ReturnErrorIfTrue(pReaderHandle->Closed, OpcUa_BadInvalidState);

    iResultCode = xmlTextReaderMoveToFirstAttribute(pReaderHandle->TextReader);
    OpcUa_ReturnErrorIfTrue(iResultCode  < 0, OpcUa_BadInternalError);
    OpcUa_ReturnErrorIfTrue(iResultCode == 0, OpcUa_BadNoDataAvailable);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlReader_MoveToNextAttribute
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_MoveToNextAttribute(
    struct _OpcUa_XmlReader*    a_pXmlReader)
{
    OpcUa_P_Libxml2_XmlReader*  pReaderHandle   = OpcUa_Null;
    OpcUa_Int32                 iResultCode     = 0;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlReader_MoveToNextAttribute");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlReader);

    pReaderHandle = (OpcUa_P_Libxml2_XmlReader*)a_pXmlReader->Handle;

    OpcUa_ReturnErrorIfArgumentNull(pReaderHandle);
    OpcUa_ReturnErrorIfTrue(pReaderHandle->Closed, OpcUa_BadInvalidState);

    iResultCode = xmlTextReaderMoveToNextAttribute(pReaderHandle->TextReader);
    OpcUa_ReturnErrorIfTrue(iResultCode  < 0, OpcUa_BadInternalError);
    OpcUa_ReturnErrorIfTrue(iResultCode == 0, OpcUa_BadNoDataAvailable);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlReader_IsStartElement
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_IsStartElement(
    struct _OpcUa_XmlReader*    a_pXmlReader,
    OpcUa_StringA               a_sLocalName,
    OpcUa_StringA               a_sNamespaceUri,
    OpcUa_Boolean*              a_pResult)
{
    OpcUa_P_Libxml2_XmlReader*  pReaderHandle   = OpcUa_Null;
    OpcUa_Int32                 iNodeType       = XML_READER_TYPE_NONE;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlReader_IsStartElement");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlReader);
    OpcUa_ReturnErrorIfArgumentNull(a_pResult);

    pReaderHandle = (OpcUa_P_Libxml2_XmlReader*)a_pXmlReader->Handle;

    OpcUa_ReturnErrorIfArgumentNull(pReaderHandle);
    OpcUa_ReturnErrorIfTrue(pReaderHandle->Closed, OpcUa_BadInvalidState);

    *a_pResult = OpcUa_False;

    uStatus = OpcUa_P_Libxml2_XmlReader_MoveToContent(a_pXmlReader, &iNodeType);
    OpcUa_GotoErrorIfBad(uStatus);

    if(iNodeType != XML_READER_TYPE_ELEMENT)
    {
        /* it is not a start element */
        *a_pResult = OpcUa_False;
        OpcUa_ReturnStatusCode(OpcUa_Good);
    }

    if(a_sLocalName == OpcUa_Null && a_sNamespaceUri == OpcUa_Null)
    {
        /* local name and namespace uri are both unspecified,
           there is nothing to compare */
        *a_pResult = OpcUa_True;
        OpcUa_ReturnStatusCode(OpcUa_Good);
    }

    if(a_sLocalName != OpcUa_Null)
    {
        /* compare local names */
        if(!xmlStrEqual(xmlTextReaderConstLocalName(pReaderHandle->TextReader), (xmlChar*)a_sLocalName))
        {
            /* local names are not the same */
            *a_pResult = OpcUa_False;
            OpcUa_ReturnStatusCode(OpcUa_Good);
        }
    }

    if(a_sNamespaceUri != OpcUa_Null)
    {
        /* compare namespace identifiers */
        if(!xmlStrEqual(xmlTextReaderConstNamespaceUri(pReaderHandle->TextReader), (xmlChar*)a_sNamespaceUri))
        {
            /* namespace identifiers are not the same */
            *a_pResult = OpcUa_False;
            OpcUa_ReturnStatusCode(OpcUa_Good);
        }
    }

    /* local names and namespace identifiers are same as specified */
    *a_pResult = OpcUa_True;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlReader_IsEmptyElement
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_IsEmptyElement(
    struct _OpcUa_XmlReader*    a_pXmlReader,
    OpcUa_Boolean*              a_pResult)
{
    OpcUa_P_Libxml2_XmlReader*  pReaderHandle   = OpcUa_Null;
    OpcUa_Int32                 iResultCode     = 0;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlReader_IsEmptyElement");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlReader);
    OpcUa_ReturnErrorIfArgumentNull(a_pResult);

    pReaderHandle = (OpcUa_P_Libxml2_XmlReader*)a_pXmlReader->Handle;

    OpcUa_ReturnErrorIfArgumentNull(pReaderHandle);
    OpcUa_ReturnErrorIfTrue(pReaderHandle->Closed, OpcUa_BadInvalidState);

    *a_pResult = OpcUa_False;

    iResultCode = xmlTextReaderIsEmptyElement(pReaderHandle->TextReader);
    OpcUa_ReturnErrorIfTrue(iResultCode < 0, OpcUa_BadInternalError);

    *a_pResult = (iResultCode == 1)? OpcUa_True: OpcUa_False;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlReader_HasAttributes
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_HasAttributes(
    struct _OpcUa_XmlReader*    a_pXmlReader,
    OpcUa_Boolean*              a_pResult)
{
    OpcUa_P_Libxml2_XmlReader*  pReaderHandle   = OpcUa_Null;
    OpcUa_Int32                 iResultCode     = 0;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlReader_IsEmptyElement");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlReader);
    OpcUa_ReturnErrorIfArgumentNull(a_pResult);

    pReaderHandle = (OpcUa_P_Libxml2_XmlReader*)a_pXmlReader->Handle;

    OpcUa_ReturnErrorIfArgumentNull(pReaderHandle);
    OpcUa_ReturnErrorIfTrue(pReaderHandle->Closed, OpcUa_BadInvalidState);

    *a_pResult = OpcUa_False;

    iResultCode = xmlTextReaderHasAttributes(pReaderHandle->TextReader);
    OpcUa_ReturnErrorIfTrue(iResultCode < 0, OpcUa_BadInternalError);

    *a_pResult = (iResultCode == 1)? OpcUa_True: OpcUa_False;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlReader_IsDefault
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_IsDefault(
    struct _OpcUa_XmlReader*    a_pXmlReader,
    OpcUa_Boolean*              a_pResult)
{
    OpcUa_P_Libxml2_XmlReader*  pReaderHandle   = OpcUa_Null;
    OpcUa_Int32                 iResultCode     = 0;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlReader_IsDefault");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlReader);
    OpcUa_ReturnErrorIfArgumentNull(a_pResult);

    pReaderHandle = (OpcUa_P_Libxml2_XmlReader*)a_pXmlReader->Handle;

    OpcUa_ReturnErrorIfArgumentNull(pReaderHandle);
    OpcUa_ReturnErrorIfTrue(pReaderHandle->Closed, OpcUa_BadInvalidState);

    *a_pResult = OpcUa_False;

    iResultCode = xmlTextReaderIsDefault(pReaderHandle->TextReader);
    OpcUa_ReturnErrorIfTrue(iResultCode < 0, OpcUa_BadInternalError);

    *a_pResult = (iResultCode == 1)? OpcUa_True: OpcUa_False;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlReader_ReadStartElement
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_ReadStartElement(
    struct _OpcUa_XmlReader*    a_pXmlReader,
    OpcUa_StringA               a_sLocalName,
    OpcUa_StringA               a_sNamespaceUri)
{
    OpcUa_P_Libxml2_XmlReader*  pReaderHandle = OpcUa_Null;
    OpcUa_Boolean               bStartElement = OpcUa_False;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlReader_ReadStartElement");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlReader);

    pReaderHandle = (OpcUa_P_Libxml2_XmlReader*)a_pXmlReader->Handle;

    OpcUa_ReturnErrorIfArgumentNull(pReaderHandle);
    OpcUa_ReturnErrorIfTrue(pReaderHandle->Closed, OpcUa_BadInvalidState);

    /* check whether the current node is a start element */
    uStatus = OpcUa_P_Libxml2_XmlReader_IsStartElement(a_pXmlReader,
                                                       a_sLocalName,
                                                       a_sNamespaceUri,
                                                       &bStartElement);
    OpcUa_ReturnErrorIfTrue(!bStartElement, OpcUa_BadInternalError);

    /* read the start element */
    OpcUa_ReturnErrorIfTrue(xmlTextReaderRead(pReaderHandle->TextReader) < 0, OpcUa_BadInternalError);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlReader_ReadEndElement
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_ReadEndElement(
    struct _OpcUa_XmlReader*    a_pXmlReader)
{
    OpcUa_P_Libxml2_XmlReader*  pReaderHandle   = OpcUa_Null;
    OpcUa_Int32                 iNodeType       = XML_READER_TYPE_NONE;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlReader_ReadEndElement");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlReader);

    pReaderHandle = (OpcUa_P_Libxml2_XmlReader*)a_pXmlReader->Handle;

    OpcUa_ReturnErrorIfArgumentNull(pReaderHandle);
    OpcUa_ReturnErrorIfTrue(pReaderHandle->Closed, OpcUa_BadInvalidState);

    uStatus = OpcUa_P_Libxml2_XmlReader_MoveToContent(a_pXmlReader, &iNodeType);
    OpcUa_ReturnErrorIfBad(uStatus);

    OpcUa_ReturnErrorIfTrue(iNodeType != XML_READER_TYPE_END_ELEMENT, OpcUa_BadInternalError);
    OpcUa_ReturnErrorIfTrue(xmlTextReaderRead(pReaderHandle->TextReader) < 0, OpcUa_BadInternalError);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlReader_GetNodeType
 *===========================================================================*/
OpcUa_Int32 OpcUa_P_Libxml2_XmlReader_GetNodeType(
    struct _OpcUa_XmlReader*    a_pXmlReader)
{
    OpcUa_P_Libxml2_XmlReader*  pReaderHandle   = OpcUa_Null;
    OpcUa_Int32                 iNodeType       = XML_READER_TYPE_NONE;

    if(a_pXmlReader != OpcUa_Null)
    {
        pReaderHandle = (OpcUa_P_Libxml2_XmlReader*)a_pXmlReader->Handle;

        if(pReaderHandle != OpcUa_Null && !pReaderHandle->Closed)
        {
            iNodeType = xmlTextReaderNodeType(pReaderHandle->TextReader);
            iNodeType = (iNodeType != -1)? iNodeType: XML_READER_TYPE_NONE;
        }
    }

    return iNodeType;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlReader_GetDepth
 *===========================================================================*/
OpcUa_Int32 OpcUa_P_Libxml2_XmlReader_GetDepth(
    struct _OpcUa_XmlReader*    a_pXmlReader)
{
    OpcUa_P_Libxml2_XmlReader*  pReaderHandle   = OpcUa_Null;
    OpcUa_Int32                 iNodeDepth      = -1;

    if(a_pXmlReader != OpcUa_Null)
    {
        pReaderHandle = (OpcUa_P_Libxml2_XmlReader*)a_pXmlReader->Handle;

        if(pReaderHandle != OpcUa_Null && !pReaderHandle->Closed)
        {
            iNodeDepth = xmlTextReaderDepth(pReaderHandle->TextReader);
        }
    }

    return iNodeDepth;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlReader_GetLocalName
 *===========================================================================*/
OpcUa_StringA OpcUa_P_Libxml2_XmlReader_GetLocalName(
    struct _OpcUa_XmlReader*    a_pXmlReader)
{
    OpcUa_P_Libxml2_XmlReader*  pReaderHandle   = OpcUa_Null;
    OpcUa_StringA sLocalName                    = "";

    if(a_pXmlReader != OpcUa_Null)
    {
        pReaderHandle = (OpcUa_P_Libxml2_XmlReader*)a_pXmlReader->Handle;

        if(pReaderHandle != OpcUa_Null && !pReaderHandle->Closed)
        {
            sLocalName = (OpcUa_StringA)xmlTextReaderConstLocalName(pReaderHandle->TextReader);
            sLocalName = (sLocalName == OpcUa_Null)? "": sLocalName;
        }
    }

    return sLocalName;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlReader_GetName
 *===========================================================================*/
OpcUa_StringA OpcUa_P_Libxml2_XmlReader_GetName(
    struct _OpcUa_XmlReader*    a_pXmlReader)
{
    OpcUa_P_Libxml2_XmlReader*  pReaderHandle   = OpcUa_Null;
    OpcUa_StringA sQualifiedName                = "";

    if(a_pXmlReader != OpcUa_Null)
    {
        pReaderHandle = (OpcUa_P_Libxml2_XmlReader*)a_pXmlReader->Handle;

        if(pReaderHandle != OpcUa_Null && !pReaderHandle->Closed)
        {
            sQualifiedName = (OpcUa_StringA)xmlTextReaderConstName(pReaderHandle->TextReader);
            sQualifiedName = (sQualifiedName == OpcUa_Null)? "": sQualifiedName;
        }
    }

    return sQualifiedName;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlReader_GetNamespaceUri
 *===========================================================================*/
OpcUa_StringA OpcUa_P_Libxml2_XmlReader_GetNamespaceUri(
    struct _OpcUa_XmlReader*    a_pXmlReader)
{
    OpcUa_P_Libxml2_XmlReader*  pReaderHandle   = OpcUa_Null;
    OpcUa_StringA               sNamespaceUri   = "";

    if(a_pXmlReader != OpcUa_Null)
    {
        pReaderHandle = (OpcUa_P_Libxml2_XmlReader*)a_pXmlReader->Handle;

        if(pReaderHandle != OpcUa_Null && !pReaderHandle->Closed)
        {
            sNamespaceUri = (OpcUa_StringA)xmlTextReaderConstNamespaceUri(pReaderHandle->TextReader);
            sNamespaceUri = (sNamespaceUri == OpcUa_Null)? "": sNamespaceUri;
        }
    }

    return sNamespaceUri;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlReader_GetPrefix
 *===========================================================================*/
OpcUa_StringA OpcUa_P_Libxml2_XmlReader_GetPrefix(
    struct _OpcUa_XmlReader*    a_pXmlReader)
{
    OpcUa_P_Libxml2_XmlReader*  pReaderHandle       = OpcUa_Null;
    OpcUa_StringA               sNamespacePrefix    = "";

    if(a_pXmlReader != OpcUa_Null)
    {
        pReaderHandle = (OpcUa_P_Libxml2_XmlReader*)a_pXmlReader->Handle;

        if(pReaderHandle != OpcUa_Null && !pReaderHandle->Closed)
        {
            sNamespacePrefix = (OpcUa_StringA)xmlTextReaderConstPrefix(pReaderHandle->TextReader);
            sNamespacePrefix = (sNamespacePrefix == OpcUa_Null)? "": sNamespacePrefix;
        }
    }

    return sNamespacePrefix;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlReader_GetValue
 *===========================================================================*/
OpcUa_StringA OpcUa_P_Libxml2_XmlReader_GetValue(
    struct _OpcUa_XmlReader*    a_pXmlReader)
{
    OpcUa_P_Libxml2_XmlReader*  pReaderHandle   = OpcUa_Null;
    OpcUa_StringA               sNodeValue      = "";

    if(a_pXmlReader != OpcUa_Null)
    {
        pReaderHandle = (OpcUa_P_Libxml2_XmlReader*)a_pXmlReader->Handle;

        if(pReaderHandle != OpcUa_Null && !pReaderHandle->Closed)
        {
            sNodeValue = (OpcUa_StringA)xmlTextReaderConstValue(pReaderHandle->TextReader);
            sNodeValue = (sNodeValue == OpcUa_Null)? "": sNodeValue;
        }
    }

    return sNodeValue;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlReader_GetAttribute
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_GetAttribute(
    struct _OpcUa_XmlReader*    a_pXmlReader,
    OpcUa_StringA               a_sAttributeName,
    OpcUa_StringA               a_sNamespaceUri,
    OpcUa_StringA               a_sAttributeValue,
    OpcUa_UInt32*               a_pValueLength)
{
    OpcUa_P_Libxml2_XmlReader*  pReaderHandle       = OpcUa_Null;
    xmlChar*                    pchAttributeValue   = OpcUa_Null;
    OpcUa_UInt32                uValueLength        = 0;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlReader_GetAttribute");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlReader);
    OpcUa_ReturnErrorIfArgumentNull(a_sAttributeName);
    OpcUa_ReturnErrorIfArgumentNull(a_pValueLength);

    pReaderHandle = (OpcUa_P_Libxml2_XmlReader*)a_pXmlReader->Handle;

    OpcUa_ReturnErrorIfArgumentNull(pReaderHandle);
    OpcUa_ReturnErrorIfTrue(pReaderHandle->Closed, OpcUa_BadInvalidState);

    a_sNamespaceUri = (xmlStrEqual((xmlChar*)a_sNamespaceUri, (xmlChar*)""))? OpcUa_Null: a_sNamespaceUri;

    pchAttributeValue = xmlTextReaderGetAttributeNs(pReaderHandle->TextReader,
                                                    (xmlChar*)a_sAttributeName,
                                                    (xmlChar*)a_sNamespaceUri);
    OpcUa_GotoErrorIfNull(pchAttributeValue, OpcUa_BadNoDataAvailable);

    uValueLength    = xmlStrlen(pchAttributeValue);

    if(a_sAttributeValue != OpcUa_Null)
    {
        OpcUa_GotoErrorIfTrue(*a_pValueLength < uValueLength + 1, OpcUa_BadInvalidArgument);

        uStatus = OpcUa_P_Memory_MemCpy(a_sAttributeValue,
                                        *a_pValueLength,
                                        pchAttributeValue,
                                        uValueLength);
        OpcUa_GotoErrorIfBad(uStatus);

        a_sAttributeValue[uValueLength] = '\0';
    }

    *a_pValueLength = uValueLength;

    xmlFree(pchAttributeValue);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    *a_pValueLength = 0;

    if(pchAttributeValue != OpcUa_Null)
    {
        xmlFree(pchAttributeValue);
    }

OpcUa_FinishErrorHandling;
}


/*============================================================================
 * OpcUa_P_Libxml2_XmlReader_Read
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_Read(
    struct _OpcUa_XmlReader*    a_pXmlReader)
{
    OpcUa_P_Libxml2_XmlReader*  pReaderHandle   = OpcUa_Null;
    OpcUa_Int32                 iResultCode     = 0;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlReader_Read");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlReader);

    pReaderHandle = (OpcUa_P_Libxml2_XmlReader*)a_pXmlReader->Handle;

    OpcUa_ReturnErrorIfArgumentNull(pReaderHandle);
    OpcUa_ReturnErrorIfTrue(pReaderHandle->Closed, OpcUa_BadInvalidState);

    iResultCode = xmlTextReaderRead(pReaderHandle->TextReader);

    OpcUa_ReturnErrorIfTrue(iResultCode  < 0, OpcUa_BadInternalError);
    OpcUa_ReturnErrorIfTrue(iResultCode == 0, OpcUa_BadNoDataAvailable);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlReader_Skip
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_Skip(
    struct _OpcUa_XmlReader*    a_pXmlReader)
{
    OpcUa_P_Libxml2_XmlReader* pReaderHandle = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlReader_Skip");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlReader);

    pReaderHandle = (OpcUa_P_Libxml2_XmlReader*)a_pXmlReader->Handle;

    OpcUa_ReturnErrorIfArgumentNull(pReaderHandle);
    OpcUa_ReturnErrorIfTrue(pReaderHandle->Closed, OpcUa_BadInvalidState);

    OpcUa_ReturnErrorIfTrue(xmlTextReaderNext(pReaderHandle->TextReader) < 0, OpcUa_BadInternalError);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlReader_Close
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Libxml2_XmlReader_Close(
    struct _OpcUa_XmlReader*    a_pXmlReader)
{
    OpcUa_P_Libxml2_XmlReader* pReaderHandle = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlReader_Close");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlReader);

    pReaderHandle = (OpcUa_P_Libxml2_XmlReader*)a_pXmlReader->Handle;

    OpcUa_ReturnErrorIfArgumentNull(pReaderHandle);
    OpcUa_ReturnErrorIfTrue(pReaderHandle->Closed, OpcUa_BadInvalidState);

    xmlFreeTextReader(pReaderHandle->TextReader);
    pReaderHandle->TextReader = OpcUa_Null;

    /* Leave the value of the pReaderHandle->Closed field as it is,
       it will be set by OpcUa_P_Libxml2_XmlReader_CloseCallback() to OpcUa_True */

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlReader_Delete
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_Libxml2_XmlReader_Delete(
    struct _OpcUa_XmlReader* a_pXmlReader)
{
OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlReader_Delete");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlReader);

    if(a_pXmlReader->Handle != OpcUa_Null)
    {
        OpcUa_P_Libxml2_XmlReader* pReaderHandle = (OpcUa_P_Libxml2_XmlReader*)a_pXmlReader->Handle;

        if(pReaderHandle->TextReader != OpcUa_Null)
        {
            xmlFreeTextReader(pReaderHandle->TextReader);
            pReaderHandle->TextReader = OpcUa_Null;
        }

        OpcUa_P_Memory_Free(a_pXmlReader->Handle);
        a_pXmlReader->Handle = OpcUa_Null;
    }

    a_pXmlReader->Handle                = OpcUa_Null;
    a_pXmlReader->MoveToContent         = OpcUa_Null;
    a_pXmlReader->MoveToElement         = OpcUa_Null;
    a_pXmlReader->MoveToFirstAttribute  = OpcUa_Null;
    a_pXmlReader->MoveToNextAttribute   = OpcUa_Null;
    a_pXmlReader->IsStartElement        = OpcUa_Null;
    a_pXmlReader->IsEmptyElement        = OpcUa_Null;
    a_pXmlReader->HasAttributes         = OpcUa_Null;
    a_pXmlReader->IsDefault             = OpcUa_Null;
    a_pXmlReader->ReadStartElement      = OpcUa_Null;
    a_pXmlReader->ReadEndElement        = OpcUa_Null;
    a_pXmlReader->GetNodeType           = OpcUa_Null;
    a_pXmlReader->GetDepth              = OpcUa_Null;
    a_pXmlReader->GetLocalName          = OpcUa_Null;
    a_pXmlReader->GetName               = OpcUa_Null;
    a_pXmlReader->GetNamespaceUri       = OpcUa_Null;
    a_pXmlReader->GetPrefix             = OpcUa_Null;
    a_pXmlReader->GetValue              = OpcUa_Null;
    a_pXmlReader->GetAttribute          = OpcUa_Null;
    a_pXmlReader->Read                  = OpcUa_Null;
    a_pXmlReader->Skip                  = OpcUa_Null;
    a_pXmlReader->Close                 = OpcUa_Null;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

#endif /* OPCUA_HAVE_XMLAPI */
