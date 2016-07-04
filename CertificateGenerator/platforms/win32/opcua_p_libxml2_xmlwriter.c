/*============================================================================
  @file opcua_p_libxml2.c

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

/* UA platform definitions */
#include <opcua_p_internal.h>

#ifdef OPCUA_HAVE_XMLAPI

/* Libxml2 headers */
#include <libxml/list.h>
#include <libxml/parser.h>
#include <libxml/xmlwriter.h>

/* UA platform definitions */
#include <opcua_p_memory.h>

/* XML writer interface */
#include <opcua_xmlwriter.h>

/* XML reader interface */
#include <opcua_xmlreader.h>

/* XML specific definitions */
#include <opcua_xmldefs.h>

/* own header */
#include <opcua_p_libxml2.h>

typedef struct _OpcUa_P_Libxml2_XmlWriter
{
    OpcUa_Boolean                       Closed;
    OpcUa_Void*                         WriteContext;
    OpcUa_XmlWriter_PfnWriteCallback*   WriteCallback;
    OpcUa_XmlWriter_PfnCloseCallback*   CloseCallback;
    OpcUa_Int32                         ElementDepth;
    xmlOutputBufferPtr                  OutputBuffer;
    xmlTextWriterPtr                    TextWriter;
    xmlListPtr                          NamespaceStack;
} OpcUa_P_Libxml2_XmlWriter;

/*============================================================================
 * OpcUa_P_Libxml2_XmlWriter_WriteCallback
 *===========================================================================*/
static OpcUa_Int OPCUA_CDECL OpcUa_P_Libxml2_XmlWriter_WriteCallback(
    OpcUa_Void*         a_pCallbackContext,
    const OpcUa_CharA*  a_pWriteBuffer,
    OpcUa_Int           a_iBufferLength)
{
    OpcUa_P_Libxml2_XmlWriter* pWriterHandle = OpcUa_Null;

    OpcUa_ReturnErrorIfNull(a_pCallbackContext, -1);
    OpcUa_ReturnErrorIfNull(a_pWriteBuffer, -1);

    pWriterHandle = (OpcUa_P_Libxml2_XmlWriter*)((OpcUa_XmlWriter*)a_pCallbackContext)->Handle;

    OpcUa_ReturnErrorIfNull(pWriterHandle, -1);
    OpcUa_ReturnErrorIfTrue(pWriterHandle->Closed, -1);

    if(pWriterHandle->WriteCallback != OpcUa_Null)
    {
        if(OpcUa_IsBad(pWriterHandle->WriteCallback((OpcUa_XmlWriter*)a_pCallbackContext,
                                                    pWriterHandle->WriteContext,
                                                    (OpcUa_Byte*)a_pWriteBuffer,
                                                    (OpcUa_UInt32)a_iBufferLength)))
        {
            return -1;
        }
    }

    return a_iBufferLength;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlWriter_CloseCallback
 *===========================================================================*/
static OpcUa_Int OPCUA_CDECL OpcUa_P_Libxml2_XmlWriter_CloseCallback(
    OpcUa_Void*         a_pCallbackContext)
{
    OpcUa_P_Libxml2_XmlWriter* pWriterHandle = OpcUa_Null;

    OpcUa_ReturnErrorIfNull(a_pCallbackContext, -1);

    pWriterHandle = (OpcUa_P_Libxml2_XmlWriter*)((OpcUa_XmlWriter*)a_pCallbackContext)->Handle;

    OpcUa_ReturnErrorIfNull(pWriterHandle, -1);
    OpcUa_ReturnErrorIfTrue(pWriterHandle->Closed, -1);

    pWriterHandle->Closed = OpcUa_True;

    if(pWriterHandle->CloseCallback != OpcUa_Null)
    {
        if(OpcUa_IsBad(pWriterHandle->CloseCallback((OpcUa_XmlWriter*)a_pCallbackContext,
                                                    pWriterHandle->WriteContext)))
        {
            return -1;
        }
    }

    return 0;
}

typedef struct _OpcUa_P_Libxml2_Namespace
{
    OpcUa_StringA NamespacePrefix;
    OpcUa_StringA NamespaceUri;
    OpcUa_Int32   ElementDepth;
} OpcUa_P_Libxml2_Namespace;


/*============================================================================
 * OpcUa_P_Libxml2_XmlWriter_PushNamespace
 *===========================================================================*/
static OpcUa_StatusCode OpcUa_P_Libxml2_XmlWriter_PushNamespace(
    struct _OpcUa_XmlWriter*    a_pXmlWriter,
    OpcUa_StringA               a_sNamespacePrefix,
    OpcUa_StringA               a_sNamespaceUri)
{
    OpcUa_P_Libxml2_XmlWriter*  pWriterHandle   = OpcUa_Null;
    OpcUa_P_Libxml2_Namespace*   pNewNamespace   = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlWriter_PushNamespace");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter);
    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter->Handle);
    OpcUa_ReturnErrorIfArgumentNull(a_sNamespaceUri);

    pWriterHandle = (OpcUa_P_Libxml2_XmlWriter*)a_pXmlWriter->Handle;

    pNewNamespace = (OpcUa_P_Libxml2_Namespace*)OpcUa_P_Memory_Alloc(sizeof(OpcUa_P_Libxml2_Namespace));
    OpcUa_GotoErrorIfAllocFailed(pNewNamespace);

    pNewNamespace->NamespacePrefix  = a_sNamespacePrefix;
    pNewNamespace->NamespaceUri     = a_sNamespaceUri;
    pNewNamespace->ElementDepth     = pWriterHandle->ElementDepth;

    uStatus = xmlListPushFront(pWriterHandle->NamespaceStack, pNewNamespace);
    OpcUa_GotoErrorIfBad(uStatus);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(pNewNamespace != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(pNewNamespace);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlWriter_PopNamespaces
 *===========================================================================*/
static OpcUa_StatusCode OpcUa_P_Libxml2_XmlWriter_PopNamespaces(
    struct _OpcUa_XmlWriter*    a_pXmlWriter,
    OpcUa_Int32                 a_iElementDepth)
{
    OpcUa_P_Libxml2_XmlWriter*  pWriterHandle       = OpcUa_Null;
    OpcUa_P_Libxml2_Namespace*   pCurrentNamespace   = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlWriter_PopNamespaces");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter);
    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter->Handle);

    pWriterHandle = (OpcUa_P_Libxml2_XmlWriter*)a_pXmlWriter->Handle;

    pCurrentNamespace = (OpcUa_P_Libxml2_Namespace*)xmlLinkGetData(xmlListFront(pWriterHandle->NamespaceStack));

    while(    pCurrentNamespace != OpcUa_Null
           && pCurrentNamespace->ElementDepth > a_iElementDepth)
    {
        OpcUa_P_Memory_Free(pCurrentNamespace);
        xmlListPopFront(pWriterHandle->NamespaceStack);
        pCurrentNamespace = (OpcUa_P_Libxml2_Namespace*)xmlLinkGetData(xmlListFront(pWriterHandle->NamespaceStack));
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

typedef struct _OpcUa_P_Libxml2_XmlWriter_ListWalkerContext
{
    OpcUa_StringA               NamespaceUri;
    OpcUa_P_Libxml2_Namespace*  FoundNamespace;
} OpcUa_P_Libxml2_XmlWriter_ListWalkerContext;

/*============================================================================
 * OpcUa_P_Libxml2_XmlWriter_ListWalkerCallback
 *===========================================================================*/
static OpcUa_Int OpcUa_P_Libxml2_XmlWriter_ListWalkerCallback(
    const OpcUa_Void* a_pElementData,
    const OpcUa_Void* a_pUserContext)
{
    OpcUa_P_Libxml2_Namespace*                   pCurrentNamespace   = OpcUa_Null;
    OpcUa_P_Libxml2_XmlWriter_ListWalkerContext* pWalkerContext      = OpcUa_Null;

    OpcUa_ReturnErrorIfNull(a_pElementData, 0);
    OpcUa_ReturnErrorIfNull(a_pUserContext, 0);

    pCurrentNamespace   = (OpcUa_P_Libxml2_Namespace*)a_pElementData;
    pWalkerContext      = (OpcUa_P_Libxml2_XmlWriter_ListWalkerContext*)a_pUserContext;

    if(xmlStrEqual((xmlChar*)pCurrentNamespace->NamespaceUri,
                   (xmlChar*)pWalkerContext->NamespaceUri))
    {
        pWalkerContext->FoundNamespace = pCurrentNamespace;
        return 0;
    }

    return 1;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlWriter_FindNamespace
 *===========================================================================*/
static OpcUa_StatusCode OpcUa_P_Libxml2_XmlWriter_FindNamespace(
    struct _OpcUa_XmlWriter*    a_pXmlWriter,
    OpcUa_StringA               a_sNamespaceUri,
    OpcUa_P_Libxml2_Namespace** a_ppFoundNamespace)
{
    OpcUa_P_Libxml2_XmlWriter*                  pWriterHandle   = OpcUa_Null;
    OpcUa_P_Libxml2_XmlWriter_ListWalkerContext context         = {OpcUa_Null, OpcUa_Null};

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlWriter_FindNamespace");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter);
    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter->Handle);
    OpcUa_ReturnErrorIfArgumentNull(a_sNamespaceUri);
    OpcUa_ReturnErrorIfArgumentNull(a_ppFoundNamespace);

    pWriterHandle = (OpcUa_P_Libxml2_XmlWriter*)a_pXmlWriter->Handle;

    context.NamespaceUri    = a_sNamespaceUri;
    context.FoundNamespace  = OpcUa_Null;

    *a_ppFoundNamespace = OpcUa_Null;

    xmlListWalk(pWriterHandle->NamespaceStack,
                OpcUa_P_Libxml2_XmlWriter_ListWalkerCallback,
                &context);

    OpcUa_ReturnErrorIfNull(context.FoundNamespace, OpcUa_GoodNoData);

    *a_ppFoundNamespace = context.FoundNamespace;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    *a_ppFoundNamespace = OpcUa_Null;

OpcUa_FinishErrorHandling;

}

/*============================================================================
 * OpcUa_P_Libxml2_XmlWriter_LookupPrefix
 *===========================================================================*/
static OpcUa_StatusCode OpcUa_P_Libxml2_XmlWriter_LookupPrefix(
    struct _OpcUa_XmlWriter*    a_pXmlWriter,
    OpcUa_StringA               a_sNamespaceUri,
    OpcUa_StringA*              a_pNamespacePrefix)
{
    OpcUa_P_Libxml2_XmlWriter*  pWriterHandle   = OpcUa_Null;
    OpcUa_P_Libxml2_Namespace*  pFoundNamespace = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlWriter_LookupPrefix");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter);
    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter->Handle);
    OpcUa_ReturnErrorIfArgumentNull(a_sNamespaceUri);
    OpcUa_ReturnErrorIfArgumentNull(a_pNamespacePrefix);

    pWriterHandle = (OpcUa_P_Libxml2_XmlWriter*)a_pXmlWriter->Handle;

    *a_pNamespacePrefix = OpcUa_Null;

    if(OpcUa_StrCmpA(a_sNamespaceUri, OPCUA_URI_XML_NAMESPACE) == 0)
    {
        *a_pNamespacePrefix = OPCUA_NAMESPACE_PREFIX_XMLNS;
        OpcUa_ReturnStatusCode;
    }

    if(OpcUa_StrCmpA(a_sNamespaceUri, OPCUA_URI_XML) == 0)
    {
        *a_pNamespacePrefix = OPCUA_NAMESPACE_PREFIX_XML;
        OpcUa_ReturnStatusCode;
    }

    uStatus = OpcUa_P_Libxml2_XmlWriter_FindNamespace(a_pXmlWriter, a_sNamespaceUri, &pFoundNamespace);
    OpcUa_ReturnErrorIfBad(uStatus);

    if(pFoundNamespace != OpcUa_Null)
    {
        *a_pNamespacePrefix = pFoundNamespace->NamespacePrefix;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    *a_pNamespacePrefix = OpcUa_Null;

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlWriter_Create
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_Libxml2_XmlWriter_Create(
    OpcUa_Void*                         a_pWriteContext,
    OpcUa_XmlWriter_PfnWriteCallback*   a_pWriteCallback,
    OpcUa_XmlWriter_PfnCloseCallback*   a_pCloseCallback,
    struct _OpcUa_XmlWriter*            a_pXmlWriter)
{
    OpcUa_P_Libxml2_XmlWriter* pWriterHandle = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlWriter_Create");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter);

    pWriterHandle = (OpcUa_P_Libxml2_XmlWriter*)OpcUa_P_Memory_Alloc(sizeof(OpcUa_P_Libxml2_XmlWriter));
    OpcUa_GotoErrorIfAllocFailed(pWriterHandle);

    pWriterHandle->Closed           = OpcUa_False;
    pWriterHandle->WriteContext     = a_pWriteContext;
    pWriterHandle->WriteCallback    = a_pWriteCallback;
    pWriterHandle->CloseCallback    = a_pCloseCallback;
    pWriterHandle->ElementDepth     = -1;

    /* Create an instance of a custom I/O interface */
    pWriterHandle->OutputBuffer     = xmlOutputBufferCreateIO(OpcUa_P_Libxml2_XmlWriter_WriteCallback,
                                                              OpcUa_P_Libxml2_XmlWriter_CloseCallback,
                                                              a_pXmlWriter,
                                                              OpcUa_Null);
    OpcUa_GotoErrorIfNull(pWriterHandle->OutputBuffer, OpcUa_BadInternalError);

    /* Create an instance of the TextWriter connected to a custom I/O interface */
    pWriterHandle->TextWriter       = xmlNewTextWriter(pWriterHandle->OutputBuffer);
    OpcUa_GotoErrorIfNull(pWriterHandle->OutputBuffer, OpcUa_BadInternalError);

    /* Create a namespace stack */
    pWriterHandle->NamespaceStack   = xmlListCreate(OpcUa_Null, OpcUa_Null);
    OpcUa_GotoErrorIfNull(pWriterHandle->NamespaceStack, OpcUa_BadInternalError);

    a_pXmlWriter->Handle            = pWriterHandle;
    a_pXmlWriter->StartElement      = OpcUa_P_Libxml2_XmlWriter_StartElement;
    a_pXmlWriter->EndElement        = OpcUa_P_Libxml2_XmlWriter_EndElement;
    a_pXmlWriter->WriteAttribute    = OpcUa_P_Libxml2_XmlWriter_WriteAttribute;
    a_pXmlWriter->WriteString       = OpcUa_P_Libxml2_XmlWriter_WriteString;
    a_pXmlWriter->WriteFormatted    = OpcUa_P_Libxml2_XmlWriter_WriteFormatted;
    a_pXmlWriter->WriteRaw          = OpcUa_P_Libxml2_XmlWriter_WriteRaw;
    a_pXmlWriter->WriteNode         = OpcUa_P_Libxml2_XmlWriter_WriteNode;
    a_pXmlWriter->Flush             = OpcUa_P_Libxml2_XmlWriter_Flush;
    a_pXmlWriter->Close             = OpcUa_P_Libxml2_XmlWriter_Close;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(pWriterHandle != OpcUa_Null)
    {
        if(pWriterHandle->TextWriter != OpcUa_Null)
        {
            xmlFreeTextWriter(pWriterHandle->TextWriter);

            /* xmlFreeTextWriter() calls xmlOutputBufferClose(), thus
               there is no need to call xmlOutputBufferClose() twice */
            pWriterHandle->OutputBuffer = OpcUa_Null;
        }

        if(pWriterHandle->OutputBuffer != OpcUa_Null)
        {
            xmlOutputBufferClose(pWriterHandle->OutputBuffer);
        }

        if (pWriterHandle->NamespaceStack != OpcUa_Null)
        {
            xmlListDelete(pWriterHandle->NamespaceStack);
        }
    }

    OpcUa_P_Memory_Free(pWriterHandle);
    a_pXmlWriter->Handle = OpcUa_Null;

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlWriter_StartElement
 *===========================================================================*/

/* NOTE : in spite of similarity between the interfaces of .Net Framework System.Xml.XmlWriter
 *        and the Libxml2 xmlTextWriter these writers behave differently. Let us consider two
 *        code snippets.
 *
 * 1. The following C# .Net Framework snippet
 *
 * writer.WriteStartElement(null, "LocalizedText", "http://opcfoundation.org/UA/2008/02/Types.xsd");
 * writer.WriteAttributeString("xmlns", "xsi", null, "http://www.w3.org/2001/XMLSchema-instance");
 * writer.WriteStartElement(null, "Locale", "http://opcfoundation.org/UA/2008/02/Types.xsd");
 * writer.WriteAttributeString("xsi", "nil", "http://www.w3.org/2001/XMLSchema-instance", "true");
 * writer.WriteEndElement();
 * writer.WriteStartElement(null, "Text", "http://opcfoundation.org/UA/2008/02/Types.xsd");
 * writer.WriteString("Hello World!");
 * writer.WriteEndElement();
 * writer.WriteEndElement();
 *
 * generates the XML stated below
 *
 * <LocalizedText xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 *                xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd">
 *      <Locale xsi:nil="true" />
 *      <Text>Hello World!</Text>
 * </LocalizedText>
 *
 * 2. But the similar C snippet that uses the Libxml2 xmlTextWriter
 *
 * xmlTextWriterStartElementNS(pXmlWriter, NULL, "LocalizedText", "http://opcfoundation.org/UA/2008/02/Types.xsd");
 * xmlTextWriterWriteAttributeNS(pXmlWriter, "xmlns", "xsi", NULL, "http://www.w3.org/2001/XMLSchema-instance");
 * xmlTextWriterStartElementNS(pXmlWriter, NULL, "Locale", "http://opcfoundation.org/UA/2008/02/Types.xsd");
 * xmlTextWriterWriteAttributeNS(pXmlWriter, "xsi", "nil", "http://www.w3.org/2001/XMLSchema-instance", "true");
 * xmlTextWriterEndElement(pXmlWriter);
 * xmlTextWriterStartElementNS(pXmlWriter, NULL, "Text", "http://opcfoundation.org/UA/2008/02/Types.xsd");
 * xmlTextWriterWriteString(pXmlWriter, "Hello World!");
 * xmlTextWriterEndElement(pXmlWriter);
 * xmlTextWriterEndElement(pXmlWriter);
 *
 * generates the quite different XML
 *
 * <LocalizedText xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 *                xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd">
 *      <Locale xsi:nil="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 *              xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd" />
 *      <Text xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd">Hello World!</Text>
 * </LocalizedText>
 *
 * The last XML is also valid but it contains a lot of unnecessary namespace declarations.
 * It seems that the xmlTextWriter does not track the namespace scope. The difference between
 * the XmlWriter implementations is taken into account and the OpcUa_XmlWriter provides the
 * necessary workarounds.
 */
OpcUa_StatusCode OpcUa_P_Libxml2_XmlWriter_StartElement(
    struct _OpcUa_XmlWriter*    a_pXmlWriter,
    OpcUa_StringA               a_sNamespacePrefix,
    OpcUa_StringA               a_sElementName,
    OpcUa_StringA               a_sNamespaceUri)
{
    OpcUa_P_Libxml2_XmlWriter*  pWriterHandle       = OpcUa_Null;
    OpcUa_StringA               sNamespacePrefix    = a_sNamespacePrefix;
    OpcUa_StringA               sNamespaceUri       = a_sNamespaceUri;
    OpcUa_Boolean               bKnownNamespace     = OpcUa_False;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlWriter_StartElement");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter);
    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter->Handle);
    OpcUa_ReturnErrorIfArgumentNull(a_sElementName);

    pWriterHandle = (OpcUa_P_Libxml2_XmlWriter*)a_pXmlWriter->Handle;

    OpcUa_ReturnErrorIfArgumentNull(pWriterHandle);
    OpcUa_ReturnErrorIfTrue(pWriterHandle->Closed, OpcUa_BadInvalidState);

    if(a_sNamespaceUri != OpcUa_Null)
    {
        /* check whether the namespace is already in scope */
        uStatus = OpcUa_P_Libxml2_XmlWriter_LookupPrefix(a_pXmlWriter, a_sNamespaceUri, &sNamespacePrefix);
        OpcUa_GotoErrorIfBad(uStatus);

        if(uStatus != OpcUa_GoodNoData)
        {
            if(    a_sNamespacePrefix == OpcUa_Null
                || xmlStrEqual((xmlChar*)a_sNamespacePrefix,
                               (xmlChar*)sNamespacePrefix))
            {
                bKnownNamespace = OpcUa_True;

                /* namespace is already in scope, prevent Libxml2
                   from adding the namespace declaration  */
                sNamespaceUri = OpcUa_Null;
            }
        }
        else
        {
            /* namespace isn't in scope, the new namespace
               declaration will be added by Libxml2 */
            sNamespacePrefix = a_sNamespacePrefix;
            sNamespaceUri    = a_sNamespaceUri;
        }
    }

    sNamespacePrefix = (xmlStrEqual((xmlChar*)sNamespacePrefix, (xmlChar*)""))? OpcUa_Null: sNamespacePrefix;
    sNamespaceUri    = (xmlStrEqual((xmlChar*)sNamespaceUri, (xmlChar*)""))?    OpcUa_Null: sNamespaceUri;

    OpcUa_ReturnErrorIfTrue(xmlTextWriterStartElementNS(pWriterHandle->TextWriter,
                                                        (xmlChar*)sNamespacePrefix,
                                                        (xmlChar*)a_sElementName,
                                                        (xmlChar*)sNamespaceUri) < 0,
                            OpcUa_BadInternalError);

    pWriterHandle->ElementDepth++;

    if(a_sNamespaceUri != OpcUa_Null && !bKnownNamespace)
    {
        /* push the namespace onto the namespace stack */
        uStatus = OpcUa_P_Libxml2_XmlWriter_PushNamespace(a_pXmlWriter, a_sNamespacePrefix, a_sNamespaceUri);
        OpcUa_GotoErrorIfBad(uStatus);
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlWriter_EndElement
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Libxml2_XmlWriter_EndElement(
    struct _OpcUa_XmlWriter* a_pXmlWriter)
{
    OpcUa_P_Libxml2_XmlWriter* pWriterHandle = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlWriter_EndElement");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter);
    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter->Handle);

    pWriterHandle = (OpcUa_P_Libxml2_XmlWriter*)a_pXmlWriter->Handle;

    OpcUa_ReturnErrorIfArgumentNull(pWriterHandle);
    OpcUa_ReturnErrorIfTrue(pWriterHandle->Closed, OpcUa_BadInvalidState);

    uStatus = OpcUa_P_Libxml2_XmlWriter_PopNamespaces(a_pXmlWriter, --(pWriterHandle->ElementDepth));
    OpcUa_GotoErrorIfBad(uStatus);

    OpcUa_ReturnErrorIfTrue(xmlTextWriterEndElement(pWriterHandle->TextWriter) < 0,
                            OpcUa_BadInternalError);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlWriter_WriteAttribute
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Libxml2_XmlWriter_WriteAttribute(
    struct _OpcUa_XmlWriter*    a_pXmlWriter,
    OpcUa_StringA               a_sNamespacePrefix,
    OpcUa_StringA               a_sAttributeName,
    OpcUa_StringA               a_sNamespaceUri,
    OpcUa_StringA               a_sAttributeValue)
{
    OpcUa_P_Libxml2_XmlWriter*  pWriterHandle       = OpcUa_Null;
    OpcUa_StringA               sNamespacePrefix    = a_sNamespacePrefix;
    OpcUa_StringA               sNamespaceUri       = a_sNamespaceUri;
    OpcUa_Boolean               bKnownNamespace     = OpcUa_False;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_XmlWriter_WriteAttribute");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter);
    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter->Handle);
    OpcUa_ReturnErrorIfArgumentNull(a_sAttributeName);

    pWriterHandle = (OpcUa_P_Libxml2_XmlWriter*)a_pXmlWriter->Handle;

    OpcUa_ReturnErrorIfArgumentNull(pWriterHandle);
    OpcUa_ReturnErrorIfTrue(pWriterHandle->Closed, OpcUa_BadInvalidState);

    if(a_sNamespaceUri != OpcUa_Null)
    {
        /* check whether the namespace is already in scope */
        uStatus = OpcUa_P_Libxml2_XmlWriter_LookupPrefix(a_pXmlWriter, a_sNamespaceUri, &sNamespacePrefix);
        OpcUa_GotoErrorIfBad(uStatus);

        if(uStatus != OpcUa_GoodNoData)
        {
            if(    a_sNamespacePrefix == OpcUa_Null
                || xmlStrEqual((xmlChar*)a_sNamespacePrefix,
                               (xmlChar*)sNamespacePrefix))
            {
                bKnownNamespace = OpcUa_True;

                /* namespace is already in scope, prevent Libxml2
                   from adding the namespace declaration  */
                sNamespaceUri = OpcUa_Null;
            }
        }
        else
        {
            /* namespace isn't in scope, the new namespace
               declaration will be added by Libxml2 */
            sNamespacePrefix = a_sNamespacePrefix;
            sNamespaceUri    = a_sNamespaceUri;
        }
    }

    /* if the default namespace is being defined, check whether the
       start element already defines the same default namespace */
    if(xmlStrEqual((xmlChar*)a_sAttributeName, (xmlChar*)OPCUA_NAMESPACE_PREFIX_XMLNS))
    {
        OpcUa_P_Libxml2_Namespace* pFoundNamespace = OpcUa_Null;

        uStatus = OpcUa_P_Libxml2_XmlWriter_FindNamespace(a_pXmlWriter, a_sAttributeValue, &pFoundNamespace);
        OpcUa_GotoErrorIfBad(uStatus);

        if(pFoundNamespace != OpcUa_Null)
        {
            if(    pFoundNamespace->ElementDepth == pWriterHandle->ElementDepth
                && (    pFoundNamespace->NamespacePrefix == OpcUa_Null
                     || OpcUa_StrCmpA(pFoundNamespace->NamespacePrefix, "") == 0))
            {
                /* default namespace is already defined inside the start element,
                   prevent Libxml2 from adding the namespace declaration */
                OpcUa_ReturnStatusCode;
            }
        }
    }

    sNamespacePrefix = (xmlStrEqual((xmlChar*)sNamespacePrefix, (xmlChar*)""))? OpcUa_Null: sNamespacePrefix;
    sNamespaceUri    = (xmlStrEqual((xmlChar*)sNamespaceUri, (xmlChar*)""))?    OpcUa_Null: sNamespaceUri;

    OpcUa_ReturnErrorIfTrue(xmlTextWriterWriteAttributeNS(pWriterHandle->TextWriter,
                                                          (xmlChar*)sNamespacePrefix,
                                                          (xmlChar*)a_sAttributeName,
                                                          (xmlChar*)sNamespaceUri,
                                                          (xmlChar*)a_sAttributeValue) < 0,
                            OpcUa_BadInternalError);

    /* if there is a namespace declared in one of possible ways
       then push it onto the namespace stack */
    if(xmlStrEqual((xmlChar*)a_sNamespacePrefix, (xmlChar*)OPCUA_NAMESPACE_PREFIX_XMLNS))
    {
        if(    a_sAttributeValue != OpcUa_Null
            && (    a_sNamespaceUri == OpcUa_Null
                 || OpcUa_StrCmpA(a_sNamespaceUri, OPCUA_URI_XML_NAMESPACE) == 0))
        {
            uStatus = OpcUa_P_Libxml2_XmlWriter_PushNamespace(a_pXmlWriter, a_sAttributeName, a_sAttributeValue);
            OpcUa_GotoErrorIfBad(uStatus);
        }
    }

    else if(xmlStrEqual((xmlChar*)a_sAttributeName, (xmlChar*)OPCUA_NAMESPACE_PREFIX_XMLNS))
    {
        if((a_sNamespacePrefix == OpcUa_Null) && (a_sAttributeValue != OpcUa_Null))
        {
            uStatus = OpcUa_P_Libxml2_XmlWriter_PushNamespace(a_pXmlWriter, OpcUa_Null, a_sAttributeValue);
            OpcUa_GotoErrorIfBad(uStatus);
        }
    }

    else if(a_sNamespaceUri != OpcUa_Null && !bKnownNamespace)
    {
        uStatus = OpcUa_P_Libxml2_XmlWriter_PushNamespace(a_pXmlWriter, a_sNamespacePrefix, a_sNamespaceUri);
        OpcUa_GotoErrorIfBad(uStatus);
    }

    uStatus = OpcUa_Good;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlWriter_WriteString
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Libxml2_XmlWriter_WriteString(
    struct _OpcUa_XmlWriter*    a_pXmlWriter,
    OpcUa_StringA               a_sValue)
{
    OpcUa_P_Libxml2_XmlWriter* pWriterHandle = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlWriter_WriteString");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter);
    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter->Handle);
    OpcUa_ReturnErrorIfArgumentNull(a_sValue);

    pWriterHandle = (OpcUa_P_Libxml2_XmlWriter*)a_pXmlWriter->Handle;

    OpcUa_ReturnErrorIfArgumentNull(pWriterHandle);
    OpcUa_ReturnErrorIfTrue(pWriterHandle->Closed, OpcUa_BadInvalidState);

    OpcUa_ReturnErrorIfTrue(xmlTextWriterWriteString(pWriterHandle->TextWriter,
                                                     (xmlChar*)a_sValue) < 0,
                            OpcUa_BadInternalError);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlWriter_WriteFormatted
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Libxml2_XmlWriter_WriteFormatted(
    struct _OpcUa_XmlWriter*    a_pXmlWriter,
    OpcUa_StringA               a_sFormat,
    OpcUa_P_VA_List             a_pArguments)
{
    OpcUa_P_Libxml2_XmlWriter* pWriterHandle = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlWriter_WriteFormatted");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter);
    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter->Handle);

    pWriterHandle = (OpcUa_P_Libxml2_XmlWriter*)a_pXmlWriter->Handle;

    OpcUa_ReturnErrorIfArgumentNull(pWriterHandle);
    OpcUa_ReturnErrorIfTrue(pWriterHandle->Closed, OpcUa_BadInvalidState);

    OpcUa_ReturnErrorIfTrue(xmlTextWriterWriteVFormatString(pWriterHandle->TextWriter,
                                                            a_sFormat,
                                                            a_pArguments) < 0,
                            OpcUa_BadInternalError);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlWriter_WriteRaw
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Libxml2_XmlWriter_WriteRaw(
    struct _OpcUa_XmlWriter*    a_pXmlWriter,
    OpcUa_Byte*                 a_pRawData,
    OpcUa_UInt32                a_uDataLength)
{
    OpcUa_P_Libxml2_XmlWriter* pWriterHandle = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlWriter_WriteRaw");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter);
    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter->Handle);
    OpcUa_ReturnErrorIfTrue(a_uDataLength > 0 && a_pRawData == OpcUa_Null,
                            OpcUa_BadInvalidArgument);

    pWriterHandle = (OpcUa_P_Libxml2_XmlWriter*)a_pXmlWriter->Handle;

    OpcUa_ReturnErrorIfArgumentNull(pWriterHandle);
    OpcUa_ReturnErrorIfTrue(pWriterHandle->Closed, OpcUa_BadInvalidState);

    if(a_pRawData != OpcUa_Null)
    {
        OpcUa_ReturnErrorIfTrue(xmlTextWriterWriteRawLen(pWriterHandle->TextWriter,
                                                         (xmlChar*)a_pRawData,
                                                         a_uDataLength),
                                OpcUa_BadInternalError);
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlWriter_WriteEntityReference
 *===========================================================================*/
static OpcUa_StatusCode OpcUa_P_Libxml2_XmlWriter_WriteEntityReference(
    struct _OpcUa_XmlWriter*    a_pXmlWriter,
    OpcUa_StringA               a_sReferenceName)
{
    OpcUa_P_Libxml2_XmlWriter*  pWriterHandle = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlWriter_WriteAttributes");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter);
    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter->Handle);
    OpcUa_ReturnErrorIfArgumentNull(a_sReferenceName);

    pWriterHandle = (OpcUa_P_Libxml2_XmlWriter*)a_pXmlWriter->Handle;

    OpcUa_ReturnErrorIfArgumentNull(pWriterHandle);
    OpcUa_ReturnErrorIfTrue(pWriterHandle->Closed, OpcUa_BadInvalidState);

    OpcUa_ReturnErrorIfTrue(xmlTextWriterWriteRawLen(pWriterHandle->TextWriter,
                                                     (OpcUa_Byte*)"&",
                                                     1),
                            OpcUa_BadInternalError);

    OpcUa_ReturnErrorIfTrue(xmlTextWriterWriteRawLen(pWriterHandle->TextWriter,
                                                     (OpcUa_Byte*)a_sReferenceName,
                                                     OpcUa_StrLenA(a_sReferenceName)),
                            OpcUa_BadInternalError);


    OpcUa_ReturnErrorIfTrue(xmlTextWriterWriteRawLen(pWriterHandle->TextWriter,
                                                     (OpcUa_Byte*)";",
                                                     1),
                            OpcUa_BadInternalError);



OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlWriter_WriteAttributes
 *===========================================================================*/
static OpcUa_StatusCode OpcUa_P_Libxml2_XmlWriter_WriteAttributes(
    struct _OpcUa_XmlWriter*    a_pXmlWriter,
    struct _OpcUa_XmlReader*    a_pXmlReader)
{
    OpcUa_P_Libxml2_XmlWriter*  pWriterHandle       = OpcUa_Null;
    OpcUa_Int32                 iNodeType           = OpcUa_XmlReader_NodeType_None;
    OpcUa_Boolean               bDefaultAttribute   = OpcUa_False;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlWriter_WriteAttributes");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter);
    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter->Handle);
    OpcUa_ReturnErrorIfArgumentNull(a_pXmlReader);

    pWriterHandle = (OpcUa_P_Libxml2_XmlWriter*)a_pXmlWriter->Handle;

    OpcUa_ReturnErrorIfArgumentNull(pWriterHandle);
    OpcUa_ReturnErrorIfTrue(pWriterHandle->Closed, OpcUa_BadInvalidState);

    iNodeType = OpcUa_P_Libxml2_XmlReader_GetNodeType(a_pXmlReader);

    if(    iNodeType == OpcUa_XmlReader_NodeType_Element
        || iNodeType == OpcUa_XmlReader_NodeType_XmlDeclaration)
    {
        uStatus = OpcUa_P_Libxml2_XmlReader_MoveToFirstAttribute(a_pXmlReader);
        OpcUa_GotoErrorIfTrue(OpcUa_IsBad(uStatus) && uStatus != OpcUa_BadNoDataAvailable, uStatus);

        if(OpcUa_IsGood(uStatus))
        {
            uStatus = OpcUa_P_Libxml2_XmlWriter_WriteAttributes(a_pXmlWriter, a_pXmlReader);
            OpcUa_GotoErrorIfBad(uStatus);

            return OpcUa_P_Libxml2_XmlReader_MoveToElement(a_pXmlReader);
        }

        uStatus = (uStatus != OpcUa_BadNoDataAvailable)? uStatus: OpcUa_Good;
        OpcUa_ReturnStatusCode;
    }

    OpcUa_GotoErrorIfTrue(iNodeType != OpcUa_XmlReader_NodeType_Attribute, OpcUa_BadInvalidState);

    for( ; ; )
    {
        uStatus = OpcUa_P_Libxml2_XmlReader_IsDefault(a_pXmlReader, &bDefaultAttribute);
        OpcUa_GotoErrorIfBad(uStatus);

        if(!bDefaultAttribute)
        {
            uStatus = OpcUa_P_Libxml2_XmlWriter_WriteAttribute(
                a_pXmlWriter,
                OpcUa_P_Libxml2_XmlReader_GetPrefix(a_pXmlReader),
                OpcUa_P_Libxml2_XmlReader_GetLocalName(a_pXmlReader),
                OpcUa_P_Libxml2_XmlReader_GetNamespaceUri(a_pXmlReader),
                OpcUa_P_Libxml2_XmlReader_GetValue(a_pXmlReader));
            OpcUa_GotoErrorIfBad(uStatus);
        }

        uStatus = OpcUa_P_Libxml2_XmlReader_MoveToNextAttribute(a_pXmlReader);
        OpcUa_GotoErrorIfTrue(OpcUa_IsBad(uStatus) && uStatus != OpcUa_BadNoDataAvailable, uStatus);

        if(uStatus == OpcUa_BadNoDataAvailable)
        {
            uStatus = OpcUa_Good;
            break;
        }
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}


/*============================================================================
 * OpcUa_P_Libxml2_XmlWriter_WriteNode
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Libxml2_XmlWriter_WriteNode(
    struct _OpcUa_XmlWriter*    a_pXmlWriter,
    struct _OpcUa_XmlReader*    a_pXmlReader)
{
    OpcUa_P_Libxml2_XmlWriter* pWriterHandle    = OpcUa_Null;
    OpcUa_Int32                iNodeDepth       = -1;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlWriter_WriteNode");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter);
    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter->Handle);
    OpcUa_ReturnErrorIfArgumentNull(a_pXmlReader);

    pWriterHandle = (OpcUa_P_Libxml2_XmlWriter*)a_pXmlWriter->Handle;

    OpcUa_ReturnErrorIfArgumentNull(pWriterHandle);
    OpcUa_ReturnErrorIfTrue(pWriterHandle->Closed, OpcUa_BadInvalidState);

    if(OpcUa_P_Libxml2_XmlReader_GetNodeType(a_pXmlReader) != OpcUa_XmlReader_NodeType_None)
    {
        iNodeDepth = OpcUa_P_Libxml2_XmlReader_GetDepth(a_pXmlReader);
    }

    for( ; ; )
    {
        OpcUa_StringA sNamespacePrefix  = OpcUa_P_Libxml2_XmlReader_GetPrefix(a_pXmlReader);
        OpcUa_StringA sNamespaceUri     = OpcUa_P_Libxml2_XmlReader_GetNamespaceUri(a_pXmlReader);
        OpcUa_StringA sLocalName        = OpcUa_P_Libxml2_XmlReader_GetLocalName(a_pXmlReader);
        OpcUa_StringA sQualifiedName    = OpcUa_P_Libxml2_XmlReader_GetName(a_pXmlReader);
        OpcUa_StringA sNodeValue        = OpcUa_P_Libxml2_XmlReader_GetValue(a_pXmlReader);

        switch(OpcUa_P_Libxml2_XmlReader_GetNodeType(a_pXmlReader))
        {
            case OpcUa_XmlReader_NodeType_Element:
            {
                OpcUa_Boolean bEmptyElement = OpcUa_False;

                uStatus = OpcUa_P_Libxml2_XmlReader_IsEmptyElement(a_pXmlReader, &bEmptyElement);
                OpcUa_GotoErrorIfBad(uStatus);

                uStatus = OpcUa_P_Libxml2_XmlWriter_StartElement(a_pXmlWriter,
                                                                 sNamespacePrefix,
                                                                 sLocalName,
                                                                 sNamespaceUri);
                OpcUa_GotoErrorIfBad(uStatus);

                uStatus = OpcUa_P_Libxml2_XmlWriter_WriteAttributes(a_pXmlWriter, a_pXmlReader);
                OpcUa_GotoErrorIfBad(uStatus);

                if(bEmptyElement)
                {
                    uStatus = OpcUa_P_Libxml2_XmlWriter_EndElement(a_pXmlWriter);
                    OpcUa_GotoErrorIfBad(uStatus);
                }

                break;
            }

            case OpcUa_XmlReader_NodeType_Text:
            {
                uStatus = OpcUa_P_Libxml2_XmlWriter_WriteString(a_pXmlWriter, sNodeValue);
                OpcUa_GotoErrorIfBad(uStatus);
                break;
            }

            case OpcUa_XmlReader_NodeType_CDATA:
            {
                OpcUa_GotoErrorIfTrue(xmlTextWriterWriteCDATA(pWriterHandle->TextWriter,
                                                              (xmlChar*)sNodeValue) < 0,
                                      OpcUa_BadInternalError);
                break;
            }

            case OpcUa_XmlReader_NodeType_EntityReference:
            {
                uStatus = OpcUa_P_Libxml2_XmlWriter_WriteEntityReference(a_pXmlWriter, sQualifiedName);
                OpcUa_GotoErrorIfBad(uStatus);
                break;
            }

            case OpcUa_XmlReader_NodeType_XmlDeclaration:
            case OpcUa_XmlReader_NodeType_ProcessingInstruction:
            {
                OpcUa_GotoErrorIfTrue(xmlTextWriterWriteProcessingInstruction(pWriterHandle->TextWriter,
                                                                              (xmlChar*)sQualifiedName,
                                                                              (xmlChar*)sNodeValue) < 0,
                                      OpcUa_BadInternalError);
                break;
            }

            case OpcUa_XmlReader_NodeType_Comment:
            {
                OpcUa_GotoErrorIfTrue(xmlTextWriterWriteComment(pWriterHandle->TextWriter,
                                                                (xmlChar*)sNodeValue) < 0,
                                      OpcUa_BadInternalError);
                break;
            }

            case OpcUa_XmlReader_NodeType_DocumentType:
            {
                OpcUa_GotoErrorIfTrue(xmlTextWriterWriteDocType(pWriterHandle->TextWriter,
                                                                (xmlChar*)sQualifiedName,
                                                                OpcUa_Null,
                                                                OpcUa_Null,
                                                                (xmlChar*)sNodeValue) < 0,
                                      OpcUa_BadInternalError);

                break;
            }

            case OpcUa_XmlReader_NodeType_Whitespace:
            case OpcUa_XmlReader_NodeType_SignificantWhitespace:
            {
                OpcUa_GotoErrorIfTrue(xmlTextWriterWriteRaw(pWriterHandle->TextWriter,
                                                            (xmlChar*)sNodeValue) < 0,
                                      OpcUa_BadInternalError);
                break;
            }

            case OpcUa_XmlReader_NodeType_EndElement:
            {
                OpcUa_GotoErrorIfTrue(xmlTextWriterFullEndElement(pWriterHandle->TextWriter) < 0,
                                      OpcUa_BadInternalError);
                break;
            }
        }

        uStatus = OpcUa_P_Libxml2_XmlReader_Read(a_pXmlReader);
        OpcUa_GotoErrorIfTrue(OpcUa_IsBad(uStatus) && uStatus != OpcUa_BadNoDataAvailable, uStatus);

        if(uStatus == OpcUa_BadNoDataAvailable)
        {
            uStatus = OpcUa_Good;
            break;
        }

        if(iNodeDepth > OpcUa_P_Libxml2_XmlReader_GetDepth(a_pXmlReader))
        {
            break;
        }

        if(    iNodeDepth == OpcUa_P_Libxml2_XmlReader_GetDepth(a_pXmlReader)
            && OpcUa_P_Libxml2_XmlReader_GetNodeType(a_pXmlReader) != OpcUa_XmlReader_NodeType_EndElement)
        {
            break;
        }
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}


/*============================================================================
 * OpcUa_P_Libxml2_XmlWriter_Flush
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Libxml2_XmlWriter_Flush(
    struct _OpcUa_XmlWriter* a_pXmlWriter)
{
    OpcUa_P_Libxml2_XmlWriter* pWriterHandle = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlWriter_Flush");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter);
    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter->Handle);

    pWriterHandle = (OpcUa_P_Libxml2_XmlWriter*)a_pXmlWriter->Handle;

    OpcUa_ReturnErrorIfArgumentNull(pWriterHandle);
    OpcUa_ReturnErrorIfTrue(pWriterHandle->Closed, OpcUa_BadInvalidState);

    OpcUa_ReturnErrorIfTrue(xmlTextWriterFlush(pWriterHandle->TextWriter) < 0,
                            OpcUa_BadInternalError);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlWriter_Flush
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Libxml2_XmlWriter_Close(
    struct _OpcUa_XmlWriter* a_pXmlWriter)
{
    OpcUa_P_Libxml2_XmlWriter* pWriterHandle = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlWriter_Close");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter);
    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter->Handle);

    pWriterHandle = (OpcUa_P_Libxml2_XmlWriter*)a_pXmlWriter->Handle;

    OpcUa_ReturnErrorIfArgumentNull(pWriterHandle);
    OpcUa_ReturnErrorIfTrue(pWriterHandle->Closed, OpcUa_BadInvalidState);

    OpcUa_P_Libxml2_XmlWriter_PopNamespaces(a_pXmlWriter, -1);
    xmlListDelete(pWriterHandle->NamespaceStack);
    pWriterHandle->NamespaceStack   = OpcUa_Null;

    xmlTextWriterFlush(pWriterHandle->TextWriter);
    xmlFreeTextWriter(pWriterHandle->TextWriter);
    pWriterHandle->TextWriter       = OpcUa_Null;

    /* Leave the value of the pXmlWriter->Closed field as it is,
       it will be set by OpcUa_P_Libxml2_XmlWriter_CloseCallback() to OpcUa_True */

    pWriterHandle->OutputBuffer     = OpcUa_Null;
    pWriterHandle->ElementDepth     = -1;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_P_Libxml2_XmlWriter_Delete
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_Libxml2_XmlWriter_Delete(
    struct _OpcUa_XmlWriter* a_pXmlWriter)
{
OpcUa_InitializeStatus(OpcUa_Module_P_Libxml2, "OpcUa_P_Libxml2_XmlWriter_Close");

    OpcUa_ReturnErrorIfArgumentNull(a_pXmlWriter);

    OpcUa_P_Libxml2_XmlWriter_PopNamespaces(a_pXmlWriter, -1);

    if(a_pXmlWriter->Handle != OpcUa_Null)
    {
        OpcUa_P_Libxml2_XmlWriter* pWriterHandle = (OpcUa_P_Libxml2_XmlWriter*)a_pXmlWriter->Handle;

        if(pWriterHandle->TextWriter != OpcUa_Null)
        {
            xmlFreeTextWriter(pWriterHandle->TextWriter);

            /* xmlFreeTextWriter() calls xmlOutputBufferClose(), thus
               there is no need to call xmlOutputBufferClose() twice */
            pWriterHandle->OutputBuffer = OpcUa_Null;
        }

        xmlListDelete(pWriterHandle->NamespaceStack);
        pWriterHandle->NamespaceStack = OpcUa_Null;

        OpcUa_P_Memory_Free(a_pXmlWriter->Handle);
        a_pXmlWriter->Handle = OpcUa_Null;
    }

    a_pXmlWriter->StartElement      = OpcUa_Null;
    a_pXmlWriter->EndElement        = OpcUa_Null;
    a_pXmlWriter->WriteAttribute    = OpcUa_Null;
    a_pXmlWriter->WriteString       = OpcUa_Null;
    a_pXmlWriter->WriteFormatted    = OpcUa_Null;
    a_pXmlWriter->WriteRaw          = OpcUa_Null;
    a_pXmlWriter->WriteNode         = OpcUa_Null;
    a_pXmlWriter->Flush             = OpcUa_Null;
    a_pXmlWriter->Close             = OpcUa_Null;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

#endif /* OPCUA_HAVE_XMLAPI */
