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
#include <opcua_builtintypes.h>
#include <opcua_encodeableobject.h>
#include <opcua_messagecontext.h>
#include <opcua_encoder.h>
#include <opcua_decoder.h>
#include <opcua_memorystream.h>
#include <opcua_utilities.h>
#include <opcua_binaryencoder.h>
#include <opcua_string.h>
#include <opcua_mutex.h>

typedef struct _OpcUa_EncodeableTypeTableEntry
{
    OpcUa_UInt32 TypeId;
    OpcUa_StringA NamespaceUri;
    OpcUa_Boolean FreeUri;
    OpcUa_EncodeableType* Type;
}
OpcUa_EncodeableTypeTableEntry;

/*============================================================================
 * OpcUa_EncodeableType_Compare
 *===========================================================================*/
OpcUa_Int OPCUA_CDECL OpcUa_EncodeableType_Compare(const OpcUa_EncodeableType* a_pType1, const OpcUa_EncodeableType* a_pType2)
{
    if (a_pType1 == OpcUa_Null && a_pType2 != OpcUa_Null)
    {
        return -1;
    }

    if (a_pType1 == OpcUa_Null)
    {
        return +1;
    }

    /* it is more efficient to sort by type first since there are many different types with the same namespace uri */
    if (a_pType1->TypeId < a_pType2->TypeId)
    {
        return -1;
    }

    if (a_pType1->TypeId > a_pType2->TypeId)
    {
        return +1;
    }

    /* check if namespaces are different - pointer compare is very efficient since namespace uri strings should be static data */
    if (a_pType1->NamespaceUri == a_pType2->NamespaceUri)
    {
        return 0;
    }

    /* compare namespace uris the hard way */
    if (a_pType1->NamespaceUri != OpcUa_Null && a_pType2->NamespaceUri != OpcUa_Null)
    {
        return OpcUa_P_String_StrnCmp(a_pType1->NamespaceUri, a_pType2->NamespaceUri, OpcUa_P_String_StrLen(a_pType1->NamespaceUri));
    }

    /* ensure types with a NULL namespace uri appear first */
    if (a_pType1->NamespaceUri == OpcUa_Null)
    {
        return -1;
    }

    return +1;
}

/*============================================================================
 * OpcUa_EncodeableTypeTableEntry_Compare
 *===========================================================================*/
static OpcUa_Int OPCUA_CDECL OpcUa_EncodeableTypeTableEntry_Compare(const OpcUa_Void* a_pElement1, const OpcUa_Void* a_pElement2)
{
    OpcUa_EncodeableTypeTableEntry* pEntry1 = (OpcUa_EncodeableTypeTableEntry*)a_pElement1;
    OpcUa_EncodeableTypeTableEntry* pEntry2 = (OpcUa_EncodeableTypeTableEntry*)a_pElement2;

    if (pEntry1 == OpcUa_Null && pEntry2 != OpcUa_Null)
    {
        return -1;
    }

    if (pEntry1 == OpcUa_Null)
    {
        return +1;
    }

    /* it is more efficient to sort by type first since there are many different types with the same namespace uri */
    if (pEntry1->TypeId < pEntry2->TypeId)
    {
        return -1;
    }

    if (pEntry1->TypeId > pEntry2->TypeId)
    {
        return +1;
    }

    /* check if namespaces are different - pointer compare is very efficient since namespace uri strings should be static data */
    if (pEntry1->NamespaceUri == pEntry2->NamespaceUri)
    {
        return 0;
    }

    /* compare namespace uris the hard way */
    if (pEntry1->NamespaceUri != OpcUa_Null && pEntry2->NamespaceUri != OpcUa_Null)
    {
        return OpcUa_P_String_StrnCmp(pEntry1->NamespaceUri, pEntry2->NamespaceUri, OpcUa_P_String_StrLen(pEntry1->NamespaceUri));
    }

    /* ensure types with a NULL namespace uri appear first */
    if (pEntry1->NamespaceUri == OpcUa_Null)
    {
        return -1;
    }

    return +1;
}

/*============================================================================
 * OpcUa_EncodeableTypeTable_Create
 *===========================================================================*/
OpcUa_StatusCode OpcUa_EncodeableTypeTable_Create(OpcUa_EncodeableTypeTable* a_pTable)
{
    OpcUa_InitializeStatus(OpcUa_Module_Channel, "OpcUa_EncodeableTypeTable_Create");

    OpcUa_ReturnErrorIfArgumentNull(a_pTable);

    a_pTable->Entries = OpcUa_Null;
    a_pTable->Count = 0;
    a_pTable->Index = OpcUa_Null;
    a_pTable->IndexCount = 0;

    uStatus = OPCUA_P_MUTEX_CREATE(&(a_pTable->Mutex));
    OpcUa_GotoErrorIfBad(uStatus);

    OpcUa_ReturnStatusCode;
    OpcUa_BeginErrorHandling;

    /* nothing to do */

    OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_EncodeableTypeTable_Delete
 *===========================================================================*/
OpcUa_Void OpcUa_EncodeableTypeTable_Delete(OpcUa_EncodeableTypeTable* a_pTable)
{
    if (a_pTable != OpcUa_Null)
    {
        OPCUA_P_MUTEX_DELETE(&(a_pTable->Mutex));
        a_pTable->Mutex = OpcUa_Null;

        if (a_pTable->Index != OpcUa_Null)
        {
            OpcUa_Int32 ii = 0;

            for (ii = 0; ii < a_pTable->IndexCount; ii++)
            {
                if (a_pTable->Index[ii].FreeUri)
                {
                    OpcUa_Free(a_pTable->Index[ii].NamespaceUri);
                }
            }
        }

        OpcUa_Free(a_pTable->Entries);
        OpcUa_Free(a_pTable->Index);

        a_pTable->Entries = OpcUa_Null;
        a_pTable->Count = 0;
        a_pTable->Index = OpcUa_Null;
        a_pTable->IndexCount = 0;
    }
}

/*============================================================================
 * OpcUa_EncodeableTypeTable_RebuildIndex
 *===========================================================================*/
static OpcUa_StatusCode OpcUa_EncodeableTypeTable_RebuildIndex(
    OpcUa_EncodeableTypeTable* a_pTable)
{
    OpcUa_Int32 ii = 0;
    OpcUa_Int32 nCount = 0;
    OpcUa_Int32 nIndexCount = 0;
    OpcUa_Int32 nCurrentIndex = 0;
    OpcUa_EncodeableType* pEntries = OpcUa_Null;
    OpcUa_EncodeableTypeTableEntry* pIndex = OpcUa_Null;

    OpcUa_InitializeStatus(OpcUa_Module_Serializer, "OpcUa_EncodeableTypeTable_RebuildIndex");

    nCount = a_pTable->Count;
    pEntries = a_pTable->Entries;

    nIndexCount =  0;

    /* count the number new definitions */
    for (ii = 0; ii < nCount; ii++)
    {
        if (pEntries[ii].TypeId != 0)
        {
            nIndexCount++;
        }

        if (pEntries[ii].BinaryEncodingTypeId != 0)
        {
            nIndexCount++;
        }

        if (pEntries[ii].XmlEncodingTypeId != 0)
        {
            nIndexCount++;
        }
    }

    /* reallocate the index */
    pIndex = (OpcUa_EncodeableTypeTableEntry*)OpcUa_ReAlloc(a_pTable->Index, nIndexCount*sizeof(OpcUa_EncodeableTypeTableEntry));
    OpcUa_GotoErrorIfAllocFailed(pIndex);

    nCurrentIndex = 0;

    /* create index table */
    for (ii = 0; ii < nCount; ii++)
    {
        OpcUa_EncodeableType* pType = OpcUa_Null;

        pType = pEntries+ii;

        /* index type id */
        if (pType->TypeId != 0 && nCurrentIndex < nIndexCount)
        {
            OpcUa_EncodeableTypeTableEntry* pIndexEntry = &(pIndex[nCurrentIndex++]);

            pIndexEntry->TypeId = pType->TypeId;
            pIndexEntry->NamespaceUri = pType->NamespaceUri;
            pIndexEntry->FreeUri = OpcUa_False;
            pIndexEntry->Type = pType;
        }

        /* index binary encoding type id */
        if (pType->BinaryEncodingTypeId != 0 && nCurrentIndex < nIndexCount)
        {
            OpcUa_EncodeableTypeTableEntry* pIndexEntry = &(pIndex[nCurrentIndex++]);

            pIndexEntry->TypeId = pType->BinaryEncodingTypeId;
            pIndexEntry->NamespaceUri = pType->NamespaceUri;
            pIndexEntry->FreeUri = OpcUa_False;
            pIndexEntry->Type = pType;
        }

        /* index xml encoding type id */
        if (pType->XmlEncodingTypeId != 0 && nCurrentIndex < nIndexCount)
        {
            OpcUa_EncodeableTypeTableEntry* pIndexEntry = &(pIndex[nCurrentIndex++]);

            pIndexEntry->TypeId = pType->XmlEncodingTypeId;
            pIndexEntry->NamespaceUri = pType->NamespaceUri;
            pIndexEntry->FreeUri = OpcUa_False;
            pIndexEntry->Type = pType;
        }
    }

    /* sort the index table */
    OpcUa_QSort(pIndex, nIndexCount, sizeof(OpcUa_EncodeableTypeTableEntry), OpcUa_EncodeableTypeTableEntry_Compare, OpcUa_Null);

    /* save the new table */
    a_pTable->Index = pIndex;
    a_pTable->IndexCount = nIndexCount;

    OpcUa_ReturnStatusCode;
    OpcUa_BeginErrorHandling;

    /* zero any new entries that could not be added but don't free the reallocated index */
    if (pIndex != OpcUa_Null)
    {
        for (ii = a_pTable->IndexCount; ii < nIndexCount; ii++)
        {
            OpcUa_MemSet(&(pIndex[ii]), 0, sizeof(OpcUa_EncodeableTypeTableEntry));
        }
    }

    OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_EncodeableTypeTable_AddTypes
 *===========================================================================*/
OpcUa_StatusCode OpcUa_EncodeableTypeTable_AddTypes(
    OpcUa_EncodeableTypeTable* a_pTable,
    OpcUa_EncodeableType**     a_pTypes)
{
    OpcUa_Int32 ii = 0;
    OpcUa_Int32 nCount = 0;
    OpcUa_EncodeableType* pEntries = OpcUa_Null;

    OpcUa_InitializeStatus(OpcUa_Module_Serializer, "EncodeableTypeTable_AddTypes");

    /* check for nulls */
    OpcUa_ReturnErrorIfArgumentNull(a_pTable);
    OpcUa_ReturnErrorIfArgumentNull(a_pTypes);

    OPCUA_P_MUTEX_LOCK(a_pTable->Mutex);

    nCount = 0;

    /* count the number new definitions */
    for (ii = 0; a_pTypes[ii] != OpcUa_Null; ii++)
    {
        nCount++;
    }

    if (nCount > 0)
    {
        nCount += a_pTable->Count;

        /* reallocate the table */
        pEntries = (OpcUa_EncodeableType*)OpcUa_ReAlloc(a_pTable->Entries, nCount*sizeof(OpcUa_EncodeableType));
        OpcUa_GotoErrorIfAllocFailed(pEntries);

        /* copy new definitions */
        for (ii = a_pTable->Count; ii < nCount; ii++)
        {
            OpcUa_EncodeableType* pDst = OpcUa_Null;
            OpcUa_EncodeableType* pSrc = OpcUa_Null;

            pDst = pEntries+ii;
            pSrc = a_pTypes[ii-a_pTable->Count];

            /* copy structure */
            OpcUa_MemCpy(pDst, sizeof(OpcUa_EncodeableType), pSrc, sizeof(OpcUa_EncodeableType));
        }

        /* save the new table */
        a_pTable->Entries = pEntries;
        a_pTable->Count = nCount;

        /* rebuild the index */
        OpcUa_EncodeableTypeTable_RebuildIndex(a_pTable);
    }

    OPCUA_P_MUTEX_UNLOCK(a_pTable->Mutex);

    OpcUa_ReturnStatusCode;
    OpcUa_BeginErrorHandling;

    /* zero any new entries that could not be added but don't free the reallocated table */
    if (pEntries != OpcUa_Null)
    {
        for (ii = a_pTable->Count; ii < nCount; ii++)
        {
            OpcUa_MemSet(&(pEntries[ii]), 0, sizeof(OpcUa_EncodeableType));
        }
    }

    OPCUA_P_MUTEX_UNLOCK(a_pTable->Mutex);

    OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_EncodeableTypeTable_Find
 *===========================================================================*/
OpcUa_StatusCode OpcUa_EncodeableTypeTable_Find(
    OpcUa_EncodeableTypeTable*  a_pTable,
    OpcUa_UInt32                a_nTypeId,
    OpcUa_StringA               a_sNamespaceUri,
    OpcUa_EncodeableType**      a_pType)
{
    OpcUa_EncodeableTypeTableEntry cKey;
    OpcUa_EncodeableTypeTableEntry* pResult = OpcUa_Null;

    OpcUa_InitializeStatus(OpcUa_Module_Serializer, "EncodeableTypeTable_Find");

    /* check for nulls */
    OpcUa_ReturnErrorIfArgumentNull(a_pTable);
    OpcUa_ReturnErrorIfArgumentNull(a_pType);

    OPCUA_P_MUTEX_LOCK(a_pTable->Mutex);

    *a_pType = OpcUa_Null;

    if (a_pTable->Entries != OpcUa_Null)
    {
        OpcUa_MemSet(&cKey, 0, sizeof(OpcUa_EncodeableTypeTableEntry));

        /* return a match for any of the three types */
        cKey.TypeId = a_nTypeId;
        cKey.NamespaceUri = a_sNamespaceUri;

        /* search for by description matching the type id and namespace uri. */
        pResult = (OpcUa_EncodeableTypeTableEntry*)OpcUa_BSearch(
            &cKey,
            a_pTable->Index,
            a_pTable->IndexCount,
            sizeof(OpcUa_EncodeableTypeTableEntry),
            OpcUa_EncodeableTypeTableEntry_Compare,
            OpcUa_Null);

        if (pResult == OpcUa_Null)
        {
            uStatus = OpcUa_GoodNoData;
        }
        else
        {
            *a_pType = pResult->Type;
        }
    }

    OPCUA_P_MUTEX_UNLOCK(a_pTable->Mutex);

    OpcUa_ReturnStatusCode;
    OpcUa_BeginErrorHandling;

    OPCUA_P_MUTEX_UNLOCK(a_pTable->Mutex);

    OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_EncodeableObject_Create
 *===========================================================================*/
OpcUa_StatusCode OpcUa_EncodeableObject_Create(
    OpcUa_EncodeableType* a_pType,
    OpcUa_Void**          a_pEncodeable)
{
    OpcUa_InitializeStatus(OpcUa_Module_Serializer, "EncodeableObject_Create");

    /* check for nulls */
    OpcUa_ReturnErrorIfArgumentNull(a_pType);
    OpcUa_ReturnErrorIfArgumentNull(a_pEncodeable);

    *a_pEncodeable = OpcUa_Null;

    /* allocate the object */
    *a_pEncodeable = OpcUa_Alloc(a_pType->AllocationSize);
    OpcUa_GotoErrorIfAllocFailed(*a_pEncodeable);

    /* initialize the object */
    a_pType->Initialize(*a_pEncodeable);

    OpcUa_ReturnStatusCode;
    OpcUa_BeginErrorHandling;

    OpcUa_Free(*a_pEncodeable);
    *a_pEncodeable = OpcUa_Null;

    OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_EncodeableObject_Delete
 *===========================================================================*/
OpcUa_Void OpcUa_EncodeableObject_Delete(
    OpcUa_EncodeableType* pType,
    OpcUa_Void**          ppEncodeable)
{
    if (ppEncodeable != OpcUa_Null)
    {
        if (pType != OpcUa_Null)
        {
            pType->Clear(*ppEncodeable);
        }

        OpcUa_Free(*ppEncodeable);
        *ppEncodeable = OpcUa_Null;
    }
}

/*============================================================================
 * OpcUa_EncodeableObject_CreateExtension
 *===========================================================================*/
OpcUa_StatusCode OpcUa_EncodeableObject_CreateExtension(
    OpcUa_EncodeableType*  a_pType,
    OpcUa_ExtensionObject* a_pExtension,
    OpcUa_Void**           a_ppObject)
{
    OpcUa_InitializeStatus(OpcUa_Module_Channel, "OpcUa_EncodeableObject_CreateExtension");

    OpcUa_ReturnErrorIfArgumentNull(a_pType);
    OpcUa_ReturnErrorIfArgumentNull(a_pExtension);
    OpcUa_ReturnErrorIfArgumentNull(a_ppObject);

    OpcUa_ExtensionObject_Initialize(a_pExtension);

    *a_ppObject = OpcUa_Null;

    /* create and initialize the object */
    uStatus = OpcUa_EncodeableObject_Create(a_pType, a_ppObject);
    OpcUa_GotoErrorIfBad(uStatus);

    /* attach to extension object which will take ownership of the memory */
    a_pExtension->Encoding = OpcUa_ExtensionObjectEncoding_EncodeableObject;

    a_pExtension->Body.EncodeableObject.Object = *a_ppObject;
    a_pExtension->Body.EncodeableObject.Type   = a_pType;

    OpcUa_ReturnStatusCode;
    OpcUa_BeginErrorHandling;

    /* nothing to do */

    OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_EncodeableObject_ParseExtension
 *===========================================================================*/
OpcUa_StatusCode OpcUa_EncodeableObject_ParseExtension(
    OpcUa_ExtensionObject* a_pExtension,
    OpcUa_MessageContext*  a_pContext,
    OpcUa_EncodeableType*  a_pType,
    OpcUa_Void**           a_ppObject)
{
    OpcUa_Decoder* pDecoder = 0;
    OpcUa_InputStream* pIstrm = 0;
    OpcUa_Handle hDecodeContext = OpcUa_Null;

    OpcUa_InitializeStatus(OpcUa_Module_Channel, "OpcUa_EncodeableObject_ParseExtension");

    OpcUa_ReturnErrorIfArgumentNull(a_pExtension);
    OpcUa_ReturnErrorIfArgumentNull(a_pContext);
    OpcUa_ReturnErrorIfArgumentNull(a_pExtension);
    OpcUa_ReturnErrorIfArgumentNull(a_ppObject);

    *a_ppObject = OpcUa_Null;

    /* only binary encoding supported at this time */
    if (a_pExtension->Encoding != OpcUa_ExtensionObjectEncoding_Binary)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadNotSupported);
    }

    /* create decoder */
    uStatus = OpcUa_BinaryDecoder_Create(&pDecoder);
    OpcUa_GotoErrorIfBad(uStatus);

    /* create stream */
    uStatus = OpcUa_MemoryStream_CreateReadable(a_pExtension->Body.Binary.Data, a_pExtension->Body.Binary.Length, &pIstrm);
    OpcUa_GotoErrorIfBad(uStatus);

    /* open the decoder */
    uStatus = pDecoder->Open(pDecoder, pIstrm, a_pContext, &hDecodeContext);
    OpcUa_GotoErrorIfBad(uStatus);

    /* create and initialize the object */
    uStatus = OpcUa_EncodeableObject_Create(a_pType, a_ppObject);
    OpcUa_GotoErrorIfBad(uStatus);

    /* read the object */
    uStatus = pDecoder->ReadEncodeable((struct _OpcUa_Decoder*)hDecodeContext, OpcUa_Null, a_pType, (OpcUa_Void*)*a_ppObject);
    OpcUa_GotoErrorIfBad(uStatus);

    /* close and delete decoder */
    OpcUa_Decoder_Close(pDecoder, &hDecodeContext);
    OpcUa_Decoder_Delete(&pDecoder);

    /* close and delete stream */
    OpcUa_Stream_Close((OpcUa_Stream*)pIstrm);
    OpcUa_Stream_Delete((OpcUa_Stream**)&pIstrm);

    OpcUa_ReturnStatusCode;
    OpcUa_BeginErrorHandling;

    if (pDecoder != 0)
    {
        OpcUa_Decoder_Close(pDecoder, &hDecodeContext);
        OpcUa_Decoder_Delete(&pDecoder);
    }

    if (pIstrm != 0)
    {
        OpcUa_Stream_Close((OpcUa_Stream*)pIstrm);
        OpcUa_Stream_Delete((OpcUa_Stream**)&pIstrm);
    }

    OpcUa_FinishErrorHandling;
}
