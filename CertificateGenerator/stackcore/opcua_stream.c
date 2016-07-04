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
#include <opcua_stream.h>


/*============================================================================
 * OpcUa_Stream_Read
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Stream_Read(
    struct _OpcUa_InputStream*     istrm,
    OpcUa_Byte*                    buffer,
    OpcUa_UInt32*                  count,
    OpcUa_Stream_PfnOnReadyToRead* callback,
    OpcUa_Void*                    callbackData)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_Stream);
    OpcUa_ReturnErrorIfArgumentNull(istrm);
    OpcUa_ReturnErrorIfArgumentNull(istrm->Read);

    return istrm->Read(istrm, buffer, count, callback, callbackData);
}

/*============================================================================
 * OpcUa_Stream_Write
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Stream_Write(
    struct _OpcUa_OutputStream* ostrm,
    OpcUa_Byte*                 buffer,
    OpcUa_UInt32                count)
{
    /*OpcUa_StatusCode uStatus = OpcUa_Good;*/
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_Stream);

    OpcUa_ReturnErrorIfArgumentNull(ostrm);
    OpcUa_ReturnErrorIfArgumentNull(ostrm->Write);

    return ostrm->Write(ostrm, buffer, count);
}

/*============================================================================
 * OpcUa_Stream_Flush
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Stream_Flush(
    struct _OpcUa_OutputStream* ostrm,
    OpcUa_Boolean               lastCall)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_Stream);
    OpcUa_ReturnErrorIfArgumentNull(ostrm);
    OpcUa_ReturnErrorIfArgumentNull(ostrm->Flush);

    return ostrm->Flush(ostrm, lastCall);
}

/*============================================================================
 * OpcUa_Stream_Close
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Stream_Close(
    struct _OpcUa_Stream* strm)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_Stream);
    OpcUa_ReturnErrorIfArgumentNull(strm);
    OpcUa_ReturnErrorIfArgumentNull(strm->Close);

    return strm->Close(strm);
}

/*============================================================================
 * OpcUa_Stream_GetChunkLength
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Stream_GetChunkLength(
    struct _OpcUa_Stream* strm,
    OpcUa_UInt32*         length)
{
    OpcUa_ReturnErrorIfArgumentNull(strm);
    OpcUa_ReturnErrorIfArgumentNull(length);

    return strm->GetChunkLength(strm, length);
}

/*============================================================================
 * OpcUa_Stream_AttachBuffer
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Stream_AttachBuffer(
    struct _OpcUa_Stream*   strm,
    OpcUa_Buffer*           buffer)
{
    OpcUa_ReturnErrorIfArgumentNull(strm);
    OpcUa_ReturnErrorIfArgumentNull(buffer);

    return strm->AttachBuffer(strm, buffer);
}


/*============================================================================
 * OpcUa_Stream_DetachBuffer
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_Stream_DetachBuffer(
    struct _OpcUa_Stream*   strm,
    OpcUa_Buffer*           buffer)
{
    OpcUa_ReturnErrorIfArgumentNull(strm);
    OpcUa_ReturnErrorIfArgumentNull(buffer);

    return strm->DetachBuffer(strm, buffer);
}

/*============================================================================
 * OpcUa_Stream_Delete
 *===========================================================================*/
OpcUa_Void OpcUa_Stream_Delete(
    struct _OpcUa_Stream** strm)
{
    if (strm != OpcUa_Null && *strm != OpcUa_Null)
    {
        (*strm)->Delete(strm);
    }
}

/*============================================================================
 * OpcUa_Stream_GetPosition
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Stream_GetPosition(
    struct _OpcUa_Stream* strm,
    OpcUa_UInt32*         position)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_Stream);
    OpcUa_ReturnErrorIfArgumentNull(strm);
    OpcUa_ReturnErrorIfArgumentNull(strm->GetPosition);

    return strm->GetPosition(strm, position);
}

/*============================================================================
 * OpcUa_Stream_SetPosition
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Stream_SetPosition(
    struct _OpcUa_Stream* strm,
    OpcUa_UInt32          position)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_Stream);
    OpcUa_ReturnErrorIfArgumentNull(strm);
    OpcUa_ReturnErrorIfArgumentNull(strm->SetPosition);

    return strm->SetPosition(strm, position);
}
