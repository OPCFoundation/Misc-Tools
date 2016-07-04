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
#include <opcua_encoder.h>
#include <opcua_decoder.h>

/*============================================================================
 * OpcUa_Decoder_Close
 *===========================================================================*/
OpcUa_Void OpcUa_Decoder_Close(
    struct _OpcUa_Decoder* a_pDecoder,
    OpcUa_Handle* a_phDecodeContext)
{
    if (a_pDecoder != OpcUa_Null && a_pDecoder->Delete != OpcUa_Null)
    {
        a_pDecoder->Close(a_pDecoder, a_phDecodeContext);
    }
}

/*============================================================================
 * OpcUa_Decoder_Delete
 *===========================================================================*/
OpcUa_Void OpcUa_Decoder_Delete(
    struct _OpcUa_Decoder** a_ppDecoder)
{
    if (a_ppDecoder != OpcUa_Null && *a_ppDecoder != OpcUa_Null && (*a_ppDecoder)->Delete != OpcUa_Null)
    {
        (*a_ppDecoder)->Delete(a_ppDecoder);
    }
}
