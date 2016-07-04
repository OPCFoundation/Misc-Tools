/**
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

#include <opcua.h>

#ifdef OPCUA_HAVE_BASE64

#include <opcua_base64.h>

static const OpcUa_CharA g_OpcUa_Base64_EncodingTable[] =
{
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};

static const OpcUa_Byte g_OpcUa_Base64_DecodingTable[] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xFF, 0xFF, 0x3F,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
    0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
    0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static OpcUa_StatusCode OpcUa_Base64_EncodeBlock(
    OpcUa_Byte  a_pBytes[3],
    OpcUa_CharA a_pChars[4],
    OpcUa_Int32 a_iByteCount)
{
    OpcUa_InitializeStatus(OpcUa_Module_Serializer, "OpcUa_Base64_EncodeBlock");

    OpcUa_GotoErrorIfArgumentNull(a_pBytes);
    OpcUa_GotoErrorIfArgumentNull(a_pChars);
    OpcUa_GotoErrorIfTrue(a_iByteCount < 1 || a_iByteCount > 3, OpcUa_BadInvalidArgument);

    switch(a_iByteCount)
    {
        case 1:
        {
            a_pChars[0] = g_OpcUa_Base64_EncodingTable[a_pBytes[0] >> 2];
            a_pChars[1] = g_OpcUa_Base64_EncodingTable[(a_pBytes[0] & 0x03) << 4];
            a_pChars[2] = '=';
            a_pChars[3] = '=';
            break;
        }

        case 2:
        {
            a_pChars[0] = g_OpcUa_Base64_EncodingTable[a_pBytes[0] >> 2];
            a_pChars[1] = g_OpcUa_Base64_EncodingTable[((a_pBytes[0] & 0x03) << 4) | ((a_pBytes[1] & 0xF0) >> 4)];
            a_pChars[2] = g_OpcUa_Base64_EncodingTable[(a_pBytes[1] & 0x0F) << 2];
            a_pChars[3] = '=';
            break;
        }

        case 3:
        {
            a_pChars[0] = g_OpcUa_Base64_EncodingTable[a_pBytes[0] >> 2];
            a_pChars[1] = g_OpcUa_Base64_EncodingTable[((a_pBytes[0] & 0x03) << 4) | ((a_pBytes[1] & 0xF0) >> 4)];
            a_pChars[2] = g_OpcUa_Base64_EncodingTable[((a_pBytes[1] & 0x0F) << 2) | ((a_pBytes[2] & 0xC0) >> 6)];
            a_pChars[3] = g_OpcUa_Base64_EncodingTable[a_pBytes[2] & 0x3F];
            break;
        }

        default:
        {
            OpcUa_ReturnStatusCode(OpcUa_BadInvalidArgument);
        }
    }

    OpcUa_ReturnStatusCode;
    OpcUa_BeginErrorHandling;

    /* nothing to do */

    OpcUa_FinishErrorHandling;
}

OpcUa_StatusCode OpcUa_Base64_Encode(
    OpcUa_Byte*     a_pBytes,
    OpcUa_Int32     a_iByteCount,
    OpcUa_StringA*  a_psString)
{
    OpcUa_Byte* pBytes = OpcUa_Null;
    OpcUa_CharA* pChars = OpcUa_Null;
    OpcUa_Int32 iByteIndex = 0;
    OpcUa_Int32 iBlockSize = 0;

    OpcUa_InitializeStatus(OpcUa_Module_Serializer, "OpcUa_Base64_Encode");

    OpcUa_ReturnErrorIfArgumentNull(a_pBytes);
    OpcUa_ReturnErrorIfArgumentNull(a_psString);
    OpcUa_ReturnErrorIfTrue(a_iByteCount <= 0 && a_pBytes != 0, OpcUa_BadInvalidArgument);

    *a_psString = OpcUa_Null;

    /* allocate the memory block of enough size (including trailing zero) */
    *a_psString = (OpcUa_CharA*)OpcUa_Alloc((((a_iByteCount + 2) / 3 * 4) + 1) * sizeof(OpcUa_CharA));
    OpcUa_GotoErrorIfAllocFailed(*a_psString);

    pBytes = a_pBytes;
    pChars = *a_psString;

    /* encode bytes block by block */
    while(iByteIndex < a_iByteCount)
    {
        iBlockSize = (a_iByteCount - iByteIndex < 3)? a_iByteCount - iByteIndex: 3;
        uStatus = OpcUa_Base64_EncodeBlock(pBytes, pChars, iBlockSize);
        OpcUa_GotoErrorIfBad(uStatus)

        iByteIndex += 3;
        pBytes += 3;
        pChars += 4;
    }

    /* place the trailing zero */
    *pChars = '\0';

    OpcUa_ReturnStatusCode;
    OpcUa_BeginErrorHandling;

    if(*a_psString != OpcUa_Null)
    {
        OpcUa_Free(*a_psString);
        *a_psString = OpcUa_Null;
    }

    OpcUa_FinishErrorHandling;
}

static OpcUa_StatusCode OpcUa_Base64_DecodeBlock(
    OpcUa_CharA     a_pChars[4],
    OpcUa_Byte      a_pBytes[3],
    OpcUa_Int32*    a_piByteCount)
{
    OpcUa_Int32 ii = 0;
    OpcUa_Byte chQuad[4];

    OpcUa_InitializeStatus(OpcUa_Module_Serializer, "OpcUa_Base64_DecodeBlock");

    OpcUa_ReturnErrorIfArgumentNull(a_pChars);
    OpcUa_ReturnErrorIfArgumentNull(a_pBytes);
    OpcUa_ReturnErrorIfArgumentNull(a_piByteCount);

    *a_piByteCount = 3;

    for(ii = 3; ii >= 0; ii--)
    {
        if(a_pChars[ii] == '=')
        {
            chQuad[ii] = 0;
            *a_piByteCount = ii - 1;
        }
        else
        {
            chQuad[ii] = g_OpcUa_Base64_DecodingTable[a_pChars[ii]];
        }

        if(chQuad[ii] == 0xFF)
        {
            OpcUa_GotoErrorWithStatus(OpcUa_BadInvalidArgument);
        }
    }

    OpcUa_GotoErrorIfTrue(*a_piByteCount < 1, OpcUa_BadInvalidArgument);

    a_pBytes[0] = (OpcUa_Byte)(chQuad[0] << 2 | chQuad[1] >> 4);
    a_pBytes[1] = (OpcUa_Byte)(chQuad[1] << 4 | chQuad[2] >> 2);
    a_pBytes[2] = (OpcUa_Byte)(((chQuad[2] << 6) & 0xC0) | chQuad[3]);

    OpcUa_ReturnStatusCode;
    OpcUa_BeginErrorHandling;

    *a_piByteCount = -1;

    OpcUa_FinishErrorHandling;
}

OpcUa_StatusCode OpcUa_Base64_Decode(
    OpcUa_StringA   a_sString,
    OpcUa_Int32*    a_piByteCount,
    OpcUa_Byte**    a_ppBytes)
{
    OpcUa_Byte* pBytes = OpcUa_Null;
    OpcUa_CharA* pChars = OpcUa_Null;
    OpcUa_Int32 iCharCount = 0;
    OpcUa_Int32 iByteCount = 0;
    OpcUa_Int32 iCharIndex = 0;

    OpcUa_InitializeStatus(OpcUa_Module_Serializer, "OpcUa_Base64_Decode");

    OpcUa_ReturnErrorIfArgumentNull(a_sString);
    OpcUa_ReturnErrorIfArgumentNull(a_piByteCount);
    OpcUa_ReturnErrorIfArgumentNull(a_ppBytes);

    iCharCount = OpcUa_StrLenA(a_sString);
    OpcUa_ReturnErrorIfTrue(iCharCount % 4, OpcUa_BadInvalidArgument);

    if(iCharCount == 0)
    {
        *a_ppBytes = OpcUa_Null;
        *a_piByteCount = -1;
        OpcUa_ReturnStatusCode;
    }

    /* allocate an initial memory block of enough size */
    *a_ppBytes = (OpcUa_Byte*)OpcUa_Alloc(((iCharCount / 4) * 3) * sizeof(OpcUa_Byte));
    OpcUa_GotoErrorIfAllocFailed(*a_ppBytes);

    *a_piByteCount = 0;

    pChars = a_sString;
    pBytes = *a_ppBytes;

    /* decode chars block by block */
    while(iCharIndex < iCharCount)
    {
        if(a_sString[iCharIndex] == '=')
        {
            /* unexpected padding char */
            OpcUa_GotoErrorIfTrue((iCharIndex != iCharCount - 1) || (iCharIndex != iCharCount - 2),
                                  OpcUa_BadInvalidArgument);
        }

        uStatus = OpcUa_Base64_DecodeBlock(pChars, pBytes, &iByteCount);
        OpcUa_GotoErrorIfBad(uStatus);

        *a_piByteCount += iByteCount;

        iCharIndex += 4;
        pChars += 4;
        pBytes += 3;
    }

    if(*a_piByteCount % 3 > 0)
    {
        /* an initial memory block should be reallocated
           because of padding char(s) */
        *a_ppBytes = (OpcUa_Byte*)OpcUa_ReAlloc(*a_ppBytes, *a_piByteCount);
        OpcUa_GotoErrorIfAllocFailed(*a_ppBytes);
    }

    OpcUa_ReturnStatusCode;
    OpcUa_BeginErrorHandling;

    if(*a_ppBytes != OpcUa_Null)
    {
        OpcUa_Free(*a_ppBytes);
        *a_ppBytes = OpcUa_Null;
    }

    *a_piByteCount = -1;

    OpcUa_FinishErrorHandling;
}

#endif /* OPCUA_HAVE_BASE64 */
