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

#ifndef _OpcUa_MemoryStream_H_
#define _OpcUa_MemoryStream_H_ 1
#if OPCUA_HAVE_MEMORYSTREAM
#include <opcua_stream.h>

OPCUA_BEGIN_EXTERN_C

/**
  @brief Allocates a new readable memory stream.

  The caller must ensure the buffer is valid memory until Close is called.

  @param buffer     [in]  The buffer which is the source for the stream.
  @param bufferSize [in]  The length of the buffer.
  @param istrm      [out] The input stream.
*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_MemoryStream_CreateReadable(
    OpcUa_Byte*         buffer,
    OpcUa_UInt32        bufferSize,
    OpcUa_InputStream** istrm);

/**
  @brief Allocates a new writeable memory stream.

  @param blockSize  [in]  The size of the block to allocate when new memory is required.
  @param maxSize    [in]  The maximum buffer size (0 means no limit).
  @param ostrm      [out] The output stream.
*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_MemoryStream_CreateWriteable(
    OpcUa_UInt32         blockSize,
    OpcUa_UInt32         maxSize,
    OpcUa_OutputStream** ostrm);

/**
  @brief Returns the internal buffer for a writeable stream.

  This function cannot be called until the stream is closed.

  The memory returned by this function is owned by the stream and will be
  de-allocated when OpcUa_MemoryStream_Delete is called.

  @param ostrm      [in]  The output stream.
  @param buffer     [out] The buffer which contains the data written to the stream.
  @param bufferSize [out] The amount of valid data in the buffer.
*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_MemoryStream_GetBuffer(
    OpcUa_OutputStream* ostrm,
    OpcUa_Byte**        buffer,
    OpcUa_UInt32*       bufferSize);

OPCUA_END_EXTERN_C

#endif /* OPCUA_HAVE_MEMORYSTREAM */
#endif /* _OpcUa_MemoryStream_H_ */
