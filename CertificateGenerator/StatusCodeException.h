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

#pragma once

// Stores a status code and message that can be thrown as an exception.
class StatusCodeException
{
public:

	// Creates a default exception.
	StatusCodeException()
	{
		m_code = OpcUa_Bad;
	}

	// Creates a new instance of the exception.
	StatusCodeException(int code)
	{
		m_code = code;
	}

	// Creates a new instance of the exception.
	StatusCodeException(int code, std::string message)
    {
	    m_code = code;
	    m_message = message;
    }

	// Frees all resources used by the exception.
	~StatusCodeException(void)
    {
    }

	// Returns the status code associated with the exception.
	int GetCode(void)
	{
		return m_code;
	}

	// Returns the message associated with the exception.
	std::string GetMessage(void)
	{
		return m_message;
	}

private:

	int m_code;
	std::string m_message;
};

#define ThrowIfBad(xStatus,xMessage) if (OpcUa_IsBad(xStatus)) throw StatusCodeException(xStatus,xMessage);
#define ThrowIfAllocFailed(xBuffer) if (xBuffer == NULL) throw StatusCodeException(OpcUa_BadOutOfMemory,"Memory allocation failed.");
#define ThrowIfCallFailed(xStatus,xFunction) if (OpcUa_IsBad(xStatus)) throw StatusCodeException(xStatus,#xFunction " call failed.");