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

// Stores information associated with a UA application instance.
class Application
{
public:

    // Constructor
	Application(void);

    // Destructor
	~Application(void);

	// Initializes the stack and application.
	virtual void Initialize(void);

	// Frees all resources used by the stack and application.
	virtual void Uninitialize(void);

    // Issues a new certificate.
	void Issue(CommandLineArgs& args);

    // Revokes a certificate.
	void Revoke(CommandLineArgs& args);

	// Converts a certificate.
	void Convert(CommandLineArgs& args);

	// Replaces a certificates in a PFX file.
	void Replace(CommandLineArgs& args);

	// Create a certificate signing request.
	void CreateRequest(CommandLineArgs& args);

	// Process a certificate signing request.
	void ProcessRequest(CommandLineArgs& args);

private:

    // Logs a message.
    void Log(OpcUa_UInt32 uTraceLevel, OpcUa_CharA* sFormat, ...);

	OpcUa_Handle m_hPlatformLayer;
	OpcUa_ProxyStubConfiguration m_tConfiguration;
};
