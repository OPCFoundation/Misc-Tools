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

enum OperationType
{
	OperationType_CreateNew,
	OperationType_SignExisting,
	OperationType_Revoke,
	OperationType_CreateRequest,
	OperationType_ProcessRequest
};

class BaseSettings
{
public:
	OperationType OperationType;
	std::string ErrorMessage;
};

class ProcessRequestSettings : public BaseSettings
{
public:
	std::string RequestFilePath;
	unsigned short HashSizeInBits;
	unsigned __int64 StartOfValidityPeriod;
	short LifetimeInMonths;
	std::string IssuerCertificateFilePath;
	std::string IssuerPrivateKeyFilePath;
	std::string IssuerPrivateKeyPassword;
	bool IsPemFormat;
	std::string NewCertificateFilePath;
};

class CommandLineArgs
{
public:
	
	CommandLineArgs()
	{
		KeyType = 0;
		KeySize = 2048;
		StartTime = 0;
		HashSize = 256;
		LifetimeInMonths = 12;
		IsCA = false;
		InputIsPEM = false;
		OutputIsPEM = false;
		ReuseKey = false;
	}

	std::string ParameterFilePath;
	std::map<std::string, std::string> OutputParameters;

	bool ProcessCommandLine(int argc, wchar_t* argv[]);

	void WriteOutput();

	std::string Command;
	std::string StorePath;
	std::string ApplicationName;
	std::string ApplicationUri;
	std::string SubjectName;
	std::string Organization;
	std::vector<std::string> DomainNames;
	std::string Password;
	std::string IssuerCertificate;
	std::string IssuerKeyFilePath;
	std::string IssuerKeyPassword;
	std::string PublicKeyFilePath;
	std::string PrivateKeyFilePath;
	std::string PrivateKeyPassword;
	std::string RequestFilePath;
	unsigned short KeyType;
	unsigned short KeySize;
	__int64 StartTime;
	unsigned short HashSize;
	short LifetimeInMonths;
	bool IsCA;
	bool InputIsPEM;
	bool OutputIsPEM;
	bool ReuseKey;

private:

	bool ValidArgs(std::map<std::string, std::string>& arguments);

	void WriteUsage();
};