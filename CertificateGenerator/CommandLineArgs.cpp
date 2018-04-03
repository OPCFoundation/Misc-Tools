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

#define WIN32_LEAN_AND_MEAN
#include "targetver.h"
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <opcua.h>

#include "CommandLineArgs.h"
#include "StatusCodeException.h"

extern OpcUa_StatusCode OpcUa_StringToUnicode(
	OpcUa_StringA a_sSource,
	OpcUa_Char**  a_pUnicode);

extern OpcUa_StatusCode OpcUa_UnicodeToString(
	OpcUa_Char*  a_pUnicode,
	OpcUa_StringA* a_sString);

// Reads the arguments from stdin.what 
static int ReadArgumentsFromFile(FILE* pFile, std::map<std::string, std::string>* arguments)
{
	wchar_t wsBuffer[65535];
	char* sBuffer = 0;
	std::string flag;
	std::string value;
	wchar_t* pResult = NULL;
	bool readingValue = false;

	do
	{
		OpcUa_Free(sBuffer);
		sBuffer = 0;

		// get the next block.
		memset(wsBuffer, 0, sizeof(wsBuffer));
		pResult = fgetws(wsBuffer, sizeof(wsBuffer), pFile);

		if (pResult == NULL)
		{
			break;
		}

		OpcUa_StatusCode uStatus = OpcUa_UnicodeToString((OpcUa_Char*)wsBuffer, &sBuffer);

		if (OpcUa_IsBad(uStatus))
		{
			return 0;
		}

		for (char* pPos = sBuffer; *pPos != 0; pPos++)
		{
			if (*pPos == L'\r')
			{
				continue;
			}

			// check for end of line.
			if (*pPos == L'\n')
			{
				// blank line means end of command.
				if (flag.empty())
				{
					OpcUa_Free(sBuffer);
					sBuffer = 0;
					return 0;
				}

				// save the argument value.
				(*arguments)[flag] = value;
				flag.clear();
				value.clear();
				readingValue = false;
				continue;
			}

			// skip whitespace until encountering the argument.
			if (!readingValue)
			{
				if (iswspace(*pPos))
				{
					if (!flag.empty())
					{
						readingValue = true;
					}

					continue;
				}

				flag.push_back(*pPos);
				continue;
			}

			// skip whitespace until encountering the value.
			else
			{
				if (iswspace(*pPos))
				{
					if (value.empty())
					{
						continue;
					}
				}

				value.push_back(*pPos);
				continue;
			}
		}
	} while (pResult != NULL);

	return 0;
}

// Reads the arguments from command line.
int ReadArgumentsFromCommandLine(int argc, wchar_t* argv[], std::map<std::string, std::string>* arguments)
{
	std::string flag;
	bool readingValue = false;
	OpcUa_CharA* sBuffer = 0;
	OpcUa_StatusCode uStatus = 0;

	for (int ii = 1; ii < argc; ii++)
	{
		OpcUa_StatusCode uStatus = OpcUa_UnicodeToString((OpcUa_Char*)argv[ii], &sBuffer);

		if (OpcUa_IsBad(uStatus))
		{
			return 0;
		}

		if (!readingValue)
		{
			flag = sBuffer;
			readingValue = true;

			if (flag == "-?" || flag == "/?" || flag == "-help" || flag == "/help")
			{
				(*arguments)["-?"] = "";
				OpcUa_Free(sBuffer);
				sBuffer = 0;
				return 0;
			}

			if (flag[0] != '-')
			{
				std::string message = "Unrecognized Parameter: ";
				message += flag;
				OpcUa_Free(sBuffer);
				sBuffer = 0;
				throw StatusCodeException(OpcUa_BadInvalidArgument, message);
			}
		}
		else
		{
			(*arguments)[flag] = sBuffer;
			flag.clear();
			readingValue = false;
		}

		OpcUa_Free(sBuffer);
		sBuffer = 0;
	}

	return 0;
}

static int CheckForNonAscii(const char* pStr)
{
	if (pStr == 0)
	{
		return 0;
	}

	const char* pPos = pStr;

	while (*pPos != 0)
	{
		if (*pPos < 0 || *pPos > 127)
		{
			return 0;
		}

		pPos++;
	}

	return 0;
}

static std::string IsArgSpecified(std::map<std::string, std::string>& arguments, std::string longForm, std::string shortForm)
{
	std::string arg;
	std::map<std::string, std::string>::iterator it;

	if ((it = arguments.find(longForm)) != arguments.end())
	{
		arg = it->second;
	}

	else if ((it = arguments.find(shortForm)) != arguments.end())
	{
		arg = it->second;
	}

	arguments.erase(longForm);
	arguments.erase(shortForm);

	if (!arg.empty())
	{
		for (std::size_t ii = 0; ii < arg.length(); ii++)
		{
			if (!isspace(arg[ii]))
			{
				arg = arg.substr(ii);
				break;
			}
		}

		for (std::size_t ii = arg.length() - 1; ii >= 0; ii--)
		{
			if (!isspace(arg[ii]))
			{
				arg = arg.substr(0, ii + 1);
				break;
			}
		}
	}

	return arg;
}

static void WriteResponse(FILE* pFile, const char* text, const char* parameter)
{
	OpcUa_Char* sBuffer = 0;
	OpcUa_StatusCode uStatus = 0;

	if (text != 0)
	{
		uStatus = OpcUa_StringToUnicode((OpcUa_CharA*)text, &sBuffer);

		if (OpcUa_IsGood(uStatus))
		{
			fputws((wchar_t*)sBuffer, pFile);
			OpcUa_Free(sBuffer);
			sBuffer = 0;
		}
	}

	if (parameter != 0)
	{
		fputws((wchar_t*)L" ", pFile);

		uStatus = OpcUa_StringToUnicode((OpcUa_CharA*)parameter, &sBuffer);

		if (OpcUa_IsGood(uStatus))
		{
			fputws((wchar_t*)sBuffer, pFile);
			OpcUa_Free(sBuffer);
			sBuffer = 0;
		}
	}

	fputws(L"\r\n", pFile);
}

bool CommandLineArgs::ValidArgs(std::map<std::string, std::string>& arguments)
{
	std::string arg;

	// set the argument values.
	if (!(arg = IsArgSpecified(arguments, "-command", "-cmd")).empty())
	{
		this->Command = arg;
	}

	if (!(arg = IsArgSpecified(arguments, "-storePath", "-sp")).empty())
	{
		this->StorePath = arg;

		if (CheckForNonAscii(this->StorePath.c_str()) != 0)
		{
			OutputParameters["-error"] = "Non-ASCII file paths not supported at this time (storePath)";
			OutputParameters["-storePath"] = this->StorePath.c_str();
			return false;
		}
	}

	if (!(arg = IsArgSpecified(arguments, "-applicationName", "-an")).empty())
	{
		this->ApplicationName = arg;
	}

	if (!(arg = IsArgSpecified(arguments, "-applicationUri", "-au")).empty())
	{
		this->ApplicationUri = arg;
	}

	if (!(arg = IsArgSpecified(arguments, "-subjectName", "-sn")).empty())
	{
		this->SubjectName = arg;
	}

	if (!(arg = IsArgSpecified(arguments, "-organization", "-o")).empty())
	{
		this->Organization = arg;
	}

	if (!(arg = IsArgSpecified(arguments, "-domainNames", "-dn")).empty())
	{
		int start = 0;
		int index = arg.find(",");

		while (index != std::string::npos)
		{
			this->DomainNames.push_back(arg.substr(start, index - start));
			start = index + 1;
			index = arg.find(",", start);
		}

		this->DomainNames.push_back(arg.substr(start));
	}

	if (!(arg = IsArgSpecified(arguments, "-password", "-pw")).empty())
	{
		this->Password = arg;
	}

	if (!(arg = IsArgSpecified(arguments, "-issuerCertificate", "-icf")).empty())
	{
		this->IssuerCertificate = arg;
	}

	if (!(arg = IsArgSpecified(arguments, "-requestFilePath", "-rfp")).empty())
	{
		this->RequestFilePath = arg;
	}

	if (!(arg = IsArgSpecified(arguments, "-issuerKeyFilePath", "-ikf")).empty())
	{
		this->IssuerKeyFilePath = arg;

		if (CheckForNonAscii(this->IssuerKeyFilePath.c_str()) != 0)
		{
			OutputParameters["-error"] = "Non-ASCII file paths not supported at this time (issuerKeyFilePath).";
			OutputParameters["-storePath"] = this->IssuerKeyFilePath.c_str();
			return false;
		}
	}

	if (!(arg = IsArgSpecified(arguments, "-issuerKeyPassword", "-ikp")).empty())
	{
		this->IssuerKeyPassword = arg;
	}

	if (!(arg = IsArgSpecified(arguments, "-keySize", "-ks")).empty())
	{
		this->KeySize = atoi(arg.c_str());
	}

	if (!(arg = IsArgSpecified(arguments, "-startTime", "-st")).empty())
	{
		this->StartTime = _atoi64(arg.c_str());
	}

	if (!(arg = IsArgSpecified(arguments, "-lifetimeInMonths", "-lm")).empty())
	{
		this->LifetimeInMonths = atoi(arg.c_str());
	}

	if (!(arg = IsArgSpecified(arguments, "-publicKeyFilePath", "-pbf")).empty())
	{
		this->PublicKeyFilePath = arg;

		if (CheckForNonAscii(this->PublicKeyFilePath.c_str()) != 0)
		{
			OutputParameters["-error"] = "Non-ASCII file paths not supported at this time (publicKeyFilePath).";
			OutputParameters["-storePath"] = this->PublicKeyFilePath.c_str();
			return false;
		}
	}

	if (!(arg = IsArgSpecified(arguments, "-privateKeyFilePath", "-pvf")).empty())
	{
		this->PrivateKeyFilePath = arg;

		if (CheckForNonAscii(this->PrivateKeyFilePath.c_str()) != 0)
		{
			OutputParameters["-error"] = "Non-ASCII file paths not supported at this time (privateKeyFilePath).";
			OutputParameters["-storePath"] = this->PrivateKeyFilePath.c_str();
			return false;
		}
	}

	if (!(arg = IsArgSpecified(arguments, "-privateKeyPassword", "-pvp")).empty())
	{
		this->PrivateKeyPassword = arg;
	}

	if (!(arg = IsArgSpecified(arguments, "-ca", "-ca")).empty())
	{
		this->IsCA = (_strcmpi(arg.c_str(), "true") == 0) ? true : false;
	}

	if (!(arg = IsArgSpecified(arguments, "-hashSize", "-hs")).empty())
	{
		this->HashSize = atoi(arg.c_str());

		if (this->HashSize == 0)
		{
			this->HashSize = 256;
		}
	}

	if (!(arg = IsArgSpecified(arguments, "-pem", "-pem")).empty())
	{
		this->OutputIsPEM = (_strcmpi(arg.c_str(), "true") == 0) ? true : false;
	}

	if (!(arg = IsArgSpecified(arguments, "-pemInput", "-pemInput")).empty())
	{
		this->InputIsPEM = (_strcmpi(arg.c_str(), "true") == 0) ? true : false;
	}
	
	if (!(arg = IsArgSpecified(arguments, "-reuseKey", "-rk")).empty())
	{
		this->ReuseKey = (_strcmpi(arg.c_str(), "true") == 0) ? true : false;
	}

	if (arguments.size() > 0)
	{
		OutputParameters["-error"] = "Unprocessed arguments exist possible syntax error.";

		for (std::map<std::string, std::string>::iterator ii = arguments.begin(); ii != arguments.end(); ++ii)
		{
			OutputParameters[ii->first.c_str()] = ii->second.c_str();
		}

		return false;
	}

	return true;
}

void CommandLineArgs::WriteUsage()
{
	FILE* pFile = stdout;
	bool bUsingStdout = true;

	try
	{
		if (!ParameterFilePath.empty())
		{
			if (fopen_s(&pFile, ParameterFilePath.c_str(), "w,ccs=UTF-8") != 0)
			{
				std::string message = "Could not open output file: ";
				message += ParameterFilePath;
				throw StatusCodeException(OpcUa_BadInvalidArgument, message);
			}

			bUsingStdout = false;
		}

		fputs("-command or -cmd <issue | revoke | unrevoke | convert | replace | request | process | password> The action to perform (default = issue).\r\n", pFile);
		fputs("\r\n", pFile);
		fputs("    issue: create a new certificate.\r\n", pFile);
		fputs("    revoke: revoke a certificate.\r\n", pFile);
		fputs("    unrevoke: unrevoke a certificate.\r\n", pFile);
		fputs("    convert: convert a private key file.\r\n", pFile);
		fputs("    replace: update the certificates in a PFX file.\r\n", pFile);
		fputs("    request: create a new certificate signing request.\r\n", pFile);
		fputs("    process: create a new certificate from a new certificate signing request.\r\n", pFile);
		fputs("    password: change the password on a private key.\r\n", pFile);
		fputs("\r\n", pFile);
		fputs("-storePath or -sp <filepath>                The directory of the certificate store (must be writeable).\r\n", pFile);
		fputs("-applicationName or -an <name>              The name of the application.\r\n", pFile);
		fputs("-applicationUri or -au <uri>                The URI for the appplication.\r\n", pFile);
		fputs("-subjectName or -sn <DN>                    The distinguished subject name, fields seperated by a / (i.e. CN=Hello/O=World).\r\n", pFile);
		fputs("-organization or -o <name>                  The organization.\r\n", pFile);
		fputs("-domainNames or -dn <name>,<name>           A list of domain names seperated by commas\r\n", pFile);
		fputs("-password or -pw <password>                 The password for the new private key file.\r\n", pFile);
		fputs("-issuerCertificate or -icf <filepath>       The path to the issuer certificate file.\r\n", pFile);
		fputs("-issuerKeyFilePath or -ikf <filepath>       The path to the issuer private key file.\r\n", pFile);
		fputs("-issuerKeyPassword or -ikp <password>       The password for the issuer private key file.\r\n", pFile);
		fputs("-keySize or -ks <bits>                      The size of key as a multiple of 1024 (default = 1024).\r\n", pFile);
		fputs("-hashSize or -hs <bits>                     The size of hash <160 | 256 | 512> (default = 256).\r\n", pFile);
		fputs("-startTime or -st <nanoseconds>             The start time for the validity period (nanoseconds from 1600-01-01).\r\n", pFile);
		fputs("-lifetimeInMonths or -lm <months>           The lifetime in months (default = 60).\r\n", pFile);
		fputs("-publicKeyFilePath or -pbf <filepath>       The path to the certificate to renew or revoke (a DER file).\r\n", pFile);
		fputs("-privateKeyFilePath or -pvf <filepath>      The path to an existing private key to reuse or convert.\r\n", pFile);
		fputs("-privateKeyPassword or -pvp <password>      The password for the existing private key.\r\n", pFile);
		fputs("-reuseKey or -rk <true | false>             Whether to reuse an existing public key (default = false).\r\n", pFile);
		fputs("-ca <true | false>                          Whether to create a CA certificate (default = false).\r\n", pFile);
		fputs("-pemInput <true | false>                    Whether the privateKeyFilePath is in PEM format (default = PFX).\r\n", pFile);
		fputs("-pem <true | false>                         Whether to output in the PEM format (default = PFX).\r\n", pFile);
		fputs("-requestFilePath or -rfp <filepath>         The path to certificate signing request.\r\n", pFile);
		fputs("-inlineOutput or -io <filepath>             Write all output as a hexadecimal string instead of saving to a file.\r\n", pFile);
		fputs("\r\n", pFile);
		fputs("\r\n", pFile);
		fputs("All input file arguments can be a valid directory path or a hexadecimal string.\r\n", pFile);
		fputs("All output files are written to output as hexadecimal strings if -inlineOutput true is specified.\r\n", pFile);
		fputs("\r\n", pFile);
		fputs("Create a self-signed Application Certificate: -cmd issue -sp . -an MyApp -au urn:MyHostMyCompany:MyApp -o MyCompany -dn MyHost -pw MyCertFilePassword\r\n", pFile);
		fputs("Create a CA Certificate: -cmd issue -sp . -sn CN=MyCA/O=Acme -ca true\r\n", pFile);
		fputs("Issue an Application Certificate: -cmd issue -sp . -an MyApp -ikf CaKeyFile -ikp CaPassword\r\n", pFile);
		fputs("Renew a Certificate: -cmd issue -sp . -pbf MyCertFile -ikf CaKeyFile -ikp CaPassword\r\n", pFile);
		fputs("Revoke a Certificate: -cmd revoke -sp . -pbf MyCertFile -ikf CaKeyFile -ikp CaPassword -hs 256\r\n", pFile);
		fputs("Unrevoke a Certificate: -cmd unrevoke -sp . -pbf MyCertFile -ikf CaKeyFile -ikp CaPassword\r\n", pFile);
		fputs("Convert key format: -cmd convert -pvf MyKeyFile -pvp oldpassword -pem true -pw newpassword\r\n", pFile);
		fputs("Create a certificate request: -cmd request -pbf MyCertFile.der -pvf MyCertFile.pfx -pvp MyCertFilePassword -rfp MyRequest.csr\r\n", pFile);
		fputs("Process a certificate request: -cmd process -rfp MyRequest.csr -ikf CaKeyFile -ikp CaPassword -pbf MyCertFile.der\r\n", pFile);
		fputs("Change a password: -cmd password -pvf MyCertFile.pfx -pvp MyCertFilePassword -password NewPassword\r\n", pFile);
		
		fclose(pFile);
		pFile = 0;
	}
	catch (StatusCodeException e)
	{
		if (!bUsingStdout && pFile != 0)
		{
			fclose(pFile);
			pFile = 0;
		}

		throw;
	}
}

bool CommandLineArgs::ProcessCommandLine(int argc, wchar_t* argv[])
{
	FILE* pFile = 0;
	std::string arg;
	std::map<std::string, std::string> arguments;
	std::map<std::string, std::string>::iterator it;

	try
	{
		// read the arguments from stdin.
		if (argc <= 1)
		{
			ReadArgumentsFromFile(stdin, &arguments);
		}

		// read the arguments from command line.
		else
		{
			ReadArgumentsFromCommandLine(argc, argv, &arguments);

			if (!(arg = IsArgSpecified(arguments, "-file", "-f")).empty())
			{
					arguments.clear();
					std::string tempFilePath = ParameterFilePath = arg;

					if (fopen_s(&pFile, tempFilePath.c_str(), "r, ccs=UTF-8") != 0)
					{
						std::string message = "Could not open input file: ";
						message += tempFilePath;
						throw StatusCodeException(OpcUa_BadInvalidArgument, message);
					}

					ReadArgumentsFromFile(pFile, &arguments);

					fclose(pFile);
					pFile = NULL;
			}
		}
		
		// check if help requested.
		if ((it = arguments.find("-?")) != arguments.end())
		{
			WriteUsage();
		}

		// validate arguments
		return ValidArgs(arguments);
	}
	catch (StatusCodeException e)
	{
		if (pFile != 0)
		{
			fclose(pFile);
			pFile = 0;
		}

		OutputParameters["-code"] = e.GetCode();
		OutputParameters["-error"] = e.GetMessage();
		return false;
	}
}

void CommandLineArgs::WriteOutput()
{
	FILE* pFile = stdout;
	bool bUsingStdout = true;
	
	try
	{
		if (!ParameterFilePath.empty())
		{
			if (fopen_s(&pFile, ParameterFilePath.c_str(), "w,ccs=UTF-8") != 0)
			{
				std::string message = "Could not open output file: ";
				message += ParameterFilePath;
				throw StatusCodeException(OpcUa_BadInvalidArgument, message);
			}

			bUsingStdout = false;
		}

		if (OutputParameters.size() > 0)
		{
			for (std::map<std::string, std::string>::iterator ii = OutputParameters.begin(); ii != OutputParameters.end(); ++ii)
			{
				WriteResponse(pFile, ii->first.c_str(), ii->second.c_str());
			}
		}

		if (!bUsingStdout && pFile != 0)
		{
			fclose(pFile);
			pFile = 0;
		}
	}
	catch (StatusCodeException e)
	{
		if (!bUsingStdout && pFile != 0)
		{
			fclose(pFile);
			pFile = 0;
		}

		throw;
	}
}
