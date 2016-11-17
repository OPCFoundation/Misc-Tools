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

#include "StatusCodeException.h"
#include "CommandLineArgs.h"
#include "Application.h"
#include "opcua_certificates.h"

#define CLIENT_SERIALIZER_MAXALLOC                   16777216
#define CLIENT_ENCODER_MAXSTRINGLENGTH               ((OpcUa_UInt32)16777216)
#define CLIENT_ENCODER_MAXARRAYLENGTH                ((OpcUa_UInt32)65536)
#define CLIENT_ENCODER_MAXBYTESTRINGLENGTH           ((OpcUa_UInt32)16777216)
#define CLIENT_ENCODER_MAXMESSAGELENGTH              ((OpcUa_UInt32)16777216)
#define CLIENT_SECURELISTENER_THREADPOOL_MINTHREADS  5
#define CLIENT_SECURELISTENER_THREADPOOL_MAXTHREADS  5
#define CLIENT_SECURELISTENER_THREADPOOL_MAXJOBS     20
#define CLIENT_SECURITYTOKEN_LIFETIME_MAX            3600000
#define CLIENT_SECURITYTOKEN_LIFETIME_MIN            60000
#define CLIENT_TCPLISTENER_DEFAULTCHUNKSIZE          ((OpcUa_UInt32)65536)
#define CLIENT_TCPCONNECTION_DEFAULTCHUNKSIZE        ((OpcUa_UInt32)65536)

Application::Application(void)
{
    memset(&m_hPlatformLayer, 0, sizeof(OpcUa_ProxyStubConfiguration));
}

Application::~Application(void)
{
    Uninitialize();
}

void Application::Uninitialize(void)
{
    if (m_hPlatformLayer != 0)
    {
        OpcUa_ProxyStub_Clear();
        OpcUa_P_Clean(&m_hPlatformLayer);
        m_hPlatformLayer = 0;
    }
}

void Application::Log(OpcUa_UInt32 uTraceLevel, OpcUa_CharA* sFormat, ...)
{
    OpcUa_P_VA_List argumentList;
    OPCUA_P_VA_START(argumentList, sFormat);
    OpcUa_Trace(uTraceLevel, sFormat, argumentList);
}

void Application::Initialize(void)
{
    OpcUa_StatusCode uStatus = OpcUa_Good;

    try
    {
        // initialize the WIN32 platform layer.
        m_hPlatformLayer = 0;
        uStatus = OpcUa_P_Initialize(&m_hPlatformLayer);
        ThrowIfBad(uStatus, "Could not initialize the platform layer.");

        // these parameters control tracing.
        m_tConfiguration.bProxyStub_Trace_Enabled              = OpcUa_False;
        m_tConfiguration.uProxyStub_Trace_Level                = OPCUA_TRACE_OUTPUT_LEVEL_ALL;

        // these parameters are used to protect against buffer overflows caused by bad data.
        // they may need to be adjusted depending on the needs of the application.
        // the server also sets these limits which means errors could occur even if these limits are raised.
        m_tConfiguration.iSerializer_MaxAlloc                  = CLIENT_SERIALIZER_MAXALLOC;
        m_tConfiguration.iSerializer_MaxStringLength           = CLIENT_ENCODER_MAXSTRINGLENGTH;
        m_tConfiguration.iSerializer_MaxByteStringLength       = CLIENT_ENCODER_MAXARRAYLENGTH;
        m_tConfiguration.iSerializer_MaxArrayLength            = CLIENT_ENCODER_MAXBYTESTRINGLENGTH;
        m_tConfiguration.iSerializer_MaxMessageSize            = CLIENT_ENCODER_MAXMESSAGELENGTH;

        // the thread pool is only used in a server to dispatch incoming requests.
        m_tConfiguration.bSecureListener_ThreadPool_Enabled    = OpcUa_False;
        m_tConfiguration.iSecureListener_ThreadPool_MinThreads = CLIENT_SECURELISTENER_THREADPOOL_MINTHREADS;
        m_tConfiguration.iSecureListener_ThreadPool_MaxThreads = CLIENT_SECURELISTENER_THREADPOOL_MAXTHREADS;
        m_tConfiguration.iSecureListener_ThreadPool_MaxJobs    = CLIENT_SECURELISTENER_THREADPOOL_MAXJOBS;
        m_tConfiguration.bSecureListener_ThreadPool_BlockOnAdd = OpcUa_True;
        m_tConfiguration.uSecureListener_ThreadPool_Timeout    = OPCUA_INFINITE;

        // these parameters are used to tune performance. larger chunks == more memory, slower performance.
        m_tConfiguration.iTcpListener_DefaultChunkSize         = CLIENT_TCPLISTENER_DEFAULTCHUNKSIZE;
        m_tConfiguration.iTcpConnection_DefaultChunkSize       = CLIENT_TCPCONNECTION_DEFAULTCHUNKSIZE;
        m_tConfiguration.iTcpTransport_MaxMessageLength        = CLIENT_ENCODER_MAXMESSAGELENGTH;
        m_tConfiguration.iTcpTransport_MaxChunkCount           = -1;
        m_tConfiguration.bTcpListener_ClientThreadsEnabled     = OpcUa_False;
        m_tConfiguration.bTcpStream_ExpectWriteToBlock         = OpcUa_True;

        // initialize the stack.
        uStatus = OpcUa_ProxyStub_Initialize(m_hPlatformLayer, &m_tConfiguration);
        ThrowIfBad(uStatus, "Could not initialize the proxy stub.");
    }
    catch (StatusCodeException e)
    {
        throw;
    }
}

static void Copy(std::vector<std::string> src, OpcUa_StringA** pStrings, OpcUa_UInt32* pNoOfStrings)
{
    OpcUa_StatusCode uStatus = OpcUa_Good;

    try
    {
        *pStrings = NULL;
        *pNoOfStrings = src.size();

        int iLength = src.size()*sizeof(OpcUa_StringA*);
        *pStrings = (OpcUa_StringA*)OpcUa_Alloc(iLength);
        ThrowIfAllocFailed(*pStrings);
        OpcUa_MemSet(*pStrings, 0, iLength);

        for (unsigned int ii = 0; ii < src.size(); ii++)
        {
            iLength = src[ii].size()+1;
            (*pStrings)[ii] = (OpcUa_StringA)OpcUa_Alloc(iLength);
            ThrowIfAllocFailed((*pStrings)[ii]);
            strcpy_s((*pStrings)[ii], iLength, src[ii].c_str());
        }
    }
    catch (StatusCodeException e)
    {
        if (*pStrings != NULL)
        {
            for (unsigned int ii = 0; ii < *pNoOfStrings; ii++)
            {
                OpcUa_Free((*pStrings)[ii]);
            }

            OpcUa_Free(*pStrings);
            *pStrings = NULL;
            *pNoOfStrings = 0;
        }

        throw;
    }
}

static const char* HexDigits = "0123456789ABCDEF";
static const int HexDigitsCount = 16;

static int ToHexValue(char digit)
{
	digit = toupper(digit);

	for (int ii = 0; ii < HexDigitsCount; ii++)
	{
		if (HexDigits[ii] == digit)
		{
			return ii;
		}
	}

	return 0;
}

static void LoadFromFile(std::string input, OpcUa_ByteString& output)
{
	FILE* pFile = NULL;
	OpcUa_Byte pBlock[4096];
	int blockSize = sizeof(pBlock);

	try
	{
		OpcUa_ByteString_Initialize(&output);

		if (fopen_s(&pFile, input.c_str(), "rb") != 0)
		{
			std::string message = "Could not open input file: ";
			message += input;
			throw StatusCodeException(OpcUa_BadDecodingError, message);
		}

		output.Length = 0;

		do
		{
			int start = output.Length;

			int result = fread_s(pBlock, blockSize, 1, blockSize, pFile);

			if (ferror(pFile))
			{
				std::string message = "Error reading input file: ";
				message += input;
				throw StatusCodeException(OpcUa_BadDecodingError, message);
			}

			output.Length += result;
			output.Data = (OpcUa_Byte*)OpcUa_ReAlloc(output.Data, output.Length);

			if (output.Data == 0)
			{
				throw StatusCodeException(OpcUa_BadOutOfMemory);
			}

			OpcUa_MemCpy(output.Data + start, output.Length - start, pBlock, result);

			if (result != blockSize)
			{
				break;
			}
		} 
		while (true);

		fclose(pFile);
		pFile = NULL;
	}
	catch (StatusCodeException e)
	{
		if (pFile != 0)
		{
			fclose(pFile);
			pFile = NULL;
		}

		OpcUa_ByteString_Clear(&output);
		throw;
	}
}

static void ParseHexString(std::string input, OpcUa_ByteString& output)
{
	OpcUa_ByteString_Initialize(&output);

	std::size_t length = input.length();

	for (std::size_t ii = 0; ii < length; ii++)
	{
		if (!isxdigit(input[ii]))
		{
			LoadFromFile(input, output); 
			return;
		}
	}

	output.Length = (length/2) + (length%2);
	output.Data = (OpcUa_Byte*)OpcUa_Alloc(output.Length*sizeof(OpcUa_Byte));

	if (output.Data == 0)
	{
		throw StatusCodeException(OpcUa_BadOutOfMemory);
	}

	for (OpcUa_Int32 ii = 0; ii < output.Length; ii++)
	{
		int index = ii * 2;

		int value = ToHexValue(input[index]);
		value <<= 4;

		if ((size_t)index < length - 1)
		{
			value += ToHexValue(input[index + 1]);
		}

		output.Data[ii] = (OpcUa_Byte)value;
	}
}

static bool FormatHexString(OpcUa_ByteString input, std::string& output)
{
	output.clear();

	if (input.Length <= 0 || input.Data == 0)
	{
		return true;
	}

	int iLength = input.Length * 2 + 1;
	char* pBuffer = (char*)OpcUa_Alloc(iLength);

	if (pBuffer == 0)
	{
		return false;
	}

	for (OpcUa_Int32 ii = 0; ii < input.Length; ii++)
	{
		sprintf_s(pBuffer + ii * 2, iLength - ii * 2, "%02X", input.Data[ii]);
	}

	pBuffer[iLength - 1] = 0;
	output = pBuffer;
	OpcUa_Free(pBuffer);

	return true;
}

void Application::CreateRequest(CommandLineArgs& args)
{
	OpcUa_StatusCode uStatus = OpcUa_Good;
	OpcUa_ByteString certificate;
	OpcUa_Key privateKey;
	OpcUa_ByteString request;
	std::string newRequest;

	try
	{
		OpcUa_ByteString_Initialize(&certificate);
		OpcUa_Key_Initialize(&privateKey);
		OpcUa_ByteString_Initialize(&request);
		
		if (args.PrivateKeyFilePath.empty())
		{
			ThrowIfBad(uStatus, "Need a path to the private key.");
		}

		if (args.InputIsPEM)
		{
			if (args.PublicKeyFilePath.empty())
			{
				ThrowIfBad(uStatus, "Need a path to the existing certificate.");
			}

			OpcUa_ByteString buffer;
			OpcUa_ByteString_Initialize(&buffer);
			ParseHexString(args.PrivateKeyFilePath, buffer);

			uStatus = OpcUa_Certificate_LoadPrivateKey(
				&buffer,
				OpcUa_Crypto_Encoding_PEM,
				args.PrivateKeyPassword.c_str(),
				&certificate,
				&privateKey);

			ThrowIfBad(uStatus, "Could not load PEM private key. The key may be bad or the password is invalid.");

			ParseHexString(args.PublicKeyFilePath, certificate);
		}
		else
		{
			OpcUa_ByteString buffer;
			OpcUa_ByteString_Initialize(&buffer);
			ParseHexString(args.PrivateKeyFilePath, buffer);

			uStatus = OpcUa_Certificate_LoadPrivateKey(
				&buffer,
				OpcUa_Crypto_Encoding_PKCS12,
				args.PrivateKeyPassword.c_str(),
				&certificate,
				&privateKey);

			ThrowIfBad(uStatus, "Could not load PFX private key. The key may be bad or the password is invalid.");
		}

		OpcUa_StringA* pDomains = 0;
		
		if (args.DomainNames.size() > 0)
		{
			pDomains = new OpcUa_StringA[args.DomainNames.size()];

			for (size_t ii = 0; ii < args.DomainNames.size(); ii++)
			{
				pDomains[ii] = (OpcUa_StringA)args.DomainNames[ii].c_str();
			}
		}

		uStatus = OpcUa_Certificate_CreateCSR(
			(OpcUa_StringA)args.ApplicationName.c_str(),
			(OpcUa_StringA)args.Organization.c_str(),
			(OpcUa_StringA)args.SubjectName.c_str(),
			(OpcUa_StringA)args.ApplicationUri.c_str(),
			pDomains,
			(OpcUa_UInt32)args.DomainNames.size(),
			0,
			args.HashSize,
			&certificate,
			&privateKey,
			&request);
		
		ThrowIfBad(uStatus, "Could not create a certificate signing request.");

		if (args.RequestFilePath.empty())
		{
			if (!FormatHexString(request, newRequest))
			{
				ThrowIfBad(uStatus, "Could not format signing request as a hexstring.");
			}

			args.RequestFilePath = newRequest;
		}
		else
		{
			uStatus = OpcUa_WriteFile(args.RequestFilePath.c_str(), request.Data, request.Length);
			ThrowIfBad(uStatus, "Could not write request file.");
		}

		args.OutputParameters["-requestFilePath"] = args.RequestFilePath;

		OpcUa_ByteString_Clear(&certificate);
		OpcUa_Key_Clear(&privateKey);
		OpcUa_ByteString_Clear(&request);
	}
	catch (StatusCodeException e)
	{
		OpcUa_ByteString_Clear(&certificate);
		OpcUa_Key_Clear(&privateKey);
		OpcUa_ByteString_Clear(&request);

		throw;
	}
}

void Application::ProcessRequest(CommandLineArgs& args)
{
	OpcUa_StatusCode uStatus = OpcUa_Good;
	OpcUa_ByteString request;
	OpcUa_ByteString issuerCertificate;
	OpcUa_ByteString issuerPrivateKey;
	OpcUa_Key issuerKey;
	OpcUa_ByteString newCertificate;

	try
	{
		OpcUa_ByteString_Initialize(&request);
		OpcUa_ByteString_Initialize(&issuerCertificate);
		OpcUa_ByteString_Initialize(&issuerPrivateKey);
		OpcUa_ByteString_Initialize(&newCertificate);
		OpcUa_Key_Initialize(&issuerKey);

		ParseHexString(args.RequestFilePath, request);
		ParseHexString(args.IssuerKeyFilePath, issuerPrivateKey);

		uStatus = OpcUa_Certificate_LoadPrivateKey(
			&issuerPrivateKey,
			(args.InputIsPEM) ? OpcUa_Crypto_Encoding_PEM : OpcUa_Crypto_Encoding_PKCS12,
			args.IssuerKeyPassword.c_str(),
			&issuerCertificate,
			&issuerKey);

		ThrowIfBad(uStatus, "Could not load private key. The key may be bad or the password is invalid.");

		if (issuerCertificate.Length <= 0 && issuerKey.Key.Length <= 0)
		{
			ParseHexString(args.IssuerCertificate, issuerCertificate);
		}

		OpcUa_DateTime startTime;
		OpcUa_DateTime_Initialize(&startTime);

		if (args.StartTime != 0)
		{
			startTime.dwHighDateTime = (0xFFFFFFFF & (args.StartTime >> 32));
			startTime.dwLowDateTime = (0xFFFFFFFF & (args.StartTime));
		}

		uStatus = OpcUa_Certificate_CreateFromCSR(
			&request,
			args.HashSize,
			(args.StartTime != 0) ? &startTime : 0,
			args.LifetimeInMonths,
			&issuerCertificate,
			&issuerKey,
			&newCertificate);

		ThrowIfBad(uStatus, "Could not create certificate from signing request.");

		if (args.PublicKeyFilePath.empty())
		{
			std::string buffer;

			if (!FormatHexString(newCertificate, buffer))
			{
				ThrowIfBad(uStatus, "Could not format certificate as a hexstring.");
			}

			args.PublicKeyFilePath = buffer;
		}
		else
		{
			uStatus = OpcUa_WriteFile(args.PublicKeyFilePath.c_str(), newCertificate.Data, newCertificate.Length);
			ThrowIfBad(uStatus, "Could not write certificate file.");
		}

		args.OutputParameters["-publicKeyFilePath"] = args.PublicKeyFilePath;

		OpcUa_ByteString_Clear(&request);
		OpcUa_ByteString_Clear(&issuerCertificate);
		OpcUa_ByteString_Clear(&issuerPrivateKey);
		OpcUa_Key_Clear(&issuerKey);
		OpcUa_ByteString_Clear(&newCertificate);
	}
	catch (StatusCodeException e)
	{
		OpcUa_ByteString_Clear(&request);
		OpcUa_ByteString_Clear(&issuerCertificate);
		OpcUa_ByteString_Clear(&issuerPrivateKey);
		OpcUa_Key_Clear(&issuerKey);
		OpcUa_ByteString_Clear(&newCertificate);

		throw;
	}
}

void Application::Issue(CommandLineArgs& args)
{
    OpcUa_StatusCode uStatus = OpcUa_Good;
    OpcUa_ByteString certificate;
    OpcUa_Key privateKey;
    OpcUa_StringA sThumbprint = NULL;
    std::string thumbprint;
    OpcUa_StringA* pDomainNames = NULL;
    OpcUa_UInt32 uNoOfDomainNames = 0;
    OpcUa_StringA sPublicKeyFilePath = NULL;
    OpcUa_StringA sPrivateKeyFilePath = NULL;
	OpcUa_ByteString issuerCertificate;
	OpcUa_ByteString passedPrivateKey;
	OpcUa_Key issuerPrivateKey;

    try
    {
		OpcUa_ByteString_Initialize(&issuerCertificate);
		OpcUa_ByteString_Initialize(&passedPrivateKey);
		OpcUa_Key_Initialize(&issuerPrivateKey);
		OpcUa_ByteString_Initialize(&certificate);
		OpcUa_Key_Initialize(&privateKey);
		Copy(args.DomainNames, &pDomainNames, &uNoOfDomainNames);

		if (!args.IssuerKeyFilePath.empty())
		{
			ParseHexString(args.IssuerKeyFilePath, passedPrivateKey);

            uStatus = OpcUa_Certificate_LoadPrivateKey(
				&passedPrivateKey,
                OpcUa_Crypto_Encoding_PKCS12,
				(OpcUa_StringA)args.IssuerKeyPassword.c_str(),
				&issuerCertificate,
				&issuerPrivateKey);

			ThrowIfBad(uStatus, "Could not load private key. The key may be bad or the password is invalid.");

			if (issuerCertificate.Length <= 0 || issuerCertificate.Data == 0)
            {
				if (args.IssuerCertificate.empty())
                {
                    ThrowIfBad(uStatus, "The private key has no public key information. The -icf <certifcate> argument must be specified.");
				}

				ParseHexString(args.IssuerCertificate, issuerCertificate);
            }
        }

		if (args.ReuseKey)
        {
			if (args.PublicKeyFilePath.empty())
            {
                ThrowIfBad(uStatus, "Need a path to the existing certificate.");
            }

			if (args.OutputIsPEM)
			{
				ParseHexString(args.PublicKeyFilePath, certificate);

				{
					OpcUa_StringA* pSubjectNameFields = 0;
					OpcUa_UInt32 nNoOfSubjectNameFields = 0;
					OpcUa_StringA sApplicationUri = 0;
					OpcUa_StringA* pExistingDomains = 0;
					OpcUa_UInt32 nNoOfExistingDomains = 0;

					uStatus = OpcUa_Certificate_GetInfo(
						&certificate,
						&pSubjectNameFields,
						&nNoOfSubjectNameFields,
						0,
						0,
						&sApplicationUri,
						&pExistingDomains,
						&nNoOfExistingDomains);
                
					ThrowIfBad(uStatus, "Could not get information from existing certificate.");

					if (args.SubjectName.empty() || !args.ApplicationName.empty())
					{
						args.SubjectName.clear();

						for (int ii = nNoOfSubjectNameFields-1; ii >= 0; ii--)
						{
							if (args.SubjectName.length() > 0)
							{
								args.SubjectName += "/";
							}

							if (!args.ApplicationName.empty())
							{
								if (strncmp(pSubjectNameFields[ii], "CN=", 3) == 0)
								{
									args.SubjectName += "CN=";
									args.SubjectName += args.ApplicationName;
									continue;
								}
							}

							args.SubjectName += pSubjectNameFields[ii];
						}
					}

					if (args.ApplicationUri.empty() && sApplicationUri != 0)
					{
						args.ApplicationUri = sApplicationUri;
					}

					if (uNoOfDomainNames == 0)
					{
						uNoOfDomainNames = nNoOfExistingDomains;
						pDomainNames = pExistingDomains;
						nNoOfExistingDomains = 0;
						pExistingDomains = 0;
					}
					
					OpcUa_Free(sApplicationUri);

					for (unsigned int ii = 0; ii < nNoOfSubjectNameFields; ii++)
					{
						OpcUa_Free(pSubjectNameFields[ii]);
					}

					for (unsigned int ii = 0; ii < nNoOfExistingDomains; ii++)
					{
						OpcUa_Free(pExistingDomains[ii]);
					}
				}
            }
            else
			{
				OpcUa_ByteString_Clear(&passedPrivateKey);

				ParseHexString(args.PrivateKeyFilePath, passedPrivateKey);

                uStatus = OpcUa_Certificate_LoadPrivateKey(
					&passedPrivateKey,
                    OpcUa_Crypto_Encoding_PKCS12,
					(OpcUa_StringA)args.PrivateKeyPassword.c_str(),
                    &certificate,
					&privateKey);

				ThrowIfBad(uStatus, "Could not load private key. The key may be bad or the password is invalid.");
            }
        }

        uStatus = OpcUa_Certificate_Create(
			(OpcUa_StringA)args.StorePath.c_str(),
			(OpcUa_StringA)args.ApplicationName.c_str(),
			(OpcUa_StringA)args.ApplicationUri.c_str(),
			(OpcUa_StringA)args.Organization.c_str(),
			(OpcUa_StringA)args.SubjectName.c_str(),
            uNoOfDomainNames,
            pDomainNames,
            0,
			args.KeySize,
			args.StartTime,
			args.LifetimeInMonths,
			args.HashSize,
			(args.IsCA) ? 1 : 0,
			(args.ReuseKey) ? 1 : 0,
			(args.OutputIsPEM) ? OpcUa_Crypto_Encoding_PEM : OpcUa_Crypto_Encoding_PKCS12,
            &issuerCertificate,
            &issuerPrivateKey,
			(OpcUa_StringA)args.Password.c_str(),
            &certificate,
            &sPublicKeyFilePath,
            &privateKey,
            &sPrivateKeyFilePath);

        ThrowIfBad(uStatus, "Could not issue a new certificate.");

        uStatus = OpcUa_Certificate_GetThumbprint(&certificate, &sThumbprint);
        ThrowIfBad(uStatus, "Could not get thumbprint for the new self-signed certificate.");

		args.OutputParameters["-thumbprint"] = sThumbprint;
		args.OutputParameters["-publicKeyFilePath"] = sPublicKeyFilePath;
		args.OutputParameters["-privateKeyFilePath"] = sPrivateKeyFilePath;

        for (unsigned int ii = 0; ii < uNoOfDomainNames; ii++)
        {
            OpcUa_Free(pDomainNames[ii]);
        }

        OpcUa_Free(pDomainNames);
        OpcUa_ByteString_Clear(&certificate);
		OpcUa_Key_Clear(&privateKey);
		OpcUa_ByteString_Clear(&issuerCertificate);
		OpcUa_ByteString_Clear(&passedPrivateKey);
		OpcUa_Key_Clear(&issuerPrivateKey);
        OpcUa_Free(sThumbprint);
        OpcUa_Free(sPublicKeyFilePath);
		OpcUa_Free(sPrivateKeyFilePath);
    }
    catch (StatusCodeException e)
    {
        for (unsigned int ii = 0; ii < uNoOfDomainNames; ii++)
        {
            OpcUa_Free(pDomainNames[ii]);
        }

		OpcUa_Free(pDomainNames);
		OpcUa_ByteString_Clear(&certificate);
		OpcUa_Key_Clear(&privateKey);
		OpcUa_ByteString_Clear(&issuerCertificate);
		OpcUa_ByteString_Clear(&passedPrivateKey);
		OpcUa_Key_Clear(&issuerPrivateKey);
		OpcUa_Free(sThumbprint);
		OpcUa_Free(sPublicKeyFilePath);
		OpcUa_Free(sPrivateKeyFilePath);

        throw;
    }
}

void Application::Revoke(CommandLineArgs& args)
{
    OpcUa_StatusCode uStatus = OpcUa_Good;
	OpcUa_ByteString certificate;
	OpcUa_ByteString issuerCertificate;
    OpcUa_ByteString issuerPrivateKey;
    OpcUa_StringA sCrlFilePath = NULL;
    std::string newCrlFilePath;

    try
    {
		OpcUa_ByteString_Initialize(&certificate);
		OpcUa_ByteString_Initialize(&issuerCertificate);
		OpcUa_ByteString_Initialize(&issuerPrivateKey);

		ParseHexString(args.PublicKeyFilePath, certificate);
		ParseHexString(args.IssuerCertificate, issuerCertificate);
		ParseHexString(args.IssuerKeyFilePath, issuerPrivateKey);

        // revoke the certificate.
        uStatus = OpcUa_Certificate_Revoke(
			(OpcUa_StringA)args.StorePath.c_str(),
			&certificate,
			&issuerPrivateKey,
			(OpcUa_StringA)args.IssuerKeyPassword.c_str(),
			args.HashSize,
			args.Command == "unrevoke",
            &sCrlFilePath);

        ThrowIfBad(uStatus, "Could not revoke the certificate.");

        // return the CRL file path.
        newCrlFilePath = sCrlFilePath;

        // clean up.
		OpcUa_ByteString_Clear(&certificate);
		OpcUa_ByteString_Clear(&issuerCertificate);
		OpcUa_ByteString_Clear(&issuerPrivateKey);
        OpcUa_Free(sCrlFilePath);
    }
    catch (StatusCodeException e)
	{
		OpcUa_ByteString_Clear(&certificate);
		OpcUa_ByteString_Clear(&issuerCertificate);
		OpcUa_ByteString_Clear(&issuerPrivateKey);
        OpcUa_Free(sCrlFilePath);

        throw;
    }
}

void Application::Convert(CommandLineArgs& args)
{
    OpcUa_StatusCode uStatus = OpcUa_Good;
    OpcUa_ByteString certificate;
	OpcUa_ByteString privateKey;
	OpcUa_ByteString newPublicKey;
	OpcUa_ByteString newPrivateKey;
	OpcUa_StringA sCommonName = 0;
	OpcUa_StringA sThumbprint = 0;

    try
    {
		OpcUa_ByteString_Initialize(&certificate);
		OpcUa_ByteString_Initialize(&privateKey);
		OpcUa_ByteString_Initialize(&newPublicKey);
		OpcUa_ByteString_Initialize(&newPrivateKey);

		ParseHexString(args.PublicKeyFilePath, certificate);
		ParseHexString(args.PrivateKeyFilePath, privateKey);

		bool inputIsPEM = args.InputIsPEM;

		if (_strnicmp(args.PrivateKeyFilePath.c_str() + args.PrivateKeyFilePath.size() - 4, ".pem", 4) == 0)
        {
            inputIsPEM = true;
        }

        // revoke the certificate.
		uStatus = OpcUa_Certificate_Convert(
			&certificate,
			&privateKey,
			(OpcUa_StringA)args.PrivateKeyPassword.c_str(),
            (inputIsPEM)?OpcUa_Crypto_Encoding_PEM:OpcUa_Crypto_Encoding_PKCS12,
			(OpcUa_StringA)args.Password.c_str(),
			(args.OutputIsPEM) ? OpcUa_Crypto_Encoding_PEM : OpcUa_Crypto_Encoding_PKCS12,
			&newPublicKey,
			&newPrivateKey);

        // return the new file path.
		ThrowIfBad(uStatus, "The conversion failed.");

		if (args.StorePath.empty())
		{
			std::string output;

			if (!FormatHexString(newPublicKey, output))
			{
				ThrowIfBad(uStatus, "Could not format certificate as a hexstring.");
			}

			args.OutputParameters["-publicKeyFilePath"] = output;

			if (!FormatHexString(newPrivateKey, output))
			{
				ThrowIfBad(uStatus, "Could not format private key as a hexstring.");
			}

			args.OutputParameters["-privateKeyFilePath"] = output;
		}
		else
		{
			uStatus = OpcUa_Certificate_GetInfo(&certificate, NULL, NULL, &sCommonName, &sThumbprint, NULL, NULL, NULL);
			ThrowIfBad(uStatus, "Could not get the certificate info.");

			std::string path;

			path = args.StorePath;
			path += "\\certs\\";
			path += sCommonName;
			path += " [";
			path += sThumbprint;
			path += "].der";

			uStatus = OpcUa_WriteFile(path.c_str(), newPublicKey.Data, newPublicKey.Length);
			ThrowIfBad(uStatus, "Could not write the certificate file.");

			path = args.StorePath;
			path += "\\private\\";
			path += sCommonName;
			path += " [";
			path += sThumbprint;
			path += "]";

			if (args.OutputIsPEM)
			{
				path += ".pem";
			}
			else
			{
				path += ".pfx";
			}

			uStatus = OpcUa_WriteFile(path.c_str(), newPrivateKey.Data, newPrivateKey.Length);
			ThrowIfBad(uStatus, "Could not write the certificate file.");
		}

		OpcUa_ByteString_Clear(&newPublicKey);
		OpcUa_ByteString_Clear(&newPrivateKey);
		OpcUa_Free(sCommonName);
		OpcUa_Free(sThumbprint);
    }
    catch (StatusCodeException e)
	{
		OpcUa_ByteString_Clear(&newPublicKey);
		OpcUa_ByteString_Clear(&newPrivateKey);
		OpcUa_Free(sCommonName);
		OpcUa_Free(sThumbprint);
        throw;
    }
}

void Application::Replace(CommandLineArgs& args)
{
	OpcUa_StatusCode uStatus = OpcUa_Good;
	OpcUa_ByteString certificate;
	OpcUa_ByteString privateKey;
	OpcUa_ByteString newPrivateKey;
	OpcUa_StringA sCommonName = 0;
	OpcUa_StringA sThumbprint = 0;

	try
	{
		OpcUa_ByteString_Initialize(&certificate);
		OpcUa_ByteString_Initialize(&privateKey);
		OpcUa_ByteString_Initialize(&newPrivateKey);

		ParseHexString(args.PublicKeyFilePath, certificate);
		ParseHexString(args.PrivateKeyFilePath, privateKey);

		// revoke the certificate.
		uStatus = OpcUa_Certificate_Replace(
			&certificate,
			&privateKey,
			(OpcUa_StringA)args.PrivateKeyPassword.c_str(),
			(OpcUa_StringA)args.Password.c_str(),
			&newPrivateKey);

		// return the new file path.
		ThrowIfBad(uStatus, "Replace certificate failed.");

		if (args.PrivateKeyFilePath.find('.') == std::string::npos)
		{
			std::string output;

			if (!FormatHexString(newPrivateKey, output))
			{
				ThrowIfBad(uStatus, "Could not format private key as a hexstring.");
			}

			args.OutputParameters["-privateKeyFilePath"] = output;
		}
		else
		{
			uStatus = OpcUa_WriteFile(args.PrivateKeyFilePath.c_str(), newPrivateKey.Data, newPrivateKey.Length);
			ThrowIfBad(uStatus, "Could not write the certificate file.");
		}

		OpcUa_ByteString_Clear(&newPrivateKey);
	}
	catch (StatusCodeException e)
	{
		OpcUa_ByteString_Clear(&newPrivateKey);
		OpcUa_Free(sCommonName);
		OpcUa_Free(sThumbprint);
		throw;
	}
}
