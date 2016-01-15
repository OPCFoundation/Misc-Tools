
/* System Headers */
#include <windows.h>
#include <time.h>

/* UA platform definitions */
#include <opcua.h>

/*============================================================================
* CreateGuid
*===========================================================================*/
OpcUa_Guid* OpcUa_P_Guid_Create(OpcUa_Guid* Guid)
{
	if (UuidCreate((UUID*)Guid) != RPC_S_OK)
	{
		Guid = OpcUa_Null;
		return OpcUa_Null;
	}

	return Guid;
}

/*============================================================================
* Calculate DateTime Difference In Seconds (Rounded)
*===========================================================================*/
OpcUa_StatusCode OpcUa_P_GetDateTimeDiffInSeconds32(
	OpcUa_DateTime  a_Value1,
	OpcUa_DateTime  a_Value2,
	OpcUa_Int32*    a_pDifference)
{
	INT64 llValue1 = 0;
	INT64 llValue2 = 0;
	INT64 llResult = 0;

	OpcUa_ReturnErrorIfArgumentNull(a_pDifference);

	*a_pDifference = (OpcUa_Int32)0;

	llValue1 = a_Value1.dwHighDateTime;
	llValue1 = (llValue1 << 32) + a_Value1.dwLowDateTime;

	llValue2 = a_Value2.dwHighDateTime;
	llValue2 = (llValue2 << 32) + a_Value2.dwLowDateTime;

	llResult = llValue2 - llValue1;
	llResult /= 10000000;

	if (llResult < OpcUa_Int32_Min || llResult > OpcUa_Int32_Max)
	{
		return OpcUa_BadOutOfRange;
	}

	*a_pDifference = (OpcUa_Int32)llResult;

	return OpcUa_Good;
}

/*============================================================================
* The OpcUa_UtcNow function (returns the time in OpcUa_DateTime format)
*===========================================================================*/
OpcUa_DateTime OpcUa_P_DateTime_UtcNow()
{
	FILETIME ftTime;

	OpcUa_DateTime tmpDateTime;

	GetSystemTimeAsFileTime(&ftTime);

	tmpDateTime.dwHighDateTime = (OpcUa_UInt32)ftTime.dwHighDateTime;
	tmpDateTime.dwLowDateTime = (OpcUa_UInt32)ftTime.dwLowDateTime;

	return tmpDateTime;
}
