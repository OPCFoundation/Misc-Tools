/*============================================================================
  @file opcua_p_libxml2.c

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

/* UA platform definitions */
#include <opcua_p_internal.h>

#ifdef OPCUA_HAVE_XMLAPI

/* Libxml2 headers */
#include <libxml/parser.h>

/* own header */
#include <opcua_p_libxml2.h>

/*============================================================================
 * OpcUa_P_Libxml2_Initialize
 *===========================================================================*/
OpcUa_Void OpcUa_P_Libxml2_Initialize()
{
    LIBXML_TEST_VERSION
}

/*============================================================================
 * OpcUa_P_Libxml2_Cleanup
 *===========================================================================*/
OpcUa_Void OpcUa_P_Libxml2_Cleanup()
{
    xmlCleanupParser();
}

#endif /* OPCUA_HAVE_XMLAPI */