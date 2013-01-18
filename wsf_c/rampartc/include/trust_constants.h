/*
* Licensed to the Apache Software Foundation (ASF) under one or more
* contributor license agreements.  See the NOTICE file distributed with
* this work for additional information regarding copyright ownership.
* The ASF licenses this file to You under the Apache License, Version 2.0
* (the "License"); you may not use this file except in compliance with
* the License.  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/


#ifndef TRUST_CONSTANTS_H
#define TRUST_CONSTANTS_H


#include <axutil_utils.h>
/**
* @file trust_constants.h
* @brief Holds constants for trust implementation
*/

#ifdef __cplusplus
extern "C"
{
#endif



	/*Trust XML Element names */
#define TRUST_RST_CONTEXT		"Context"
#define TRUST_TOKEN_TYPE		"TokenType"
#define TRUST_REQUEST_TYPE		"RequestType"
#define TRUST_APPLIES_TO		"AppliesTo"

#define TRUST_CLAIMS			"Claims"
#define TRUST_CLAIMS_DIALECT    "Dialect"

#define TRUST_ENTROPY			"Entropy"
#define TRUST_BINARY_SECRET		"BinarySecret"

#define TRUST_LIFE_TIME                 "LifeTime"
#define TRUST_LIFE_TIME_CREATED         "Created"
#define TRUST_LIFE_TIME_EXPIRES         "Expires"

#define TRUST_REQUEST_SECURITY_TOKEN          	"RequestSecurityToken"
#define TRUST_REQUESTED_SECURITY_TOKEN          "RequestedSecurityToken"
#define TRUST_REQUEST_SECURITY_TOKEN_RESPONSE 	"RequestSecurityTokenResponse"
#define TRUST_REQUESTED_PROOF_TOKEN             "RequestedProofToken"
#define TRUST_REQUEST_SECURITY_TOKEN_RESPONSE_COLLECTION "RequestSecurityTokenResponseCollection"
#define TRUST_REQUESTED_TOKEN_CANCELED        	"RequestedTokenCancelled"
#define TRUST_COMPUTED_KEY                    	"ComputedKey"
#define TRUST_REQUESTED_ATTACHED_REFERENCE    	"RequestedAttachedReference"
#define TRUST_REQUESTED_UNATTACHED_REFERENCE  	"RequestedUnattachedReference"
#define TRUST_SECURITY_TOKEN_REFERENCE          "SecurityTokenReference"
#define TRUST_ENCRYPTED_DATA                    "EncryptedData"
#define TRUST_REQUESTED_TOKEN_CANCELED        	"RequestedTokenCancelled"
#define TRUST_CANCEL_TARGET                   	"CancelTarget"
#define TRUST_URI                             	"URI"
#define TRUST_EPR                   "EndpointReference"
#define TRUST_EPR_ADDRESS			"Address"
#define TRUST_STR_REFERENCE			"Reference"

	/* Renewal Bindings */
#define TRUST_RENEW_TARGET          "RenewTarget"
#define TRUST_ALLOW_POSTDATING      "AllowPostdating"
#define TRUST_RENEWING              "Renewing"

#define TRUST_RENEW_ALLOW_ATTR      "Allow"
#define TRUST_RENEW_OK_ATTR         "OK"

#define TRUST_VALIDATION_STATUS		"Status"
#define TRUST_VALIDATION_CODE		"Code"
#define TRUST_VALIDATION_REASON		"Reason"
    
#define TRUST_CANCEL_TARGET			"CancelTarget"

    
#define ATTR_TYPE                   "Type"
#define	TRUST_BIN_SEC_TYPE_NONCE	"/Nonce"

	/* Request Types */
#define TRUST_REQ_TYPE_ISSUE		"/Issue"
#define TRUST_REQ_TYPE_VALIDATE		"/Validate"
#define TRUST_REQ_TYPE_RENEW		"/Renew"
#define TRUST_REQ_TYPE_CANCEL		"/Cancel"
    
#define TRUST_RST_ACTION_ISSUE		"/RST/Issue" 
#define TRUST_RST_ACTION_VALIDATE	"/RST/Validate"
#define TRUST_RST_ACTION_RENEW		"/RST/Renew"
#define TRUST_RST_ACTION_CANCEL		"/RST/Cancel"
#define TRUST_RST_ACTION_SCT		"/RST/SCT"
#define TRUST_RST_ACTION_CANCEL_SCT	"/RST/SCT/Cancel"
    
#define TRUST_KEY_TYPE_SYMM_KEY		"/SymmetricKey"
#define TRUST_KEY_TYPE_PUBLIC_KEY	"/PublicKey"
#define TRUST_KEY_TYPE_BEARER		"/Bearer"


    /*Key and Token Parameter Extensions*/
#define TRUST_AUTHENTICATION_TYPE       "AuthenticationType"
#define TRUST_KEY_TYPE			"KeyType"
#define TRUST_KEY_SIZE			"KeySize"
#define TRUST_SIGNATURE_ALGO            "SignatureAlgorithm"
#define TRUST_ENCRYPTION_ALGO           "EncryptionAlgorithm"
#define TRUST_CANONICAL_ALGO            "CanonicalizationAlgorithm"
#define TRUST_COMPUTED_KEY_ALGO         "ComputedKeyAlgorithm"
#define TRUST_DESIRED_ENCRYPTION         "Encryption"
#define TRUST_PROOF_ENCRYPTION           "ProofEncryption"
#define TRUST_USE_KEY                    "UseKey"
#define TRUST_SIGN_WITH                  "SignWith"
#define TRUST_ENCRYPT_WITH               "EncryptWith"

#define TRUST_ATTR_USE_KEY_SIG          "Sig"


#define TRUST_DEFAULT_KEY_SIZE 256

	/* Trust Namespace URIs and Namespace prefix */
#define TRUST_S11        "S11"
#define TRUST_S11_XMLNS  "http://schemas.xmlsoap.org/soap/envelope/"
#define TRUST_S12        "S12"
#define TRUST_S12_XMLNS  "http://www.w3.org/2003/05/soap-envelope"
#define TRUST_WSU        "wsu"
#define TRUST_WSU_XMLNS  "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
#define TRUST_WSSE       "wsse"
#define TRUST_WSSE_XMLNS "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
#define TRUST_WST        "wst"
#define TRUST_DS         "ds"
#define TRUST_DS_XMLNS   "http://www.w3.org/2000/09/xmldsig#"
#define TRUST_XENC       "xenc"
#define TRUST_XENC_XMLNS "http://www.w3.org/2001/04/xmlenc#"
#define TRUST_WSP        "wsp"
#define TRUST_WSP_XMLNS  "http://schemas.xmlsoap.org/ws/2004/09/policy"
#define TRUST_WSA        "wsa"
#define TRUST_WSA_XMLNS  "http://schemas.xmlsoap.org/ws/2004/08/addressing"
#define TRUST_XS         "xs"
#define TRUST_XS_XMLNS   "http://www.w3.org/2001/XMLSchema"

#define SECCONV_200502_REQUEST_ISSUE_ACTION "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT"
#define SECCONV_200502_REPLY_ISSUE_ACTION "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT"
#define SECCONV_200502_REQUEST_AMEND_ACTION "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT/Amend"
#define SECCONV_200502_REPLY_AMEND_ACTION "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT/Amend"
#define SECCONV_200502_REQUEST_RENEW_ACTION "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT/Renew"
#define SECCONV_200502_REPLY_RENEW_ACTION "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT/Renew"
#define SECCONV_200502_REQUEST_CANCEL_ACTION "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT/Cancel"
#define SECCONV_200502_REPLY_CANCEL_ACTION "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT/Cancel"
#define SECCONV_200512_REQUEST_ISSUE_ACTION "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/SCT"
#define SECCONV_200512_REPLY_ISSUE_ACTION "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/SCT"
#define SECCONV_200512_REQUEST_AMEND_ACTION "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/SCT/Amend"
#define SECCONV_200512_REPLY_AMEND_ACTION "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/SCT/Amend"
#define SECCONV_200512_REQUEST_RENEW_ACTION "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/SCT/Renew"
#define SECCONV_200512_REPLY_RENEW_ACTION "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/SCT/Renew"
#define SECCONV_200512_REQUEST_CANCEL_ACTION "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/SCT/Cancel"
#define SECCONV_200512_REPLY_CANCEL_ACTION "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/SCT/Cancel"

#define SECCONV_GLOBAL_ID_PREFIX "urn:uuid:"
#define SECCONV_LOCAL_ID_PREFIX "sctId"


#define TRUST_COMPUTED_KEY_PSHA1 "http://schemas.xmlsoap.org/ws/2005/02/trust/CK/PSHA1"
#define TRUST_COMPUTED_KEY_PSHA1_05_12 "http://docs.oasis-open.org/ws-sx/ws-trust/200512/CK/PSHA1"
/* NS Versions */

#define TRUST_VERSION_INVALID 0
#define TRUST_VERSION_05_02 1
#define TRUST_VERSION_05_12 2

#define SECCONV_ACTION_INVALID 0
#define SECCONV_ACTION_ISSUE 1
#define SECCONV_ACTION_AMEND 2
#define SECCONV_ACTION_RENEW 3
#define SECCONV_ACTION_CANCEL 4


/* WS-SX Namespaces*/

#define TRUST_WST_XMLNS_05_12 "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
#define TRUST_WST_XMLNS_05_02 "http://schemas.xmlsoap.org/ws/2005/02/trust"

#ifdef __cplusplus
}
#endif

#endif /* TRUST_CONSTANTS_H*/
