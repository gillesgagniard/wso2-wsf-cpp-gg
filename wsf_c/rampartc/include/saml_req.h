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

#ifndef SAML_REQ_H
#define SAML_REQ_H

#include <saml.h>
#include <oxs_xml_signature.h>
#include <oxs_sign_ctx.h>
#include <oxs_xml_key_processor.h>
#include <oxs_utility.h>
#include <oxs_transforms_factory.h>
#include <oxs_xml_key_info_builder.h>
#include <oxs_key_mgr.h>
#include <oxs_transform.h>
#include <oxs_x509_cert.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define SAML_REQUEST_ID        "RequestID"
#define SAML_SIGNATURE        "Signature"
#define SAML_SUBJECT_QUERY    "SubjectQuery"
#define SAML_ATTRIBUTE_QUERY  "AttributeQuery"
#define SAML_AUTHENTICATION_QUERY    "AuthenticationQuery"
#define SAML_AUTHORIZATION_DECISION_QUERY    "AuthorizationDecisionQuery"
#define SAML_ASSERTION_ID_REF        "AssertionIDReference"
#define SAML_ASSERTION_ARTIFACT    "AssertionArtifact"
#define SAML_RESPOND_WITH            "RespondWith"
#define SAML_ATTRIBUTE_DESIGNATOR        "AttributeDesignator"
#define SAML_RESPONSE_ID            "ResponceID"
#define SAML_IN_RESPONSE_TO        "InResponseTo"
#define SAML_RECEPIENT            "Recipient"
#define SAML_STATUS_CODE            "StatusCode"
#define SAML_STATUS_MESSAGE            "StatusMessage"
#define SAML_STATUS_DETAIL        "StatusDetail"
#define SAML_STATUS_VALUE        "Value"
#define SAML_STATUS                "Status"
#define SAML_PROTOCOL_NMSP			"urn:oasis:names:tc:SAML:1.0:protocol"
#define SAML_PROTOCOL_PREFIX		"samlp"
#define SAML_REQUEST				"Request"
#define SAML_RESPONSE				"Response"

/*A code representing the status of the corresponding request*/

/*
 * saml artifact for saml passive client assertion identifiers 
 */
typedef struct saml_artifact
{
	axis2_char_t *artifact; 
}saml_artifact_t;

/*
 * saml status : defines the status returned in saml response
 */
typedef struct saml_status
{
    axutil_qname_t *status_value;
    axis2_char_t *status_code;
    axis2_char_t *status_msg;
    axiom_node_t *status_detail;

}saml_status_t;

/*
 * the saml query for requesting required saml assertion
 */
typedef struct saml_query
{
	axis2_char_t *type;
	void *query;
}saml_query_t;

typedef struct saml_subject_query
{
    saml_subject_t *subject;
}saml_subject_query_t;

/*
 * saml authentication query : for requesting authentication details
 */
typedef struct saml_authentication_query
{
    saml_subject_t *subject;
    /* A URI reference that specifies the type of authentication that took place */
    axis2_char_t *auth_method;

}saml_authentication_query_t;

/*
 * saml qttribute query : for requesting the attributes 
 */
typedef struct saml_attr_query
{
    saml_subject_t *subject;
    axis2_char_t *resource;
    axutil_array_list_t *attr_desigs;
}saml_attr_query_t;

/*
 * saml authorization decision query : for requesting information for asserting authorization decisions  
 */
typedef struct saml_autho_decision_query
{
    saml_subject_t *subject;
    axis2_char_t *resource;
    /* One or more saml actions*/
    axutil_array_list_t *saml_actions;
    saml_evidence_t *evidence;

}saml_autho_decision_query_t;

typedef struct saml_request
{
	/* unique request id*/
    axis2_char_t *request_id;

    /* major version */
    axis2_char_t *major_version;

    /* minor version */
    axis2_char_t *minor_version;

    /* time instant of the issue */
    axutil_date_time_t *issue_instant;

    /*optional*/
    oxs_sign_ctx_t *sig_ctx;

    /* An array for QNames	
	 * specifies the type of statement the SAML relying party wants from the
	 * SAML authority*
	 */
    axutil_array_list_t *saml_responds;

    /*To request assrtions by means of ID one or more*/
    axutil_array_list_t *saml_asserion_id_ref;

	/* saml artifacts for saml passive client*/    
    axutil_array_list_t *saml_artifacts;

	saml_query_t *query;

	/*reference to the saml request node*/
	axiom_node_t *original_xml;

	/*reference to the saml response node*/
	axiom_node_t *signature;
}saml_request_t;

typedef struct saml_response
{
	/*sunique saml response id*/
    axis2_char_t *response_id;

	/*major version*/
    axis2_char_t *major_version;

	/*minor version*/
    axis2_char_t *minor_version;

    /*saml request party*/
    axis2_char_t *recepient;

	/*saml request identifier for the specific saml response*/
    axis2_char_t  *request_response_id;

	/*time instant for the respone*/
    axutil_date_time_t *issue_instant;

	/* information about the signing */
    oxs_sign_ctx_t *sig_ctx;

    saml_status_t *status;

    axutil_array_list_t *saml_assertions;

	/* reference to the saml response node*/
	axiom_node_t *original_xml;

	/*reference to the saml signature node*/
	axiom_node_t *signature;
}saml_response_t;

/* request */

/* 
 *  Creates a saml request.
 *  @param env pointer to environment struct
 */
AXIS2_EXTERN saml_request_t *AXIS2_CALL 
saml_request_create(const axutil_env_t *env);

/* 
 * Free a saml request
 * @param env pointer to environment struct
 */
AXIS2_EXTERN void AXIS2_CALL 
saml_request_free(saml_request_t *request, const axutil_env_t *env);

/* 
* Build the saml request from a axiom node.
* @param request request to be populated
* @param env pointer to environment struct
*/
AXIS2_EXTERN int AXIS2_CALL 
saml_request_build(saml_request_t *request, axiom_node_t *node, 
				   const axutil_env_t *env);

/* 
* Serialize a saml request to a om node.
* @param request request to be serialized
* @param parent if specified created node will be a child of this  
* @param env pointer to environment struct
*/
AXIS2_EXTERN axiom_node_t* AXIS2_CALL 
saml_request_to_om(saml_request_t *request, axiom_node_t *parent, 
				   const axutil_env_t *env); 
/*
* Return the unique ID of the request. 
* @param request SAML Request object
* @param env pointer to environment struct
*/
AXIS2_EXTERN axis2_char_t* AXIS2_CALL 
saml_request_get_id(saml_request_t *request, const axutil_env_t *env);

/* 
 * Set the information required to sign the message.
 * @param assertion SAML Request object
 * @param env pointer to environment struct
 * @param sign_ctx oxs_sign_ctx_t object which contains the sign information
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_request_set_signature(saml_request_t *request, const axutil_env_t *env, 
						   oxs_sign_ctx_t *sig_ctx);
/* 
 * Set the default information required to sign the message. 
 * @param response SAML response object
 * @param env pointer to environment struct
 * @param sign_ctx oxs_sign_ctx_t object which contains the sign information
 * oxs_sign_ctx should contain the key info and the certification info.
 * all other information are set to default settings.
 */
AXIS2_EXTERN void AXIS2_CALL 
saml_request_set_default_signature(saml_request_t *request, const axutil_env_t *env, 
								   oxs_sign_ctx_t *sig_ctx);
/* 
 * Remove the information set for signing or verifying the Request.
 * @param assertion SAML Request object
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_request_unsign(saml_request_t *request, const axutil_env_t *env);

/* 
 * Sign the Request using the information set in the 
 * saml_request_set_default_signature or saml_request_set_signature method.
 * @param assertion SAML Request object
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_request_sign(saml_request_t *request, axiom_node_t *node, const axutil_env_t *env);

/* 
 * Set the minor version of the Request
 * @param request SAML Request object
 * @param env pointer to environment struct
 * @param version minor version number
 */ 
AXIS2_EXTERN int AXIS2_CALL 
saml_request_set_minor_version(saml_request_t *request, const axutil_env_t *env,
							   int version);
/* 
 * Set the major version of the assertion
 * @param assertion SAML Request object
 * @param env pointer to environment struct
 * @param version major version number
 */ 
AXIS2_EXTERN int AXIS2_CALL 
saml_request_set_major_version(saml_request_t *request, 
							   const axutil_env_t *env, int version);
/* 
 * Set the issue instant of the Request
 * @param request SAML Request object
 * @param env pointer to environment struct
 * @param time time instant of the saml issue
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_request_set_issue_instant(saml_request_t *request, 
							   const axutil_env_t *env, axutil_date_time_t *date_time);

/*
 * Return the time instant of the Request
 * @param request SAML Request object
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN axutil_date_time_t* AXIS2_CALL 
saml_request_get_issue_instant(saml_request_t *request, const  axutil_env_t *env);

/*
 * Set the set of qname respond with references in Request
 * @param request SAML Request object
 * @param responds list of qname objects
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_request_set_respond_withs(saml_request_t *request, 
							   const axutil_env_t *env, axutil_array_list_t *responds);

/*
 * Return the set of qname respond with references in Request
 * @param request SAML Request object
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN axutil_array_list_t* AXIS2_CALL 
saml_request_get_respond_withs(saml_request_t *request, const axutil_env_t *env);

/*
 * Add a qname object respond with to the Request
 * @param request SAML Request object
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_request_add_respond_with(saml_request_t *request, const axutil_env_t *env,
							  axutil_qname_t *respond);
/*
 * Remove a qname object at the specified index
 * @param request SAML Request object
 * @index the specific index to remove
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_request_remove_respond_with(saml_request_t *request, const axutil_env_t *env, int index);

/*
 * Set the SAML Query of SAML Request.
 * @param request SAML Request object
 * @param query SAML Query object
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_request_set_query(saml_request_t *request, const axutil_env_t *env, saml_query_t *query);

/*
 * Returns the SAML Query of SAML Request.
 * @param request SAML Request
 * @param env pointer to the environemt struct
 */
AXIS2_EXTERN saml_query_t* AXIS2_CALL 
saml_request_get_query(saml_request_t *request, const axutil_env_t *env);

/*
 * Set the set of Identifer References of the Request.
 * @param request SAML Request
 * @param id_refs list of Identifier references
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_request_set_id_refs(saml_request_t *request, const axutil_env_t *env,
						 axutil_array_list_t *id_refs);
/*
 * Returne the list of Identifier references of the Request
 * @param request SAML Request
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN axutil_array_list_t* AXIS2_CALL 
saml_request_get_id_refs(saml_request_t *request, const axutil_env_t *env);

/*
 * Add an Id Reference to the SAML Request.
 * @param request SAML Request
 * @param id_references list of Id references
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_request_add_id_refs(saml_request_t *request, const axutil_env_t *env, 
						 axis2_char_t *id_reference);
/*
 * Remove an Id Reference at the specified index.
 * @param request SAML Request
 * @param index the specific to remove
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_request_remove_id_refs(saml_request_t *request, 
							const axutil_env_t *env, int index);
/*
 * Set the set of SAML Assertion Artifact objects of the Request.
 * @param request SAML Request
 * @param artifacts list of SAML Artifact objects
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_request_set_artifacts(saml_request_t *request, 
						   const axutil_env_t *env, axutil_array_list_t *artifacts);
/*
 * Returns the list of SAML Assertion Artifacts of the Request
 * @param request SAML Request
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN axutil_array_list_t*  AXIS2_CALL 
saml_request_get_artifacts(saml_request_t *request, const axutil_env_t *env);

/*
 * Add a SAML Assertion Artifact to the Request
 * @param request SAML Request
 * @param artifact SAML Assertion Artifact
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_request_add_artifact(saml_request_t *request, const axutil_env_t *env,
						  saml_artifact_t *artifact);
/* 
 * Remove a SAML Assertion Artifact at the specified index
 * @param request SAML Request
 * @param index specific index to remove
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_request_remove_artifact(saml_request_t *request, const axutil_env_t *env,
							 int index);
/*
 * Check the validity of the recieved Request
 * @param request SAML Request
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN axis2_bool_t AXIS2_CALL 
saml_request_check_validity(saml_request_t *request, const axutil_env_t *env);

/* 
 *  Creates a saml Response.
 *  @param env pointer to environment struct
 */
AXIS2_EXTERN saml_response_t* saml_response_create(const axutil_env_t *env);

/* 
 * Free a saml Response
 * @param env pointer to environment struct
 */
AXIS2_EXTERN void saml_response_free(saml_response_t *response, 
									 const axutil_env_t *env);
/* 
* Build the saml response from a axiom node.
* @param request response to be populated
* @param env pointer to environment struct
*/
AXIS2_EXTERN int AXIS2_CALL 
saml_response_build(saml_response_t *response, axiom_node_t *node, 
					const axutil_env_t *env);
/* 
* Serialize a saml response to a om node.
* @param request response to be serialized
* @param parent if specified created node will be a child of this  
* @param env pointer to environment struct
*/
AXIS2_EXTERN axiom_node_t* AXIS2_CALL 
saml_response_to_om(saml_response_t *response, axiom_node_t *parent, 
					const axutil_env_t *env);
/*
* Returns the unique ID of the response. 
* @param request SAML response object
* @param env pointer to environment struct
*/
AXIS2_EXTERN axis2_char_t* AXIS2_CALL 
saml_response_get_id(saml_response_t *response, const axutil_env_t *env);

/* 
 * Set the information required to sign the message.
 * @param assertion SAML response object
 * @param env pointer to environment struct
 * @param sign_ctx oxs_sign_ctx_t object which contains the sign information
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_response_set_signature(saml_response_t *response, 
							const axutil_env_t *env, oxs_sign_ctx_t *sig_ctx);

AXIS2_EXTERN int AXIS2_CALL 
saml_response_unset_signature(saml_response_t *response, const axutil_env_t *env);

/* 
 * Sign the response using the information set in the 
 * saml_response_set_default_signature or saml_response_set_signature method.
 * @param response SAML response object
 * @param node axiom node to of the response
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_response_sign(saml_response_t *response, axiom_node_t *node, 
				   const axutil_env_t *env);

/* 
 * Set the default information required to sign the message. 
 * @param response SAML response object
 * @param env pointer to environment struct
 * @param sign_ctx oxs_sign_ctx_t object which contains the sign information
 * oxs_sign_ctx should contain the key info and the certification info.
 * all other information are set to default settings.
 */
AXIS2_EXTERN void AXIS2_CALL 
saml_response_set_default_signature(saml_response_t *response, 
									const axutil_env_t *env, oxs_sign_ctx_t *sig_ctx);

/* 
 * Set the minor version of the response
 * @param response SAML response object
 * @param env pointer to environment struct
 * @param version minor version number
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_response_set_minor_version(saml_response_t *response, 
								const axutil_env_t *env, int version);
/* 
 * Set the major version of the response
 * @param response SAML response object
 * @param env pointer to environment struct
 * @param version major version number
 */ 
AXIS2_EXTERN int AXIS2_CALL 
saml_response_set_major_version(saml_response_t *response, 
								const axutil_env_t *env, int version);
/* 
 * Set the issue instant of the response
 * @param response SAML response object
 * @param env pointer to environment struct
 * @param time time instant of the saml issue
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_response_set_issue_instant(saml_response_t *response, 
								const axutil_env_t *env, axutil_date_time_t *date_time);
/*
 * Returns the time instant of the response
 * @param response SAML response object
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN  axutil_date_time_t* AXIS2_CALL 
saml_response_get_issue_instant(saml_response_t *response, const axutil_env_t *env);

/*
 * Set the SAML recepient of the response
 * @param response SAML response
 * @param recepient SAML recepient identifier
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_response_set_recepient(saml_response_t *response, const axutil_env_t *env,
							axis2_char_t *recepient);
/*
 * Returns the SAML response recepient.
 * @param response SAML response
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN axis2_char_t* AXIS2_CALL 
saml_response_get_recepient(saml_response_t *response, const axutil_env_t *env);

/*
 * Set the status of the SAML response.
 * @param response SAML response
 * @param status SAML status
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_response_set_status(saml_response_t *response, const axutil_env_t *env,
						 saml_status_t *status);
/*
 * Returns the status of the recieved SAML response
 * @param response SAML response
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN saml_status_t* AXIS2_CALL 
saml_response_get_status(saml_response_t *response, const axutil_env_t *env);

/*
 * Set the set of SAML Assertion of the SAML response
 * @param response SAML response
 * @param assertions list of SAML Assertions
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_response_set_assertions(saml_response_t *response, 
							 const axutil_env_t *env, axutil_array_list_t *assertions);

/*
 * Returns the set of SAML Assertions of response
 * @param response SAML response
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN axutil_array_list_t* AXIS2_CALL 
saml_response_get_assertions(saml_response_t *response, const axutil_env_t *env);

/*
 * Add a SAML assertion to the response
 * @param response SAML response
 * @param assertion SAML Assertion
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_response_add_assertion(saml_response_t *response, const axutil_env_t *env,
							saml_assertion_t *assertion);

/* 
 * Remove a SAML assertion at the specified index
 * @param response SAML response
 * @param index the specific index to remove
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_response_remove_assertion(saml_response_t *response, const axutil_env_t *env, int index);

/*
 * Set the request reference of the SAML response
 * @param response SAML response
 * @param request_response request reference
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_response_set_in_reponses_to(saml_response_t *response, 
								 const axutil_env_t *env, axis2_char_t *request_response);

/* 
 *  Creates a saml query.
 *  @param env pointer to environment struct
 */
AXIS2_EXTERN saml_query_t* AXIS2_CALL 
saml_query_create(const axutil_env_t *env);

/* 
 * Build the saml query from an axiom node.
 * @param query SAML query to be populated
 * @param node axiom node of SAML query
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_query_build(saml_query_t *query, axiom_node_t *node, const axutil_env_t *env);


/* 
* Serialize a saml query to a om node.
* @param query SAML response to be serialized
* @param parent if specified created node will be a child of this  
* @param env pointer to environment struct
*/
AXIS2_EXTERN axiom_node_t* AXIS2_CALL 
saml_query_to_om(saml_query_t *query, axiom_node_t *parent, const axutil_env_t *env);

/* 
 * Free a saml query
 * @param env pointer to environment struct
 */
AXIS2_EXTERN void AXIS2_CALL 
saml_query_free(saml_query_t *query, const axutil_env_t *env);

/* 
 *  Creates a saml subject query.
 *  @param env pointer to environment struct
 */

AXIS2_EXTERN saml_subject_query_t* AXIS2_CALL 
saml_subject_query_create(const axutil_env_t *env);

/* 
 * Free a saml subject query
 * @param env pointer to environment struct
 */
AXIS2_EXTERN void AXIS2_CALL 
saml_subject_query_free(saml_subject_query_t* subject_query, const axutil_env_t *env);

/* 
 * Build the saml subject query from an axiom node.
 * @param query SAML subject query to be populated
 * @param node axiom node of SAML subject query
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_subject_query_build(saml_subject_query_t* subject_query, 
						 axiom_node_t *node, const axutil_env_t *env);

/* 
* Serialize a saml subject query to a om node.
* @param query saml subject query to be serialized
* @param parent if specified created node will be a child of this  
* @param env pointer to environment struct
*/
AXIS2_EXTERN axiom_node_t* AXIS2_CALL 
saml_subject_query_to_om(saml_subject_query_t *subject_query, 
						 axiom_node_t *parent, const axutil_env_t *env);
/* 
 *  Creates a saml authentication query.
 *  @param env pointer to environment struct
 */
AXIS2_EXTERN saml_authentication_query_t* AXIS2_CALL 
saml_authentication_query_create(const axutil_env_t *env);

/* 
 * Free a saml authentication query
 * @param env pointer to environment struct
 */
AXIS2_EXTERN void AXIS2_CALL 
saml_authentication_query_free(saml_authentication_query_t *authentication_query, 
							   const axutil_env_t *env);
/* 
 * Build the saml authentication query from an axiom node.
 * @param query SAML authentication query to be populated
 * @param node axiom node of SAML query
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_authentication_query_build(saml_authentication_query_t* authentication_query, 
								axiom_node_t *node, const axutil_env_t *env);

/* 
* Serialize a saml authentication query to a om node.
* @param authentication_query saml authentication query to be serialized
* @param parent if specified created node will be a child of this  
* @param env pointer to environment struct
*/
AXIS2_EXTERN axiom_node_t* AXIS2_CALL 
saml_authentication_query_to_om(saml_authentication_query_t *authentication_query, 
								axiom_node_t *parent, const axutil_env_t *env);

/*
 * Set authetication method of saml authentication query.
 * @param authentication_query saml authentication query
 * @param env pointer to environment struct
 * @param authentication_mtd required authentication method in the secifying query
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_auth_query_set_authentication_method(
	saml_authentication_query_t *authentication_query,
	const axutil_env_t *env, 
	axis2_char_t *authentication_mtd);

/*
 * Returns the authentication method of the saml authentication query.
 * @param authentication_query saml authentication query
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_auth_query_get_authentication_method(
	saml_authentication_query_t *authentication_query,
	const axutil_env_t *env);

/* 
 *  Creates a saml attribute query.
 *  @param env pointer to environment struct
 */
AXIS2_EXTERN saml_attr_query_t* AXIS2_CALL 
saml_attr_query_create(const axutil_env_t *env);

/* 
 * Free a saml attribute query
 * @param env pointer to environment struct
 */
AXIS2_EXTERN void AXIS2_CALL
saml_attr_query_free(saml_attr_query_t* attribute_query, const axutil_env_t *env);

/* 
 * Build the saml attribute query from an axiom node.
 * @param attribute_query SAML attribute query to be populated
 * @param node axiom node of SAML query
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_attr_query_build(saml_attr_query_t* attribute_query, 
					  axiom_node_t *node, const axutil_env_t *env);

/* 
* Serialize a saml attribute to a om node.
* @param attribute_query saml attribute query to be serialized
* @param parent if specified created node will be a child of this  
* @param env pointer to environment struct
*/
AXIS2_EXTERN axiom_node_t* AXIS2_CALL 
saml_attr_query_to_om(saml_attr_query_t *attribute_query, 
					  axiom_node_t *parent, const axutil_env_t *env);

/*
 * Returns the saml subject of the saml query.
 * @param query saml query
 * @param env pointer to the environment struct
 */
AXIS2_EXTERN saml_subject_t* AXIS2_CALL 
saml_query_get_subject(saml_query_t* query,
						const axutil_env_t *env);
/*
 * Set the subject of a saml query.
 * @param query saml query
 * @param env pointer to the environment struct
 * @param subject saml subject
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_query_set_subject(saml_query_t *query, const axutil_env_t *env,
					   saml_subject_t *subject);
/*
 * Set the type of the saml query.
 * @param query saml query
 * @param env pointer to the environment struct
 * @param type type of the saml query
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_query_set_type(saml_query_t *query, const axutil_env_t *env, axis2_char_t *type);

/*
 * Set the saml specific query object of saml query
 * @param query saml query
 * @param spec_query specific query object to be set as the saml query
 * @param type the type of the specifying query
 * spec_query can be any type of query defined in saml queries.
 * the specified saml queries, saml subject query, attribute query, 
 * authentication query, athorization decision query
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_query_set_query(saml_query_t *query, const axutil_env_t *env,
					 void *spec_query, 
					 axis2_char_t *type);

/*
 * Set the resource required of saml attribute query.
 * @param attr_query saml attribute query
 * @param env pointer to environment struct
 * @param resource specific saml resource
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_attr_query_set_resource(saml_attr_query_t *attr_query, 
							 const axutil_env_t *env, axis2_char_t *resource);

/*
 * Returns the saml resource required of saml attribute query.
 * @param attr_query saml attribute query
 * @param env pointer to environment struct
 */
AXIS2_EXTERN axis2_char_t* AXIS2_CALL 
saml_attr_query_get_resource(saml_attr_query_t *attr_query, const axutil_env_t *env);

/*
 * Set a set of attribute designators of the saml attribute query.
 * @param env pointer to environment struct
 * @param saml_designators list of saml attribute designators
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_attr_query_set_designators(saml_attr_query_t *attr_query,  
								const axutil_env_t *env,
								axutil_array_list_t *saml_designators);
/*
 * Returns the set of attribute designators of saml attribute query.
 * @param attr_query saml attribute query
 * @param env pointer to environment struct
 */
AXIS2_EXTERN axutil_array_list_t* AXIS2_CALL 
saml_attr_query_get_designators(saml_attr_query_t *attr_query, const axutil_env_t *env);

/*
 * Add a saml attribute designator to the saml attribute query.
 * @param attr_query saml attribute query
 * @param env pointer to environment struct
 * @param desig saml attribute designator object
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_attr_query_add_designators(saml_attr_query_t *attr_query, const axutil_env_t *env,
								saml_attr_desig_t *desig);
/*
 * Remove saml attribute designator at the specified index.
 * @param attr_query saml attribute query
 * @param env pointer to environment struct
 * @param index the specified index to remove
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_attr_query_remove_designator(saml_attr_query_t *attr_query, const axutil_env_t *env,
								  int index);

/* 
 *  Creates a saml authorization decision query.
 *  @param env pointer to environment struct
 */
AXIS2_EXTERN saml_autho_decision_query_t* AXIS2_CALL 
saml_autho_decision_query_create(const axutil_env_t *env);

/* 
 * Free a saml authorizaion decision query
 * @param env pointer to environment struct
 */
AXIS2_EXTERN void AXIS2_CALL 
saml_autho_decision_query_free(saml_autho_decision_query_t* autho_decision_query, 
							   const axutil_env_t *env);

/* 
 * Build the saml authorization decision query from an axiom node.
 * @param query SAML authorization decision query to be populated
 * @param node axiom node of SAML authorization decision query
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_autho_decision_query_build(saml_autho_decision_query_t* autho_decision_query, 
								axiom_node_t *node, const axutil_env_t *env);

/* 
* Serialize a saml authorization decision query to a om node.
* @param autho_decision_query authorization decision query to be serialized
* @param parent if specified created node will be a child of this  
* @param env pointer to environment struct
*/
AXIS2_EXTERN axiom_node_t* AXIS2_CALL 
saml_autho_decision_query_to_om(saml_autho_decision_query_t *autho_decision_query, 
								axiom_node_t *parent, const axutil_env_t *env);
/*
 * Set the resource required of saml authorization decision query.
 * @param autho_dec_query saml authorization decision query
 * @param env pointer to environment struct
 * @param resource saml resource required
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_autho_decision_query_set_resource(
			saml_autho_decision_query_t *autho_dec_query,
			const axutil_env_t *env,
			axis2_char_t *resource);
/*
 * Returns the saml resource of saml authorization decision query.
 * @param autho_dec_query saml authorization decision query
 * @param env pointer to environment struct
 */
AXIS2_EXTERN axis2_char_t* AXIS2_CALL 
saml_autho_decision_query_get_resource(saml_autho_decision_query_t *autho_dec_query,
														 const axutil_env_t *env);
/*
 * Set a set of action of saml authorization decision query.
 * @param autho_dec_query saml authorization decision query
 * @param env pointer to the environment struct
 * @param actions list of saml action objects
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_autho_decision_query_set_actions(
			saml_autho_decision_query_t *autho_dec_query,
			const axutil_env_t *env,
			axutil_array_list_t *actions);
/*
 * Returns the set of actions of saml authorization decision query.
 * @param autho_dec_query saml authorization decision query
 * @param env envionment struct
 */
AXIS2_EXTERN axutil_array_list_t* AXIS2_CALL 
saml_autho_decision_query_get_actions(
			saml_autho_decision_query_t *autho_dec_query,
			const axutil_env_t *env);
														
/*
 * Add a saml action to saml authorization decision query.
 * @param autho_dec_query saml authorization decision query
 * @param env pointer to environment struct
 * @param action saml action object
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_autho_decision_query_add_action(
			saml_autho_decision_query_t *autho_dec_query,
			const axutil_env_t *env,
			saml_action_t *action);
/*
 * Remove a saml action at the the specified index.
 * @param autho_dec_query saml authorization decision query
 * @param env pointer to environment struct
 * @param index specified index to remove
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_autho_decision_remove_action(saml_autho_decision_query_t *autho_dec_query,
								  const axutil_env_t *env,
								  int index);
/*
 * Set a saml evidence of the saml authorization decision query.
 * @param autho_dec_query saml authorization decision query
 * @param env pointer to environment struct
 * @param evidence saml evidence object
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_autho_decision_query_set_evidence(
			saml_autho_decision_query_t *autho_dec_query,
			const axutil_env_t *env,
			saml_evidence_t *evidence);
/*
 * Returns the saml evidence of saml authorization decision query.
 * @param autho_dec_query saml authorization decision query
 * @param env pointer to environment struct
 */
AXIS2_EXTERN saml_evidence_t* AXIS2_CALL 
saml_autho_decision_query_get_evidence(
			saml_autho_decision_query_t *autho_dec_query,
			const axutil_env_t *env);
	
/* 
 * Build the saml status from an axiom node.
 * @param query SAML status to be populated
 * @param node axiom node of SAML status
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_status_build(saml_status_t *status, axiom_node_t *node, const axutil_env_t *env);

/* 
* Serialize a saml status to a om node.
* @param status saml status to be serialized
* @param parent if specified created node will be a child of this  
* @param env pointer to environment struct
*/
AXIS2_EXTERN axiom_node_t* AXIS2_CALL saml_status_to_om(saml_status_t *status, 
														axiom_node_t *parent, 
														const axutil_env_t *env);

/* 
 *  Creates a saml status.
 *  @param env pointer to environment struct
 */
AXIS2_EXTERN saml_status_t* AXIS2_CALL 
saml_status_create(const axutil_env_t *env);

/* 
 * Free a saml status
 * @param env pointer to environment struct
 */
AXIS2_EXTERN void 
saml_status_free(saml_status_t *status, const axutil_env_t *env);

/*
 * Set the saml status value to be returned in saml status.
 * @param status saml status object
 * @param qname axutil qname object which specify saml status value
 * @param env pointer to environment struct
*/
AXIS2_EXTERN int AXIS2_CALL 
saml_status_set_status_value(saml_status_t *status, 
							 const axutil_env_t *env, axutil_qname_t *qname);

/*
 * Returns the saml status value of saml status.
 * @param status saml status
 * @param env pointer to environment struct
 */
AXIS2_EXTERN axutil_qname_t* AXIS2_CALL 
saml_status_get_status_value(saml_status_t *status, const axutil_env_t *env);

/*
 * Set the status message of saml status
 * @param status saml status object
 * @param env pointer to environment struct
 * @param msg status message to be set in saml status
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_status_set_status_msg(saml_status_t *status, const axutil_env_t *env,
						   axis2_char_t *msg);
/*
 * Set the status code of saml status object.
 * @param status saml status object
 * @param env pointer to environment struct
 * @param code status code to be set in saml status
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_status_set_status_code(saml_status_t *status, const axutil_env_t *env,
							axis2_char_t *code);
/*
 * Returns the status message of saml status.
 * @param status saml status struct
 * @env pointer to environment struct
 */
AXIS2_EXTERN axis2_char_t* AXIS2_CALL 
saml_status_get_status_msg(saml_status_t *status, const axutil_env_t *env);
/* 
 * Set the saml status detail of saml status.
 * @param status saml status struct
 * @param det axiom node struct to be set as saml status detail
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_status_set_status_detail(saml_status_t *status, axiom_node_t *det, 
							  const axutil_env_t *env);
/*
 * Returns the saml status detail node of saml status
 * @param status saml status struct
 * @param env pointer to environment struct
 */
AXIS2_EXTERN axiom_node_t* AXIS2_CALL 
saml_status_get_status_detail(saml_status_t *status, const axutil_env_t *env);

/* 
 *  Creates a saml artifact.
 *  @param env pointer to environment struct
 */
AXIS2_EXTERN saml_artifact_t* AXIS2_CALL 
saml_artifact_create(const axutil_env_t *env);

/* 
 * Free a saml artifact
 * @param env pointer to environment struct
 */
AXIS2_EXTERN void AXIS2_CALL 
saml_artifact_free(saml_artifact_t *artifact, const axutil_env_t *env);

/*
 * Returns the data value of saml artifact.
 * @param artifact saml artifact srtuct
 * @param env pointer to environment struct
 */
AXIS2_EXTERN axis2_char_t* AXIS2_CALL 
saml_artifact_get_data(saml_artifact_t *artifact, const axutil_env_t *env);

/*
 * Set data value of saml artifact.
 * @param artifact saml artifact
 * @param env pointer to environment struct
 * @data data value to be set in smal artifact
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_artifact_set_data(saml_artifact_t *artifact, const axutil_env_t *env, 
					   axis2_char_t *data);
/*
 * Verify a signed saml response.
 * @param response saml response struct
 * @param env pointer to environement struct
 */
AXIS2_EXTERN int AXIS2_CALL
saml_response_signature_verify(saml_response_t *response, const axutil_env_t *env);

/*
 * Check whether the saml response has to sign.
 * @param response saml response struct
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL
saml_response_is_sign_set(saml_response_t *response, const axutil_env_t *env);

/*
 * Check whether the recieved response is signed.
 * @param response saml response struct
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL
saml_response_is_signed(saml_response_t *response, const axutil_env_t *env);

/*
 * Verify a signed saml request.
 * @param response saml request struct
 * @param env pointer to environement struct
 */
AXIS2_EXTERN int AXIS2_CALL
saml_request_signature_verify(saml_request_t *request, const axutil_env_t *env);

/*
 * Check whether the saml request has to sign.
 * @param request saml request struct
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL
saml_request_is_sign_set(saml_request_t *request, const axutil_env_t *env);

/*
 * Check whether the recieved request is signed.
 * @param request saml request struct
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL
saml_request_is_signed(saml_request_t *request, const axutil_env_t *env);

#ifdef __cplusplus
}
#endif

#endif 

