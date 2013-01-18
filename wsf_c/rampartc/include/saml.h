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
#ifndef SAML_H
#define SAML_H

#include <axutil_utils.h>
#include <axutil_array_list.h>
#include <axutil_hash.h>
#include <axutil_date_time.h>
#include <axiom.h>
#include <oxs_xml_signature.h>
#include <oxs_sign_ctx.h>
#include <oxs_xml_key_processor.h>
#include <oxs_utility.h>
#include <oxs_transforms_factory.h>
#include <oxs_xml_key_info_builder.h>
#include <oxs_key_mgr.h>
#include <oxs_transform.h>
#include <oxs_x509_cert.h>
#include <openssl_pkey.h>

#ifdef __cplusplus
extern "C"
{
#endif


#define SAML_VERSION_MAX    16
#define SAML_URI_LEN_MAX    2048
#define SAML_ARRAY_LIST_DEF    4

#define SAML_PREFIX							"saml"
#define SAML_NMSP_URI						"urn:oasis:names:tc:SAML:1.0:assertion"
#define SAML_XML_TYPE						"type"
#define SAML_XSI_NS							"http://www.w3.org/2001/XMLSchema-instance"
#define SAML_XSI							"xsi"

#define SAML_MAJORVERSION					"MajorVersion"
#define SAML_MINORVERSION					"MinorVersion"
#define SAML_ASSERTION_ID					"AssertionID"
#define SAML_ISSUER							"Issuer"
#define SAML_ISSUE_INSTANT					"IssueInstant"
#define SAML_STATEMENT						"Statement"
#define SAML_SUBJECT_STATEMENT				"SubjectStatement"
#define SAML_AUTHENTICATION_STATEMENT		"AuthenticationStatement"
#define SAML_AUTHORIZATION_DECISION_STATEMENT "AuthorizationDecisionStatement"
#define SAML_ATTRIBUTE_STATEMENT			"AttributeStatement"
#define SAML_CONDITIONS						"Conditions"
#define SAML_ADVICE							"Advice"
#define SAML_NOT_BEFORE						"NotBefore"
#define SAML_NOT_ON_OR_AFTER                "NotOnOrAfter"
#define SAML_SIGNATURE						"Signature"

#define SAML_EMAIL_ADDRESS					"#emailAddress"
#define SAML_X509_SUBJECT_NAME				"#X509SubjectName"
#define SAML_WINDOWS_DOMAIN_QUALIFIED_NAME  "#WindowsDomainQualifiedName"

#define SAML_NAME_QUALIFIER					"NameQualifier"
#define SAML_FORMAT							"Format"
#define SAML_NAME_IDENTIFIER                "NameIdentifier"
#define SAML_SUBJECT_CONFIRMATION			"SubjectConfirmation"
#define SAML_CONFIRMATION_METHOD            "ConfirmationMethod"
#define SAML_SUBJECT_CONFIRMATION_DATA		"SubjectConfirmationData"
#define SAML_KEY_INFO						"KeyInfo"
#define SAML_SUBJECT						"Subject"

#define SAML_AUDIENCE						"Audience"
#define SAML_AUDIENCE_RESTRICTION_CONDITION_TYPE "AudienceRestrictionConditionType" 
#define SAML_AUDIENCE_RESTRICTION_CONDITION "AudienceRestrictionCondition"

#define SAML_AUTHENTICATION_METHOD			"AuthenticationMethod"
#define SAML_AUTHENTICATION_INSTANT			"AuthenticationInstant"
#define SAML_IP_ADDRESS						"IPAddress" 
#define SAML_DNS_ADDRESS                    "DNSAddress"
#define SAML_SUBJECT_LOCALITY                "SubjectLocality"
#define SAML_AUTHORITY_BINDING				"AuthorityBinding"
#define SAML_AUTHORITY_KIND					"AuthorityKind"
#define SAML_LOCATION						"Location"
#define SAML_BINDING						"Binding"

#define SAML_RESOURCE						"Resource"
#define SAML_DECISION						"Decision"    
#define SAML_ACTION							"Action"
#define SAML_NAMESPACE						"Namespace"
#define SAML_ASSERTION_ID_REFERENCE			"AssertionIDReference" 
#define SAML_ASSERTION						"Assertion"    
#define SAML_ACTION							"Action"
#define SAML_EVIDENCE						"Evidence"

#define SAML_ATTRIBUTE_NAME					"AttributeName"
#define SAML_ATTRIBUTE_NAMESPACE            "AttributeNamespace"
#define SAML_ATTRIBUTE_VALUE                "AttributeValue"
#define SAML_ATTRIBUTE						"Attribute"
#define SAML_ATTRIBUTE_DESIGNATOR			"AttributeDesignator"

#define SAML_SUB_CONFIRMATION_HOLDER_OF_KEY	"urn:oasis:names:tc:SAML:1.0:cm:holder-of-key"
#define SAML_SUB_CONFIRMATION_SENDER_VOUCHES	"urn:oasis:names:tc:SAML:1.0:cm:sender-vouches"
#define SAML_SUB_CONFIRMATION_ARTIFACT		"urn:oasis:names:tc:SAML:1.0:cm:artifact-01"
#define SAML_SUB_CONFIRMATION_BEARER		"urn:oasis:names:tc:SAML:1.0:cm:bearer"

#define SAML_AUTH_METHOD_URI_PASSWORD		"urn:oasis:names:tc:SAML:1.0:am:password"
#define SAML_AUTH_METHOD_URI_KERBEROS		"urn:ietf:rfc:1510"
#define SAML_AUTH_METHOD_URI_SRP			"urn:ietf:rfc:2945"
#define SAML_AUTH_METHOD_URI_HARDWARE_TOKEN	"urn:oasis:names:tc:SAML:1.0:am:HardwareToken"
#define SAML_AUTH_METHOD_URI_SSL_TLS		"urn:ietf:rfc:2246"
#define SAML_AUTH_METHOD_URI_X509			"urn:oasis:names:tc:SAML:1.0:am:X509-PKI"
#define SAML_AUTH_METHOD_URI_PGP			"urn:oasis:names:tc:SAML:1.0:am:PGP"
#define SAML_AUTH_METHOD_URI_SPKI			"urn:oasis:names:tc:SAML:1.0:am:SPKI"
#define SAML_AUTH_METHOD_URI_XKMS			"urn:oasis:names:tc:SAML:1.0:am:XKMS"
#define SAML_AUTH_METHOD_URI_XML_DS			"urn:ietf:rfc:3075"
#define SAML_AUTH_METHOD_URI_UNSPECIFIED	"urn:oasis:names:tc:SAML:1.0:am:unspecified"

#define SAML_ACTION_URI_RWEDC_N				"urn:oasis:names:tc:SAML:1.0:action:rwedc-negation"
#define SAML_ACTION_URI_RWEDC				"urn:oasis:names:tc:SAML:1.0:action:rwedc"

#define SAML_ACTION_READ					"Read"
#define SAML_ACTION_WRITE					"Write"
#define SAML_ACTION_EXECUTE					"Execute"
#define SAML_ACTION_DELETE					"Delete"
#define SAML_ACTION_CONTROL					"Control"
#define SAML_ACTION_READ_N					"~Read"
#define SAML_ACTION_WRITE_N					"~Write"
#define SAML_ACTION_EXECUTE_N				"~Execute"
#define SAML_ACTION_DELETE_N				"~Delete"
#define SAML_ACTION_CONTROL_N				"~Control"

#define SAML_MAJOR_VERSION					"1"

typedef struct saml_assertion_s saml_assertion_t;

#ifndef SAML_DECLARE
#define SAML_DECLARE(type)	AXIS2_EXTERN type AXIS2_CALL
#endif

/* Defines the possible values to be reported as the status of an
 * authorization decision statement.
 */
typedef enum decision_type
{
    PERMIT = 0,
    DENY,
    INDETERMINATE
} decision_type_t;

typedef enum
{
    SAML_COND_UNSPECFIED = 0,
    SAML_COND_AUDI_RESTRICTION 
} saml_cond_type_t; 

typedef struct condition_s 
{
    saml_cond_type_t type;
    void *cond;
} saml_condition_t;

typedef struct saml_audi_restriction_cond_s
{
    axutil_array_list_t *audiences;	
} saml_audi_restriction_cond_t;

typedef struct saml_advise_s
{
    int a;
} saml_advise_t;

typedef enum
{
    SAML_STMT_UNSPECIFED = 0,
    SAML_STMT_SUBJECTSTATEMENT,
    SAML_STMT_AUTHENTICATIONSTATEMENT,
    SAML_STMT_AUTHORIZATIONDECISIONSTATEMENT,
    SAML_STMT_ATTRIBUTESTATEMENT
} saml_stmt_type_t;

typedef struct
{
    saml_stmt_type_t type;
    void *stmt;
} saml_stmt_t;

typedef struct saml_named_id_s
{
    /* The security or administrative domain that qualifies the name of 
     * the subject 
     */
    axis2_char_t *name_qualifier;

    /* The syntax used to describe the name of the subject */
    axis2_char_t *format;

    axis2_char_t *name;
} saml_named_id_t;


typedef struct saml_subject_s
{
    saml_named_id_t *named_id;
    
    /* URI reference that identifies a protocol to be used to authenticate 
     * the subject 
     */
    axutil_array_list_t *confirmation_methods;

    /* An XML Signature element that specifies a cryptographic key held by 
     * the subject 
     */
    axiom_node_t *key_info;

    /* Additional authentication information to be used by a specific 
     * authentication protocol 
     */
    axiom_node_t *confirmation_data;    
} saml_subject_t;

typedef struct saml_subject_stmt_s
{
    saml_subject_t *subject;
} saml_subject_stmt_t;

typedef struct saml_action
{
    /* URI for the specified action to be performed */
    char *name_space;

    /* An action to be performed on the data */
    char *data;
} saml_action_t;


typedef struct saml_evidence_s
{
    /* Specifies an assertion by reference to the value of the assertion’s 
     * AssertionID attribute 
     */
    axutil_array_list_t *assertion_ids;

    /* Specifies an assertion by value */
    axutil_array_list_t *assertions;
} saml_evidence_t;


typedef struct saml_subject_locality
{
    /* The IP address of the system entity that was authenticated */
    axis2_char_t *ip;

    /* The DNS address of the system entity that was authenticated */
    axis2_char_t *dns;
} saml_subject_locality_t;


typedef struct saml_auth_binding
{
    /* The type of SAML Protocol queries to which the authority described 
     * by this element will respond 
     */
    axis2_char_t *auth_kind;

    /* A URI reference describing how to locate and communicate with the 
     * authority 
     */
    axis2_char_t *location;

    /* A URI reference identifying the SAML protocol binding to use 
     * in communicating with the authority 
     */
    axis2_char_t *binding;
} saml_auth_binding_t;

typedef struct saml_auth_stmt
{
	saml_subject_t *subject;

    /* A URI reference that specifies the type of authentication that took place */
    axis2_char_t *auth_method;
    
    /* Specifies the time at which the authentication took place */
    axutil_date_time_t *auth_instanse;

    /* 
     * Specifies the DNS domain name and IP address for the system entity from which the Subject was
     * apparently authenticated 
     */
    /*saml_subject_locality_t *sub_locality;*/
	axis2_char_t *ip;
	
	axis2_char_t *dns;

    /* Indicates that additional information about the subject of the statement may be available */
    axutil_array_list_t *auth_binding;

} saml_auth_stmt_t;

typedef struct saml_auth_desicion_stmt
{
    saml_subject_t *subject;
    /* A URI reference identifying the resource to which access authorization */
    char *resource;

    /* The decision rendered by the issuer with respect to the specified resource */
    char *decision;

    /* The set of actions authorized to be performed on the specified resource */
    axutil_array_list_t *action;

    /* A set of assertions that the issuer relied on in making the decision */
    saml_evidence_t *evidence;
} saml_auth_desicion_stmt_t;

typedef struct saml_attr_s 
{
    /* The name of the attribute */
    char *attr_name;

    /* The namespace in which the AttributeName elements are interpreted */
    char *attr_nmsp;

    axutil_array_list_t *attr_value;
} saml_attr_t;


typedef struct saml_attr_stmt_s 
{
    saml_subject_t *subject;
    /* An attribute */
    axutil_array_list_t *attribute;
} saml_attr_stmt_t;

typedef struct saml_attr_desig_s
{
    axis2_char_t *attr_name;
    axis2_char_t *attr_nmsp;
} saml_attr_desig_t;

struct saml_assertion_s
{
    /* majod version */
    axis2_char_t *major_version;

    /* minor version */
    axis2_char_t *minor_version;

    /* id */
    axis2_char_t *assertion_id;

    /* uri representing the issuer */
    axis2_char_t *issuer;

    /* time instant of the issue */
    axutil_date_time_t *issue_instant;
	
	/* specifies the time instant at which the validity interval begins */
    axutil_date_time_t *not_before;    

	/* specifies the time instant at which the validity interval has ended */
    axutil_date_time_t *not_on_or_after;

    /* SAML condition */
    axutil_array_list_t *conditions;

    /* An XML Signature that authenticates the assertion */
    axiom_node_t *signature;

	/* array list containing the statements */
	axutil_array_list_t *statements;

	/* information about the signing */
	oxs_sign_ctx_t *sign_ctx;

	/* The xml node which is used to build the assertion */
	axiom_node_t *ori_xml;	
};

/* assertion */

/* 
 * Creates a saml assertion.
 * @param env pointer to environment struct
 */
AXIS2_EXTERN saml_assertion_t *AXIS2_CALL 
saml_assertion_create(
	const axutil_env_t *env);

/* 
 * Free a saml assertion
 * @param env pointer to environment struct
 */
AXIS2_EXTERN void AXIS2_CALL 
saml_assertion_free(
	saml_assertion_t *assertion, 
	const axutil_env_t *env);

/* 
 * Build the saml assertion from a axiom node.
 * @param assertion assertion to be populated
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_build(
	saml_assertion_t *a, 
	axiom_node_t *node, 
	const axutil_env_t *env);

/* 
 * Serialize a saml assertion to a om node.
 * @param assertion assertion to be serialized
 * @param parent if specified created node will be a child of this  
 * @param env pointer to environment struct
 */
AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_assertion_to_om(
	saml_assertion_t *assertion, 
	axiom_node_t *parent, 
	const axutil_env_t *env);

/* 
 * Returns all the condition in the assertion.
 * @param assertion assertion object
 * @param env pointer to environment struct
 */
AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_assetion_get_conditions(
	saml_assertion_t *assertion, 
	const axutil_env_t *env);

/* 
 * Returns all the statements in the assertion.
 * @param assertion SAML assertion object
 * @param env pointer to environment struct
 */
AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_assertion_get_statements(
	saml_assertion_t *assertion, 
	const axutil_env_t *env);

/* 
 * Set the conditions for the assertion. If there are conditions already 
 * specified, they will be freed. 
 * @param assertion SAML assertion object
 * @param env pointer to environment struct
 * @param list array list containing the conditions
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_set_conditions(
	saml_assertion_t *assertion, 
	const axutil_env_t *env, axutil_array_list_t *list);

/* 
 * Add a condition to the assertin.
 * @param assertion SAML assertion object
 * @param env pointer to environment struct
 * @param cond a pointer to a condition to be added
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_add_condition(
	saml_assertion_t *assertion, 
	const axutil_env_t *env, 
	saml_condition_t *cond);

/*
 * Remove a condition from the assertion.
 * @param assertion SAML assertion object
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_remove_condition(
	saml_assertion_t *assertion, 
	const axutil_env_t *env, 
	int index);

/* 
 * Set the statements for the assertion. If there are statements already 
 * specified, they will be freed. 
 * @param assertion SAML assertion object
 * @param env pointer to environment struct
 * @param list array list containing the statements
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_set_statements(
	saml_assertion_t *assertion, 
	const axutil_env_t *env, 
	axutil_array_list_t *list);

/* 
 * Add a statement to the assertin.
 * @param assertion SAML assertion object
 * @param env pointer to environment struct
 * @param cond a pointer to a statement to be added
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_add_statement(
	saml_assertion_t *assertion, 
	const axutil_env_t *env, 
	saml_stmt_t *stmt);

/*
 * Remove a statement from the assertion.
 * @param assertion SAML assertion object
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_remove_statement(
	saml_assertion_t *assertion, 
	const axutil_env_t *env, 
	int index);

/* 
 * Set the minor vertion of the assertion
 * @param assertion SAML assertion object
 * @param env pointer to environment struct
 * @param version minor version number
 */ 
AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_set_minor_version(
	saml_assertion_t *assertion, 
	const axutil_env_t *env, 
	int version);

/* 
 * Set the minor vertion of the assertion
 * @param assertion SAML assertion object
 * @param env pointer to environment struct
 */ 
AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_set_issuer(
	saml_assertion_t *assertion, 
	const axutil_env_t *env, 
	axis2_char_t *issuer);

/* 
 * Set the issuer of the assertion
 * @param assertion SAML assertion object
 * @param env pointer to environment struct
 * @instant time of the saml issue
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_set_issue_instant(
	saml_assertion_t *assertion, 
	const axutil_env_t *env, 
	axutil_date_time_t *instant);

/* 
 * Specifies the time instant at which the validity interval begins.
 * @param assertion SAML assertion object
 * @param env pointer to environment struct
 * @instant time at which validity interval begins 
 */ 
AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_set_not_before(
	saml_assertion_t *assertion, 
	const axutil_env_t *env, 
	axutil_date_time_t *time);

/* 
 * Specifies the time instant at which the validity interval has ended
 * @param assertion SAML assertion object
 * @param env pointer to environment struct
 * @instant time at which validity interval has ended 
 */ 
AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_set_not_on_or_after(
	saml_assertion_t *assertion, 
	const axutil_env_t *env, 
	axutil_date_time_t *time);

/* 
 * Return SAML authority that created the assertion. The name of the issuer 
 * is provided as a string and it is unambiguous to the relying party.
 * @param assertion SAML assertion object
 * @param env pointer to environment struct
 */
AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_assertion_get_issuer(
	saml_assertion_t *assertion, 
	const axutil_env_t *env);

/*
 * Return the time instant of issue.
 * @param assertion SAML assertion object
 * @param env pointer to environment struct
 */
AXIS2_EXTERN axutil_date_time_t * AXIS2_CALL 
saml_assertion_get_issue_instant(
	saml_assertion_t *assertion, 
	const axutil_env_t *env);

/* 
 * Get the time instant at which the validity interval begins.
 * @param assertion SAML assertion object
 * @param env pointer to environment struct
 */ 
AXIS2_EXTERN axutil_date_time_t * AXIS2_CALL 
saml_assertion_get_not_before(
	saml_assertion_t *assertion, 
	const axutil_env_t *env);

/* 
 * Get the time instant at which the validity interval has ended
 * @param assertion SAML assertion object
 * @param env pointer to environment struct
 */ 
AXIS2_EXTERN axutil_date_time_t * AXIS2_CALL 
saml_assertion_get_not_on_or_after(
	saml_assertion_t *assertion, 
	const axutil_env_t *env);

/* sign methods */

/* 
 * Get weather a assertion is signed. This is set when the Assertion is built 
 * from a om node.
 * @param assertion SAML assertion object
 * @param env pointer to environment struct
 * @return AXIS2_TRUE if signed.
 */
AXIS2_EXTERN int AXIS2_CALL
saml_assertion_is_signed(
	saml_assertion_t *assertion, 
	const axutil_env_t *env);

/*
 * Get weather a assertion is set to be signed. This applies when building 
 * the SAML object programmatically.
 * @param assertion SAML assertion object
 * @param env pointer to environment struct
 * @return AXIS2_TRUE if the object model is set to be signed.
 */
AXIS2_EXTERN int AXIS2_CALL
saml_assertion_is_sign_set(
	saml_assertion_t *assertion, 
	const axutil_env_t *env);

/*
 * Verify the assertion according to the sign context set in the 
 * saml_assertion_set_default_signature or saml_assertion_set_signature method.
 * @param assertion SAML assertion object
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL
saml_assertion_signature_verify(
	saml_assertion_t *assertion, 
	const axutil_env_t *env);

/* 
 * Sign the assertion using the information set in the 
 * saml_assertion_set_default_signature or saml_assertion_set_signature method.
 * @param assertion SAML assertion object
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL
saml_assertion_sign(
	saml_assertion_t *assertion, 
	axiom_node_t *node, 
	const axutil_env_t *env);

/* 
 * Remove the information set for signing or verifying the assertion.
 * @param assertion SAML assertion object
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_unsign(
	saml_assertion_t *assertion, 
	const axutil_env_t *env);

/* 
 * Set the information required to sign the message. 
 * @param assertion SAML assertion object
 * @param env pointer to environment struct
 * @param sign_ctx oxs_sign_ctx_t object which contains the sign information
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_set_default_signature(
	saml_assertion_t *assertion, 
	const axutil_env_t *env, 
	oxs_sign_ctx_t *sign_ctx);

/* 
 * Set the information required to sign the message.
 * @param assertion SAML assertion object
 * @param env pointer to environment struct
 * @param sign_ctx oxs_sign_ctx_t object which contains the sign information
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_set_signature(
	saml_assertion_t *assertion, 
	const axutil_env_t *env, 
	oxs_sign_ctx_t *sign_ctx);


/* statement */

/* 
 * Create a saml statement. Statement is a generic object which can hold 
 * tatement object can hold other statements like Autherization statements.
 * @param env pointer to environment struct 
 * @return saml_stmt object to hold other staments
 */
AXIS2_EXTERN saml_stmt_t * AXIS2_CALL 
saml_stmt_create(
	const axutil_env_t *env);

/* 
 * Free a saml statment. 
 * @param stmt SAML stmt object
 * @param env pointer to environment struct
 */
AXIS2_EXTERN void AXIS2_CALL 
saml_stmt_free(
	saml_stmt_t *stmt, 
	const axutil_env_t *env);

/* 
 * Build a saml statement from a XML node. The statement types that are 
 * supported are Authentication Statement, Attribute Statement, 
 * Authentication Dicision Statement.
 * @param stmt SAML stmt object
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_stmt_build(
	saml_stmt_t *stmt, 
	axiom_node_t *node, 
	const axutil_env_t *env);

/*
 * Serialize a statement to a axiom node.
 * @param stmt SAML stmt object
 * @param parent if specified created node will be a child of this  
 * @param env pointer to environment struct
 */
AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_stmt_to_om(saml_stmt_t *stmt, axiom_node_t *parent, const axutil_env_t *env);

/*
 * Get the type of the statement. 
 * @param stmt SAML stmt object
 * @param env pointer to environment struct
 * @return statment type as saml_stmt_type_t
 */
AXIS2_EXTERN saml_stmt_type_t AXIS2_CALL 
saml_stmt_get_type(saml_stmt_t *stmt, const axutil_env_t *env);

/*
 * Return the specific stament in this statement. 
 * @param stmt SAML stmt object
 * @param env pointer to environment struct
 */
AXIS2_EXTERN saml_stmt_t * AXIS2_CALL 
saml_stmt_get_stmt(saml_stmt_t *stmt, const axutil_env_t *env);

/* 
 * Set the type of statement.
 * @param stmt SAML stmt object
 * @param env pointer to environment struct
 * @param type type of the statement as saml_stmt_type_t 
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_stmt_set_type(saml_stmt_t *stmt, const axutil_env_t *env, saml_stmt_type_t type);

/*
 * Set the statement. If a statment is already specified it will be freed.
 * @param stmt SAML stmt object
 * @param env pointer to environment struct
 * @param st pointer to the statement to be set
 * @param type type of the statement as saml_stmt_type_t 
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_stmt_set_stmt(saml_stmt_t *stmt, const axutil_env_t *env, 
				   void *st, saml_stmt_type_t type);


/*AXIS2_EXTERN int AXIS2_CALL saml_id_init(saml_id_t *id, const axutil_env_t *env);*/
AXIS2_EXTERN axis2_char_t * AXIS2_CALL saml_id_generate_random_bytes(const axutil_env_t *env);
/*AXIS2_EXTERN void AXIS2_CALL saml_id_uninit(saml_id_t *id, const axutil_env_t *env);*/


/* AuthorityBinding */

/*
 * Creates a SAML AuthorityBinding.
 * @param env pointer to environment struct
 */
AXIS2_EXTERN saml_auth_binding_t * AXIS2_CALL 
saml_auth_binding_create(const axutil_env_t *env);

/*
 * Free a SAML Autherity binding.
 * @param auth_bind SAML Autherity binding object
 * @param env pointer to environment struct
 */
AXIS2_EXTERN void AXIS2_CALL 
saml_auth_binding_free(saml_auth_binding_t *auth_bind, const axutil_env_t *env);

/*
 * Create a SAML autherity binding from a XML node.
 * @param auth_bind SAML Autherity binding object
 * @param node XML node containing the autherity binding 
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_auth_binding_build(saml_auth_binding_t *auth_bind, 
						axiom_node_t *node, const axutil_env_t *env);

/*
 * Serialize an auth binding to axiom node
 * @param auth_bind SAML Autherity binding object
 * @param parent if specified created node will be a child of this node  
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_auth_binding_to_om(saml_auth_binding_t *auth_binding, 
						axiom_node_t *parent, const axutil_env_t *env);

/*
 * Return the type of SAML protocol queries to which the authority described 
 * by this element will respond.
 * @param auth_bind SAML Autherity binding object
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_auth_binding_get_authoity_kind(saml_auth_binding_t *auth_bind, 
									const axutil_env_t *env);

/*
 * Return the URI identifying the SAML protocol binding to use in 
 * communicating with the authority.
 * @param auth_bind SAML Autherity binding object
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_auth_binding_get_binding(saml_auth_binding_t *auth_binding, 
							  const axutil_env_t *env);

/*
 * Return a URI describing how to locate and communicate with the authority
 * @param auth_bind SAML Autherity binding object
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_auth_binding_get_location(saml_auth_binding_t *auth_bind, 
							   const axutil_env_t *env);

/*
 * Set the type of SAML protocol queries to which the authority described 
 * by this element will respond.
 * @param auth_bind SAML Autherity binding object
 * @param env pointer to environment struct 
 * @param auth_kind A string representing the SAML protocol queries 
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_auth_binding_set_authority_kind(saml_auth_binding_t *auth_bind, 
									 const axutil_env_t *env, axis2_char_t *auth_kind);

/*
 * Set the URI identifying the SAML protocol binding to use in 
 * communicating with the authority.
 * @param auth_bind SAML Autherity binding object
 * @param env pointer to environment struct 
 * @param binding URI identifying the SAML protocol binding 
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_auth_binding_set_binding(saml_auth_binding_t *auth_bind, 
							  const axutil_env_t *env, axis2_char_t *binding);

/*
 * Set a URI describing how to locate and communicate with the authority
 * @param auth_bind SAML Autherity binding object
 * @param env pointer to environment struct 
 * @param location URI describing location and communication protocol
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_auth_binding_set_location(saml_auth_binding_t *auth_bind, 
							   const axutil_env_t *env, axis2_char_t *location);


/* subject locality */

/*
 * Create a SAML subject locality.
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN saml_subject_locality_t * AXIS2_CALL 
saml_subject_locality_create(const axutil_env_t *env);

/*
 * Free a SAML subject locality.
 * @param sub_locality SAML subject locality object
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN void AXIS2_CALL 
saml_subject_locality_free(saml_subject_locality_t *sub_locality, 
						   const axutil_env_t *env);

/*
 * Populate a SAML subject locality from a XML node containing a SAML 
 * subject locality.
 * @param sub_locality SAML subject locality object
 * @param node XML node containing the SAML subject locality
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_subject_locality_build(saml_subject_locality_t *sub_locality, 
							axiom_node_t *node, const axutil_env_t *env);

/*
 * Serialize a subject locality to an axiom node.
 * @param sub_locality SAML subject locality object
 * @param parent if specified created node will be a child of this node  
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN axiom_node_t *AXIS2_CALL 
saml_subject_locality_to_om(saml_subject_locality_t *sub_locality, 
							axiom_node_t *parent, const axutil_env_t *env);

/*
 * Return the IP address of the system entity that was authenticated.
 * @param sub_locality SAML subject locality object
 * @param env pointer to environment struct 
 * @return IP address
 */
AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_subject_locality_get_ip(saml_subject_locality_t *sub_locality, 
							 const axutil_env_t *env);

/*
 * Return the DNS address of the system entity that was authenticated.
 * @param sub_locality SAML subject locality object
 * @param env pointer to environment struct 
 * @return DNS address
 */
AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_subject_locality_get_dns(saml_subject_locality_t *sub_locality, 
							  const axutil_env_t *env);

/*
 * Set the IP address of the system entity that was authenticated.
 * @param sub_locality SAML subject locality object
 * @param env pointer to environment struct 
 * @param ip IP address
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_subject_locality_set_ip(saml_subject_locality_t *sub_locality, 
							 const axutil_env_t *env, axis2_char_t *ip);

/*
 * Set the DNS address of the system entity that was authenticated.
 * @param sub_locality SAML subject locality object
 * @param env pointer to environment struct 
 * @param ip DNS address
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_subject_locality_set_dns(saml_subject_locality_t *sub_locality, 
							  const axutil_env_t *env, axis2_char_t *dns);


/* subject */

/*
 * Create a SAML subject
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN saml_subject_t * AXIS2_CALL 
saml_subject_create(const axutil_env_t *env);

/*
 * Free a SAML subject
 * @param subject SAML subject object
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN void AXIS2_CALL 
saml_subject_free(saml_subject_t *subject, const axutil_env_t *env);

/*
 * Populates a SAML subject from a XML node containing a SAML subject.
 * @param subject SAML subject object
 * @param node XML node containing the SAML subject locality
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_subject_build(saml_subject_t *subject, 
				   axiom_node_t *node, const axutil_env_t *env);

/*
 * Serialize a SAML subject to a axiom node.
 * @param subject SAML subject object
 * @param parent if specified created node will be a child of this node  
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_subject_to_om(saml_subject_t *subject, 
				   axiom_node_t *parent, const axutil_env_t *env);

/*
 * Return the named id of the subject.
 * @param subject SAML subject object
 * @param env pointer to environment struct 
 * @return named id object
 */
AXIS2_EXTERN saml_named_id_t * AXIS2_CALL 
saml_subject_get_named_id(saml_subject_t *subject, const axutil_env_t *env);

/*
 * Return the list of confirmation methods. Array list contains string values.
 * @param subject SAML subject object
 * @param env pointer to environment struct 
 * @return list containing the subject confirmation methods
 */
AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_subject_get_confirmation_methods(saml_subject_t *subject, 
									  const axutil_env_t *env);

/*
 * Return the list of confirmation data. Array list contains string values.
 * @param subject SAML subject object
 * @param env pointer to environment struct 
 * @return list containing the subject confirmation data
 */
AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_subject_get_confirmation_data(saml_subject_t *subject, const axutil_env_t *env);

/*
 * Return an axiom node containing the key info of this subject. The axiom node 
 * is a ds:keyinfo of XML signature. 
 * @param subject SAML subject object
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_subject_get_key_info(saml_subject_t *subject, const axutil_env_t *env);

/*
 * Set the named id of the subject.
 * @param subject SAML subject object
 * @param env pointer to environment struct  
 * @param named_id a named id to be set
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_subject_set_named_id(saml_subject_t *subject, 
						  const axutil_env_t *env, saml_named_id_t *named_id);

/*
 * Set the confirmation as a array list. The array list should contain 
 * string values. If confirmation methods are already present they will 
 * be freed.
 * @param subject SAML subject object
 * @param env pointer to environment struct  
 * @param list list of confirmation methods
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_subject_set_confirmation_methods(saml_subject_t *subject, 
									  const axutil_env_t *env, 
									  axutil_array_list_t *list);
/* 
 * Add a subject confirmation to this subject.
 * @param subject SAML subject object
 * @param env pointer to environment struct
 * @param sub_confirmation subject confirmation
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_subject_add_confirmation(saml_subject_t *subject, 
							  const axutil_env_t *env, 
							  axis2_char_t *sub_confirmation);

/* 
 * Remove a subject confirmatin at the specified index.
 * @param subject SAML subject object
 * @param env pointer to environment struct
 * @param index index of the subject confirmation
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_subject_remove_subject_confiirmation(saml_subject_t *subject, 
										  const axutil_env_t *env, int index);

/* 
 * Set an XML Signature keyinfo element that provides access to a cryptographic 
 * key held by the subject
 * @param subject SAML subject object
 * @param env pointer to environment struct
 * @param node XML signature keyinfo element
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_subject_set_key_info(saml_subject_t *subject, 
						  const axutil_env_t *env, axiom_node_t *node);

/* subject statement */

/*
 * Builds a subject statement from a om node containing a subject statement.
 * @param subject_stmt a subject statement object
 * @param node om node containing a subject statement
 * @param env pointer to environment struct
 */ 
AXIS2_EXTERN int AXIS2_CALL 
saml_subject_stmt_build(saml_subject_stmt_t *subject_stmt, 
						axiom_node_t *node, const axutil_env_t *env);

/* 
 * Free a subject statement object
 * @param subject_stmt a subject statement object 
 * @param env pointer to environment struct
 */
AXIS2_EXTERN void AXIS2_CALL 
saml_subject_stmt_free(saml_subject_stmt_t *subject_stmt, 
					   const axutil_env_t *env);

/* 
 * Create a subject statment object
 * @param env pointer to environment struct
 * @return a subject statement object
 */
AXIS2_EXTERN saml_subject_stmt_t * AXIS2_CALL 
saml_subject_stmt_create(const axutil_env_t *env);

/*
 * Serialize a subject statment to an axiom node
 * @param subject_stmt a subject statement object 
 * @param parent if specified created node will be a child of this node  
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_subject_stmt_to_om(saml_subject_stmt_t *subject_stmt, 
						axiom_node_t *parent, const axutil_env_t *env);

/* 
 * Set the subject of the subject statement
 * @param subject_stmt a subject statement object 
 * @param env pointer to environment struct 
 * @param subject subject to be set
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_subject_stmt_set_subject(saml_subject_stmt_t *subject_stmt, 
							  const axutil_env_t *env, saml_subject_t *subject);

/*
 * Set the subject of the subject statement
 * @param subject_stmt a subject statement object 
 * @param env pointer to environment struct 
 * @param subject subject to be set
 */
AXIS2_EXTERN saml_subject_t * AXIS2_CALL 
saml_subject_stmt_get_subject(saml_subject_stmt_t *subject_stmt, 
							  const axutil_env_t *env);

/* auth desicin statement */
/*
 * Create an autherization decision statement object.
 * @param env pointer to environment struct 
 * @return an autherization decision statement object
 */
AXIS2_EXTERN saml_auth_desicion_stmt_t * AXIS2_CALL 
saml_auth_desicion_stmt_create(const axutil_env_t *env);

/*
 * Free an autherization decision statement object.
 * @param auth_des_stmt a autherization decision statement object
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN void AXIS2_CALL 
saml_auth_desicion_stmt_free(saml_auth_desicion_stmt_t *auth_des_stmt, 
							 const axutil_env_t *env);

/*
 * Populates an saml_auth_desicion_stmt_t object from a XML node containing
 * autherization decision statement.
 * @param auth_des_stmt a autherization decision statement object
 * @param node xml node containing autherization decision object.
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_auth_desicion_stmt_build(saml_auth_desicion_stmt_t *auth_des_stmt, 
							  axiom_node_t *node, const axutil_env_t *env);

/*
 * Serialize an saml_auth_desicion_stmt_t object to a axiom node.
 * @param auth_des_stmt a autherization decision statement object
 * @param parent if specified created node will be a child of this node  
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_auth_desicion_stmt_to_om(saml_auth_desicion_stmt_t *auth_des_stmt, 
							  axiom_node_t *parent, const axutil_env_t *env);

/*
 * Get the subject which is in this autheization decision statement.
 * @param auth_des_stmt a autherization decision statement object
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN saml_subject_t * AXIS2_CALL 
saml_auth_desicion_stmt_get_subject(saml_auth_desicion_stmt_t *auth_des_stmt, 
									const axutil_env_t *env);
/*
 * Return a URI reference identifying the resource to which access 
 * authorization is sought.
 * @param auth_des_stmt a autherization decision statement object
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_auth_desicion_stmt_get_resource(saml_auth_desicion_stmt_t *auth_des_stmt, 
									 const axutil_env_t *env);

/*
 * Return the decision rendered by the SAML authority with respect to 
 * the specified resource. 
 * @param auth_des_stmt a autherization decision statement object
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_auth_desicion_stmt_get_desicion(saml_auth_desicion_stmt_t *auth_des_stmt, 
									 const axutil_env_t *env);

/* 
 * Return the list of actions authorized to be performed on the specified 
 * resource.
 * @param auth_des_stmt a autherization decision statement object
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_auth_desicion_stmt_get_actions(saml_auth_desicion_stmt_t *auth_des_stmt, 
									const axutil_env_t *env);

/*
 * Return the list of assertions that the SAML authority relied on in making 
 * the decision.
 * @param auth_des_stmt a autherization decision statement object
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN saml_evidence_t * AXIS2_CALL 
saml_auth_desicion_stmt_get_evidence(saml_auth_desicion_stmt_t *auth_des_stmt, 
									 const axutil_env_t *env);

/*
 * Set a URI reference identifying the resource to which access 
 * authorization is sought.
 * @param auth_des_stmt a autherization decision statement object
 * @param env pointer to environment struct 
 * @param resource a URI referencing the resource
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_auth_desicion_stmt_set_resource(saml_auth_desicion_stmt_t *auth_des_stmt, 
									 const axutil_env_t *env, axis2_char_t *resource);

/*
 * Set the decision rendered by the SAML authority with respect to 
 * the specified resource as a string value. Valid decisions are Permit, 
 * Deny and Indeterminate.
 * @param auth_des_stmt a autherization decision statement object
 * @param env pointer to environment struct 
 * @param decision set the decision.
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_auth_desicion_stmt_set_desicion(saml_auth_desicion_stmt_t *auth_des_stmt, 
									 const axutil_env_t *env, axis2_char_t *desicion);

/* 
 * Set the list of actions authorized to be performed on the specified 
 * resource.
 * @param auth_des_stmt a autherization decision statement object
 * @param env pointer to environment struct 
 * @param list list containing action objects
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_auth_desicion_stmt_set_actions(saml_auth_desicion_stmt_t *auth_des_stmt, 
									const axutil_env_t *env, axutil_array_list_t *list);

/*
 * Remove an action in the specified index.
 * @param auth_des_stmt a autherization decision statement object
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_auth_desicion_stmt_remove_action(saml_auth_desicion_stmt_t *auth_des_stmt, 
									  const axutil_env_t *env, int index);

/*
 * Add an action.
 * @param auth_des_stmt a autherization decision statement object
 * @param env pointer to environment struct 
 * @param action action object to be added
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_auth_desicion_stmt_add_action(saml_auth_desicion_stmt_t *auth_des_stmt, 
								   const axutil_env_t *env, saml_action_t *action);

/*
 * Set the subject of the autherization decision object
 * @param auth_des_stmt a autherization decision statement object
 * @param env pointer to environment struct 
 * @param subject subject to be added
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_auth_desicion_stmt_set_subject(saml_auth_desicion_stmt_t *auth_des_stmt, 
									const axutil_env_t *env, saml_subject_t *subject);

/* auth statement */

/*
 * Create an autherization statement.
 * @param env pointer to environment struct 
 * @return autherization statement object
 */ 
AXIS2_EXTERN saml_auth_stmt_t * AXIS2_CALL 
saml_auth_stmt_create(const axutil_env_t *env);

/*
 * Free a autherization statement.
 * @param auth_stmt autherization statment object
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN void AXIS2_CALL 
saml_auth_stmt_free(saml_auth_stmt_t *auth_stmt, const axutil_env_t *env);

/*
 * Populates an auth_stmt from a om node containing a autherization statement
 * @param auth_stmt autherization statment object
 * @param node an om node containing an autherization statement
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_build(saml_auth_stmt_t *auth_stmt, 
					 axiom_node_t *node, const axutil_env_t *env);

/*
 * Serialize an autherization statement to an om node
 * @param auth_stmt autherization statment object
 * @param parent if specified created node will be a child of this node  
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN axiom_node_t *AXIS2_CALL 
saml_auth_stmt_to_om(saml_auth_stmt_t *auth_stmt, 
					 axiom_node_t *parent, const axutil_env_t *env);

/*
 * Return a URI reference that specifies the type of authentication that 
 * took place.
 * @param auth_stmt autherization statment object
 * @param env pointer to environment struct
 * @return URI reference 
 */
AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_auth_stmt_get_auth_method(saml_auth_stmt_t *auth_stmt, 
							   const axutil_env_t *env);

/*
 * Return the time at which the authentication took place.
 * @param auth_stmt autherization statment object
 * @param env pointer to environment struct
 * @return time at which authentication took place 
 */
AXIS2_EXTERN axutil_date_time_t * AXIS2_CALL 
saml_auth_stmt_get_auth_instant(saml_auth_stmt_t *auth_stmt, 
								const axutil_env_t *env);

/*
 * Return a list of additional information about the subject of 
 * the statement that may be available.
 * @param auth_stmt autherization statment object
 * @param env pointer to environment struct
 * @return a list of autherization binings
 */
AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_auth_stmt_get_auth_bindings(saml_auth_stmt_t *auth_stmt, 
								 const axutil_env_t *env);

/*
 * Return the IP address of the system entity that was authenticated.
 * @param auth_stmt autherization statment object
 * @param env pointer to environment struct
 * @return an IP address
 */
AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_auth_stmt_get_subject_ip(saml_auth_stmt_t *auth_stmt, 
							  const axutil_env_t *env);
/*
 * Return the DNS address of the system entity that was authenticated.
 * @param auth_stmt autherization statment object
 * @param env pointer to environment struct
 * @return an DNS address
 */
AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_auth_stmt_get_subject_dns(saml_auth_stmt_t *auth_stmt, 
							   const axutil_env_t *env);

/* 
 * Set the subject of the autherization statement
 * @param auth_stmt autherization statment object
 * @param env pointer to environment struct
 * @param subject a subject to be added
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_set_subject(saml_auth_stmt_t *auth_stmt, 
						   const axutil_env_t *env, saml_subject_t *subject);

/*
 * Set a URI reference that specifies the type of authentication that 
 * took place.
 * @param auth_stmt autherization statment object
 * @param env pointer to environment struct
 * @param method URI reference 
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_set_auth_method(saml_auth_stmt_t *auth_stmt, 
							   const axutil_env_t *env, axis2_char_t *method);

/*
 * Set the time at which the authentication took place.
 * @param auth_stmt autherization statment object
 * @param env pointer to environment struct
 * @param dt time at which authentication took place 
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_set_auth_instant(saml_auth_stmt_t *auth_stmt, 
								const axutil_env_t *env, axutil_date_time_t *dt);

/*
 * Set a list of additional information about the subject of 
 * the statement that may be available as auth_bindings.
 * @param auth_stmt autherization statment object
 * @param env pointer to environment struct
 * @param list a list of autherization binings
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_set_auth_bindings(saml_auth_stmt_t *auth_stmt, 
								 const axutil_env_t *env, axutil_array_list_t *list);

/*
 * Add a additional information about the subject of 
 * the statement that may be available as an auth_binding.
 * @param auth_stmt autherization statment object
 * @param env pointer to environment struct
 * @param bind an authority binding
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_add_auth_binding(saml_auth_stmt_t *auth_stmt, 
								const axutil_env_t *env, saml_auth_binding_t *bind);

/*
 * Remove an authority binding from a auth_statement.
 * @param auth_stmt autherization statment object
 * @param env pointer to environment struct
 * @param index index of the authority binding to be removed
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_remove_auth_binding(saml_auth_stmt_t *auth_stmt, 
								   const axutil_env_t *env, int index);

/*
 * Set the DNS address of the system entity that was authenticated.
 * @param auth_stmt autherization statment object
 * @param env pointer to environment struct
 * @param dns a DNS address
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_set_subject_dns(saml_auth_stmt_t *auth_stmt, 
							   const axutil_env_t *env, axis2_char_t *dns);

/*
 * Set the IP address of the system entity that was authenticated.
 * @param auth_stmt autherization statment object
 * @param env pointer to environment struct
 * @param ip an IP address
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_set_subject_ip(saml_auth_stmt_t *auth_stmt, 
							  const axutil_env_t *env, axis2_char_t *ip);

/* attribute statement */

/*
 * Create a attribute statement.
 * @param env pointer to environment struct
 * @return saml attribute object
 */
AXIS2_EXTERN saml_attr_stmt_t * AXIS2_CALL 
saml_attr_stmt_create(const axutil_env_t *env);

/*
 * Free an attribute statement.
 * @param attr_stmt pointer to an attribute statement object
 * @param env pointer to environment struct
 */
AXIS2_EXTERN void AXIS2_CALL 
saml_attr_stmt_free(saml_attr_stmt_t *attr_stmt, const axutil_env_t *env);

/* 
 * Populates a attribute statement object from a axiom node containing a 
 * attribute statement.
 * @param attr_stmt pointer to an attribute statement object
 * @param node om node containing a attribute statement
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_attr_stmt_build(saml_attr_stmt_t *attr_stmt, 
					 axiom_node_t *node, const axutil_env_t *env);

/*
 * Serialize an saml_attr_stmt to an om node
 * @param attr_stmt pointer to an attribute statement object
 * @param parent if specified created node will be a child of this node  
 * @param env pointer to environment struct
 */
AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_attr_stmt_to_om(saml_attr_stmt_t *attr_stmt, 
					 axiom_node_t *parent, const axutil_env_t *env);

/*
 * Get the saml subject in this attribute statement.
 * @param attr_stmt pointer to an attribute statement object
 * @param env pointer to environment struct
 * @return saml subject
 */
AXIS2_EXTERN saml_subject_t * AXIS2_CALL 
saml_attr_stmt_get_subject(saml_attr_stmt_t *attr_stmt, const axutil_env_t *env);

/*
 * Get the list of attributes in this attribute statement.
 * @param attr_stmt pointer to an attribute statement object
 * @param env pointer to environment struct
 * @return array list containing the attribute objects
 */
AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_attr_stmt_get_attributes(saml_attr_stmt_t *attr_stmt, const axutil_env_t *env);

/*
 * Set the subject of this attribute statement
 * @param attr_stmt pointer to an attribute statement object
 * @param env pointer to environment struct
 * @param subject 
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_attr_stmt_set_subject(saml_attr_stmt_t *attr_stmt, 
						   const axutil_env_t *env, saml_subject_t *subject);

/*
 * Set the attributes of the attribute statement as a list. If the attribute 
 * statement already contains attributes they will be replaced.
 * @param attr_stmt pointer to an attribute statement object
 * @param env pointer to environment struct
 * @param list attribute list
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_attr_stmt_set_attributes(saml_attr_stmt_t *attr_stmt, 
							  const axutil_env_t *env, axutil_array_list_t *list);

/*
 * Add an attribute to the attribute statement       
 * @param attr_stmt pointer to an attribute statement object
 * @param env pointer to environment struct
 * @param attribute an attribute to be added
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_attr_stmt_add_attribute(saml_attr_stmt_t *attr_stmt, 
							 const axutil_env_t *env, saml_attr_t *attribute);

/* 
 * Remove an attribute at the given index.
 * @param attr_stmt pointer to an attribute statement object
 * @param env pointer to environment struct
 * @param index index of the attribute
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_attr_stmt_remove_attribute(saml_attr_stmt_t *attr_stmt, 
								const axutil_env_t *env, int index);

/* condition */

/*
 * Create a generic condition. Condition objects holds more specific 
 * conditions. The type attribute of a condition determines the specific 
 * condition.
 * @param env pointer to environment struct
 */
AXIS2_EXTERN saml_condition_t * AXIS2_CALL 
saml_condition_create(const axutil_env_t *env);

/*
 * Free a condition object. The specific condition which is in this conditions 
 * will also be freed.
 * @param cond pointer to a condition object
 * @param env pointer to environment struct
 */
AXIS2_EXTERN void AXIS2_CALL 
saml_condition_free(saml_condition_t *cond, const axutil_env_t *env);

/*
 * Populates a condition from a om node containing a condition. After this a 
 * specific condition will be built and set to this condition. 
 * @param cond pointer to a condition object
 * @param env pointer to environment struct
 * @param node om node containing a condition
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_condition_build(saml_condition_t *cond, 
					 axiom_node_t *node, const axutil_env_t *env);

/* 
 * Serialize a condition to a om node. 
 * @param cond pointer to a condition object
 * @param parent if specified created node will be a child of this node  
 * @param env pointer to environment struct
 */
AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_condition_to_om(saml_condition_t *cond, 
					 axiom_node_t *parent, const axutil_env_t *env);

/*
 * Set the specific condition for this condition.
 * @param cond pointer to a condition object
 * @param env pointer to environment struct
 * @param condition the specific condition
 * @param type condition type
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_condition_set_condition(saml_condition_t *cond, 
							 const axutil_env_t *env, void * condition, 
							 saml_cond_type_t type);

/*
 * Set the type of the conition. 
 * @param cond pointer to a condition object
 * @param env pointer to environment struct
 * @param type specific type of the condition
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_condition_set_type(saml_condition_t *cond, 
						const axutil_env_t *env, saml_cond_type_t type);

/*
 * Get the specific condtion in this generic condition.
 * @param cond pointer to a condition object
 * @param env pointer to environment struct
 */
AXIS2_EXTERN void * AXIS2_CALL 
saml_condition_get_condition(saml_condition_t *cond, const axutil_env_t *env);

/*
 * Get the type of the specific condtion in this generic condition.
 * @param cond pointer to a condition object
 * @param env pointer to environment struct
 */
AXIS2_EXTERN saml_cond_type_t AXIS2_CALL 
saml_condition_get_type(saml_condition_t *cond, const axutil_env_t *env);

/* audio restriction */

/*
 * Populates an audi restriction condition from an om node.
 * @param arc a ponter to saml_aud_restriction_conf object
 * @param node om node containing an audience restriction condition
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_audi_restriction_cond_build(saml_audi_restriction_cond_t *arc, 
								 axiom_node_t *node, const axutil_env_t *env);

/*
 * Serialize an saml_audi_restriction_cond_t object in to an om node.
 * @param arc a ponter to saml_aud_restriction_conf object
 * @param parent if specified created node will be a child of this node  
 * @param env pointer to environment struct
 */
AXIS2_EXTERN axiom_node_t *AXIS2_CALL 
saml_audi_restriction_cond_to_om(saml_audi_restriction_cond_t *arc, 
								 axiom_node_t *parent, const axutil_env_t *env);

/*
 * Free a saml_aud_restriction_conf object.
 * @param arc a ponter to saml_aud_restriction_conf object
 * @param env pointer to environment struct
 */
AXIS2_EXTERN void AXIS2_CALL 
saml_audi_restriction_cond_free(saml_audi_restriction_cond_t *arc, 
								const axutil_env_t *env);

/*
 * Create a saml_aud_restriction_conf object.
 * @param env pointer to environment struct
 * @return a ponter to saml_aud_restriction_conf object
 */
AXIS2_EXTERN saml_audi_restriction_cond_t * AXIS2_CALL 
saml_audi_restriction_cond_create(const axutil_env_t *env);

/*
 * Return a list of URI references that identifies a list of intended audiences.
 * @param arc a ponter to saml_aud_restriction_conf object
 * @param env pointer to environment struct
 */
AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_audi_restriction_cond_get_audiences(saml_audi_restriction_cond_t *arc, 
										 const axutil_env_t *env);

/*
 * Set a list of URI references that identifies a list of intended audiences.
 * @param arc a ponter to saml_aud_restriction_conf object
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_audi_restriction_cond_set_audiences(saml_audi_restriction_cond_t *cond, 
										 const axutil_env_t *env, axutil_array_list_t *list);

/*
 * Remove a URI reference that identifies an intended audiences.
 * @param arc a ponter to saml_aud_restriction_conf object
 * @param env pointer to environment struct
 * @param index the number of the audience in the list, to be removed
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_audi_restriction_cond_remove_audiences(saml_audi_restriction_cond_t *cond, 
											const axutil_env_t *env, int index);

/*
 * Ad a URI reference that identifies an intended audiences.
 * @param arc a ponter to saml_aud_restriction_conf object
 * @param env pointer to environment struct
 * @param audience a new audience to be added
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_audi_restriction_cond_add_audience(saml_audi_restriction_cond_t *cond, 
										const axutil_env_t *env, axis2_char_t *audience);


/* action */

/*
 * Create a saml_action_t.
 * @param env pointer to environment struct
 * @return pointer to saml_action_t 
 */
AXIS2_EXTERN saml_action_t * AXIS2_CALL 
saml_action_create(const axutil_env_t *env);

/*
 * Free a saml_action_t.
 * @param action pointer to saml_action_t 
 * @param env pointer to environment struct
 */
AXIS2_EXTERN void AXIS2_CALL 
saml_action_free(saml_action_t *action, const axutil_env_t *env);

/*
 * Populates a saml action from a om node containing a saml action.
 * @param action pointer to saml_action_t 
 * @param node om node conatining a saml action
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_action_build(saml_action_t *action, axiom_node_t *node, const axutil_env_t *env);

/*
 * Serialize a action_t object to an om node.
 * @param action pointer to saml_action_t 
 * @param parent if specified created node will be a child of this node  
 * @param env pointer to environment struct
 */
AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_action_to_om(saml_action_t *action, 
				  axiom_node_t *parent, const axutil_env_t *env);

/*
 * Get an action sought to be performed on the specified resource.
 * @param action pointer to saml_action_t 
 * @param env pointer to environment struct
 */
AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_action_get_data(saml_action_t *action, const axutil_env_t *env);

/*
 * Get a URI reference representing the namespace in which the name of the 
 * specified action is to be interpreted.
 * @param action pointer to saml_action_t 
 * @param env pointer to environment struct
 */
AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_action_get_namespace(saml_action_t *action, const axutil_env_t *env);

/*
 * Set an action sought to be performed on the specified resource.
 * @param action pointer to saml_action_t 
 * @param env pointer to environment struct
 * @param data an action to be performed
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_action_set_data(saml_action_t *action, const axutil_env_t *env, 
					 axis2_char_t *data);

/*
 * Set a URI reference representing the namespace in which the name of the 
 * specified action is to be interpreted.
 * @param action pointer to saml_action_t 
 * @param env pointer to environment struct
 * @param name_space a URI reference
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_action_set_namespace(saml_action_t *action, const axutil_env_t *env, 
						  axis2_char_t *name_space);

/* evidence */
AXIS2_EXTERN saml_evidence_t * AXIS2_CALL 
saml_evidence_create(const axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL 
saml_evidence_free(saml_evidence_t *evidence, const axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_evidence_build(saml_evidence_t *evidence, 
					axiom_node_t *node, const axutil_env_t *env);

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_evidence_to_om(saml_evidence_t *evidence, axiom_node_t *parent, 
					const axutil_env_t *env);

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_evidence_get_assertions(saml_evidence_t *evidence, const axutil_env_t *env);

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_evidence_get_assertion_ids(saml_evidence_t *evidence, const axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_evidence_set_assertions(saml_evidence_t *evidence, 
							 const axutil_env_t *env, axutil_array_list_t *list);

AXIS2_EXTERN int AXIS2_CALL 
saml_evidence_remove_assertion(saml_evidence_t *evidence, 
							   const axutil_env_t *env, int index);

AXIS2_EXTERN int AXIS2_CALL 
saml_evidence_add_assertion(saml_evidence_t *evidence, 
							const axutil_env_t *env, saml_assertion_t *assertion);

AXIS2_EXTERN int AXIS2_CALL 
saml_evidence_set_assertion_ids(saml_evidence_t *evidence, 
								const axutil_env_t *env, axutil_array_list_t *list);

AXIS2_EXTERN int AXIS2_CALL 
saml_evidence_remove_assertion_id(saml_evidence_t *evidence, 
								  const axutil_env_t *env, int index);

AXIS2_EXTERN int AXIS2_CALL 
saml_evidence_add_assertion_id(saml_evidence_t *evidence, 
							   const axutil_env_t *env, axis2_char_t *assertion_id);

/* atrribute designature */

/* 
 * Create a saml_attr_desig_t. 
 * @param env pointer to environment struct
 * @return pointer to saml_attr_desig_t
 */
AXIS2_EXTERN saml_attr_desig_t * AXIS2_CALL 
saml_attr_desig_create(const axutil_env_t *env);

/* 
 * Free a saml_attr_desig_t. 
 * @param attr_desig a pointer to saml_attr_desig_t
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN void AXIS2_CALL 
saml_attr_desig_free(saml_attr_desig_t *attr_desig, const axutil_env_t *env);

/*
 * Populates a saml_attr_desig_t from a om node contailing a saml attriibute desgnator
 * @param attr_desig a pointer to saml_attr_desig_t
 * @param node om node containing saml attriibute desgnator
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_attr_desig_build(saml_attr_desig_t *attr_desig, 
					  axiom_node_t *node, const axutil_env_t *env);

/*
 * Serialize a saml_attr_desig_t to an om node.
 * @param attr_desig a pointer to saml_attr_desig_t
 * @param parent if specified created node will be a child of this node  
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_attr_desig_to_om(saml_attr_desig_t *attr_desig, 
					  axiom_node_t *parent, const axutil_env_t *env);

/* 
 * Get the name of the attribute.
 * @param attr_desig a pointer to saml_attr_desig_t
 * @param env pointer to environment struct 
 * @return a string name of the attribute
 */
AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_attr_desig_get_name(saml_attr_desig_t *attr_desig, const axutil_env_t *env);

/*
 * Get the namespace in which the AttributeName elements are interpreted.
 * @param attr_desig a pointer to saml_attr_desig_t
 * @param env pointer to environment struct 
 * @return a string representing a namespace
 */
AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_attr_desig_get_namespace(saml_attr_desig_t *attr_desig, const axutil_env_t *env);

/* 
 * Set the name of the attribute.
 * @param attr_desig a pointer to saml_attr_desig_t
 * @param env pointer to environment struct 
 * @param name a string name of the attribute
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_attr_desig_set_name(saml_attr_desig_t *attr_desig, 
						 const axutil_env_t *env, axis2_char_t *name);

/*
 * Set the namespace in which the AttributeName elements are interpreted.
 * @param attr_desig a pointer to saml_attr_desig_t
 * @param env pointer to environment struct 
 * @param name_space a string representing a namespace
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_attr_desig_set_namespace(saml_attr_desig_t *attr_desig, 
							  const axutil_env_t *env, axis2_char_t *name_space);

/* attribute */

/*
 * Create a saml_attr_t.
 * @param env pointer to environment struct 
 * @return pointer to saml_attr_t
 */
AXIS2_EXTERN saml_attr_t * AXIS2_CALL 
saml_attr_create(const axutil_env_t *env);

/*
 * Free a saml_attr_t.
 * @param attr pointer to saml_attr_t
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN void AXIS2_CALL 
saml_attr_free(saml_attr_t *attr, const axutil_env_t *env);

/*
 * Populates a saml_attr_t from an om node containing a saml attribute.
 * @param attr pointer to saml_attr_t
 * @node an om node containing a saml attribute
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_attr_build(saml_attr_t *attr, axiom_node_t *node, const axutil_env_t *env);

/*
 * Serialize a saml_attr_t in to an om node.
 * @param attr pointer to saml_attr_t
 * @param parent if specified created node will be a child of this node  
 * @param env pointer to environment struct 
 */
AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_attr_to_om(saml_attr_t *attr, axiom_node_t *parent, const axutil_env_t *env);

/* 
 * Get the name of the attribute.
 * @param attr a pointer to saml_attr_t
 * @param env pointer to environment struct 
 * @return a string name of the attribute
 */
AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_attr_get_name(saml_attr_t *attr, const axutil_env_t *env);

/*
 * Get the namespace in which the AttributeName elements are interpreted.
 * @param attr a pointer to saml_attr_t
 * @param env pointer to environment struct 
 * @return a string representing a namespace
 */
AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_attr_get_namespace(saml_attr_t *attr_stmt, const axutil_env_t *env);

/* 
 * Set the name of the attribute.
 * @param attr a pointer to saml_attr_t
 * @param env pointer to environment struct 
 * @param name a string name of the attribute
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_attr_set_name(saml_attr_t *attr, const axutil_env_t *env, axis2_char_t *name);

/*
 * Set the namespace in which the AttributeName elements are interpreted.
 * @param attr a pointer to saml_attr_t
 * @param env pointer to environment struct 
 * @param name_space a string representing a namespace
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_attr_set_namespace(saml_attr_t *attr, const axutil_env_t *env, 
						axis2_char_t *name_space);

/*
 * Set the values of the attribute as a list of om nodes.
 * @param attr a pointer to saml_attr_t
 * @param env pointer to environment struct 
 * @param list a om node list
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_attr_set_values(saml_attr_t *attr, const axutil_env_t *env, 
					 axutil_array_list_t *list);

/*
 * Remove om node at the specified index.
 * @param attr a pointer to saml_attr_t
 * @param env pointer to environment struct 
 * @param index index number of the om node to be removed
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_attr_remove_value(saml_attr_t *attr, const axutil_env_t *env, int index);

/*
 * Add a om node to the attribute value list.
 * @param attr a pointer to saml_attr_t
 * @param env pointer to environment struct 
 * @param value an om node
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_attr_add_value(saml_attr_t *attr, const axutil_env_t *env, axiom_node_t *value);


/*named id*/

/*
 * Create a SAML named id object
 * @param env pointer to environment struct
 * @return saml named id object
 */
AXIS2_EXTERN saml_named_id_t * AXIS2_CALL 
saml_named_id_create(const axutil_env_t *env);

/*
 * Free a saml named id object
 * @param named_id named_id to be freed
 * @param env pointer to environment struct
 */
AXIS2_EXTERN void AXIS2_CALL 
saml_named_id_free(saml_named_id_t *named_id, const axutil_env_t *env);

/*
 * Build a saml named id from an om node containing a saml named identifier
 * @param named_id named id object
 * @param node om node containing the saml named identifier
 * @param env pointer to environment struct
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_named_id_build(saml_named_id_t *named_id, axiom_node_t *node, 
					const axutil_env_t *env);

/*
 * Serialize a named id object in to an om node.
 * @param named_id named id object
 * @param parent if specified this will be the parent of the newely created node
 * @param env pointer to environment struct
 */
AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_named_id_to_om(saml_named_id_t *id, axiom_node_t *parent, 
					const axutil_env_t *env);

/* 
 * Get the name of the named identifier.
 * @param named_id named id object
 * @param env pointer to environment struct
 * @return name as a string
 */
AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_named_id_get_name(saml_named_id_t *id, const axutil_env_t *env);

/*
 * Get a URI reference representing the format in which the <NameIdentifier> 
 * information is provided.
 * @param named_id named id object
 * @param env pointer to environment struct
 * @return format as a URI string
 */
AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_named_id_get_format(saml_named_id_t *id, const axutil_env_t *env);

/*
 * Get the security or administrative domain that qualifies the name of the 
 * subject.
 * @param named_id named id object
 * @param env pointer to environment struct
 * @return string representing the domain
 */
AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_named_id_get_name_qualifier(saml_named_id_t *id, const axutil_env_t *env);

/* 
 * Set the name of the named identifier.
 * @param named_id named id object
 * @param env pointer to environment struct
 * @param name name as a string
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_named_id_set_name(saml_named_id_t *id, 
					   const axutil_env_t *env, axis2_char_t *name);

/*
 * Set a URI reference representing the format in which the <NameIdentifier> 
 * information is provided.
 * @param named_id named id object
 * @param env pointer to environment struct
 * @param format format of the nameidentifier
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_named_id_set_format(saml_named_id_t *id, 
						 const axutil_env_t *env, axis2_char_t *format);

/*
 * Set the security or administrative domain that qualifies the name of the 
 * subject.
 * @param named_id named id object
 * @param env pointer to environment struct
 * @param qualifier string representing the domain 
 */
AXIS2_EXTERN int AXIS2_CALL 
saml_named_id_set_name_qualifier(saml_named_id_t *id, 
								 const axutil_env_t *env, axis2_char_t *qualifier);


/* private method */
AXIS2_EXTERN int AXIS2_CALL saml_util_set_sig_ctx_defaults(oxs_sign_ctx_t *sig_ctx, const axutil_env_t *env, axis2_char_t *id);

/* Get the session key from a assertion. Session key is inside the SAML 
 * token as an EncryptedKey 
 * @param env pointer to environment struct
 * @param assertion an saml assertion node
 * @param pvt_key private key used to encrypt the session key
 */
AXIS2_EXTERN oxs_key_t * AXIS2_CALL
saml_assertion_get_session_key(const axutil_env_t *env, axiom_node_t *assertion, 
                               openssl_pkey_t *pvt_key);

#ifdef __cplusplus
}
#endif


#endif 
