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

#include <stdio.h>
#include <axiom.h>
#include <axis2_util.h>
#include <axiom_soap.h>
#include <axis2_client.h>
#include <rampart_constants.h>
#include <neethi_util.h>
#include <neethi_policy.h>
#include <saml.h>
#include <rampart_config.h>
#include <rampart_saml_token.h>
#include <oxs_saml_token.h>
#include <oxs_sign_ctx.h>
#include <oxs_tokens.h>
#include <oxs_xml_encryption.h>

axiom_node_t * AXIS2_CALL
build_om_payload_for_echo_svc(const axutil_env_t *env);

rampart_saml_token_t * AXIS2_CALL
create_saml_token(const axutil_env_t *env);

oxs_key_t * AXIS2_CALL
get_session_key(const axutil_env_t *env, axiom_node_t *assertion);

axiom_node_t * AXIS2_CALL
create_key_info(const axutil_env_t *env, rampart_saml_token_t *saml);

saml_subject_t * AXIS2_CALL
create_subject(const axutil_env_t *env, rampart_saml_token_t *saml);

saml_auth_binding_t * AXIS2_CALL
create_autherity_binding(const axutil_env_t *env);

saml_stmt_t * AXIS2_CALL
create_auth_statement(const axutil_env_t *env, rampart_saml_token_t *saml);

saml_condition_t * AXIS2_CALL
create_condition(const axutil_env_t *env);

#define PRIVATE_KEY_FILE            "/bin/samples/rampart/keys/ahome/alice_key.pem"
#define PRIVATE_KEY_PASSWORD        "password"
#define CERTIFICATE_FILE            "/bin/samples/rampart/keys/ahome/alice_cert.cert"
#define RECEIVER_CERTIFICATE_FILE   "/bin/samples/rampart/keys/ahome/bob_cert.cert"

axis2_char_t *axis2c_home;

int main(int argc, char** argv)
{
    const axutil_env_t *env = NULL;
    const axis2_char_t *address = NULL;
    const axis2_char_t *client_home = NULL;
    axis2_char_t *file_name = NULL;
    axis2_char_t *policy_file = NULL;
    axis2_endpoint_ref_t* endpoint_ref = NULL;
    axis2_options_t *options = NULL;
    axis2_svc_client_t* svc_client = NULL;
    axiom_node_t *payload = NULL;
    axiom_node_t *ret_node = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    neethi_policy_t *policy = NULL;
    rampart_config_t* client_config = NULL;
    axutil_property_t *property = NULL;
    rampart_saml_token_t *saml = NULL;
	/* Set up the environment */
    env = axutil_env_create_all("echo.log", AXIS2_LOG_LEVEL_TRACE);

    printf("SAML PROOF");
    /* Set end-point-reference of echo service */
    address = "http://localhost:9090/axis2/services/echo";
    if (argc > 2)
    {
        address = argv[1];
        client_home = argv[2];
        printf("Using endpoint : %s\n", address);
        printf("Using client_home : %s\n", client_home);
    }

    if (axutil_strcmp(address, "-h") == 0)
    {
        printf("Usage : %s [endpoint_url] [client_home]\n", argv[0]);
        printf("use -h for help\n");
        return 0;
    }

    axis2c_home = AXIS2_GETENV("AXIS2C_HOME");
    if (!axis2c_home)
    {
        printf("AXIS2C_HOME not set. Cannot find the key files");
        return -1;
    }
    /* Create end-point-reference with given address */
    endpoint_ref = axis2_endpoint_ref_create(env, address);

    /* Setup options */
    options = axis2_options_create(env);
    axis2_options_set_to(options, env, endpoint_ref);
    axis2_options_set_action(options, env,
            "http://example.com/ws/2004/09/policy/Test/EchoRequest");
    /*axis2_options_set_action(options, env,
            "urn:echo");*/


    /*If the client home is not specified, use the AXIS2C_HOME*/
    if (!client_home)
    {
        client_home = axutil_strdup(env, axis2c_home);
        printf("\nNo client_home specified. Using default %s", client_home);
    }

    /* Create service client */
    printf("client_home= %s", client_home);
    svc_client = axis2_svc_client_create(env, client_home);
    if (!svc_client)
    {
        printf("Error creating service client\n");
        return -1;
    }

    client_config = rampart_config_create(env);
    if(!client_config)
    {
        printf("Cannot create rampart config\n");
        return 0;
    }

    saml = create_saml_token(env);
    rampart_config_add_saml_token(client_config, env, saml);
    property = axutil_property_create_with_args(env, AXIS2_SCOPE_REQUEST ,
        AXIS2_TRUE, (void *)rampart_config_free, client_config);
    axis2_options_set_property(options, env, RAMPART_CLIENT_CONFIGURATION, property);

    /* Set service client options */
    axis2_svc_client_set_options(svc_client, env, options);

    /*We need to specify the client's policy file location*/
    if(client_home)
    {
        file_name = axutil_stracat(env, client_home, AXIS2_PATH_SEP_STR);
        policy_file = axutil_stracat(env, file_name, "policy.xml" );
        AXIS2_FREE(env->allocator, file_name);
        file_name = NULL;        
    }else{
        printf("Client Home not Specified\n");
        printf("echo client invoke FAILED!\n");
        return 0;
    }
    /*Create the policy, from file*/   
    policy = neethi_util_create_policy_from_file(env, policy_file);
    if(!policy)
    {
        printf("\nPolicy creation failed from the file. %s\n", policy_file);
    }
	if(policy_file){
        AXIS2_FREE(env->allocator, policy_file);
        policy_file = NULL;
    }

    status = axis2_svc_client_set_policy(svc_client, env, policy);

    if(status == AXIS2_FAILURE)
    {
        printf("Policy setting failed\n");
    }
    
    /* Build the SOAP request message payload using OM API.*/
    payload = build_om_payload_for_echo_svc(env);
    
    /*If not engaged in the client's axis2.xml, uncomment this line*/
    axis2_svc_client_engage_module(svc_client, env, "rampart");
    
    /* Send request */
    ret_node = axis2_svc_client_send_receive(svc_client, env, payload);


    if (axis2_svc_client_get_last_response_has_fault(svc_client, env))
    {
        axiom_soap_envelope_t *soap_envelope = NULL;
        axiom_soap_body_t *soap_body = NULL;
        axiom_soap_fault_t *soap_fault = NULL;

        printf ("\nResponse has a SOAP fault\n");
        soap_envelope =
            axis2_svc_client_get_last_response_soap_envelope(svc_client, env);
        if (soap_envelope)
            soap_body = axiom_soap_envelope_get_body(soap_envelope, env);
        if (soap_body)
            soap_fault = axiom_soap_body_get_fault(soap_body, env);
        if (soap_fault)
        {
            printf("\nReturned SOAP fault: %s\n",
            axiom_node_to_string(axiom_soap_fault_get_base_node(soap_fault,env),
                env));
        }
            printf("echo client invoke FAILED!\n");
            return -1;
    }
    
    if (ret_node)
    {
        axis2_char_t *om_str = NULL;
        om_str = axiom_node_to_string(ret_node, env);
        if (om_str)
        {
            printf("\nReceived OM : %s\n", om_str);
        }
        printf("\necho client invoke SUCCESSFUL!\n");
        AXIS2_FREE(env->allocator, om_str);
        ret_node = NULL;
    }
    else
    {
        printf("echo client invoke FAILED!\n");
        return -1;
    }

    if (svc_client)
    {
        axis2_svc_client_free(svc_client, env);
        svc_client = NULL;
    }
    if (env)
    {
        axutil_env_free((axutil_env_t *) env);
        env = NULL;
    }
    
    return 0;
}

axiom_node_t * AXIS2_CALL
build_om_payload_for_echo_svc(const axutil_env_t *env)
{
    axiom_node_t *echo_om_node = NULL;
    axiom_element_t* echo_om_ele = NULL;
    axiom_node_t* text_om_node = NULL;
    axiom_element_t * text_om_ele = NULL;
    axiom_namespace_t *ns1 = NULL;
    axis2_char_t *om_str = NULL;

    ns1 = axiom_namespace_create(env, "http://ws.apache.org/rampart/c/samples", "ns1");
    echo_om_ele = axiom_element_create(env, NULL, "echoIn", ns1, &echo_om_node);
    
    
    text_om_ele = axiom_element_create(env, echo_om_node, "text", NULL, &text_om_node);
    axiom_element_set_text(text_om_ele, env, "Hello", text_om_node);

    om_str = axiom_node_to_string(echo_om_node, env);
    if (om_str){
        printf("\nSending OM : %s\n", om_str);
        AXIS2_FREE(env->allocator, om_str);
        om_str =  NULL;
    }
    return echo_om_node;
}

rampart_saml_token_t * AXIS2_CALL
create_saml_token(const axutil_env_t *env)
{
    oxs_sign_ctx_t *sign_ctx = NULL;
	oxs_x509_cert_t *cert = NULL;
	openssl_pkey_t *prv_key = NULL;
	rampart_saml_token_t *saml = NULL;

	axutil_date_time_t *time = NULL;
	saml_assertion_t *assertion = NULL;
	axiom_node_t *node = NULL;
    axis2_char_t *prv_key_file = NULL;
    axis2_char_t *certificate_file = NULL;
    /* 
     * Create a rampart_saml_token_t to give to the Rampart/C 
     * Here the token type is protection token.
     */    
	saml = rampart_saml_token_create(env, NULL, RAMPART_ST_CONFIR_TYPE_HOLDER_OF_KEY);
	time = axutil_date_time_create(env);
	assertion = saml_assertion_create(env);
	if (assertion)	
	{
		saml_assertion_set_minor_version(assertion, env, 1);		
		saml_assertion_set_issue_instant(assertion, env, time);
		saml_assertion_set_issuer(assertion, env, "http://ws.apache.org/rampart/c");	
		saml_assertion_add_condition(assertion, env, create_condition(env));
		saml_assertion_set_not_before(assertion, env, axutil_date_time_create(env));
		saml_assertion_add_statement(assertion, env, create_auth_statement(env, saml));
	}
    /* Load the private key from file*/
    prv_key_file = axutil_stracat(env, axis2c_home, PRIVATE_KEY_FILE);  
    certificate_file = axutil_stracat(env, axis2c_home, CERTIFICATE_FILE);
    prv_key = oxs_key_mgr_load_private_key_from_pem_file(env, prv_key_file, PRIVATE_KEY_PASSWORD);
    cert = oxs_key_mgr_load_x509_cert_from_pem_file(env, certificate_file);

	sign_ctx = oxs_sign_ctx_create(env);
	saml_util_set_sig_ctx_defaults(sign_ctx, env, "AssertionID");
	oxs_sign_ctx_set_private_key(sign_ctx, env, prv_key);
    oxs_sign_ctx_set_certificate(sign_ctx, env, cert);
    saml_assertion_set_signature(assertion, env, sign_ctx);

	node = saml_assertion_to_om(assertion, NULL, env);	 
	rampart_saml_token_set_assertion(saml, env, node);
    rampart_saml_token_set_token_type(saml, env, RAMPART_ST_TYPE_PROTECTION_TOKEN);
	saml_assertion_free(assertion, env);
	return saml;
}

saml_condition_t * AXIS2_CALL
create_condition(const axutil_env_t *env)
{
	saml_audi_restriction_cond_t *arc = NULL;
	saml_condition_t *condition = AXIS2_MALLOC(env->allocator, sizeof(saml_condition_t));	
	arc = saml_audi_restriction_cond_create(env);
	saml_audi_restriction_cond_add_audience(arc, env, "www.samle.com");	
	return condition;
}

saml_stmt_t * AXIS2_CALL
create_auth_statement(const axutil_env_t *env, rampart_saml_token_t *saml)
{
	saml_auth_stmt_t *a_stmt = NULL;	
	saml_stmt_t *stmt = saml_stmt_create(env);
	a_stmt = saml_auth_stmt_create(env);
	saml_stmt_set_stmt(stmt, env, a_stmt, SAML_STMT_AUTHENTICATIONSTATEMENT);

	saml_auth_stmt_set_auth_method(a_stmt, env, SAML_AUTH_METHOD_URI_PASSWORD);
	saml_auth_stmt_set_auth_instant(a_stmt, env, axutil_date_time_create(env));
	
	saml_auth_stmt_set_subject(a_stmt, env, create_subject(env, saml));	
	saml_auth_stmt_set_subject_dns(a_stmt, env,  "192.148.5.8");
	saml_auth_stmt_set_subject_ip(a_stmt, env,  "128.5.6.4");
	saml_auth_stmt_add_auth_binding(a_stmt, env, create_autherity_binding(env));
	return stmt;	
}

saml_auth_binding_t * AXIS2_CALL
create_autherity_binding(const axutil_env_t *env)
{
	saml_auth_binding_t *bind = NULL;
	bind = saml_auth_binding_create(env);
	saml_auth_binding_set_authority_kind(bind, env, "abc:aa:aa");
	saml_auth_binding_set_binding(bind, env, "SOAP");
	saml_auth_binding_set_location(bind, env, "http://myhome.com/sevices/echo");
	return bind;
}

saml_subject_t * AXIS2_CALL
create_subject(const axutil_env_t *env, rampart_saml_token_t *saml)
{
	saml_subject_t *subject = NULL;
	saml_named_id_t *id = NULL;		
    axiom_node_t *key_info = NULL;
	subject = saml_subject_create(env);


	id = saml_named_id_create(env);
	saml_named_id_set_name(id, env, "Computer Science & Engineering Department");
	saml_named_id_set_format(id, env, SAML_EMAIL_ADDRESS);
	saml_named_id_set_name_qualifier(id, env, "University of Moratuwa");
	saml_subject_set_named_id(subject, env, id);

	saml_subject_add_confirmation(subject, env, SAML_SUB_CONFIRMATION_HOLDER_OF_KEY);

    key_info = create_key_info(env, saml);
    saml_subject_set_key_info(subject, env, key_info);
	return subject;
}

axiom_node_t *  AXIS2_CALL
create_key_info(const axutil_env_t *env, rampart_saml_token_t *saml)
{
    axiom_node_t *key_info = NULL;
    oxs_key_t *session_key = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    oxs_asym_ctx_t * asym_ctx = NULL;
    axis2_char_t *key_info_str = NULL;
	oxs_x509_cert_t *cert = NULL;
    /* Set the receiver certificate file. This public key will be used to encrypt the session key.*/
    axis2_char_t *certificate_file = axutil_stracat(env, axis2c_home, RECEIVER_CERTIFICATE_FILE);

    session_key = oxs_key_create(env);
    status = oxs_key_for_algo(session_key, env, NULL);    

    key_info = oxs_token_build_key_info_element(env, NULL);

    /* Create the asym_ctx_t and populate it.*/
    asym_ctx = oxs_asym_ctx_create(env);
    oxs_asym_ctx_set_algorithm(asym_ctx, env, OXS_HREF_RSA_PKCS1);
    oxs_asym_ctx_set_operation(asym_ctx, env,
                               OXS_ASYM_CTX_OPERATION_PUB_ENCRYPT);

	cert = oxs_key_mgr_load_x509_cert_from_pem_file(env, certificate_file);
	if (!cert)
	{
		AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "Certificate cannot be loaded");
		return NULL;
	}
	oxs_asym_ctx_set_certificate(asym_ctx, env, cert);
    status = oxs_xml_enc_encrypt_key(env,
                            asym_ctx,
                            key_info,
                            session_key,
                            NULL);
	rampart_saml_token_set_session_key(saml, env, session_key);
    key_info_str = axiom_node_to_string(key_info, env);
    return key_info;
}




