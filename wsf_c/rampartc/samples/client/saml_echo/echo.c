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

axiom_node_t *
build_om_payload_for_echo_svc(const axutil_env_t *env);

axiom_node_t * AXIS2_CALL
create_saml_assertion(const axutil_env_t *env);

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
    axiom_node_t *assertion = NULL;
	/* Set up the environment */
    env = axutil_env_create_all("echo.log", AXIS2_LOG_LEVEL_TRACE);

    /* Set end-point-reference of echo service */
    address = "http://localhost:9090/axis2/services/echo";
    if (argc > 2)
    {
        address = argv[1];
        client_home = argv[2];
        printf("Using endpoint : %s\n", address);
        printf("Using client_home : %s\n", client_home);
    }

    if ((axutil_strcmp(argv[1], "-h") == 0) || (axutil_strcmp(argv[1], "--help") == 0))
    {
        printf("Usage : %s [endpoint_url] [client_home]\n", argv[0]);
        printf("use -h for help\n");
        return 0;
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
        client_home = AXIS2_GETENV("AXIS2C_HOME");
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
    assertion = create_saml_assertion(env);
    saml = rampart_saml_token_create(env, assertion, RAMPART_ST_CONFIR_TYPE_SENDER_VOUCHES);
	rampart_saml_token_set_token_type(saml, env, RAMPART_ST_TYPE_SIGNED_SUPPORTING_TOKEN);
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

/* build SOAP request message content using OM */
axiom_node_t *
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

axiom_node_t * AXIS2_CALL
create_saml_assertion(const axutil_env_t *env)
{
    saml_assertion_t *assertion = NULL;
    saml_attr_stmt_t *attr_stmt = NULL;
    saml_subject_t *subject = NULL;
    saml_named_id_t *named_id = NULL;
    saml_attr_t *attr = NULL;
    axiom_node_t *attr_val = NULL;
    axiom_element_t *e = NULL;
    saml_stmt_t *stmt = NULL;

    assertion = saml_assertion_create(env);
    attr_stmt = saml_attr_stmt_create(env);
    subject = saml_subject_create(env);

    saml_assertion_set_issue_instant(assertion, env, axutil_date_time_create(env));
    saml_assertion_set_issuer(assertion, env, "www.mrt.ac.lk");
    saml_assertion_set_minor_version(assertion, env, 1);

    saml_subject_add_confirmation(subject, env, SAML_SUB_CONFIRMATION_SENDER_VOUCHES);

    named_id = saml_named_id_create(env);
    saml_named_id_set_name(named_id, env, "cse07");
    saml_subject_set_named_id(subject, env, named_id);

    attr = saml_attr_create(env);
    saml_attr_set_name(attr, env, "csestudent");
    saml_attr_set_namespace(attr, env, "www.mrt.ac.lk/cse");
    e = axiom_element_create(env, NULL, "noofstudent", NULL, &attr_val);
    axiom_element_set_text(e, env, "10", attr_val);
    saml_attr_add_value(attr, env, attr_val); 
   
    saml_attr_stmt_set_subject(attr_stmt, env, subject);
    saml_attr_stmt_add_attribute(attr_stmt, env, attr);

    stmt = saml_stmt_create(env);
    saml_stmt_set_stmt(stmt, env, attr_stmt, SAML_STMT_ATTRIBUTESTATEMENT);

    saml_assertion_add_statement(assertion, env, stmt);
    return saml_assertion_to_om(assertion, NULL, env);
}
