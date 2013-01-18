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
#include <rampart_context.h>
#include <trust_rst.h>
#include <trust_rstr.h>

axiom_node_t *
build_om_payload_for_echo_svc(const axutil_env_t *env);

rampart_issued_token_t * AXIS2_CALL 
get_issued_token(const axutil_env_t *env, rp_property_t *issued_token, rampart_context_t *rampart_context);

axis2_char_t *policy_file = NULL;
axis2_char_t *sts_ploicy = NULL;
const axis2_char_t *client_home = NULL;

int main(int argc, char** argv)
{
    const axutil_env_t *env = NULL;
    const axis2_char_t *address = NULL;    
    axis2_char_t *file_name = NULL;    
    axis2_endpoint_ref_t* endpoint_ref = NULL;
    axis2_options_t *options = NULL;
    axis2_svc_client_t* svc_client = NULL;
    axiom_node_t *payload = NULL;
    axiom_node_t *ret_node = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    neethi_policy_t *policy = NULL;
    rampart_config_t* client_config = NULL;
    axutil_property_t *property = NULL;
    

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
    
    rampart_config_set_issued_token_aquire_function(client_config, env, (rampart_issued_token_t*)get_issued_token);

    property = axutil_property_create_with_args(env, AXIS2_SCOPE_REQUEST ,
        AXIS2_TRUE, (void *)rampart_config_free, client_config);
    axis2_options_set_property(options, env, RAMPART_CLIENT_CONFIGURATION, property);

    /* Set service client options */
    axis2_svc_client_set_options(svc_client, env, options);

    /*We need to specify the client's policy file location*/
    if(client_home)
    {
        file_name = axutil_stracat(env, client_home, AXIS2_PATH_SEP_STR);
        policy_file = axutil_stracat(env, file_name, "policy.xml");
		sts_ploicy = axutil_stracat(env, file_name, "sts_policy.xml");
        AXIS2_FREE(env->allocator, file_name);
        file_name = NULL;        
    }else{
        printf("Client Home not Specified\n");
        printf("echo client invoke FAILED!\n");
        return 0;
    }
    /*Create the policy, from file*/   
    policy = neethi_util_create_policy_from_file(env, policy_file);
    if(policy_file){
        AXIS2_FREE(env->allocator, policy_file);
        policy_file = NULL;
    }
    if(!policy)
    {
        printf("\nPolicy creation failed from the file. %s\n", policy_file);
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


rampart_issued_token_t * AXIS2_CALL 
get_issued_token(const axutil_env_t *env, rp_property_t *issued_token, rampart_context_t *rampart_context)
{
	axis2_endpoint_ref_t *endpoint_ref = NULL;
    axis2_options_t *options = NULL;
    axis2_svc_client_t *svc_client = NULL;

	axiom_node_t *rst_node = NULL;
	axiom_node_t *return_rstr_node = NULL;
	trust_rstr_t *rstr = NULL;
	axiom_node_t *assertion = NULL;
    rampart_saml_token_t *saml = NULL;
    rampart_issued_token_t *token = NULL;
	axis2_op_client_t* op_client = NULL;
	axis2_msg_ctx_t *in_msg_ctx = NULL;
	axis2_status_t status = AXIS2_SUCCESS;
	neethi_policy_t *issuer_policy = NULL;
    trust_rst_t *rst = NULL;
	rp_issued_token_t *it = (rp_issued_token_t *)rp_property_get_value(issued_token, env);
	/*Setting Issuer's EPR*/
	endpoint_ref = endpoint_ref = axis2_endpoint_ref_create(env, "http://127.0.0.1:9090/axis2/services/saml_sts");
    options = axis2_options_create(env);
    axis2_options_set_to(options, env, endpoint_ref);
    /*Create the policy, from file*/   
    issuer_policy = neethi_util_create_policy_from_file(env, sts_ploicy);
    if(!issuer_policy)
    {
        printf("\nPolicy creation failed from the file. %s\n", policy_file);
    }
    /*axis2_options_set_action(options, env, action); WSA Action*/
    svc_client = axis2_svc_client_create(env, client_home);

    if (!svc_client)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Stub invoke FAILED: Error code:" " %d :: %s",
                        env->error->error_number, AXIS2_ERROR_GET_MESSAGE(env->error));
        return NULL;
    }
	axis2_options_set_action(options, env, "http://example.com/ws/2004/09/policy/Test/EchoRequest");
    /* Set service client options */
    axis2_svc_client_set_options(svc_client, env, options);
    rst = trust_rst_create(env);
    trust_rst_set_wst_ns_uri(rst, env, "http://schemas.xmlsoap.org/ws/2005/02/trust");

	rst_node = trust_rst_build_rst_with_issued_token_assertion(rst, env, it);
	if (status == AXIS2_SUCCESS)
    {
        status = axis2_svc_client_set_policy(svc_client, env, issuer_policy);
        if (status == AXIS2_FAILURE)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Policy setting failed.");
        }
		/*Building the RST */       
        if(rst_node)
        {            
			return_rstr_node = axis2_svc_client_send_receive(svc_client, env, rst_node);
			rstr = trust_rstr_create(env);
			trust_rstr_set_wst_ns_uri(rstr, env, "http://schemas.xmlsoap.org/ws/2005/02/trust");		
			trust_rstr_populate_rstr(rstr, env, return_rstr_node);
			assertion = trust_rstr_get_requested_security_token(rstr, env);	
        }
	}
    saml = rampart_saml_token_create(env, assertion, RAMPART_ST_CONFIR_TYPE_SENDER_VOUCHES);
	rampart_saml_token_set_token_type(saml, env, RAMPART_ST_TYPE_SIGNED_SUPPORTING_TOKEN);
    token = rampart_issued_token_create(env);
    rampart_issued_token_set_token(token, env, saml, RP_PROPERTY_SAML_TOKEN);
    return token;
}



