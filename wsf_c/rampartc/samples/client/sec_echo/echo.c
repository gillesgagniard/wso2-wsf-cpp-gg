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
#include <axis2_addr.h>

axiom_node_t *
build_om_payload_for_echo_svc(
    const axutil_env_t *env);

axiom_node_t *
build_om_payload_for_echo_svc_interop(
    const axutil_env_t *env);

axiom_node_t *
build_om_programatically_mtom(
    const axutil_env_t * env);

int
main(
    int argc,
    char** argv)
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
    /*axutil_property_t *property  = NULL;
     int i = 0;*/

    /* Set up the environment */
    env = axutil_env_create_all("echo.log", AXIS2_LOG_LEVEL_TRACE);

    /*if (argc == 4)
     AXIS2_SLEEP(10); */

    /* Set end-point-reference of echo service */
    address = "http://localhost:9090/axis2/services/echo";
    if(argc > 2)
    {
        address = argv[1];
        client_home = argv[2];
        printf("Using endpoint : %s\n", address);
        printf("Using client_home : %s\n", client_home);
    }

    if((axutil_strcmp(argv[1], "-h") == 0) || (axutil_strcmp(argv[1], "--help") == 0))
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
    axis2_options_set_action(options, env, "http://example.com/ws/2004/09/policy/Test/EchoRequest");

    /*axis2_options_set_action(options, env,
     "http://xmlsoap.org/Ping");*/
    /*axis2_options_set_action(options, env,
     "urn:echoString");*/

    /*axis2_options_set_soap_action(options, env, axutil_string_create(env, "http://xmlsoap.org/Ping"));
     axis2_options_set_soap_version(options, env, AXIOM_SOAP11);*/
    axis2_options_set_soap_version(options, env, AXIOM_SOAP12);

    /*If the client home is not specified, use the AXIS2C_HOME*/
    if(!client_home)
    {
        client_home = AXIS2_GETENV("AXIS2C_HOME");
        printf("\nNo client_home specified. Using default %s", client_home);
    }

    /* Create service client */
    printf("client_home= %s", client_home);
    svc_client = axis2_svc_client_create(env, client_home);
    if(!svc_client)
    {
        printf("Error creating service client\n");
        return -1;
    }

    /* Set service client options */
    axis2_svc_client_set_options(svc_client, env, options);

    /* 
     property = axutil_property_create(env);
     axutil_property_set_scope(property, env, AXIS2_SCOPE_APPLICATION);
     axutil_property_set_value(property, env, AXIS2_WSA_NAMESPACE_SUBMISSION);
     axis2_options_set_property(options, env, AXIS2_WSA_VERSION, property);
     */

    /*We need to specify the client's policy file location*/
    if(client_home)
    {
        file_name = axutil_stracat(env, client_home, AXIS2_PATH_SEP_STR);
        policy_file = axutil_stracat(env, file_name, "policy.xml");
        AXIS2_FREE(env->allocator, file_name);
        file_name = NULL;
    }
    else
    {
        printf("Client Home not Specified\n");
        printf("echo client invoke FAILED!\n");
        return 0;
    }
    /*Create the policy, from file*/
    policy = neethi_util_create_policy_from_file(env, policy_file);
    if(policy_file)
    {
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
    /*axis2_options_set_enable_mtom(options, env, AXIS2_TRUE);*/

    /*If not engaged in the client's axis2.xml, uncomment this line*/
    axis2_svc_client_engage_module(svc_client, env, "rampart");

    /* Send request */
    ret_node = axis2_svc_client_send_receive(svc_client, env, payload);

    if(axis2_svc_client_get_last_response_has_fault(svc_client, env))
    {
        axiom_soap_envelope_t *soap_envelope = NULL;
        axiom_soap_body_t *soap_body = NULL;
        axiom_soap_fault_t *soap_fault = NULL;

        printf("\nResponse has a SOAP fault\n");
        soap_envelope = axis2_svc_client_get_last_response_soap_envelope(svc_client, env);
        if(soap_envelope)
            soap_body = axiom_soap_envelope_get_body(soap_envelope, env);
        if(soap_body)
            soap_fault = axiom_soap_body_get_fault(soap_body, env);
        if(soap_fault)
        {
            printf("\nReturned SOAP fault: %s\n", axiom_node_to_string(
                axiom_soap_fault_get_base_node(soap_fault, env), env));
        }
        printf("echo client invoke FAILED!\n");
        return -1;
    }

    if(ret_node)
    {
        axis2_char_t *om_str = NULL;
        om_str = axiom_node_to_string(ret_node, env);
        if(om_str)
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

    if(svc_client)
    {
        axis2_svc_client_free(svc_client, env);
        svc_client = NULL;
    }
    if(env)
    {
        axutil_env_free((axutil_env_t *)env);
        env = NULL;
    }

    return 0;
}

/* build SOAP request message content using OM */
axiom_node_t *
build_om_payload_for_echo_svc(
    const axutil_env_t *env)
{
    axiom_node_t *echo_om_node = NULL;
    axiom_element_t* echo_om_ele = NULL;
    axiom_node_t* text_om_node = NULL;
    axiom_element_t * text_om_ele = NULL;
    axiom_namespace_t *ns1 = NULL;
    axis2_char_t *om_str = NULL;

    ns1 = axiom_namespace_create(env, "http://ws.apache.org/rampart/c/samples", "ns1");
    /*ns1 = axiom_namespace_create(env, "http://echo.services.wsas.wso2.org", "ns1");*/
    echo_om_ele = axiom_element_create(env, NULL, "echoIn", ns1, &echo_om_node);

    text_om_ele = axiom_element_create(env, echo_om_node, "text", NULL, &text_om_node);
    axiom_element_set_text(text_om_ele, env, "Hello", text_om_node);

    om_str = axiom_node_to_string(echo_om_node, env);
    if(om_str)
    {
        printf("\nSending OM : %s\n", om_str);
        AXIS2_FREE(env->allocator, om_str);
        om_str = NULL;
    }
    return echo_om_node;
}

/* build SOAP request message content using OM (for java interop)*/
axiom_node_t *
build_om_payload_for_echo_svc_interop(
    const axutil_env_t *env)
{
    axiom_node_t *ping_request_om_node = NULL;
    axiom_element_t* ping_request_om_ele = NULL;
    axiom_node_t *ping_om_node = NULL;
    axiom_element_t* ping_om_ele = NULL;
    axiom_node_t* text_om_node = NULL;
    axiom_element_t * text_om_ele = NULL;
    axiom_namespace_t *ns1 = NULL;
    axiom_namespace_t *ns0 = NULL;
    axis2_char_t *om_str = NULL;

    ns0 = axiom_namespace_create(env, "http://InteropBaseAddress/interop", "ns0");
    ns1 = axiom_namespace_create(env, "http://xmlsoap.org/Ping", "ns1");
    ping_request_om_ele
        = axiom_element_create(env, NULL, "PingRequest", ns0, &ping_request_om_node);
    ping_om_ele = axiom_element_create(env, ping_request_om_node, "Ping", ns1, &ping_om_node);

    text_om_ele = axiom_element_create(env, ping_om_node, "scenario", ns1, &text_om_node);
    axiom_element_set_text(text_om_ele, env, "scenario", text_om_node);
    text_om_node = NULL;
    text_om_ele = axiom_element_create(env, ping_om_node, "origin", ns1, &text_om_node);
    axiom_element_set_text(text_om_ele, env, "origin", text_om_node);
    text_om_node = NULL;
    text_om_ele = axiom_element_create(env, ping_om_node, "text", ns1, &text_om_node);
    axiom_element_set_text(text_om_ele, env, "text", text_om_node);

    om_str = axiom_node_to_string(ping_request_om_node, env);
    if(om_str)
    {
        printf("\nSending OM : %s\n", om_str);
        AXIS2_FREE(env->allocator, om_str);
        om_str = NULL;
    }
    return ping_request_om_node;
}

/* build SOAP request message content using OM */
axiom_node_t *
build_om_programatically_mtom(
    const axutil_env_t * env)
{
    axiom_node_t *mtom_om_node = NULL;
    axiom_element_t *mtom_om_ele = NULL;
    axiom_node_t *image_om_node = NULL;
    axiom_element_t *image_om_ele = NULL;
    axiom_node_t *file_om_node = NULL;
    axiom_element_t *file_om_ele = NULL;
    axiom_node_t *data_om_node = NULL;
    axiom_text_t *data_text = NULL;
    axiom_namespace_t *ns1 = NULL;
    axis2_char_t *om_str = NULL;
    const axis2_char_t *image_name = "E:/src/C/Axis2C/build/deploy/samples/bin/resources/axis2.jpg";
    const axis2_char_t *to_save_name = "test.jpg";
    axis2_bool_t optimized = AXIS2_TRUE;

    axiom_data_handler_t *data_handler = NULL;

    ns1 = axiom_namespace_create(env, "http://ws.apache.org/axis2/c/samples/mtom", "ns1");
    mtom_om_ele = axiom_element_create(env, NULL, "mtomSample", ns1, &mtom_om_node);

    file_om_ele = axiom_element_create(env, mtom_om_node, "fileName", ns1, &file_om_node);
    axiom_element_set_text(file_om_ele, env, to_save_name, file_om_node);

    image_om_ele = axiom_element_create(env, mtom_om_node, "image", ns1, &image_om_node);

    /* This is when we directly give file name */

    data_handler = axiom_data_handler_create(env, image_name, "image/jpeg");

    /* Uncomment following to set a callback instead of a file */

    /*data_handler = axiom_data_handler_create(env, NULL, "image/jpeg");
     axiom_data_handler_set_data_handler_type(data_handler, env, AXIOM_DATA_HANDLER_TYPE_CALLBACK);
     axiom_data_handler_set_user_param(data_handler, env, (void *)image_name);*/

    data_text
        = axiom_text_create_with_data_handler(env, image_om_node, data_handler, &data_om_node);

    axiom_text_set_optimize(data_text, env, optimized);
    /*axiom_text_set_is_swa(data_text, env, AXIS2_TRUE);*/
    om_str = axiom_node_to_string(mtom_om_node, env);
    if(om_str)
    {
        printf("%s", om_str);
        AXIS2_FREE(env->allocator, om_str);
    }
    return mtom_om_node;
}
