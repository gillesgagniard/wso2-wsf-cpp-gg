/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mtom_util.h"
#include <axis2_util.h>
#include <axiom_soap.h>
#include <axis2_client.h>
#include <axis2_svc_ctx.h>
#include <axis2_conf_ctx.h>
#include <axis2_op_client.h>
#include <axis2_listener_manager.h>
#include <axis2_callback_recv.h>
#include <axis2_svc_client.h>
#include <sandesha2_client.h>
#include <sandesha2_constants.h>
#include <sandesha2_client_constants.h>
#include <ctype.h>
#include <neethi_policy.h>
#include <neethi_util.h>

#define SANDESHA2_MAX_COUNT 8

axiom_node_t *build_om_programatically(
    const axutil_env_t * env,
    const axis2_char_t * image_name,
    const axis2_char_t * to_save_name,
    axis2_bool_t optimized);

int main(int argc, char** argv)
{
    const axutil_env_t *env = NULL;
    const axis2_char_t *address = NULL;
    axis2_endpoint_ref_t* endpoint_ref = NULL;
    axis2_options_t *options = NULL;
    const axis2_char_t *client_home = NULL;
    axis2_svc_client_t* svc_client = NULL;
    axiom_node_t *payload = NULL;
    axutil_property_t *property = NULL;
    axiom_node_t *result = NULL;
    axutil_string_t *soap_action = NULL;
    const axis2_char_t *image_name = "../resources/axis2.jpg";
    axis2_bool_t optimized = AXIS2_TRUE;
    neethi_policy_t *policy = NULL;
    axis2_status_t status = AXIS2_FAILURE;  
 
    /* Set up the environment */
    env = axutil_env_create_all("rm_mtom_1_0.log", AXIS2_LOG_LEVEL_TRACE);

    /* Set end point reference of echo service */
    address = "http://127.0.0.1:9090/axis2/services/RM10SampleService";
    if (argc > 1)
    {
        if (axutil_strcmp(argv[1], "-h") == 0)
        {
            printf("Usage : %s [endpoint_url]\n", argv[0]);
            printf("use -h for help\n");
            return 0;
        }
        else
        {
            address = argv[1];
        }
    }
    printf ("Using endpoint : %s\n", address);
    
    /* Create EPR with given address */
    endpoint_ref = axis2_endpoint_ref_create(env, address);

    /* Setup options */
    options = axis2_options_create(env);
    axis2_options_set_to(options, env, endpoint_ref);
    axis2_options_set_enable_mtom(options, env, AXIS2_TRUE); 

    soap_action = axutil_string_create(env, "urn:wsrm:EchoString");
    axis2_options_set_soap_action(options, env, soap_action);
    axis2_options_set_action(options, env, "urn:wsrm:EchoString");

    /* Set up deploy folder. It is from the deploy folder, the configuration is 
     * picked up using the axis2.xml file.
     * In this sample client_home points to the Axis2/C default deploy folder. 
     * The client_home can be different from this folder on your system. For 
     * example, you may have a different folder (say, my_client_folder) with its 
     * own axis2.xml file. my_client_folder/modules will have the modules that 
     * the client uses
     */
    client_home = AXIS2_GETENV("AXIS2C_HOME");
    if (!client_home)
    {
        client_home = "../../deploy";
    }

    /* Create service client */
    svc_client = axis2_svc_client_create(env, client_home);
    if (!svc_client)
    {
        printf("Error creating service client\n");
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Stub invoke FAILED: Error code:"
            " %d :: %s", env->error->error_number,
                AXIS2_ERROR_GET_MESSAGE(env->error));
        return -1;
    }

    policy = neethi_util_create_policy_from_file(env, "policy/rm10-policy.xml");
    if(!policy)
    {
        printf("\nPolicy creation failed from the file");
        return 0;
    }

    status = axis2_svc_client_set_policy(svc_client, env, policy);

    if(status == AXIS2_FAILURE)
    {
        printf("Policy setting failed\n");
    }


    /* Set service client options */
    axis2_svc_client_set_options(svc_client, env, options);    
    
    axis2_svc_client_engage_module(svc_client, env, AXIS2_MODULE_ADDRESSING);  
    axis2_svc_client_engage_module(svc_client, env, "sandesha2");

    property = axutil_property_create_with_args(env, 0, 0, 0, "12");
    if(property)
    {
        axis2_options_set_property(options, env, AXIS2_TIMEOUT_IN_SECONDS, property);
    }

    payload = build_om_programatically(env, image_name, "test3.jpg", optimized);
    result = axis2_svc_client_send_receive(svc_client, env, payload);
    if(result)
    {
        printf("\necho client two way single channel invoke SUCCESSFUL!\n");
    }
    else
    {
        printf("\necho client two way single channel invoke FAILED!\n");
    }
    
    axis2_svc_client_close(svc_client, env);
    
    AXIS2_SLEEP(SANDESHA2_MAX_COUNT); 
    if (svc_client)
    {
        axis2_svc_client_free(svc_client, env);
        svc_client = NULL;
    }
    
    return 0;
}

/* build SOAP request message content using OM */
axiom_node_t *
build_om_programatically(
    const axutil_env_t * env,
    const axis2_char_t * image_name,
    const axis2_char_t * to_save_name,
    axis2_bool_t optimized)
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

    axiom_data_handler_t *data_handler = NULL;

    ns1 =
        axiom_namespace_create(env, "http://ws.apache.org/axis2/c/samples/mtom",
                               "ns1");
    mtom_om_ele =
        axiom_element_create(env, NULL, "mtomSample", ns1, &mtom_om_node);

    file_om_ele =
        axiom_element_create(env, mtom_om_node, "fileName", ns1, &file_om_node);
    axiom_element_set_text(file_om_ele, env, to_save_name, file_om_node);

    image_om_ele =
        axiom_element_create(env, mtom_om_node, "image", ns1, &image_om_node);

    data_handler = axiom_data_handler_create(env, image_name, "image/jpeg");
    data_text =
        axiom_text_create_with_data_handler(env, image_om_node, data_handler,
                                            &data_om_node);
    axiom_text_set_optimize(data_text, env, optimized);
    om_str = axiom_node_to_string(mtom_om_node, env);
    if (om_str)
    {
        printf("%s", om_str);
        AXIS2_FREE(env->allocator, om_str);
    }
    return mtom_om_node;
}

