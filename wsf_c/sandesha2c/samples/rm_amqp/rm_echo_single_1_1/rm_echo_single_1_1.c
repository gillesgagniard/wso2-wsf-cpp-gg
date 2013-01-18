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

#include "echo_util.h"
#include <axis2_util.h>
#include <axiom_soap.h>
#include <axis2_client.h>
#include <axis2_svc_ctx.h>
#include <axis2_conf_ctx.h>
#include <axis2_op_client.h>
#include <axis2_listener_manager.h>
#include <axis2_callback_recv.h>
#include <axis2_svc_client.h>
#include <sandesha2_client_constants.h>
#include <sandesha2_constants.h>
#include <sandesha2_client.h>
#include <axis2_addr.h>
#include <ctype.h>
#include <neethi_util.h>
#include <neethi_policy.h>

#define SANDESHA2_SLEEP 4

int main(int argc, char** argv)
{
    const axutil_env_t *env = NULL;
    const axis2_char_t *address = NULL;
    axis2_endpoint_ref_t* endpoint_ref = NULL;
    axis2_endpoint_ref_t* reply_to = NULL;
    axis2_options_t *options = NULL;
    const axis2_char_t *client_home = NULL;
    axis2_svc_client_t* svc_client = NULL;
    axiom_node_t *payload = NULL;
    axutil_property_t *property = NULL;
    axis2_listener_manager_t *listener_manager = NULL;
    axis2_char_t *offered_seq_id = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    axiom_node_t *result = NULL;
    neethi_policy_t *policy = NULL;
    
    /* Set up the environment */
    env = axutil_env_create_all("rm_echo_single_1_1_amqp.log", AXIS2_LOG_LEVEL_TRACE);
 

    /* Set end point reference of echo service */
    address = "amqp://127.0.0.1:5672/axis2/services/RM11SampleService";
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
    
    /* Seperate listner needs addressing, hence addressing stuff in options */
    axis2_options_set_action(options, env,
        "http://127.0.0.1:8080/axis2/services/RM11SampleService/anonOutInOp");

    reply_to = axis2_endpoint_ref_create(env, AXIS2_WSA_ANONYMOUS_URL);
    axis2_options_set_reply_to(options, env, reply_to);

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
        client_home = "../../..";
    }

    /* Create service client */
    svc_client = axis2_svc_client_create(env, client_home);
    if (!svc_client)
    {
        printf("Error creating service client\n");
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Stub invoke FAILED: Error code:%d :: %s", 
                env->error->error_number, AXIS2_ERROR_GET_MESSAGE(env->error));

        return -1;
    }

    policy = neethi_util_create_policy_from_file(env, "../policy/rm11-policy.xml");
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

    listener_manager = axis2_listener_manager_create(env);
    if (!listener_manager)
    {
        return AXIS2_FAILURE;
    }

    /* Offer sequence */
    offered_seq_id = axutil_uuid_gen(env);
    property = axutil_property_create(env);
    if(property)
    {
        axutil_property_set_value(property, env, axutil_strdup(env, offered_seq_id));
        axis2_options_set_property(options, env, SANDESHA2_CLIENT_OFFERED_SEQ_ID, property);
    }

    /* RM Version 1.1 */
    property = axutil_property_create_with_args(env, 3, 0, 0, SANDESHA2_SPEC_VERSION_1_1);
    if(property)
    {
        axis2_options_set_property(options, env, SANDESHA2_CLIENT_RM_SPEC_VERSION, property);
    }

    payload = build_om_payload_for_echo_svc(env, "echo1");
    /*status = axis2_svc_client_send_robust(svc_client, env, payload);
    if(status)
    {
        printf("\necho client single channel invoke SUCCESSFUL!\n");
    }
    payload = NULL;*/
    result = axis2_svc_client_send_receive(svc_client, env, payload);
    if(result)
    {
        axis2_char_t *om_str = NULL;
        om_str = axiom_node_to_string(result, env);
        if (om_str)
        {
            printf("\nReceived OM : %s\n", om_str);
            AXIS2_FREE(env->allocator, om_str);
        }
        printf("\necho client two way single channel invoke SUCCESSFUL!\n");
        result = NULL;
    }
    else
    {
        printf("\necho client two way single channel invoke FAILED!\n");
    }

    payload = build_om_payload_for_echo_svc(env, "echo2");
    /*status = axis2_svc_client_send_robust(svc_client, env, payload);
    if(status)
    {
        printf("\necho client single channel invoke SUCCESSFUL!\n");
    }
    payload = NULL;*/
    result = axis2_svc_client_send_receive(svc_client, env, payload);
    if(result)
    {
        axis2_char_t *om_str = NULL;
        om_str = axiom_node_to_string(result, env);
        if (om_str)
        {
            printf("\nReceived OM : %s\n", om_str);
            AXIS2_FREE(env->allocator, om_str);
        }
        printf("\necho client two way single channel invoke SUCCESSFUL!\n");
        result = NULL;
    }
    else
    {
        printf("\necho client two way single channel invoke FAILED!\n");
    }

    payload = build_om_payload_for_echo_svc(env, "echo3");
    /*status = axis2_svc_client_send_robust(svc_client, env, payload);
    if(status)
    {
        printf("\necho client single channel invoke SUCCESSFUL!\n");
    }
    payload = NULL;*/
    
    result = axis2_svc_client_send_receive(svc_client, env, payload);
    if(result)
    {
        axis2_char_t *om_str = NULL;
        om_str = axiom_node_to_string(result, env);
        if (om_str)
        {
            printf("\nReceived OM : %s\n", om_str);
            AXIS2_FREE(env->allocator, om_str);
        }
        printf("\necho client two way single channel invoke SUCCESSFUL!\n");
        result = NULL;
    }
    else
    {
        printf("\necho client two way single channel invoke FAILED!\n");
    }

    AXIS2_SLEEP(SANDESHA2_SLEEP); 

    sandesha2_client_terminate_seq_with_svc_client_and_seq_key(env, svc_client, NULL, NULL);

    AXIS2_SLEEP(6 * SANDESHA2_SLEEP);

    if (svc_client)
    {
        axis2_svc_client_free(svc_client, env);
        svc_client = NULL;
    }
    
    return 0;
}


