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

#include <stdio.h>
#include <axiom.h>
#include <axis2_util.h>
#include <axiom_soap.h>
#include <axis2_client.h>
#include <axis2_svc_client.h>
#include <axutil_env.h>

#include <savan_client.h>
#include <savan_constants.h>

static void event_source_send_event(
        axutil_env_t* env, 
        axis2_svc_client_t *svc_client,
        axis2_char_t *address,
        axis2_char_t *action);

axiom_node_t *
build_om_payload_for_weather_event(
        const axutil_env_t *env,
        axis2_char_t *node_name);

int main(int argc, char** argv)
{
    const axutil_env_t *env = NULL;
    const axis2_char_t *address = NULL;
    axis2_endpoint_ref_t* endpoint_ref = NULL;
    axis2_options_t *options = NULL;
    axis2_char_t *client_home = NULL;
    axis2_svc_client_t* svc_client = NULL;
    axutil_hash_t *savan_options = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    savan_client_t *savan_client = NULL;
    axis2_char_t *subs_status = NULL;
    int action = 0;

    /* Set up the environment */
    env = axutil_env_create_all("subscriber.log", AXIS2_LOG_LEVEL_TRACE);

    printf("Starting Savan subscriber...\n");

    client_home = AXIS2_GETENV("AXIS2C_HOME");
     
    /* Set end point reference of echo service */
    address = "http://localhost:9090/axis2/services/weather";
    if (argc > 1 )
    {
        address = argv[1];
    }
    
    printf ("Event source endpoint : %s\n", address);
   
    /* Create EPR with given address */
    endpoint_ref = axis2_endpoint_ref_create(env, address);

    /* Setup options */
    options = axis2_options_create(env);
    axis2_options_set_to(options, env, endpoint_ref);
/*    axis2_options_set_action(options, env,
        "http://schemas.xmlsoap.org/ws/2004/08/eventing/Subscribe");    
*/
    /* Create service client */
    svc_client = axis2_svc_client_create(env, client_home);
    if (!svc_client)
    {
        printf("Error creating service client\n");
        exit(1);
    }

    /* Set service client options */
    axis2_svc_client_set_options(svc_client, env, options);    
    
    /* Engage addressing module */
    axis2_svc_client_engage_module(svc_client, env, AXIS2_MODULE_ADDRESSING);
    
    /* Engage savan module */
    axis2_svc_client_engage_module(svc_client, env, "savan");

    savan_options = axutil_hash_make(env);
    axutil_hash_set(savan_options, SAVAN_OP_KEY_NOTIFY_EPR, AXIS2_HASH_KEY_STRING,
        "http://localhost:9090/axis2/services/listener");

    /**
     * Following commented lines show how to use filtering when savan server side is
     * built and running with filtering enabled.
     */
    /*axutil_hash_set(savan_options, SAVAN_OP_KEY_FILTER, AXIS2_HASH_KEY_STRING,
        "//weather_report");

    axutil_hash_set(savan_options, SAVAN_OP_KEY_FILTER_DIALECT, AXIS2_HASH_KEY_STRING,
        XPATH_FILTER_DIALECT);*/
    
    axutil_hash_set(savan_options, SAVAN_OP_KEY_FILTER, AXIS2_HASH_KEY_STRING, "weather/4");

    axutil_hash_set(savan_options, SAVAN_OP_KEY_FILTER_DIALECT, AXIS2_HASH_KEY_STRING,
        SYNAPSE_FILTER_DIALECT);

    /* Create a savan client */
    savan_client = savan_client_create(env);

    while(AXIS2_TRUE)
    {
        printf("\nSelect the action:\n"\
                "1 subscribe\n"\
                "2 renew\n"\
                "3 get status\n"\
                "4 unsubscribe\n"\
                "5 Generate weather event\n"\
                "6 quit\n\n");

        if(1 != scanf("%d", &action))
        {
            printf("Give correct input\n");
            continue;
        }

        if(1 == action) /* Send subscribe message */
        {
            status  = savan_client_subscribe(savan_client, env, svc_client, savan_options);
            
            if (status == AXIS2_SUCCESS)
            {
                printf("Subscribe successful\n");
                printf("Subscription ID: %s\n", savan_client_get_sub_id(savan_client));
            }
            else
            {
                printf("Subscription Failed\n");
                exit(0);
            }
        }
        else if(2 == action)
        {
            axis2_char_t *renew_status = NULL;

            printf("Renewing subscription...\n");
            address = savan_client_get_sub_url(savan_client);
            printf("address:%s\n", address); 
            endpoint_ref = axis2_options_get_to(options, env);
            axis2_endpoint_ref_set_address(endpoint_ref, env, address);
            /*axutil_hash_set(savan_options, SAVAN_OP_KEY_EXPIRES, AXIS2_HASH_KEY_STRING, "2010-02-12T06:54Z");*/
            axutil_hash_set(savan_options, SAVAN_OP_KEY_EXPIRES, AXIS2_HASH_KEY_STRING, "2009-04-26T21:07:00.000-08:00");
            /*axutil_hash_set(savan_options, SAVAN_OP_KEY_EXPIRES, AXIS2_HASH_KEY_STRING, "P3Y6M4DT12H30M5S");*/
            renew_status = savan_client_renew(savan_client, env, svc_client, savan_options);
            if (renew_status)
            {
                printf("Renew successful\n");
                printf("Renewed Subscription expires on:%s\n", renew_status);
            }
        }
        else if(3 == action)
        {
            printf("Getting status of subscription...\n");
            address = savan_client_get_sub_url(savan_client);
            endpoint_ref = axis2_options_get_to(options, env);
            axis2_endpoint_ref_set_address(endpoint_ref, env, address);
            axis2_svc_client_remove_all_headers(svc_client, env);
            subs_status = savan_client_get_status(savan_client, env, svc_client);
            if (subs_status)
            {
                printf("GetStatus successful\n");
                printf("Subscription expires on:%s\n", subs_status);
            }
        }
        else if(4 == action)
        {
            printf("Unsubscribing...\n");
            address = savan_client_get_sub_url(savan_client);
            endpoint_ref = axis2_options_get_to(options, env);
            axis2_endpoint_ref_set_address(endpoint_ref, env, address);
            axis2_svc_client_remove_all_headers(svc_client, env);
            status = savan_client_unsubscribe(savan_client, env, svc_client);
            if (status == AXIS2_SUCCESS)
            {
                printf("Unsubscribe successful\n");
            }
        }
        else if(5 == action)
        {
            axis2_options_set_action(options, env,
                "http://ws.apache.org/axis2/c/savan/samples/weather/send");
            endpoint_ref = axis2_options_get_to(options, env);
            axis2_endpoint_ref_set_address(endpoint_ref, env, address);
            axis2_svc_client_remove_all_headers(svc_client, env);
            event_source_send_event((axutil_env_t*)env, svc_client, address, "send");
        }
        else if(7 == action)
        {
            break;
        }
        else
        {
            break;
        }
    }

    if (svc_client)
    {
        axis2_svc_client_free(svc_client, env);
        svc_client = NULL;
    }
    
    return 0;
}


static void event_source_send_event(
        axutil_env_t* env, 
        axis2_svc_client_t *svc_client, 
        axis2_char_t *address,
        axis2_char_t *action)
{
    axiom_node_t *payload = NULL;

    AXIS2_LOG_INFO(env->log, "[savan] event_source_handle_lifecycle");

    payload = build_om_payload_for_weather_event(env, action);
    
    /* Send request */
    axis2_svc_client_fire_and_forget(svc_client, env, payload);
}

axiom_node_t *
build_om_payload_for_weather_event(
        const axutil_env_t *env,
        axis2_char_t *node_name)
{
    axiom_namespace_t *test_ns = NULL;
    axiom_element_t* test_elem = NULL;
    axiom_node_t *test_node = NULL;
    axiom_element_t* test_elem1 = NULL;
    axiom_node_t *test_node1 = NULL;
    
    /* Build a payload and pass it to the savan publisher module */ 
    test_ns = axiom_namespace_create(env, "http://ws.apache.org/savan/samples/weather", "weather");
    test_elem = axiom_element_create(env, NULL, node_name, test_ns, &test_node);
    test_elem1 = axiom_element_create(env, test_node, "weather_report", NULL, &test_node1);

    axiom_element_set_text(test_elem1, env, "sunny day", test_node1);
    
    return test_node;
}
 
