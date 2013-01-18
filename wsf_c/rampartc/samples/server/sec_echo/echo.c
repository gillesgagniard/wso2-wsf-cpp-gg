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
#include "echo.h"
#include <axiom_xml_writer.h>
#include <axiom_util.h>
#include <stdio.h>

axiom_node_t *
build_om_programatically(const axutil_env_t *env, axis2_char_t *text);
axiom_node_t *
build_om_payload_for_echo_svc_interop(const axutil_env_t *env, axis2_char_t *text);


axiom_node_t *
axis2_echo_echo(const axutil_env_t *env, axiom_node_t *node, axis2_msg_ctx_t *msg_ctx)
{
    axiom_node_t *ret_node = NULL;
    axis2_char_t *name = NULL;
    AXIS2_ENV_CHECK(env, NULL);
    
    name = axiom_util_get_localname(node, env);
    AXIS2_LOG_INFO(env->log, "[rampart][sec_echo_service] Recieved node %s", name);     
/*
 * This shows how to acces the security processed results from the message context
    {
    axis2_char_t *username = NULL;
    
    username = (axis2_char_t*)rampart_get_security_processed_result(env, msg_ctx, "SPR_UT_username");
    printf("Username of the Token is = %s ", username);
    }
*/   
    ret_node = build_om_programatically(env, name);
    return ret_node;
}

/* Builds the response content */
axiom_node_t *
build_om_programatically(const axutil_env_t *env, axis2_char_t *text)
{
    axiom_node_t *echo_om_node = NULL;
    axiom_element_t* echo_om_ele = NULL;
    axiom_node_t* text_om_node = NULL;
    axiom_element_t * text_om_ele = NULL;
    axiom_namespace_t *ns1 = NULL;

    ns1 = axiom_namespace_create(env, "http://ws.apache.org/axis2/rampart/samples", "ns1");
    echo_om_ele = axiom_element_create(env, NULL, "RecievedNode", ns1, &echo_om_node);

    text_om_ele = axiom_element_create(env, echo_om_node, "LocalName", NULL, &text_om_node);

    axiom_element_set_text(text_om_ele, env, text, text_om_node);
 
    return echo_om_node;
}

axiom_node_t *
build_om_payload_for_echo_svc_interop(const axutil_env_t *env, axis2_char_t *text)
{
 axiom_node_t *echo_om_node = NULL;
    axiom_element_t* echo_om_ele = NULL;
    axiom_node_t* text_om_node = NULL;
    axiom_element_t * text_om_ele = NULL;
    axiom_namespace_t *ns1 = NULL;

    ns1 = axiom_namespace_create(env, "http://InteropBaseAddress/interop", "ns1");
    echo_om_ele = axiom_element_create(env, NULL, "echoResponse", ns1, &echo_om_node);

    text_om_ele = axiom_element_create(env, echo_om_node, "LocalName", NULL, &text_om_node);

    axiom_element_set_text(text_om_ele, env, text, text_om_node);
 
    return echo_om_node;

}
