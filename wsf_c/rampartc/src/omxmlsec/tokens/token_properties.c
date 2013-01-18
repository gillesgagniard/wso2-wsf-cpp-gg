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

#include <oxs_tokens.h>

AXIS2_EXTERN axis2_char_t* AXIS2_CALL
oxs_token_get_properties_value(
    const axutil_env_t *env,
    axiom_node_t *properties_node)
{
    axis2_char_t *value = NULL;
    value = (axis2_char_t*)oxs_axiom_get_node_content(env, properties_node);
    return value;
}

/**
 * Creates <wsc:Properties> element
 */
AXIS2_EXTERN axiom_node_t* AXIS2_CALL
oxs_token_build_properties_element(
    const axutil_env_t *env,
    axiom_node_t *parent,
    axis2_char_t *properties_val, 
    axis2_char_t *wsc_ns_uri)
{
    axiom_node_t *properties_node = NULL;
    axiom_element_t *properties_ele = NULL;
    axis2_status_t ret;
    axiom_namespace_t *ns_obj = NULL;

    if(!wsc_ns_uri)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Error creating %s Token element. SecConv namespace uri is not valid.", 
            OXS_NODE_PROPERTIES);
        return NULL;
    }

    ns_obj = axiom_namespace_create(env, wsc_ns_uri,OXS_WSC);
    properties_ele = axiom_element_create(
        env, parent, OXS_NODE_PROPERTIES, ns_obj, &properties_node);
    if (!properties_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Error creating %s Token element.", OXS_NODE_PROPERTIES);
        axiom_namespace_free(ns_obj, env);
        return NULL;
    }

    if (properties_val)
    {
        ret  = axiom_element_set_text(properties_ele, env, properties_val, properties_node);
    }

    return properties_node;
}

