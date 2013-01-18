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

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
oxs_token_get_signature_confirmation_value(
    const axutil_env_t *env, 
    axiom_node_t *signature_confirmation_node)
{
    axis2_char_t *value = NULL;
    axiom_element_t *signature_confirmation_ele = NULL;

    if(!signature_confirmation_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Error retrieving SignatureConfirmation method node.");
        return NULL;
    }

    signature_confirmation_ele = axiom_node_get_data_element(signature_confirmation_node, env);
    if(!signature_confirmation_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Error retrieving SignatureConfirmation method element.");
        return NULL;
    }

    value = axiom_element_get_attribute_value_by_name(
        signature_confirmation_ele, env, OXS_ATTR_VALUE);
    if((!value) ||(!axutil_strcmp("", value)))
    {
        return NULL;
    }

    return value;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
oxs_token_get_signature_confirmation_id(
    const axutil_env_t *env, 
    axiom_node_t *signature_confirmation_node)
{
    axis2_char_t *id = NULL;
    axiom_element_t *signature_confirmation_ele = NULL;

    if(!signature_confirmation_node)
    {
       AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Error retrieving SignatureConfirmation method node.");
        return NULL;
    }

    signature_confirmation_ele = axiom_node_get_data_element(signature_confirmation_node, env);
    if (!signature_confirmation_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Error retrieving SignatureConfirmation method element.");
        return NULL;
    }

    id = axiom_element_get_attribute_value_by_name(signature_confirmation_ele, env, OXS_ATTR_ID);
    if((!id) ||(!axutil_strcmp("", id)))
    {
        return NULL;
    }

    return id;
}

/**
 * Creates <wsse11:SignatureConfirmation> element
 */
AXIS2_EXTERN axiom_node_t* AXIS2_CALL
oxs_token_build_signature_confirmation_element(
    const axutil_env_t *env,
    axiom_node_t *parent,
    axis2_char_t *id,
    axis2_char_t *val)
{
    axiom_node_t *signature_confirmation_node = NULL;
    axiom_element_t *signature_confirmation_ele = NULL;
    axis2_status_t ret;
    axiom_namespace_t *ns_obj = NULL;
    axiom_attribute_t *id_attr = NULL;
    axiom_attribute_t *val_attr = NULL;

    ns_obj = axiom_namespace_create(env, OXS_WSSE_11_XMLNS,OXS_WSSE_11);
    signature_confirmation_ele = axiom_element_create(
        env, parent, OXS_NODE_SIGNATURE_CONFIRMATION, ns_obj, &signature_confirmation_node);
    if(!signature_confirmation_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Error %s element", OXS_NODE_SIGNATURE_CONFIRMATION);
        axiom_namespace_free(ns_obj, env);
        return NULL;
    }

    if (id)
    {
        id_attr =  axiom_attribute_create(env, OXS_ATTR_ID, id, NULL);
        ret = axiom_element_add_attribute(
            signature_confirmation_ele, env, id_attr, signature_confirmation_node);
    }
    
    if (val)
    {
        val_attr =  axiom_attribute_create(env, OXS_ATTR_VALUE, val, NULL);
        ret = axiom_element_add_attribute(
            signature_confirmation_ele, env, val_attr, signature_confirmation_node);
    }

    return signature_confirmation_node;
}

