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

/**
 * Creates <xenc:EncryptedData> element
 */
AXIS2_EXTERN axiom_node_t* AXIS2_CALL
oxs_token_build_encrypted_data_element(
    const axutil_env_t *env,
    axiom_node_t *parent,
    axis2_char_t* type_attribute,
    axis2_char_t* id)
{
    axiom_node_t *encrypted_data_node = NULL;
    axiom_element_t *encrypted_data_ele = NULL;
    axiom_attribute_t *type_attr = NULL;
    axiom_attribute_t *id_attr = NULL;
    axiom_namespace_t *ns_obj = NULL;
    int ret;

    ns_obj = axiom_namespace_create(env, OXS_ENC_NS, OXS_XENC);
    encrypted_data_ele = axiom_element_create(
        env, parent, OXS_NODE_ENCRYPTED_DATA, ns_obj, &encrypted_data_node);
    if(!encrypted_data_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Error creating encrypted data element.");
        axiom_namespace_free(ns_obj, env);
        return NULL;
    }

    if (type_attribute)
    {
        type_attr =  axiom_attribute_create(env, OXS_ATTR_TYPE, type_attribute, NULL);
        ret = axiom_element_add_attribute(encrypted_data_ele, env, type_attr, encrypted_data_node);
    }

    if(!id)
    {
        id = oxs_util_generate_id(env, (axis2_char_t*)OXS_ENCDATA_ID);
    }
    id_attr = axiom_attribute_create(env, OXS_ATTR_ID, id, NULL );
    ret = axiom_element_add_attribute(encrypted_data_ele, env, id_attr, encrypted_data_node);

    return encrypted_data_node;
}

