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
* Creates <wss11:EncryptedHeader> element
*/
AXIS2_EXTERN axiom_node_t* AXIS2_CALL
oxs_token_build_enc_header_element(
    const axutil_env_t *env,
    axiom_node_t *parent,
    axis2_char_t* id)
{
    axiom_node_t *enc_header_node = NULL;
    axiom_element_t *enc_header_ele = NULL;
    axiom_attribute_t *id_attr = NULL;
    axiom_namespace_t *ns_obj = NULL;
    int ret;

    ns_obj = axiom_namespace_create(env, OXS_WSSE_11_XMLNS, OXS_WSSE_11);
    enc_header_ele = axiom_element_create(
        env, parent, OXS_NODE_ENCRYPTED_HEADER, ns_obj, &enc_header_node);
    if(!enc_header_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Error creating EncryptedHeader element.");
        axiom_namespace_free(ns_obj, env);
        return NULL;
    }

    if(id)
    {
        id_attr = axiom_attribute_create(env, OXS_ATTR_ID, id, NULL);
        ret = axiom_element_add_attribute(enc_header_ele, env, id_attr, enc_header_node);
    }

    return enc_header_node;
}

