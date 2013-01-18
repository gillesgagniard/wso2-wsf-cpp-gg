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

AXIS2_EXTERN axiom_node_t* AXIS2_CALL
oxs_token_build_security_token_reference_element(
    const axutil_env_t *env,
    axiom_node_t *parent)
{
    axiom_node_t *security_token_reference_node = NULL;
    axiom_element_t *security_token_reference_ele = NULL;
    axiom_namespace_t *ns_obj = NULL;

    ns_obj = axiom_namespace_create(env, OXS_WSSE_XMLNS, OXS_WSSE);

    /* We especially pass parent=NULL in order to add WSSE namespace to the SECURITY_TOKEN_REFRENCE 
     * node. Otherwise if we encrypt the signature , the dercyption fails to build the node as the 
     * namespace is not within the doc */
    security_token_reference_ele = axiom_element_create(
        env, NULL, OXS_NODE_SECURITY_TOKEN_REFRENCE, ns_obj, &security_token_reference_node);
    if(!security_token_reference_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Error creating SecurityTokenReference element.");
        axiom_namespace_free(ns_obj, env);
        return NULL;
    }

    if(parent)
    {
        axiom_node_add_child(parent, env, security_token_reference_node);
    }

    return security_token_reference_node;
}


