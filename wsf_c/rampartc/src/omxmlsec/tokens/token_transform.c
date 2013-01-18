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
* Creates <ds:Transform> element
*/
AXIS2_EXTERN axiom_node_t* AXIS2_CALL
oxs_token_build_transform_element(
    const axutil_env_t *env,
    axiom_node_t *parent,
    axis2_char_t* algorithm)
{
    axiom_node_t *transform_node = NULL, *tr_para_node = NULL, *tr_can_node = NULL;
    axiom_element_t *transform_ele = NULL, *tr_para_ele = NULL, *tr_can_ele = NULL;
    axiom_attribute_t *algo_attr = NULL;
    int ret;
    axiom_namespace_t *ns_obj = NULL;

    ns_obj = axiom_namespace_create(env, OXS_DSIG_NS, OXS_DS);
    transform_ele = axiom_element_create(env, parent, OXS_NODE_TRANSFORM, ns_obj, &transform_node);
    if (!transform_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Error creating transform element.");
        axiom_namespace_free(ns_obj, env);
        return NULL;
    }

    /* If transform algorithm is NULL then use the default */
    if(!algorithm)
    {
        algorithm = (axis2_char_t*)OXS_HREF_XML_EXC_C14N;
    }

    algo_attr =  axiom_attribute_create(env, OXS_ATTR_ALGORITHM, algorithm, NULL);
    ret = axiom_element_add_attribute(transform_ele, env, algo_attr, transform_node);
   
    if (!axutil_strcmp(algorithm, OXS_HREF_TRANSFORM_STR_TRANSFORM))
    {
        ns_obj = axiom_namespace_create(env, OXS_WSSE_NS, OXS_WSSE);
        tr_para_ele = axiom_element_create(
            env, NULL, OXS_NODE_TRANSFORMATIONPARAMETERS, ns_obj, &tr_para_node);
        if (!tr_para_ele)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[rampart]Error creating TransformationParameters element.");
            axiom_namespace_free(ns_obj, env);
            return NULL;
        }

        ns_obj = axiom_namespace_create(env, OXS_DSIG_NS, OXS_DS);
        tr_can_ele = axiom_element_create(
            env, tr_para_node, OXS_NODE_CANONICALIZATION_METHOD, ns_obj, &tr_can_node);
        if (!tr_can_ele)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[rampart]Error creating CanonicalizationMethod element.");
            axiom_namespace_free(ns_obj, env);
            return NULL;
        }

        algo_attr =  axiom_attribute_create(env, OXS_ATTR_ALGORITHM, OXS_HREF_XML_EXC_C14N, NULL);		
		axiom_element_add_attribute(tr_can_ele, env, algo_attr, tr_can_node);
		axiom_node_add_child(transform_node, env, tr_para_node);
    }
    return transform_node;
}



AXIS2_EXTERN axis2_char_t *AXIS2_CALL
oxs_token_get_transform(
    const axutil_env_t *env, 
    axiom_node_t *transform_node)
{
    axis2_char_t *transform = NULL;
    axiom_element_t *transform_ele = NULL;

    if(!transform_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Error retrieving digest method node.");
        return NULL;
    }

    transform_ele = axiom_node_get_data_element(transform_node, env);
    if (!transform_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Error retrieving digest method element.");
        return NULL;
    }

    transform = axiom_element_get_attribute_value_by_name(transform_ele, env, OXS_ATTR_ALGORITHM);
    if((!transform) ||(!axutil_strcmp("", transform)))
    {
        return NULL;
    }

    return transform;
}

