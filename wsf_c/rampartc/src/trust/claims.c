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

#include <trust_claims.h>

struct trust_claims
{
    axis2_char_t *attr_dialect;
    axis2_char_t *wst_ns_uri;
    axutil_array_list_t * claim_list;
    
};

AXIS2_EXTERN trust_claims_t * AXIS2_CALL
trust_claims_create(
        const axutil_env_t *env)
{
    trust_claims_t *claims = NULL;
    
    claims = (trust_claims_t*)AXIS2_MALLOC(env->allocator, sizeof(trust_claims_t));
    claims->attr_dialect = NULL;
    claims->wst_ns_uri = NULL;
    claims->claim_list = axutil_array_list_create(env, 10);
    
    return claims;
}

AXIS2_EXTERN  axis2_status_t AXIS2_CALL
trust_claims_free(
        trust_claims_t *claims,
        const axutil_env_t *env)
{
    if(NULL != claims->claim_list)
    {
        axutil_array_list_free(claims->claim_list, env);
    }
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_claims_deserialize(
        trust_claims_t *claims,
        const axutil_env_t *env,
        axiom_node_t *claims_node)
{
    axiom_element_t *claims_ele = NULL;
    axiom_children_iterator_t *children_iter = NULL;
    axis2_char_t *dialect_attr = NULL;
    axiom_node_t * temp_node = NULL;
    
    claims_ele = axiom_node_get_data_element(claims_node, env);
    if(claims_ele)
    {
        children_iter = axiom_element_get_children(claims_ele, env, claims_node);
        if(children_iter)
        {
            while (axiom_children_iterator_has_next(children_iter, env))
            {
                temp_node = axiom_children_iterator_next( children_iter, env);
                if(axiom_node_get_node_type(temp_node, env) == AXIOM_ELEMENT)
                {
                    axutil_array_list_add(claims->claim_list, env, temp_node);
                }
            }
        }
        
        dialect_attr = axiom_element_get_attribute_value_by_name(claims_ele, env, TRUST_CLAIMS_DIALECT);
        claims->wst_ns_uri = TRUST_WST_XMLNS_05_02;
        if(dialect_attr)
        {
            claims->attr_dialect = dialect_attr;
        } 
		else
		{	
			return AXIS2_FAILURE;
		}
    }
    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
trust_claims_serialize(
        trust_claims_t *claims,
        const axutil_env_t *env,
        axiom_node_t *parent)
{
    axiom_node_t *claims_node = NULL;
    int index = 0;
    
    claims_node = (axiom_node_t*)trust_util_create_claims_element(env, TRUST_WST_XMLNS_05_02, parent, claims->attr_dialect);
    if(!claims_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Claims Element creation failed!");
        return NULL;
    }
      
    
    for(index = 0; index <axutil_array_list_size(claims->claim_list, env); index++)
    {
        axiom_node_add_child(claims_node, env, 
                (axiom_node_t*) axutil_array_list_get(claims->claim_list, env, index));
    }
    
    
    
    return claims_node;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_claims_set_attr_dialect(
        trust_claims_t *claims,
        const axutil_env_t *env,
        axis2_char_t *dialect_attr)
{
    if(dialect_attr)
    {
        claims->attr_dialect = dialect_attr;
        
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_claims_get_attr_dialect(
        trust_claims_t *claims,
        const axutil_env_t *env)
{
    return claims->attr_dialect;
}

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL
trust_claims_get_claim_list(
    trust_claims_t *claims,
    const axutil_env_t *env)
{
    return claims->claim_list;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_claims_set_wst_ns_uri(
        trust_claims_t *claims,
        const axutil_env_t *env,
        axis2_char_t *wst_ns_uri)
{
    if(wst_ns_uri)
    {
        claims->wst_ns_uri = wst_ns_uri;
        
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
trust_claims_get_wst_ns_uri(
        trust_claims_t *claims,
        const axutil_env_t *env)
{
    return claims->wst_ns_uri;
}
