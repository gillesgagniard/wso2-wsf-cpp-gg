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

#include <trust_rstr.h>

struct trust_rstr{

    axis2_char_t *attr_context; /*Context Attribute of RSTR : same as RST context attribute */

    axis2_char_t *token_type;
    
    axis2_char_t *request_type;
    
    axiom_node_t *requested_sec_token;
    
    axis2_char_t *applies_to;
    
    axiom_node_t *requested_attached_ref;
    
    axiom_node_t *requested_unattached_ref;
    
    axiom_node_t *requested_proof_token;
    
    trust_entropy_t *entropy;
    
    trust_life_time_t *life_time;
    
    int key_size;

    axis2_char_t *wst_ns_uri;
    
    /*Use state whether response is going inside soap header or soap body*/
    axis2_bool_t in_header;
};

AXIS2_EXTERN trust_rstr_t * AXIS2_CALL
trust_rstr_create(
        const axutil_env_t *env)
{
    trust_rstr_t *rstr = NULL;
    
    rstr = (trust_rstr_t*)AXIS2_MALLOC(env->allocator, sizeof(trust_rstr_t));
    
    rstr->token_type = NULL;
    rstr->attr_context = NULL;
    rstr->request_type = NULL;
    rstr->requested_sec_token = NULL;
    rstr->applies_to = NULL;
    rstr->requested_attached_ref = NULL;
    rstr->requested_unattached_ref = NULL;
    rstr->requested_proof_token = NULL;
    rstr->entropy = NULL;
    rstr->life_time = NULL;
    rstr->key_size = -1;
    rstr->wst_ns_uri = NULL;
    
    return rstr;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rstr_free(
        trust_rstr_t *rstr,
        const axutil_env_t *env)
{
	AXIS2_FREE(env->allocator, rstr);
    return AXIS2_SUCCESS;
}


/*Populating RSTR*/

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rstr_populate_rstr(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        axiom_node_t *rstr_node)
{
    axiom_element_t *rstr_ele = NULL;
    axutil_qname_t *attr_ctx_qname = NULL;
    axis2_char_t *attr_ctx = NULL;
    
    axiom_node_t *requested_security_token_node = NULL;
    axiom_element_t *requested_security_token_ele = NULL;
    axutil_qname_t *requested_security_token_qname = NULL;

    axiom_node_t *proof_token_node = NULL;
    axiom_element_t *proof_token_ele = NULL;
    axutil_qname_t *proof_token_qname = NULL;

    axiom_node_t *attached_reference_node = NULL;
    axiom_element_t *attached_reference_ele = NULL;
    axutil_qname_t *attached_reference_qname = NULL;

    axiom_node_t *unattached_reference_node = NULL;
    axiom_element_t *unattached_reference_ele = NULL;
    axutil_qname_t *unattached_reference_qname = NULL;
    
    axiom_node_t *token_type_node = NULL;
    axiom_element_t *token_type_ele = NULL;
    axutil_qname_t *token_type_qname = NULL;
    axis2_char_t *token_type = NULL;    
    
    axutil_qname_t *applies_to_qname = NULL;
    axiom_node_t *appliesto_node = NULL;
    axiom_element_t *appliesto_ele = NULL;
    axiom_node_t *first_node = NULL;
    axiom_element_t *first_ele = NULL;
    
    
    trust_entropy_t *entropy = NULL;
    axiom_node_t *entropy_node = NULL;
    axiom_element_t *entropy_ele = NULL;
    axutil_qname_t *entropy_qname = NULL;
    
    axiom_node_t *lifetime_node = NULL;
    axiom_element_t *lifetime_ele = NULL;
    axutil_qname_t *lifetime_qname = NULL;
    
    axiom_node_t *key_size_node = NULL;
    axiom_element_t *key_size_ele = NULL;
    axutil_qname_t *key_size_qname = NULL;
    axis2_char_t *key_size = NULL;
    
        
    rstr_ele = (axiom_element_t*)axiom_node_get_data_element(rstr_node, env);
    
    /*@Context RSTR*/
    attr_ctx_qname = axutil_qname_create(env, TRUST_RST_CONTEXT, rstr->wst_ns_uri, TRUST_WST);
    if (!attr_ctx_qname)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Context Attribute Qname creation failed.");
        return AXIS2_FAILURE;
    }
    attr_ctx = axiom_element_get_attribute_value(rstr_ele, env, attr_ctx_qname);
    if (attr_ctx)
    {
        rstr->attr_context = attr_ctx;
    }
	axutil_qname_free(attr_ctx_qname, env);
    
    /*TokenType*/
    token_type_qname = axutil_qname_create(env, TRUST_TOKEN_TYPE, rstr->wst_ns_uri, TRUST_WST);
    if (!token_type_qname)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] TokenType Qname creation failed.");
        return AXIS2_FAILURE;
    }
    token_type_ele = axiom_element_get_first_child_with_qname(rstr_ele, env, token_type_qname, rstr_node, &token_type_node);
    if (token_type_ele)
    {
        token_type = axiom_element_get_text(token_type_ele, env, token_type_node);
        if(token_type)
        {
            rstr->token_type = token_type;
        }        
    }
	axutil_qname_free(token_type_qname, env);
    
    
    /*RequestedSecurityToken*/
    requested_security_token_qname = axutil_qname_create(env, TRUST_REQUESTED_SECURITY_TOKEN, rstr->wst_ns_uri, TRUST_WST);
    if(!requested_security_token_qname)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RequestedSecurityToken Qname creation failed.");
        return AXIS2_FAILURE;
    }
    requested_security_token_ele = axiom_element_get_first_child_with_qname(rstr_ele, env, requested_security_token_qname, 
                                            rstr_node, &requested_security_token_node);
    if(requested_security_token_ele)
    {
        axiom_element_get_first_element(requested_security_token_ele, env, requested_security_token_node, &rstr->requested_sec_token);
    }
	axutil_qname_free(requested_security_token_qname, env);

	
	/*RequestedProofToken*/
	proof_token_qname = axutil_qname_create(env, TRUST_REQUESTED_PROOF_TOKEN, rstr->wst_ns_uri, TRUST_WST);
	if(!proof_token_qname)
	{
		AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RequestedProofToken Qname creation failed.");
		return AXIS2_FAILURE;
	}
	proof_token_ele = axiom_element_get_first_child_with_qname(rstr_ele, env, proof_token_qname, rstr_node, &proof_token_node);
	if(proof_token_ele)
	{
		axiom_element_get_first_element(proof_token_ele, env, proof_token_node, &rstr->requested_proof_token);
	}
	axutil_qname_free(proof_token_qname, env);
    
    /*AppliesTo*/
    applies_to_qname = axutil_qname_create(env, TRUST_APPLIES_TO, TRUST_WSP_XMLNS, TRUST_WSP);
    if (!applies_to_qname)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Appliesto Qname creation failed.");
        return AXIS2_FAILURE;
    }
    appliesto_ele = axiom_element_get_first_child_with_qname(rstr_ele, env, applies_to_qname, rstr_node, &appliesto_node);
    if(appliesto_ele)
    {
        first_ele = axiom_element_get_first_element(appliesto_ele, env, appliesto_node, &first_node);
        if(first_ele)
        {
            rstr->applies_to = axiom_element_get_text(first_ele, env, first_node);
        }
    }
	axutil_qname_free(applies_to_qname, env);
    
    /*Entropy*/
    entropy_qname = axutil_qname_create(env, TRUST_ENTROPY, rstr->wst_ns_uri, TRUST_WST);
    if (!entropy_qname)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Entropy Qname creation failed.");
        return AXIS2_FAILURE;
    }
    entropy_ele = axiom_element_get_first_child_with_qname(rstr_ele, env, entropy_qname, rstr_node, &entropy_node);
    if(entropy_ele)
    {
        entropy = trust_entropy_create(env);
        trust_entropy_set_ns_uri(entropy, env, rstr->wst_ns_uri);
        if(AXIS2_SUCCESS == trust_entropy_deserialize(entropy, env, entropy_node))
        {
            rstr->entropy = entropy;
        }
    }
	axutil_qname_free(entropy_qname, env);
    
    
    /*LifeTime*/
    lifetime_qname = axutil_qname_create(env, TRUST_LIFE_TIME, rstr->wst_ns_uri, TRUST_WST);
    if(!lifetime_qname)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] LifeTime Qname creation failed.");
        return AXIS2_FAILURE;        
    }
    lifetime_ele = axiom_element_get_first_child_with_qname(rstr_ele, env, lifetime_qname, rstr_node, &lifetime_node);
    if(lifetime_ele)
    {
        rstr->life_time = trust_life_time_create(env);
        if(AXIS2_SUCCESS == trust_life_time_deserialize(rstr->life_time, env, lifetime_node))
        {
            
        }
    }
    axutil_qname_free(lifetime_qname, env);

        /* KeySize */
    key_size_qname = axutil_qname_create(env, TRUST_KEY_SIZE, rstr->wst_ns_uri, TRUST_WST);
    key_size_ele = axiom_element_get_first_child_with_qname(rstr_ele, env, key_size_qname, rstr_node, &key_size_node);
    if(key_size_ele)
    {
        key_size = axiom_element_get_text(key_size_ele, env, key_size_node);
        if(key_size)
        {
            rstr->key_size = atoi(key_size);
        }
    }
	axutil_qname_free(key_size_qname, env);

    /*Attached reference*/
	attached_reference_qname = axutil_qname_create(env, TRUST_REQUESTED_ATTACHED_REFERENCE, rstr->wst_ns_uri, TRUST_WST);
	if(!attached_reference_qname)
	{
		AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RequestedAttachedReference Qname creation failed.");
		return AXIS2_FAILURE;
	}
	attached_reference_ele = axiom_element_get_first_child_with_qname(rstr_ele, env, attached_reference_qname, rstr_node, &attached_reference_node);
	if(attached_reference_ele)
	{
		axiom_element_get_first_element(attached_reference_ele, env, attached_reference_node, &rstr->requested_attached_ref);
	}
    axutil_qname_free(attached_reference_qname, env);

    /*Unattached reference*/
	unattached_reference_qname = axutil_qname_create(env, TRUST_REQUESTED_UNATTACHED_REFERENCE, rstr->wst_ns_uri, TRUST_WST);
	if(!unattached_reference_qname)
	{
		AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RequestedUnattachedReference Qname creation failed.");
		return AXIS2_FAILURE;
	}
	unattached_reference_ele = axiom_element_get_first_child_with_qname(rstr_ele, env, unattached_reference_qname, rstr_node, &unattached_reference_node);
	if(unattached_reference_ele)
	{
		axiom_element_get_first_element(unattached_reference_ele, env, unattached_reference_node, &rstr->requested_unattached_ref);
	}
	axutil_qname_free(unattached_reference_qname, env);

    return AXIS2_SUCCESS;
    
}


/*Build RSTR */
AXIS2_EXTERN axiom_node_t * AXIS2_CALL
trust_rstr_build_rstr(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        axiom_node_t *parent)
{
    axiom_node_t *rstr_node = NULL;
    axis2_char_t *key_size = NULL;
    
    rstr_node = (axiom_node_t*)trust_util_create_rstr_element(env, rstr->wst_ns_uri, rstr->attr_context);

    if(rstr_node)
    {
        if(rstr->token_type)
        {
            if(NULL == (axiom_node_t*)trust_util_create_token_type_element(env, rstr->wst_ns_uri, rstr_node, rstr->token_type))
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RSTR TokenType element creation failed.");
                return NULL;
            }
        }
        
        if(rstr->requested_sec_token)
        {
            if(NULL == (axiom_node_t*)trust_util_create_requested_security_token_element(env, rstr->wst_ns_uri, rstr_node, rstr->requested_sec_token))
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RSTR ReqSecToken element creation failed.");
                return NULL;
            }
            
        }

		if(rstr->requested_proof_token)
		{
			/*Appending generic proof token node to RSTR - Here proof token can be just a session key, entropy node with binary secret
			 * Creating the proof token is completely up to the user. Eventhough, there are some default util methods provided by trust_util to create 
			 * proof tokens. 
			*/
			axiom_node_add_child(rstr_node, env, rstr->requested_proof_token);
		}

        if(rstr->applies_to)
        {
            if(NULL == (axiom_node_t*)trust_util_create_applies_to_element(env, rstr_node, rstr->applies_to, TRUST_WSA_XMLNS))
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RSTR AppliesTo element creation failed.");
                return NULL;
            }
        }
        if(rstr->requested_attached_ref)
        {
            axiom_node_t* attached_ref = NULL;
            attached_ref = trust_util_create_req_attached_reference_element(env, rstr->wst_ns_uri, rstr_node);
            if(NULL == attached_ref)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RSTR AttachedReference element creation failed.");
                return NULL;   
            }
            axiom_node_add_child(attached_ref, env, rstr->requested_attached_ref);
            
        }
        if(rstr->requested_unattached_ref)
        {
            axiom_node_t* unattached_ref = NULL;
            unattached_ref = trust_util_create_req_unattached_reference_element(env, rstr->wst_ns_uri, rstr_node);
            if(NULL == unattached_ref)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RSTR UnattachedReference element creation failed.");
                return NULL;   
            }
            axiom_node_add_child(unattached_ref, env, rstr->requested_unattached_ref);
        }
        
        if(rstr->entropy)
        {
            if(NULL == trust_entropy_serialize(rstr->entropy, env, rstr_node))
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RSTR Entropy element creation failed.");
                return NULL;
            }
        }
        
        if(rstr->life_time)
        {
            if(NULL == trust_life_time_serialize(rstr->life_time, env, rstr_node))
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RSTR LifeTime element creation failed.");
                return NULL;
            }
        }
        
        if(rstr->key_size > 0)
        {
            /*INFO -keysize Malloc Size = 128 */
            key_size = AXIS2_MALLOC( env->allocator, sizeof(char)*128);
            sprintf(key_size, "%d", rstr->key_size);
            if(NULL == (axiom_node_t*)trust_util_create_key_size_element(env, rstr->wst_ns_uri, rstr_node, key_size))
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] KeySize element creation failed.");
                return NULL; 
            }
        }
        return rstr_node;
    }
	return NULL;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_rstr_get_token_type(
        trust_rstr_t *rstr,
        const axutil_env_t *env)
{
    return rstr->token_type;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rstr_set_token_type(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        axis2_char_t *token_type)
{
    if(token_type)
    {
        rstr->token_type = token_type;
        
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_rstr_get_request_type(
        trust_rstr_t *rstr,
        const axutil_env_t *env)
{
    return rstr->request_type;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rstr_set_request_type(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        axis2_char_t *request_type)
{
    if(request_type)
    {
        rstr->request_type = request_type;
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
trust_rstr_get_requested_security_token(
        trust_rstr_t *rstr,
        const axutil_env_t *env)
{
    return rstr->requested_sec_token;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rstr_set_requested_security_token(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        axiom_node_t *security_token)
{
    if (security_token) 
    {
        rstr->requested_sec_token = security_token;
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;

}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_rstr_get_applies_to(
        trust_rstr_t *rstr,
        const axutil_env_t *env)
{
    return rstr->applies_to;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rstr_set_applies_to(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        axis2_char_t *applies_to)
{
    if (applies_to) 
    {
        rstr->applies_to = applies_to;
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
trust_rstr_get_requested_attached_reference(
        trust_rstr_t *rstr,
        const axutil_env_t *env)
{
    return rstr->requested_attached_ref;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rstr_set_requested_attached_reference(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        axiom_node_t *ref_node)
{
    if (ref_node) 
    {
        rstr->requested_attached_ref = ref_node;
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
trust_rstr_get_requested_unattached_reference(
        trust_rstr_t *rstr,
        const axutil_env_t *env)
{
    return rstr->requested_unattached_ref;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rstr_set_requested_unattached_reference(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        axiom_node_t *ref_node)
{
    if (ref_node) 
    {
        rstr->requested_unattached_ref = ref_node;
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN  axiom_node_t * AXIS2_CALL
trust_rstr_get_requested_proof_token(
        trust_rstr_t *rstr,
        const axutil_env_t *env)
{
    return rstr->requested_proof_token;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rstr_set_requested_proof_token(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        axiom_node_t *proof_token)
{
    if (proof_token) 
    {
        rstr->requested_proof_token = proof_token;
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN trust_entropy_t * AXIS2_CALL
trust_rstr_get_entropy(
        trust_rstr_t *rstr,
        const axutil_env_t *env)
{
    return rstr->entropy;
}

AXIS2_EXTERN  axis2_status_t AXIS2_CALL
trust_rstr_set_entropy(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        trust_entropy_t *entropy)
{
    if (entropy) 
    {
        rstr->entropy = entropy;
        return AXIS2_SUCCESS;
    }

    return AXIS2_FAILURE;
}

AXIS2_EXTERN trust_life_time_t* AXIS2_CALL
trust_rstr_get_life_time(
        trust_rstr_t *rstr,
        const axutil_env_t *env)
{
    return rstr->life_time;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rstr_set_life_time(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        trust_life_time_t *life_time)
{
    if (life_time) 
    {
        rstr->life_time = life_time;
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
trust_rstr_get_in_header(
        trust_rstr_t *rstr,
        const axutil_env_t *env)
{
    return rstr->in_header;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rstr_set_in_header(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        axis2_bool_t in_header)
{
    rstr->in_header = in_header;
    
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_rstr_get_wst_ns_uri(
	trust_rstr_t *rstr,
	const axutil_env_t *env)
{
		return rstr->wst_ns_uri;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rstr_set_wst_ns_uri(
	trust_rstr_t *rstr,
	const axutil_env_t *env,
	axis2_char_t *wst_ns_uri)
{
		if(wst_ns_uri)
		{
			rstr->wst_ns_uri = wst_ns_uri;
			return AXIS2_SUCCESS;
		}

		return AXIS2_FAILURE;
}

AXIS2_EXTERN int AXIS2_CALL
trust_rstr_get_key_size(
        trust_rstr_t *rstr,
        const axutil_env_t *env)
{
    return rstr->key_size;
}

AXIS2_EXTERN  axis2_status_t AXIS2_CALL
trust_rstr_set_key_size(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        int key_size)
{
    rstr->key_size = key_size;
    return AXIS2_SUCCESS;
}
