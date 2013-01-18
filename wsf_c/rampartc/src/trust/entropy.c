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

#include <trust_entropy.h>

struct trust_entropy
{
    /* Boolean to specify the type of the entropy. Entropy can be either binary secret
     * or encrypted key
     */
    axis2_bool_t bin_sec;
    
    axis2_char_t *binary_secret;
    
    axis2_char_t *encrypted_key;
    
    trust_bin_sec_type_t binsec_type;
    
    axiom_node_t *other;
    
    axis2_char_t *ns_uri;
       
};

AXIS2_EXTERN trust_entropy_t * AXIS2_CALL
trust_entropy_create(
        const axutil_env_t *env)
{
    trust_entropy_t *entropy = NULL;
    
    entropy = (trust_entropy_t*)AXIS2_MALLOC(env->allocator, sizeof(trust_entropy_t));
    
    entropy->bin_sec = AXIS2_TRUE;
    entropy->binary_secret = NULL;
    entropy->binsec_type = SYMMETRIC;
    entropy->encrypted_key = NULL;
    
    return entropy;   
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_entropy_free(
        trust_entropy_t *entropy,
        const axutil_env_t *env)
{
    
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_entropy_deserialize(
        trust_entropy_t *entropy,
        const axutil_env_t *env,
        axiom_node_t *entropy_node)
{
    axutil_qname_t *bin_sec_qname = NULL;
    axiom_element_t *entropy_ele = NULL;
    axiom_node_t *bin_sec_node = NULL;
    axiom_element_t *bin_sec_ele = NULL;
    axis2_char_t *bin_sec = NULL;
    axis2_char_t *binsec_type = NULL;
    axiom_node_t *other_node = NULL;
    axiom_element_t *other_ele = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    
    entropy_ele = axiom_node_get_data_element(entropy_node, env);
    
    if(entropy_ele)
    {
        bin_sec_qname = axutil_qname_create(env, TRUST_BINARY_SECRET, entropy->ns_uri, TRUST_WST);
        if(!bin_sec_qname)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] BinarySecret Qname creation failed.");
            return AXIS2_FAILURE;
        }
        
        bin_sec_ele = axiom_element_get_first_child_with_qname(entropy_ele, env, bin_sec_qname, entropy_node, &bin_sec_node);
        if(bin_sec_ele)
        {
            bin_sec = axiom_element_get_text(bin_sec_ele, env, bin_sec_node);
            status = trust_entropy_set_binary_secret(entropy, env, bin_sec);            
            
            binsec_type = axiom_element_get_attribute_value_by_name(bin_sec_ele, env, TRUST_BIN_SEC_TYPE_ATTR);
            if(binsec_type)
            {
                entropy->binsec_type =  trust_entropy_get_bin_sec_type_from_str(binsec_type, env); /* TODO*/
                if(status == AXIS2_SUCCESS)
                {
                    return AXIS2_SUCCESS;
                }
            }
        }
        else
        {
            other_ele = axiom_element_get_first_element(entropy_ele, env, entropy_node, &other_node);
            if(other_ele)
            {
                entropy->bin_sec = AXIS2_FALSE;
                entropy->other = other_node;
                
                return AXIS2_SUCCESS;
            }
        }
            
    }
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
trust_entropy_serialize(
        trust_entropy_t *entropy,
        const axutil_env_t *env,
        axiom_node_t *parent)
{
    axiom_node_t *entropy_node = NULL;
    axiom_node_t *bin_sec_node = NULL;
    axis2_char_t *bin_sec_type = NULL;
    
    entropy_node = (axiom_node_t*)trust_util_create_entropy_element(env, entropy->ns_uri, parent);
    
    if(entropy_node)
    {
        if(entropy->bin_sec == AXIS2_TRUE)
        {
            bin_sec_type = trust_entropy_get_str_for_bin_sec_type(entropy->binsec_type, env);
            bin_sec_node = (axiom_node_t*)trust_util_create_binary_secret_element(env, entropy->ns_uri, entropy_node, entropy->binary_secret, bin_sec_type);
            if(bin_sec_node)
            {
                return entropy_node;
            }
        }
        else
        {
            if(AXIS2_SUCCESS == axiom_node_add_child(entropy_node, env, entropy->other))
            {
                return entropy_node;                
            }
        }
    }
    
    return NULL;    
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_entropy_get_binary_secret(
        trust_entropy_t *entropy,
        const axutil_env_t *env)
{
    if(entropy->bin_sec == AXIS2_TRUE)
    {
        return entropy->binary_secret;        
    }
    
    return NULL;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_entropy_set_binary_secret(
        trust_entropy_t *entropy,
        const axutil_env_t *env,
        axis2_char_t *bin_sec)
{
    if(bin_sec)
    {
        entropy->binary_secret = bin_sec;
        entropy->bin_sec = AXIS2_TRUE;
        
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FALSE;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_entropy_set_binary_secret_type(
        trust_entropy_t *entropy,
        const axutil_env_t *env,
        trust_bin_sec_type_t binsec_type)
{
    entropy->binsec_type = binsec_type;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
trust_entropy_get_other(
        trust_entropy_t *entropy,
        const axutil_env_t *env)
{
    if(entropy->bin_sec == AXIS2_FALSE)
    {
        return entropy->other;
    }
    
    return NULL;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_entropy_set_other(
        trust_entropy_t *entropy,
        const axutil_env_t *env,
        axiom_node_t *other_node)
{
    if(other_node)
    {
        entropy->bin_sec = AXIS2_FALSE;
        entropy->other = other_node;
        
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_entropy_get_ns_uri(
        trust_entropy_t *entropy,
        const axutil_env_t *env)
{
    return entropy->ns_uri;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_entropy_set_ns_uri(
        trust_entropy_t *entropy,
        const axutil_env_t *env,
        axis2_char_t *ns_uri)
{
    if(ns_uri)
    {
        entropy->ns_uri = ns_uri;
        
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN trust_bin_sec_type_t AXIS2_CALL
trust_entropy_get_bin_sec_type_from_str(
        axis2_char_t *str,
        const axutil_env_t *env)
{
    if(!axutil_strcmp(str, BIN_SEC_ASSYM))
    {
        return ASYMMETRIC;
    }
    else if(!axutil_strcmp(str, BIN_SEC_SYM))
    {
        return SYMMETRIC;
    }
    else if(!axutil_strcmp(str, BIN_SEC_NONCE))
    {
        return NONCE;
    }
    
    return BIN_SEC_TYPE_ERROR;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_entropy_get_str_for_bin_sec_type(
        trust_bin_sec_type_t type,
        const axutil_env_t *env)
{
    if(type == ASYMMETRIC)
    {
        return axutil_strdup(env, BIN_SEC_ASSYM);
    }
    else if (type == SYMMETRIC)
    {
        return axutil_strdup(env, BIN_SEC_SYM);
    }
    else if (type == NONCE)
    {
        return axutil_strdup(env, BIN_SEC_NONCE);
    }
    
    return NULL;
}
