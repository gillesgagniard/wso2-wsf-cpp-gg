/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
#include <sandesha2_create_seq.h>
#include <sandesha2_constants.h>
#include <axiom_soap_body.h>
#include <sandesha2_utils.h>
/** 
 * @brief CreateSeq struct impl
 *	Sandesha2 CreateSeq
 */
  
struct sandesha2_create_seq_t
{
	sandesha2_acks_to_t *acks_to;
	sandesha2_expires_t *expires;
	sandesha2_seq_offer_t *seq_offer;
	axis2_char_t *rm_ns_val;
	axis2_char_t *addr_ns_val;
};

static axis2_bool_t AXIS2_CALL 
sandesha2_create_seq_is_namespace_supported(
    const axutil_env_t *env, 
    axis2_char_t *namespace);
                    	
AXIS2_EXTERN sandesha2_create_seq_t* AXIS2_CALL
sandesha2_create_seq_create(
    const axutil_env_t *env,  
    axis2_char_t *addr_ns_val,
    axis2_char_t *rm_ns_val)
{
    sandesha2_create_seq_t *create_seq = NULL;
    AXIS2_PARAM_CHECK(env->error, rm_ns_val, NULL);
	AXIS2_PARAM_CHECK(env->error, addr_ns_val, NULL);
    
    if(AXIS2_FALSE == sandesha2_create_seq_is_namespace_supported(env, rm_ns_val))
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
            "[sandesha2]Unsupported namespace :%s", rm_ns_val);
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_UNSUPPORTED_NS, 
            AXIS2_FAILURE);
        return NULL;
    }    
    create_seq =  (sandesha2_create_seq_t *)AXIS2_MALLOC 
        (env->allocator, sizeof(sandesha2_create_seq_t));
	
    if(!create_seq)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}
    create_seq->rm_ns_val = (axis2_char_t*)axutil_strdup(env, rm_ns_val);
    create_seq->addr_ns_val = (axis2_char_t*)axutil_strdup(env, addr_ns_val);
    create_seq->acks_to = NULL;
    create_seq->expires = NULL;
    create_seq->seq_offer = NULL;
    
	return create_seq;
}

axis2_status_t AXIS2_CALL
sandesha2_create_seq_free_void_arg(
    void *create_seq,
    const axutil_env_t *env)
{
    sandesha2_create_seq_t *create_seq_l = NULL;

    create_seq_l = (sandesha2_create_seq_t *) create_seq;
    return sandesha2_create_seq_free(create_seq_l, env);
}

axis2_status_t AXIS2_CALL 
sandesha2_create_seq_free(
    sandesha2_create_seq_t *create_seq, 
    const axutil_env_t *env)
{
    if(create_seq->rm_ns_val)
    {
        AXIS2_FREE(env->allocator, create_seq->rm_ns_val);
        create_seq->rm_ns_val = NULL;
    }
    if(create_seq->addr_ns_val)
    {
        AXIS2_FREE(env->allocator, create_seq->addr_ns_val);
        create_seq->addr_ns_val = NULL;
    }

 	if(create_seq->acks_to)
	{
		sandesha2_acks_to_free(create_seq->acks_to, env);
		create_seq->acks_to = NULL;
	}

    create_seq->expires = NULL;

    if(create_seq->seq_offer)
    {
        sandesha2_seq_offer_free(create_seq->seq_offer, env);
        create_seq->seq_offer = NULL;
    }

	AXIS2_FREE(env->allocator, create_seq);

	return AXIS2_SUCCESS;
}

axis2_char_t* AXIS2_CALL 
sandesha2_create_seq_get_namespace_value (
    sandesha2_create_seq_t *create_seq,
	const axutil_env_t *env)
{
	return create_seq->rm_ns_val;
}


void* AXIS2_CALL 
sandesha2_create_seq_from_om_node(
    sandesha2_create_seq_t *create_seq,
    const axutil_env_t *env, 
    axiom_node_t *seq_node)
{
    axiom_element_t *seq_part = NULL;
    axiom_element_t *offer_part = NULL;
    axiom_element_t *expires_part = NULL;
    axiom_node_t *offer_node = NULL;
    axiom_node_t *expires_node = NULL;
    axutil_qname_t *offer_qname = NULL;
    axutil_qname_t *expires_qname = NULL;
    
    AXIS2_PARAM_CHECK(env->error, seq_node, NULL);
    
    seq_part = axiom_node_get_data_element(seq_node, env);
    if(!seq_part)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_OM_ELEMENT,
            AXIS2_FAILURE);
        return NULL;
    }
    create_seq->acks_to = sandesha2_acks_to_create(env, NULL, 
        create_seq->rm_ns_val, create_seq->addr_ns_val);
    if(!create_seq->acks_to)
    {
        return NULL;
    }
    if(!sandesha2_acks_to_from_om_node(create_seq->acks_to, env, seq_node))
    {
        return NULL;
    }
    offer_qname = axutil_qname_create(env, SANDESHA2_WSRM_COMMON_SEQ_OFFER, 
        create_seq->rm_ns_val, NULL);
    if(!offer_qname)
    {
        return NULL;
    }
    offer_part = axiom_element_get_first_child_with_qname(seq_part, env, 
        offer_qname, seq_node, &offer_node);
    if(offer_qname)
        axutil_qname_free(offer_qname, env);
    if(offer_part)
    {
        create_seq->seq_offer = sandesha2_seq_offer_create(env, 
            create_seq->rm_ns_val, create_seq->addr_ns_val);  
        if(!create_seq->seq_offer)
        {
            return NULL;
        }
        if(!sandesha2_seq_offer_from_om_node(create_seq->seq_offer, env, 
            seq_node))
        {
            return NULL;
        } 
    }
    expires_qname = axutil_qname_create(env, SANDESHA2_WSRM_COMMON_EXPIRES, 
        create_seq->rm_ns_val, NULL);
    if(!expires_qname)
    {
        return NULL;
    }
    expires_part = axiom_element_get_first_child_with_qname(seq_part, env, 
        expires_qname, seq_node, &expires_node);
    if(expires_qname)
        axutil_qname_free(expires_qname, env);
    if(expires_part)
    {
        create_seq->expires = sandesha2_expires_create(env, 
            create_seq->rm_ns_val);
        if(!create_seq->expires)
        {
            return NULL;
        }
        if(!sandesha2_expires_from_om_node(create_seq->expires, env, seq_node))
        {
            return NULL;
        }
    }
    return create_seq;
}

axiom_node_t* AXIS2_CALL 
sandesha2_create_seq_to_om_node(
    sandesha2_create_seq_t *create_seq,
    const axutil_env_t *env, 
    void *om_node)
{
    axiom_namespace_t *rm_ns = NULL;
    axiom_element_t *cs_element = NULL;
    axiom_node_t *cs_node = NULL;
    
    AXIS2_PARAM_CHECK(env->error, om_node, NULL);
    
    if(!create_seq->acks_to)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_TO_OM_NULL_ELEMENT, 
            AXIS2_FAILURE);
        return NULL;
    }
    rm_ns = axiom_namespace_create(env, create_seq->rm_ns_val,
        SANDESHA2_WSRM_COMMON_NS_PREFIX_RM);
    if(!rm_ns)
    {
        return NULL;
    }
    cs_element = axiom_element_create(env, NULL, 
        SANDESHA2_WSRM_COMMON_CREATE_SEQ, rm_ns, &cs_node);
    if(!cs_element)
    {
        return NULL;
    }
    sandesha2_acks_to_to_om_node(create_seq->acks_to, env, cs_node);
    if(create_seq->expires)
    {
        sandesha2_expires_to_om_node(create_seq->expires, env, cs_node);
    }
    if(create_seq->seq_offer)
    {
        sandesha2_seq_offer_to_om_node(create_seq->seq_offer, env, cs_node);
    }
    axiom_node_add_child((axiom_node_t*)om_node, env, cs_node);
    return (axiom_node_t*)om_node;
}

sandesha2_acks_to_t * AXIS2_CALL
sandesha2_create_seq_get_acks_to(
    sandesha2_create_seq_t *create_seq,
    const axutil_env_t *env)
{
	return create_seq->acks_to;
}                    	

axis2_status_t AXIS2_CALL                 
sandesha2_create_seq_set_acks_to(
    sandesha2_create_seq_t *create_seq,
    const axutil_env_t *env, 
    sandesha2_acks_to_t *acks_to)
{
 	if(create_seq->acks_to)
	{
		sandesha2_acks_to_free(create_seq->acks_to, env);
		create_seq->acks_to = NULL;
	}
	create_seq->acks_to = acks_to;
 	return AXIS2_SUCCESS;
}

sandesha2_seq_offer_t * AXIS2_CALL
sandesha2_create_seq_get_seq_offer(
    sandesha2_create_seq_t *create_seq,
    const axutil_env_t *env)
{
	return create_seq->seq_offer;
}                    	

axis2_status_t AXIS2_CALL                 
sandesha2_create_seq_set_seq_offer(
    sandesha2_create_seq_t *create_seq,
    const axutil_env_t *env, 
    sandesha2_seq_offer_t *seq_offer)
{
 	if(create_seq->seq_offer)
	{
		sandesha2_seq_offer_free(create_seq->seq_offer, env);
		create_seq->seq_offer = NULL;
	}
	create_seq->seq_offer = seq_offer;
 	return AXIS2_SUCCESS;
}

axis2_status_t AXIS2_CALL
sandesha2_create_seq_to_soap_envelope(
    sandesha2_create_seq_t *create_seq,
    const axutil_env_t *env, 
    axiom_soap_envelope_t *envelope)
{
    axiom_node_t *body_node = NULL;
    axutil_qname_t *create_seq_qname = NULL;
    AXIS2_PARAM_CHECK(env->error, envelope, AXIS2_FAILURE);
    /**
     * Remove if old exists
     */
    create_seq_qname = axutil_qname_create(env, 
        SANDESHA2_WSRM_COMMON_CREATE_SEQ, 
        create_seq->rm_ns_val, NULL);
    if(!create_seq_qname)
    {
        return AXIS2_FAILURE;
    }
    sandesha2_utils_remove_soap_body_part(env, envelope, create_seq_qname);
    body_node = axiom_soap_body_get_base_node(axiom_soap_envelope_get_body(
        envelope, env), env);
    sandesha2_create_seq_to_om_node((sandesha2_create_seq_t*)create_seq, 
        env, body_node);
    if(create_seq_qname)
        axutil_qname_free(create_seq_qname, env);
	return AXIS2_SUCCESS;
}

static axis2_bool_t AXIS2_CALL 
sandesha2_create_seq_is_namespace_supported(
    const axutil_env_t *env, 
    axis2_char_t *namespace)
{
    if(0 == axutil_strcmp(namespace, SANDESHA2_SPEC_2005_02_NS_URI))
    {
        return AXIS2_TRUE;
    }
    if(0 == axutil_strcmp(namespace, SANDESHA2_SPEC_2007_02_NS_URI))
    {
        return AXIS2_TRUE;
    }
    return AXIS2_FALSE;
}

