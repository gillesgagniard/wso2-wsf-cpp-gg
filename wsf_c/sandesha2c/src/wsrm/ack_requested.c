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
 
#include <sandesha2_ack_requested.h>
#include <axiom_soap_header.h>
#include <axiom_soap_header_block.h>
#include <sandesha2_constants.h>

/** 
 * @brief AckRequested struct impl
 *	Sandesha2 AckRequested
 */
struct sandesha2_ack_requested_t
{
	sandesha2_identifier_t *identifier;
	sandesha2_msg_number_t *msg_num;
	axis2_bool_t must_understand;
	axis2_char_t *ns_val;
};
 	
static axis2_bool_t AXIS2_CALL 
sandesha2_ack_requested_is_namespace_supported(
    const axutil_env_t *env, 
    axis2_char_t *namespace);

AXIS2_EXTERN sandesha2_ack_requested_t* AXIS2_CALL
sandesha2_ack_requested_create(
    const axutil_env_t *env,  axis2_char_t *ns_val)
{
    sandesha2_ack_requested_t *ack_requested = NULL;
    AXIS2_PARAM_CHECK(env->error, ns_val, NULL);
    if(AXIS2_FALSE == sandesha2_ack_requested_is_namespace_supported(env, 
        ns_val))
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_UNSUPPORTED_NS, 
            AXIS2_FAILURE);
        return NULL;
    }    
    ack_requested =  (sandesha2_ack_requested_t *)AXIS2_MALLOC 
        (env->allocator, sizeof(sandesha2_ack_requested_t));
	
    if(!ack_requested)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}
    ack_requested->ns_val = NULL;
    ack_requested->identifier = NULL;
    ack_requested->msg_num = NULL;
    ack_requested->must_understand = AXIS2_FALSE;
    
    ack_requested->ns_val = (axis2_char_t *)axutil_strdup(env , ns_val);
    
	return ack_requested;
}


axis2_status_t AXIS2_CALL 
sandesha2_ack_requested_free (
    sandesha2_ack_requested_t *ack_requested, 
    const axutil_env_t *env)
{
    if(ack_requested->ns_val)
    {
        AXIS2_FREE(env->allocator, ack_requested->ns_val);
        ack_requested->ns_val = NULL;
    }
    ack_requested->identifier = NULL;
    ack_requested->msg_num = NULL;
    
	AXIS2_FREE(env->allocator, ack_requested);
	return AXIS2_SUCCESS;
}

axis2_char_t* AXIS2_CALL 
sandesha2_ack_requested_get_namespace_value (
    sandesha2_ack_requested_t *ack_requested,
    const axutil_env_t *env)
{
	return ack_requested->ns_val;
}


void* AXIS2_CALL 
sandesha2_ack_requested_from_om_node(
    sandesha2_ack_requested_t *ack_requested,
    const axutil_env_t *env, 
    axiom_node_t *requested_node)
{
    axiom_element_t *requested_part = NULL;
    axiom_element_t *msg_num_part = NULL;
    axiom_node_t *msg_num_node = NULL;
    axutil_qname_t *msg_num_qname = NULL;
    
    AXIS2_PARAM_CHECK(env->error, requested_node, NULL);
    
    requested_part = axiom_node_get_data_element(requested_node, env);
    if(!requested_part)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_OM_ELEMENT,
                        AXIS2_FAILURE);
        return NULL;
    }
    ack_requested->identifier = sandesha2_identifier_create(env, 
                        ack_requested->ns_val);
    if(!ack_requested->identifier)
    {
        return NULL;
    }
    if(!sandesha2_identifier_from_om_node(ack_requested->identifier, env, 
        requested_node))
    {
        return NULL;
    }
    msg_num_qname = axutil_qname_create(env, SANDESHA2_WSRM_COMMON_MSG_NUMBER,
        ack_requested->ns_val, NULL);
    if(!msg_num_qname)
    {
        return NULL;
    }
    msg_num_part = axiom_element_get_first_child_with_qname(requested_part, env, 
        msg_num_qname, requested_node, &msg_num_node);
    if(msg_num_qname)
        axutil_qname_free(msg_num_qname, env);
    if(msg_num_part)
    {
        ack_requested->msg_num = sandesha2_msg_number_create(env, 
            ack_requested->ns_val);
        if(!ack_requested->msg_num)
        {
            return NULL;
        }
        if(!sandesha2_msg_number_from_om_node(ack_requested->msg_num, env, 
            requested_node))
        {
            return NULL;
        }
    }
    return ack_requested;
}

axiom_node_t* AXIS2_CALL 
sandesha2_ack_requested_to_om_node(
    sandesha2_ack_requested_t *ack_requested,
    const axutil_env_t *env, 
    void *om_node)
{
    axiom_namespace_t *rm_ns = NULL;
    axiom_node_t *ar_node = NULL;
    axiom_soap_header_t *soap_header = NULL;
    axiom_soap_header_block_t *ar_header_blk = NULL;
    
    AXIS2_PARAM_CHECK(env->error, om_node, NULL);
    
    soap_header = (axiom_soap_header_t*)om_node;
    if(!ack_requested->identifier)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_TO_OM_NULL_ELEMENT, 
            AXIS2_FAILURE);
        return NULL;
    }
    rm_ns = axiom_namespace_create(env, ack_requested->ns_val,
        SANDESHA2_WSRM_COMMON_NS_PREFIX_RM);
    if(!rm_ns)
    {
        return NULL;
    }
    ar_header_blk = axiom_soap_header_add_header_block(soap_header, env, 
        SANDESHA2_WSRM_COMMON_ACK_REQUESTED, rm_ns);
    axiom_soap_header_block_set_must_understand_with_bool(ar_header_blk, env,
        ack_requested->must_understand);
    ar_node = axiom_soap_header_block_get_base_node(ar_header_blk, env);
    sandesha2_identifier_to_om_node(ack_requested->identifier, env, 
        ar_node);
    if(ack_requested->msg_num)
    {
        sandesha2_msg_number_to_om_node(ack_requested->msg_num, env, 
            ar_node);
    }
    return ar_node;
}

axis2_status_t AXIS2_CALL
sandesha2_ack_requested_to_soap_envelope(
    sandesha2_ack_requested_t *ack_requested,
    const axutil_env_t *env, 
    axiom_soap_envelope_t *envelope)
{
    axiom_soap_header_t *soap_header = NULL;
    axutil_qname_t *requested_qname = NULL;
    AXIS2_PARAM_CHECK(env->error, envelope, AXIS2_FAILURE);
    soap_header = axiom_soap_envelope_get_header(envelope, env);
    /**
     * Remove if header block exists
     */
    requested_qname = axutil_qname_create(env, 
        SANDESHA2_WSRM_COMMON_ACK_REQUESTED,
        ack_requested->ns_val, NULL);
    if(!requested_qname)
    {
        return AXIS2_FAILURE;
    } 
    axiom_soap_header_remove_header_block(soap_header, env, requested_qname);
    sandesha2_ack_requested_to_om_node(ack_requested, env, soap_header);
    if(requested_qname)
        axutil_qname_free(requested_qname, env);
	return AXIS2_SUCCESS;
}

sandesha2_identifier_t * AXIS2_CALL
sandesha2_ack_requested_get_identifier(
    sandesha2_ack_requested_t *ack_requested,
    const axutil_env_t *env)
{
	return ack_requested->identifier;
}                    	

axis2_status_t AXIS2_CALL                 
sandesha2_ack_requested_set_identifier(sandesha2_ack_requested_t *ack_requested,
                    	const axutil_env_t *env, sandesha2_identifier_t *identifier)
{
 	if(ack_requested->identifier)
	{
		
		sandesha2_identifier_free(ack_requested->identifier, env);
		ack_requested->identifier = NULL;
		
	}
	ack_requested->identifier = identifier;
 	return AXIS2_SUCCESS;
}

sandesha2_msg_number_t * AXIS2_CALL                    	
sandesha2_ack_requested_get_msg_number(
    sandesha2_ack_requested_t *ack_requested,
    const axutil_env_t *env)
{
	return ack_requested->msg_num;
}

axis2_status_t AXIS2_CALL
sandesha2_ack_requested_set_msg_number(
    sandesha2_ack_requested_t *ack_requested,
    const axutil_env_t *env, 
    sandesha2_msg_number_t *msg_number)
{
 	if(ack_requested->msg_num)
	{
	    /*
		SANDESHA2_MSG_NUMBER_FREE(ack_requested->msg_num, env);
		ack_requested->msg_num = NULL;
		*/
	}
	ack_requested->msg_num = msg_number;
 	return AXIS2_SUCCESS;
}

axis2_bool_t AXIS2_CALL
sandesha2_ack_requested_is_must_understand(
    sandesha2_ack_requested_t *ack_requested,
    const axutil_env_t *env)
{
	return ack_requested->must_understand;
}
                    	
axis2_status_t AXIS2_CALL
sandesha2_ack_requested_set_must_understand(
    sandesha2_ack_requested_t *ack_requested,
    const axutil_env_t *env, 
    axis2_bool_t mu)
{
	ack_requested->must_understand = mu;
	return AXIS2_SUCCESS;
}

static axis2_bool_t AXIS2_CALL 
sandesha2_ack_requested_is_namespace_supported(
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


