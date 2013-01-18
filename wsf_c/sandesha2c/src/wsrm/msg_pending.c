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
 
#include <sandesha2_msg_pending.h>
#include <sandesha2_constants.h>
#include <axiom_soap_header.h>
#include <axiom_soap_header_block.h>
#include <axis2_const.h>

/** 
 * @brief Message Pending struct impl
 *	Sandesha2 Message Pending
 */
  
struct sandesha2_msg_pending_t
{
	axis2_bool_t pending;
	axis2_char_t *ns_val;
};

static axis2_bool_t AXIS2_CALL 
sandesha2_msg_pending_is_namespace_supported(
    const axutil_env_t *env, 
    axis2_char_t *namespace);

AXIS2_EXTERN sandesha2_msg_pending_t* AXIS2_CALL
sandesha2_msg_pending_create(
    const axutil_env_t *env,  
    axis2_char_t *ns_val)
{
    sandesha2_msg_pending_t *msg_pending = NULL;
    
    if(AXIS2_FALSE == sandesha2_msg_pending_is_namespace_supported(env, ns_val))
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_UNSUPPORTED_NS, 
            AXIS2_FAILURE);
        return NULL;
    }    
    msg_pending =  (sandesha2_msg_pending_t *)AXIS2_MALLOC 
        (env->allocator, sizeof(sandesha2_msg_pending_t));
	
    if(!msg_pending)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}
    msg_pending->ns_val = (axis2_char_t *)axutil_strdup(env, ns_val);
    msg_pending->pending = AXIS2_TRUE;
    
	return msg_pending;
}

axis2_status_t AXIS2_CALL
sandesha2_msg_pending_free_void_arg(
    void *msg_pending,
    const axutil_env_t *env)
{
    sandesha2_msg_pending_t *msg_pending_l = NULL;

    msg_pending_l = (sandesha2_msg_pending_t *) msg_pending;
    return sandesha2_msg_pending_free(msg_pending_l, env);
}

axis2_status_t AXIS2_CALL 
sandesha2_msg_pending_free (
    sandesha2_msg_pending_t *msg_pending, 
	const axutil_env_t *env)
{
    if(msg_pending->ns_val)
    {
        AXIS2_FREE(env->allocator, msg_pending->ns_val);
        msg_pending->ns_val = NULL;
    }
    
	AXIS2_FREE(env->allocator, msg_pending);
	return AXIS2_SUCCESS;
}

axis2_char_t* AXIS2_CALL 
sandesha2_msg_pending_get_namespace_value (
    sandesha2_msg_pending_t *msg_pending,
	const axutil_env_t *env)
{
	return msg_pending->ns_val;
}

void* AXIS2_CALL 
sandesha2_msg_pending_from_om_node(
    sandesha2_msg_pending_t *msg_pending,
    const axutil_env_t *env, 
    axiom_node_t *msg_pending_node)
{
    axiom_element_t *msg_pending_element = NULL;
    axutil_qname_t *pending_qname = NULL; 
    axis2_char_t *value = NULL;
    axiom_attribute_t *pending_attr = NULL;
    axis2_bool_t pending = AXIS2_FALSE;
    
    AXIS2_PARAM_CHECK(env->error, msg_pending_node, NULL);
    
    msg_pending_element = axiom_node_get_data_element(msg_pending_node, env);
    if(!msg_pending_element)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_OM_ELEMENT,
             AXIS2_FAILURE);
        return NULL;
    }
    pending_qname = axutil_qname_create(env, SANDESHA2_WSRM_COMMON_PENDING,
        NULL, NULL);
    if(!pending_qname)
    {
        return NULL;
    }
    pending_attr = axiom_element_get_attribute(msg_pending_element, env, 
        pending_qname);
    if(pending_qname)
        axutil_qname_free(pending_qname, env);
    if(!pending_attr)
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "MessagePending header must" \
                "have an attribute named 'pending'");
        AXIS2_ERROR_SET(env->error, 
            SANDESHA2_ERROR_PENDING_HEADER_MUST_HAVE_ATTRIBUTE_PENDING, 
            AXIS2_FAILURE);
    }
    value = axiom_attribute_get_value(pending_attr, env);
    if(0 == axutil_strcmp(value, AXIS2_VALUE_TRUE))
        pending = AXIS2_TRUE;
    if(0 == axutil_strcmp(value, AXIS2_VALUE_FALSE))
        pending = AXIS2_FALSE;
    else
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
            "Attribute 'pending' must have value 'true' or 'false'");
        AXIS2_ERROR_SET(env->error, 
            SANDESHA2_ERROR_ATTRIBUTE_PENDING_MUST_HAVE_VALUE_TRUE_OR_FALSE, 
            AXIS2_FAILURE);
        
    }
    return msg_pending_node;
}

axiom_node_t* AXIS2_CALL 
sandesha2_msg_pending_to_om_node(
    sandesha2_msg_pending_t *msg_pending,
    const axutil_env_t *env, 
    void *header_node)
{
    axiom_namespace_t *rm_ns = NULL;
    axiom_soap_header_t *soap_header = NULL;
    axiom_soap_header_block_t *msg_pending_block = NULL;
    axiom_node_t *msg_pending_node = NULL;
    axiom_element_t *msg_pending_element = NULL;
    axiom_attribute_t *pending_attr = NULL;
    axis2_char_t *attr_value = NULL;
    axis2_bool_t pending = AXIS2_FALSE;
    
    AXIS2_PARAM_CHECK(env->error, header_node, NULL);
    
    soap_header = (axiom_soap_header_t*)header_node;
    rm_ns = axiom_namespace_create(env, msg_pending->ns_val,
        SANDESHA2_WSRM_COMMON_NS_PREFIX_RM);
    if(!rm_ns)
    {
        return NULL;
    }
    msg_pending_block = axiom_soap_header_add_header_block(soap_header, env, 
        SANDESHA2_WSRM_COMMON_MESSAGE_PENDING, rm_ns);
    if(!msg_pending_block)
    {
        return NULL;
    }
    msg_pending_node = axiom_soap_header_block_get_base_node(msg_pending_block, 
        env);
    msg_pending_element = axiom_node_get_data_element(msg_pending_node, env);
    if(pending)
        attr_value = AXIS2_VALUE_TRUE;
    else if(!pending)
        attr_value = AXIS2_VALUE_FALSE;
    pending_attr = axiom_attribute_create(env, 
        SANDESHA2_WSRM_COMMON_PENDING, attr_value, NULL);
    axiom_element_add_attribute(msg_pending_element, env, pending_attr, 
        msg_pending_node);
    return header_node;
}

axis2_bool_t AXIS2_CALL
sandesha2_msg_pending_is_pending(
    sandesha2_msg_pending_t *msg_pending,
    const axutil_env_t *env)
{
	return msg_pending->pending;
}                    	

axis2_status_t AXIS2_CALL                 
sandesha2_msg_pending_set_pending(
    sandesha2_msg_pending_t *msg_pending,
    const axutil_env_t *env, 
    axis2_bool_t pending)
{
	msg_pending->pending = pending;
 	return AXIS2_SUCCESS;
}

axis2_status_t AXIS2_CALL
sandesha2_msg_pending_to_soap_envelope(
    sandesha2_msg_pending_t *msg_pending,
    const axutil_env_t *env, 
    axiom_soap_envelope_t *envelope)
{
	axiom_soap_header_t *soap_header = NULL;
    axutil_qname_t *msg_pending_qname = NULL;
    
    AXIS2_PARAM_CHECK(env->error, envelope, AXIS2_FAILURE);
	
    soap_header = axiom_soap_envelope_get_header(envelope, env);
    /**
     * Remove if already exists
     */
    msg_pending_qname = axutil_qname_create(env, 
            SANDESHA2_WSRM_COMMON_MESSAGE_PENDING, msg_pending->ns_val, 
            NULL);
    if(!msg_pending_qname)
    {
        return AXIS2_FAILURE;
    }
    axiom_soap_header_remove_header_block(soap_header, env, msg_pending_qname);
    sandesha2_msg_pending_to_om_node((sandesha2_msg_pending_t*)msg_pending, 
        env, soap_header);
    if(msg_pending_qname)
        axutil_qname_free(msg_pending_qname, env);
	return AXIS2_SUCCESS;
}

static axis2_bool_t AXIS2_CALL 
sandesha2_msg_pending_is_namespace_supported(
    const axutil_env_t *env, 
    axis2_char_t *namespace)
{
    if(0 == axutil_strcmp(namespace, SANDESHA2_SPEC_2005_02_NS_URI))
    {
        return AXIS2_FALSE;
    }
    if(0 == axutil_strcmp(namespace, SANDESHA2_SPEC_2007_02_NS_URI))
    {
        return AXIS2_TRUE;
    }
    return AXIS2_FALSE;
}


