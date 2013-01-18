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
 
#include <sandesha2_close_seq.h>
#include <sandesha2_constants.h>
#include <sandesha2_utils.h>
#include <axiom_soap_body.h>
/** 
 * @brief CloseSeq struct impl
 *	Sandesha2 CloseSeq
 */
struct sandesha2_close_seq_t
{
	sandesha2_identifier_t *identifier;
	sandesha2_last_msg_number_t *last_msg_number;
	axis2_char_t *ns_val;
};
                   	
static axis2_bool_t AXIS2_CALL 
sandesha2_close_seq_is_namespace_supported(
    const axutil_env_t *env, 
    axis2_char_t *namespace);

AXIS2_EXTERN sandesha2_close_seq_t* AXIS2_CALL
sandesha2_close_seq_create(
    const axutil_env_t *env,  
    axis2_char_t *ns_val)
{
    sandesha2_close_seq_t *close_seq = NULL;
    AXIS2_PARAM_CHECK(env->error, ns_val, NULL);
    
    if(!sandesha2_close_seq_is_namespace_supported(env, ns_val))
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_UNSUPPORTED_NS, AXIS2_FAILURE);
        return NULL;
    }

    close_seq =  (sandesha2_close_seq_t *)AXIS2_MALLOC(env->allocator, sizeof(sandesha2_close_seq_t));
    if(!close_seq)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}

    close_seq->ns_val = NULL;
    close_seq->identifier = NULL;
    close_seq->last_msg_number = NULL;
    
    close_seq->ns_val = (axis2_char_t *)axutil_strdup(env, ns_val);
    
	return close_seq;
}

axis2_status_t AXIS2_CALL
sandesha2_close_seq_free_void_arg(
    void *seq,
    const axutil_env_t *env)
{
    sandesha2_close_seq_t *seq_l = NULL;

    seq_l = (sandesha2_close_seq_t *) seq;
    return sandesha2_close_seq_free(seq_l, env);
}

axis2_status_t AXIS2_CALL 
sandesha2_close_seq_free (
    sandesha2_close_seq_t *close_seq, 
    const axutil_env_t *env)
{
    if(close_seq->ns_val)
    {
        AXIS2_FREE(env->allocator, close_seq->ns_val);
        close_seq->ns_val = NULL;
    }

    close_seq->identifier = NULL;
    close_seq->last_msg_number = NULL;

	AXIS2_FREE(env->allocator, close_seq);
	return AXIS2_SUCCESS;
}

axis2_char_t* AXIS2_CALL 
sandesha2_close_seq_get_namespace_value (
    sandesha2_close_seq_t *close_seq,
	const axutil_env_t *env)
{
	return close_seq->ns_val;
}

void* AXIS2_CALL 
sandesha2_close_seq_from_om_node(
    sandesha2_close_seq_t *close_seq,
    const axutil_env_t *env, 
    axiom_node_t *close_seq_node)
{
    axiom_element_t *close_seq_part = NULL;
    
    AXIS2_PARAM_CHECK(env->error, close_seq_node, NULL);
    
    close_seq_part = axiom_node_get_data_element(close_seq_node, env);
    if(!close_seq_part)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_OM_ELEMENT, AXIS2_FAILURE);
        return NULL;
    }

    close_seq->identifier = sandesha2_identifier_create(env, close_seq->ns_val); 
    if(!close_seq->identifier)
    {
        return NULL;
    }

    if(!sandesha2_identifier_from_om_node(close_seq->identifier, env, close_seq_node))
    {
        return NULL;   
    }

    close_seq->last_msg_number = sandesha2_last_msg_number_create(env, close_seq->ns_val); 
    if(!close_seq->last_msg_number)
    {
        return NULL;
    }

    if(!sandesha2_last_msg_number_from_om_node(close_seq->last_msg_number, env, close_seq_node))
    {
        return NULL;   
    }

    return close_seq;
}


axiom_node_t* AXIS2_CALL 
sandesha2_close_seq_to_om_node(
    sandesha2_close_seq_t *close_seq,
    const axutil_env_t *env, 
    void *om_node)
{
    axiom_namespace_t *rm_ns = NULL;
    axiom_element_t *cs_element = NULL;
    axiom_node_t *cs_node = NULL;
    
    AXIS2_PARAM_CHECK(env->error, om_node, NULL);

    /* identifier is a MUST element within close sequence. So we need to check it's presense */
    if(!close_seq->identifier)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_TO_OM_NULL_ELEMENT, AXIS2_FAILURE);
        return NULL;
    }

    rm_ns = axiom_namespace_create(env, close_seq->ns_val, SANDESHA2_WSRM_COMMON_NS_PREFIX_RM);
    if(!rm_ns)
    {
        return NULL;
    }

    cs_element = axiom_element_create(env, NULL, SANDESHA2_WSRM_COMMON_CLOSE_SEQ, rm_ns, &cs_node);
    if(!cs_element)
    {
        return NULL;
    }

    sandesha2_identifier_to_om_node(close_seq->identifier, env, cs_node);
    
    if(close_seq->last_msg_number)
    {
        sandesha2_last_msg_number_to_om_node(close_seq->last_msg_number, env, cs_node);
    }

    axiom_node_add_child((axiom_node_t*)om_node, env, cs_node);

    return (axiom_node_t*)om_node;
}

sandesha2_identifier_t * AXIS2_CALL
sandesha2_close_seq_get_identifier(
    sandesha2_close_seq_t *close_seq,
    const axutil_env_t *env)
{
	return close_seq->identifier;
}                    	

axis2_status_t AXIS2_CALL                 
sandesha2_close_seq_set_identifier(
    sandesha2_close_seq_t *close_seq,
    const axutil_env_t *env, 
    sandesha2_identifier_t *identifier)
{
 	if(close_seq->identifier)
	{
	    
		sandesha2_identifier_free(close_seq->identifier, env);
		close_seq->identifier = NULL;
	
	}
	close_seq->identifier = identifier;
 	return AXIS2_SUCCESS;
}

sandesha2_last_msg_number_t * AXIS2_CALL
sandesha2_close_seq_get_last_msg_number(
    sandesha2_close_seq_t *close_seq,
    const axutil_env_t *env)
{
	return close_seq->last_msg_number;
}                    	

axis2_status_t AXIS2_CALL                 
sandesha2_close_seq_set_last_msg_number(
    sandesha2_close_seq_t *close_seq,
    const axutil_env_t *env, 
    sandesha2_last_msg_number_t *last_msg_number)
{
 	if(close_seq->last_msg_number)
	{
	    
		sandesha2_last_msg_number_free(close_seq->last_msg_number, env);
		close_seq->last_msg_number = NULL;
	
	}

	close_seq->last_msg_number = last_msg_number;

 	return AXIS2_SUCCESS;
}

axis2_status_t AXIS2_CALL
sandesha2_close_seq_to_soap_envelope(
    sandesha2_close_seq_t *close_seq,
    const axutil_env_t *env, 
    axiom_soap_envelope_t *envelope)
{
    axiom_node_t *body_node = NULL;
    axutil_qname_t *close_seq_qname = NULL;
    
    AXIS2_PARAM_CHECK(env->error, envelope, AXIS2_FAILURE);
	
    /**
     * Remove if old exists
     */
    close_seq_qname = axutil_qname_create(env, SANDESHA2_WSRM_COMMON_CLOSE_SEQ, close_seq->ns_val, 
            NULL);

    if(!close_seq_qname)
    {
        return AXIS2_FAILURE;
    }

    sandesha2_utils_remove_soap_body_part(env, envelope, close_seq_qname);
    body_node = axiom_soap_body_get_base_node(axiom_soap_envelope_get_body(envelope, env), env);  
    sandesha2_close_seq_to_om_node(close_seq, env, body_node);
    if(close_seq_qname)
    {
        axutil_qname_free(close_seq_qname, env);
    }

	return AXIS2_SUCCESS;
}

static axis2_bool_t AXIS2_CALL 
sandesha2_close_seq_is_namespace_supported(
    const axutil_env_t *env, 
    axis2_char_t *namespace)
{
    if(!axutil_strcmp(namespace, SANDESHA2_SPEC_2005_02_NS_URI))
    {
        return AXIS2_FALSE;
    }

    if(!axutil_strcmp(namespace, SANDESHA2_SPEC_2007_02_NS_URI))
    {
        return AXIS2_TRUE;
    }
    return AXIS2_FALSE;
}


