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
 
#include <sandesha2_seq.h>
#include <sandesha2_constants.h>
#include <axiom_soap_header.h>
#include <axiom_soap_header_block.h>

/** 
 * @brief Sequence struct impl
 *	Sandesha2 Sequence
 */
  
struct sandesha2_seq_t
{
	sandesha2_identifier_t *identifier;
	sandesha2_msg_number_t *msg_num;
	sandesha2_last_msg_t *last_msg;
	axis2_bool_t must_understand;
	axis2_char_t *ns_val;
};

static axis2_bool_t AXIS2_CALL 
sandesha2_seq_is_namespace_supported(
    const axutil_env_t *env, 
    axis2_char_t *namespace);

AXIS2_EXTERN sandesha2_seq_t* AXIS2_CALL
sandesha2_seq_create(
    const axutil_env_t *env,  
    axis2_char_t *ns_val)
{
    sandesha2_seq_t *seq = NULL;
    AXIS2_PARAM_CHECK(env->error, ns_val, NULL);
    
    if(AXIS2_FALSE == sandesha2_seq_is_namespace_supported(env, ns_val))
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_UNSUPPORTED_NS, 
            AXIS2_FAILURE);
        return NULL;
    }    
    seq =  (sandesha2_seq_t *)AXIS2_MALLOC 
        (env->allocator, sizeof(sandesha2_seq_t));
	
    if(!seq)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}
    seq->ns_val = NULL;
    seq->identifier = NULL;
    seq->msg_num = NULL;
    seq->last_msg = NULL;
    seq->must_understand = AXIS2_TRUE;
    
    seq->ns_val = (axis2_char_t *)axutil_strdup(env, ns_val);
    
	return seq;
}

AXIS2_EXTERN sandesha2_seq_t* AXIS2_CALL
sandesha2_seq_clone(
    const axutil_env_t *env,  
    sandesha2_seq_t *sequence)
{
    sandesha2_seq_t *rm_sequence = NULL;
    AXIS2_PARAM_CHECK(env->error, sequence, NULL);
    
    rm_sequence = sandesha2_seq_create(env, sandesha2_seq_get_namespace_value (sequence, env));
	
    if(!rm_sequence)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}

    sandesha2_seq_set_identifier(rm_sequence, env, sandesha2_identifier_clone(env, 
                sandesha2_seq_get_identifier(sequence, env)));
    sandesha2_seq_set_msg_num(rm_sequence, env, sandesha2_msg_number_clone(env, 
                sandesha2_seq_get_msg_num(sequence, env)));
    sandesha2_seq_set_last_msg(rm_sequence, env, sandesha2_last_msg_clone(env, 
                sandesha2_seq_get_last_msg(sequence, env)));
    
	return rm_sequence;
}

axis2_status_t AXIS2_CALL
sandesha2_seq_free_void_arg(
    void *seq,
    const axutil_env_t *env)
{
    sandesha2_seq_t *seq_l = NULL;

    seq_l = (sandesha2_seq_t *) seq;
    return sandesha2_seq_free(seq_l, env);
}

axis2_status_t AXIS2_CALL 
sandesha2_seq_free (
    sandesha2_seq_t *seq, 
	const axutil_env_t *env)
{
    if(seq->ns_val)
    {
        AXIS2_FREE(env->allocator, seq->ns_val);
        seq->ns_val = NULL;
    }
    if(seq->identifier)
    {
        sandesha2_identifier_free(seq->identifier, env);
        seq->identifier = NULL;
    }
    if(seq->msg_num)
    {
        sandesha2_msg_number_free(seq->msg_num, env);
        seq->msg_num = NULL;
    }
    if(seq->last_msg)
    {
        sandesha2_last_msg_free(seq->last_msg, env);
        seq->last_msg = NULL;
    }
	AXIS2_FREE(env->allocator, seq);
	return AXIS2_SUCCESS;
}

axis2_char_t* AXIS2_CALL 
sandesha2_seq_get_namespace_value (
    sandesha2_seq_t *seq,
	const axutil_env_t *env)
{
	return seq->ns_val;
}


void* AXIS2_CALL 
sandesha2_seq_from_om_node(
    sandesha2_seq_t *seq,
    const axutil_env_t *env, 
    axiom_node_t *seq_node)
{
    axiom_element_t *seq_part = NULL;
    axiom_element_t *lm_part = NULL;
    axiom_node_t *lm_node = NULL;
    axutil_qname_t *lm_qname = NULL; 
    AXIS2_PARAM_CHECK(env->error, seq_node, NULL);
        
    seq_part = axiom_node_get_data_element(seq_node, env);
    if(!seq_part)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[sandesha2] Sequence element not found in the sequence node");

        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_OM_ELEMENT, AXIS2_FAILURE);
        return NULL;
    }

    seq->identifier = sandesha2_identifier_create(env, seq->ns_val);
    if(!seq->identifier)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[sandesha2] Sequence identifier not found in the sequence node");

        return NULL;
    }

    sandesha2_identifier_from_om_node(seq->identifier, env, seq_node);
    seq->msg_num= sandesha2_msg_number_create(env, seq->ns_val);
    if(!seq->msg_num)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[sandesha2] Sequence message number not found in the sequence node");

        return NULL;
    }

    sandesha2_msg_number_from_om_node(seq->msg_num, env, seq_node);
    lm_qname = axutil_qname_create(env, SANDESHA2_WSRM_COMMON_LAST_MSG, seq->ns_val, NULL);
    
    if(!lm_qname)
    {
        return NULL;
    }

    lm_part = axiom_element_get_first_child_with_qname(seq_part, env, lm_qname, seq_node, &lm_node);
    if(lm_qname)
    {
        axutil_qname_free(lm_qname, env);
    }

    if(lm_part)
    {
        seq->last_msg = sandesha2_last_msg_create(env, seq->ns_val);
        if(!seq->last_msg)
        {
            return NULL;
        }

        sandesha2_last_msg_from_om_node(seq->last_msg, env, lm_node);
    }

    return seq;
}


axiom_node_t* AXIS2_CALL 
sandesha2_seq_to_om_node(
    sandesha2_seq_t *seq,
    const axutil_env_t *env, 
    void *om_node)
{
    axiom_namespace_t *rm_ns = NULL;
    axiom_soap_header_t *soap_header = NULL;
    axiom_soap_header_block_t *seq_block = NULL;
    axiom_node_t *seq_node = NULL;
    AXIS2_PARAM_CHECK(env->error, om_node, NULL);
    soap_header = (axiom_soap_header_t*)om_node;
    if(!seq->identifier || !seq->msg_num)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_TO_OM_NULL_ELEMENT, 
            AXIS2_FAILURE);
        return NULL;
    }
    rm_ns = axiom_namespace_create(env, seq->ns_val, SANDESHA2_WSRM_COMMON_NS_PREFIX_RM);
    if(rm_ns)
    {
        seq_block = axiom_soap_header_add_header_block(soap_header, env, SANDESHA2_WSRM_COMMON_SEQ, 
                rm_ns);
        axiom_namespace_free(rm_ns, env);
    }

    if(!seq_block)
    {
        return NULL;
    }

    axiom_soap_header_block_set_must_understand_with_bool(seq_block, env, seq->must_understand);
    seq_node = axiom_soap_header_block_get_base_node(seq_block, env);
    sandesha2_identifier_to_om_node(seq->identifier, env, seq_node);
    sandesha2_msg_number_to_om_node(seq->msg_num, env, seq_node);
    if(seq->last_msg)
    {
        sandesha2_last_msg_to_om_node(seq->last_msg, env, seq_node);
    }

    return seq_node;
}

sandesha2_identifier_t * AXIS2_CALL
sandesha2_seq_get_identifier(
    sandesha2_seq_t *seq,
    const axutil_env_t *env)
{
	return seq->identifier;
}                    	

axis2_status_t AXIS2_CALL                 
sandesha2_seq_set_identifier(
    sandesha2_seq_t *seq,
    const axutil_env_t *env, 
    sandesha2_identifier_t *identifier)
{
	seq->identifier = identifier;
 	return AXIS2_SUCCESS;
}

sandesha2_msg_number_t * AXIS2_CALL
sandesha2_seq_get_msg_num(
    sandesha2_seq_t *seq,
    const axutil_env_t *env)
{
	return seq->msg_num;
}                    	

axis2_status_t AXIS2_CALL                 
sandesha2_seq_set_msg_num(
    sandesha2_seq_t *seq,
    const axutil_env_t *env, sandesha2_msg_number_t *msg_num)
{
	seq->msg_num = msg_num;
 	return AXIS2_SUCCESS;
}

sandesha2_last_msg_t * AXIS2_CALL
sandesha2_seq_get_last_msg(
    sandesha2_seq_t *seq,
    const axutil_env_t *env)
{
	return seq->last_msg;
}                    	

axis2_status_t AXIS2_CALL                 
sandesha2_seq_set_last_msg(
    sandesha2_seq_t *seq,
    const axutil_env_t *env, sandesha2_last_msg_t *last_msg)
{
	seq->last_msg = last_msg;
 	return AXIS2_SUCCESS;
}

axis2_bool_t AXIS2_CALL
sandesha2_seq_is_must_understand(
    sandesha2_seq_t *seq,
    const axutil_env_t *env)
{
	return seq->must_understand;
}                    	

axis2_status_t AXIS2_CALL                 
sandesha2_seq_set_must_understand(
    sandesha2_seq_t *seq,
    const axutil_env_t *env, axis2_bool_t mu)
{
	seq->must_understand = mu;
 	return AXIS2_SUCCESS;
}


axis2_status_t AXIS2_CALL
sandesha2_seq_to_soap_envelope(
    sandesha2_seq_t *seq,
    const axutil_env_t *env, 
    axiom_soap_envelope_t *envelope)
{
	axiom_soap_header_t *soap_header = NULL;
    axutil_qname_t *seq_qname = NULL;

    AXIS2_PARAM_CHECK(env->error, envelope, AXIS2_FAILURE);
    soap_header = axiom_soap_envelope_get_header(envelope, env);

    /**
     * Remove if old exists
     */
    seq_qname = axutil_qname_create(env, SANDESHA2_WSRM_COMMON_SEQ, seq->ns_val, NULL);
    if(!seq_qname)
    {
        return AXIS2_FAILURE;
    }
    axiom_soap_header_remove_header_block(soap_header, env, seq_qname);

    if(seq_qname)
    {
        axutil_qname_free(seq_qname, env);
    }
    
    sandesha2_seq_to_om_node((sandesha2_seq_t*)seq, env, soap_header);

	return AXIS2_SUCCESS;
}

static axis2_bool_t AXIS2_CALL 
sandesha2_seq_is_namespace_supported(
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

