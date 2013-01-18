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
 
#include <sandesha2_terminate_seq_res.h>
#include <sandesha2_constants.h>
#include <axiom_soap_body.h>
#include <sandesha2_utils.h>

/** 
 * @brief TerminateSeqResponse struct impl
 *	Sandesha2 TerminateSeqResponse
 */
struct sandesha2_terminate_seq_res_t
{
	sandesha2_identifier_t *identifier;
	axis2_char_t *ns_val;
};
                   	
static axis2_bool_t AXIS2_CALL 
sandesha2_terminate_seq_res_is_namespace_supported(
    const axutil_env_t *env, 
    axis2_char_t *namespace);

AXIS2_EXTERN sandesha2_terminate_seq_res_t* AXIS2_CALL
sandesha2_terminate_seq_res_create(
    const axutil_env_t *env,  
    axis2_char_t *ns_val)
{
    sandesha2_terminate_seq_res_t *terminate_seq_res = NULL;
    AXIS2_PARAM_CHECK(env->error, ns_val, NULL);
    
    if(AXIS2_FALSE == sandesha2_terminate_seq_res_is_namespace_supported(env, ns_val))
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_UNSUPPORTED_NS, 
            AXIS2_FAILURE);
        return NULL;
    }    
    terminate_seq_res =  (sandesha2_terminate_seq_res_t *)AXIS2_MALLOC 
        (env->allocator, sizeof(sandesha2_terminate_seq_res_t));
	
    if(!terminate_seq_res)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}
    terminate_seq_res->ns_val = NULL;
    terminate_seq_res->identifier = NULL;
    
    terminate_seq_res->ns_val = (axis2_char_t *)axutil_strdup(env, ns_val);
    
	return terminate_seq_res;
}

axis2_status_t AXIS2_CALL
sandesha2_terminate_seq_res_free_void_arg(
    void *seq,
    const axutil_env_t *env)
{
    sandesha2_terminate_seq_res_t *seq_l = NULL;

    seq_l = (sandesha2_terminate_seq_res_t *) seq;
    return sandesha2_terminate_seq_res_free(seq_l, env);
}

axis2_status_t AXIS2_CALL 
sandesha2_terminate_seq_res_free (
    sandesha2_terminate_seq_res_t *terminate_seq_res, 
    const axutil_env_t *env)
{
    if(terminate_seq_res->ns_val)
    {
        AXIS2_FREE(env->allocator, terminate_seq_res->ns_val);
        terminate_seq_res->ns_val = NULL;
    }
    terminate_seq_res->identifier = NULL;
	AXIS2_FREE(env->allocator, terminate_seq_res);
	return AXIS2_SUCCESS;
}

axis2_char_t* AXIS2_CALL 
sandesha2_terminate_seq_res_get_namespace_value (
    sandesha2_terminate_seq_res_t *terminate_seq_res,
    const axutil_env_t *env)
{
	return terminate_seq_res->ns_val;
}


void* AXIS2_CALL 
sandesha2_terminate_seq_res_from_om_node(
    sandesha2_terminate_seq_res_t *terminate_seq_res,
    const axutil_env_t *env, 
    axiom_node_t *tsr_node)
{
    axiom_element_t *tsr_part = NULL;
    AXIS2_PARAM_CHECK(env->error, tsr_node, NULL);
    tsr_part = axiom_node_get_data_element(tsr_node, env);
    if(!tsr_part)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_OM_ELEMENT,
            AXIS2_FAILURE);
        return NULL;
    }
    terminate_seq_res->identifier = sandesha2_identifier_create(env,
        terminate_seq_res->ns_val);
    if(!terminate_seq_res->identifier)
    {
        return NULL;
    }
    sandesha2_identifier_from_om_node(terminate_seq_res->identifier, env, 
        tsr_node);
    return terminate_seq_res;
}


axiom_node_t* AXIS2_CALL 
sandesha2_terminate_seq_res_to_om_node(
    sandesha2_terminate_seq_res_t *terminate_seq_res,
    const axutil_env_t *env, 
    void *om_node)
{
    axiom_namespace_t *rm_ns = NULL;
    axiom_element_t *tsr_element = NULL;
    axiom_node_t *tsr_node = NULL;
    
    AXIS2_PARAM_CHECK(env->error, om_node, NULL);
    
    if(!terminate_seq_res->identifier)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_TO_OM_NULL_ELEMENT, 
            AXIS2_FAILURE);
        return NULL;
    }
    rm_ns = axiom_namespace_create(env, terminate_seq_res->ns_val,
        SANDESHA2_WSRM_COMMON_NS_PREFIX_RM);
    if(!rm_ns)
    {
        return NULL;
    }
    tsr_element = axiom_element_create(env, NULL, 
        SANDESHA2_WSRM_COMMON_TERMINATE_SEQ_RESPONSE, rm_ns, &tsr_node);
    if(!tsr_element)
    {
        return NULL;
    }
    sandesha2_identifier_to_om_node(terminate_seq_res->identifier, env, 
        tsr_node);
    axiom_node_add_child((axiom_node_t*)om_node, env, tsr_node);
    return (axiom_node_t*)om_node;
}

sandesha2_identifier_t * AXIS2_CALL
sandesha2_terminate_seq_res_get_identifier(
    sandesha2_terminate_seq_res_t *terminate_seq_res,
    const axutil_env_t *env)
{
	return terminate_seq_res->identifier;
}                    	

axis2_status_t AXIS2_CALL                 
sandesha2_terminate_seq_res_set_identifier(
    sandesha2_terminate_seq_res_t *terminate_seq_res,
    const axutil_env_t *env, 
    sandesha2_identifier_t *identifier)
{
 	if(terminate_seq_res->identifier)
	{
		sandesha2_identifier_free(terminate_seq_res->identifier, env);
		terminate_seq_res->identifier = NULL;
	}

	terminate_seq_res->identifier = identifier;
 	return AXIS2_SUCCESS;
}

axis2_status_t AXIS2_CALL
sandesha2_terminate_seq_res_to_soap_envelope(
    sandesha2_terminate_seq_res_t *terminate_seq_res,
    const axutil_env_t *env, 
    axiom_soap_envelope_t *envelope)
{
    axutil_qname_t *tsr_qname = NULL;
    axiom_node_t *body_node = NULL;
    
    AXIS2_PARAM_CHECK(env->error, envelope, AXIS2_FAILURE);
	
    /**
     * Remove if old exists
     */
    tsr_qname = axutil_qname_create(env, 
        SANDESHA2_WSRM_COMMON_TERMINATE_SEQ_RESPONSE, 
        terminate_seq_res->ns_val, NULL);
    if(!tsr_qname)
    {
        return AXIS2_FAILURE;
    }
    sandesha2_utils_remove_soap_body_part(env, envelope, tsr_qname);
    body_node = axiom_soap_body_get_base_node(axiom_soap_envelope_get_body(
                        envelope, env), env);  
    sandesha2_terminate_seq_res_to_om_node((sandesha2_terminate_seq_res_t*)
                        terminate_seq_res, env, body_node);
    if(tsr_qname)
        axutil_qname_free(tsr_qname, env);
	return AXIS2_SUCCESS;
}

static axis2_bool_t AXIS2_CALL 
sandesha2_terminate_seq_res_is_namespace_supported(
    const axutil_env_t *env, 
    axis2_char_t *namespace)
{
    if(0 == axutil_strcmp(namespace, SANDESHA2_SPEC_2007_02_NS_URI))
    {
        return AXIS2_TRUE;
    }
    return AXIS2_FALSE;
}

