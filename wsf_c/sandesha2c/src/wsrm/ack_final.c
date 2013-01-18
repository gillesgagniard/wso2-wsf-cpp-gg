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
 
#include <sandesha2_ack_final.h>
#include <sandesha2_constants.h>
#include <sandesha2_error.h>
/** 
 * @brief AckFinal struct impl
 *	Sandesha2 AckFinal
 */
struct sandesha2_ack_final_t
{
	axis2_char_t *ns_val;
};
                   	
static axis2_bool_t AXIS2_CALL 
sandesha2_ack_final_is_namespace_supported(
    const axutil_env_t *env, 
    axis2_char_t *namespace);

AXIS2_EXTERN sandesha2_ack_final_t* AXIS2_CALL
sandesha2_ack_final_create(
    const axutil_env_t *env,
    axis2_char_t *ns_val)
{
    sandesha2_ack_final_t *ack_final = NULL;
    AXIS2_PARAM_CHECK(env->error, ns_val, NULL);
    
    if(!sandesha2_ack_final_is_namespace_supported(env, ns_val))
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_UNSUPPORTED_NS, AXIS2_FAILURE);
        return NULL;
    }

    ack_final =  (sandesha2_ack_final_t *)AXIS2_MALLOC(env->allocator, sizeof(sandesha2_ack_final_t));
	
    if(!ack_final)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}

    ack_final->ns_val = NULL;
    ack_final->ns_val = (axis2_char_t *)axutil_strdup(env, ns_val);
    
	return ack_final;
}


axis2_status_t AXIS2_CALL 
sandesha2_ack_final_free(
    sandesha2_ack_final_t *ack_final, 
    const axutil_env_t *env)
{
    if(ack_final->ns_val)
    {
        AXIS2_FREE(env->allocator, ack_final->ns_val);
        ack_final->ns_val = NULL;
    }

	AXIS2_FREE(env->allocator, ack_final);

	return AXIS2_SUCCESS;
}

axis2_char_t* AXIS2_CALL 
sandesha2_ack_final_get_namespace_value(
    sandesha2_ack_final_t *ack_final,
	const axutil_env_t *env)
{
	return ack_final->ns_val;
}


void* AXIS2_CALL 
sandesha2_ack_final_from_om_node(
    sandesha2_ack_final_t *ack_final,
    const axutil_env_t *env, 
    axiom_node_t *om_node)
{
    axutil_qname_t *final_qname = NULL;
    axiom_element_t *om_element = NULL;
    axiom_element_t *final_part = NULL;
    axiom_node_t *final_part_node = NULL;
    
    AXIS2_PARAM_CHECK(env->error, om_node, NULL);
    
    final_qname = axutil_qname_create(env, SANDESHA2_WSRM_COMMON_FINAL, ack_final->ns_val, NULL);
    if(!final_qname)
    {
        return NULL;
    }

    om_element = axiom_node_get_data_element(om_node, env); 
    if(!om_element)
    {
        if(final_qname)
        {
            axutil_qname_free(final_qname, env);
        }

        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_OM_ELEMENT, AXIS2_FAILURE); 
        return NULL;
    }

    final_part = axiom_element_get_first_child_with_qname(om_element, env, final_qname, om_node, 
            &final_part_node);  

    if(final_qname)
    {
        axutil_qname_free(final_qname, env);
    }

    if(!final_part)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_OM_ELEMENT, AXIS2_FAILURE);
        return NULL;
    }

    return ack_final;
}


axiom_node_t* AXIS2_CALL 
sandesha2_ack_final_to_om_node(
    sandesha2_ack_final_t *ack_final,
    const axutil_env_t *env, 
    void *om_node)
{
	axiom_namespace_t *rm_ns = NULL;
	axiom_element_t *af_element = NULL;
	axiom_node_t *af_node = NULL;
    
    AXIS2_PARAM_CHECK(env->error, om_node, NULL);
    
	rm_ns = axiom_namespace_create(env, ack_final->ns_val, SANDESHA2_WSRM_COMMON_NS_PREFIX_RM);
    if(!rm_ns)
    {
        return NULL;
    }

    af_element = axiom_element_create(env, NULL, SANDESHA2_WSRM_COMMON_FINAL, rm_ns, &af_node);
    axiom_node_add_child((axiom_node_t*)om_node, env, af_node);

    return (axiom_node_t*)om_node;
}

static axis2_bool_t AXIS2_CALL 
sandesha2_ack_final_is_namespace_supported(
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

