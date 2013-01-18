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
 
#include <sandesha2_acks_to.h>
#include <sandesha2_constants.h>
#include <sandesha2_error.h>
#include <axis2_addr.h>

/** 
 * @brief AcksTo struct impl
 *	Sandesha2 AcksTo
 */
  
struct sandesha2_acks_to_t
{
	sandesha2_address_t *address;
    /** reference parameters */
    axutil_array_list_t *ref_param_list;
	axis2_char_t *addr_ns_val;
	axis2_char_t *rm_ns_val;
};

                   	
static axis2_bool_t AXIS2_CALL 
sandesha2_acks_to_is_namespace_supported(
   	const axutil_env_t *env, 
    axis2_char_t *namespace);

AXIS2_EXTERN sandesha2_acks_to_t* AXIS2_CALL
sandesha2_acks_to_create(
    const axutil_env_t *env, 
    sandesha2_address_t *address,
	axis2_char_t *rm_ns_val, 
    axis2_char_t *addr_ns_val)
{
    sandesha2_acks_to_t *acks_to = NULL;
    AXIS2_PARAM_CHECK(env->error, rm_ns_val, NULL);
    AXIS2_PARAM_CHECK(env->error, addr_ns_val, NULL);
    
    if(AXIS2_FALSE == sandesha2_acks_to_is_namespace_supported(env, rm_ns_val))
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_UNSUPPORTED_NS, 
            AXIS2_FAILURE);
        return NULL;
    }    
    acks_to =  (sandesha2_acks_to_t *)AXIS2_MALLOC 
        (env->allocator, sizeof(sandesha2_acks_to_t));
	
    if(NULL == acks_to)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}
    acks_to->rm_ns_val = (axis2_char_t *)axutil_strdup(env, rm_ns_val);
    acks_to->addr_ns_val = (axis2_char_t *)axutil_strdup(env, addr_ns_val);
    acks_to->address = address;
    acks_to->ref_param_list = NULL;
    
	return acks_to;
}


axis2_status_t AXIS2_CALL 
sandesha2_acks_to_free (
    sandesha2_acks_to_t *acks_to, 
    const axutil_env_t *env)
{
    if(acks_to->addr_ns_val)
    {
        AXIS2_FREE(env->allocator, acks_to->addr_ns_val);
        acks_to->addr_ns_val = NULL;
    }
    if(acks_to->rm_ns_val)
    {
        AXIS2_FREE(env->allocator, acks_to->rm_ns_val);
        acks_to->rm_ns_val = NULL;
    }
    if(acks_to->address)
    {
        sandesha2_address_free(acks_to->address, env);
        acks_to->address = NULL;
    }
    
    if (acks_to->ref_param_list)
    {
        axutil_array_list_free(acks_to->ref_param_list, env);
    }
    
	AXIS2_FREE(env->allocator, acks_to);
	return AXIS2_SUCCESS;
}

axis2_char_t* AXIS2_CALL 
sandesha2_acks_to_get_namespace_value(
    sandesha2_acks_to_t *acks_to,
	const axutil_env_t *env)
{
	return acks_to->rm_ns_val;
}

axutil_array_list_t *AXIS2_CALL
sandesha2_acks_to_get_ref_param_list(
    sandesha2_acks_to_t * acks_to,
    const axutil_env_t * env)
{
    return acks_to->ref_param_list;
}

axis2_status_t AXIS2_CALL
sandesha2_acks_to_add_ref_param(
    sandesha2_acks_to_t * acks_to,
    const axutil_env_t * env,
    axiom_node_t * ref_param_node)
{
    if (!(acks_to->ref_param_list))
    {
        acks_to->ref_param_list = axutil_array_list_create(env, 0);
        if (!(acks_to->ref_param_list))
        {
            AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
            return AXIS2_FAILURE;
        }
    }

    if (acks_to->ref_param_list && ref_param_node)
    {
        return axutil_array_list_add(acks_to->ref_param_list, env, ref_param_node);
    }

    return AXIS2_FAILURE;
}


void* AXIS2_CALL 
sandesha2_acks_to_from_om_node(
    sandesha2_acks_to_t *acks_to,
   	const axutil_env_t *env, 
    axiom_node_t *om_node)
{
    axiom_element_t *om_element = NULL; 
    axiom_element_t *acks_to_part = NULL; 
    axiom_node_t *acks_to_node = NULL;
    axutil_qname_t *acks_to_qname = NULL;
    axutil_qname_t *ref_param_qname = NULL;
    axiom_element_t *ref_params_ele = NULL; 
    axiom_node_t *ref_params_node = NULL;
    
    AXIS2_PARAM_CHECK(env->error, om_node, NULL);
     
    om_element = axiom_node_get_data_element(om_node, env);
    if(NULL == om_element)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_OM_ELEMENT,
            AXIS2_FAILURE);
        return NULL;
    }
    acks_to_qname = axutil_qname_create(env, SANDESHA2_WSRM_COMMON_ACKS_TO,
        acks_to->rm_ns_val, NULL);
    if(NULL == acks_to_qname)
    {
        return NULL;
    }
    acks_to_part = axiom_element_get_first_child_with_qname(om_element, env,
        acks_to_qname, om_node, &acks_to_node);
    if(acks_to_qname)
        axutil_qname_free(acks_to_qname, env);
    if(NULL == acks_to_part)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_OM_ELEMENT,
            AXIS2_FAILURE);
        return NULL;
    }

    if(acks_to->address)
    {
        sandesha2_address_free(acks_to->address, env);
        acks_to->address = NULL;
    }

    acks_to->address = sandesha2_address_create(env, acks_to->addr_ns_val, NULL);
    if(NULL == acks_to->address)
    {
        return NULL;
    }
    if(!sandesha2_address_from_om_node(acks_to->address, env, acks_to_node))
    {
        return NULL;
    }

    ref_param_qname =
        axutil_qname_create(env, EPR_REFERENCE_PARAMETERS, acks_to->addr_ns_val, NULL);

    ref_params_ele = axiom_element_get_first_child_with_qname(acks_to_part, env,
        ref_param_qname, acks_to_node, &ref_params_node);
   
    if(ref_param_qname)
    {
        axutil_qname_free(ref_param_qname, env);
    }

    if(ref_params_ele)
    {
        axiom_child_element_iterator_t *ref_param_iter = NULL;

        ref_param_iter =
            axiom_element_get_child_elements(ref_params_ele, env, ref_params_node);
        if (ref_param_iter)
        {
            while (AXIOM_CHILD_ELEMENT_ITERATOR_HAS_NEXT(ref_param_iter, env))
            {
                axiom_node_t *om_node = NULL;
                axiom_element_t *om_ele = NULL;
                om_node = AXIOM_CHILD_ELEMENT_ITERATOR_NEXT(ref_param_iter, env);
                om_ele = (axiom_element_t *) axiom_node_get_data_element(om_node, env);
                sandesha2_acks_to_add_ref_param(acks_to, env, om_node);                    
            }
        }
    }

    return acks_to; 
}


axiom_node_t* AXIS2_CALL 
sandesha2_acks_to_to_om_node(
    sandesha2_acks_to_t *acks_to,
   	const axutil_env_t *env, void *om_node)
{
    axiom_namespace_t *rm_ns = NULL;
    axiom_element_t *at_element = NULL;
    axiom_node_t *at_node = NULL;
    int i = 0, size = 0;
    
    AXIS2_PARAM_CHECK(env->error, om_node, NULL);
    
    if(!acks_to->address)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_TO_OM_NULL_ELEMENT, AXIS2_FAILURE);
        return NULL;
    }
    rm_ns = axiom_namespace_create(env, acks_to->rm_ns_val, SANDESHA2_WSRM_COMMON_NS_PREFIX_RM);
    if(!rm_ns)
    {
        return NULL;
    }

    at_element = axiom_element_create(env, NULL, SANDESHA2_WSRM_COMMON_ACKS_TO, rm_ns, &at_node);
    if(!at_element)
    {
        return NULL;
    }
    sandesha2_address_to_om_node(acks_to->address, env, at_node);
    axiom_node_add_child((axiom_node_t*)om_node, env, at_node);
    
    size = axutil_array_list_size(acks_to->ref_param_list, env);
    for(i = 0; i < size; i++)
    {
        axiom_node_t *node = axutil_array_list_get(acks_to->ref_param_list, env, i);
        axiom_node_add_child((axiom_node_t*)om_node, env, node);
    }

    return (axiom_node_t*)om_node;
}

sandesha2_address_t * AXIS2_CALL
sandesha2_acks_to_get_address(
    sandesha2_acks_to_t *acks_to,
    const axutil_env_t *env)
{
	return acks_to->address;
}
                    	
axis2_status_t AXIS2_CALL
sandesha2_acks_to_set_address (
    sandesha2_acks_to_t *acks_to, 
	const axutil_env_t *env, 
    sandesha2_address_t *address) 
{
    if(acks_to->address)
    {
        sandesha2_address_free(acks_to->address, env);
        acks_to->address = NULL;
    }

	acks_to->address = address;

    return AXIS2_SUCCESS;
}
    
static axis2_bool_t AXIS2_CALL 
sandesha2_acks_to_is_namespace_supported(
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


