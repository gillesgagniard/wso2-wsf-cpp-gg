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
 
#include <sandesha2_endpoint.h>
#include <sandesha2_constants.h>
#include <sandesha2_error.h>
/** 
 * @brief Endpoint struct impl
 *	Sandesha2 Endpoint
 */
  
struct sandesha2_endpoint_t
{
	sandesha2_address_t *address;
	axis2_char_t *addr_ns_val;
	axis2_char_t *rm_ns_val;
};

                   	
static axis2_bool_t AXIS2_CALL 
sandesha2_endpoint_is_namespace_supported(
   	const axutil_env_t *env, 
    axis2_char_t *namespace);

AXIS2_EXTERN sandesha2_endpoint_t* AXIS2_CALL
sandesha2_endpoint_create(
    const axutil_env_t *env, 
    sandesha2_address_t *address,
	axis2_char_t *rm_ns_val, 
    axis2_char_t *addr_ns_val)
{
    sandesha2_endpoint_t *endpoint = NULL;
    AXIS2_PARAM_CHECK(env->error, rm_ns_val, NULL);
    AXIS2_PARAM_CHECK(env->error, addr_ns_val, NULL);
    
    if(AXIS2_FALSE == sandesha2_endpoint_is_namespace_supported(env, rm_ns_val))
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_UNSUPPORTED_NS, 
            AXIS2_FAILURE);
        return NULL;
    }    
    endpoint =  (sandesha2_endpoint_t *)AXIS2_MALLOC 
        (env->allocator, sizeof(sandesha2_endpoint_t));
	
    if(NULL == endpoint)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}
    endpoint->rm_ns_val = (axis2_char_t *)axutil_strdup(env, rm_ns_val);
    endpoint->addr_ns_val = (axis2_char_t *)axutil_strdup(env, addr_ns_val);
    endpoint->address = address;
    
	return endpoint;
}


axis2_status_t AXIS2_CALL 
sandesha2_endpoint_free (
    sandesha2_endpoint_t *endpoint, 
    const axutil_env_t *env)
{
    if(endpoint->addr_ns_val)
    {
        AXIS2_FREE(env->allocator, endpoint->addr_ns_val);
        endpoint->addr_ns_val = NULL;
    }
    if(endpoint->rm_ns_val)
    {
        AXIS2_FREE(env->allocator, endpoint->rm_ns_val);
        endpoint->rm_ns_val = NULL;
    }
    if(endpoint->address)
    {
        sandesha2_address_free(endpoint->address, env);
        endpoint->address = NULL;
    }
    
	AXIS2_FREE(env->allocator, endpoint);
	return AXIS2_SUCCESS;
}

axis2_char_t* AXIS2_CALL 
sandesha2_endpoint_get_namespace_value(
    sandesha2_endpoint_t *endpoint,
	const axutil_env_t *env)
{
	return endpoint->rm_ns_val;
}


void* AXIS2_CALL 
sandesha2_endpoint_from_om_node(
    sandesha2_endpoint_t *endpoint,
   	const axutil_env_t *env, 
    axiom_node_t *om_node)
{
    axiom_element_t *om_element = NULL; 
    axiom_element_t *endpoint_part = NULL; 
    axiom_node_t *endpoint_node = NULL;
    axutil_qname_t *endpoint_qname = NULL;
    
    AXIS2_PARAM_CHECK(env->error, om_node, NULL);
     
    om_element = axiom_node_get_data_element(om_node, env);
    if(!om_element)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_OM_ELEMENT, AXIS2_FAILURE);
        return NULL;
    }
    endpoint_qname = axutil_qname_create(env, SANDESHA2_WSRM_COMMON_ENDPOINT,
        endpoint->rm_ns_val, NULL);

    if(!endpoint_qname)
    {
        return NULL;
    }

    endpoint_part = axiom_element_get_first_child_with_qname(om_element, env,
        endpoint_qname, om_node, &endpoint_node);

    if(endpoint_qname)
    {
        axutil_qname_free(endpoint_qname, env);
    }

    if(!endpoint_part)
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                "Endpoint is not set. It means this is not RM 1.1 Create Sequence Message");
        return NULL;
    }

    if(endpoint->address)
    {
        sandesha2_address_free(endpoint->address, env);
        endpoint->address = NULL;
    }

    endpoint->address = sandesha2_address_create(env, endpoint->addr_ns_val, NULL);
    if(NULL == endpoint->address)
    {
        return NULL;
    }
    if(!sandesha2_address_from_om_node(endpoint->address, env, endpoint_node))
    {
        return NULL;
    }
    return endpoint; 
}


axiom_node_t* AXIS2_CALL 
sandesha2_endpoint_to_om_node(
    sandesha2_endpoint_t *endpoint,
   	const axutil_env_t *env, void *om_node)
{
    axiom_namespace_t *rm_ns = NULL;
    axiom_element_t *at_element = NULL;
    axiom_node_t *at_node = NULL;
    
    AXIS2_PARAM_CHECK(env->error, om_node, NULL);
    
    if(!endpoint->address)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_TO_OM_NULL_ELEMENT, AXIS2_FAILURE);
        return NULL;
    }
    rm_ns = axiom_namespace_create(env, endpoint->rm_ns_val, SANDESHA2_WSRM_COMMON_NS_PREFIX_RM);
    if(!rm_ns)
    {
        return NULL;
    }

    at_element = axiom_element_create(env, NULL, SANDESHA2_WSRM_COMMON_ENDPOINT, rm_ns, &at_node);
    if(!at_element)
    {
        return NULL;
    }
    sandesha2_address_to_om_node(endpoint->address, env, at_node);
    axiom_node_add_child((axiom_node_t*)om_node, env, at_node);
    return (axiom_node_t*)om_node;
}

sandesha2_address_t * AXIS2_CALL
sandesha2_endpoint_get_address(
    sandesha2_endpoint_t *endpoint,
    const axutil_env_t *env)
{
	return endpoint->address;
}
                    	
axis2_status_t AXIS2_CALL
sandesha2_endpoint_set_address (
    sandesha2_endpoint_t *endpoint, 
	const axutil_env_t *env, 
    sandesha2_address_t *address) 
{
    if(endpoint->address)
    {
        sandesha2_address_free(endpoint->address, env);
        endpoint->address = NULL;
    }

	endpoint->address = address;

    return AXIS2_SUCCESS;
}
    
static axis2_bool_t AXIS2_CALL 
sandesha2_endpoint_is_namespace_supported(
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


