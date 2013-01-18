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
 #include <sandesha2_accept.h>
 #include <sandesha2_acks_to.h>
 #include <sandesha2_constants.h>

/** 
 * @brief Accept struct impl
 *	Sandesha2 IOM Accept
 */
  
struct sandesha2_accept_t 
{
	sandesha2_acks_to_t *acks_to;
	axis2_char_t *rm_ns_val;
    axis2_char_t *addr_ns_val;
};

static axis2_bool_t AXIS2_CALL 
sandesha2_accept_is_namespace_supported(
   	const axutil_env_t *env, 
    axis2_char_t *namespace);

AXIS2_EXTERN sandesha2_accept_t* AXIS2_CALL
sandesha2_accept_create(
    const axutil_env_t *env,  
    axis2_char_t *rm_ns_val, 
	axis2_char_t *addr_ns_val)
{
    sandesha2_accept_t *accept = NULL;
    AXIS2_PARAM_CHECK(env->error, rm_ns_val, NULL);
    AXIS2_PARAM_CHECK(env->error, addr_ns_val, NULL);
    
    if(AXIS2_FALSE == sandesha2_accept_is_namespace_supported(env, rm_ns_val))
	{
		AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_UNSUPPORTED_NS, 
	        AXIS2_FAILURE);
		return NULL;
	}
    accept =  (sandesha2_accept_t *)AXIS2_MALLOC(env->allocator, sizeof(sandesha2_accept_t));
	
    if(NULL == accept)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}
    accept->rm_ns_val = NULL;
    accept->addr_ns_val = NULL;
    accept->acks_to = NULL;
    
    accept->rm_ns_val = (axis2_char_t *)axutil_strdup(env ,rm_ns_val);
    accept->addr_ns_val = (axis2_char_t *)axutil_strdup(env, addr_ns_val);
    
	return accept;
}


axis2_status_t AXIS2_CALL 
sandesha2_accept_free(
    sandesha2_accept_t *accept, 
    const axutil_env_t *env)
{
    if(accept->addr_ns_val)
    {
        AXIS2_FREE(env->allocator, accept->addr_ns_val);
        accept->addr_ns_val = NULL;
    }

    if(accept->rm_ns_val)
    {
        AXIS2_FREE(env->allocator, accept->rm_ns_val);
        accept->rm_ns_val = NULL;
    }
    
    if(accept->acks_to)
    {
        sandesha2_acks_to_free(accept->acks_to, env);
        accept->acks_to = NULL;
    }
        
	AXIS2_FREE(env->allocator, accept);

	return AXIS2_SUCCESS;
}

axis2_char_t* AXIS2_CALL 
sandesha2_accept_get_namespace_value(
    sandesha2_accept_t *accept,
	const axutil_env_t *env)
{
	return accept->rm_ns_val;
}


void* AXIS2_CALL 
sandesha2_accept_from_om_node(
    sandesha2_accept_t *accept,
    const axutil_env_t *env, 
    axiom_node_t *om_node)
{
    axutil_qname_t *accept_qname = NULL;
    axiom_node_t *child_om_node = NULL;
    axiom_element_t *om_element = NULL;
    axiom_element_t *accept_part = NULL;

    AXIS2_PARAM_CHECK(env->error, om_node, NULL);
    
    accept_qname = axutil_qname_create(env, SANDESHA2_WSRM_COMMON_ACCEPT, 
        accept->rm_ns_val, NULL);
    if(NULL == accept_qname)
    {
        return NULL;
    }
    om_element = axiom_node_get_data_element(om_node, env); 
    if(NULL == om_element)
    {
        if(accept_qname)
            axutil_qname_free(accept_qname, env);
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_OM_ELEMENT, 
            AXIS2_FAILURE);
        return NULL;
    }
    accept_part = axiom_element_get_first_child_with_qname(om_element, env,
        accept_qname, om_node, &child_om_node); 
    if(accept_qname)
        axutil_qname_free(accept_qname, env);
    if(NULL == accept_part || NULL == child_om_node)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_OM_ELEMENT,
            AXIS2_FAILURE);
        return NULL;
    }
    
    if(accept->acks_to)
    {
        sandesha2_acks_to_free(accept->acks_to, env);
        accept->acks_to = NULL;
    }

    accept->acks_to = sandesha2_acks_to_create(env, NULL, accept->rm_ns_val, accept->addr_ns_val);
    if(!accept->acks_to)
    {
        return NULL;
    }

    if(!sandesha2_acks_to_from_om_node(accept->acks_to, env, child_om_node))
    {
        return NULL;
    }

    return accept;
}


axiom_node_t* AXIS2_CALL 
sandesha2_accept_to_om_node(
    sandesha2_accept_t *accept,
    const axutil_env_t *env, 
    void *om_node)
{
    axiom_namespace_t *rm_namespace = NULL;
    axiom_element_t *accept_element = NULL;
    axiom_node_t *accept_node = NULL;
    AXIS2_PARAM_CHECK(env->error, om_node, NULL);
    
    if(NULL == accept->acks_to)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_TO_OM_NULL_ELEMENT, 
             AXIS2_FAILURE);
        return NULL;
    }
    rm_namespace = axiom_namespace_create(env, accept->rm_ns_val,
                        SANDESHA2_WSRM_COMMON_NS_PREFIX_RM);
    if(NULL == rm_namespace)
    {
        return NULL;
    }
    accept_element = axiom_element_create(env, NULL, 
                        SANDESHA2_WSRM_COMMON_ACCEPT, rm_namespace, 
                        &accept_node);
    if(NULL == accept_element)
    {
        return NULL;
    }
    sandesha2_acks_to_to_om_node(accept->acks_to, env, accept_node);
    axiom_node_add_child((axiom_node_t*)om_node, env, accept_node);

    return (axiom_node_t*)om_node;
}

axis2_status_t AXIS2_CALL
sandesha2_accept_set_acks_to(
    sandesha2_accept_t *accept,
    const axutil_env_t *env, 
    sandesha2_acks_to_t *acks_to)
{
    if(accept->acks_to)
    {
        sandesha2_acks_to_free(accept->acks_to, env);
        accept->acks_to = NULL;
    }

    accept->acks_to = acks_to;
    return AXIS2_SUCCESS;
}

sandesha2_acks_to_t * AXIS2_CALL
sandesha2_accept_get_acks_to(
    sandesha2_accept_t *accept,
    const axutil_env_t *env)
{
    return accept->acks_to;
}

static axis2_bool_t AXIS2_CALL 
sandesha2_accept_is_namespace_supported(
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


