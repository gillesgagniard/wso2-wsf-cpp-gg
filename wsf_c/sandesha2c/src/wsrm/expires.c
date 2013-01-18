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
 
#include <sandesha2_expires.h>
#include <sandesha2_constants.h>
#include <axiom_node.h>
#include <axiom_element.h>

/** 
 * @brief Expires struct impl
 *	Sandesha2 Expires
 */
struct sandesha2_expires_t
{
	axis2_char_t *duration;
	axis2_char_t *ns_val;
};                   	

static axis2_bool_t AXIS2_CALL 
sandesha2_expires_is_namespace_supported(
    const axutil_env_t *env, 
    axis2_char_t *namespace);

AXIS2_EXTERN sandesha2_expires_t* AXIS2_CALL
sandesha2_expires_create(
    const axutil_env_t *env,  
    axis2_char_t *ns_val)
{
    sandesha2_expires_t *expires = NULL;
    AXIS2_PARAM_CHECK(env->error, ns_val, NULL);
    
    if(AXIS2_FALSE == sandesha2_expires_is_namespace_supported(env, ns_val))
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_UNSUPPORTED_NS, 
            AXIS2_FAILURE);
        return NULL;
    }    
    expires =  (sandesha2_expires_t *)AXIS2_MALLOC 
        (env->allocator, sizeof(sandesha2_expires_t));
	
    if(NULL == expires)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}
    expires->ns_val = NULL;
    expires->duration = NULL;
    
    expires->ns_val = (axis2_char_t *)axutil_strdup(env, ns_val);
    
	return expires;
}

axis2_status_t AXIS2_CALL 
sandesha2_expires_free (
    sandesha2_expires_t *expires, 
	const axutil_env_t *env)
{
    if(expires->ns_val)
    {
        AXIS2_FREE(env->allocator, expires->ns_val);
        expires->ns_val = NULL;
    }
    if(expires->duration)
    {
    	AXIS2_FREE(env->allocator, expires->duration);
    	expires->duration = NULL;
    }
	AXIS2_FREE(env->allocator, expires);
	return AXIS2_SUCCESS;
}

axis2_char_t* AXIS2_CALL 
sandesha2_expires_get_namespace_value (
    sandesha2_expires_t *expires,
	const axutil_env_t *env)
{
	return expires->ns_val;
}


void* AXIS2_CALL 
sandesha2_expires_from_om_node(
    sandesha2_expires_t *expires,
    const axutil_env_t *env, 
    axiom_node_t *om_node)
{
    axiom_element_t *om_element = NULL;
    axiom_element_t *exp_part = NULL;
    axiom_node_t *exp_node = NULL;
    axutil_qname_t *exp_qname = NULL;
    axis2_char_t *text = NULL;
    
    AXIS2_PARAM_CHECK(env->error, om_node, NULL);
    
    om_element = axiom_node_get_data_element(om_node, env);
    if(NULL == om_element)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_OM_ELEMENT,
            AXIS2_FAILURE);
        return NULL;
    }
    exp_qname = axutil_qname_create(env, SANDESHA2_WSRM_COMMON_EXPIRES, 
        expires->ns_val, NULL); 
    if(NULL == exp_qname)
    {
        return NULL;
    }
    exp_part = axiom_element_get_first_child_with_qname(om_element, env,
        exp_qname, om_node, &exp_node);
    if(exp_qname)
        axutil_qname_free(exp_qname, env);
    if(NULL == exp_part)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_OM_ELEMENT,
                        AXIS2_FAILURE);
        return NULL;
    }
    text = axiom_element_get_text(exp_part, env, exp_node);
    if(NULL == text)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_EMPTY_OM_ELEMENT, 
                        AXIS2_FAILURE);
        return NULL;
    }
    expires->duration = axutil_strdup(env, text); 
    if(NULL == expires->duration)
    {
        return NULL;
    }
    return expires;
}


axiom_node_t* AXIS2_CALL 
sandesha2_expires_to_om_node(
   sandesha2_expires_t *expires,
   const axutil_env_t *env, 
   void *om_node)
{
    axiom_namespace_t *rm_ns = NULL;
    axiom_element_t *exp_element = NULL;
    axiom_node_t *exp_node = NULL;
    
    AXIS2_PARAM_CHECK(env->error, om_node, NULL);
    
    if(NULL == expires->duration || 0 == axutil_strlen(
                        expires->duration))
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_TO_OM_NULL_ELEMENT, 
                        AXIS2_FAILURE);
        return NULL;
    }
    rm_ns = axiom_namespace_create(env, expires->ns_val,
                        SANDESHA2_WSRM_COMMON_NS_PREFIX_RM);
    if(NULL == rm_ns)
    {
        return NULL;
    }
    exp_element = axiom_element_create(env, NULL, 
                        SANDESHA2_WSRM_COMMON_EXPIRES, rm_ns, &exp_node);
    if(NULL == exp_element)
    {
        return NULL;
    }
    axiom_element_set_text(exp_element, env, expires->duration, 
                        exp_node);
    axiom_node_add_child((axiom_node_t*)om_node, env, exp_node);
    return (axiom_node_t*)om_node;
}

axis2_char_t * AXIS2_CALL
sandesha2_expires_get_duration(
    sandesha2_expires_t *expires,
    const axutil_env_t *env)
{
	return expires->duration;
}                    	


axis2_status_t AXIS2_CALL                 
sandesha2_expires_set_duration(
    sandesha2_expires_t *expires,
    const axutil_env_t *env, 
    axis2_char_t *duration)
{
    expires->duration = duration;
	return AXIS2_SUCCESS;
}

static axis2_bool_t AXIS2_CALL 
sandesha2_expires_is_namespace_supported(
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


