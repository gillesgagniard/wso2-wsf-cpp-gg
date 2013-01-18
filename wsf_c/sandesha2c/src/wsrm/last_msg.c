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
 
#include <sandesha2_last_msg.h>
#include <sandesha2_constants.h>
#include <axiom_node.h>
#include <axiom_element.h>

/** 
 * @brief LastMessage struct impl
 *	Sandesha2 LastMessage
 */
  
struct sandesha2_last_msg_t
{
	axis2_char_t *ns_val;
};
                   	
static axis2_bool_t AXIS2_CALL 
sandesha2_last_msg_is_namespace_supported(
    const axutil_env_t *env, 
    axis2_char_t *namespace);

AXIS2_EXTERN sandesha2_last_msg_t* AXIS2_CALL
sandesha2_last_msg_create(
    const axutil_env_t *env, 
    axis2_char_t *ns_val)
{
    sandesha2_last_msg_t *last_msg = NULL;
    AXIS2_PARAM_CHECK(env->error, ns_val, NULL);
    
    if(AXIS2_FALSE == sandesha2_last_msg_is_namespace_supported(env, ns_val))
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_UNSUPPORTED_NS, 
            AXIS2_FAILURE);
        return NULL;
    }    
    last_msg =  (sandesha2_last_msg_t *)AXIS2_MALLOC 
        (env->allocator, sizeof(sandesha2_last_msg_t));
	
    if(NULL == last_msg)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}
    last_msg->ns_val = NULL;
    
    last_msg->ns_val = (axis2_char_t *)axutil_strdup(env, ns_val);
    
	return last_msg;
}

AXIS2_EXTERN sandesha2_last_msg_t* AXIS2_CALL
sandesha2_last_msg_clone(
    const axutil_env_t *env, 
    sandesha2_last_msg_t *last_msg)
{
    sandesha2_last_msg_t *rm_last_msg = NULL;
    AXIS2_PARAM_CHECK(env->error, last_msg, NULL);
    
    rm_last_msg = sandesha2_last_msg_create(env, sandesha2_last_msg_get_namespace_value(last_msg, 
                env));
	
    if(!rm_last_msg)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}
    
	return rm_last_msg;
}

axis2_status_t AXIS2_CALL
sandesha2_last_msg_free_void_arg(
    void *last_msg,
    const axutil_env_t *env)
{
    sandesha2_last_msg_t *last_msg_l = NULL;

    last_msg_l = (sandesha2_last_msg_t *) last_msg;
    return sandesha2_last_msg_free(last_msg_l, env);
}

axis2_status_t AXIS2_CALL 
sandesha2_last_msg_free (
    sandesha2_last_msg_t *last_msg, 
    const axutil_env_t *env)
{
    if(NULL != last_msg->ns_val)
    {
        AXIS2_FREE(env->allocator, last_msg->ns_val);
        last_msg->ns_val = NULL;
    }
	AXIS2_FREE(env->allocator, last_msg);
	return AXIS2_SUCCESS;
}

axis2_char_t* AXIS2_CALL 
sandesha2_last_msg_get_namespace_value(
    sandesha2_last_msg_t *last_msg,
	const axutil_env_t *env)
{
	return last_msg->ns_val;
}


void* AXIS2_CALL 
sandesha2_last_msg_from_om_node(
    sandesha2_last_msg_t *last_msg,
   	const axutil_env_t *env, axiom_node_t *om_node)
{
    axiom_element_t *om_element = NULL;
    axiom_element_t *lm_part = NULL;
    axiom_node_t *lm_node = NULL;
    axutil_qname_t *lm_qname = NULL;
    
    AXIS2_PARAM_CHECK(env->error, om_node, NULL);
    
    om_element = axiom_node_get_data_element(om_node, env);
    if(!om_element)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_OM_ELEMENT,
            AXIS2_FAILURE);
        return NULL;
    }
    lm_qname = axutil_qname_create(env, SANDESHA2_WSRM_COMMON_LAST_MSG, 
        last_msg->ns_val, NULL);
    if(!lm_qname)
    {
        return NULL;
    }
    lm_part = axiom_element_get_first_child_with_qname(om_element, env,
        lm_qname, om_node, &lm_node);
    if(lm_qname)
        axutil_qname_free(lm_qname, env);
    if(!lm_part)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_OM_ELEMENT,
            AXIS2_FAILURE);
        return NULL;
    }
    return last_msg;
}


axiom_node_t* AXIS2_CALL 
sandesha2_last_msg_to_om_node(
    sandesha2_last_msg_t *last_msg,
    const axutil_env_t *env, 
    void *om_node)
{
    axiom_namespace_t *rm_ns = NULL;
    axiom_element_t *lm_element = NULL;
    axiom_node_t *lm_node = NULL;
    
    AXIS2_PARAM_CHECK(env->error, om_node, NULL);
    
    rm_ns = axiom_namespace_create(env, last_msg->ns_val,
        SANDESHA2_WSRM_COMMON_NS_PREFIX_RM);
    if(NULL == rm_ns)
    {
        return NULL;
    }
    lm_element = axiom_element_create(env, NULL, 
        SANDESHA2_WSRM_COMMON_LAST_MSG, rm_ns, &lm_node);
    if(NULL == lm_element)
    {
        return NULL;
    }
    axiom_node_add_child((axiom_node_t*)om_node, env, lm_node);
    return (axiom_node_t*)om_node;
}

static axis2_bool_t AXIS2_CALL 
sandesha2_last_msg_is_namespace_supported(
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
