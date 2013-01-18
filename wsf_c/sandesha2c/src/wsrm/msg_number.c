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
 
#include <sandesha2_msg_number.h>
#include <sandesha2_constants.h>
#include <stdio.h>
#include <stdlib.h>
#include <axiom_node.h>
#include <axiom_element.h>

/** 
 * @brief MessageNumber struct impl
 *	Sandesha2 MessageNumber
 */
struct sandesha2_msg_number_t
{
	long msg_num;
	axis2_char_t *ns_val;
};

static axis2_bool_t AXIS2_CALL 
sandesha2_msg_number_is_namespace_supported(
    const axutil_env_t *env, 
    axis2_char_t *namespace);

AXIS2_EXTERN sandesha2_msg_number_t* AXIS2_CALL
sandesha2_msg_number_create(
    const axutil_env_t *env,  
    axis2_char_t *ns_val)
{
    sandesha2_msg_number_t *msg_number = NULL;
    AXIS2_PARAM_CHECK(env->error, ns_val, NULL);
    
    if(AXIS2_FALSE == sandesha2_msg_number_is_namespace_supported(env, ns_val))
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_UNSUPPORTED_NS, 
            AXIS2_FAILURE);
        return NULL;
    }    
    msg_number =  (sandesha2_msg_number_t *)AXIS2_MALLOC 
        (env->allocator, sizeof(sandesha2_msg_number_t));
	
    if(NULL == msg_number)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}
    msg_number->ns_val = NULL;
    msg_number->msg_num = 0;
    
    msg_number->ns_val = (axis2_char_t *)axutil_strdup(env, ns_val);
    
	return msg_number;
}

AXIS2_EXTERN sandesha2_msg_number_t* AXIS2_CALL
sandesha2_msg_number_clone(
    const axutil_env_t *env,  
    sandesha2_msg_number_t *msg_number)
{
    sandesha2_msg_number_t *rm_msg_number = NULL;
    AXIS2_PARAM_CHECK(env->error, msg_number, NULL);
    
    rm_msg_number =  (sandesha2_msg_number_t *) sandesha2_msg_number_create(env, 
            sandesha2_msg_number_get_namespace_value(msg_number, env));
	
    if(!rm_msg_number)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}
    sandesha2_msg_number_set_msg_num(rm_msg_number, env, sandesha2_msg_number_get_msg_num(msg_number, 
                env));
    
	return rm_msg_number;
}

axis2_status_t AXIS2_CALL
sandesha2_msg_number_free_void_arg(
    void *msg_num,
    const axutil_env_t *env)
{
    sandesha2_msg_number_t *msg_num_l = NULL;

    msg_num_l = (sandesha2_msg_number_t *) msg_num;
    return sandesha2_msg_number_free(msg_num_l, env);
}

axis2_status_t AXIS2_CALL 
sandesha2_msg_number_free (
    sandesha2_msg_number_t *msg_number, 
	const axutil_env_t *env)
{
    if(msg_number->ns_val)
    {
        AXIS2_FREE(env->allocator, msg_number->ns_val);
        msg_number->ns_val = NULL;
    }
    msg_number->msg_num = 0;
    
	AXIS2_FREE(env->allocator, msg_number);
	return AXIS2_SUCCESS;
}

axis2_char_t* AXIS2_CALL 
sandesha2_msg_number_get_namespace_value(
    sandesha2_msg_number_t *msg_number,
	const axutil_env_t *env)
{
	return msg_number->ns_val;
}


void* AXIS2_CALL 
sandesha2_msg_number_from_om_node(
    sandesha2_msg_number_t *msg_number,
    const axutil_env_t *env, 
    axiom_node_t *om_node)
{
    axiom_element_t *om_element = NULL;
    axiom_element_t *mn_part = NULL;
    axiom_node_t *mn_node = NULL;
    axutil_qname_t *mn_qname = NULL;
    axis2_char_t *mn_str = NULL;

    AXIS2_PARAM_CHECK(env->error, om_node, NULL);
    
    om_element = axiom_node_get_data_element(om_node, env);
    if(!om_element)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_OM_ELEMENT,
            AXIS2_FAILURE);
        return NULL;
    }
    mn_qname = axutil_qname_create(env, SANDESHA2_WSRM_COMMON_MSG_NUMBER, 
        msg_number->ns_val, NULL);
    if(!mn_qname)
    {
        return NULL;
    }
    mn_part = axiom_element_get_first_child_with_qname(om_element, env,
        mn_qname, om_node, &mn_node);
    if(mn_qname)
        axutil_qname_free(mn_qname, env);
    if(!mn_part)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_OM_ELEMENT,
            AXIS2_FAILURE);
        return NULL;
    }
    mn_str = axiom_element_get_text(mn_part, env, mn_node);
    if(!mn_str)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_EMPTY_OM_ELEMENT,
            AXIS2_FAILURE);
        return NULL;
    } 
    msg_number->msg_num = atol(mn_str); 
    return msg_number;
    
}


axiom_node_t* AXIS2_CALL 
sandesha2_msg_number_to_om_node(
    sandesha2_msg_number_t *msg_number,
    const axutil_env_t *env, void *om_node)
{
    axiom_namespace_t *rm_ns = NULL;
    axiom_element_t *mn_element = NULL;
    axiom_node_t *mn_node = NULL;
    /*axis2_char_t *str_num = NULL;*/
    axis2_char_t str_num[32];
    
    AXIS2_PARAM_CHECK(env->error, om_node, NULL);
    
    if(msg_number->msg_num <= 0)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_TO_OM_INVALID_NUMBER, 
            AXIS2_FAILURE);
        return NULL;
    }
    rm_ns = axiom_namespace_create(env, msg_number->ns_val,
        SANDESHA2_WSRM_COMMON_NS_PREFIX_RM);
    if(NULL == rm_ns)
    {
        return NULL;
    }
    mn_element = axiom_element_create(env, NULL, 
        SANDESHA2_WSRM_COMMON_MSG_NUMBER, rm_ns, &mn_node);
    if(NULL == mn_element)
    {
        return NULL;
    }

    /*str_num = AXIS2_MALLOC(env->allocator, 32 * sizeof(axis2_char_t));*/
    sprintf(str_num, "%ld", msg_number->msg_num);
    axiom_element_set_text(mn_element, env, str_num, mn_node);
    axiom_node_add_child((axiom_node_t*)om_node, env, mn_node);
    
    return (axiom_node_t*)om_node;
 }

long AXIS2_CALL
sandesha2_msg_number_get_msg_num(
    sandesha2_msg_number_t *msg_number,
   	const axutil_env_t *env)
{
	return msg_number->msg_num;
}                    	

axis2_status_t AXIS2_CALL                 
sandesha2_msg_number_set_msg_num(
    sandesha2_msg_number_t *msg_number,
   	const axutil_env_t *env, long value)
{
 	msg_number->msg_num = value;
 	return AXIS2_SUCCESS;
}
    
static axis2_bool_t AXIS2_CALL 
sandesha2_msg_number_is_namespace_supported(
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


