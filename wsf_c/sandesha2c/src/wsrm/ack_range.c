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
 
#include <sandesha2_ack_range.h>
#include <sandesha2_constants.h>
#include <axutil_types.h>
#include <axiom_node.h>
#include <axiom_element.h>
#include <stdio.h>
/** 
 * @brief AckRange struct impl
 *	Sandesha2 AckRange
 */
struct sandesha2_ack_range_t
{
	long upper_val;
	long lower_val;
	axis2_char_t *ns_val;
    axis2_char_t *prefix;
};
                   	
static axis2_bool_t AXIS2_CALL 
sandesha2_ack_range_is_namespace_supported(
    const axutil_env_t *env, 
    axis2_char_t *namespace);

AXIS2_EXTERN sandesha2_ack_range_t* AXIS2_CALL 
sandesha2_ack_range_create(
    const axutil_env_t *env,  
    axis2_char_t *ns_val,
    axis2_char_t *prefix)
{
    sandesha2_ack_range_t *ack_range = NULL;
    AXIS2_PARAM_CHECK(env->error, ns_val, NULL);
    
    if(AXIS2_FAILURE == sandesha2_ack_range_is_namespace_supported(env, ns_val))
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_UNSUPPORTED_NS, 
            AXIS2_FAILURE);
        return NULL;
    }        
    ack_range =  (sandesha2_ack_range_t *)AXIS2_MALLOC 
        (env->allocator, sizeof(sandesha2_ack_range_t));
	
    if(NULL == ack_range)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}
    ack_range->ns_val = NULL;
    ack_range->prefix = NULL;
    ack_range->upper_val = 0;
    ack_range->lower_val = 0;
    
    ack_range->ns_val = (axis2_char_t *)axutil_strdup(env ,ns_val);
    ack_range->prefix = (axis2_char_t *)axutil_strdup(env, prefix);
    ack_range->upper_val = 0;
    ack_range->lower_val = 0;
    
	return ack_range;
}

axis2_status_t AXIS2_CALL
sandesha2_ack_range_free_void_arg(
    void *ack_range,
    const axutil_env_t *env)
{
    sandesha2_ack_range_t *ack_range_l = NULL;

    ack_range_l = (sandesha2_ack_range_t *) ack_range;
    return sandesha2_ack_range_free(ack_range_l, env);
}

axis2_status_t AXIS2_CALL 
sandesha2_ack_range_free (
    sandesha2_ack_range_t *ack_range, 
	const axutil_env_t *env)
{
    if(NULL != ack_range->ns_val)
    {
        AXIS2_FREE(env->allocator, ack_range->ns_val);
        ack_range->ns_val = NULL;
    }
    
    if(NULL != ack_range->prefix)
    {
        AXIS2_FREE(env->allocator, ack_range->prefix);
        ack_range->prefix = NULL;
    }

    ack_range->upper_val = 0;
    ack_range->lower_val = 0;
    
	AXIS2_FREE(env->allocator, ack_range);
	return AXIS2_SUCCESS;
}

axis2_char_t* AXIS2_CALL 
sandesha2_ack_range_get_namespace_value (
    sandesha2_ack_range_t *ack_range,
	const axutil_env_t *env)
{
	return ack_range->ns_val;
}


void* AXIS2_CALL 
sandesha2_ack_range_from_om_node(
    sandesha2_ack_range_t *ack_range,
    const axutil_env_t *env, 
    axiom_node_t *om_node)
{
    axiom_element_t *om_element = NULL;
    axis2_char_t *lower_str = NULL;
    axis2_char_t *upper_str = NULL;

    AXIS2_PARAM_CHECK(env->error, om_node, NULL);
    
    om_element = axiom_node_get_data_element(om_node, env);
    if(!om_element)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_OM_ELEMENT,
                        AXIS2_FAILURE);
        return NULL;
    }
    /*lower_str = axiom_element_get_attribute_value(om_element, env,
                        low_qname);
    upper_str = axiom_element_get_attribute_value(om_element, env,
                        upper_qname);*/
    lower_str = axiom_element_get_attribute_value_by_name(om_element, env,
                        SANDESHA2_WSRM_COMMON_LOWER);
    upper_str = axiom_element_get_attribute_value_by_name(om_element, env,
                        SANDESHA2_WSRM_COMMON_UPPER);
    
    if(!lower_str || !upper_str)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_OM_ATTRIBUTE,
                        AXIS2_FAILURE);
        return NULL; 
    }
    ack_range->lower_val = AXIS2_ATOI(lower_str);
    ack_range->upper_val = AXIS2_ATOI(upper_str);
    return ack_range;
    
}


axiom_node_t* AXIS2_CALL 
sandesha2_ack_range_to_om_node(
    sandesha2_ack_range_t *ack_range,
    const axutil_env_t *env, 
    void *om_node)
{
    axiom_namespace_t *rm_ns = NULL;
    axiom_element_t *ar_element = NULL;
    axiom_node_t *ar_node = NULL;
    axiom_attribute_t *lower_attr = NULL;
    axiom_attribute_t *upper_attr = NULL;
    axis2_char_t *lower_str = NULL;
    axis2_char_t *upper_str = NULL;
    AXIS2_PARAM_CHECK(env->error, om_node, NULL);
    
    lower_str = AXIS2_MALLOC(env->allocator, 32*sizeof(axis2_char_t));
    upper_str = AXIS2_MALLOC(env->allocator, 32*sizeof(axis2_char_t));
    sprintf(lower_str, "%ld", ack_range->lower_val);
    sprintf(upper_str, "%ld", ack_range->upper_val);
    
    rm_ns = axiom_namespace_create(env, ack_range->ns_val,
                        SANDESHA2_WSRM_COMMON_NS_PREFIX_RM);
    if(NULL == rm_ns)
    {
        return NULL;
    }
    /*lower_attr = axiom_attribute_create(env, SANDESHA2_WSRM_COMMON_LOWER,
        lower_str, rm_ns);*/
    lower_attr = axiom_attribute_create(env, SANDESHA2_WSRM_COMMON_LOWER,
        lower_str, NULL);
    if(lower_str)
        AXIS2_FREE(env->allocator, lower_str);
    if(!lower_attr)
    {
        return NULL;
    }
    /*upper_attr = axiom_attribute_create(env, SANDESHA2_WSRM_COMMON_UPPER,
        upper_str, rm_ns);*/
    upper_attr = axiom_attribute_create(env, SANDESHA2_WSRM_COMMON_UPPER,
        upper_str, NULL);
    if(upper_str)
        AXIS2_FREE(env->allocator, upper_str);
    if(!upper_attr)
    {
        return NULL;
    }
    ar_element = axiom_element_create(env, (axiom_node_t*)om_node, 
        SANDESHA2_WSRM_COMMON_ACK_RANGE, rm_ns, &ar_node);
    if(!ar_element)
    {
        return NULL;
    }
    axiom_element_add_attribute(ar_element, env, lower_attr, ar_node);
    axiom_element_add_attribute(ar_element, env, upper_attr, ar_node);

    return (axiom_node_t*)om_node;
}

long AXIS2_CALL
sandesha2_ack_range_get_lower_value(
    sandesha2_ack_range_t *ack_range,
   	const axutil_env_t *env)
{
	return ack_range->lower_val;
}                    	

axis2_status_t AXIS2_CALL                 
sandesha2_ack_range_set_lower_value(
    sandesha2_ack_range_t *ack_range,
   	const axutil_env_t *env, 
    long value)
{
 	ack_range->lower_val = value;
 	return AXIS2_SUCCESS;
}

long AXIS2_CALL                    	
sandesha2_ack_range_get_upper_value(
    sandesha2_ack_range_t *ack_range,
  	const axutil_env_t *env)
{
	return ack_range->upper_val;
}

axis2_status_t AXIS2_CALL                    	
sandesha2_ack_range_set_upper_value(
    sandesha2_ack_range_t *ack_range,
  	const axutil_env_t *env, long value)
{
 	ack_range->upper_val = value;
 	return AXIS2_SUCCESS;
}

static axis2_bool_t AXIS2_CALL 
sandesha2_ack_range_is_namespace_supported(
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

