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
 
#include <sandesha2_identifier.h>
#include <sandesha2_constants.h>
/** 
 * @brief Identifier struct impl
 *	Sandesha2 Identifier
 */
struct sandesha2_identifier_t
{
	axis2_char_t *str_id;
	axis2_char_t *ns_val;
};

static axis2_bool_t AXIS2_CALL 
sandesha2_identifier_is_namespace_supported(
    const axutil_env_t *env, 
    axis2_char_t *namespace);

AXIS2_EXTERN sandesha2_identifier_t* AXIS2_CALL
sandesha2_identifier_create(
    const axutil_env_t *env,  
    axis2_char_t *ns_val)
{
    sandesha2_identifier_t *identifier = NULL;
    AXIS2_PARAM_CHECK(env->error, ns_val, NULL);

    identifier =  (sandesha2_identifier_t *)AXIS2_MALLOC 
        (env->allocator, sizeof(sandesha2_identifier_t));
	
    if(NULL == identifier)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}
    identifier->ns_val = NULL;
    identifier->str_id = NULL;
    
    if(AXIS2_FALSE == sandesha2_identifier_is_namespace_supported(env, ns_val))
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_UNSUPPORTED_NS, 
            AXIS2_FAILURE);
        return NULL;
    }        
    
    identifier->ns_val = (axis2_char_t *)axutil_strdup(env, ns_val);
    
	return identifier;
}

AXIS2_EXTERN sandesha2_identifier_t* AXIS2_CALL
sandesha2_identifier_clone(
    const axutil_env_t *env,  
    sandesha2_identifier_t *identifier)
{
    sandesha2_identifier_t *rm_identifier = NULL;
    AXIS2_PARAM_CHECK(env->error, identifier, NULL);

    rm_identifier =  (sandesha2_identifier_t *) sandesha2_identifier_create(env, 
            sandesha2_identifier_get_namespace_value(identifier, env));	
    if(!rm_identifier)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}

    sandesha2_identifier_set_identifier(rm_identifier, env, 
            sandesha2_identifier_get_identifier(identifier, env));
    
	return rm_identifier;
}

axis2_status_t AXIS2_CALL
sandesha2_identifier_free_void_arg(
    void *identifier,
    const axutil_env_t *env)
{
    sandesha2_identifier_t *identifier_l = NULL;

    identifier_l = (sandesha2_identifier_t *) identifier;
    return sandesha2_identifier_free(identifier_l, env);
}

axis2_status_t AXIS2_CALL 
sandesha2_identifier_free (
    sandesha2_identifier_t *identifier, 
	const axutil_env_t *env)
{
    if(identifier->ns_val)
    {
        AXIS2_FREE(env->allocator, identifier->ns_val);
        identifier->ns_val = NULL;
    }

    if(identifier->str_id)
    {
    	AXIS2_FREE(env->allocator, identifier->str_id);
        identifier->str_id = NULL;
    }

	AXIS2_FREE(env->allocator, identifier);

	return AXIS2_SUCCESS;
}

axis2_char_t* AXIS2_CALL 
sandesha2_identifier_get_namespace_value (
    sandesha2_identifier_t *identifier,
	const axutil_env_t *env)
{
	return identifier->ns_val;
}


void* AXIS2_CALL 
sandesha2_identifier_from_om_node(
    sandesha2_identifier_t *identifier,
    const axutil_env_t *env, 
    axiom_node_t *om_node)
{
    axiom_element_t *om_element = NULL;
    axiom_element_t *ident_part = NULL;
    axiom_node_t *ident_node = NULL;
    axutil_qname_t *ident_qname = NULL;
    axis2_char_t *ident_str = NULL;
    
    AXIS2_PARAM_CHECK(env->error, om_node, NULL);
    
    om_element = axiom_node_get_data_element(om_node, env);
    if(!om_element)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_OM_ELEMENT, AXIS2_FAILURE);
        return NULL;
    }

    ident_qname = axutil_qname_create(env, SANDESHA2_WSRM_COMMON_IDENTIFIER, identifier->ns_val, 
            NULL); 

    if(!ident_qname)
    {
        return NULL;
    }

    ident_part = axiom_element_get_first_child_with_qname(om_element, env, ident_qname, om_node, 
            &ident_node);

    if(ident_qname)
    {
        axutil_qname_free(ident_qname, env);
    }

    if(!ident_part)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_OM_ELEMENT, AXIS2_FAILURE);
        return NULL;
    }

    ident_str = axiom_element_get_text(ident_part, env, ident_node);
    if(!ident_str)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_EMPTY_OM_ELEMENT, AXIS2_FAILURE);
        return NULL;
    }

    if(identifier->str_id)
    {
        AXIS2_FREE(env->allocator, identifier->str_id);
    }

    identifier->str_id = axutil_strdup(env, ident_str);
    if(!identifier->str_id)
    {
        return NULL;
    }

    return identifier;
}

axiom_node_t* AXIS2_CALL 
sandesha2_identifier_to_om_node(
    sandesha2_identifier_t *identifier,
    const axutil_env_t *env, 
    void *om_node)
{
    axiom_namespace_t *rm_ns = NULL;
    axiom_element_t *id_element = NULL;
    axiom_node_t *id_node = NULL;
    
    AXIS2_PARAM_CHECK(env->error, om_node, NULL);
    
    if(!identifier->str_id || 0 == axutil_strlen(identifier->str_id))
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_TO_OM_NULL_ELEMENT, AXIS2_FAILURE);
        return NULL;
    }

    rm_ns = axiom_namespace_create(env, identifier->ns_val, SANDESHA2_WSRM_COMMON_NS_PREFIX_RM);
    if(!rm_ns)
    {
        return NULL;
    }

    id_element = axiom_element_create(env, (axiom_node_t *) om_node, 
            SANDESHA2_WSRM_COMMON_IDENTIFIER, rm_ns, &id_node);
    if(!id_element)
    {
        return NULL;
    }

    axiom_element_set_text(id_element, env, identifier->str_id, id_node);

    return (axiom_node_t*)om_node;
}

axis2_char_t * AXIS2_CALL
sandesha2_identifier_get_identifier(
    sandesha2_identifier_t *identifier,
    const axutil_env_t *env)
{
	return identifier->str_id;
}                    	

axis2_status_t AXIS2_CALL                 
sandesha2_identifier_set_identifier(
    sandesha2_identifier_t *identifier,
    const axutil_env_t *env, 
    axis2_char_t *str_id)
{
 	if(identifier->str_id)
	{
		AXIS2_FREE(env->allocator, identifier->str_id);
		identifier->str_id = NULL;
	}
	
	identifier->str_id = (axis2_char_t *)axutil_strdup(env, str_id);
 	return AXIS2_SUCCESS;
}

static axis2_bool_t AXIS2_CALL 
sandesha2_identifier_is_namespace_supported(
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


