/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <saml.h>

AXIS2_EXTERN saml_audi_restriction_cond_t * AXIS2_CALL 
saml_audi_restriction_cond_create(const axutil_env_t *env)
{
	saml_audi_restriction_cond_t *arc = AXIS2_MALLOC(env->allocator, sizeof(saml_audi_restriction_cond_t));
	if (arc)
	{
		arc->audiences = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
		if (arc->audiences)
		{
			return arc;
		}
		AXIS2_FREE(env->allocator, arc);
	}
	return NULL;
}

AXIS2_EXTERN void AXIS2_CALL 
saml_audi_restriction_cond_free(saml_audi_restriction_cond_t *arc, const axutil_env_t *env)
{
	int i = 0, size = 0;
	char *val = NULL;
	if (arc->audiences)
	{
		size = axutil_array_list_size(arc->audiences, env);
		for (i = 0; i <size; i++)
		{
			val = axutil_array_list_get(arc->audiences, env, i);
			if (val)
			{
				AXIS2_FREE(env->allocator, val);
			}
		}
	}
	AXIS2_FREE(env->allocator, arc);
}


AXIS2_EXTERN int AXIS2_CALL 
saml_audi_restriction_cond_build(saml_audi_restriction_cond_t *arc, 
								 axiom_node_t *node, const axutil_env_t *env)
{	
	axiom_element_t *element = NULL;
	axiom_child_element_iterator_t *ci = NULL;
	if (axiom_node_get_node_type(node, env) != AXIOM_ELEMENT || (element = (axiom_element_t *)axiom_node_get_data_element(node, env)) == NULL)
	{
		return AXIS2_FAILURE;
	}
	ci = axiom_element_get_child_elements(element, env, node);
	if (ci)
	{
		axiom_node_t *cn = NULL;
		axiom_element_t *ce = NULL;		
		while(AXIS2_TRUE == axiom_child_element_iterator_has_next(ci, env))	
		{
			cn = axiom_child_element_iterator_next(ci, env);
			ce = axiom_node_get_data_element(cn, env);
			if (0 == axutil_strcmp(SAML_AUDIENCE, axiom_element_get_localname(ce, env)))
			{
				axutil_array_list_add(arc->audiences, env, axiom_element_get_text(ce, env, cn));
			}
			else
			{
				return AXIS2_FAILURE;
			}			
		}
	}
	return AXIS2_SUCCESS;
}


AXIS2_EXTERN axiom_node_t *AXIS2_CALL 
saml_audi_restriction_cond_to_om(saml_audi_restriction_cond_t *cond, 
								 axiom_node_t *parent, const axutil_env_t *env)
{
	int i = 0, size = 0;
	axiom_element_t *e = NULL, *ce = NULL;
	axiom_node_t *n = NULL, *cn = NULL;
	axiom_namespace_t *ns = NULL, *cns = NULL;
	ns = axiom_namespace_create(env, SAML_NMSP_URI, SAML_PREFIX);
	e = axiom_element_create(env, parent, SAML_AUDIENCE_RESTRICTION_CONDITION, ns, &n);
	if (e && cond->audiences)
	{
		size = axutil_array_list_size(cond->audiences, env);
		for (i = 0; i < size; i++)
		{
			cns = axiom_namespace_create(env, SAML_NMSP_URI, SAML_PREFIX);
			ce = axiom_element_create(env, n, SAML_AUDIENCE, cns, &cn);
			axiom_element_set_text(ce, env, (axis2_char_t *)axutil_array_list_get(cond->audiences, env, i), cn);
		}
	}
	return n;
}

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_audi_restriction_cond_get_audiences(saml_audi_restriction_cond_t *cond, 
										 const axutil_env_t *env)
{
	return cond->audiences;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_audi_restriction_cond_set_audiences(saml_audi_restriction_cond_t *cond, 
										 const axutil_env_t *env, 
										 axutil_array_list_t *list)
{
	int i = 0, size = 0;
	char *val = NULL;
	if (cond->audiences)
	{
		size = axutil_array_list_size(cond->audiences, env);
		for (i = 0; i <size; i++)
		{
			val = axutil_array_list_get(cond->audiences, env, i);
			if (val)
			{
				AXIS2_FREE(env->allocator, val);
			}
		}
	}
	cond->audiences = list;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_audi_restriction_cond_remove_audiences(saml_audi_restriction_cond_t *cond, 
											const axutil_env_t *env, int index)
{
	axis2_char_t *val = NULL;
	if (cond->audiences && axutil_array_list_size(cond->audiences, env) > index)
	{
		val = axutil_array_list_remove(cond->audiences, env, index);			
		if (cond)
		{
			AXIS2_FREE(env->allocator, val);
		}
		return AXIS2_SUCCESS;		
	}
	else
	{
		return AXIS2_FAILURE;
	}
}

AXIS2_EXTERN int AXIS2_CALL 
saml_audi_restriction_cond_add_audience(saml_audi_restriction_cond_t *cond, 
										const axutil_env_t *env, 
										axis2_char_t *audience)
{
	if (!cond->audiences)
	{
		cond->audiences = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
	}
	axutil_array_list_add(cond->audiences, env, axutil_strdup(env, audience));
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN saml_condition_t * AXIS2_CALL 
saml_condition_create(const axutil_env_t *env)
{
	saml_condition_t *cond = AXIS2_MALLOC(env->allocator, sizeof(saml_condition_t));
	if (cond)
	{
		cond->type = SAML_COND_UNSPECFIED;
		cond->cond = NULL;
	}
	return cond;
}

AXIS2_EXTERN void AXIS2_CALL 
saml_condition_free(saml_condition_t *cond, const axutil_env_t *env)
{
	if (cond->type == SAML_COND_AUDI_RESTRICTION)
	{
		saml_audi_restriction_cond_free(cond->cond, env);		
	}
	AXIS2_FREE(env->allocator, cond);	
}

AXIS2_EXTERN int AXIS2_CALL 
saml_condition_build(saml_condition_t *cond, axiom_node_t *node, 
					 const axutil_env_t *env)
{
	axiom_element_t *element = NULL;	
	axis2_char_t *locname = NULL;
	if (axiom_node_get_node_type(node, env) != AXIOM_ELEMENT || (element = (axiom_element_t *)axiom_node_get_data_element(node, env)) == NULL)
	{
		return AXIS2_FAILURE;
	}
	locname = axiom_element_get_localname(element, env);
	if (0 == axutil_strcmp(locname, SAML_AUDIENCE_RESTRICTION_CONDITION))
	{
		if (cond->cond)
		{
			saml_audi_restriction_cond_free(cond->cond, env);
		}
		cond->cond = saml_audi_restriction_cond_create(env);
		cond->type = SAML_COND_AUDI_RESTRICTION;
		if (cond->cond)
		{
			return saml_audi_restriction_cond_build(cond->cond, node, env);
		}
	}
	return AXIS2_FAILURE;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_condition_to_om(saml_condition_t *cond, 
					 axiom_node_t *parent, const axutil_env_t *env)
{	
	if (cond->type == SAML_COND_AUDI_RESTRICTION)
	{
		return saml_audi_restriction_cond_to_om(cond->cond, parent, env);		
	}
	return NULL;
}

AXIS2_EXTERN saml_cond_type_t AXIS2_CALL 
saml_condition_get_type(saml_condition_t *cond, const axutil_env_t *env)
{
	return cond->type;
}

AXIS2_EXTERN void * AXIS2_CALL 
saml_condition_get_condition(saml_condition_t *cond, const axutil_env_t *env)
{
	return cond->cond;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_condition_set_type(saml_condition_t *cond, 
						const axutil_env_t *env, saml_cond_type_t type)
{
	cond->type = type;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_condition_set_condition(saml_condition_t *cond, 
							 const axutil_env_t *env, void * condition, 
							 saml_cond_type_t type)
{
	if (cond->type == SAML_COND_AUDI_RESTRICTION)
	{
		saml_audi_restriction_cond_free(cond->cond, env);		
	}
	cond->type = type;
	cond->cond = condition;
	return AXIS2_SUCCESS;
}
