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

AXIS2_EXTERN saml_attr_desig_t * AXIS2_CALL 
saml_attr_desig_create(const axutil_env_t *env)
{
	saml_attr_desig_t *attr_desig = AXIS2_MALLOC(env->allocator, sizeof(saml_attr_desig_t));
	if (attr_desig)
	{
		attr_desig->attr_name = NULL;
		attr_desig->attr_nmsp = NULL;
	}
	return attr_desig;
}

AXIS2_EXTERN void AXIS2_CALL 
saml_attr_desig_free(saml_attr_desig_t *attr_desig, const axutil_env_t *env)
{
	if (attr_desig->attr_name)
	{
		AXIS2_FREE(env->allocator, attr_desig->attr_name);
	}
	if (attr_desig->attr_nmsp)
	{
		AXIS2_FREE(env->allocator, attr_desig->attr_nmsp);
	}
	AXIS2_FREE(env->allocator, attr_desig);
}

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_desig_build(saml_attr_desig_t *attr_desig, 
					  axiom_node_t *node, const axutil_env_t *env)
{
	axutil_hash_t *attr_hash = NULL;
	axutil_hash_index_t *hi = NULL;
	axiom_element_t *element = NULL;
	
	if (axiom_node_get_node_type(node, env) != AXIOM_ELEMENT || (element = (axiom_element_t *)axiom_node_get_data_element(node, env)) == NULL)
	{
		return AXIS2_FAILURE;
	}	
	if ((attr_desig->attr_name = axiom_element_get_attribute_value_by_name(element, env, SAML_ATTRIBUTE_NAME)) == NULL || (attr_desig->attr_nmsp = axiom_element_get_attribute_value_by_name(element, env, SAML_ATTRIBUTE_NAMESPACE)) == NULL)
	{
		return AXIS2_FAILURE;
	}
	attr_hash = axiom_element_get_all_attributes(element, env);		
	for (hi = axutil_hash_first(attr_hash, env); hi != NULL; hi = axutil_hash_next(env, hi))
	{
		void *v = NULL;
        axutil_hash_this(hi, NULL, NULL, &v);
		if (v)
		{
			axis2_char_t *attr_name = NULL;
			axiom_attribute_t *attr = (axiom_attribute_t*)v;			
			attr_name = axiom_attribute_get_localname(attr, env);			
			if (0 != axutil_strcmp(attr_name, SAML_ATTRIBUTE_NAME) && 0 != axutil_strcmp(attr_name, SAML_ATTRIBUTE_NAMESPACE))
			{
				return AXIS2_FALSE;
			}           	
		}
	}
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_attr_desig_to_om(saml_attr_desig_t *attr_desig, 
					  axiom_node_t *parent, const axutil_env_t *env)
{
	axiom_element_t *e = NULL;
	axiom_node_t *n = NULL;
	axiom_attribute_t *attr = NULL;
	axiom_namespace_t *ns = NULL;
	ns = axiom_namespace_create(env, SAML_NMSP_URI, SAML_PREFIX);
	e = axiom_element_create(env, parent, SAML_ATTRIBUTE_DESIGNATOR, ns, &n);
	if (e)
	{
		if (attr_desig->attr_name && attr_desig->attr_nmsp)
		{
			attr = axiom_attribute_create(env, SAML_ATTRIBUTE_NAME, attr_desig->attr_name, NULL);
			axiom_element_add_attribute(e, env, attr, n);
			attr = axiom_attribute_create(env, SAML_ATTRIBUTE_NAMESPACE, attr_desig->attr_nmsp, NULL);
			axiom_element_add_attribute(e, env, attr, n);			
		}
		else
		{
			return NULL;
		}
	}
	return n;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_attr_desig_get_name(saml_attr_desig_t *attr_desig, const axutil_env_t *env)
{
	return attr_desig->attr_name;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_attr_desig_get_namespace(saml_attr_desig_t *attr_desig, const axutil_env_t *env)
{
	return attr_desig->attr_nmsp;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_desig_set_name(saml_attr_desig_t *attr_desig, 
						 const axutil_env_t *env, axis2_char_t *name)
{
	if (attr_desig->attr_name)
	{
		AXIS2_FREE(env->allocator, name);
	}
	attr_desig->attr_name = axutil_strdup(env, name);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_desig_set_namespace(saml_attr_desig_t *attr_desig, 
							  const axutil_env_t *env, axis2_char_t *name_space)
{
	if (attr_desig->attr_nmsp)
	{
		AXIS2_FREE(env->allocator, name_space);
	}
	attr_desig->attr_nmsp = axutil_strdup(env, name_space);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN saml_attr_t * AXIS2_CALL 
saml_attr_create(const axutil_env_t *env)
{
	saml_attr_t *attr = AXIS2_MALLOC(env->allocator, sizeof(saml_attr_t));
	if (attr)
	{
		attr->attr_name = NULL;
		attr->attr_nmsp = NULL;	
		attr->attr_value = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
	}
	return attr;
}

AXIS2_EXTERN void AXIS2_CALL 
saml_attr_free(saml_attr_t *attr, const axutil_env_t *env)
{
	/*int i = 0;
	char *val = NULL;*/
	if (attr->attr_name)
	{
		AXIS2_FREE(env->allocator, attr->attr_name);
	}
	if (attr->attr_nmsp)
	{
		AXIS2_FREE(env->allocator, attr->attr_nmsp);
	}
	if (attr->attr_value)
	{
		/*for(i = 0; i < axutil_array_list_size(attr->attr_value, env); i++)
		{
			val = axutil_array_list_get(attr->attr_value, env, i);
			if (val)
				AXIS2_FREE(env->allocator, val);
		}*/
		axutil_array_list_free(attr->attr_value, env);
	}
	AXIS2_FREE(env->allocator, attr);
}

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_build(saml_attr_t *attr, axiom_node_t *node, const axutil_env_t *env)
{
	axutil_hash_t *attr_hash = NULL;
	axutil_hash_index_t *hi = NULL;
	axiom_element_t *element = NULL;
	axiom_element_t *fce = NULL;
	axiom_node_t *fcn = NULL;
	axiom_child_element_iterator_t *ci = NULL;
	if (axiom_node_get_node_type(node, env) != AXIOM_ELEMENT || (element = (axiom_element_t *)axiom_node_get_data_element(node, env)) == NULL)
	{
		return AXIS2_FAILURE;
	}	
	if ((attr->attr_name = axiom_element_get_attribute_value_by_name(element, env, SAML_ATTRIBUTE_NAME)) == NULL || (attr->attr_nmsp = axiom_element_get_attribute_value_by_name(element, env, SAML_ATTRIBUTE_NAMESPACE)) == NULL)
	{
		return AXIS2_FAILURE;
	}
	attr_hash = axiom_element_get_all_attributes(element, env);		
	for (hi = axutil_hash_first(attr_hash, env); hi != NULL; hi = axutil_hash_next(env, hi))
	{
		void *v = NULL;
        axutil_hash_this(hi, NULL, NULL, &v);
		if (v)
		{
			axis2_char_t *attr_local_name = NULL;
			axiom_attribute_t *attr = (axiom_attribute_t*)v;			
			attr_local_name = axiom_attribute_get_localname(attr, env);			
			if (0 != axutil_strcmp(attr_local_name, SAML_ATTRIBUTE_NAME) && 0 != axutil_strcmp(attr_local_name, SAML_ATTRIBUTE_NAMESPACE))
			{
				return AXIS2_FALSE;
			}           	
		}
	}
	ci = axiom_element_get_child_elements(element, env, node);
	if (ci)
	{
		while(AXIS2_TRUE == axiom_child_element_iterator_has_next(ci, env))
		{
		
			fcn = axiom_child_element_iterator_next(ci, env);
			fce = axiom_node_get_data_element(fcn, env);
			if (strcmp(axiom_element_get_localname(fce, env), SAML_ATTRIBUTE_VALUE) == 0)
			{
				axiom_node_t *temp = axiom_node_get_first_child(fcn, env);
				axutil_array_list_add(attr->attr_value, env, temp);									
			}		
			else
			{
				return AXIS2_FAILURE;
			}		
		}
	}
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_attr_to_om(saml_attr_t *sattr, axiom_node_t *parent, const axutil_env_t *env)
{
	int i = 0, size = 0;
	axiom_element_t *e = NULL, *ce = NULL;
	axiom_node_t *n = NULL, *cn = NULL;
	axiom_attribute_t *attr = NULL;
	axiom_namespace_t *ns = NULL;
	ns = axiom_namespace_create(env, SAML_NMSP_URI, SAML_PREFIX);
	e = axiom_element_create(env, parent, SAML_ATTRIBUTE, ns, &n);
	if (e)
	{
		if (sattr->attr_name && sattr->attr_nmsp)
		{
			attr = axiom_attribute_create(env, SAML_ATTRIBUTE_NAME, sattr->attr_name, NULL);
			axiom_element_add_attribute(e, env, attr, n);
			attr = axiom_attribute_create(env, SAML_ATTRIBUTE_NAMESPACE, sattr->attr_nmsp, NULL);
			axiom_element_add_attribute(e, env, attr, n);			
		}
		else
		{
			return NULL;
		}
		if (sattr->attr_value)
		{			
			size = axutil_array_list_size(sattr->attr_value, env);
			
			for (i = 0; i < size; i++)
			{
				ns = axiom_namespace_create(env, SAML_NMSP_URI, SAML_PREFIX);
				ce = axiom_element_create(env, n, SAML_ATTRIBUTE_VALUE, ns, &cn);
				if (ce)
				{
					axiom_node_add_child(cn, env, (axiom_node_t*)axutil_array_list_get(sattr->attr_value, env, i));
				}
			}
		}
	}
	return n;																																
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_attr_get_name(saml_attr_t *attr_stmt, const axutil_env_t *env)
{
	return attr_stmt->attr_name;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_attr_get_namespace(saml_attr_t *attr_stmt, const axutil_env_t *env)
{
	return attr_stmt->attr_nmsp;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_set_name(saml_attr_t *attr_stmt, const axutil_env_t *env, axis2_char_t *name)
{
	if (attr_stmt->attr_name)
	{
		AXIS2_FREE(env->allocator, name);
	}
	attr_stmt->attr_name = axutil_strdup(env, name);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_set_namespace(saml_attr_t *attr_stmt, 
						const axutil_env_t *env, axis2_char_t *name_space)
{
	if (attr_stmt->attr_nmsp)
	{
		AXIS2_FREE(env->allocator, name_space);
	}
	attr_stmt->attr_nmsp = axutil_strdup(env, name_space);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_set_values(saml_attr_t *attr, 
						  const axutil_env_t *env, axutil_array_list_t *list)
{
	/*int i = 0, size = 0;
	axis2_char_t *val = NULL;*/
	if (attr->attr_value)
	{
		/*size = axutil_array_list_size(attr->attr_value, env);
		for (i = 0; i <size; i++)
		{
			val = axutil_array_list_get(attr->attr_value, env, i);
			if (val)
			{
				AXIS2_FREE(env->allocator, val);
			}
		}*/
		axutil_array_list_free(attr->attr_value, env);
	}
	attr->attr_value = list;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_remove_value(saml_attr_t *attr, const axutil_env_t *env, int index)
{
	/*axis2_char_t *val = NULL;*/
	if (attr->attr_value && axutil_array_list_size(attr->attr_value, env) > index)
	{
		axutil_array_list_remove(attr->attr_value, env, index);			
		/*if (attr)
		{
			AXIS2_FREE(env->allocator, val);
		}*/		
		return AXIS2_SUCCESS;
	}
	else
	{
		return AXIS2_FAILURE;
	}
}

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_add_value(saml_attr_t *attr, 
						 const axutil_env_t *env, axiom_node_t *value)
{
	if (!attr->attr_value)
	{
		attr->attr_value = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
	}
	axutil_array_list_add(attr->attr_value, env, value);
	return AXIS2_SUCCESS;
}


AXIS2_EXTERN saml_attr_stmt_t * AXIS2_CALL 
saml_attr_stmt_create(const axutil_env_t *env)
{	
	saml_attr_stmt_t *attr_stmt = AXIS2_MALLOC(env->allocator, sizeof(saml_attr_stmt_t));
	if (attr_stmt)
	{	
		attr_stmt->attribute = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
		attr_stmt->subject = NULL;
	}
	return attr_stmt;
}

AXIS2_EXTERN void AXIS2_CALL 
saml_attr_stmt_free(saml_attr_stmt_t *attr_stmt, const axutil_env_t *env)
{
	int i = 0, size = 0;
	saml_attr_t *attr = NULL;
	if (attr_stmt->attribute)
	{
		size = axutil_array_list_size(attr_stmt->attribute, env);
		for (i = 0; i < size; i++)
		{
			attr = axutil_array_list_get(attr_stmt->attribute, env, i);
			saml_attr_free(attr, env);
		}
	}
	if (attr_stmt->subject)
	{
		saml_subject_free(attr_stmt->subject, env);
	}
	AXIS2_FREE(env->allocator, attr_stmt);
}

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_stmt_build(saml_attr_stmt_t *attr_stmt, 
					 axiom_node_t *node, const axutil_env_t *env)
{
	axiom_element_t *element = NULL;	
	axiom_element_t *fce = NULL;
	axiom_node_t *fcn = NULL;
	saml_attr_t *attr = NULL;
	axiom_child_element_iterator_t *ci = NULL;
	if (axiom_node_get_node_type(node, env) != AXIOM_ELEMENT || (element = (axiom_element_t *)axiom_node_get_data_element(node, env)) == NULL)
	{
		return AXIS2_FAILURE;
	}
	ci = axiom_element_get_child_elements(element, env, node);
	if (ci)
	{
		while(AXIS2_TRUE == axiom_child_element_iterator_has_next(ci, env))
		{
			fcn = axiom_child_element_iterator_next(ci, env);
			fce = axiom_node_get_data_element(fcn, env);
			if (strcmp(axiom_element_get_localname(fce, env), SAML_SUBJECT) == 0)
			{
				attr_stmt->subject = saml_subject_create(env);
				saml_subject_build(attr_stmt->subject, fcn, env);
			}
			else if (strcmp(axiom_element_get_localname(fce, env), SAML_ATTRIBUTE) == 0)
			{
				attr = saml_attr_create(env);
				saml_attr_build(attr, fcn, env);
				axutil_array_list_add(attr_stmt->attribute, env, attr);									
			}
			else
			{
				return AXIS2_FAILURE;
			}		
		}
	}
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_attr_stmt_to_om(saml_attr_stmt_t *attr_stmt, 
					 axiom_node_t *parent, const axutil_env_t *env)
{	
	int i = 0, size = 0;
	axiom_element_t *e = NULL;
	axiom_node_t *n = NULL;	
	axiom_namespace_t *ns = NULL;
	ns = axiom_namespace_create(env, SAML_NMSP_URI, SAML_PREFIX);
	e = axiom_element_create(env, parent, SAML_ATTRIBUTE_STATEMENT, ns, &n);
	if (e)
	{
		if (attr_stmt->subject)
		{
			saml_subject_to_om(attr_stmt->subject, n, env);
		}
		if (attr_stmt->attribute)
		{
			size = axutil_array_list_size(attr_stmt->attribute, env);
			for (i = 0; i < size; i++)
			{				
				saml_attr_to_om(axutil_array_list_get(attr_stmt->attribute, env, i), n, env);				
			}
		}
	}
	return n;
}

AXIS2_EXTERN saml_subject_t * AXIS2_CALL 
saml_attr_stmt_get_subject(saml_attr_stmt_t *attr_stmt, const axutil_env_t *env)
{
	return attr_stmt->subject;
}

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_attr_stmt_get_attributes(saml_attr_stmt_t *attr_stmt, const axutil_env_t *env)
{
	return attr_stmt->attribute;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_stmt_set_subject(saml_attr_stmt_t *attr_stmt, 
						   const axutil_env_t *env, saml_subject_t *subject)
{
	if (attr_stmt->subject)
	{
		saml_subject_free(attr_stmt->subject, env);		
	}
	attr_stmt->subject = subject;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_stmt_set_attributes(saml_attr_stmt_t *attr_stmt, 
							  const axutil_env_t *env, axutil_array_list_t *list)
{
	int i = 0, size = 0;
	saml_attr_t *attr = NULL;
	if (attr_stmt->attribute)
	{
		size = axutil_array_list_size(attr_stmt->attribute, env);
		for (i = 0; i <size; i++)
		{
			attr = axutil_array_list_get(attr_stmt->attribute, env, i);
			if (attr)
			{
				AXIS2_FREE(env->allocator, attr);
			}
		}
	}
	attr_stmt->attribute = list;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_stmt_remove_attribute(saml_attr_stmt_t *attr_stmt, 
								const axutil_env_t *env, int index)
{
	saml_attr_t *attr = NULL;
	if (attr_stmt->attribute && axutil_array_list_size(attr_stmt->attribute, env) > index)
	{
		attr = axutil_array_list_remove(attr_stmt->attribute, env, index);			
		if (attr)
		{
			AXIS2_FREE(env->allocator, attr);
		}
		return AXIS2_SUCCESS;		
	}
	else
	{
		return AXIS2_FAILURE;
	}
}

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_stmt_add_attribute(saml_attr_stmt_t *attr_stmt, 
							 const axutil_env_t *env, saml_attr_t *attribute)
{
	if (!attr_stmt->attribute)
	{
		attr_stmt->attribute = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
	}
	axutil_array_list_add(attr_stmt->attribute, env, attribute);
	return AXIS2_SUCCESS;
}
