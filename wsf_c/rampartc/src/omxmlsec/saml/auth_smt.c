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

AXIS2_EXTERN saml_auth_stmt_t * AXIS2_CALL 
saml_auth_stmt_create(const axutil_env_t *env)
{
	saml_auth_stmt_t *auth_stmt = AXIS2_MALLOC(env->allocator, sizeof(saml_auth_stmt_t));
	if (auth_stmt)
	{
		auth_stmt->auth_instanse = NULL;
		auth_stmt->auth_method = NULL;
		auth_stmt->ip = NULL;
		auth_stmt->dns = NULL;
		auth_stmt->auth_binding = NULL;
		auth_stmt->subject = saml_subject_create(env);
	}
	return auth_stmt;	
}

AXIS2_EXTERN void AXIS2_CALL 
saml_auth_stmt_free(saml_auth_stmt_t *auth_stmt, const axutil_env_t *env)
{
	if (auth_stmt->auth_instanse)
	{
		axutil_date_time_free(auth_stmt->auth_instanse, env);
	}
	if (auth_stmt->auth_method)
	{
		AXIS2_FREE(env->allocator, auth_stmt->auth_method);
	}
	/*if (auth_stmt->sub_locality)
	{
		saml_subject_locality_free(auth_stmt->sub_locality, env);
	}*/
	if (auth_stmt->auth_binding)
	{
		int i = 0;
		saml_auth_binding_t *auth_bind = NULL;
		for (i = 0; i < axutil_array_list_size(auth_stmt->auth_binding, env); i++)
		{
			 auth_bind = axutil_array_list_get(auth_stmt->auth_binding, env, i);
			 if (auth_bind)
			 {
				saml_auth_binding_free(auth_bind, env);
			 }
		}
		axutil_array_list_free(auth_stmt->auth_binding, env);
	}
	if (auth_stmt->subject)
	{
		saml_subject_free(auth_stmt->subject, env);
	}
	AXIS2_FREE(env->allocator, auth_stmt);
}


AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_build(saml_auth_stmt_t *auth_stmt, 
					 axiom_node_t *node, const axutil_env_t *env)
{
	axiom_element_t *element = NULL, *ce = NULL;
	axiom_node_t *cn = NULL;
	axiom_child_element_iterator_t *ci = NULL;
	axis2_char_t *time = NULL;
	saml_auth_binding_t *auth_bind = NULL;		
	if (axiom_node_get_node_type(node, env) != AXIOM_ELEMENT || (element = axiom_node_get_data_element(node, env)) == NULL)
	{
		return AXIS2_FAILURE;
	}			
	if ((auth_stmt->auth_method = axiom_element_get_attribute_value_by_name(element, env, SAML_AUTHENTICATION_METHOD)) == NULL)
	{
		return AXIS2_FAILURE;
	}
	if ((time = axiom_element_get_attribute_value_by_name(element, env, SAML_AUTHENTICATION_INSTANT)) != NULL)
	{
		auth_stmt->auth_instanse = axutil_date_time_create(env);
		axutil_date_time_deserialize_date_time(auth_stmt->auth_instanse, env, time);
	}	
	ci = axiom_element_get_child_elements(element, env, node);	
	if (ci)
	{
		while(AXIS2_TRUE == axiom_child_element_iterator_has_next(ci, env))
		{
			cn = axiom_child_element_iterator_next(ci, env);
			ce = axiom_node_get_data_element(cn, env);
			if (axutil_strcmp(axiom_element_get_localname(ce, env), SAML_SUBJECT) == 0)
			{
				auth_stmt->subject = saml_subject_create(env);
				saml_subject_build(auth_stmt->subject, cn, env);
			}
			else if (axutil_strcmp(axiom_element_get_localname(ce, env), SAML_SUBJECT_LOCALITY) == 0)
			{
				/*auth_stmt->sub_locality = saml_subject_locality_create(env);
				saml_subject_locality_build(auth_stmt->sub_locality, cn, env);*/
				auth_stmt->ip = axiom_element_get_attribute_value_by_name(ce, env, SAML_IP_ADDRESS);
				auth_stmt->dns = axiom_element_get_attribute_value_by_name(ce, env, SAML_DNS_ADDRESS);
			}
			else if (axutil_strcmp(axiom_element_get_localname(ce, env), SAML_AUTHORITY_BINDING) == 0)
			{
				auth_bind = saml_auth_binding_create(env);
				saml_auth_binding_build(auth_bind, cn, env);
				if (!auth_stmt->auth_binding)
				{
					auth_stmt->auth_binding = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF * 2);
				}
				axutil_array_list_add(auth_stmt->auth_binding, env, auth_bind);
			}
			else
			{				
				return AXIS2_FAILURE;
			}		
		}
	}
	else
	{
		return AXIS2_FAILURE;
	}
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL 
saml_auth_stmt_to_om(saml_auth_stmt_t *auth_stmt, 
					 axiom_node_t *parent, const axutil_env_t *env)
{
	int i = 0, size = 0;
	axiom_element_t *e = NULL, *ce = NULL;
	axiom_node_t *n = NULL, *cn = NULL;
	axiom_attribute_t *attr = NULL;
	axiom_namespace_t *ns = NULL;
	saml_auth_binding_t *auth_bind = NULL;
	ns = axiom_namespace_create(env, SAML_NMSP_URI, SAML_PREFIX);
	e = axiom_element_create(env, parent, SAML_AUTHENTICATION_STATEMENT, ns, &n);
	if (e)
	{
		if (auth_stmt->auth_instanse && auth_stmt->auth_method)
		{
			attr = axiom_attribute_create(env, SAML_AUTHENTICATION_METHOD, auth_stmt->auth_method, NULL);
			axiom_element_add_attribute(e, env, attr, n);
			attr = axiom_attribute_create(env, SAML_AUTHENTICATION_INSTANT, axutil_date_time_serialize_date_time(auth_stmt->auth_instanse, env), NULL);
			axiom_element_add_attribute(e, env, attr, n);						
		}		
		else
		{
			return NULL;
		}
		if (auth_stmt->subject)
		{
			saml_subject_to_om(auth_stmt->subject, n, env);
		}
		if (auth_stmt->ip || auth_stmt->dns)
		{
			ns = axiom_namespace_create(env, SAML_NMSP_URI, SAML_PREFIX);
			ce = axiom_element_create(env, n, SAML_SUBJECT_LOCALITY, ns, &cn); 
			if (auth_stmt->ip)
			{
				attr = axiom_attribute_create(env, SAML_IP_ADDRESS, auth_stmt->ip, NULL);
				axiom_element_add_attribute(ce, env, attr, cn);
			}
			if (auth_stmt->dns)
			{
				attr = axiom_attribute_create(env, SAML_DNS_ADDRESS, auth_stmt->dns, NULL);
				axiom_element_add_attribute(ce, env, attr, cn);									
			}
		}
		if (auth_stmt->auth_binding)
		{
			size = axutil_array_list_size(auth_stmt->auth_binding, env);
			for (i = 0; i < size; i++)
			{
				auth_bind = axutil_array_list_get(auth_stmt->auth_binding, env, i);
				saml_auth_binding_to_om(auth_bind, n, env);
			}
		}
	}	
	return n;
}

AXIS2_EXTERN saml_subject_t * AXIS2_CALL 
saml_auth_stmt_get_subject(saml_auth_stmt_t *auth_stmt, const axutil_env_t *env)
{
	return auth_stmt->subject;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_auth_stmt_get_auth_method(saml_auth_stmt_t *auth_stmt, const axutil_env_t *env)
{
	return auth_stmt->auth_method;
}

AXIS2_EXTERN axutil_date_time_t * AXIS2_CALL 
saml_auth_stmt_get_auth_instant(saml_auth_stmt_t *auth_stmt, const axutil_env_t *env)
{
	return auth_stmt->auth_instanse;
}

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_auth_stmt_get_auth_bindings(saml_auth_stmt_t *auth_stmt, const axutil_env_t *env)
{
	return auth_stmt->auth_binding;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_auth_stmt_get_subject_ip(saml_auth_stmt_t *auth_stmt, const axutil_env_t *env)
{
	return auth_stmt->ip;	
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_auth_stmt_get_subject_dns(saml_auth_stmt_t *auth_stmt, const axutil_env_t *env)
{
	return auth_stmt->dns;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_set_auth_method(saml_auth_stmt_t *auth_stmt, 
							   const axutil_env_t *env, axis2_char_t *method)
{
	if (auth_stmt->auth_method)
	{
		AXIS2_FREE(env->allocator, auth_stmt->auth_method);
	}
	auth_stmt->auth_method = axutil_strdup(env, method);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_set_auth_instant(saml_auth_stmt_t *auth_stmt, 
								const axutil_env_t *env, axutil_date_time_t *dt)
{
	if (auth_stmt->auth_instanse)
	{
		axutil_date_time_free(auth_stmt->auth_instanse, env);
	}
	auth_stmt->auth_instanse = dt;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_set_auth_bindings(saml_auth_stmt_t *auth_stmt, 
								 const axutil_env_t *env, axutil_array_list_t *list)
{
	int i = 0, size = 0;
	saml_auth_binding_t *bind = NULL;
	if (auth_stmt->auth_binding)
	{
		size = axutil_array_list_size(auth_stmt->auth_binding, env);
		for (i = 0; i <size; i++)
		{
			bind = axutil_array_list_get(auth_stmt->auth_binding, env, i);
			if (bind)
			{
				saml_auth_binding_free(bind, env);
			}
		}
	}
	auth_stmt->auth_binding = list;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_add_auth_binding(saml_auth_stmt_t *auth_stmt, 
								const axutil_env_t *env, saml_auth_binding_t *bind)
{
	if (!auth_stmt->auth_binding)
	{
		auth_stmt->auth_binding = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
	}
	axutil_array_list_add(auth_stmt->auth_binding, env, bind);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_remove_auth_binding(saml_auth_stmt_t *auth_stmt, 
								   const axutil_env_t *env, int index)
{
	saml_auth_binding_t *bind = NULL;
	if (auth_stmt->auth_binding && axutil_array_list_size(auth_stmt->auth_binding, env) > index)
	{
		bind = axutil_array_list_remove(auth_stmt->auth_binding, env, index);			
		if (bind)
		{
			saml_auth_binding_free(bind, env);	
		}
		return AXIS2_SUCCESS;		
	}
	else
	{
		return AXIS2_FAILURE;
	}
}

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_set_subject_ip(saml_auth_stmt_t *auth_stmt, 
							  const axutil_env_t *env, axis2_char_t *ip)
{
	if (auth_stmt->ip)
	{
		AXIS2_FREE(env->allocator, auth_stmt->ip);
	}
	auth_stmt->ip = axutil_strdup(env, ip);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_set_subject_dns(saml_auth_stmt_t *auth_stmt, 
							   const axutil_env_t *env, axis2_char_t *dns)
{
	if (auth_stmt->dns)
	{
		AXIS2_FREE(env->allocator, auth_stmt->dns);
	}
	auth_stmt->dns = axutil_strdup(env, dns);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_set_subject(saml_auth_stmt_t *auth_stmt, 
						   const axutil_env_t *env, saml_subject_t *subject)
{
	if (auth_stmt->subject)
	{
		saml_subject_free(auth_stmt->subject, env);
	}
	auth_stmt->subject = subject;	
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN saml_subject_locality_t * AXIS2_CALL 
saml_subject_locality_create(const axutil_env_t *env)
{
	saml_subject_locality_t *sub_locality = AXIS2_MALLOC(env->allocator, sizeof(saml_subject_locality_t));
	if (sub_locality)
	{
		sub_locality->ip = NULL;
		sub_locality->dns = NULL;
		return sub_locality;
	}
	return NULL;
}

AXIS2_EXTERN void AXIS2_CALL 
saml_subject_locality_free(saml_subject_locality_t *sub_locality, 
						   const axutil_env_t *env)
{
	if (sub_locality->dns)
	{
		AXIS2_FREE(env->allocator, sub_locality->dns);
	}
	if (sub_locality->ip)
	{
		AXIS2_FREE(env->allocator, sub_locality->ip);
	}	
	AXIS2_FREE(env->allocator, sub_locality);	
}

AXIS2_EXTERN int AXIS2_CALL 
saml_subject_locality_build(saml_subject_locality_t *sub_locality, 
							axiom_node_t *node, const axutil_env_t *env)
{
	axutil_hash_t *attr_hash = NULL;
	axiom_element_t *element = NULL;
	axutil_hash_index_t *hi = NULL;		
	if (axiom_node_get_node_type(node, env) != AXIOM_ELEMENT || (element = (axiom_element_t *)axiom_node_get_data_element(node, env)) == NULL)
	{
		return AXIS2_FAILURE;
	}	
	attr_hash = axiom_element_get_all_attributes(element, env);	
	for (hi = axutil_hash_first(attr_hash, env); hi; hi = axutil_hash_next(env, hi))
	{
		void *v = NULL;
        axutil_hash_this(hi, NULL, NULL, &v);
		if (v)
		{
			axis2_char_t *attr_val = NULL;
			axis2_char_t *attr_lname = NULL;
			axiom_attribute_t *attr = (axiom_attribute_t*)v;			
			attr_val = axiom_attribute_get_value(attr, env);			
			attr_lname = axiom_attribute_get_localname(attr, env);
			if (0 == axutil_strcmp(attr_lname, SAML_IP_ADDRESS))
			{
				sub_locality->ip = attr_val;
			}        
			else if (0 == axutil_strcmp(attr_lname, SAML_DNS_ADDRESS))
			{
				sub_locality->dns = attr_val;				
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
saml_subject_locality_to_om(saml_subject_locality_t *sub_locality, 
							axiom_node_t *parent, const axutil_env_t *env)
{
	axiom_element_t *e = NULL;
	axiom_node_t *n = NULL;
	axiom_attribute_t *attr = NULL;
	axiom_namespace_t *ns = NULL;
	ns = axiom_namespace_create(env, SAML_NMSP_URI, SAML_PREFIX);
	e = axiom_element_create(env, parent, SAML_SUBJECT_LOCALITY, ns, &n);
	if (e)
	{
		if (sub_locality->dns)
		{
			attr = axiom_attribute_create(env, SAML_DNS_ADDRESS, sub_locality->dns, NULL);
			axiom_element_add_attribute(e, env, attr, n);
		}
		if (sub_locality->ip)
		{
			attr = axiom_attribute_create(env, SAML_IP_ADDRESS, sub_locality->ip, NULL);
			axiom_element_add_attribute(e, env, attr, n);						
		}
	}	
	return n;
}

AXIS2_EXTERN saml_auth_binding_t * AXIS2_CALL 
saml_auth_binding_create(const axutil_env_t *env)
{
	saml_auth_binding_t *auth_bind = AXIS2_MALLOC(env->allocator, sizeof(saml_auth_binding_t));
	if (auth_bind)
	{
		auth_bind->auth_kind = NULL;
		auth_bind->binding = NULL;
		auth_bind->location = NULL;
		return auth_bind;
	}
	return NULL;
}

AXIS2_EXTERN void AXIS2_CALL 
saml_auth_binding_free(saml_auth_binding_t *auth_bind, const axutil_env_t *env)
{
	if (auth_bind->auth_kind)
	{
		AXIS2_FREE(env->allocator, auth_bind->auth_kind);
	}
	if (auth_bind->binding)
	{
		AXIS2_FREE(env->allocator, auth_bind->binding);
	}
	if (auth_bind->location)
	{
		AXIS2_FREE(env->allocator, auth_bind->location);
	}
	AXIS2_FREE(env->allocator, auth_bind);
}

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_binding_build(saml_auth_binding_t *auth_bind, axiom_node_t *node, 
						const axutil_env_t *env)
{
	axiom_element_t *element = NULL;
	
	if (axiom_node_get_node_type(node, env) != AXIOM_ELEMENT || (element = (axiom_element_t *)axiom_node_get_data_element(node, env)) == NULL)
	{
		return AXIS2_FAILURE;
	}
	if ((auth_bind->auth_kind = axiom_element_get_attribute_value_by_name(element, env, SAML_AUTHORITY_KIND)) == NULL ||
		(auth_bind->binding = axiom_element_get_attribute_value_by_name(element, env, SAML_BINDING)) == NULL ||
		(auth_bind->location = axiom_element_get_attribute_value_by_name(element, env, SAML_LOCATION)) == NULL)
	{
		return AXIS2_FAILURE;
	}	
	return AXIS2_SUCCESS;
}


AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_auth_binding_to_om(saml_auth_binding_t *auth_binding, 
						axiom_node_t *parent, const axutil_env_t *env)
{
	axiom_element_t *e = NULL;
	axiom_node_t *n = NULL;
	axiom_attribute_t *attr = NULL;
	axiom_namespace_t *ns = NULL;
	ns = axiom_namespace_create(env, SAML_NMSP_URI, SAML_PREFIX);
	e = axiom_element_create(env, parent, SAML_AUTHORITY_BINDING, ns, &n);
	if (e)
	{
		if (auth_binding->auth_kind && auth_binding->binding && auth_binding->location)
		{
			attr = axiom_attribute_create(env, SAML_AUTHORITY_KIND, auth_binding->auth_kind, NULL);
			axiom_element_add_attribute(e, env, attr, n);
			attr = axiom_attribute_create(env, SAML_BINDING, auth_binding->binding, NULL);
			axiom_element_add_attribute(e, env, attr, n);			
			attr = axiom_attribute_create(env, SAML_LOCATION, auth_binding->location, NULL);
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
saml_auth_binding_get_authoity_kind(saml_auth_binding_t *auth_binding, 
									const axutil_env_t *env)
{
	return auth_binding->auth_kind;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_auth_binding_get_binding(saml_auth_binding_t *auth_binding, 
							  const axutil_env_t *env)
{
	return auth_binding->binding;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_auth_binding_get_location(saml_auth_binding_t *auth_binding, 
							   const axutil_env_t *env)
{
	return auth_binding->location;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_binding_set_authority_kind(saml_auth_binding_t *auth_binding, 
									 const axutil_env_t *env, axis2_char_t *auth_kind)
{
	if (auth_binding->auth_kind)
	{
		AXIS2_FREE(env->allocator, auth_binding->auth_kind);
	}
	auth_binding->auth_kind = axutil_strdup(env, auth_kind);
	return AXIS2_SUCCESS;	
}

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_binding_set_binding(saml_auth_binding_t *auth_binding, 
							  const axutil_env_t *env, axis2_char_t *binding)
{
	if (auth_binding->binding)
	{
		AXIS2_FREE(env->allocator, auth_binding->binding);
	}
	auth_binding->binding = axutil_strdup(env, binding);
	return AXIS2_SUCCESS;	
}

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_binding_set_location(saml_auth_binding_t *auth_binding, 
							   const axutil_env_t *env, axis2_char_t *location)
{
	if (auth_binding->location)
	{
		AXIS2_FREE(env->allocator, auth_binding->location);
	}
	auth_binding->location = axutil_strdup(env, location);
	return AXIS2_SUCCESS;	
}

