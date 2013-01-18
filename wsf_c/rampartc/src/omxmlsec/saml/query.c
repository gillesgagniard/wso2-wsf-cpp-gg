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
#include <saml_req.h>

AXIS2_EXTERN saml_subject_query_t* AXIS2_CALL saml_subject_query_create(const axutil_env_t *env)
{
	saml_subject_query_t *subject_query = NULL;
		
	subject_query = (saml_subject_query_t *)AXIS2_MALLOC(env->allocator, 
												sizeof(saml_subject_query_t));
	if(subject_query)
	{
		subject_query->subject = saml_subject_create(env);
	}
	return subject_query;
}

AXIS2_EXTERN void AXIS2_CALL saml_subject_query_free(saml_subject_query_t *subject_query, const axutil_env_t *env)
{
	if(subject_query->subject)
	{
		saml_subject_free(subject_query->subject, env);
	}
	AXIS2_FREE(env->allocator, subject_query);
	subject_query = NULL;
}


AXIS2_EXTERN saml_authentication_query_t* AXIS2_CALL saml_authentication_query_create(const axutil_env_t *env)
{
	saml_authentication_query_t *authentication_query = NULL;
	
	authentication_query = (saml_authentication_query_t*)AXIS2_MALLOC(env->allocator, 
															sizeof(saml_authentication_query_t));
	if(authentication_query)
	{
		authentication_query->subject = saml_subject_create(env);
		authentication_query->auth_method = NULL;
	}
	return authentication_query;
}

AXIS2_EXTERN void AXIS2_CALL saml_authentication_query_free(saml_authentication_query_t *auth_query, const axutil_env_t *env)
{
	if(auth_query->auth_method)
	{
		AXIS2_FREE(env->allocator, auth_query->auth_method);
	}
	if(auth_query->subject)
	{
		saml_subject_free(auth_query->subject, env);
	}
	AXIS2_FREE(env->allocator, auth_query);
	auth_query = NULL;
}

AXIS2_EXTERN saml_attr_query_t* AXIS2_CALL saml_attr_query_create(const axutil_env_t *env)
{
	saml_attr_query_t *attribute_query = NULL;
	attribute_query = (saml_attr_query_t *)AXIS2_MALLOC(env->allocator, 
														sizeof(saml_attr_query_t));
	
	if(attribute_query)
	{
		attribute_query->resource = NULL;
		attribute_query->subject = saml_subject_create(env);
		attribute_query->attr_desigs = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
		
	}
	return attribute_query;
}

AXIS2_EXTERN void AXIS2_CALL saml_attr_query_free(saml_attr_query_t *attr_query, const axutil_env_t *env)
{
	int size = 0, i = 0;
	saml_attr_desig_t *attr_desig = NULL;

	if(attr_query->resource)
	{
		AXIS2_FREE(env->allocator, attr_query->resource);
	}
	if(attr_query->subject)
	{
		saml_subject_free(attr_query->subject, env);
	}
	if(attr_query->attr_desigs)
	{
		size = axutil_array_list_size(attr_query->attr_desigs, env);
		for(i = 0; i < size; i++)
		{
			attr_desig = (saml_attr_desig_t*) axutil_array_list_get(attr_query->attr_desigs, env, i);
			if(attr_desig)
				saml_attr_desig_free(attr_desig, env);
		}

		axutil_array_list_free(attr_query->attr_desigs, env);
	}

	AXIS2_FREE(env->allocator, attr_query);
	attr_query = NULL;
}

AXIS2_EXTERN saml_autho_decision_query_t* AXIS2_CALL saml_autho_decision_query_create(const axutil_env_t *env)
{
	saml_autho_decision_query_t *autho_decision_query = NULL;
	
	autho_decision_query = (saml_autho_decision_query_t *)AXIS2_MALLOC(env->allocator, 
																sizeof(saml_autho_decision_query_t));
	
	if(autho_decision_query)
	{
		autho_decision_query->subject = saml_subject_create(env);
		autho_decision_query->resource = NULL;
		autho_decision_query->saml_actions = axutil_array_list_create(env, 
												SAML_ARRAY_LIST_DEF);
		autho_decision_query->evidence = saml_evidence_create(env);
	}
	return autho_decision_query;
}

AXIS2_EXTERN void AXIS2_CALL saml_autho_decision_query_free(saml_autho_decision_query_t* autho_decision_query, 
														   const axutil_env_t *env)
{
	int size = 0, i = 0;
	saml_action_t *action = NULL;

	if(autho_decision_query->evidence)
	{
		saml_evidence_free(autho_decision_query->evidence, env);
	}
	if(autho_decision_query->resource)
	{
		AXIS2_FREE(env->allocator, autho_decision_query->resource);
	}
	if(autho_decision_query->subject)
	{
		saml_subject_free(autho_decision_query->subject, env);
	}
	if(autho_decision_query->saml_actions)
	{
		size = axutil_array_list_size(autho_decision_query->saml_actions, env);
		for(i = 0; i < size ; i++)
		{
			action = (saml_action_t *)axutil_array_list_get(autho_decision_query->saml_actions, env, i);
			if(action)
				saml_action_free(action, env);
		}
		axutil_array_list_free(autho_decision_query->saml_actions, env);
	}
	AXIS2_FREE(env->allocator, autho_decision_query);
	autho_decision_query = NULL;
	
}

AXIS2_EXTERN int AXIS2_CALL saml_subject_query_build(saml_subject_query_t* subject_query, 
													 axiom_node_t *node, 
													 const axutil_env_t *env)

{

	axiom_element_t *element = NULL;
	axiom_child_element_iterator_t *iterator = NULL;
	axiom_node_t *child_node = NULL;
	
	if (axiom_node_get_node_type(node, env) != AXIOM_ELEMENT)
	{
		return AXIS2_FAILURE;
	}
	
	if ((element = axiom_node_get_data_element(node, env)) == NULL)
	{
		return AXIS2_FAILURE;
	}
	
	iterator = axiom_element_get_child_elements(element, env, node);

	if(iterator)
	{
		while(axiom_child_element_iterator_has_next(iterator, env))
		{
			child_node = axiom_child_element_iterator_next(iterator, env);
			element = (axiom_element_t *)axiom_node_get_data_element(child_node, env);

			if(element != NULL && !(axutil_strcmp(axiom_element_get_localname(element, env), 
																		SAML_SUBJECT)))
			{
				if(subject_query->subject)
					return 	saml_subject_build(subject_query->subject, child_node, env);
				else 
					return AXIS2_FAILURE; /*subject query saml subject does not exist*/
			}
		}
		return AXIS2_SUCCESS;
	}
	else
		return AXIS2_FAILURE;
	
}

AXIS2_EXTERN axiom_node_t* AXIS2_CALL saml_subject_query_to_om(saml_subject_query_t *subject_query, 
															   axiom_node_t *parent, 
															   const axutil_env_t *env)
{

	axiom_element_t *e = NULL;
	axiom_node_t *n = NULL;	
	axiom_namespace_t *ns = NULL;

	ns = axiom_namespace_create(env, SAML_PROTOCOL_NMSP, SAML_PROTOCOL_PREFIX);
	e = axiom_element_create(env, parent, SAML_SUBJECT_QUERY, ns, &n);

	if(e)
	{
		if(subject_query->subject)
			saml_subject_to_om(subject_query->subject, n, env);
	}
	return n;
}

AXIS2_EXTERN int AXIS2_CALL saml_authentication_query_build(saml_authentication_query_t* authentication_query, 
															axiom_node_t *node, 
															const axutil_env_t *env)
{
	axutil_hash_t *attr_hash = NULL;
	axiom_element_t *element = NULL;
	axutil_hash_index_t *hi = NULL;
	axiom_child_element_iterator_t *iterator = NULL;
	axiom_node_t *child_node;


	if (axiom_node_get_node_type(node, env) != AXIOM_ELEMENT)
	{
		return AXIS2_FAILURE;
	}
	
	if ((element = axiom_node_get_data_element(node, env)) == NULL)
	{
		return AXIS2_FAILURE;
	}
	
	/* initialize the attributes */
	attr_hash = axiom_element_get_all_attributes(element, env);	

	if(attr_hash)
	{
		for (hi = axutil_hash_first(attr_hash, env); hi; hi = axutil_hash_next(env, hi))
		{
			void *v = NULL;
			axutil_hash_this(hi, NULL, NULL, &v);
			if (v)
			{
				axis2_char_t *attr_val = NULL;
				axiom_attribute_t *attr = (axiom_attribute_t*)v;			
				attr_val = axiom_attribute_get_value(attr, env);

				if(!axutil_strcmp(axiom_attribute_get_localname(attr, env), SAML_AUTHENTICATION_METHOD))
				{
					authentication_query->auth_method = attr_val;
					break;
				}
			}
		}
	}

	iterator = axiom_element_get_child_elements(element, env, node);
	if(iterator)
	{
		while(axiom_child_element_iterator_has_next(iterator, env))
		{
		
			child_node = axiom_child_element_iterator_next(iterator, env);
			element = (axiom_element_t *)axiom_node_get_data_element(child_node, env);

			if(element != NULL && !(axutil_strcmp(axiom_element_get_localname(element, env), 
																	SAML_SUBJECT)))
			{
				if(authentication_query->subject)
					return saml_subject_build(authentication_query->subject, child_node, env);
				else
					return AXIS2_FAILURE;
			}
		}
		return AXIS2_SUCCESS;
	}
	else
		return AXIS2_FAILURE;


}

AXIS2_EXTERN axiom_node_t* AXIS2_CALL saml_authentication_query_to_om(saml_authentication_query_t *authentication_query, 
																	  axiom_node_t *parent, 
																	  const axutil_env_t *env)
{
	axiom_element_t *e = NULL;
	axiom_node_t *n = NULL;	
	axiom_namespace_t *ns = NULL;
	axiom_attribute_t *attr = NULL;
		
	ns = axiom_namespace_create(env, SAML_PROTOCOL_NMSP, SAML_PROTOCOL_PREFIX);
	e = axiom_element_create(env, parent, SAML_AUTHENTICATION_QUERY, ns, &n);

		if(e)
		{
			if(authentication_query->subject)
				saml_subject_to_om(authentication_query->subject, n, env);
			if(authentication_query->auth_method)
			{
				attr = axiom_attribute_create(env, SAML_AUTHENTICATION_METHOD, authentication_query->auth_method, NULL);
				axiom_element_add_attribute(e, env, attr, n);
			}
		}
	return n;

}

AXIS2_EXTERN int AXIS2_CALL saml_autho_decision_query_build(saml_autho_decision_query_t* autho_decision_query, 
															axiom_node_t *node, 
															const axutil_env_t *env)
{
	axutil_hash_t *attr_hash = NULL;
	axiom_element_t *element = NULL;
	axutil_hash_index_t *hi = NULL;
	axiom_child_element_iterator_t *iterator = NULL;
	axiom_node_t *child_node;
	saml_action_t *action;

	if (axiom_node_get_node_type(node, env) != AXIOM_ELEMENT)
	{
		return AXIS2_FAILURE;
	}
	
	if ((element = axiom_node_get_data_element(node, env)) == NULL)
	{
		return AXIS2_FAILURE;
	}
	
	/* initialize the attributes */
	attr_hash = axiom_element_get_all_attributes(element, env);	

	for (hi = axutil_hash_first(attr_hash, env); hi; hi = axutil_hash_next(env, hi))
	{
		void *v = NULL;
        axutil_hash_this(hi, NULL, NULL, &v);
		if (v)
		{
			axis2_char_t *attr_val = NULL;
			axiom_attribute_t *attr = (axiom_attribute_t*)v;			
			attr_val = axiom_attribute_get_value(attr, env);

			if(!axutil_strcmp(axiom_attribute_get_localname(attr, env), SAML_RESOURCE))
			{
				if(autho_decision_query->resource)
				{
					autho_decision_query->resource = attr_val;
					break;
				}
				else
					return AXIS2_FAILURE;
			}
		}
	}
	
	iterator = axiom_element_get_child_elements(element, env, node);

	if(iterator)
	{
		while(axiom_child_element_iterator_has_next(iterator, env))
		{
			child_node = axiom_child_element_iterator_next(iterator, env);
			element = (axiom_element_t *)axiom_node_get_data_element(child_node, env);

			if(element != NULL && !(axutil_strcmp(axiom_element_get_localname(element, env), 
																		SAML_SUBJECT)))
			{
				if(autho_decision_query->subject)
					saml_subject_build(autho_decision_query->subject, child_node, env);
			}
			
			else if(element != NULL && !(axutil_strcmp(axiom_element_get_localname(element, env), 
																		SAML_ACTION)))
			{
				if(autho_decision_query->saml_actions)
				{
					action = saml_action_create(env);					
					saml_action_build(action, child_node, env);
					axutil_array_list_add(autho_decision_query->saml_actions, env, action);
				}
			}
			else if(element != NULL && !(axutil_strcmp(axiom_element_get_localname(element, env), 
																		SAML_EVIDENCE)))
			{
				if(autho_decision_query->evidence)
					saml_evidence_build(autho_decision_query->evidence, child_node, env);
			}
		}
		return AXIS2_SUCCESS;
	}

	else
		return AXIS2_FAILURE;


	
}

AXIS2_EXTERN axiom_node_t* AXIS2_CALL saml_autho_decision_query_to_om(saml_autho_decision_query_t *autho_decision_query, 
																	  axiom_node_t *parent, 
																	  const axutil_env_t *env)
{
	int size = 0, i = 0;
	axiom_element_t *e = NULL;
	axiom_node_t *n = NULL;	
	axiom_namespace_t *ns = NULL;
	axiom_attribute_t *attr = NULL;
	saml_action_t *action;

	ns = axiom_namespace_create(env, SAML_PROTOCOL_NMSP, SAML_PROTOCOL_PREFIX);
	e = axiom_element_create(env, parent, SAML_AUTHORIZATION_DECISION_QUERY, ns, &n);

	if(e)
	{
		if(autho_decision_query->subject)
			saml_subject_to_om(autho_decision_query->subject, n, env);

		if(autho_decision_query->resource)
		{
			attr = axiom_attribute_create(env, SAML_RESOURCE, autho_decision_query->resource, NULL);
			axiom_element_add_attribute(e, env, attr, n);
		}
		if(autho_decision_query->saml_actions)
		{
			size = axutil_array_list_size(autho_decision_query->saml_actions, env);

			for(i = 0 ; i < size ; i++)
			{
				action = (saml_action_t*)axutil_array_list_get(autho_decision_query->saml_actions, env, i);
				saml_action_to_om(action, n, env);
			}
		}
		if(autho_decision_query->evidence)
		{
			saml_evidence_to_om(autho_decision_query->evidence, n, env);
		}
	}
	return n;



}

AXIS2_EXTERN int AXIS2_CALL saml_attr_query_build(saml_attr_query_t* attribute_query, 
												  axiom_node_t *node, 
												  const axutil_env_t *env)
{
	axutil_hash_t *attr_hash = NULL;
	axiom_element_t *element = NULL;
	axutil_hash_index_t *hi = NULL;
	axiom_child_element_iterator_t *iterator = NULL;
	axiom_node_t *child_node;
	saml_attr_desig_t *attr_desig = NULL;

	if (axiom_node_get_node_type(node, env) != AXIOM_ELEMENT)
	{
		return AXIS2_FAILURE;
	}
	
	if ((element = axiom_node_get_data_element(node, env)) == NULL)
	{
		return AXIS2_FAILURE;
	}
	
	/* initialize the attributes */
	attr_hash = axiom_element_get_all_attributes(element, env);	

	/*One resource attribute relate to the attibute query*/
	for (hi = axutil_hash_first(attr_hash, env); hi; hi = axutil_hash_next(env, hi))
	{
		void *v = NULL;
        axutil_hash_this(hi, NULL, NULL, &v);
		if (v)
		{
			axis2_char_t *attr_val = NULL;
			axiom_attribute_t *attr = (axiom_attribute_t*)v;			
			attr_val = axiom_attribute_get_value(attr, env);

			if(!axutil_strcmp(axiom_attribute_get_localname(attr, env),SAML_RESOURCE))
			{
				attribute_query->resource = attr_val;
				break;
			}
		}
	}
	
	iterator = axiom_element_get_child_elements(element, env, node);
	if(iterator)
	{
		while(axiom_child_element_iterator_has_next(iterator, env))
		{
			child_node = axiom_child_element_iterator_next(iterator, env);
			element = (axiom_element_t *)axiom_node_get_data_element(child_node, env);

			if(element != NULL && !(axutil_strcmp(axiom_element_get_localname(element, env), 
																	SAML_SUBJECT)))
			{
				if(attribute_query->subject)
					saml_subject_build(attribute_query->subject, child_node, env);
			}
			
			else if(element != NULL && !(axutil_strcmp(axiom_element_get_localname(element, env), 
																		SAML_ATTRIBUTE_DESIGNATOR)))
			{
				/*attr_desig = saml_attr_desig_create(env);
				*/
				attr_desig = (saml_attr_desig_t*)AXIS2_MALLOC(env->allocator,
														sizeof(saml_attr_desig_t));

				if( AXIS2_SUCCESS == saml_attr_desig_build(attr_desig, child_node, env))
				{
					axutil_array_list_add(attribute_query->attr_desigs,env, attr_desig);
				}
			}
		
		}
		return AXIS2_SUCCESS;
	}
	else
		return AXIS2_FAILURE;

	
}

AXIS2_EXTERN axiom_node_t* AXIS2_CALL saml_attr_query_to_om(saml_attr_query_t *attribute_query, 
															axiom_node_t *parent, 
															const axutil_env_t *env)
{
	int size = 0, i = 0;
	axiom_element_t *e = NULL;
	axiom_node_t *n = NULL;	
	axiom_namespace_t *ns = NULL;
	axiom_attribute_t *attr = NULL;
	saml_attr_desig_t *attr_desig = NULL;

	ns = axiom_namespace_create(env, SAML_PROTOCOL_NMSP, SAML_PROTOCOL_PREFIX);
	e = axiom_element_create(env, parent, SAML_ATTRIBUTE_QUERY, ns, &n);

	if(e)
	{
		if(attribute_query->subject)
			saml_subject_to_om(attribute_query->subject, n, env);

		if(attribute_query->resource)
		{
			attr = axiom_attribute_create(env, SAML_RESOURCE, attribute_query->resource, NULL);
			axiom_element_add_attribute(e, env, attr, n);
		}
		if(attribute_query->attr_desigs)
		{
			size = axutil_array_list_size(attribute_query->attr_desigs, env);

			for( i=0 ; i < size ; i++)
			{
				attr_desig = (saml_attr_desig_t*)axutil_array_list_get(attribute_query->attr_desigs, env, i);
				saml_attr_desig_to_om(attr_desig, n, env);
			}
		}
	}
	return n;

}

AXIS2_EXTERN int AXIS2_CALL saml_query_build(saml_query_t *query, axiom_node_t *node, const axutil_env_t *env)
{
	if(!axutil_strcmp(query->type,SAML_SUBJECT_QUERY))
	{
		query->query = saml_subject_query_create(env);
		if(query->query)
		{
			saml_subject_query_build((saml_subject_query_t*)query->query, node, env);
			return AXIS2_SUCCESS;
		}
		else 
			return AXIS2_FAILURE;
	}
	if(!axutil_strcmp(query->type, SAML_AUTHENTICATION_QUERY))
	{
		query->query = saml_authentication_query_create(env);
		if(query->query)
		{	
			saml_authentication_query_build((saml_authentication_query_t*)query->query, node, env);
			return AXIS2_SUCCESS;
		}
		else 
			return AXIS2_FAILURE;
	}
	if(!axutil_strcmp(query->type, SAML_ATTRIBUTE_QUERY))
	{
		query->query = saml_attr_query_create(env);
		if(query->query)
		{
			saml_attr_query_build((saml_attr_query_t*)query->query, node, env);
			return AXIS2_SUCCESS;
		}
		else
			return AXIS2_FAILURE;
	}
	if(!axutil_strcmp(query->type, SAML_AUTHORIZATION_DECISION_QUERY))
	{
		query->query = saml_autho_decision_query_create(env);
		if(query->query)
		{
			saml_autho_decision_query_build((saml_autho_decision_query_t*)query->query, node, env);
			return AXIS2_SUCCESS;
		}
		else 
			return AXIS2_FAILURE;
	}
	else
		return AXIS2_FAILURE;
}

AXIS2_EXTERN saml_query_t* AXIS2_CALL saml_query_create(const axutil_env_t *env)
{
	saml_query_t* query = NULL;
	query = AXIS2_MALLOC(env->allocator, sizeof(saml_query_t));
	if(query)
	{
		query->query = NULL;
		query->type = NULL;
	}
	return query;
}


AXIS2_EXTERN void AXIS2_CALL saml_query_free(saml_query_t *query, const axutil_env_t *env)
{
	if(query->type)
	{
		if(!axutil_strcmp(query->type,SAML_SUBJECT_QUERY))
		{
			if(query->query)
			{
				saml_subject_query_free(query->query, env);
			}
		}
		if(!axutil_strcmp(query->type, SAML_AUTHENTICATION_QUERY))
		{
			if(query->query)
			{
				saml_authentication_query_free(query->query, env);
			}
		}
		if(!axutil_strcmp(query->type, SAML_ATTRIBUTE_QUERY))
		{
			if(query->query)
			{
				saml_attr_query_free(query->query, env);
			}
		}
		if(!axutil_strcmp(query->type, SAML_AUTHORIZATION_DECISION_QUERY))
		{
			if(query->query)
			{
				saml_autho_decision_query_free(query->query, env);
			}
		}

		AXIS2_FREE(env->allocator, query->type);
		AXIS2_FREE(env->allocator, query);
		query = NULL;
	}
	
}
AXIS2_EXTERN axiom_node_t* AXIS2_CALL saml_query_to_om(saml_query_t *query, axiom_node_t *parent, const axutil_env_t *env)
{
	
	if(!axutil_strcmp(query->type,SAML_SUBJECT_QUERY))
	{
		return saml_subject_query_to_om((saml_subject_query_t*)query->query, parent, env);
		
	}
	if(!axutil_strcmp(query->type, SAML_AUTHENTICATION_QUERY))
	{
		return saml_authentication_query_to_om((saml_authentication_query_t*)query->query, parent, env);
	}
	if(!axutil_strcmp(query->type, SAML_ATTRIBUTE_QUERY))
	{
		return saml_attr_query_to_om((saml_attr_query_t*)query->query, parent, env);	
	}
	if(!axutil_strcmp(query->type, SAML_AUTHORIZATION_DECISION_QUERY))
	{
		return saml_autho_decision_query_to_om((saml_autho_decision_query_t*)query->query, parent, env);
	}
	return NULL;
}


AXIS2_EXTERN int AXIS2_CALL saml_auth_query_set_authentication_method(saml_authentication_query_t *authentication_query,
																	  const axutil_env_t *env,
																	  axis2_char_t *authentication_mtd)
{
	if(authentication_query->auth_method)
	{
		AXIS2_FREE(env->allocator, authentication_query->auth_method);
	}
	authentication_query->auth_method = axutil_strdup(env, authentication_mtd);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL saml_attr_query_set_resource(saml_attr_query_t *attr_query, const axutil_env_t *env, axis2_char_t *resource)
{
	if(attr_query->resource)
	{
		AXIS2_FREE(env->allocator, attr_query->resource);
	}
	attr_query->resource = axutil_strdup(env, resource);

	return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t* AXIS2_CALL saml_auth_query_get_authentication_method(saml_authentication_query_t *authentication_query,
															const axutil_env_t *env)
{
	if(authentication_query)
		return authentication_query->auth_method;
	else
		return NULL;

}


AXIS2_EXTERN axis2_char_t* AXIS2_CALL saml_attr_query_get_resource(saml_attr_query_t *attr_query, const axutil_env_t *env)
{
	if(attr_query)
		return attr_query->resource;
	else
		return NULL;
}


AXIS2_EXTERN int AXIS2_CALL saml_attr_query_set_designators(saml_attr_query_t *attr_query, const axutil_env_t *env,
															axutil_array_list_t *attr_desigs)
{
	if(attr_query->attr_desigs)
	{
		axutil_array_list_free(attr_query->attr_desigs, env);
	}
	attr_query->attr_desigs = attr_desigs;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN axutil_array_list_t*  AXIS2_CALL saml_attr_query_get_designators(saml_attr_query_t *attr_query, 
															const axutil_env_t *env)
{
	if(attr_query)
		return attr_query->attr_desigs;
	else
		return NULL;
}


AXIS2_EXTERN int AXIS2_CALL saml_attr_query_add_designators(saml_attr_query_t *attr_query, const axutil_env_t *env,
															saml_attr_desig_t *desig)
{
	if(!attr_query->attr_desigs)
	{
		axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
	}
	axutil_array_list_add(attr_query->attr_desigs, env, desig);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL saml_attr_query_remove_designator(saml_attr_query_t *attr_query, const axutil_env_t *env, int index)
{
	saml_attr_desig_t *desig;

	if(attr_query->attr_desigs)
	{
		desig = axutil_array_list_remove(attr_query->attr_desigs, env, index);
		if(desig)
		{
			saml_attr_desig_free(desig, env);
			return AXIS2_SUCCESS;
		}

	}
	return AXIS2_FAILURE;
}							

AXIS2_EXTERN int AXIS2_CALL saml_autho_decision_query_set_resource(saml_autho_decision_query_t *autho_dec_query,
														 const axutil_env_t *env,
														 axis2_char_t *resource)
{
	if(autho_dec_query->resource)
	{
		AXIS2_FREE(env->allocator, autho_dec_query->resource);
	}

	autho_dec_query->resource = axutil_strdup(env, resource);
	return AXIS2_SUCCESS;
}
AXIS2_EXTERN axis2_char_t* AXIS2_CALL saml_autho_decision_query_get_resource(saml_autho_decision_query_t *autho_dec_query,
														  const axutil_env_t *env)
{
	if(autho_dec_query)
		return autho_dec_query->resource;
	else
		return NULL;
}

AXIS2_EXTERN int AXIS2_CALL saml_autho_decision_query_set_actions(saml_autho_decision_query_t *autho_dec_query,
														const axutil_env_t *env,
														axutil_array_list_t *actions)
{
	if(autho_dec_query->saml_actions)
	{
		axutil_array_list_free(autho_dec_query->saml_actions, env);
	}
	autho_dec_query->saml_actions = actions;
	return AXIS2_SUCCESS;
}
AXIS2_EXTERN axutil_array_list_t* AXIS2_CALL saml_autho_decision_query_get_actions(saml_autho_decision_query_t *autho_dec_query,
														const axutil_env_t *env)
{
	if(autho_dec_query)
		return autho_dec_query->saml_actions;
	else
		return NULL;
}

AXIS2_EXTERN int AXIS2_CALL saml_autho_decision_query_add_action(saml_autho_decision_query_t *autho_dec_query,
													     		 const axutil_env_t *env,
																 saml_action_t *action)
{
	if(!autho_dec_query->saml_actions)
	{
	  autho_dec_query->saml_actions = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
	}
	if(autho_dec_query->saml_actions)
	{
		axutil_array_list_add(autho_dec_query->saml_actions, env, action);
		return AXIS2_SUCCESS;
	}
	return AXIS2_FAILURE;
}
AXIS2_EXTERN int AXIS2_CALL saml_autho_decision_remove_action(saml_autho_decision_query_t *autho_dec_query,
															  const axutil_env_t *env,
															  int index)
{
	saml_action_t *act;
	if(autho_dec_query->saml_actions)
	{
		act = axutil_array_list_remove(autho_dec_query->saml_actions, env, index);
		if(act)
		{
			saml_action_free(act, env);			
			return AXIS2_SUCCESS;
		}
	}
	return AXIS2_FAILURE;
}
AXIS2_EXTERN int AXIS2_CALL saml_autho_decision_query_set_evidence(saml_autho_decision_query_t *autho_dec_query,
																   const axutil_env_t *env,
																   saml_evidence_t *evidence)
{
	if(autho_dec_query->evidence)
	{
		saml_evidence_free(autho_dec_query->evidence, env);
	}
	autho_dec_query->evidence = evidence;
	return AXIS2_FAILURE;
}

AXIS2_EXTERN saml_evidence_t* AXIS2_CALL saml_autho_decision_query_get_evidence(saml_autho_decision_query_t *autho_dec_query,
														const axutil_env_t *env)
{
	if(autho_dec_query)
		return autho_dec_query->evidence;
	else
		return NULL;
}
AXIS2_EXTERN int AXIS2_CALL saml_query_set_subject(saml_query_t* query, const axutil_env_t *env,
												   saml_subject_t *subject)
{
	saml_subject_query_t *sub_q = NULL;
	saml_authentication_query_t *authent_q;
	saml_autho_decision_query_t *autho_de_q;
	saml_attr_query_t *attr_q;
	if(query)
	{
		if(query->type)
		{
			if(!axutil_strcmp(query->type,SAML_SUBJECT_QUERY))
			{
				sub_q = (saml_subject_query_t*)query->query;
				if(sub_q)
				{
					if(sub_q->subject)
					{
						saml_subject_free(sub_q->subject, env);
					}
					sub_q->subject = subject;
				}
			}
			if(!axutil_strcmp(query->type, SAML_AUTHENTICATION_QUERY))
			{
				authent_q = (saml_authentication_query_t*)query->query;
				if(authent_q->subject)
				{
					saml_subject_free(authent_q->subject, env);
				}
				authent_q->subject = subject;
			}
			if(!axutil_strcmp(query->type, SAML_ATTRIBUTE_QUERY))
			{
				attr_q = (saml_attr_query_t*)query->query;
				if(attr_q)
				{
					saml_subject_free(attr_q->subject, env);
				}
				attr_q->subject = subject;
			}
			if(!axutil_strcmp(query->type, SAML_AUTHORIZATION_DECISION_QUERY))
			{
				autho_de_q = (saml_autho_decision_query_t*)query->query;
				if(autho_de_q)
				{
					saml_subject_free(autho_de_q->subject, env);
				}
				autho_de_q->subject = subject;
			}
			
		}
		
	}
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN saml_subject_t* AXIS2_CALL saml_query_get_subject(saml_query_t* query,
															   const axutil_env_t *env)
{
	saml_subject_query_t *sub_q = NULL;
	saml_authentication_query_t *authent_q;
	saml_autho_decision_query_t *autho_de_q;
	saml_attr_query_t *attr_q;
	if(query)
	{
		if(query->type)
		{
			if(!axutil_strcmp(query->type,SAML_SUBJECT_QUERY))
			{
				sub_q = (saml_subject_query_t*)query->query;
				if(sub_q)
					return sub_q->subject;
				else
					return NULL;
			}
			if(!axutil_strcmp(query->type, SAML_AUTHENTICATION_QUERY))
			{
				authent_q = (saml_authentication_query_t*)query->query;
				if(authent_q)
					return authent_q->subject;
			}
			if(!axutil_strcmp(query->type, SAML_ATTRIBUTE_QUERY))
			{
				attr_q = (saml_attr_query_t*)query->query;
				if(attr_q)
					return attr_q->subject;
				else
					return NULL;
			}
			if(!axutil_strcmp(query->type, SAML_AUTHORIZATION_DECISION_QUERY))
			{
				autho_de_q = (saml_autho_decision_query_t*)query->query;
				if(autho_de_q)
					return autho_de_q->subject;
				else
					return NULL;
			}
			
		}
		
	}
	return NULL;
}

AXIS2_EXTERN int AXIS2_CALL saml_query_set_type(saml_query_t *query, const axutil_env_t *env,
												axis2_char_t *type)
{
	if(query->type)
	{
		AXIS2_FREE(env->allocator, query->type);
	}
	query->type = axutil_strdup(env, type);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL saml_query_set_query(saml_query_t *query, const axutil_env_t *env, void *spec_query,
														axis2_char_t *type)
{
	if(query->query)
	{
		
		if(!axutil_strcmp(query->type,SAML_SUBJECT_QUERY))
		{
			if(query->query)
			{
				saml_subject_query_free(query->query, env);
			}
		}
		if(!axutil_strcmp(query->type, SAML_AUTHENTICATION_QUERY))
		{
			if(query->query)
			{
				saml_authentication_query_free(query->query, env);
			}
		}
		if(!axutil_strcmp(query->type, SAML_ATTRIBUTE_QUERY))
		{
			if(query->query)
			{
				saml_attr_query_free(query->query, env);
			}
		}
		if(!axutil_strcmp(query->type, SAML_AUTHORIZATION_DECISION_QUERY))
		{
			if(query->query)
			{
				saml_autho_decision_query_free(query->query, env);
			}
		}
		AXIS2_FREE(env->allocator, query->type);
	}

	query->query = spec_query;
	query->type = axutil_strdup(env, type);
	return AXIS2_SUCCESS;

}
