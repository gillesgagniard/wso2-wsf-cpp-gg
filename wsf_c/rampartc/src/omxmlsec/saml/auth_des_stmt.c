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


AXIS2_EXTERN saml_action_t * AXIS2_CALL 
saml_action_create(const axutil_env_t *env)
{
	saml_action_t *action = AXIS2_MALLOC(env->allocator, sizeof(saml_action_t));
	if (action)
	{
		action->data = NULL;
		action->name_space = NULL;
	}
	return action;
}

AXIS2_EXTERN void AXIS2_CALL 
saml_action_free(saml_action_t *action, const axutil_env_t *env)
{
	if (action->data)
	{
		AXIS2_FREE(env->allocator, action->data);
	}
	if (action->name_space)
	{
		AXIS2_FREE(env->allocator, action->name_space);
	}
	AXIS2_FREE(env->allocator, action);	
}

AXIS2_EXTERN int AXIS2_CALL 
saml_action_build(saml_action_t *action, 
				  axiom_node_t *node, const axutil_env_t *env)
{
	axiom_element_t *element = NULL;	
	if (axiom_node_get_node_type(node, env) != AXIOM_ELEMENT || (element = (axiom_element_t *)axiom_node_get_data_element(node, env)) == NULL)
	{
		return AXIS2_FAILURE;
	}	
	action->name_space = axiom_element_get_attribute_value_by_name(element, env, SAML_NAMESPACE);
	if ((action->data = axiom_element_get_text(element, env, node)) == NULL)
	{
		return AXIS2_FALSE;
	}
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_action_to_om(saml_action_t *action, 
				  axiom_node_t *parent, const axutil_env_t *env)
{
	axiom_element_t *e = NULL;
	axiom_node_t *n = NULL;	
	axiom_namespace_t *ns = NULL;
	axiom_attribute_t *attr = NULL;
	ns = axiom_namespace_create(env, SAML_NMSP_URI, SAML_PREFIX);
	e = axiom_element_create(env, parent, SAML_ACTION, ns, &n);
	if (e)
	{
		if (action->name_space)
		{
			attr = axiom_attribute_create(env, SAML_NAMESPACE, action->name_space, NULL);
			axiom_element_add_attribute(e, env, attr, n);			
		}
		if (action->data)
		{				
			axiom_element_set_text(e, env, action->data, n);		
		}
		else
		{
			return NULL;
		}
	}
	return n;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_action_get_data(saml_action_t *action, const axutil_env_t *env)
{
	return action->data;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_action_get_namespace(saml_action_t *action, const axutil_env_t *env)
{
	return action->name_space;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_action_set_data(saml_action_t *action, 
					 const axutil_env_t *env, axis2_char_t *data)
{
	if (action->data)
	{
		AXIS2_FREE(env->allocator, action->data);
	}
	action->data = axutil_strdup(env, data);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_action_set_namespace(saml_action_t *action, 
						  const axutil_env_t *env, axis2_char_t *name_space)
{
	if (action->name_space)
	{
		AXIS2_FREE(env->allocator, action->name_space);
	}
	action->name_space = axutil_strdup(env, name_space);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN saml_evidence_t * AXIS2_CALL 
saml_evidence_create(const axutil_env_t *env)
{
	saml_evidence_t *evidence = (saml_evidence_t *)AXIS2_MALLOC(env->allocator, sizeof(saml_evidence_t));
	if (evidence)
	{
		evidence->assertion_ids = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
		evidence->assertions = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);		
	}
	return evidence;
}

AXIS2_EXTERN void AXIS2_CALL 
saml_evidence_free(saml_evidence_t *evidence, const axutil_env_t *env)
{
	int i = 0, size = 0;
	char *val = NULL;
	saml_assertion_t *assertion = NULL;
	
	if (evidence->assertion_ids)
	{
		size = axutil_array_list_size(evidence->assertion_ids, env);
		for (i = 0; i < size; i++)
		{
			val = axutil_array_list_get(evidence->assertion_ids, env, i);
			if (val)
			{
				AXIS2_FREE(env->allocator, val);
			}
		}
	}
	if (evidence->assertions)
	{
		size = axutil_array_list_size(evidence->assertions, env);
		for (i = 0; i < size; i++)
		{
			assertion = axutil_array_list_get(evidence->assertions, env, i);
			if (assertion)
			{
				saml_assertion_free(assertion, env);				
			}
		}
	}
}

AXIS2_EXTERN int AXIS2_CALL 
saml_evidence_build(saml_evidence_t *evidence, 
					axiom_node_t *node, const axutil_env_t *env)
{
	axiom_element_t *element = NULL;
	axiom_element_t *fce = NULL;
	axiom_node_t *fcn = NULL;
	axiom_child_element_iterator_t *ci = NULL;
	saml_assertion_t *assertion = NULL;
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
			if (strcmp(axiom_element_get_localname(fce, env), SAML_ASSERTION_ID_REFERENCE) == 0)
			{
				axutil_array_list_add(evidence->assertion_ids, env, axiom_element_get_text(fce, env, fcn));									
			}
			else if (strcmp(axiom_element_get_localname(fce, env), SAML_ASSERTION) == 0)
			{
				assertion = AXIS2_MALLOC(env->allocator, sizeof(saml_assertion_t));
				saml_assertion_build(assertion, fcn, env);
				axutil_array_list_add(evidence->assertions, env, assertion);
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
saml_evidence_to_om(saml_evidence_t *evidence, 
					axiom_node_t *parent, const axutil_env_t *env)
{
	int size = 0, i = 0;
	axiom_element_t *e = NULL, *ce = NULL;
	axiom_node_t *n = NULL, *cn = NULL;	
	axiom_namespace_t *ns = NULL;
	saml_assertion_t *assertion = NULL;
	ns = axiom_namespace_create(env, SAML_NMSP_URI, SAML_PREFIX);
	e = axiom_element_create(env, parent, SAML_EVIDENCE, ns, &n);
	if (e)
	{
		if (evidence->assertion_ids)
		{
			size = axutil_array_list_size(evidence->assertion_ids, env);
			for (i = 0; i < size; i++)
			{
				ns = axiom_namespace_create(env, SAML_NMSP_URI, SAML_PREFIX);
				ce = axiom_element_create(env, n, SAML_ASSERTION_ID_REFERENCE, ns, &n);
				axiom_element_set_text(ce, env, axutil_array_list_get(evidence->assertion_ids, env, i), cn);
			}
		}
		if (evidence->assertions)
		{	
			size = axutil_array_list_size(evidence->assertions, env);
			for (i = 0; i < size; i++)
			{
				assertion = axutil_array_list_get(evidence->assertions, env, i);
				saml_assertion_to_om(assertion, n, env);
			}
		}	
	}
	return n;
}

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_evidence_get_assertions(saml_evidence_t *evidence, const axutil_env_t *env)
{
	return evidence->assertions;
}

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_evidence_get_assertion_ids(saml_evidence_t *evidence, const axutil_env_t *env)
{
	return evidence->assertion_ids;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_evidence_set_assertions(saml_evidence_t *evidence, 
							 const axutil_env_t *env, axutil_array_list_t *list)
{
	int i = 0, size = 0;
	saml_assertion_t *a = NULL;
	if (evidence->assertions)
	{
		size = axutil_array_list_size(evidence->assertions, env);
		for (i = 0; i <size; i++)
		{
			a = axutil_array_list_get(evidence->assertions, env, i);
			if (a)
			{
				AXIS2_FREE(env->allocator, a);
			}
		}
	}
	evidence->assertions = list;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_evidence_remove_assertion(saml_evidence_t *evidence, 
							   const axutil_env_t *env, int index)
{
	saml_assertion_t *a = NULL;
	if (evidence->assertions && axutil_array_list_size(evidence->assertions, env) > index)
	{
		a = axutil_array_list_remove(evidence->assertions, env, index);			
		if (a)
		{
			AXIS2_FREE(env->allocator, a);
		}
		return AXIS2_SUCCESS;		
	}
	else
	{
		return AXIS2_FAILURE;
	}
}

AXIS2_EXTERN int AXIS2_CALL 
saml_evidence_add_assertion(saml_evidence_t *evidence, 
							const axutil_env_t *env, saml_assertion_t *assertion)
{
	if (!evidence->assertions)
	{
		evidence->assertions = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
	}
	axutil_array_list_add(evidence->assertions, env, assertion);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_evidence_set_assertion_ids(saml_evidence_t *evidence, 
								const axutil_env_t *env, axutil_array_list_t *list)
{
	int i = 0, size = 0;
	axis2_char_t *a = NULL;
	if (evidence->assertion_ids)
	{
		size = axutil_array_list_size(evidence->assertion_ids, env);
		for (i = 0; i <size; i++)
		{
			a = axutil_array_list_get(evidence->assertion_ids, env, i);
			if (a)
			{
				AXIS2_FREE(env->allocator, a);
			}
		}
	}
	evidence->assertion_ids = list;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_evidence_remove_assertion_id(saml_evidence_t *evidence, 
								  const axutil_env_t *env, int index)
{
	axis2_char_t *a = NULL;
	if (evidence->assertion_ids && axutil_array_list_size(evidence->assertion_ids, env) > index)
	{
		a = axutil_array_list_remove(evidence->assertion_ids, env, index);			
		if (a)
		{
			AXIS2_FREE(env->allocator, a);
		}
		return AXIS2_SUCCESS;		
	}
	else
	{
		return AXIS2_FAILURE;
	}
}

AXIS2_EXTERN int AXIS2_CALL 
saml_evidence_add_assertion_id(saml_evidence_t *evidence, 
							   const axutil_env_t *env, axis2_char_t *assertion_id)
{
	if (!evidence->assertion_ids)
	{
		evidence->assertion_ids = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
	}
	axutil_array_list_add(evidence->assertion_ids, env, assertion_id);
	return AXIS2_SUCCESS;
}


AXIS2_EXTERN saml_auth_desicion_stmt_t * AXIS2_CALL 
saml_auth_desicion_stmt_create(const axutil_env_t *env)
{
	saml_auth_desicion_stmt_t *auth_des_stmt = AXIS2_MALLOC(env->allocator, sizeof(saml_auth_desicion_stmt_t));
	if (auth_des_stmt)
	{
		auth_des_stmt->decision = NULL;
		auth_des_stmt->resource = NULL;
		auth_des_stmt->evidence = NULL;
		auth_des_stmt->action = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
		auth_des_stmt->subject = saml_subject_create(env);
	}
	return auth_des_stmt;
}



AXIS2_EXTERN void AXIS2_CALL 
saml_auth_desicion_stmt_free(saml_auth_desicion_stmt_t *auth_des_stmt, 
							 const axutil_env_t *env)
{
	if (auth_des_stmt->decision)
	{
		AXIS2_FREE(env->allocator, auth_des_stmt->decision);
	}
	if (auth_des_stmt->resource)
	{
		AXIS2_FREE(env->allocator, auth_des_stmt->resource);
	}
	if (auth_des_stmt->evidence)
	{
		saml_evidence_free(auth_des_stmt->evidence, env);
	}
	if (auth_des_stmt->action)
	{
		int i = 0;
		saml_action_t *action = NULL;
		for (i = 0; i < axutil_array_list_size(auth_des_stmt->action, env); i++)
		{
			 action = axutil_array_list_get(auth_des_stmt->action, env, i);
			 if (action)
			 {
				saml_action_free(action, env);
			 }
		}
		axutil_array_list_free(auth_des_stmt->action, env);
	}
	if (auth_des_stmt->subject)
	{
		saml_subject_free(auth_des_stmt->subject, env);
	}
	AXIS2_FREE(env->allocator, auth_des_stmt);	
}

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_desicion_stmt_build(saml_auth_desicion_stmt_t *auth_des_stmt, 
							  axiom_node_t *node, const axutil_env_t *env)
{
	axutil_hash_t *attr_hash = NULL;
	axutil_hash_index_t *hi = NULL;
	axiom_element_t *element = NULL;
	axiom_element_t *fce = NULL;
	axiom_node_t *fcn = NULL;
	axiom_child_element_iterator_t *ci = NULL;
	saml_action_t *action = NULL;
	if (axiom_node_get_node_type(node, env) != AXIOM_ELEMENT || (element = (axiom_element_t *)axiom_node_get_data_element(node, env)) == NULL)
	{
		return AXIS2_FAILURE;
	}	
	if ((auth_des_stmt->resource = axiom_element_get_attribute_value_by_name(element, env, SAML_RESOURCE)) == NULL || (auth_des_stmt->decision = axiom_element_get_attribute_value_by_name(element, env, SAML_DECISION)) == NULL)
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
			axis2_char_t *attr_val = NULL;
			axiom_attribute_t *attr = (axiom_attribute_t*)v;			
			attr_val = axiom_attribute_get_localname(attr, env);			
			if (0 != axutil_strcmp(attr_val, SAML_RESOURCE) && 0 != axutil_strcmp(attr_val, SAML_DECISION))
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
			if (strcmp(axiom_element_get_localname(fce, env), SAML_SUBJECT) == 0)
			{
				saml_subject_build(auth_des_stmt->subject, fcn, env);			
			}
			else if (strcmp(axiom_element_get_localname(fce, env), SAML_ACTION) == 0)
			{
				action = saml_action_create(env);
				saml_action_build(action, fcn, env);
				axutil_array_list_add(auth_des_stmt->action, env, action);									
			}
			else if (strcmp(axiom_element_get_localname(fce, env), SAML_EVIDENCE) == 0)
			{
				saml_evidence_t *evi = saml_evidence_create(env);
				if (saml_evidence_build(evi, fcn, env))
				{
					auth_des_stmt->evidence = evi;
				}
				else
				{
					return AXIS2_FALSE;
				}
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
saml_auth_desicion_stmt_to_om(saml_auth_desicion_stmt_t *auth_des_stmt, 
							  axiom_node_t *parent, const axutil_env_t *env)
{
	int i = 0, size = 0;
	axiom_element_t *e = NULL;
	axiom_node_t *n = NULL;
	axiom_attribute_t *attr = NULL;
	axiom_namespace_t *ns = NULL;
	saml_action_t *action = NULL;
	ns = axiom_namespace_create(env, SAML_NMSP_URI, SAML_PREFIX);
	e = axiom_element_create(env, parent, SAML_AUTHORIZATION_DECISION_STATEMENT, ns, &n);
	if (e)
	{
		if (auth_des_stmt->resource && auth_des_stmt->decision)
		{
			attr = axiom_attribute_create(env, SAML_RESOURCE, auth_des_stmt->resource, NULL);
			axiom_element_add_attribute(e, env, attr, n);
			attr = axiom_attribute_create(env, SAML_DECISION, auth_des_stmt->decision, NULL);
			axiom_element_add_attribute(e, env, attr, n);			
		}
		else
		{
			return NULL;
		}
		if (auth_des_stmt->subject)
		{
			saml_subject_to_om(auth_des_stmt->subject, n, env);
		}
		if (auth_des_stmt->action)
		{
			size = axutil_array_list_size(auth_des_stmt->action, env);
			for (i = 0; i < size; i++)
			{
				action = axutil_array_list_get(auth_des_stmt->action, env, i);
				saml_action_to_om(action, n, env);
			}
		}
		if (auth_des_stmt->evidence)
		{
			saml_evidence_to_om(auth_des_stmt->evidence, n, env); 
		}
	}
	return NULL;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_auth_desicion_stmt_get_resource(saml_auth_desicion_stmt_t *auth_des_stmt, 
									 const axutil_env_t *env)
{
	return auth_des_stmt->resource;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL saml_auth_desicion_stmt_get_desicion(saml_auth_desicion_stmt_t *auth_des_stmt, const axutil_env_t *env)
{
	return auth_des_stmt->decision;
}

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_auth_desicion_stmt_get_actions(saml_auth_desicion_stmt_t *auth_des_stmt, 
									const axutil_env_t *env)
{
	return auth_des_stmt->action;
}

AXIS2_EXTERN saml_evidence_t * AXIS2_CALL 
saml_auth_desicion_stmt_get_evidence(saml_auth_desicion_stmt_t *auth_des_stmt, 
									 const axutil_env_t *env)
{
	return auth_des_stmt->evidence;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_desicion_stmt_set_resource(saml_auth_desicion_stmt_t *auth_des_stmt, 
									 const axutil_env_t *env, axis2_char_t *resource)
{
	if (auth_des_stmt->resource)
	{
		AXIS2_FREE(env->allocator, auth_des_stmt->resource);
	}
	auth_des_stmt->resource = axutil_strdup(env, resource);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_desicion_stmt_set_desicion(saml_auth_desicion_stmt_t *auth_des_stmt, 
									 const axutil_env_t *env, axis2_char_t *desicion)
{
	if (auth_des_stmt->decision)
	{
		AXIS2_FREE(env->allocator, auth_des_stmt->decision);
	}
	auth_des_stmt->decision = axutil_strdup(env, desicion);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_desicion_stmt_set_actions(saml_auth_desicion_stmt_t *auth_des_stmt, 
									const axutil_env_t *env, axutil_array_list_t *list)
{
	int i = 0, size = 0;
	saml_action_t *action = NULL;
	if (auth_des_stmt->action)
	{
		size = axutil_array_list_size(auth_des_stmt->action, env);
		for (i = 0; i <size; i++)
		{
			action = axutil_array_list_get(auth_des_stmt->action, env, i);
			if (action)
			{
				AXIS2_FREE(env->allocator, action);
			}
		}
	}
	auth_des_stmt->action = list;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_desicion_stmt_remove_action(saml_auth_desicion_stmt_t *auth_des_stmt, 
									  const axutil_env_t *env, int index)
{
	saml_action_t *action = NULL;
	if (auth_des_stmt->action && axutil_array_list_size(auth_des_stmt->action, env) > index)
	{
		action = axutil_array_list_remove(auth_des_stmt->action, env, index);			
		if (action)
		{
			AXIS2_FREE(env->allocator, action);
		}
		return AXIS2_SUCCESS;		
	}
	else
	{
		return AXIS2_FAILURE;
	}
}

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_desicion_stmt_add_action(saml_auth_desicion_stmt_t *auth_des_stmt, 
								   const axutil_env_t *env, saml_action_t *action)
{
	if (!auth_des_stmt->action)
	{
		auth_des_stmt->action = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
	}
	axutil_array_list_add(auth_des_stmt->action, env, action);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_desicion_stmt_set_subject(saml_auth_desicion_stmt_t *auth_des_stmt, 
									const axutil_env_t *env, saml_subject_t *subject)
{
	if (auth_des_stmt->subject)
	{
		saml_subject_free(auth_des_stmt->subject, env);
	}
	auth_des_stmt->subject = subject;
	return AXIS2_SUCCESS;
}

