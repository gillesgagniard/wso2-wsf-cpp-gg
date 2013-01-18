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


AXIS2_EXTERN saml_assertion_t * AXIS2_CALL 
saml_assertion_create(const axutil_env_t *env)
{		
	saml_assertion_t *assertion = AXIS2_MALLOC(env->allocator, sizeof(saml_assertion_t));
	if (assertion)
	{
		assertion->major_version = NULL;
		assertion->minor_version = NULL;
		assertion->not_before = NULL;
		assertion->not_on_or_after = NULL;
		assertion->assertion_id = NULL;
		assertion->conditions = NULL;
		assertion->statements = axutil_array_list_create(env, (SAML_ARRAY_LIST_DEF) * 2);
		assertion->issuer = NULL;
		assertion->issue_instant = NULL;
		assertion->signature = NULL;
		assertion->sign_ctx = NULL;
		assertion->ori_xml = NULL;
	}
	return assertion;
}

AXIS2_EXTERN void AXIS2_CALL 
saml_assertion_free(saml_assertion_t *assertion, const axutil_env_t *env)
{	
	int i = 0, size = 0;

	
	if (assertion->major_version)
	{
		AXIS2_FREE(env->allocator, assertion->major_version);
		assertion->major_version = NULL;
	}
	if (assertion->minor_version)
	{
		AXIS2_FREE(env->allocator, assertion->minor_version);
		assertion->minor_version = NULL;
	}
	if (assertion->not_before)
	{
		axutil_date_time_free(assertion->not_before, env);
		assertion->not_before = NULL;
	}
	if (assertion->not_on_or_after)
	{
		axutil_date_time_free(assertion->not_on_or_after, env);
		assertion->not_on_or_after = NULL;
	}
	if (assertion->issue_instant)
	{
		axutil_date_time_free(assertion->issue_instant, env);
		assertion->issue_instant = NULL;
	}
	if (assertion->assertion_id)
	{
		AXIS2_FREE(env->allocator, assertion->assertion_id);
		assertion->assertion_id = NULL;
	}
	if (assertion->conditions)
	{
		saml_condition_t *cond = NULL;
		size = axutil_array_list_size(assertion->conditions, env);
		for (i = 0; i < size; i++)
		{
			cond = (saml_condition_t*)axutil_array_list_get(assertion->conditions, env, i);
			if (cond)
			{
				saml_condition_free(cond, env);
			}
		}
	}
	if (assertion->statements)
	{
		saml_stmt_t *stmt = NULL;
		size = axutil_array_list_size(assertion->statements, env);
		for (i = 0; i < size; i++)
		{
			stmt = axutil_array_list_get(assertion->statements, env, i);
			if (stmt)
			{
				saml_stmt_free(stmt, env);
			}
		}
	}
	if (assertion->issue_instant)
	{
		AXIS2_FREE(env->allocator, assertion->issue_instant);
		assertion->issue_instant = NULL;
	}
	if (assertion->signature)
	{
		assertion->signature = NULL;
	}
	AXIS2_FREE(env->allocator, assertion);
}

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_build(saml_assertion_t *assertion, 
					 axiom_node_t *node, const axutil_env_t *env)
{			
	axiom_element_t *element = NULL;	
	axiom_child_element_iterator_t *ci = NULL;
	axis2_char_t *attr_val = NULL;
	saml_stmt_t *stmt = NULL;
	saml_condition_t *cond = NULL;
	if (axiom_node_get_node_type(node, env) != AXIOM_ELEMENT || (element = (axiom_element_t *)axiom_node_get_data_element(node, env)) == NULL)
	{
		return AXIS2_FAILURE;
	}	
	if (!(assertion->major_version = axiom_element_get_attribute_value_by_name(element, env, SAML_MAJORVERSION)) ||
		!(assertion->minor_version = axiom_element_get_attribute_value_by_name(element, env, SAML_MINORVERSION)) ||
		!(assertion->assertion_id = axiom_element_get_attribute_value_by_name(element, env, SAML_ASSERTION_ID)) ||
		!(assertion->issuer = axiom_element_get_attribute_value_by_name(element, env, SAML_ISSUER)))
	{
		return AXIS2_FAILURE;
	}	
	assertion->issue_instant = axutil_date_time_create(env);
	attr_val = axiom_element_get_attribute_value_by_name(element, env, SAML_ISSUE_INSTANT);
	if (attr_val)
	{
		axutil_date_time_deserialize_date_time(assertion->issue_instant, env, attr_val);
	}
	else
	{
		return AXIS2_FAILURE;
	}
	assertion->ori_xml = node; 
	if ((ci = axiom_element_get_child_elements(element, env, node)) != NULL)
	{
		axiom_element_t *ce = NULL;
		axiom_node_t *cn = NULL;
		axiom_node_t *ccn = NULL;
		axiom_child_element_iterator_t *cci = NULL;
		while(AXIS2_TRUE == axiom_child_element_iterator_has_next(ci, env))
		{			
			cn = axiom_child_element_iterator_next(ci, env);
			ce = axiom_node_get_data_element(cn, env);			
			if (0 == axutil_strcmp(axiom_element_get_localname(ce, env), SAML_CONDITIONS))
			{
				attr_val = axiom_element_get_attribute_value_by_name(ce, env, SAML_NOT_BEFORE);
				if (attr_val)
				{
					assertion->not_before = axutil_date_time_create(env);
					axutil_date_time_deserialize_date_time(assertion->not_before, env, attr_val);
				}
				attr_val = axiom_element_get_attribute_value_by_name(ce, env, SAML_NOT_ON_OR_AFTER);
				if (attr_val)
				{
					assertion->not_on_or_after = axutil_date_time_create(env);
					axutil_date_time_deserialize_date_time(assertion->not_on_or_after, env, attr_val);
				}				
				if ((cci = axiom_element_get_child_elements(ce, env, cn)) != NULL)
				{
					assertion->conditions = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
					while(AXIS2_TRUE == axiom_child_element_iterator_has_next(cci, env))
					{
						ccn = axiom_child_element_iterator_next(ci, env);						
						cond = saml_condition_create(env);
						if(saml_condition_build(cond, ccn, env))
						{
							axutil_array_list_add(assertion->conditions, env, cond);
						}
						else
						{
							saml_condition_free(cond, env);
						}
					}
					/*axiom_child_element_iterator_free(cci, env);*/
				}
			}
			else if (0 == axutil_strcmp(axiom_element_get_localname(ce, env), SAML_ADVICE))
			{	
				
			}
			else if (0 == axutil_strcmp(axiom_element_get_localname(ce, env), SAML_SIGNATURE))
			{	
				assertion->signature = cn;										
			}
			else 
			{
				/*if ((cci = axiom_element_get_child_elements(element, env, node)) != NULL)
				{
					while(AXIS2_TRUE == axiom_child_element_iterator_has_next(cci, env))
					{
						ccn = axiom_child_element_iterator_next(cci, env);*/						
						stmt = saml_stmt_create(env);
						if(saml_stmt_build(stmt, cn, env))
						{
							axutil_array_list_add(assertion->statements, env, stmt);
						}
						else
						{
							saml_stmt_free(stmt, env);
						}
					/*}*/
					/*axiom_child_element_iterator_free(cci, env);*/
				/*}				*/
			}
		}
	}	
	return AXIS2_SUCCESS;
}


AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_assertion_to_om(saml_assertion_t *assertion, 
					 axiom_node_t *parent, const axutil_env_t *env)
{
	int i = 0, size = 0;
	axiom_element_t *e = NULL, *ce = NULL;
	axiom_node_t *n = NULL, *cn = NULL;
	axiom_attribute_t *attr = NULL;
	axiom_namespace_t *ns = NULL;	
	saml_condition_t *cond = NULL;
	saml_stmt_t *stmt = NULL;
	ns = axiom_namespace_create(env, SAML_NMSP_URI, SAML_PREFIX);
	e = axiom_element_create(env, parent, SAML_ASSERTION, ns, &n);
	if (e)
	{
		if (assertion->minor_version && assertion->issuer && 
			assertion->issue_instant)
		{
			axis2_char_t *random_byte = NULL;
			axis2_char_t *serialised_date = NULL;
			attr = axiom_attribute_create(env, SAML_MAJORVERSION, 
				SAML_MAJOR_VERSION, NULL);
			axiom_element_add_attribute(e, env, attr, n);
			attr = axiom_attribute_create(env, SAML_MINORVERSION, 
				assertion->minor_version, NULL);
			axiom_element_add_attribute(e, env, attr, n);
			random_byte = saml_id_generate_random_bytes(env);
			attr = axiom_attribute_create(env, SAML_ASSERTION_ID, 
				random_byte, NULL);
			axiom_element_add_attribute(e, env, attr, n);
			attr = axiom_attribute_create(env, SAML_ISSUER, assertion->issuer, NULL);
			axiom_element_add_attribute(e, env, attr, n);
			serialised_date = axutil_date_time_serialize_date_time(assertion->issue_instant, env);
			attr = axiom_attribute_create(env, SAML_ISSUE_INSTANT, 
				serialised_date, NULL);
			axiom_element_add_attribute(e, env, attr, n);
			AXIS2_FREE(env->allocator, random_byte);
			AXIS2_FREE(env->allocator, serialised_date);
		}		
		else
		{
			return NULL;
		}
		if (assertion->conditions || assertion->not_before || assertion->not_on_or_after)
		{		
			ns = axiom_namespace_create(env, SAML_NMSP_URI, SAML_PREFIX);
			ce = axiom_element_create(env, n, SAML_CONDITIONS, ns, &cn);
			if (ce)
			{
				if (assertion->not_before)
				{
					attr = axiom_attribute_create(env, SAML_NOT_BEFORE, 
						axutil_date_time_serialize_date_time(assertion->not_before, env), 
						NULL);
					axiom_element_add_attribute(ce, env, attr, cn);						
				}
				if (assertion->not_on_or_after)
				{
					attr = axiom_attribute_create(env, SAML_NOT_ON_OR_AFTER, 
						axutil_date_time_serialize_date_time(assertion->not_on_or_after, env), 
						NULL);
					axiom_element_add_attribute(ce, env, attr, cn);						
				}
				if (assertion->conditions)
				{
					size = axutil_array_list_size(assertion->conditions, env);
					for (i = 0; i < size; i++)
					{
						cond = axutil_array_list_get(assertion->conditions, env, i);
						if (cond)
						{
							saml_condition_to_om(cond, cn, env);
						}
					}
				}
			}
		}
		if (assertion->statements)
		{									
			size = axutil_array_list_size(assertion->statements, env);
			for (i = 0; i < size; i++)
			{
				stmt = axutil_array_list_get(assertion->statements, env, i);
				if (stmt)
				{
					saml_stmt_to_om(stmt, n, env);
				}
			}		
		}
		/*if (assertion->signature)
		{
																			
		}*/
		if (assertion->sign_ctx)
		{
		  /*oxs_xml_sig_sign(env, assertion->sign_ctx, n, &assertion->signature); */
			saml_assertion_sign(assertion, n, env);
		}
	}	
	return n;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_assetion_get_assertion_id(saml_assertion_t *a, const axutil_env_t *env)
{
	return a->assertion_id;
}

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_assetion_get_conditions(saml_assertion_t *a, const axutil_env_t *env)
{
	return a->conditions;;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_set_conditions(saml_assertion_t *a, 
							  const axutil_env_t *env, axutil_array_list_t *list)
{
	int i = 0, size = 0;
	saml_condition_t *cond = NULL;
	if (a->conditions)
	{
		size = axutil_array_list_size(a->conditions, env);
		for (i = 0; i < size; i++)
		{
			cond =  axutil_array_list_get(a->conditions, env, i);
			if (cond)
			{
				saml_condition_free(cond, env);
			}
		}
		axutil_array_list_free(a->conditions, env);
		a->conditions = list;
	}
	else
	{
		a->conditions = list;
	}
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_add_condition(saml_assertion_t *a, 
							 const axutil_env_t *env, saml_condition_t *cond)
{
	if (!a->conditions)
	{
		a->conditions = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
	}
	axutil_array_list_add(a->conditions, env, cond);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_remove_condition(saml_assertion_t *a, 
								const axutil_env_t *env, int index)
{
	saml_condition_t *cond = NULL;
	if (a->conditions && axutil_array_list_size(a->conditions, env) > index)
	{
		cond = axutil_array_list_remove(a->conditions, env, index);			
		if (cond)
		{
			saml_condition_free(cond, env);
		}
		return AXIS2_SUCCESS;		
	}
	else
	{
		return AXIS2_FAILURE;
	}
}

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_assertion_get_statements(saml_assertion_t *a, const axutil_env_t *env)
{
	return a->statements;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_set_statements(saml_assertion_t *a, 
							  const axutil_env_t *env, axutil_array_list_t *list)
{
	int i = 0, size = 0;
	saml_stmt_t *stmt = NULL;
	if (a->statements)
	{
		size = axutil_array_list_size(a->statements, env);
		for (i = 0; i < size; i++)
		{
			stmt =  axutil_array_list_get(a->statements, env, i);
			if (stmt)
			{
				saml_stmt_free(stmt, env);
			}
		}
		axutil_array_list_free(a->statements, env);
		a->statements = list;
	}
	else
	{
		a->statements = list;
	}
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_add_statement(saml_assertion_t *a, 
							 const axutil_env_t *env, saml_stmt_t *stmt)
{
	if (!a->statements)
	{
		a->statements = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF * 2);
	}
	axutil_array_list_add(a->statements, env, stmt);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_remove_statement(saml_assertion_t *a, 
								const axutil_env_t *env, int index)
{
	saml_stmt_t *stmt = NULL;
	if (a->statements && axutil_array_list_size(a->statements, env) > index)
	{
		stmt = axutil_array_list_remove(a->statements, env, index);			
		if (stmt)
		{
			saml_stmt_free(stmt, env);
		}
		return AXIS2_SUCCESS;		
	}
	else
	{
		return AXIS2_FAILURE;
	}
}

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_set_minor_version(saml_assertion_t *a, 
								 const axutil_env_t *env, int version)
{
	if (!a->minor_version)
	{
		a->minor_version = AXIS2_MALLOC(env->allocator, 8);
	}	
	sprintf(a->minor_version, "%d", version);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_set_issuer(saml_assertion_t *a, 
						  const axutil_env_t *env, axis2_char_t *issuer)
{
	if (a->issuer)
	{
		AXIS2_FREE(env->allocator, a->issuer);
	}
	a->issuer = axutil_strdup(env, issuer);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_set_issue_instant(saml_assertion_t *a, 
								 const axutil_env_t *env, axutil_date_time_t *instant)
{
	if (a->issue_instant)
	{
		axutil_date_time_free(a->issue_instant, env);
	}
	a->issue_instant = instant;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_set_not_before(saml_assertion_t *a, 
							  const axutil_env_t *env, axutil_date_time_t *time)
{
	if (a->not_before)
	{
		axutil_date_time_free(a->not_before, env);
	}
	a->not_before = time;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_set_not_on_or_after(saml_assertion_t *a, 
								   const axutil_env_t *env, axutil_date_time_t *time)
{
	if (a->not_on_or_after)
	{
		axutil_date_time_free(a->not_on_or_after, env);
	}
	a->not_on_or_after = time;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_assertion_get_issuer(saml_assertion_t *a, const axutil_env_t *env)
{
	return a->issuer;
}

AXIS2_EXTERN axutil_date_time_t * AXIS2_CALL 
saml_assertion_get_issue_instant(saml_assertion_t *a, const axutil_env_t *env)
{
	return a->issue_instant;
}

AXIS2_EXTERN axutil_date_time_t * AXIS2_CALL 
saml_assertion_get_not_before(saml_assertion_t *a, const axutil_env_t *env)
{
	return a->not_before;
}

AXIS2_EXTERN axutil_date_time_t * AXIS2_CALL 
saml_assertion_get_not_on_or_after(saml_assertion_t *a, const axutil_env_t *env)
{
	return a->not_on_or_after;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_unsign(saml_assertion_t *a, const axutil_env_t *env)
{
	if (a->sign_ctx)
	{
		oxs_sign_ctx_free(a->sign_ctx, env);
	}
	a->sign_ctx = NULL;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL
saml_assertion_sign(saml_assertion_t *a, axiom_node_t *node, const axutil_env_t *env)
{
	 axiom_node_t *n= NULL;
	 oxs_sign_part_t* sig_part = NULL;
	 axutil_array_list_t *sig_parts = NULL;
	 int size = 0, i = 0;

	 sig_parts = oxs_sign_ctx_get_sign_parts(a->sign_ctx, env);
	 if(sig_parts)
	 {
		 size = axutil_array_list_size(sig_parts, env);
		 for(i = 0; i < size; i++)
		 {
			sig_part = axutil_array_list_get(sig_parts, env, i);
			if(sig_part)
			{
				oxs_sign_part_set_node(sig_part, env, node);
			}
		 }
	 }

	 oxs_xml_sig_sign(env, a->sign_ctx, node, &n);
     /*Finally build KeyInfo*/
	 oxs_xml_key_info_build(env, n, oxs_sign_ctx_get_certificate(a->sign_ctx, env), OXS_KIBP_X509DATA_X509CERTIFICATE);
	 return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL
saml_assertion_signature_verify(saml_assertion_t *a, const axutil_env_t *env)
{			
	return oxs_xml_sig_verify(env, a->sign_ctx, a->signature, a->ori_xml);
}

AXIS2_EXTERN int AXIS2_CALL
saml_assertion_is_sign_set(saml_assertion_t *a, const axutil_env_t *env)
{
	if (a->sign_ctx)
	{
		return AXIS2_TRUE;
	}
	return AXIS2_FALSE;
}

AXIS2_EXTERN int AXIS2_CALL
saml_assertion_is_signed(saml_assertion_t *a, const axutil_env_t *env)
{
	if (a->signature)
	{
		return AXIS2_TRUE;
	}
	return AXIS2_FALSE;
}

AXIS2_EXTERN int AXIS2_CALL saml_assertion_set_default_signature(saml_assertion_t *a, const axutil_env_t *env, oxs_sign_ctx_t *sign_ctx)
{
	if (a->sign_ctx)
	{
		oxs_sign_ctx_free(a->sign_ctx, env);
	}
	a->sign_ctx = sign_ctx;
	saml_util_set_sig_ctx_defaults(a->sign_ctx, env, SAML_ASSERTION_ID);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL saml_assertion_set_signature(saml_assertion_t *a, const axutil_env_t *env, oxs_sign_ctx_t *sign_ctx)
{
	if (a->sign_ctx)
	{
		oxs_sign_ctx_free(a->sign_ctx, env);
	}
	a->sign_ctx = sign_ctx;
	return AXIS2_SUCCESS;
}

