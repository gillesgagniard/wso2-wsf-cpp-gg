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
#include <oxs_xml_encryption.h>
#include <oxs_tokens.h>

AXIS2_EXTERN saml_named_id_t * AXIS2_CALL 
saml_named_id_create(const axutil_env_t *env)
{
	saml_named_id_t *named_id = AXIS2_MALLOC(env->allocator, sizeof(saml_named_id_t));
	if (named_id)
	{
		named_id->format = NULL;
		named_id->name_qualifier = NULL;
		named_id->name = NULL;
	}
	return named_id;
}

#ifndef SAML_NAMED_ID_RESET
#define SAML_NAMED_ID_RESET(_named_id, _env)				\
	if (_named_id->format)									\
	{														\
		AXIS2_FREE(_env->allocator, _named_id->format);		\
	}														\
	if (named_id->name_qualifier)							\
	{														\
		AXIS2_FREE(_env->allocator, _named_id->name_qualifier);	\
	}														\
	if (_named_id->name)									\
	{														\
		AXIS2_FREE(_env->allocator, _named_id->name);		\
	}														
#endif


AXIS2_EXTERN void AXIS2_CALL 
saml_named_id_free(saml_named_id_t *named_id, const axutil_env_t *env)
{
	if (named_id->format)									
	{														
		AXIS2_FREE(env->allocator, named_id->format);		
	}														
	if (named_id->name_qualifier)							
	{														
		AXIS2_FREE(env->allocator, named_id->name_qualifier);	
	}														
	if (named_id->name)									
	{													
		AXIS2_FREE(env->allocator, named_id->name);		
	}
	AXIS2_FREE(env->allocator, named_id);	
}

AXIS2_EXTERN int AXIS2_CALL 
saml_named_id_build(saml_named_id_t *named_id, axiom_node_t *node, 
					const axutil_env_t *env)
{	
	axutil_hash_t *attr_hash = NULL;
	axutil_hash_index_t *hi = NULL;
	axiom_element_t *element = NULL;
	SAML_NAMED_ID_RESET(named_id, env);
	if (axiom_node_get_node_type(node, env) != AXIOM_ELEMENT || (element = (axiom_element_t *)axiom_node_get_data_element(node, env)) == NULL)
	{
		return AXIS2_FAILURE;
	}
	attr_hash = axiom_element_get_all_attributes(element, env);	
	if (attr_hash == NULL)
	{
		return AXIS2_FAILURE;
	}	
	for (hi = axutil_hash_first(attr_hash, env); hi != NULL; hi = axutil_hash_next(env, hi))
	{
		void *v = NULL;
        axutil_hash_this(hi, NULL, NULL, &v);
		if (v)
		{			
			axis2_char_t *local_name = NULL;
			axiom_attribute_t *attr = (axiom_attribute_t*)v;			
			local_name = axiom_attribute_get_localname(attr, env);			
			if (0 == axutil_strcmp(local_name, SAML_NAME_QUALIFIER))
			{
				named_id->name_qualifier = axiom_attribute_get_value(attr, env);
			}        
			else if (0 == axutil_strcmp(local_name, SAML_FORMAT))
			{
				named_id->format = axiom_attribute_get_value(attr, env);
			}      			
			else 
			{				
				return AXIS2_FAILURE;
			}
		}
	}
	if ((named_id->name = axiom_element_get_text(element, env, node)) == NULL)
	{
		return AXIS2_FAILURE;
	}
	return AXIS2_SUCCESS;
}


AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_named_id_to_om(saml_named_id_t *id, axiom_node_t *parent, 
					const axutil_env_t *env)
{
	axiom_element_t *e = NULL;
	axiom_node_t *n = NULL;
	axiom_namespace_t *ns = NULL;
	axiom_attribute_t *attr = NULL;
	ns = axiom_namespace_create(env, SAML_NMSP_URI, SAML_PREFIX);
	e = axiom_element_create(env, parent, SAML_NAME_IDENTIFIER, ns, &n);	
	if (e)
	{
		if (id->format)
		{
			attr = axiom_attribute_create(env, SAML_FORMAT, id->format, NULL);
			axiom_element_add_attribute(e, env, attr, n);
		}
		if (id->name_qualifier)
		{
			attr = axiom_attribute_create(env, SAML_NAME_QUALIFIER, id->name_qualifier, NULL);
			axiom_element_add_attribute(e, env, attr, n);
		}
		if (id->name)
		{
			axiom_element_set_text(e, env, id->name, n);
		}
	}	
	return n;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_named_id_get_name(saml_named_id_t *id, const axutil_env_t *env)
{
	return id->name;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_named_id_get_format(saml_named_id_t *id, const axutil_env_t *env)
{
	return id->format;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_named_id_get_name_qualifier(saml_named_id_t *id, 
								 const axutil_env_t *env)
{
	return id->name_qualifier;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_named_id_set_name(saml_named_id_t *id, const axutil_env_t *env, 
					   axis2_char_t *name)
{
	if (id->name)
	{
		AXIS2_FREE(env->allocator, id->name);
	}
	id->name = axutil_strdup(env, name);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_named_id_set_format(saml_named_id_t *id, const axutil_env_t *env, 
						 axis2_char_t *format)
{
	if (id->format)
	{
		AXIS2_FREE(env->allocator, id->format);
	}
	id->format = axutil_strdup(env, format);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_named_id_set_name_qualifier(saml_named_id_t *id, const axutil_env_t *env, 
								 axis2_char_t *qualifier)
{
	if (id->name_qualifier)
	{
		AXIS2_FREE(env->allocator, id->name_qualifier);
	}
	id->name_qualifier = axutil_strdup(env, qualifier);
	return AXIS2_SUCCESS;
}


AXIS2_EXTERN saml_subject_t * AXIS2_CALL 
saml_subject_create(const axutil_env_t *env)
{
	saml_subject_t *subject = AXIS2_MALLOC(env->allocator, sizeof(saml_subject_t));
	if (subject)
	{
		subject->named_id = NULL;
		subject->confirmation_data = NULL;
		subject->confirmation_methods = NULL;
		subject->key_info = NULL;
	}
	return subject;	
}

AXIS2_EXTERN void AXIS2_CALL 
saml_subject_free(saml_subject_t *subject, const axutil_env_t *env)
{
	/*if (subject->named_id)
	{
		saml_named_id_free(subject->named_id, env);	
	}*/
	if (subject->confirmation_methods)
	{
		axutil_array_list_free(subject->confirmation_methods, env);
	}
	if (subject->confirmation_data)
	{
		subject->confirmation_data = NULL;
	}
	if (subject->key_info)
	{
		subject->key_info = NULL;
	}
	AXIS2_FREE(env->allocator, subject);	
}

AXIS2_EXTERN int AXIS2_CALL 
saml_subject_build(saml_subject_t *subject, axiom_node_t *node, 
				   const axutil_env_t *env)
{
	axiom_element_t *element = NULL;
	axiom_node_t *cn = NULL, *ccn = NULL;
	axiom_element_t *ce = NULL, *cce = NULL;
	axiom_child_element_iterator_t *ci = NULL, *cci = NULL;
	if (axiom_node_get_node_type(node, env) != AXIOM_ELEMENT || (element = (axiom_element_t *)axiom_node_get_data_element(node, env)) == NULL)
	{
		return AXIS2_FAILURE;
	}			
	ci = axiom_element_get_child_elements(element, env, node);
	if (ci)
	{				
		while (AXIS2_TRUE == axiom_child_element_iterator_has_next(ci, env))
		{  					
			cn = axiom_child_element_iterator_next(ci, env);
            ce = axiom_node_get_data_element(cn, env);			            						
			if (0 == axutil_strcmp(axiom_element_get_localname(ce, env), SAML_NAME_IDENTIFIER))
			{
				if (!subject->named_id)
				{
					subject->named_id = saml_named_id_create(env);
				}
				saml_named_id_build(subject->named_id, cn, env);							
			}
			if (0 == axutil_strcmp(axiom_element_get_localname(ce, env), SAML_SUBJECT_CONFIRMATION))
			{
				cci = axiom_element_get_child_elements(ce, env, cn); 
				if (cci)
				{
					while (AXIS2_TRUE == axiom_child_element_iterator_has_next(cci, env))
					{											
						ccn = axiom_child_element_iterator_next(cci, env);
						cce = axiom_node_get_data_element(ccn, env);
						if (0 == axutil_strcmp(axiom_element_get_localname(cce, env), SAML_CONFIRMATION_METHOD))
						{
							if (!subject->confirmation_methods)
							{
								subject->confirmation_methods = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
							}
							axutil_array_list_add(subject->confirmation_methods, env, axiom_element_get_text(cce, env, ccn));
						}
						else if (0 == axutil_strcmp(axiom_element_get_localname(cce, env), SAML_SUBJECT_CONFIRMATION_DATA))
						{
							subject->confirmation_data = ccn;
						}
						else if (0 == axutil_strcmp(axiom_element_get_localname(cce, env), SAML_KEY_INFO))
						{
							subject->key_info = ccn;
						}
						else
						{
							return AXIS2_FAILURE;
						}
					}
				}
			}
        }
	}
	else
	{
		return AXIS2_FAILURE;
	}																		
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_subject_to_om(saml_subject_t *subject, axiom_node_t *parent, 
				   const axutil_env_t *env)
{
	int i = 0, size = 0;
	axiom_element_t *e = NULL, *ce = NULL, *cce = NULL;
	axiom_node_t *n = NULL, *cn = NULL, *ccn = NULL;
	axiom_namespace_t *ns = NULL;
	ns = axiom_namespace_create(env, SAML_NMSP_URI, SAML_PREFIX);
	e = axiom_element_create(env, parent, SAML_SUBJECT, ns, &n);	
	if (e)
	{
		if (subject->named_id)
		{
			saml_named_id_to_om(subject->named_id, n, env);		
		}
		ns = axiom_namespace_create(env, SAML_NMSP_URI, SAML_PREFIX);
		ce = axiom_element_create(env, n, SAML_SUBJECT_CONFIRMATION, ns, &cn);				
		if (ce)
		{
			if (subject->confirmation_methods)
			{
				size = axutil_array_list_size(subject->confirmation_methods, env);
				for (i = 0; i < size; i++)
				{
					ns = axiom_namespace_create(env, SAML_NMSP_URI, SAML_PREFIX);
					cce = axiom_element_create(env, cn, SAML_CONFIRMATION_METHOD, ns, &ccn);
					if (cce)
					{
						axiom_element_set_text(cce, env, axutil_array_list_get(subject->confirmation_methods, env, i), ccn);
					}
				}
			}
			if (subject->confirmation_data)
			{
				ns = axiom_namespace_create(env, SAML_NMSP_URI, SAML_PREFIX);
				cce = axiom_element_create(env, cn, SAML_SUBJECT_CONFIRMATION_DATA, ns, &ccn);
				if (cce)
				{
					axiom_node_add_child(cn, env, subject->confirmation_data);														
				}
			}
			if (subject->key_info)
			{
				axiom_node_add_child(cn, env, subject->key_info);
			}
		}
	}
	return n;
}

AXIS2_EXTERN saml_named_id_t * AXIS2_CALL 
saml_subject_get_named_id(saml_subject_t *subject, const axutil_env_t *env)
{
	return subject->named_id;
}

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_subject_get_confirmation_methods(saml_subject_t *subject, 
									  const axutil_env_t *env)
{
	return subject->confirmation_methods;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_subject_get_confirmation_data(saml_subject_t *subject, const axutil_env_t *env)
{
	return subject->confirmation_data;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_subject_get_key_info(saml_subject_t *subject, const axutil_env_t *env)
{
	return subject->key_info;
}

AXIS2_EXTERN int AXIS2_CALL
saml_subject_set_session_key(saml_subject_t *subject, axutil_env_t *env,
							 axis2_char_t *certificate_file, oxs_key_t *session_key, 
							 axis2_char_t *algorithm)
{
	axiom_node_t *key_info = NULL;    
    axis2_status_t status = AXIS2_FAILURE;
    oxs_asym_ctx_t * asym_ctx = NULL;        
	oxs_x509_cert_t *cert = NULL;

    key_info = oxs_token_build_key_info_element(env, NULL);

    asym_ctx = oxs_asym_ctx_create(env);
    oxs_asym_ctx_set_algorithm(asym_ctx, env, algorithm);
    oxs_asym_ctx_set_operation(asym_ctx, env,
                               OXS_ASYM_CTX_OPERATION_PUB_ENCRYPT);

	cert = oxs_key_mgr_load_x509_cert_from_pem_file(env, certificate_file);
	if (!cert)
	{
		AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[oxs][saml]Cannot load the certificate to encrypt the ses. key.");
        return AXIS2_FAILURE;
	}
    oxs_asym_ctx_set_certificate(asym_ctx, env, cert);    
    status = oxs_xml_enc_encrypt_key(env,
                            asym_ctx,
                            key_info,
                            session_key,
                            NULL);
	if (status == AXIS2_FAILURE)
	{
		AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[oxs][saml]Session key encryption failed");
        return AXIS2_FAILURE;
	}
	subject->key_info = key_info;    
	saml_subject_add_confirmation(subject, env, SAML_SUB_CONFIRMATION_HOLDER_OF_KEY);
    return AXIS2_SUCCESS;											
}

AXIS2_EXTERN int AXIS2_CALL 
saml_subject_set_named_id(saml_subject_t *subject, 
						  const axutil_env_t *env, saml_named_id_t *named_id)
{
	if (subject->named_id)
	{
		saml_named_id_free(subject->named_id, env);
	}
	subject->named_id = named_id;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_subject_set_confirmation_methods(saml_subject_t *subject, 
									  const axutil_env_t *env, 
									  axutil_array_list_t *list)
{
	int i = 0, size = 0;
	axis2_char_t *val = NULL;
	if (subject->confirmation_methods)
	{
		size = axutil_array_list_size(subject->confirmation_methods, env);
		for (i = 0; i < size; i++)
		{
			val =  axutil_array_list_get(subject->confirmation_methods, env, i);
			if (val)
			{
				AXIS2_FREE(env->allocator, val);
			}
		}
		axutil_array_list_free(subject->confirmation_methods, env);
		subject->confirmation_methods = list;
	}
	else
	{
		subject->confirmation_methods = list;
	}
	return AXIS2_SUCCESS;
}


AXIS2_EXTERN int AXIS2_CALL 
saml_subject_add_confirmation(saml_subject_t *subject, 
							  const axutil_env_t *env, axis2_char_t *sub_confirmation)
{
	if (!subject->confirmation_methods)
	{
		subject->confirmation_methods = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF * 2);
	}
	axutil_array_list_add(subject->confirmation_methods, env, axutil_strdup(env, sub_confirmation));
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_subject_remove_subject_confiirmation(saml_subject_t *subject, 
										  const axutil_env_t *env, int index)
{
	axis2_char_t *val = NULL;
	if (subject->confirmation_methods && axutil_array_list_size(subject->confirmation_methods, env) > index)
	{
		val = axutil_array_list_remove(subject->confirmation_methods, env, index);			
		if (val)
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
saml_subject_set_key_info(saml_subject_t *subject, 
						  const axutil_env_t *env, axiom_node_t *node)
{
	if (subject->key_info)
	{
		axiom_node_free_tree(subject->key_info, env);
	}
	subject->key_info = node;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN saml_subject_stmt_t * AXIS2_CALL 
saml_subject_stmt_create(const axutil_env_t *env)
{
	saml_subject_stmt_t *stmt = AXIS2_MALLOC(env->allocator, sizeof(saml_subject_stmt_t));
	if (stmt)
	{
		if (!(stmt->subject = saml_subject_create(env)))
		{
			AXIS2_FREE(env->allocator, stmt);
			return NULL;
		}
	}
	return stmt;
}

AXIS2_EXTERN void AXIS2_CALL 
saml_subject_stmt_free(saml_subject_stmt_t *subject_stmt,
					   const axutil_env_t *env)
{
	saml_subject_free(subject_stmt->subject, env);
	AXIS2_FREE(env->allocator, subject_stmt);
}

AXIS2_EXTERN int AXIS2_CALL 
saml_subject_stmt_build(saml_subject_stmt_t *subject_stmt, 
						axiom_node_t *node, const axutil_env_t *env)
{
	axiom_element_t *element = NULL;	
	axiom_node_t *first_enode = NULL;
	axiom_element_t *first_element;
	if (axiom_node_get_node_type(node, env) != AXIOM_ELEMENT || (element = (axiom_element_t *)axiom_node_get_data_element(node, env)) == NULL)
	{
		return AXIS2_FAILURE;
	}
	if ((first_element = axiom_element_get_first_element(element, env, node, &first_enode)) != NULL && 0 == axutil_strcmp(axiom_element_get_localname(element, env), SAML_SUBJECT))
	{
		saml_subject_build(subject_stmt->subject, first_enode, env);		
		return AXIS2_SUCCESS;
	}
	return AXIS2_FAILURE;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_subject_stmt_to_om(saml_subject_stmt_t *subject_stmt, 
						axiom_node_t *parent, const axutil_env_t *env)
{
	axiom_element_t *e = NULL;
	axiom_node_t *n = NULL;
	axiom_namespace_t *ns = NULL;
	ns = axiom_namespace_create(env, SAML_NMSP_URI, SAML_PREFIX);
	e = axiom_element_create(env, parent, SAML_SUBJECT_STATEMENT, ns, &n);
	if (e)
	{
		saml_subject_to_om(subject_stmt->subject, n, env);
	}
	return n;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_subject_stmt_set_subject(saml_subject_stmt_t *subject_stmt, 
							  const axutil_env_t *env, saml_subject_t *subject)
{
	saml_subject_free(subject_stmt->subject, env);
	subject_stmt->subject = subject;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN saml_subject_t * AXIS2_CALL 
saml_subject_stmt_get_subject(saml_subject_stmt_t *subject_stmt, 
							  const axutil_env_t *env)
{
	return subject_stmt->subject;	
}
