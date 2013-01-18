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

AXIS2_EXTERN saml_status_t* AXIS2_CALL saml_status_create(const axutil_env_t *env)
{
	saml_status_t *status = NULL;
	status = (saml_status_t*)AXIS2_MALLOC(env->allocator, sizeof(saml_status_t));

	if(status)
	{
		status->status_value = NULL;
		status->status_msg = NULL;
		status->status_code = NULL;
		status->status_detail = NULL;
	}
	return status;
}
AXIS2_EXTERN void saml_status_free(saml_status_t *status, const axutil_env_t *env)
{
	if(status->status_value)
	{
		axutil_qname_free(status->status_value, env);
	}
	if(status->status_code)
	{
		AXIS2_FREE(env->allocator, status->status_code);
	}
	if(status->status_msg)
	{
		AXIS2_FREE(env->allocator, status->status_msg);
	}
	status->status_detail = NULL;
	AXIS2_FREE(env->allocator, status);
	status = NULL;
}

AXIS2_EXTERN int AXIS2_CALL saml_status_build(saml_status_t *status, 
											  axiom_node_t *node, 
											  const axutil_env_t *env)
{
	
	axiom_element_t *element = NULL;
	axiom_child_element_iterator_t *iterator = NULL;
	axiom_node_t *child_node;
	axis2_char_t *qname = NULL;

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
																		SAML_STATUS_CODE)))
			{
				qname = axiom_element_get_attribute_value_by_name(element, env, SAML_STATUS_VALUE);
				if(qname)
					status->status_value = axutil_qname_create_from_string(env, qname); 

			}
			else if(element != NULL && !(axutil_strcmp(axiom_element_get_localname(element, env), 
																		SAML_STATUS_MESSAGE)))
			{
				status->status_msg = 	axiom_element_get_text(element, env, child_node);
			}
			else if(element != NULL && !(axutil_strcmp(axiom_element_get_localname(element, env), 
																		SAML_STATUS_DETAIL)))
			{
				status->status_detail = child_node;
			}
		}
		return AXIS2_SUCCESS;
	}
	return AXIS2_FAILURE;

}

AXIS2_EXTERN axiom_node_t* AXIS2_CALL saml_status_to_om(saml_status_t *status, 
														axiom_node_t *parent, 
														const axutil_env_t *env)
{	
	axiom_element_t *e = NULL, *ce = NULL;
	axiom_node_t *n = NULL, *cn = NULL;	
	axiom_namespace_t *ns = NULL;
	axiom_attribute_t *attr = NULL;

	ns = axiom_namespace_create(env, SAML_PROTOCOL_NMSP, SAML_PROTOCOL_PREFIX);
	e = axiom_element_create(env, parent, SAML_STATUS, ns, &n);

	if(e)
	{
		if(status->status_detail)
		{
			
			axiom_node_add_child(n, env, status->status_detail);
			
		}
		if(status->status_msg)
		{	
			ns = axiom_namespace_create(env, SAML_PROTOCOL_NMSP, SAML_PROTOCOL_PREFIX);
			ce = axiom_element_create(env, n, SAML_STATUS_MESSAGE, ns, &cn);
			if(ce)
			{
				axiom_element_set_text(ce, env, status->status_msg, cn);
			}
		}
		if(status->status_code)
		{	
			ns = axiom_namespace_create(env, SAML_PROTOCOL_NMSP, SAML_PROTOCOL_PREFIX);
			ce = axiom_element_create(env, n, SAML_STATUS_CODE, ns, &cn);
			if(ce)
			{
				axiom_element_set_text(ce, env, status->status_code, cn);
				attr = axiom_attribute_create(env, SAML_STATUS_VALUE,axutil_qname_to_string(status->status_value, env), NULL);
				axiom_element_add_attribute(ce, env, attr, cn);
			}
		}
	}
	return n;
	
}

AXIS2_EXTERN int AXIS2_CALL saml_status_set_status_value(saml_status_t *status, const axutil_env_t *env, axutil_qname_t *qname)
{
	if(status->status_value)
	{
		axutil_qname_free(status->status_value, env);
	}
	status->status_value = qname;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN axutil_qname_t* AXIS2_CALL saml_status_get_status_value(saml_status_t *status, const axutil_env_t *env)
{
	if(status)
		return status->status_value;
	else
		return NULL;
}
AXIS2_EXTERN int AXIS2_CALL saml_status_set_status_msg(saml_status_t *status, const axutil_env_t *env,  axis2_char_t *msg)
{
	if(status)
	{
		AXIS2_FREE(env->allocator, status->status_msg);
	}
	status->status_msg = axutil_strdup(env, msg);
	return AXIS2_SUCCESS;
}
AXIS2_EXTERN axis2_char_t* AXIS2_CALL saml_status_get_status_msg(saml_status_t *status, const axutil_env_t *env)
{
	if(status)
		return status->status_msg;
	else
		return NULL;
}
AXIS2_EXTERN int AXIS2_CALL saml_status_set_status_detail(saml_status_t *status, axiom_node_t *det, const axutil_env_t *env)
{
	if(status->status_detail)
	{
		axiom_node_free_tree(status->status_detail, env);
	}
	status->status_detail = det;
	return AXIS2_SUCCESS;
}
AXIS2_EXTERN axiom_node_t* AXIS2_CALL saml_status_get_status_detail(saml_status_t *status, const axutil_env_t *env)
{
	if(status)
		return status->status_detail;
	else
		return NULL;
}

AXIS2_EXTERN saml_response_t* saml_response_create(const axutil_env_t *env)
{
	saml_response_t *response = NULL;
	response = (saml_response_t*)AXIS2_MALLOC(env->allocator, sizeof(saml_response_t));
	if(response)
	{
		response->response_id = NULL;
		response->issue_instant = NULL;
		response->major_version = NULL;
		response->minor_version = NULL;
		response->recepient = NULL;
		response->request_response_id = NULL;
		response->sig_ctx = NULL;
		response->status = saml_status_create(env);
		response->saml_assertions = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
		response->signature = NULL;
		response->original_xml = NULL;
	}
	return response;
}
AXIS2_EXTERN void saml_response_free(saml_response_t *response, const axutil_env_t *env)
{
	int size =0, i = 0;
	saml_assertion_t *assertion = NULL;
	if(response->major_version)
	{
		AXIS2_FREE(env->allocator, response->major_version);
	}
	if(response->minor_version)
	{
		AXIS2_FREE(env->allocator, response->minor_version);
	}
	if(response->issue_instant)
	{
		axutil_date_time_free(response->issue_instant, env);
	}
	if(response->recepient)
	{
		AXIS2_FREE(env->allocator, response->recepient);
	}
	if(response->response_id)
	{
		AXIS2_FREE(env->allocator, response->response_id);
	}
	if(response->sig_ctx)
	{
		oxs_sign_ctx_free(response->sig_ctx, env);
	}
	if(response->status)
	{
		saml_status_free(response->status, env);
	}
	if(response->request_response_id)
	{
		AXIS2_FREE(env->allocator, response->request_response_id);
	}
	if(response->saml_assertions)
	{
		size = axutil_array_list_size(response->saml_assertions, env);
		for(i = 0; i < size ; i++)
		{
			assertion = (saml_assertion_t*)axutil_array_list_get(response->saml_assertions, env, i);
			if(assertion)
			{
				saml_assertion_free(assertion, env);
			}
		}
		axutil_array_list_free(response->saml_assertions, env);
	}
	response->original_xml = NULL;
	response->signature = NULL;
	AXIS2_FREE(env->allocator, response);
	response = NULL;
}

AXIS2_EXTERN int AXIS2_CALL saml_response_build(saml_response_t *response,
												axiom_node_t *node, 
												const axutil_env_t *env)
{
	axutil_hash_t *attr_hash = NULL;
	axiom_element_t *element = NULL;
	axutil_hash_index_t *hi = NULL;
	axiom_child_element_iterator_t *iterator = NULL;
	axiom_node_t *child_node;
	saml_assertion_t *assertion;

	if (axiom_node_get_node_type(node, env) != AXIOM_ELEMENT)
	{
		return AXIS2_FAILURE;
	}
	
	if ((element = axiom_node_get_data_element(node, env)) == NULL)
	{
		return AXIS2_FAILURE;
	}
	
	response->original_xml = node;
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

			if(!axutil_strcmp(axiom_attribute_get_localname(attr, env), SAML_RESPONSE_ID))
			{
				response->response_id=  attr_val;
			}
			if(!axutil_strcmp(axiom_attribute_get_localname(attr, env), SAML_IN_RESPONSE_TO))
			{
				response->request_response_id =  attr_val;
			}
			else if(!axutil_strcmp(axiom_attribute_get_localname(attr, env), SAML_MAJORVERSION))
			{
				response->major_version = attr_val;
			}
			else if(!axutil_strcmp(axiom_attribute_get_localname(attr, env), SAML_MINORVERSION))
			{
				response->minor_version = attr_val;
			}
			else if(!axutil_strcmp(axiom_attribute_get_localname(attr, env), SAML_ISSUE_INSTANT))
			{
				response->issue_instant = axutil_date_time_create(env);
				axutil_date_time_deserialize_date(response->issue_instant, env, attr_val);
			}
			else if(!axutil_strcmp(axiom_attribute_get_localname(attr, env), SAML_RECEPIENT))
			{
				response->recepient = attr_val;
			}
		}
	}

	iterator = axiom_element_get_child_elements(element, env, node);
	if(iterator)
	{
		while(axiom_child_element_iterator_has_next(iterator, env))
		{
		
			axis2_char_t *t = NULL;
			child_node = axiom_child_element_iterator_next(iterator, env);
			element = (axiom_element_t *)axiom_node_get_data_element(child_node, env);
			t = axiom_node_to_string(child_node, env);
			if(element != NULL && !(axutil_strcmp(axiom_element_get_localname(element, env),
																		SAML_SIGNATURE)))
			{
				response->signature = child_node;
			}
			else if(element != NULL && !(axutil_strcmp(axiom_element_get_localname(element, env), 
																		SAML_STATUS)))
			{
				response->status = (saml_status_t*)AXIS2_MALLOC(env->allocator,
															sizeof(saml_status_t));
				if(response->status)
				{
					saml_status_build(response->status, child_node, env);
				}
			}
			else if(element != NULL && !(axutil_strcmp(axiom_element_get_localname(element, env), 
																		SAML_ASSERTION)))
			{
				assertion = saml_assertion_create(env);
				if(assertion)
				{
					saml_assertion_build(assertion, child_node, env);
					axutil_array_list_add(response->saml_assertions, env, assertion);
				}
			}
		
		}

	}

	return AXIS2_SUCCESS;



}

AXIS2_EXTERN axiom_node_t* AXIS2_CALL saml_response_to_om(saml_response_t *response, 
														  axiom_node_t *parent, 
														  const axutil_env_t *env)
{
	int size = 0, i = 0;
	axiom_element_t *e = NULL;
	axiom_node_t *n = NULL;	
	axiom_namespace_t *ns = NULL;
	axiom_attribute_t *attr = NULL;
	saml_assertion_t *assertion = NULL;
	axis2_char_t *t = NULL;
	ns = axiom_namespace_create(env, SAML_PROTOCOL_NMSP, SAML_PROTOCOL_PREFIX);
	e = axiom_element_create(env, parent, SAML_RESPONSE, ns, &n);
	
	if(e)
	{
		if(response->minor_version && response->issue_instant)
		{
			if(!response->response_id)
				response->response_id = saml_id_generate_random_bytes(env);
			attr = axiom_attribute_create(env, SAML_RESPONSE_ID, response->response_id, NULL);
			axiom_element_add_attribute(e, env, attr, n);
			
			attr = axiom_attribute_create(env, SAML_MAJORVERSION, SAML_MAJOR_VERSION, NULL);
			axiom_element_add_attribute(e, env, attr, n);
			
			attr = axiom_attribute_create(env, SAML_MINORVERSION, response->minor_version, NULL);
			axiom_element_add_attribute(e, env, attr, n);

			attr = axiom_attribute_create(env, SAML_ISSUE_INSTANT, axutil_date_time_serialize_date_time(response->issue_instant, env), NULL);
			axiom_element_add_attribute(e, env, attr, n);
		}
		else
		{
			return NULL;
		}
		t = axiom_node_to_string(n, env);
		if(response->request_response_id && response->recepient)
		{
			attr = axiom_attribute_create(env, SAML_IN_RESPONSE_TO, response->request_response_id, NULL);
			axiom_element_add_attribute(e, env, attr, n);
			attr = axiom_attribute_create(env, SAML_RECEPIENT, response->recepient, NULL);
			axiom_element_add_attribute(e, env, attr, n);
		
		}
		t = axiom_node_to_string(n, env);

		if(response->saml_assertions)
		{
			size = axutil_array_list_size(response->saml_assertions, env);

			for(i = 0 ; i < size ; i++)
			{
				assertion = (saml_assertion_t*)axutil_array_list_get(response->saml_assertions, env, i);
				if(assertion)
					saml_assertion_to_om(assertion, n, env);

			}
		}
		if(response->status)
		{
			saml_status_to_om(response->status, n, env);
		}
		if(response->sig_ctx)
		{
			saml_response_sign(response, n, env);		
		}
	}
	return n;


}
AXIS2_EXTERN axis2_char_t* AXIS2_CALL saml_response_get_id(saml_response_t *response, const axutil_env_t *env)
{
	if(response)
	{
		return response->response_id;
	}
	else
		return NULL;
}
AXIS2_EXTERN int AXIS2_CALL saml_response_set_major_version(saml_response_t *response, const axutil_env_t *env, int version)
{
	if(response->major_version)
	{
		AXIS2_FREE(env->allocator,response->major_version);
	}
	response->minor_version = AXIS2_MALLOC(env->allocator,8);
	sprintf(response->major_version, "%d", version);	
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL saml_response_set_minor_version(saml_response_t *response, const axutil_env_t *env, int version)
{
	if(response->minor_version)
	{
		AXIS2_FREE(env->allocator,response->minor_version);
	}
	response->minor_version = AXIS2_MALLOC(env->allocator, 8);
	sprintf(response->minor_version, "%d", version);	
	return AXIS2_SUCCESS;
}
AXIS2_EXTERN int AXIS2_CALL saml_response_set_issue_instant(saml_response_t *response, const axutil_env_t *env, axutil_date_time_t *date_time)
{
	if(response->issue_instant)
	{
		axutil_date_time_free(response->issue_instant, env);
	}
	response->issue_instant = date_time;
	return AXIS2_SUCCESS;
}
AXIS2_EXTERN axutil_date_time_t* AXIS2_CALL saml_response_get_issue_instant(saml_response_t *response, const axutil_env_t *env)
{
	if(response)
		return response->issue_instant;
	else
		return NULL;
}

AXIS2_EXTERN int AXIS2_CALL saml_response_set_recepient(saml_response_t *response, const axutil_env_t *env, axis2_char_t *recepient)
{
	if(response->recepient)
	{
		AXIS2_FREE(env->allocator, response->issue_instant);
	}
	response->recepient= axutil_strdup(env, recepient);
	return AXIS2_SUCCESS;
}
AXIS2_EXTERN axis2_char_t* AXIS2_CALL saml_response_get_recepient(saml_response_t *response, const axutil_env_t *env)
{
	if(response)
		return response->recepient;
	else
		return NULL;
}

AXIS2_EXTERN int AXIS2_CALL saml_response_set_status(saml_response_t *response, const axutil_env_t *env, saml_status_t *status)
{
	if(response->status)
	{
		saml_status_free(response->status, env);
	}
	response->status = status;
	return AXIS2_SUCCESS;
}
AXIS2_EXTERN saml_status_t* AXIS2_CALL saml_response_get_status(saml_response_t *response, const axutil_env_t *env)
{
	if(response)
		return response->status;
	else
		return NULL;
}

AXIS2_EXTERN int AXIS2_CALL saml_response_set_assertions(saml_response_t *response, const axutil_env_t *env, axutil_array_list_t *assertions)
{
	int size = 0, i = 0;
	saml_assertion_t *assert = NULL;
	if(response->saml_assertions)
	{
		size = axutil_array_list_size(response->saml_assertions, env);
		for(i = 0; i < size; i++)
		{
			assert = (saml_assertion_t*)axutil_array_list_get(response->saml_assertions, env, i);
			if(assert)
				saml_assertion_free(assert, env);
		}
		axutil_array_list_free(response->saml_assertions, env);
	}
	response->saml_assertions = assertions;
	return AXIS2_SUCCESS;
}
AXIS2_EXTERN axutil_array_list_t*  AXIS2_CALL saml_response_get_assertions(saml_response_t *response, const axutil_env_t *env)
{
	if(response)
		return response->saml_assertions;
	else
		return NULL;
}

AXIS2_EXTERN int AXIS2_CALL saml_response_add_assertion(saml_response_t *response, const axutil_env_t *env, saml_assertion_t *assertion)
{
	if(!response->saml_assertions)
	{
		axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
	}
	axutil_array_list_add(response->saml_assertions, env, assertion);
	return AXIS2_SUCCESS;
}
AXIS2_EXTERN int AXIS2_CALL saml_response_remove_assertion(saml_response_t *response, const axutil_env_t *env, int index)
{
	saml_assertion_t *assert;
	if(response->saml_assertions)
	{
		assert = axutil_array_list_remove(response->saml_assertions, env, index);
		if(assert)
		{
			saml_assertion_free(assert, env);
		}
		
	}
	return AXIS2_FAILURE;
}
AXIS2_EXTERN int AXIS2_CALL saml_response_set_in_reponses_to(saml_response_t *response, const axutil_env_t *env, axis2_char_t *request_response)
{
	if(response->request_response_id)
	{
		AXIS2_FREE(env->allocator,response->request_response_id);
	}
	response->request_response_id = axutil_strdup(env, request_response);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t* AXIS2_CALL saml_response_get_in_reponses_to(saml_response_t *response, const axutil_env_t *env)
{
	if(response)
		return response->request_response_id;
	else
		return NULL;
}
AXIS2_EXTERN int AXIS2_CALL saml_response_set_signature(saml_response_t *response, const axutil_env_t *env, oxs_sign_ctx_t *sig_ctx)
{
	if(response->sig_ctx)
	{
		oxs_sign_ctx_free(response->sig_ctx, env);
	}
	response->sig_ctx = sig_ctx;
	return AXIS2_SUCCESS;
}
AXIS2_EXTERN int AXIS2_CALL saml_response_unset_signature(saml_response_t *response, const axutil_env_t *env)
{
	if(response->sig_ctx)
	{
		oxs_sign_ctx_free(response->sig_ctx, env);
	}
	response->sig_ctx = NULL;
	return AXIS2_SUCCESS;
}
AXIS2_EXTERN int AXIS2_CALL saml_response_sign(saml_response_t *response, axiom_node_t *node, const axutil_env_t *env)
{
	 axiom_node_t *n= NULL;
	 axis2_char_t *id = NULL;	 
	 oxs_sign_part_t* sig_part = NULL;
	 axutil_array_list_t *sig_parts = NULL;
	 int size = 0, i = 0;

	 sig_parts = oxs_sign_ctx_get_sign_parts(response->sig_ctx, env);
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
	id = axiom_node_to_string(node, env);
	 oxs_xml_sig_sign(env, response->sig_ctx, node, &n);
	id = axiom_node_to_string(node, env);
	id = axiom_node_to_string(n, env);

     /*Finally build KeyInfo*/
	 oxs_xml_key_info_build(env, n, oxs_sign_ctx_get_certificate(response->sig_ctx, env), OXS_KIBP_X509DATA_X509CERTIFICATE);
	 return AXIS2_SUCCESS;
}
AXIS2_EXTERN void AXIS2_CALL saml_response_set_default_signature(saml_response_t *response, const axutil_env_t *env, oxs_sign_ctx_t *sig_ctx)
{
	if(response->sig_ctx)
	{
		oxs_sign_ctx_free(response->sig_ctx, env);
	}
	response->sig_ctx = sig_ctx;
	saml_util_set_sig_ctx_defaults(response->sig_ctx, env, SAML_RESPONSE_ID);
}
AXIS2_EXTERN int AXIS2_CALL saml_status_set_status_code(saml_status_t *status, const axutil_env_t *env, axis2_char_t *code)
{
	if(status->status_code)
	{
		AXIS2_FREE(env->allocator, status->status_code);
	}
	status->status_code = axutil_strdup(env, code);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL
saml_response_signature_verify(saml_response_t *response, const axutil_env_t *env)
{			
	return oxs_xml_sig_verify(env, response->sig_ctx, response->signature, response->original_xml);
}

AXIS2_EXTERN int AXIS2_CALL
saml_response_is_sign_set(saml_response_t *response, const axutil_env_t *env)
{
	if (response->sig_ctx)
	{
		return AXIS2_TRUE;
	}
	return AXIS2_FALSE;
}

AXIS2_EXTERN int AXIS2_CALL
saml_response_is_signed(saml_response_t *response, const axutil_env_t *env)
{
	if (response->signature)
	{
		return AXIS2_TRUE;
	}
	return AXIS2_FALSE;
}

