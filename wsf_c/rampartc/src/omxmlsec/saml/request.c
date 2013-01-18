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

AXIS2_EXTERN saml_artifact_t* AXIS2_CALL saml_artifact_create(const axutil_env_t *env)
{
	saml_artifact_t *artifact = NULL;
	
	artifact = AXIS2_MALLOC(env->allocator, sizeof(saml_artifact_t));
	if(artifact)
	{
		artifact->artifact = NULL;
	}
	return artifact;
}
AXIS2_EXTERN void AXIS2_CALL saml_artifact_free(saml_artifact_t *artifact, const axutil_env_t *env)
{
	if(artifact->artifact)
	{
		AXIS2_FREE(env->allocator, artifact->artifact);
	}
	AXIS2_FREE(env->allocator, artifact);
	artifact = NULL;
}
AXIS2_EXTERN axis2_char_t* AXIS2_CALL saml_artifact_get_data(saml_artifact_t *artifact, const axutil_env_t *env)
{
	if(artifact)
		return artifact->artifact;
	else
		return NULL;
}
AXIS2_EXTERN int AXIS2_CALL saml_artifact_set_data(saml_artifact_t *artifact, const axutil_env_t *env, axis2_char_t *data)
{
	if(artifact->artifact)
	{
		AXIS2_FREE(env->allocator, artifact->artifact);
	}
	artifact->artifact = axutil_strdup(env, data);

	return AXIS2_SUCCESS;
}


AXIS2_EXTERN saml_request_t* AXIS2_CALL saml_request_create(const axutil_env_t *env)
{
	saml_request_t *request = NULL;

	request = (saml_request_t*)AXIS2_MALLOC(env->allocator, sizeof(saml_request_t));

	if(request)
	{
		request->issue_instant = NULL;
		request->major_version = NULL;
		request->query = NULL;
		request->minor_version = NULL;
		request->saml_asserion_id_ref = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
		request->saml_artifacts = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
		request->saml_responds = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
		request->sig_ctx = NULL;
		request->request_id = NULL;
		request->signature = NULL;
		request->original_xml = NULL;
	}
	return request;
}
AXIS2_EXTERN void AXIS2_CALL saml_request_free(saml_request_t *request, const axutil_env_t *env)
{
	int size = 0, i = 0;
	saml_artifact_t *artifact = NULL;
	axutil_qname_t *respond = NULL;

	if(request->request_id)
	{
		AXIS2_FREE(env->allocator, request->request_id);
	}
	if(request->issue_instant)
	{
		axutil_date_time_free(request->issue_instant, env);
	}
	if(request->major_version)
	{
		AXIS2_FREE(env->allocator, request->major_version);
	}
	if(request->minor_version)
	{
		AXIS2_FREE(env->allocator, request->minor_version);
	}
	if(request->query)
	{
		saml_query_free(request->query, env);
	}
	if(request->sig_ctx)
	{
		oxs_sign_ctx_free(request->sig_ctx, env);
	}
	if(request->saml_artifacts)
	{
		size = axutil_array_list_size(request->saml_artifacts, env);
		for(i = 0; i < size ; i++)
		{
			artifact = (saml_artifact_t*)axutil_array_list_get(request->saml_artifacts, env , i);
			if(artifact)
				saml_artifact_free(artifact, env);
		}

		axutil_array_list_free(request->saml_artifacts, env);
	}
	if(request->saml_asserion_id_ref)
	{
		axis2_char_t *id_ref = NULL;

		size = axutil_array_list_size(request->saml_asserion_id_ref, env);
		for(i = 0; i < size ; i++)
		{
			id_ref = (axis2_char_t*)axutil_array_list_get(request->saml_asserion_id_ref, env , i);
			if(id_ref)
				AXIS2_FREE(env->allocator, id_ref);
		}

		axutil_array_list_free(request->saml_asserion_id_ref, env);
	}
	if(request->saml_responds)
	{

		size = axutil_array_list_size(request->saml_responds, env);
		for(i = 0; i < size ; i++)
		{
			respond = (axutil_qname_t*)axutil_array_list_get(request->saml_responds, env , i);
			if(respond)
				axutil_qname_free(respond, env);
		}

		axutil_array_list_free(request->saml_responds, env);
	}
	request->original_xml = NULL;
	request->signature = NULL;
	AXIS2_FREE(env->allocator, request);
	request = NULL;

}

AXIS2_EXTERN int AXIS2_CALL saml_request_build(saml_request_t *request, 
											   axiom_node_t *node, 
											   const axutil_env_t *env)
{
	/*populate the saml request struct from the axiom om node struct*/
	axutil_hash_t *attr_hash = NULL;
	axiom_element_t *element = NULL;
	axutil_hash_index_t *hi = NULL;
	axiom_child_element_iterator_t *iterator = NULL;
	axiom_node_t *child_node = NULL;
	axis2_char_t *element_local_name = NULL;
	saml_artifact_t *artifact = NULL;

	if (axiom_node_get_node_type(node, env) != AXIOM_ELEMENT)
	{
		return AXIS2_FAILURE;
	}
	if ((element = axiom_node_get_data_element(node, env)) == NULL)
	{
		return AXIS2_FAILURE;
	}
	/* Get all the the attributes */
	attr_hash = axiom_element_get_all_attributes(element, env);	
	request->original_xml = node;
	if(attr_hash)
	{
		/*for each attribute*/
		for (hi = axutil_hash_first(attr_hash, env); hi; hi = axutil_hash_next(env, hi))
		{
			void *v = NULL;
			axutil_hash_this(hi, NULL, NULL, &v);
			if (v)
			{
				axis2_char_t *attr_val = NULL;
				axiom_attribute_t *attr = (axiom_attribute_t*)v;			
				attr_val = axiom_attribute_get_value(attr, env);

				if(!axutil_strcmp(axiom_attribute_get_localname(attr, env), SAML_REQUEST_ID))
				{
					request->request_id = attr_val; 
				}
				else if(!axutil_strcmp(axiom_attribute_get_localname(attr, env), SAML_MAJORVERSION))
				{
					request->major_version = attr_val;
				}
				else if(!axutil_strcmp(axiom_attribute_get_localname(attr, env), SAML_MINORVERSION))
				{
					request->minor_version = attr_val;
				}
				else if(!axutil_strcmp(axiom_attribute_get_localname(attr, env), SAML_ISSUE_INSTANT))
				{
					request->issue_instant = axutil_date_time_create(env);
					axutil_date_time_deserialize_date(request->issue_instant, env, attr_val);
				}
			}
		}
	}
	/* Get all child elements of <samlp:Request>*/

	iterator = axiom_element_get_child_elements(element, env, node);
	if(iterator)
	{
		while(axiom_child_element_iterator_has_next(iterator, env))
		{
		
			child_node = axiom_child_element_iterator_next(iterator, env);
			element = (axiom_element_t *)axiom_node_get_data_element(child_node, env);
			if(element)
				element_local_name = axiom_element_get_localname(element, env);

			if(element != NULL && !(axutil_strcmp(element_local_name, SAML_RESPOND_WITH)))
			{				
				axutil_array_list_add(request->saml_responds, 
					env, 
					axiom_element_get_qname(element, env, child_node));

			}
			else if(element != NULL && !(axutil_strcmp(element_local_name,SAML_SIGNATURE)))
			{
				/*Set the reference of the <ds:Signature> of the request struct to verify*/
				request->signature = child_node;
			}
			/* Check for the saml queries*/
			else if(element != NULL && !(axutil_strcmp(element_local_name, SAML_SUBJECT_QUERY)))
			{
				request->query = saml_query_create(env);
				if(request->query)
				{
					/*populate the saml subject query*/
					request->query->type = element_local_name;
					if(saml_query_build(request->query, child_node, env)== AXIS2_FAILURE)
					{
						saml_query_free(request->query, env);
					}
				}
			}
			else if(element != NULL && !(axutil_strcmp(element_local_name,SAML_AUTHENTICATION_QUERY)))
			{
				request->query = saml_query_create(env);
				if(request->query)
				{
					/*populate the saml authentication query*/
					request->query->type = axutil_strdup(env, element_local_name);
					if(saml_query_build(request->query, child_node, env)== AXIS2_FAILURE)
					{
						saml_query_free(request->query, env);
					}
				}
			}
			else if(element != NULL && !(axutil_strcmp(element_local_name,SAML_AUTHORIZATION_DECISION_QUERY)))
			{
				request->query = saml_query_create(env);
				if(request->query)
				{
					/*populate the saml authorization decision query*/
					request->query->type = axutil_strdup(env, element_local_name);;
					if(saml_query_build(request->query, child_node, env)== AXIS2_FAILURE)
					{
						saml_query_free(request->query, env);
					}
				}
			}
			else if(element != NULL && !(axutil_strcmp(element_local_name, SAML_ATTRIBUTE_QUERY)))
			{
				request->query = saml_query_create(env);
				if(request->query)
				{
					/*populate the saml attribute query*/
					request->query->type = axutil_strdup(env, element_local_name);;
					if(saml_query_build(request->query, child_node, env)== AXIS2_FAILURE)
					{
						saml_query_free(request->query, env);
					}
				}
			}
			else if(element != NULL && !(axutil_strcmp(element_local_name,SAML_ASSERTION_ID_REFERENCE)))
			{
				axutil_array_list_add(request->saml_asserion_id_ref, 
					env, 
					axiom_element_get_text(element, env, child_node));
			}
			else if(element != NULL && !(axutil_strcmp(element_local_name, SAML_ASSERTION_ARTIFACT)))
			{
				artifact = saml_artifact_create(env);
				if(artifact)
				{
					/*populate the saml artifacts*/
					artifact->artifact = axiom_element_get_text(element, env, child_node);
					axutil_array_list_add(request->saml_artifacts, 
						env, 
					artifact);
				}
			}
		}
	}

	return AXIS2_SUCCESS;


}

AXIS2_EXTERN axiom_node_t* AXIS2_CALL saml_request_to_om(saml_request_t *request, 
														 axiom_node_t *parent, 
														 const axutil_env_t *env)
{
	int size = 0, i = 0;
	axiom_element_t *element = NULL, *ce = NULL;
	axiom_node_t *n = NULL, *cn = NULL;	
	axiom_namespace_t *ns1 = NULL, *ns2 = NULL;
	axiom_attribute_t *attr = NULL;
	axutil_qname_t *qname = NULL;
	saml_artifact_t *artifact = NULL;
	axis2_char_t *id_reference = NULL;

	/*construct the <samlp:Request> element*/
	ns1 = axiom_namespace_create(env, SAML_PROTOCOL_NMSP, SAML_PROTOCOL_PREFIX);
	ns2 = axiom_namespace_create(env, SAML_NMSP_URI, SAML_PREFIX);
	element = axiom_element_create(env, parent, SAML_REQUEST, ns1, &n);
	axiom_element_declare_namespace(element, env, n, ns2);

	if(element)
	{
		if(request->minor_version && request->issue_instant)
		{
			/* set the <samlp:Request> element attributes*/
			if(!request->request_id)
				request->request_id = saml_id_generate_random_bytes(env);

			attr = axiom_attribute_create(env, SAML_REQUEST_ID, request->request_id, NULL);
			axiom_element_add_attribute(element, env, attr, n);
		
			attr = axiom_attribute_create(env, SAML_MAJORVERSION, SAML_MAJOR_VERSION, NULL);
			axiom_element_add_attribute(element, env, attr, n);
		
			attr = axiom_attribute_create(env, SAML_MINORVERSION, request->minor_version, NULL);
			axiom_element_add_attribute(element, env, attr, n);

			attr = axiom_attribute_create(env, SAML_ISSUE_INSTANT, axutil_date_time_serialize_date_time(request->issue_instant, env), NULL);
			axiom_element_add_attribute(element, env, attr, n);
		}
		if(request->saml_responds)
		{
			/*if saml request response values are set, construct <samlp:RespondWith> elements*/
			size = axutil_array_list_size(request->saml_responds, env);

			for (i = 0 ; i < size ; i++)
			{
				qname = (axutil_qname_t*) axutil_array_list_get(request->saml_responds, env, i);
				ns1 = axiom_namespace_create(env, SAML_PROTOCOL_NMSP, SAML_PROTOCOL_PREFIX);
				ce = axiom_element_create(env, n, SAML_RESPOND_WITH, ns1, &cn);
				if(ce)
				{
					axiom_element_set_text(ce, env, axutil_qname_to_string(qname, env), cn);
				}
			}
		}
		if(request->query || request->saml_artifacts || request->saml_asserion_id_ref)
		{
			if(request->query)
			{
				/* construct the saml query element*/
				saml_query_to_om(request->query, n, env);
			}
			if(request->saml_artifacts)
			{
				/*if defined construct <samlp:AssertionArtifact> elements*/
				size = axutil_array_list_size(request->saml_artifacts, env);

				for(i = 0; i < size ; i++)
				{
					artifact = (saml_artifact_t*) axutil_array_list_get(request->saml_artifacts, env, i);
					if(artifact)
					{
						ns1 = axiom_namespace_create(env, SAML_PROTOCOL_NMSP, SAML_PROTOCOL_PREFIX);
						ce = axiom_element_create(env, n, SAML_ASSERTION_ARTIFACT, ns1, &cn);
						if(ce)
						{
							axiom_element_set_text(ce, env, artifact->artifact, cn);
						}
					}
					
				}
			}
			if(request->saml_asserion_id_ref)
			{
				/*if defined construct <samlp:AssertionIDReference> elements*/
				size = axutil_array_list_size(request->saml_asserion_id_ref, env);

				for(i = 0; i < size ; i++)
				{
					id_reference = (axis2_char_t*) axutil_array_list_get(request->saml_asserion_id_ref, env, i);

					ns1 = axiom_namespace_create(env, SAML_PROTOCOL_NMSP, SAML_PROTOCOL_PREFIX);
					ce = axiom_element_create(env, n, SAML_ASSERTION_ID_REFERENCE, ns1, &cn);
					if(ce)
					{
						axiom_element_set_text(ce, env, id_reference, cn);
					}
				}
			}
		}
		if(request->sig_ctx)
		{
			/*if saml sign context is set, sign the saml request element*/
			saml_request_sign(request, n, env);
		}
	}
	return n;
}
AXIS2_EXTERN axis2_char_t* AXIS2_CALL saml_request_get_id(saml_request_t *request, const axutil_env_t *env)
{
	if(request)
	{
		return request->request_id;
	}
	else
		return NULL;
}
AXIS2_EXTERN int AXIS2_CALL saml_request_set_minor_version(saml_request_t *request, const axutil_env_t *env, int version)
{
	if(request->minor_version)
	{
		AXIS2_FREE(env->allocator, request->minor_version);
	}
	request->minor_version = AXIS2_MALLOC(env->allocator, 8);
	sprintf(request->minor_version, "%d", version);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL saml_request_set_major_version(saml_request_t *request, const axutil_env_t *env, int version)
{
	if(request->major_version)
	{
		AXIS2_FREE(env->allocator, request->major_version);
	}
	request->minor_version = AXIS2_MALLOC(env->allocator, 8);
	sprintf(request->major_version, "%d", version);
	return AXIS2_SUCCESS;

}

AXIS2_EXTERN int AXIS2_CALL saml_request_set_issue_instant(saml_request_t *request, const axutil_env_t *env, axutil_date_time_t *date_time)
{
	if(request->issue_instant)
	{
		axutil_date_time_free(request->issue_instant, env);
	}
	request->issue_instant = date_time;
	return AXIS2_SUCCESS;
}
AXIS2_EXTERN  axutil_date_time_t* AXIS2_CALL saml_request_get_issue_instant(saml_request_t *request, const axutil_env_t *env)
{
	if(request)
		return request->issue_instant;
	else
		return NULL;
}

AXIS2_EXTERN int AXIS2_CALL saml_request_set_respond_withs(saml_request_t *request, const axutil_env_t *env, axutil_array_list_t *responds)
{
	int size = 0, i = 0;
	axutil_qname_t *respond = NULL;
	if(request->saml_responds)
	{
		size = axutil_array_list_size(request->saml_responds, env);
		for(i = 0; i < size; i++)
		{
			respond = (axutil_qname_t*)axutil_array_list_get(request->saml_responds, env, i);
			if(respond)
				axutil_qname_free(respond, env);
		}
		axutil_array_list_free(request->saml_responds, env);
	}
	request->saml_responds = responds;
	return  AXIS2_SUCCESS;
}

AXIS2_EXTERN  axutil_array_list_t* AXIS2_CALL saml_request_get_respond_withs(saml_request_t *request, const axutil_env_t *env)
{
	if(request)
		return request->saml_responds;
	else
		return NULL;
}

AXIS2_EXTERN int AXIS2_CALL saml_request_add_respond_with(saml_request_t *request, const axutil_env_t *env, axutil_qname_t *respond)
{
	if(!request->saml_responds)
	{
		request->saml_responds = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
	}
	if(request->saml_responds)
	{
		axutil_array_list_add(request->saml_responds, env, respond);
		return AXIS2_SUCCESS;
	}
	return AXIS2_FAILURE;
	
}
AXIS2_EXTERN int AXIS2_CALL saml_request_remove_respond_with(saml_request_t *request, const axutil_env_t *env, int index)
{
	axutil_qname_t *qname;
	if(request->saml_responds)
	{
		qname = axutil_array_list_remove(request->saml_responds, env, index);
		if(qname)
		{
			axutil_qname_free(qname, env);
		}
		return AXIS2_SUCCESS;
	}
	return AXIS2_FAILURE;
}
AXIS2_EXTERN int AXIS2_CALL saml_request_set_query(saml_request_t *request, const axutil_env_t *env, saml_query_t *query)
{
	if(request->query)
	{
		saml_query_free(request->query, env);
	}
	request->query = query;
	return AXIS2_SUCCESS;
}
AXIS2_EXTERN saml_query_t* AXIS2_CALL saml_request_get_query(saml_request_t *request, const axutil_env_t *env)
{
	if(request)
		return request->query;
	else
		return NULL;
}

AXIS2_EXTERN int AXIS2_CALL saml_request_set_id_refs(saml_request_t *request, const axutil_env_t *env, axutil_array_list_t *id_refs)
{
	int size = 0, i = 0;
	if(request->saml_asserion_id_ref)
	{
		axis2_char_t *id_ref = NULL;
		size = axutil_array_list_size(request->saml_asserion_id_ref, env);
		for(i = 0; i < size; i++)
		{
			id_ref = (axis2_char_t*)axutil_array_list_get(request->saml_asserion_id_ref, env, i);
			if(id_ref)
				AXIS2_FREE(env->allocator, id_ref);
		}
		axutil_array_list_free(request->saml_asserion_id_ref, env);
	}
	request->saml_asserion_id_ref = id_refs;
	return AXIS2_SUCCESS;
}
AXIS2_EXTERN axutil_array_list_t* AXIS2_CALL saml_request_get_id_refs(saml_request_t *request, const axutil_env_t *env)
{
	if(request)
		return request->saml_asserion_id_ref;
	else
		return NULL;
}

AXIS2_EXTERN int AXIS2_CALL saml_request_add_id_refs(saml_request_t *request, const axutil_env_t *env, axis2_char_t *id_reference)
{
	if(!request->saml_asserion_id_ref)
	{
		request->saml_asserion_id_ref = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
	}
	if(request->saml_asserion_id_ref)
	{
		axutil_array_list_add(request->saml_asserion_id_ref, env, axutil_strdup(env, id_reference));
		return AXIS2_SUCCESS;
	}
	return AXIS2_FAILURE;
}
AXIS2_EXTERN int AXIS2_CALL saml_request_remove_id_refs(saml_request_t *request, const axutil_env_t *env, int index)
{
	axis2_char_t *id_ref;
	if(request->saml_asserion_id_ref)
	{
		id_ref = axutil_array_list_remove(request->saml_asserion_id_ref, env,index);
		if(id_ref)
		{
			AXIS2_FREE(env->allocator, id_ref);
			return AXIS2_SUCCESS;
		}
	}
	return AXIS2_FAILURE;
}
AXIS2_EXTERN int AXIS2_CALL saml_request_set_artifacts(saml_request_t *request, const axutil_env_t *env, axutil_array_list_t *artifacts)
{
	int size = 0, i = 0;
	saml_artifact_t *artifact = NULL;
	if(request->saml_artifacts)
	{
		size = axutil_array_list_size(request->saml_artifacts,env);
		for(i = 0; i < size ; i++)
		{
			artifact = (saml_artifact_t*)axutil_array_list_get(request->saml_artifacts, env, i);
			if(artifact)
				saml_artifact_free(artifact, env);
		}
		axutil_array_list_free(request->saml_artifacts, env);
	}
	request->saml_artifacts = artifacts;
	return AXIS2_SUCCESS;
}
AXIS2_EXTERN axutil_array_list_t*  AXIS2_CALL saml_request_get_artifacts(saml_request_t *request, const axutil_env_t *env)
{
	if(request)
		return	request->saml_artifacts;
	else
		return NULL;
}

AXIS2_EXTERN int AXIS2_CALL saml_request_add_artifact(saml_request_t *request, const axutil_env_t *env, saml_artifact_t *artifact)
{
	if(!request->saml_artifacts)
	{
		request->saml_artifacts = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
	}
	if(request->saml_artifacts)
	{
		axutil_array_list_add(request->saml_artifacts, env, artifact);
		return AXIS2_SUCCESS;
	}
	return AXIS2_FAILURE;
}
AXIS2_EXTERN int AXIS2_CALL saml_request_remove_artifact(saml_request_t *request, const axutil_env_t *env, int index)
{
	saml_artifact_t *ar;
	if(request->saml_artifacts)
	{
		ar = axutil_array_list_remove(request->saml_artifacts, env ,index);
		if(ar)
		{
			saml_artifact_free(ar, env);
			return AXIS2_SUCCESS;
		}
	}
	return AXIS2_FAILURE;
}
AXIS2_EXTERN axis2_bool_t AXIS2_CALL saml_request_check_validity(saml_request_t *request, const axutil_env_t *env)
{
	if(request->query)
		return AXIS2_TRUE;
	else if(request->saml_artifacts)
	{
		if(!axutil_array_list_is_empty(request->saml_artifacts, env))
			return AXIS2_TRUE;
		else if(request->saml_asserion_id_ref)
		{
			if(!axutil_array_list_is_empty(request->saml_asserion_id_ref, env))
				return AXIS2_TRUE;
			else
				return AXIS2_FALSE;
		}
		else
			return AXIS2_FALSE;
	}
	else
		return AXIS2_FALSE;
}

AXIS2_EXTERN int AXIS2_CALL saml_request_set_signature(saml_request_t *request, const axutil_env_t *env, oxs_sign_ctx_t *sig_ctx)
{
	if(request->sig_ctx)
	{
		oxs_sign_ctx_free(request->sig_ctx, env);
	}
	request->sig_ctx = sig_ctx;
	return AXIS2_SUCCESS;
}
AXIS2_EXTERN int AXIS2_CALL saml_request_unsign(saml_request_t *request, const axutil_env_t *env)
{
	if(request->sig_ctx)
	{
		oxs_sign_ctx_free(request->sig_ctx, env);
	}
	return AXIS2_SUCCESS;
}
AXIS2_EXTERN int AXIS2_CALL saml_request_sign(saml_request_t *request, axiom_node_t *node, const axutil_env_t *env)
{
	axiom_node_t *n= NULL;
	oxs_sign_part_t* sig_part = NULL;
	axutil_array_list_t *sig_parts = NULL;
	int size = 0, i = 0;
	/*Get the sign parts defined in saml request sign context*/
	sig_parts = oxs_sign_ctx_get_sign_parts(request->sig_ctx, env);
	if(sig_parts)
	{
		/* for each sign part, set the node to be signed*/
		size = axutil_array_list_size(sig_parts, env);
		for(i = 0; i < size; i++)
		{
			sig_part = axutil_array_list_get(sig_parts, env, i);
			oxs_sign_part_set_node(sig_part, env, node);
		}
	}
	/*sign the node with the saml request sign info*/
	oxs_xml_sig_sign(env, request->sig_ctx, node, &n);
    /*Finally build KeyInfo*/
	oxs_xml_key_info_build(env, n, oxs_sign_ctx_get_certificate(request->sig_ctx, env), OXS_KIBP_X509DATA_X509CERTIFICATE);

	return AXIS2_SUCCESS;


}
AXIS2_EXTERN void AXIS2_CALL saml_request_set_default_signature(saml_request_t *request, const axutil_env_t *env, oxs_sign_ctx_t *sig_ctx)
{
	if(request->sig_ctx)
	{
		oxs_sign_ctx_free(request->sig_ctx, env);
	}
	request->sig_ctx = sig_ctx;

	/*create transform sor SAML XML signature with identifier*/
	saml_util_set_sig_ctx_defaults(request->sig_ctx, env, SAML_REQUEST_ID);
}

AXIS2_EXTERN int AXIS2_CALL
saml_request_signature_verify(saml_request_t *request, const axutil_env_t *env)
{			
	return oxs_xml_sig_verify(env, request->sig_ctx, request->signature, request->original_xml);
}

AXIS2_EXTERN int AXIS2_CALL
saml_request_is_sign_set(saml_request_t *request, const axutil_env_t *env)
{
	if (request->sig_ctx)
	{
		return AXIS2_TRUE;
	}
	return AXIS2_FALSE;
}

AXIS2_EXTERN int AXIS2_CALL
saml_request_is_signed(saml_request_t *request, const axutil_env_t *env)
{
	if (request->signature)
	{
		return AXIS2_TRUE;
	}
	return AXIS2_FALSE;
}

