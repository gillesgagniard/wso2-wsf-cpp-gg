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

AXIS2_EXTERN saml_stmt_t * AXIS2_CALL 
saml_stmt_create(const axutil_env_t *env)
{
	saml_stmt_t *stmt = AXIS2_MALLOC(env->allocator, sizeof(saml_stmt_t));
	if (stmt)
	{
		stmt->type = SAML_STMT_UNSPECIFED;
		stmt->stmt = NULL;
	}
	return stmt;
}

AXIS2_EXTERN void AXIS2_CALL 
saml_stmt_free(saml_stmt_t *stmt, const axutil_env_t *env)
{
	if (stmt->type == SAML_STMT_AUTHENTICATIONSTATEMENT)
	{
		saml_auth_stmt_free(stmt->stmt, env);
		stmt->type = SAML_STMT_UNSPECIFED;
	}
	else if (stmt->type == SAML_STMT_AUTHORIZATIONDECISIONSTATEMENT)
	{
		saml_auth_desicion_stmt_free(stmt->stmt, env);
		stmt->type = SAML_STMT_UNSPECIFED;
	}
	else if (stmt->type == SAML_STMT_ATTRIBUTESTATEMENT)
	{
		saml_attr_stmt_free(stmt->stmt, env);
		stmt->type = SAML_STMT_UNSPECIFED;
	}
	else if (stmt->type == SAML_STMT_SUBJECTSTATEMENT)
	{
		saml_subject_stmt_free(stmt->stmt, env);
		stmt->type = SAML_STMT_UNSPECIFED;
	}	
	AXIS2_FREE(env->allocator, stmt);
}

AXIS2_EXTERN int AXIS2_CALL 
saml_stmt_build(saml_stmt_t *stmt, axiom_node_t *node, const axutil_env_t *env)
{
	axis2_char_t *locname = NULL;
	axiom_element_t *element = NULL;	
	
	if (axiom_node_get_node_type(node, env) != AXIOM_ELEMENT || (element = (axiom_element_t *)axiom_node_get_data_element(node, env)) == NULL)
	{
		return AXIS2_FAILURE;
	}
	locname = axiom_element_get_localname(element, env);
	if (0 == strcmp(locname, SAML_AUTHENTICATION_STATEMENT))
	{
		stmt->stmt = saml_auth_stmt_create(env);
		stmt->type = SAML_STMT_AUTHENTICATIONSTATEMENT;
		return saml_auth_stmt_build(stmt->stmt, node, env);		
	}
	else if (0 == strcmp(locname, SAML_AUTHORIZATION_DECISION_STATEMENT))
	{
		stmt->stmt = saml_auth_desicion_stmt_create(env);
		stmt->type = SAML_STMT_AUTHORIZATIONDECISIONSTATEMENT;
		return saml_auth_desicion_stmt_build(stmt->stmt, node,env);		
	}
	else if (0 == strcmp(locname, SAML_ATTRIBUTE_STATEMENT))
	{
		stmt->stmt = saml_attr_stmt_create(env);
		stmt->type = SAML_STMT_ATTRIBUTESTATEMENT;
		return saml_attr_stmt_build(stmt->stmt, node, env);		
	}
	else if (0 == strcmp(locname, SAML_SUBJECT_STATEMENT))
	{
		stmt->stmt = saml_subject_stmt_create(env);
		stmt->type = SAML_STMT_SUBJECTSTATEMENT;
		return saml_subject_stmt_build(stmt->stmt, node, env);		
	}
	return AXIS2_SUCCESS;	
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_stmt_to_om(saml_stmt_t *stmt, axiom_node_t *parent, const axutil_env_t *env)
{
	if (stmt->type == SAML_STMT_AUTHENTICATIONSTATEMENT)
	{
		return saml_auth_stmt_to_om(stmt->stmt, parent, env);		
	}
	else if (stmt->type == SAML_STMT_AUTHORIZATIONDECISIONSTATEMENT)
	{		
		return saml_auth_desicion_stmt_to_om(stmt->stmt, parent,env);		
	}
	else if (stmt->type == SAML_STMT_ATTRIBUTESTATEMENT)
	{		
		return saml_attr_stmt_to_om(stmt->stmt, parent, env);		
	}
	else if (stmt->type == SAML_STMT_SUBJECTSTATEMENT)
	{		
		return saml_subject_stmt_to_om(stmt->stmt, parent, env);		
	}
	return NULL;
}

AXIS2_EXTERN saml_stmt_type_t AXIS2_CALL 
saml_stmt_get_type(saml_stmt_t *stmt, const axutil_env_t *env)
{
	return stmt->type;
}

AXIS2_EXTERN saml_stmt_t * AXIS2_CALL 
saml_stmt_get_stmt(saml_stmt_t *stmt, const axutil_env_t *env)
{
	return stmt->stmt;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_stmt_set_type(saml_stmt_t *stmt, const axutil_env_t *env, saml_stmt_type_t type)
{
	stmt->type = type;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL 
saml_stmt_set_stmt(saml_stmt_t *stmt, const axutil_env_t *env, 
				   void *st, saml_stmt_type_t type)
{
	if (stmt->type == SAML_STMT_AUTHENTICATIONSTATEMENT)
	{
		saml_auth_stmt_free(stmt->stmt, env);
	}
	else if (stmt->type == SAML_STMT_AUTHORIZATIONDECISIONSTATEMENT)
	{
		saml_auth_desicion_stmt_free(stmt->stmt, env);
	}
	else if (stmt->type == SAML_STMT_ATTRIBUTESTATEMENT)
	{
		saml_attr_stmt_free(stmt->stmt, env);
	}
	else if (stmt->type == SAML_STMT_SUBJECTSTATEMENT)
	{
		saml_subject_stmt_free(stmt->stmt, env);
	}		
	stmt->stmt = st;
	stmt->type = type;
	return AXIS2_SUCCESS;
}

