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

#include "saml_issuer.h"

#include <axis2_op_ctx.h>
#include <axis2_msg_ctx.h>

axiom_node_t *
create_saml_token(axutil_env_t *env);

saml_condition_t *
create_condition(axutil_env_t *env);

saml_stmt_t *
create_auth_statement(axutil_env_t *env);

saml_auth_binding_t *
create_autherity_binding(axutil_env_t *env);

saml_subject_t * 
create_subject(axutil_env_t *env);

axiom_node_t *axis2_saml_issuer_issue(
    const axutil_env_t * env, 
    trust_context_t *trust_ctx)
{
    axis2_char_t *token_type = NULL;
    axiom_node_t *issued_saml_token = NULL;    
    axiom_node_t *rstr_node = NULL;
    axiom_node_t *requested_sec_token_node = NULL;

	trust_rst_t *rst = NULL;	/*Created RST Context*/
	trust_rstr_t *rstr = NULL;	/*Used for Creating RSTR*/
    
	rst = trust_context_get_rst(trust_ctx, env);
	

    token_type = trust_rst_get_token_type(rst, env);
	if(token_type)
    	AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sts] token type: %s !", token_type);
	else
		return NULL;
    
    if (axutil_strcmp(token_type, SAML_TOKEN))
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sts] token type not equal..!");
        return NULL;
    }
    
    rstr = trust_rstr_create(env);
    
	
	
    issued_saml_token = create_saml_token(env);	
	trust_rstr_set_requested_security_token(rstr, env, issued_saml_token);
    trust_rstr_set_wst_ns_uri(rstr, env, "http://schemas.xmlsoap.org/ws/2005/02/trust");
	trust_rstr_set_requested_proof_token(rstr, env, trust_util_create_random_session_key_proof_token_element(env, 
				"http://schemas.xmlsoap.org/ws/2005/02/trust")
			);

	trust_context_set_rstr(trust_ctx, env, rstr);
	rstr_node = trust_context_build_rstr_node(trust_ctx, env);
   	
    return rstr_node;
}

axiom_node_t *
create_saml_token(axutil_env_t *env)
{
	axutil_date_time_t *time = NULL;
	saml_assertion_t *assertion = NULL;
	axiom_node_t *node = NULL;
	time = axutil_date_time_create(env);
	assertion = saml_assertion_create(env);
	if (assertion)	
	{
		saml_assertion_set_minor_version(assertion, env, 1);		
		saml_assertion_set_issue_instant(assertion, env, time);
		saml_assertion_set_issuer(assertion, env, "http://ws.apache.org/rampart/c");	
		saml_assertion_add_condition(assertion, env, create_condition(env));
		saml_assertion_set_not_before(assertion, env, axutil_date_time_create(env));
		saml_assertion_add_statement(assertion, env, create_auth_statement(env));
	}	
	node = saml_assertion_to_om(assertion, NULL, env);	 
	saml_assertion_free(assertion, env);
	return node;
}

saml_condition_t *
create_condition(axutil_env_t *env)
{
	saml_audi_restriction_cond_t *arc = NULL;
	saml_condition_t *condition = AXIS2_MALLOC(env->allocator, sizeof(saml_condition_t));	
	arc = saml_audi_restriction_cond_create(env);
	saml_audi_restriction_cond_add_audience(arc, env, "www.samle.com");	
	return condition;
}

saml_stmt_t *
create_auth_statement(axutil_env_t *env)
{
	saml_auth_stmt_t *a_stmt = NULL;	
	saml_stmt_t *stmt = saml_stmt_create(env);
	a_stmt = saml_auth_stmt_create(env);
	saml_stmt_set_stmt(stmt, env, a_stmt, SAML_STMT_AUTHENTICATIONSTATEMENT);

	saml_auth_stmt_set_auth_method(a_stmt, env, SAML_AUTH_METHOD_URI_PASSWORD);
	saml_auth_stmt_set_auth_instant(a_stmt, env, axutil_date_time_create(env));
	
	saml_auth_stmt_set_subject(a_stmt, env, create_subject(env));	
	saml_auth_stmt_set_subject_dns(a_stmt, env,  "192.148.5.8");
	saml_auth_stmt_set_subject_ip(a_stmt, env,  "128.5.6.4");
	saml_auth_stmt_add_auth_binding(a_stmt, env, create_autherity_binding(env));
	return stmt;	
}

saml_auth_binding_t *
create_autherity_binding(axutil_env_t *env)
{
	saml_auth_binding_t *bind = NULL;
	bind = saml_auth_binding_create(env);
	saml_auth_binding_set_authority_kind(bind, env, "abc:aa:aa");
	saml_auth_binding_set_binding(bind, env, "SOAP");
	saml_auth_binding_set_location(bind, env, "http://myhome.com/sevices/echo");
	return bind;
}

saml_subject_t *
create_subject(axutil_env_t *env)
{
	saml_subject_t *subject = NULL;
	saml_named_id_t *id = NULL;		
	subject = saml_subject_create(env);
	
	id = saml_named_id_create(env);
	saml_named_id_set_name(id, env, "Computer Science & Engineering Department");
	saml_named_id_set_format(id, env, SAML_EMAIL_ADDRESS);
	saml_named_id_set_name_qualifier(id, env, "University of Moratuwa");
	saml_subject_set_named_id(subject, env, id);

	saml_subject_add_confirmation(subject, env, SAML_SUB_CONFIRMATION_ARTIFACT);
	saml_subject_add_confirmation(subject, env, SAML_SUB_CONFIRMATION_BEARER);	
	return subject;
}
