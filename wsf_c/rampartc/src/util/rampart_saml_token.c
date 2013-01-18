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
 */

#include <axiom.h>
#include <axiom_soap_envelope.h>
#include <axiom_soap_fault.h>
#include <axiom_soap_fault_sub_code.h>
#include <axiom_soap_body.h>
#include <axis2_msg_ctx.h>
#include <rampart_saml_token.h>


struct rampart_saml_token_t 
{
    /* Actual assertion */
    axiom_node_t *assertion;    
    /* Confirmation type */
    rampart_st_confir_type_t type;
	/* Confirmation key material*/
	oxs_key_t *key;
    /* Security token reference for this saml token */
    axiom_node_t *str;
	/* Set weather the token is added to the header or not */
    axis2_bool_t is_token_added;
	/* specify weather this is a protection token, supporting token,
	encryption token or signature token */
	/*rp_property_type_t token_type;*/
    rampart_st_type_t tok_type;
};

AXIS2_EXTERN rampart_saml_token_t *AXIS2_CALL
rampart_saml_token_create(const axutil_env_t *env, axiom_node_t *assertion, 
                          rampart_st_confir_type_t type)
{
	rampart_saml_token_t *tok = AXIS2_MALLOC(env->allocator, 
                                            sizeof(rampart_saml_token_t));
	if (tok)
	{
		tok->assertion = assertion;
		tok->type = type;
        tok->is_token_added = AXIS2_FALSE;
        tok->key = NULL;
        tok->str = NULL;
		tok->type = type;
		tok->tok_type = RAMPART_ST_TYPE_UNSPECIFIED;
	}
	return tok;
}

AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_free(rampart_saml_token_t *tok, const axutil_env_t *env)
{	
    if (tok->key)
    {
        oxs_key_free(tok->key, env);
    }
	AXIS2_FREE(env->allocator, tok);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_set_assertion(rampart_saml_token_t *tok, const axutil_env_t *env, 
                                 axiom_node_t *assertion)
{
	tok->assertion = assertion;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN axiom_node_t* AXIS2_CALL
rampart_saml_token_get_assertion(rampart_saml_token_t *tok, const axutil_env_t *env)
{
	return tok->assertion;
}

AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_set_type(rampart_saml_token_t *tok, const axutil_env_t *env, 
                            rampart_st_confir_type_t type)
{
	tok->type = type;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN rampart_st_confir_type_t AXIS2_CALL
rampart_saml_token_get_type(rampart_saml_token_t *tok, const axutil_env_t *env)
{
	return tok->type;
}

AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_set_key_value(rampart_saml_token_t *tok, 
                                 const axutil_env_t *env, 
                                 oxs_key_t *key)
{
	if (tok->key)
	{
		oxs_key_free(tok->key, env);
	}
	tok->key = key;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_set_str(rampart_saml_token_t *tok, const axutil_env_t *env, 
                           axiom_node_t *str)
{
	if (str)
	{
		tok->str = oxs_axiom_clone_node(env, str);
	}    
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
rampart_saml_token_get_str(rampart_saml_token_t *tok, const axutil_env_t *env)
{
	if (tok->str)
	{
		return oxs_axiom_clone_node(env, tok->str);
	}
    return NULL;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rampart_saml_token_is_added_to_header(rampart_saml_token_t *tok, const axutil_env_t *env)
{
    return tok->is_token_added;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_saml_token_set_is_added_to_header(rampart_saml_token_t *tok, 
                                      const axutil_env_t *env,
                                      axis2_bool_t is_token_added)
{
    tok->is_token_added = is_token_added;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN rampart_st_type_t AXIS2_CALL
rampart_saml_token_get_token_type(rampart_saml_token_t *tok,
								  const axutil_env_t *env)
{
	return tok->tok_type;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_saml_token_set_token_type(rampart_saml_token_t *tok,
								  const axutil_env_t *env,
								  rampart_st_type_t token_type)
{
	tok->tok_type = token_type;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN oxs_key_t * AXIS2_CALL
rampart_saml_token_get_session_key(rampart_saml_token_t *tok, 
								   const axutil_env_t *env)
{
	return tok->key;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_saml_token_set_session_key(rampart_saml_token_t *tok, 
								   const axutil_env_t *env,
								   oxs_key_t *key)
{
	if (tok->key)
	{
		oxs_key_free(tok->key, env);
	}
	tok->key = key;
	return AXIS2_SUCCESS;
}


