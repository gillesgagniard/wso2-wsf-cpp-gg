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

#include <rampart_issued_token.h>
#include <rampart_saml_token.h>

struct rampart_issued_token_t {
	void *token;

	/* specify weather this type of the token aquired. 
	security context token, saml token etc */
	rp_property_type_t token_type;
};

AXIS2_EXTERN rampart_issued_token_t * AXIS2_CALL
rampart_issued_token_create(const axutil_env_t *env)
{
	rampart_issued_token_t *issued_token = AXIS2_MALLOC(env-> allocator, sizeof(rampart_issued_token_t));

	if (issued_token)
	{
		issued_token->token = NULL;
		issued_token->token_type = RP_PROPERTY_UNKNOWN;
	}
	return issued_token;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_issued_token_free(rampart_issued_token_t *token, const axutil_env_t *env)
{
	if (token->token_type == RP_PROPERTY_SAML_TOKEN)
	{
		if (token->token)
		{
			rampart_saml_token_free(token->token, env);
		}
	}
	AXIS2_FREE(env->allocator, token->token);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_issued_token_set_token(rampart_issued_token_t *issued_token, const axutil_env_t *env, void *token, rp_property_type_t token_type)
{
	issued_token->token = token;
	issued_token->token_type = token_type;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN rp_property_type_t AXIS2_CALL
rampart_issued_token_get_token_type(rampart_issued_token_t *token, const axutil_env_t *env)
{
	return token->token_type;
}

AXIS2_EXTERN void * AXIS2_CALL
rampart_issued_token_get_token(rampart_issued_token_t *token, const axutil_env_t *env)
{
	return token->token;
}

