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

#include <rampart_config.h>

struct rampart_config_t
{
    axis2_char_t *username;
    axis2_char_t *password;
    axis2_char_t *password_type;
    axutil_array_list_t *saml_tokens;
	issued_token_callback_func issued_token_aquire;
    int ttl;
};

AXIS2_EXTERN rampart_config_t *AXIS2_CALL
rampart_config_create(
    const axutil_env_t *env)
{
    rampart_config_t *rampart_config = NULL;
    rampart_config =  (rampart_config_t *) AXIS2_MALLOC (env->allocator, sizeof (rampart_config_t));

    if(!rampart_config)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart] Unable to create rampart configuration. Insufficient memory.");
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
    }

    rampart_config->username = NULL;
    rampart_config->password = NULL;
    rampart_config->password_type = NULL;
    rampart_config->ttl = 0;
    rampart_config->saml_tokens = NULL;
	rampart_config->issued_token_aquire = NULL;
    return rampart_config;
}

AXIS2_EXTERN void AXIS2_CALL
rampart_config_free(
    rampart_config_t *rampart_config,
    const axutil_env_t *env)
{
    AXIS2_FREE(env->allocator,rampart_config);
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_config_set_username(
    rampart_config_t *rampart_config,
    const axutil_env_t *env,
    axis2_char_t *username)
{
    rampart_config->username = username;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_config_set_password(
    rampart_config_t *rampart_config,
    const axutil_env_t *env,
    axis2_char_t *password)
{
    rampart_config->password = password;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_config_set_password_type(
    rampart_config_t *rampart_config,
    const axutil_env_t *env,
    axis2_char_t *password_type)
{
    rampart_config->password_type = password_type;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_config_set_ttl(
    rampart_config_t *rampart_config,
    const axutil_env_t *env,
    int ttl)
{
    rampart_config->ttl = ttl;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_config_get_username(
    rampart_config_t *rampart_config,
    const axutil_env_t *env)
{
    return rampart_config->username;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_config_get_password(
    rampart_config_t *rampart_config,
    const axutil_env_t *env)
{
    return rampart_config->password;
}


AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_config_get_password_type(
    rampart_config_t *rampart_config,
    const axutil_env_t *env)
{
    return rampart_config->password_type;
}

AXIS2_EXTERN int AXIS2_CALL
rampart_config_get_ttl(
    rampart_config_t *rampart_config,
    const axutil_env_t *env)
{
    return rampart_config->ttl;
}

AXIS2_EXTERN int AXIS2_CALL
rampart_config_add_saml_token(
    rampart_config_t *rampart_config, 
    const axutil_env_t *env, 
    rampart_saml_token_t *saml)
{
	if (!rampart_config->saml_tokens)
	{
		rampart_config->saml_tokens = axutil_array_list_create(env, 3);
	}
	if (saml)
	{
		axutil_array_list_add(rampart_config->saml_tokens, env, saml);
		return AXIS2_SUCCESS;
	}
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL
    rampart_config_get_saml_tokens(
    rampart_config_t *rampart_config, 
    const axutil_env_t *env)
{
    return rampart_config->saml_tokens;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_config_set_issued_token_aquire_function(
    rampart_config_t *rampart_config,
    const axutil_env_t *env,
    issued_token_callback_func issued_token_aquire)
{
	rampart_config->issued_token_aquire = issued_token_aquire;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN issued_token_callback_func AXIS2_CALL
rampart_config_get_issued_token_aquire_function(
    rampart_config_t *rampart_config, 
    const axutil_env_t *env)  
{
	return rampart_config->issued_token_aquire;
}

