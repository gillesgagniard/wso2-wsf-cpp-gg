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

#include <rp_x509_token.h>

struct rp_x509_token_t
{
    rp_token_t *token;
    axis2_bool_t require_key_identifier_reference;
    axis2_bool_t require_issuer_serial_reference;
    axis2_bool_t require_embedded_token_reference;
    axis2_bool_t require_thumb_print_reference;
    axis2_char_t *token_version_and_type;
    int ref;

};

AXIS2_EXTERN rp_x509_token_t *AXIS2_CALL
rp_x509_token_create(
    const axutil_env_t * env)
{
    rp_x509_token_t *x509_token = NULL;
    x509_token = (rp_x509_token_t *)AXIS2_MALLOC(env->allocator, sizeof(rp_x509_token_t));

    if(!x509_token)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[neethi] X509 token assertion creation failed. Insufficient memory");
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
    }
    x509_token->require_key_identifier_reference = AXIS2_FALSE;
    x509_token->require_issuer_serial_reference = AXIS2_FALSE;
    x509_token->require_embedded_token_reference = AXIS2_FALSE;
    x509_token->require_thumb_print_reference = AXIS2_FALSE;
    x509_token->token_version_and_type = RP_WSS_X509_V3_TOKEN_10;
    x509_token->ref = 0;

    x509_token->token = rp_token_create(env);
    if(!x509_token->token)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[neethi] X509 token assertion creation failed.");
        rp_x509_token_free(x509_token, env);
        return NULL;
    }
    return x509_token;
}

AXIS2_EXTERN void AXIS2_CALL
rp_x509_token_free(
    rp_x509_token_t * x509_token,
    const axutil_env_t * env)
{
    if(x509_token)
    {
        if(--(x509_token->ref) > 0)
        {
            return;
        }

        rp_token_free(x509_token->token, env);
        AXIS2_FREE(env->allocator, x509_token);
        x509_token = NULL;
    }
}

/* Implementations */

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rp_x509_token_get_inclusion(
    rp_x509_token_t * x509_token,
    const axutil_env_t * env)
{
    return rp_token_get_inclusion(x509_token->token, env);
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rp_x509_token_set_inclusion(
    rp_x509_token_t * x509_token,
    const axutil_env_t * env,
    axis2_char_t * inclusion)
{
    return rp_token_set_inclusion(x509_token->token, env, inclusion);
}

AXIS2_EXTERN derive_key_type_t AXIS2_CALL
rp_x509_token_get_derivedkey(
    rp_x509_token_t * x509_token,
    const axutil_env_t * env)
{
    return rp_token_get_derivedkey_type(x509_token->token, env);
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rp_x509_token_set_derivedkey(
    rp_x509_token_t * x509_token,
    const axutil_env_t * env,
    derive_key_type_t derivedkeys)
{
    return rp_token_set_derivedkey_type(x509_token->token, env, derivedkeys);
}

AXIS2_EXTERN derive_key_version_t AXIS2_CALL
rp_x509_token_get_derivedkey_version(
    rp_x509_token_t *x509_token,
    const axutil_env_t *env)
{
    return rp_token_get_derive_key_version(x509_token->token, env);
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rp_x509_token_set_derivedkey_version(
    rp_x509_token_t *x509_token,
    const axutil_env_t *env,
    derive_key_version_t version)
{
    return rp_token_set_derive_key_version(x509_token->token, env, version);
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rp_x509_token_get_require_key_identifier_reference(
    rp_x509_token_t * x509_token,
    const axutil_env_t * env)
{
    return x509_token->require_key_identifier_reference;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rp_x509_token_set_require_key_identifier_reference(
    rp_x509_token_t * x509_token,
    const axutil_env_t * env,
    axis2_bool_t require_key_identifier_reference)
{
    x509_token->require_key_identifier_reference = require_key_identifier_reference;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rp_x509_token_get_require_issuer_serial_reference(
    rp_x509_token_t * x509_token,
    const axutil_env_t * env)
{
    return x509_token->require_issuer_serial_reference;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rp_x509_token_set_require_issuer_serial_reference(
    rp_x509_token_t * x509_token,
    const axutil_env_t * env,
    axis2_bool_t require_issuer_serial_reference)
{
    x509_token->require_issuer_serial_reference = require_issuer_serial_reference;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rp_x509_token_get_require_embedded_token_reference(
    rp_x509_token_t * x509_token,
    const axutil_env_t * env)
{
    return x509_token->require_embedded_token_reference;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rp_x509_token_set_require_embedded_token_reference(
    rp_x509_token_t * x509_token,
    const axutil_env_t * env,
    axis2_bool_t require_embedded_token_reference)
{
    x509_token->require_embedded_token_reference = require_embedded_token_reference;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rp_x509_token_get_require_thumb_print_reference(
    rp_x509_token_t * x509_token,
    const axutil_env_t * env)
{
    return x509_token->require_thumb_print_reference;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rp_x509_token_set_require_thumb_print_reference(
    rp_x509_token_t * x509_token,
    const axutil_env_t * env,
    axis2_bool_t require_thumb_print_reference)
{
    x509_token->require_thumb_print_reference = require_thumb_print_reference;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rp_x509_token_get_token_version_and_type(
    rp_x509_token_t * x509_token,
    const axutil_env_t * env)
{
    return x509_token->token_version_and_type;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rp_x509_token_set_token_version_and_type(
    rp_x509_token_t * x509_token,
    const axutil_env_t * env,
    axis2_char_t * token_version_and_type)
{
    x509_token->token_version_and_type = token_version_and_type;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rp_x509_token_increment_ref(
    rp_x509_token_t * x509_token,
    const axutil_env_t * env)
{
    x509_token->ref++;
    return AXIS2_SUCCESS;
}
