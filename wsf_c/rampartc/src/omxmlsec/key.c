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

#include <stdio.h>
#include <axis2_util.h>
#include <oxs_key.h>
#include <oxs_buffer.h>
#include <oxs_cipher.h>
#include <oxs_error.h>
#include <openssl_cipher_property.h>
#include <openssl_util.h>
#include <openssl_constants.h>

struct oxs_key_t
{
    oxs_buffer_t *buf;
    axis2_char_t *name;
    int           usage;
    
    axis2_char_t *nonce;  /*Specially added for WS-Secure Conversation*/
    axis2_char_t *label;  /*Specially added for WS-Secure Conversation*/
    int           offset; /*Specially added for WS-Secure Conversation*/
    int           length; /*Specially added for WS-Secure Conversation. used to pass the derived key length for processing.*/
							/*size is used when building and length is used when processing*/

    axis2_char_t *key_sha;
};

/******************** end of function headers *****************/

AXIS2_EXTERN unsigned char *AXIS2_CALL
oxs_key_get_data(
    const oxs_key_t *key,
    const axutil_env_t *env)
{
    AXIS2_ENV_CHECK(env, NULL);

    return oxs_buffer_get_data(key->buf, env);
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
oxs_key_get_name(
    const oxs_key_t *key,
    const axutil_env_t *env)
{
    AXIS2_ENV_CHECK(env, NULL);

    return key->name;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
oxs_key_get_nonce(
    const oxs_key_t *key,
    const axutil_env_t *env)
{
    AXIS2_ENV_CHECK(env, NULL);

    return key->nonce;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
oxs_key_get_label(
    const oxs_key_t *key,
    const axutil_env_t *env)
{
    AXIS2_ENV_CHECK(env, NULL);

    return key->label;
}

AXIS2_EXTERN oxs_buffer_t *AXIS2_CALL
oxs_key_get_buffer(const oxs_key_t *key,
                   const axutil_env_t *env)
{
    AXIS2_ENV_CHECK(env, NULL);
    return key->buf;
}

AXIS2_EXTERN int AXIS2_CALL
oxs_key_get_size(
    const oxs_key_t *key,
    const axutil_env_t *env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    return oxs_buffer_get_size(key->buf, env);
}

AXIS2_EXTERN int AXIS2_CALL
oxs_key_get_usage(
    const oxs_key_t *key,
    const axutil_env_t *env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    return key->usage;
}

AXIS2_EXTERN int AXIS2_CALL
oxs_key_get_offset(
    const oxs_key_t *key,
    const axutil_env_t *env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    return key->offset;
}

AXIS2_EXTERN int AXIS2_CALL
oxs_key_get_length(
    const oxs_key_t *key,
    const axutil_env_t *env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    return key->length;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_set_name(
    oxs_key_t *key,
    const axutil_env_t *env,
    axis2_char_t *name)
{

    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, name, AXIS2_FAILURE);

    if (key->name)
    {
        AXIS2_FREE(env->allocator, key->name);
        key->name = NULL;
    }
    key->name = axutil_strdup(env, name);
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_set_key_sha(
    oxs_key_t *key,
    const axutil_env_t *env,
    axis2_char_t *key_sha)
{

    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, key_sha, AXIS2_FAILURE);

    if(key->key_sha)
    {
        AXIS2_FREE(env->allocator, key->key_sha);
        key->key_sha = NULL;
    }
    key->key_sha = key_sha;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
oxs_key_get_key_sha(
    const oxs_key_t *key,
    const axutil_env_t *env)
{
    AXIS2_ENV_CHECK(env, NULL);

    return key->key_sha;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_set_nonce(
    oxs_key_t *key,
    const axutil_env_t *env,
    axis2_char_t *nonce)
{

    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, nonce, AXIS2_FAILURE);

    if (key->nonce)
    {
        AXIS2_FREE(env->allocator, key->nonce);
        key->nonce = NULL;
    }
    key->nonce = axutil_strdup(env, nonce);
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_set_label(
    oxs_key_t *key,
    const axutil_env_t *env,
    axis2_char_t *label)
{

    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, label, AXIS2_FAILURE);

    if (key->label)
    {
        AXIS2_FREE(env->allocator, key->label);
        key->label = NULL;
    }
    key->label = axutil_strdup(env, label);
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_set_usage(
    oxs_key_t *key,
    const axutil_env_t *env,
    int usage)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    key->usage = usage;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_set_offset(
    oxs_key_t *key,
    const axutil_env_t *env,
    int offset)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    key->offset = offset;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_set_length(
    oxs_key_t *key,
    const axutil_env_t *env,
    int length)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    key->length = length;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN oxs_key_t *AXIS2_CALL
oxs_key_dup(oxs_key_t *key,
            const axutil_env_t *env)
{
    oxs_key_t *new_key = NULL;

    AXIS2_ENV_CHECK(env, NULL);

    AXIS2_PARAM_CHECK(env->error, key, NULL);

    /*Create new key*/
    new_key = oxs_key_create(env);
    if (!new_key)
    {
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
    }

    /*Populate with data buf*/
    oxs_key_populate_with_buf(new_key,
                              env,
                              oxs_key_get_buffer(key, env),
                              key->name,
                              key->usage);
    new_key->key_sha = key->key_sha;
    return new_key;
}

AXIS2_EXTERN oxs_key_t *AXIS2_CALL
oxs_key_create(const axutil_env_t *env)
{
    oxs_key_t *key = NULL;
    AXIS2_ENV_CHECK(env, NULL);

    key = (oxs_key_t*)AXIS2_MALLOC(env->allocator, sizeof(oxs_key_t));

    if (!key)
    {
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
    }

    key->buf = NULL;
    key->name = NULL;
    key->nonce = NULL;
    key->label = NULL;
    key->usage = -1;
    key->offset = 0;
    key->length = 0;
    key->key_sha = NULL;

    /*additionally we need to create a buffer to keep data*/
    key->buf = oxs_buffer_create(env);

    return key;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_free(oxs_key_t *key,
             const axutil_env_t *env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    oxs_buffer_free(key->buf, env);
    key->buf = NULL;
    AXIS2_FREE(env->allocator,  key->name);
    key->name = NULL;
    AXIS2_FREE(env->allocator,  key->nonce);
    key->nonce = NULL;
    AXIS2_FREE(env->allocator, key->label);
    key->label = NULL;

    if(key->key_sha)
        AXIS2_FREE(env->allocator, key->key_sha);

    AXIS2_FREE(env->allocator,  key);
    key = NULL;

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_populate_with_buf(oxs_key_t *key,
                          const axutil_env_t *env,
                          oxs_buffer_t *buffer,
                          axis2_char_t *name,
                          int usage)
{
    int ret;
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    ret = oxs_key_set_name(key, env, name);
    ret = oxs_key_set_usage(key, env, usage);

    ret = oxs_buffer_populate(key->buf, env,  oxs_buffer_get_data(buffer, env), oxs_buffer_get_size(buffer, env));
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_populate(oxs_key_t *key,
                 const axutil_env_t *env,
                 unsigned char *data,
                 axis2_char_t *name,
                 int size,
                 int usage)
{
    int ret;

    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    ret = oxs_key_set_name(key, env, name);
    ret = oxs_key_set_usage(key, env, usage);

    ret = oxs_buffer_populate(key->buf, env, data, size);

    return AXIS2_SUCCESS;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_read_from_file(oxs_key_t *key,
                       const axutil_env_t *env,
                       axis2_char_t *file_name)
{
    oxs_buffer_t *buf = NULL;
    axis2_status_t status = AXIS2_FAILURE;

    buf = oxs_buffer_create(env);
    status = oxs_buffer_read_file(buf, env, file_name);

    status = oxs_key_populate(key, env,
                              oxs_buffer_get_data(buf, env), file_name,
                              oxs_buffer_get_size(buf, env), OXS_KEY_USAGE_NONE);

    oxs_buffer_free(buf, env);
    buf = NULL;

    return status;

}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_for_algo(oxs_key_t *key,
                 const axutil_env_t *env,
                 rp_algorithmsuite_t *key_algo)
{
    oxs_buffer_t *key_buf = NULL;
    /*openssl_cipher_property_t * cprop = NULL;*/
    axis2_status_t ret = AXIS2_FAILURE;
    int size;


#if 0
    if(0 == axutil_strcmp(key_algo, OXS_HREF_HMAC_SHA1)){
        /*We need to make an special entry for the HMAC-Sha1 as we do not need a cipher property for it.*/
        size = OPENSSL_HMAC_SHA1_KEY_LEN;
    }else{

        cprop = (openssl_cipher_property_t *)oxs_get_cipher_property_for_url(env, key_algo);
        if (!cprop)
        {
            oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_DEFAULT,
                  "openssl_get_cipher_property failed");
            return AXIS2_FAILURE;
        }

        size = openssl_cipher_property_get_key_size(cprop, env);
	    openssl_cipher_property_free(cprop, env);
	    cprop = NULL;
    }
#endif
    if(key_algo)
        size = rp_algorithmsuite_get_min_symmetric_keylength(key_algo,env)/8;
    else
        size = OPENSSL_HMAC_SHA1_KEY_LEN;

    key_buf = oxs_buffer_create(env);
    /*The actual key generation happens here*/
    ret = openssl_generate_random_data(env, key_buf, size);
    if (ret == AXIS2_FAILURE)
    {
        oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_DEFAULT,
                  "generate_random_data failed");
        return AXIS2_FAILURE;
    }


    ret = oxs_key_populate(key, env,
                           oxs_buffer_get_data(key_buf, env), "for-algo",
                           oxs_buffer_get_size(key_buf, env), OXS_KEY_USAGE_NONE);

    oxs_buffer_free(key_buf, env);
    key_buf = NULL;

    return ret;
}
