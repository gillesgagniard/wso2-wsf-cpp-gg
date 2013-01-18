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

#include <rampart_crypto_util.h>
#include <axis2_util.h>
#include <axutil_base64.h>
#include <openssl_digest.h>

/**
 * Calculate the hash of concatenated string of nonce+created+password
 * @param env pointer to environment variable
 * @param nonce randomly created bytes
 * @param created created time
 * @param password password to be hashed
 * @return calculated hash on success. NULL otherwise
 */
AXIS2_EXTERN axis2_char_t* AXIS2_CALL 
rampart_crypto_sha1(
    const axutil_env_t *env,
    const axis2_char_t *nonce,
    const axis2_char_t *created,
    const axis2_char_t *password)
{
    char* input = NULL;
    axis2_char_t* digest = NULL;
    axis2_char_t* decoded_nonce = NULL;
    int decoded_nonce_length = 0;
    int created_length = 0;
    int password_length = 0;

    /* Decode the nonce first */
    if(nonce)
    {
        int ret;
        decoded_nonce_length = axutil_base64_decode_len(nonce);
        decoded_nonce = AXIS2_MALLOC(env->allocator, decoded_nonce_length);
        ret = axutil_base64_decode_binary((unsigned char *)decoded_nonce, nonce);
    }

    if ((!nonce) && (!created))
    {
        /* If both nonce and created are omitted, string to be hashed is only password */
        password_length = axutil_strlen(password);
        input = AXIS2_MALLOC(env->allocator, password_length);
        memcpy(input, password, password_length);
    }
    else if (!nonce)
    {
        /* If nonce is omitted, but created is given. 
         * So, string to be hashed is created + password */
        created_length = axutil_strlen(created);
        password_length = axutil_strlen(password);
        input = AXIS2_MALLOC(env->allocator, created_length + password_length);
        memcpy(input, created, created_length);
        memcpy(input + created_length, password, password_length);
    }
    else  if (!created)
    {
        /* If created is omitted, but nonce is given. 
         * So, string to be hased is nonce + password */
        password_length = axutil_strlen(password);
        input = AXIS2_MALLOC(env->allocator, decoded_nonce_length + password_length);
        memcpy(input, decoded_nonce, decoded_nonce_length);
        memcpy(input + decoded_nonce_length, password, password_length);
    }
    else
    {
        /* If all nonce, created and password are present */
        created_length = axutil_strlen(created);
        password_length = axutil_strlen(password);
        input = AXIS2_MALLOC(
            env->allocator, decoded_nonce_length + created_length + password_length);
        memcpy(input, decoded_nonce, decoded_nonce_length);
        memcpy(input + decoded_nonce_length, created, created_length);
        memcpy(input + decoded_nonce_length + created_length, password, password_length);
    }

    digest = openssl_sha1(env, input, decoded_nonce_length + created_length + password_length);
    AXIS2_FREE(env->allocator, input);
    AXIS2_FREE(env->allocator, decoded_nonce);
    return digest;
}
