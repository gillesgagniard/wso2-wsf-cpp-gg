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
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl_hmac.h>
#include <axutil_base64.h>
#include <axis2_util.h>
#include <openssl_constants.h>
#include <oxs_utility.h>
/**

*/
AXIS2_EXTERN axis2_status_t AXIS2_CALL
openssl_hmac_sha1(const axutil_env_t *env,
             oxs_key_t *secret,
             oxs_buffer_t *input,
             oxs_buffer_t *output)
{
    HMAC_CTX ctx;
    unsigned char hmac[EVP_MAX_MD_SIZE + 1];
    unsigned int hashed_len;

    if(!secret){
       oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_SIGN_FAILED,"[oxs][openssl] No key to sign ");
       return AXIS2_FAILURE; 
    }
    
    if(!input){
       oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_SIGN_FAILED,"[oxs][openssl] Nothing to sign ");
       return AXIS2_FAILURE; 
    }
    
    if(!output){
       oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_SIGN_FAILED,"[oxs][openssl] The buffer to place signature is NULL ");
       return AXIS2_FAILURE; 
    }

    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, oxs_key_get_data(secret, env), oxs_key_get_size(secret, env), EVP_sha1(), NULL);
    HMAC_Update(&ctx, oxs_buffer_get_data(input, env), oxs_buffer_get_size(input, env));
    HMAC_Final(&ctx, hmac, &hashed_len);

    /*Fill the output buffer*/
    oxs_buffer_populate(output, env, hmac, hashed_len); 

    HMAC_cleanup(&ctx); 
    
    HMAC_CTX_cleanup(&ctx);
    return AXIS2_SUCCESS;
}

/*
 * Borrowed from openssl library. Thankyou
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
openssl_p_hash(const axutil_env_t *env,
			unsigned char *secret,
            unsigned int secret_len,
			unsigned char *seed, 
			unsigned int seed_len, 
			unsigned char *output,
			unsigned int output_len)
{
	int chunk;
	unsigned int j;
	HMAC_CTX ctx;
	HMAC_CTX ctx_tmp;
	unsigned char A1[EVP_MAX_MD_SIZE];
	unsigned int A1_len;

	/*
	char a[5000];
	printf("seed_len %d\n", seed_len);
	axutil_base64_encode(a, (const char*)seed, seed_len);
	printf("seed is %s\n", a);
	*/

    if(!secret)
	{
       oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_KEY_DERIVATION_FAILED,"[oxs][openssl] No key to derive ");
       return AXIS2_FAILURE; 
    }
    
    if(!seed)
	{
       oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_KEY_DERIVATION_FAILED,"[oxs][openssl] lable+seed is empty ");
       return AXIS2_FAILURE; 
    }
    
    if(!output)
	{
       oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_KEY_DERIVATION_FAILED,"[oxs][openssl] The buffer to place hash is NULL ");
       return AXIS2_FAILURE; 
    }
	
	chunk=EVP_MD_size(EVP_sha1());

	HMAC_CTX_init(&ctx);
	HMAC_CTX_init(&ctx_tmp);
	HMAC_Init_ex(&ctx, secret, secret_len, EVP_sha1(), NULL);
	HMAC_Init_ex(&ctx_tmp, secret, secret_len, EVP_sha1(), NULL);
	HMAC_Update(&ctx, seed, seed_len);
	HMAC_Final(&ctx, A1, &A1_len);

	for (;;)
	{
		HMAC_Init_ex(&ctx, NULL, 0, NULL, NULL); /* re-init */
		HMAC_Init_ex(&ctx_tmp, NULL, 0, NULL, NULL); /* re-init */
		HMAC_Update(&ctx, A1, A1_len);
		HMAC_Update(&ctx_tmp, A1, A1_len);
		HMAC_Update(&ctx, seed, seed_len);

		if (output_len > chunk)
		{
			HMAC_Final(&ctx, output, &j);
			output+=j;
			output_len-=j;
			HMAC_Final(&ctx_tmp, A1, &A1_len); /* calc the next A1 value */
		}
		else    /* last one */
		{
			HMAC_Final(&ctx, A1, &A1_len);
			memcpy(output, A1, output_len);
			break;
		}
	}
	HMAC_CTX_cleanup(&ctx);
	HMAC_CTX_cleanup(&ctx_tmp);
	OPENSSL_cleanse(A1,sizeof(A1));

	return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
openssl_p_sha1(const axutil_env_t *env,
			oxs_key_t *secret,
			axis2_char_t *label,
			axis2_char_t *seed,
			oxs_key_t *derived_key)
{
	oxs_buffer_t *label_and_seed = NULL;
	unsigned int key_len = 0;
	unsigned char *output = NULL;
	axis2_char_t *dk_id = NULL;
	axis2_char_t *dk_name = NULL;
	axis2_char_t *decoded_seed = NULL;
	unsigned int decoded_seed_len = 0;
	axis2_status_t status = AXIS2_FAILURE;
	unsigned int length;
	unsigned int offset;

	if(!derived_key)
	{
       oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_KEY_DERIVATION_FAILED,"[oxs][openssl] derived key is null ");
       return status; 
	}

	if (!secret)
	{
		oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_KEY_DERIVATION_FAILED,"[oxs][openssl] secret is not valid ");
		return status;
	}

	length = oxs_key_get_length(derived_key, env);
	offset = oxs_key_get_offset(derived_key, env);

	if (!length)
	{
		length = OPENSSL_DEFAULT_KEY_LEN_FOR_PSHA1;
        oxs_key_set_length(derived_key, env, length);
	}

	label_and_seed = oxs_buffer_create(env);

	if((!label) || (!axutil_strlen(label)))
	{
		label = axutil_stracat(env, OPENSSL_DEFAULT_LABEL_FOR_PSHA1, OPENSSL_DEFAULT_LABEL_FOR_PSHA1);
		oxs_key_set_label(derived_key, env, label);
		oxs_buffer_append(label_and_seed, env, (unsigned char*)label, axutil_strlen(label));
		AXIS2_FREE(env->allocator, label);
		label = NULL;
	}
	else
	{
		oxs_buffer_append(label_and_seed, env, (unsigned char*)label, axutil_strlen(label));
	}
	

	if ((!seed) || (!axutil_strlen(seed)))
	{
		seed = oxs_util_generate_nonce(env, 16);
		oxs_key_set_nonce(derived_key, env, seed);
		decoded_seed_len = axutil_base64_decode_len(seed);
		decoded_seed = AXIS2_MALLOC(env->allocator, decoded_seed_len);
		axutil_base64_decode_binary((unsigned char*)decoded_seed, seed);
		AXIS2_FREE(env->allocator, seed);
		seed = NULL;
	}
	else
	{
		decoded_seed_len = axutil_base64_decode_len(seed);
		decoded_seed = AXIS2_MALLOC(env->allocator, decoded_seed_len);
		axutil_base64_decode_binary((unsigned char*)decoded_seed, seed);
	}

	if(decoded_seed)
	{
		oxs_buffer_append(label_and_seed, env,  (unsigned char*)decoded_seed, decoded_seed_len);
		AXIS2_FREE(env->allocator, decoded_seed);
		decoded_seed = NULL;
	}
	
	
	oxs_key_set_offset(derived_key, env, offset);
	key_len = length + offset;
	output = (unsigned char*)AXIS2_MALLOC(env->allocator, key_len + 1);
    status = openssl_p_hash(env, oxs_key_get_data(secret, env), 
                            oxs_key_get_size(secret, env), 
                            oxs_buffer_get_data(label_and_seed, env), 
                            oxs_buffer_get_size(label_and_seed, env), 
                            output, key_len);
	/*output = (unsigned char*)axutil_string_substring_starting_at((axis2_char_t*)output, offset);*/
	dk_id = (axis2_char_t*)oxs_util_generate_id(env, (axis2_char_t*)OXS_DERIVED_ID);
	dk_name = axutil_stracat(env, OXS_LOCAL_REFERENCE_PREFIX, dk_id);

	status = status && oxs_key_populate(derived_key, env, (unsigned char*)(output+offset), dk_name, length, OXS_KEY_USAGE_DERIVED);
	AXIS2_FREE(env->allocator, output);
	AXIS2_FREE(env->allocator, dk_id);
	AXIS2_FREE(env->allocator, dk_name);
	oxs_buffer_free(label_and_seed, env);

	return status;
}
