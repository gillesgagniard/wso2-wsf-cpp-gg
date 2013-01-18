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
#include <oxs_utility.h>
#include <oxs_error.h>
#include <oxs_buffer.h>
#include <oxs_asym_ctx.h>
#include <openssl_util.h>
#include <oxs_key_mgr.h>

AXIS2_EXTERN axis2_char_t* AXIS2_CALL
oxs_util_generate_nonce(const axutil_env_t *env, int length)
{
    oxs_buffer_t *buffer = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    char *rand_str = NULL;
    axis2_char_t* encoded_str = NULL;

    buffer = oxs_buffer_create(env);
    status = openssl_generate_random_data(env, buffer, length);
    rand_str = (char*)oxs_buffer_get_data(buffer, env);
    encoded_str = AXIS2_MALLOC(env->allocator, sizeof(char) * (axutil_base64_encode_len(length)+1));
    axutil_base64_encode(encoded_str, rand_str, oxs_buffer_get_size(buffer, env));
    oxs_buffer_free(buffer, env);

    return encoded_str;
}



/* Generates an id for an element.
 * Specially used in xml encryption and signature references.
 * */
AXIS2_EXTERN axis2_char_t* AXIS2_CALL
oxs_util_generate_id(const axutil_env_t *env,
                     axis2_char_t *prefix)
{
    axis2_char_t *id = NULL;
    char _id[50];
    axis2_char_t *random ;
	axis2_char_t *uuid = NULL;

	uuid = axutil_uuid_gen(env);
    random =  axutil_strndup(env, uuid, 23);
    sprintf(_id, "%s-%s", prefix, random);
    id = (axis2_char_t*)axutil_strdup(env, _id);
	AXIS2_FREE(env->allocator, uuid);
    AXIS2_FREE(env->allocator, random);
    random = NULL;
    return id;

}

AXIS2_EXTERN oxs_key_mgr_format_t AXIS2_CALL
oxs_util_get_format_by_file_extension(const axutil_env_t *env,
                                      axis2_char_t *file_name)
{
    axis2_char_t *extension = NULL;
    if(!file_name){
        return OXS_ASYM_CTX_FORMAT_UNKNOWN;
    }
    extension = axutil_rindex(file_name, '.');
    if(!extension){
        /*No extension*/
        /*Its safe to assume that PEM can be without extension*/
        return OXS_ASYM_CTX_FORMAT_PEM;
    }

    if((strcmp(extension, ".pfx") == 0) || (strcmp(extension, ".p12") == 0) ){
        return OXS_ASYM_CTX_FORMAT_PKCS12;
    }else{
        /*Its safe to assume that PEM can be in any extensions. e.g. .cert, .cer, .pem*/
        return OXS_ASYM_CTX_FORMAT_PEM;
    }

}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
oxs_util_get_newline_removed_string(const axutil_env_t *env,
                                    axis2_char_t *input)
{
    /*axis2_char_t *output = NULL;
    int i = 0;

    output = AXIS2_MALLOC(env->allocator, axutil_strlen(input) +1);

    while(*input!='\0')
    {
        if(*input!='\n')
        {
            output[i] = *input;
            i++;
        }
        input++;
    }
    output[i]='\0';
    return output;*/

    axis2_char_t *output = NULL;
    int index = 0;
    int len = axutil_strlen(input);

    output = AXIS2_MALLOC(env->allocator, len +1);

    while(len > 0)
    {
        size_t i = 0;

        /* scan buffer until the next newline character and skip it */
        axis2_char_t *pos = (axis2_char_t*)strchr(input, '\n');
        if(pos)
        {
            i = pos - input;
        }
        else
        {
            i = len;
        }

        /* write everything until the special character */
        if(i > 0)
        {
            memcpy(output + index, input, i);
            input += i;
            index += i;
            len -= i;
        }

        /* skip the new line */
        if(len > 0)
        {
            ++input;
            --len;
        }
    }

    output[index]='\0';
    return output;
}
