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

#include <axis2_defines.h>
#include <stdio.h>
#include <axis2_util.h>
#include <oxs_constants.h>
#include <oxs_buffer.h>
#include <oxs_axiom.h>
#include <oxs_error.h>

struct oxs_buffer
{
    unsigned char* data; /* will be adjusted based on oxs_buffer_remove_head method */
    unsigned char* original_data; /* to free the data */
    int size;
    int max_size;
    oxs_AllocMode alloc_mode;
};

AXIS2_EXTERN oxs_buffer_t *AXIS2_CALL
oxs_buffer_create(
    const axutil_env_t *env)
{
    oxs_buffer_t *buffer = NULL;

    buffer = (oxs_buffer_t*)AXIS2_MALLOC(env->allocator, sizeof(oxs_buffer_t));
    if(!buffer)
    {
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[rampart]insufficient memory. oxs buffer creation failed");
        return NULL;
    }

    buffer->data = NULL;
    buffer->original_data = NULL;
    buffer->size = 0;
    buffer->max_size = 0;
    buffer->alloc_mode = oxs_alloc_mode_double;  /* increase the size exponentially */
    return buffer;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_buffer_free(
    oxs_buffer_t *buffer,
    const axutil_env_t *env)
{
    if(buffer->original_data)
    {
        AXIS2_FREE(env->allocator, buffer->original_data);
    }

    AXIS2_FREE(env->allocator, buffer);
    buffer = NULL;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_buffer_remove_head(
    oxs_buffer_t *buffer,
    const axutil_env_t *env,
    int size)
{
    if(!buffer->data)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[rampart]oxs_buffer_remove_head failed. data is NULL");
        return AXIS2_FAILURE;
    }

    /*If the size to be removed is less than the buffer size*/
    if(size < buffer->size)
    {
        buffer->size -= size;
        buffer->max_size -= size; /* since we are not freeing the head, effective max_size is less */
        buffer->data += size;
    }
    else
    {
        buffer->size = 0;
        buffer->data = NULL;
    }

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_buffer_populate(
    oxs_buffer_t *buffer,
    const axutil_env_t *env,
    unsigned char *data,
    int size)
{
    if((!data) || (size <= 0))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[rampart]Cannot populate data to oxs buffer. data is not valid");
        return AXIS2_FAILURE;
    }

    oxs_buffer_set_max_size(buffer, env, size);
    memcpy(buffer->data, data, size);
    buffer->size = size;
    buffer->data[size] = '\0';
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_buffer_append(
    oxs_buffer_t *buffer,
    const axutil_env_t *env,
    unsigned char *data,
    int size)
{
    if((!data) || (size <= 0))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[rampart]Cannot append data to oxs buffer. data is not valid");
        return AXIS2_FAILURE;
    }

    oxs_buffer_set_max_size(buffer, env, buffer->size + size);
    memcpy(buffer->data + buffer->size, data, size);
    buffer->size += size;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_buffer_read_file(
    oxs_buffer_t *buffer,
    const axutil_env_t *env,
    const axis2_char_t *filename)
{
    unsigned char fbuffer[1024];
    FILE * f;
    int len;

    f = fopen(filename, "rb");
    if(!f)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[rampart]cannot open file %s. Populating oxs buffer from file failed.", filename);
        return AXIS2_FAILURE;
    }

    while(1)
    {
        len = fread(fbuffer, 1, sizeof(fbuffer), f);
        if(len == 0)
        {
            break; /*Stop reading*/
        }
        else if(len < 0)
        {
            fclose(f);
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                "[rampart]Cannot read file %s. Populating oxs buffer from file failed.", filename);
            return AXIS2_FAILURE;
        }

        if(oxs_buffer_append(buffer, env, fbuffer, len) != AXIS2_SUCCESS)
        {
            fclose(f);
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                "[rampart]Cannot append data to oxs buffer. Populating buffer from %s failed.",
                filename);
            return AXIS2_FAILURE;
        }
    }/*End of while*/

    fclose(f);
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_buffer_set_size(
    oxs_buffer_t *buffer,
    const axutil_env_t *env,
    int size)
{
    /*First we need to make sure that the max size has a value greater or equal value*/
    if(oxs_buffer_set_max_size(buffer, env, size) != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart] oxs_buffer_set_max_size failed");
        return AXIS2_FAILURE;
    }

    /*Now set the size*/
    buffer->size = size;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_buffer_set_max_size(
    oxs_buffer_t *buffer,
    const axutil_env_t *env,
    int size)
{
    unsigned char* new_data;
    unsigned int new_size = 0;

    if(size <= buffer->max_size)
    {
        return AXIS2_SUCCESS;
    }

    switch(buffer->alloc_mode)
    {
        case oxs_alloc_mode_exact:
            new_size = size + 8;
            break;
        case oxs_alloc_mode_double:
            new_size = 2 * size + 32;
            break;
    }

    if(new_size < OXS_BUFFER_INITIAL_SIZE)
    {
        new_size = OXS_BUFFER_INITIAL_SIZE;
    }

    new_data = (unsigned char*)AXIS2_MALLOC(env->allocator, new_size);
    if(!new_data)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[rampart]cannot increase the size of oxs buffer. Insufficient memory");
        return AXIS2_FAILURE;
    }

    if(buffer->data)
    {
        /* Copy existing data */
        new_data = memcpy(new_data, buffer->data, buffer->size);
    }

    if(buffer->original_data)
    {
        /* we don't need the original data now. buffer->data is part of buffer->original_data.
         * Since we are going to change the pointer of buffer->data, we can free original_data
         */
        AXIS2_FREE(env->allocator, buffer->original_data);
    }

    buffer->data = new_data;
    buffer->original_data = new_data;
    buffer->max_size = new_size;

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN unsigned char* AXIS2_CALL
oxs_buffer_get_data(
    oxs_buffer_t *buffer,
    const axutil_env_t *env)
{
    return buffer->data;
}

AXIS2_EXTERN int AXIS2_CALL
oxs_buffer_get_size(
    oxs_buffer_t *buffer,
    const axutil_env_t *env)
{
    return buffer->size;
}

AXIS2_EXTERN int AXIS2_CALL
oxs_buffer_get_max_size(
    oxs_buffer_t *buffer,
    const axutil_env_t *env)
{
    return buffer->max_size;
}

#if 0 /* this seemed to be not used 1.3.0*/
AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_buffer_prepend(
    oxs_buffer_t *buffer,
    const axutil_env_t *env,
    unsigned char *data,
    int size)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    if(size > 0)
    {
        if(!data)
        {
            oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_INVALID_DATA, "Passed data is NULL");
            return AXIS2_FAILURE;
        }

        buffer->max_size = buffer->size + size;

        memmove(buffer->data + size, buffer->data, buffer->size);
        memcpy(buffer->data, data, size);
        buffer->size += size;
    }

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN oxs_buffer_t *AXIS2_CALL
oxs_buffer_dup(
    oxs_buffer_t *buffer,
    const axutil_env_t *env)
{
    oxs_buffer_t *buf = NULL;

    buf = oxs_buffer_create(env);
    if(!buf)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]duplicating oxs buffer failed");
        return NULL;
    }

    if(oxs_buffer_populate(buf, env, oxs_buffer_get_data(buffer, env),
        oxs_buffer_get_size(buffer, env)) != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[rampart]populating buffer failed. Cannot duplicate given oxs buffer");
        oxs_buffer_free(buf, env);
        return NULL;
    }

    return buf;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_buffer_remove_tail(
    oxs_buffer_t *buffer,
    const axutil_env_t *env,
    int size)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    if(size < buffer->size)
    {
        buffer->size -= size;
    }
    else
    {
        buffer->size = 0;
    }
    if(buffer->size < buffer->max_size)
    {
        if(buffer->data)
        {
            oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_INVALID_DATA, "");
            return AXIS2_FAILURE;
        }
        memset(buffer->data + buffer->size, 0, buffer->max_size - buffer->size);
    }

    return AXIS2_SUCCESS;
}
#endif
