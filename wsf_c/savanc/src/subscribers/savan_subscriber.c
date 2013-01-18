/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
#include <axiom.h>
#include <platforms/axutil_platform_auto_sense.h>
#include <axis2_endpoint_ref.h>

#include <savan_subscriber.h>
#include <savan_util.h>
#include <savan_error.h>

struct savan_subscriber_t
{
    axis2_char_t *id;
    axis2_endpoint_ref_t *end_to;
    axis2_endpoint_ref_t *notify_to;
    axis2_char_t *delivery_mode;
    axis2_char_t *expires;
    axis2_char_t *filter;
    axis2_bool_t renewed;
	axis2_char_t *filter_dialect;
};

AXIS2_EXTERN savan_subscriber_t * AXIS2_CALL
savan_subscriber_create(
    const axutil_env_t *env)
{
    savan_subscriber_t *subscriber = NULL;
    
    subscriber = AXIS2_MALLOC(env->allocator, sizeof(savan_subscriber_t));
     
    if (!subscriber)
    { 
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;        
    }
    
    subscriber->id = NULL;
    subscriber->end_to = NULL;
    subscriber->notify_to = NULL;
    subscriber->delivery_mode = NULL;
    subscriber->expires = NULL;
    subscriber->filter = NULL;
    subscriber->filter_dialect = NULL;
    subscriber->renewed = AXIS2_FALSE;
        
    return subscriber;
}

AXIS2_EXTERN void AXIS2_CALL
savan_subscriber_free_void_arg(
    void *subscriber, 
    const axutil_env_t *env)
{
    savan_subscriber_t *subs = (savan_subscriber_t *) subscriber;
    savan_subscriber_free(subs, env);
}

AXIS2_EXTERN void AXIS2_CALL
savan_subscriber_free(
    savan_subscriber_t *subscriber, 
    const axutil_env_t *env)
{
    if(subscriber->id)
    {
        AXIS2_FREE(env->allocator, subscriber->id);
    }

    if(subscriber->delivery_mode)
    {
        AXIS2_FREE(env->allocator, subscriber->delivery_mode);
    }

    if(subscriber->expires)
    {
        AXIS2_FREE(env->allocator, subscriber->expires);
    }

    if(subscriber->filter)
    {
        AXIS2_FREE(env->allocator, subscriber->filter);
    }

    if(subscriber->filter_dialect)
    {
        AXIS2_FREE(env->allocator, subscriber->filter_dialect);
    }

    AXIS2_FREE(env->allocator, subscriber);
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
savan_subscriber_get_id(
    savan_subscriber_t *subscriber,
    const axutil_env_t *env)
{
    return subscriber->id;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_subscriber_set_id(
    savan_subscriber_t *subscriber,
    const axutil_env_t *env,
    const axis2_char_t *id)
{
    /* If id is already set, free it */
    if (subscriber->id)
    {
        AXIS2_FREE(env->allocator, subscriber->id);
        subscriber->id = NULL;
    }
    
    /* copy the new id */
    subscriber->id = axutil_strdup(env, id);

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_subscriber_set_filter_dialect
	(savan_subscriber_t *subscriber,
	const axutil_env_t *env,
	const axis2_char_t *filter_dialect)
{
	if(subscriber->filter_dialect)
	{
		AXIS2_FREE(env->allocator, subscriber->filter_dialect);
		subscriber->filter_dialect = NULL;
	}

	subscriber->filter_dialect = axutil_strdup(env, filter_dialect);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
savan_subscriber_get_filter_dialect(
	savan_subscriber_t *subscriber,
	const axutil_env_t *env)
{
	return subscriber->filter_dialect;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_subscriber_set_end_to(
    savan_subscriber_t *subscriber,
    const axutil_env_t *env,
    axis2_endpoint_ref_t *end_to)
{
    subscriber->end_to = end_to;

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_endpoint_ref_t *AXIS2_CALL
savan_subscriber_get_end_to(
    savan_subscriber_t *subscriber,
    const axutil_env_t *env)
{
    return subscriber->end_to;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_subscriber_set_notify_to(
    savan_subscriber_t *subscriber,
    const axutil_env_t *env,
    axis2_endpoint_ref_t *notify_to)
{
    subscriber->notify_to = notify_to;

    return AXIS2_SUCCESS;
}    
            
AXIS2_EXTERN axis2_endpoint_ref_t *AXIS2_CALL
savan_subscriber_get_notify_to(
    savan_subscriber_t *subscriber,
    const axutil_env_t *env)
{
    return subscriber->notify_to;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_subscriber_set_delivery_mode(
    savan_subscriber_t *subscriber,
    const axutil_env_t *env,
    const axis2_char_t *mode)
{
    /* if already set, free it */
    if (subscriber->delivery_mode)
    {
        AXIS2_FREE(env->allocator, subscriber->delivery_mode);
        subscriber->delivery_mode = NULL;
    }
    
    /* copy the new one */
    subscriber->delivery_mode = axutil_strdup(env, mode);

    return AXIS2_SUCCESS;
}    
            
AXIS2_EXTERN axis2_char_t * AXIS2_CALL
savan_subscriber_get_delivery_mode(
	savan_subscriber_t *subscriber,
	const axutil_env_t *env)
{
	return subscriber->delivery_mode;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_subscriber_set_expires(
    savan_subscriber_t *subscriber,
    const axutil_env_t *env,
    const axis2_char_t *expires)
{
    /* if already set, free it */
    if (subscriber->expires)
    {
        AXIS2_FREE(env->allocator, subscriber->expires);
        subscriber->expires = NULL;
    }
    
    /* copy the new one */
    subscriber->expires = axutil_strdup(env, expires);

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
savan_subscriber_get_expires(
    savan_subscriber_t *subscriber,
    const axutil_env_t *env)
{
    return subscriber->expires;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_subscriber_set_filter(
    savan_subscriber_t *subscriber,
    const axutil_env_t *env,
    const axis2_char_t *filter)
{
    /* if already set, free it */
    if (subscriber->filter)
    {
        AXIS2_FREE(env->allocator, subscriber->filter);
        subscriber->filter = NULL;
    }
    
    /* copy the new one */
    subscriber->filter = axutil_strdup(env, filter);

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
savan_subscriber_get_filter(
    savan_subscriber_t *subscriber,
    const axutil_env_t *env)
{
    return subscriber->filter;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_subscriber_set_renew_status(
    savan_subscriber_t *subscriber,
    const axutil_env_t *env,
    axis2_bool_t renewed)
{
    subscriber->renewed = renewed;

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
savan_subscriber_get_renew_status(
    savan_subscriber_t *subscriber,
    const axutil_env_t *env)
{
    return subscriber->renewed;
}

