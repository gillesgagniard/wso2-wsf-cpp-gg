/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sandesha2_sender_bean.h>
#include <string.h>
#include <axutil_string.h>
#include <axutil_utils.h>


/*sender_bean struct */
struct sandesha2_sender_bean
{
	axis2_char_t *msg_ctx_ref_key;
	axis2_char_t *msg_id;
	axis2_char_t *internal_seq_id;
	int sent_count;
	long msg_no;
	axis2_bool_t send;
	axis2_bool_t resend;
	long time_to_send;
	int msg_type;
	axis2_char_t *seq_id;
	axis2_char_t *wsrm_anon_uri;
	axis2_char_t *to_address;
};

AXIS2_EXTERN sandesha2_sender_bean_t* AXIS2_CALL
sandesha2_sender_bean_create(const axutil_env_t *env)
{
	sandesha2_sender_bean_t *sender_bean = NULL;

	sender_bean = (sandesha2_sender_bean_t*) AXIS2_MALLOC(env->allocator,
				sizeof(sandesha2_sender_bean_t));

	if(!sender_bean)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
		return NULL;
	}

	/* init properties */
	sender_bean->msg_ctx_ref_key = NULL;
	sender_bean->msg_id = NULL;
	sender_bean->internal_seq_id = NULL;
	sender_bean->sent_count = -1;
	sender_bean->msg_no = -1;
	sender_bean->send = AXIS2_FALSE;
	sender_bean->resend = AXIS2_TRUE;
	sender_bean->time_to_send = -1;
	sender_bean->msg_type = 0;
	sender_bean->seq_id = NULL;
	sender_bean->wsrm_anon_uri = NULL;
	sender_bean->to_address = NULL;

    return sender_bean;
}


AXIS2_EXTERN sandesha2_sender_bean_t* AXIS2_CALL
sandesha2_sender_bean_create_with_data(
    const axutil_env_t *env,
    axis2_char_t *msg_id,
    axis2_char_t *key,
    axis2_bool_t send,
    long    time_to_send,
    axis2_char_t *int_seq_id,
    long msg_no)

{
	sandesha2_sender_bean_t *sender_bean = NULL;

	sender_bean = (sandesha2_sender_bean_t*) AXIS2_MALLOC(env->allocator,
				sizeof(sandesha2_sender_bean_t));

	if(!sender_bean)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
		return NULL;
	}

	/* init properties */
	sender_bean->msg_ctx_ref_key = (axis2_char_t *)axutil_strdup(env, key);
	sender_bean->msg_id = (axis2_char_t *)axutil_strdup(env, msg_id);
	sender_bean->internal_seq_id = (axis2_char_t *)axutil_strdup(env, int_seq_id);
	sender_bean->sent_count = -1;
	sender_bean->msg_no = msg_no;
	sender_bean->send = send; 
	sender_bean->resend = AXIS2_TRUE;
	sender_bean->time_to_send = time_to_send;
	sender_bean->msg_type = 0;
	sender_bean->seq_id = NULL;
	sender_bean->wsrm_anon_uri = NULL;

    return sender_bean;
}

void AXIS2_CALL
sandesha2_sender_bean_free (
    sandesha2_sender_bean_t *sender_bean,
	const axutil_env_t *env)
{
	if(sender_bean->msg_ctx_ref_key)
	{
		AXIS2_FREE(env->allocator, sender_bean->msg_ctx_ref_key);
		sender_bean->msg_ctx_ref_key = NULL;
	}
	if(sender_bean->msg_id)
	{
		AXIS2_FREE(env->allocator, sender_bean->msg_id);
		sender_bean->msg_id = NULL;
	}
	if(sender_bean->internal_seq_id)
	{
		AXIS2_FREE(env->allocator, sender_bean->internal_seq_id);
		sender_bean->internal_seq_id = NULL;
	}
	if(sender_bean->seq_id)
	{
		AXIS2_FREE(env->allocator, sender_bean->seq_id);
		sender_bean->seq_id = NULL;
	}
	if(sender_bean->wsrm_anon_uri)
	{
		AXIS2_FREE(env->allocator, sender_bean->wsrm_anon_uri);
		sender_bean->wsrm_anon_uri = NULL;
	}
	if(sender_bean->to_address)
	{
		AXIS2_FREE(env->allocator, sender_bean->to_address);
		sender_bean->to_address = NULL;
	}
    if(sender_bean)
    {
        AXIS2_FREE(env->allocator, sender_bean);
        sender_bean = NULL;
    }
}

axis2_char_t* AXIS2_CALL
sandesha2_sender_bean_get_msg_ctx_ref_key (
    sandesha2_sender_bean_t *sender_bean,
    const axutil_env_t *env)
{
	return sender_bean->msg_ctx_ref_key;
}

void AXIS2_CALL
sandesha2_sender_bean_set_msg_ctx_ref_key (
    sandesha2_sender_bean_t *sender_bean,
    const axutil_env_t *env,
    axis2_char_t *ref_key)
{
	if(sender_bean->msg_ctx_ref_key)
	{
		AXIS2_FREE(env->allocator, sender_bean->msg_ctx_ref_key);
		sender_bean->msg_ctx_ref_key = NULL;
	}
	sender_bean->msg_ctx_ref_key = (axis2_char_t *)axutil_strdup(env, ref_key);
}

axis2_char_t* AXIS2_CALL
sandesha2_sender_bean_get_msg_id (
    sandesha2_sender_bean_t *sender_bean,
    const axutil_env_t *env)
{
	return sender_bean->msg_id;
}

void AXIS2_CALL 
sandesha2_sender_bean_set_msg_id (
    sandesha2_sender_bean_t *sender_bean,
    const axutil_env_t *env,
    axis2_char_t *msg_id)
{
	if(sender_bean->msg_id)
	{
		AXIS2_FREE(env->allocator, msg_id);
		sender_bean->msg_id = NULL;
	}
	sender_bean->msg_id = (axis2_char_t *)axutil_strdup(env, msg_id);
}

axis2_bool_t AXIS2_CALL
sandesha2_sender_bean_is_send (
    sandesha2_sender_bean_t *sender_bean,
    const axutil_env_t *env)
{
	return sender_bean->send;
}

void AXIS2_CALL 
sandesha2_sender_bean_set_send (
    sandesha2_sender_bean_t *sender_bean,
    const axutil_env_t *env,
    axis2_bool_t send)
{
	sender_bean->send = send;
}

axis2_char_t* AXIS2_CALL
sandesha2_sender_bean_get_internal_seq_id (
    sandesha2_sender_bean_t *sender_bean,
    const axutil_env_t *env)
{
	return sender_bean->internal_seq_id;
}

void AXIS2_CALL 
sandesha2_sender_bean_set_internal_seq_id (
    sandesha2_sender_bean_t *sender_bean,
    const axutil_env_t *env,
    axis2_char_t *int_seq_id)
{
	if(sender_bean->internal_seq_id)
	{
		AXIS2_FREE(env->allocator, int_seq_id);
		sender_bean->internal_seq_id = NULL;
	}

	sender_bean->internal_seq_id = (axis2_char_t *)axutil_strdup(env, int_seq_id);
}

int AXIS2_CALL 
sandesha2_sender_bean_get_sent_count (
    sandesha2_sender_bean_t *sender_bean,
    const axutil_env_t *env)
{
	return sender_bean->sent_count;
}

void AXIS2_CALL 
sandesha2_sender_bean_set_sent_count (
    sandesha2_sender_bean_t *sender_bean,
    const axutil_env_t *env,
    int sent_count)
{
	sender_bean->sent_count = sent_count;
}

long AXIS2_CALL
sandesha2_sender_bean_get_msg_no (
    sandesha2_sender_bean_t *sender_bean,
    const axutil_env_t *env)
{
	return sender_bean->msg_no;
}

void AXIS2_CALL
sandesha2_sender_bean_set_msg_no (
    sandesha2_sender_bean_t *sender_bean,
    const axutil_env_t *env,
    long msg_no)
{
	sender_bean->msg_no = msg_no;
}

axis2_bool_t AXIS2_CALL
sandesha2_sender_bean_is_resend (
    sandesha2_sender_bean_t *sender_bean,
    const axutil_env_t *env)
{
	return sender_bean->resend;
}

void AXIS2_CALL
sandesha2_sender_bean_set_resend (
    sandesha2_sender_bean_t *sender_bean,
    const axutil_env_t *env,
    axis2_bool_t resend)
{
	sender_bean->resend = resend;
}

long AXIS2_CALL
sandesha2_sender_bean_get_time_to_send (
    sandesha2_sender_bean_t *sender_bean,
    const axutil_env_t *env)
{
	return sender_bean->time_to_send;
}


void AXIS2_CALL
sandesha2_sender_bean_set_time_to_send (
    sandesha2_sender_bean_t *sender_bean,
    const axutil_env_t *env,
    long time_to_send)
{
	sender_bean->time_to_send = time_to_send;
}

int AXIS2_CALL
sandesha2_sender_bean_get_msg_type (
    sandesha2_sender_bean_t *sender_bean,
    const axutil_env_t *env)
{
	return sender_bean->msg_type;
}

void AXIS2_CALL
sandesha2_sender_bean_set_msg_type (
    sandesha2_sender_bean_t *sender_bean,
    const axutil_env_t *env,
    int msg_type)
{
	sender_bean->msg_type = msg_type;
}

axis2_char_t* AXIS2_CALL
sandesha2_sender_bean_get_seq_id(
    sandesha2_sender_bean_t *sender_bean,
    const axutil_env_t *env)
{
	return sender_bean->seq_id;
}

void AXIS2_CALL
sandesha2_sender_bean_set_seq_id (
    sandesha2_sender_bean_t *sender_bean,
    const axutil_env_t *env,
    axis2_char_t *seq_id)
{
	if(sender_bean->seq_id)
	{
		AXIS2_FREE(env->allocator, sender_bean->seq_id);
		sender_bean->seq_id = NULL;
	}

	sender_bean->seq_id = (axis2_char_t *)axutil_strdup(env, seq_id);
}

axis2_char_t* AXIS2_CALL
sandesha2_sender_bean_get_wsrm_anon_uri(
    sandesha2_sender_bean_t *sender_bean,
	const axutil_env_t *env)
{
	return sender_bean->wsrm_anon_uri;
}

void AXIS2_CALL
sandesha2_sender_bean_set_wsrm_anon_uri (
    sandesha2_sender_bean_t *sender_bean,
    const axutil_env_t *env,
    axis2_char_t *anon_uri)
{
	if(sender_bean->wsrm_anon_uri)
	{
		AXIS2_FREE(env->allocator, sender_bean->wsrm_anon_uri);
		sender_bean->wsrm_anon_uri = NULL;
	}

	sender_bean->wsrm_anon_uri = (axis2_char_t *)axutil_strdup(env, anon_uri);
}

void AXIS2_CALL
sandesha2_sender_bean_set_to_address (
    sandesha2_sender_bean_t *sender_bean,
    const axutil_env_t *env,
    axis2_char_t *to_address)
{
	if(sender_bean->to_address)
	{
		AXIS2_FREE(env->allocator, sender_bean->to_address);
		sender_bean->to_address = NULL;
	}

	sender_bean->to_address = (axis2_char_t *)axutil_strdup(env, to_address);
}

axis2_char_t* AXIS2_CALL
sandesha2_sender_bean_get_to_address(
    sandesha2_sender_bean_t *sender_bean,
	const axutil_env_t *env)
{
	return sender_bean->to_address;
}

