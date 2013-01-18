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

#include <sandesha2_invoker_bean.h>
#include <axutil_string.h>
#include <axutil_utils.h>

struct sandesha2_invoker_bean
{
	/*  This is the messageContextRefKey that is obtained after saving a message context in a storage. */
	axis2_char_t *msg_ctx_ref_key;

	/* The message number of the message. */
	long msg_no;

	/*  The seq ID of the seq the message belong to. */
	axis2_char_t *seq_id;

	/* Weather the message has been invoked by the invoker.*/
	axis2_bool_t invoked;

};

AXIS2_EXTERN sandesha2_invoker_bean_t* AXIS2_CALL
sandesha2_invoker_bean_create(
    const axutil_env_t *env )
{
	sandesha2_invoker_bean_t *invoker_bean = NULL;
	invoker_bean = (sandesha2_invoker_bean_t *) AXIS2_MALLOC(
        env->allocator, sizeof(sandesha2_invoker_bean_t) );

	if (!invoker_bean)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
		return NULL;
	}

	/* init the properties. */
	invoker_bean->msg_ctx_ref_key = NULL;
	invoker_bean->msg_no = -1;
	invoker_bean->seq_id = NULL;	
	invoker_bean->invoked = AXIS2_FALSE;

	return invoker_bean;
}

AXIS2_EXTERN sandesha2_invoker_bean_t* AXIS2_CALL
sandesha2_invoker_bean_create_with_data(
    const axutil_env_t *env,
    axis2_char_t *ref_key,
    long msg_no,
    axis2_char_t *seq_id,
    axis2_bool_t invoked)
{
	sandesha2_invoker_bean_t *invoker_bean = NULL;
    invoker_bean = (sandesha2_invoker_bean_t *) AXIS2_MALLOC(
        env->allocator, sizeof(sandesha2_invoker_bean_t) );

	if (!invoker_bean)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
		return NULL;
	}
	/* init the properties. */
	if(!ref_key)
		invoker_bean->msg_ctx_ref_key = NULL;
	else
		invoker_bean->msg_ctx_ref_key = (axis2_char_t*)axutil_strdup(
            env, ref_key);

	if(!seq_id)
		invoker_bean->seq_id = NULL;	
	else
		invoker_bean->seq_id = (axis2_char_t*)axutil_strdup(env, seq_id);

	invoker_bean->msg_no = msg_no;
	invoker_bean->invoked = invoked;

	return invoker_bean;
}

void AXIS2_CALL
sandesha2_invoker_bean_free(
    sandesha2_invoker_bean_t *invoker_bean,
    const axutil_env_t *env)
{
	if(invoker_bean->msg_ctx_ref_key)
	{
		AXIS2_FREE(env->allocator, invoker_bean->msg_ctx_ref_key);
		invoker_bean->msg_ctx_ref_key= NULL;
	}
		
	if(!invoker_bean->seq_id)
	{
		AXIS2_FREE(env->allocator, invoker_bean->seq_id);
		invoker_bean->seq_id= NULL;
	}
    if(invoker_bean)
    {
        AXIS2_FREE(env->allocator, invoker_bean->seq_id);
        invoker_bean = NULL;
    }
}

axis2_char_t* AXIS2_CALL 
sandesha2_invoker_bean_get_msg_ctx_ref_key(
        sandesha2_invoker_bean_t *invoker_bean,
		const axutil_env_t *env)
{
	return invoker_bean->msg_ctx_ref_key;
}

void AXIS2_CALL 
sandesha2_invoker_bean_set_msg_ctx_ref_key(
    sandesha2_invoker_bean_t *invoker_bean,
    const axutil_env_t *env, axis2_char_t* context_ref_id)
{
	if(invoker_bean->msg_ctx_ref_key)
		AXIS2_FREE(env->allocator, invoker_bean->msg_ctx_ref_key);

	invoker_bean->msg_ctx_ref_key = 
        (axis2_char_t*)axutil_strdup(env, context_ref_id);
}
	

long AXIS2_CALL 
sandesha2_invoker_bean_get_msg_no(
    sandesha2_invoker_bean_t *invoker_bean,
    const axutil_env_t *env)
{
	return invoker_bean->msg_no;
}
	
void AXIS2_CALL
sandesha2_invoker_bean_set_msg_no(
    sandesha2_invoker_bean_t *invoker_bean,
    const axutil_env_t *env, long msgno)
{
	invoker_bean->msg_no = msgno;
}

axis2_char_t* AXIS2_CALL
sandesha2_invoker_bean_get_seq_id(
    sandesha2_invoker_bean_t *invoker_bean,
    const axutil_env_t *env)
{
	return invoker_bean->seq_id;
}

void AXIS2_CALL
sandesha2_invoker_bean_set_seq_id(
    sandesha2_invoker_bean_t *invoker_bean,
    const axutil_env_t *env, axis2_char_t* int_seq_id)
{
	invoker_bean->seq_id = (axis2_char_t*)axutil_strdup(env ,int_seq_id);

}

axis2_bool_t AXIS2_CALL
sandesha2_invoker_bean_is_invoked (
    sandesha2_invoker_bean_t *invoker_bean,
    const axutil_env_t *env)
{
	return invoker_bean->invoked;
}

void AXIS2_CALL 
sandesha2_invoker_bean_set_invoked( 
    sandesha2_invoker_bean_t *invoker_bean,
    const axutil_env_t *env,
    axis2_bool_t invoked)
{
	invoker_bean->invoked = invoked;
}

