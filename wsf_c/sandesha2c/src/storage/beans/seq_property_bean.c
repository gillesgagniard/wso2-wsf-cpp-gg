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

#include <sandesha2_seq_property_bean.h>
#include <sandesha2_transaction.h>
#include <string.h>
#include <axutil_string.h>
#include <axutil_utils.h>


/*seq_property_bean struct */
struct sandesha2_seq_property_bean
{
	axis2_char_t *seq_id;
	axis2_char_t *name;
	axis2_char_t *value;
};

AXIS2_EXTERN sandesha2_seq_property_bean_t* AXIS2_CALL
sandesha2_seq_property_bean_create(
    const axutil_env_t *env)
{
    sandesha2_seq_property_bean_t *seq_property_bean = NULL;
	seq_property_bean = (sandesha2_seq_property_bean_t *)AXIS2_MALLOC(
        env->allocator, sizeof(sandesha2_seq_property_bean_t));

	if(!seq_property_bean)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
		return NULL;
	}

	/* initialize properties */
	seq_property_bean->seq_id = NULL;
	seq_property_bean->name = NULL;
	seq_property_bean->value = NULL;

    return seq_property_bean;
}

AXIS2_EXTERN sandesha2_seq_property_bean_t* AXIS2_CALL
sandesha2_seq_property_bean_create_with_data(
    const axutil_env_t *env,
    axis2_char_t *seq_id,
    axis2_char_t *prop_name,
    axis2_char_t *value)

{
    sandesha2_seq_property_bean_t *seq_property_bean = NULL;
	seq_property_bean = (sandesha2_seq_property_bean_t *)AXIS2_MALLOC(
        env->allocator, sizeof(sandesha2_seq_property_bean_t));

	if(!seq_property_bean)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
		return NULL;
	}
	/* initialize properties */
	seq_property_bean->seq_id = (axis2_char_t *)axutil_strdup(env, seq_id);
	seq_property_bean->name = (axis2_char_t *)axutil_strdup(env, prop_name);
	seq_property_bean->value = (axis2_char_t *)axutil_strdup(env, value);

    return seq_property_bean;
}


void AXIS2_CALL
sandesha2_seq_property_bean_free (
    sandesha2_seq_property_bean_t *seq_property_bean,
    const axutil_env_t *env)
{
	if(seq_property_bean->seq_id)
	{
		AXIS2_FREE(env->allocator, seq_property_bean->seq_id);
		seq_property_bean->seq_id = NULL;
	}
	if(seq_property_bean->name)
	{
		AXIS2_FREE(env->allocator, seq_property_bean->name);
		seq_property_bean->name = NULL;
	}
	if(seq_property_bean->value)
	{
		AXIS2_FREE(env->allocator,  seq_property_bean->value);
		seq_property_bean->value = NULL;
	}
	if(seq_property_bean)
	{
		AXIS2_FREE(env->allocator,  seq_property_bean);
        seq_property_bean = NULL;
	}
}

axis2_char_t *AXIS2_CALL
sandesha2_seq_property_bean_get_name (
    sandesha2_seq_property_bean_t *seq_property_bean,
    const axutil_env_t *env)
{
	return seq_property_bean->name;
}

void AXIS2_CALL 
sandesha2_seq_property_bean_set_name (
    sandesha2_seq_property_bean_t *seq_property_bean,
    const axutil_env_t *env,
    axis2_char_t *name)
{
	if(seq_property_bean->name)
	{
		AXIS2_FREE(env->allocator, seq_property_bean->name);
		seq_property_bean->name = NULL;
	}
    if(name)
        seq_property_bean->name = (axis2_char_t *)axutil_strdup(env, name);
}

axis2_char_t *AXIS2_CALL
sandesha2_seq_property_bean_get_seq_id (
    sandesha2_seq_property_bean_t *seq_property_bean,
    const axutil_env_t *env)
{
	return seq_property_bean->seq_id;
}


void AXIS2_CALL
sandesha2_seq_property_bean_set_seq_id (
    sandesha2_seq_property_bean_t *seq_property_bean,
    const axutil_env_t *env,
    axis2_char_t *seq_id)
{
	if(seq_property_bean->seq_id)
	{
		AXIS2_FREE(env->allocator, seq_property_bean->seq_id);
		seq_property_bean->seq_id = NULL;
	}
    if(seq_id)
        seq_property_bean->seq_id = (axis2_char_t *)axutil_strdup(env, seq_id);
}

axis2_char_t* AXIS2_CALL
sandesha2_seq_property_bean_get_value (
    sandesha2_seq_property_bean_t *seq_property_bean,
    const axutil_env_t *env)
{
	return seq_property_bean->value;
}


void AXIS2_CALL
sandesha2_seq_property_bean_set_value (
    sandesha2_seq_property_bean_t *seq_property_bean,
    const axutil_env_t *env,
    axis2_char_t *value)
{
	if(seq_property_bean->value)
	{
		AXIS2_FREE(env->allocator, seq_property_bean->value);
		seq_property_bean->value = NULL;
	}

    if(value)
    {
        seq_property_bean->value = (axis2_char_t *)axutil_strdup(env, value);
    }
}

