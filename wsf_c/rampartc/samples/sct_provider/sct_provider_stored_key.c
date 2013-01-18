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

#include <axis2_util.h>
#include <axutil_string.h>
#include <axutil_utils.h>
#include <oxs_utility.h>
#include <rampart_util.h>
#include <rampart_sct_provider.h>
#include <secconv_security_context_token.h>
#include <axis2_conf_ctx.h>

#define RAMPART_SCT_PROVIDER_HASH_PROB "Rampart_SCT_Prov_DB_Prop"

AXIS2_EXTERN axis2_status_t AXIS2_CALL
sct_provider_free(
    rampart_sct_provider_t *sct_provider,
    const axutil_env_t* env)
{
	if (sct_provider)
	{
		if (sct_provider->ops)
		{
			AXIS2_FREE(env->allocator, sct_provider->ops);
		}
		AXIS2_FREE(env->allocator, sct_provider);
	}
	return AXIS2_SUCCESS;
}

static void 
sct_provider_stored_key_sct_hash_store_free(
    axutil_hash_t *sct_hash_store,
    const axutil_env_t *env)
{
	axutil_hash_index_t *hi = NULL;

	for (hi = axutil_hash_first(sct_hash_store, env); hi != NULL; hi = axutil_hash_next(env, hi))
	{
		void *v = NULL;
        axutil_hash_this(hi, NULL, NULL, &v);
		if (v)
		{
			security_context_token_free((security_context_token_t*)v, env);        	
		}
	}

	axutil_hash_free(sct_hash_store, env);
}

static axutil_hash_t *
sct_provider_stored_key_get_sct_hash_store(
    const axutil_env_t *env, 
    axis2_msg_ctx_t* msg_ctx)
{
    axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_ctx_t *ctx = NULL;
    axutil_property_t *property = NULL;
    axutil_hash_t *hash_store = NULL;
    
    /* Get the conf ctx */
    conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);
    if(!conf_ctx)
    {
        AXIS2_LOG_ERROR(env->log,AXIS2_LOG_SI, 
            "[rampart]Config context is NULL. Cannot get security context token hash store.");
        return NULL;
    }

    ctx = axis2_conf_ctx_get_base(conf_ctx,env);
    if(!ctx)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[rampart]Axis2 context is NULL. Cannot get security context token hash store.");
        return NULL;
    }

    /* Get the hash store property */
    property = axis2_ctx_get_property(ctx, env, RAMPART_SCT_PROVIDER_HASH_PROB);
    if(property)
    {
        /* Get the store */
        hash_store = (axutil_hash_t*)axutil_property_get_value(property, env);
    }
    else
    {
        axutil_property_t *hash_store_prop = NULL;

        hash_store = axutil_hash_make(env);
        hash_store_prop = axutil_property_create_with_args(env, AXIS2_SCOPE_APPLICATION,
               AXIS2_TRUE, (void *)sct_provider_stored_key_sct_hash_store_free, hash_store);
        axis2_ctx_set_property(ctx, env, RAMPART_SCT_PROVIDER_HASH_PROB, hash_store_prop);
    }

    return hash_store;
}

AXIS2_EXTERN void* AXIS2_CALL
sct_provider_stored_key_obtain_token(
    const axutil_env_t *env, 
    axis2_bool_t is_encryption, 
    axis2_msg_ctx_t* msg_ctx, 
    axis2_char_t *sct_id, 
    int sct_id_type,
    void* user_params)
{
    axutil_hash_t *hash_store = NULL;
    security_context_token_t *sct = NULL;

    /* sct should be get from global pool */
    axutil_allocator_switch_to_global_pool(env->allocator);
    
    /* Get sct hash store */
    hash_store = sct_provider_stored_key_get_sct_hash_store(env, msg_ctx);
    if(!hash_store)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot find security context token storage.");
        return NULL;
    }

    /* get the sct if sct_id is given */
    if(sct_id)
    {
        /* set env */
        axutil_hash_set_env(hash_store, env);

        sct = (security_context_token_t *)axutil_hash_get(
            hash_store, sct_id, AXIS2_HASH_KEY_STRING);
    }

    if(!sct)
    {
        /* we can create an sct and send it */

        sct = security_context_token_create(env);
        if(sct)
        {
            oxs_buffer_t* key_buffer = NULL;
            axis2_bool_t free_sctid = AXIS2_FALSE;

            key_buffer = oxs_buffer_create(env);
            oxs_buffer_populate(
                key_buffer, env, (unsigned char*)"01234567012345670123456701234567", 32);
            security_context_token_set_secret(sct, env, key_buffer);
            if(!sct_id)
            {
                sct_id = oxs_util_generate_id(env,"urn:uuid:");
                free_sctid = AXIS2_TRUE;
            }
            security_context_token_set_global_identifier(sct, env, axutil_strdup(env, sct_id));
            security_context_token_set_local_identifier(
                sct, env, axutil_strdup(env, "#sctId-29530019"));
            security_context_token_set_is_sc10(sct, env, AXIS2_TRUE);
    
            if(free_sctid)
            {
                AXIS2_FREE(env->allocator, sct_id);
            }
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[rampart]Cannot create security context token. Insufficient memory.");
        }
    }
    axutil_allocator_switch_to_local_pool(env->allocator);
    
    return sct;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
sct_provider_stored_key_store_token(
    const axutil_env_t *env, 
    axis2_msg_ctx_t* msg_ctx, 
    axis2_char_t *sct_global_id, 
    axis2_char_t *sct_local_id, 
    void *sct, 
    void *user_params)
{
    axutil_hash_t *hash_store = NULL;
    axis2_status_t status = AXIS2_SUCCESS;

    /* if given sct is null, then we can't store it */
    if(!sct)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Security context token to be stored in not valid.");
        return AXIS2_FAILURE;
    }

    /* sct should be stored in global pool */
    axutil_allocator_switch_to_global_pool(env->allocator);
    
    /* Get sct hash store */
    hash_store = sct_provider_stored_key_get_sct_hash_store(env, msg_ctx);
    if(hash_store)
    {
        /* set env */
        axutil_hash_set_env(hash_store, env);

        /* store sct */
        if(sct_global_id)
        {
            axutil_hash_set(hash_store, sct_global_id, AXIS2_HASH_KEY_STRING, sct);
            if(sct_local_id)
            {
                security_context_token_increment_ref(sct, env);
                axutil_hash_set(hash_store, sct_local_id, AXIS2_HASH_KEY_STRING, sct);
            }
        }
        else
        {
            if(sct_local_id)
            {
                axutil_hash_set(hash_store, sct_local_id, AXIS2_HASH_KEY_STRING, sct);
            }
            else
            {
                /* if both local_id and global_id are NULL, then we can't store it */
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                    "[rampart]Security context token identifiers are not valid. "
                    "Cannot store security context token. ");
                status = AXIS2_FAILURE;
            }
        }
    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot find security context token storage.");
        status = AXIS2_FAILURE;
    }

    axutil_allocator_switch_to_local_pool(env->allocator);
    return status;

}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
sct_provider_stored_key_delete_token(
    const axutil_env_t *env, 
    axis2_msg_ctx_t* msg_ctx, 
    axis2_char_t *sct_id, 
    int sct_id_type,
    void* user_params)
{
    /* delete method is not implemented, because we are still not supporting sct cancel function */

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
sct_provider_stored_key_validate_token(
    const axutil_env_t *env, 
    axiom_node_t *sct_node, 
    axis2_msg_ctx_t *msg_ctx,
    void *user_params)
{
    /* default implementation does not need to validate anything. We haven't extended the 
     * functionality of sct */

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN void* AXIS2_CALL
sct_provider_stored_key_get_user_params(
    const axutil_env_t *env)
{
    return NULL;
}

/**
 * Following block distinguish the exposed part of the dll.
 */
AXIS2_EXPORT int
axis2_get_instance(
    rampart_sct_provider_t **inst,
    const axutil_env_t *env)
{
    rampart_sct_provider_t* sct_provider = NULL;

    sct_provider = AXIS2_MALLOC(env->allocator,
            sizeof(rampart_sct_provider_t));

    sct_provider->ops = AXIS2_MALLOC(
                env->allocator, sizeof(rampart_sct_provider_ops_t));

    /*assign function pointers*/

    sct_provider->ops->obtain_security_context_token = sct_provider_stored_key_obtain_token;
    sct_provider->ops->store_security_context_token = sct_provider_stored_key_store_token;
    sct_provider->ops->delete_security_context_token = sct_provider_stored_key_delete_token;
    sct_provider->ops->validate_security_context_token = sct_provider_stored_key_validate_token;
    sct_provider->ops->get_user_params = sct_provider_stored_key_get_user_params;
    sct_provider->ops->free = sct_provider_free;

    *inst = sct_provider;

    if (!(*inst))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot initialize the sct provider module");
        return AXIS2_FAILURE;
    }

    return AXIS2_SUCCESS;
}

AXIS2_EXPORT int
axis2_remove_instance(
    rampart_sct_provider_t *inst,
    const axutil_env_t *env)
{
    axis2_status_t status = AXIS2_FAILURE;
    if (inst)
    {
        status = RAMPART_SCT_PROVIDER_FREE(inst, env);
    }
    return status;
}
