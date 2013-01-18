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

#include <axutil_linked_list.h>
#include <rampart_replay_detector.h>
#include <axutil_property.h>
#include <rampart_constants.h>
#include <rampart_sec_processed_result.h>
#include <axis2_conf_ctx.h>

#define RAMPART_RD_LL_PROP "Rampart_RD_LL_Prop"

/** 
 * Get replay detector storage from msg_ctx. If it is not yet created, it will create a new one and
 * store it in conf_context.
 */
static axutil_linked_list_t *
rampart_replay_detector_get_linked_list(
    const axutil_env_t *env,
    axis2_msg_ctx_t* msg_ctx)
{
    axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_ctx_t *ctx = NULL;
    axutil_property_t *property = NULL;
    axutil_linked_list_t *ll = NULL;
    
    conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);
    if(!conf_ctx)
    {
        AXIS2_LOG_ERROR(env->log,AXIS2_LOG_SI, 
            "[rampart]Conf context is not valid. Could not get replay detector store.");
        return NULL;
    }
    ctx = axis2_conf_ctx_get_base(conf_ctx,env);
    if(!ctx)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[rampart]Axis2 context is not valid. Could not get replay detector store.");
        return NULL;
    }

    /* Get the Linked list property */
    property = axis2_ctx_get_property(ctx, env, RAMPART_RD_LL_PROP);
    if(property)
    {
        ll = (axutil_linked_list_t*)axutil_property_get_value(property, env);
        return ll;
    }
    else
    {
        /* not found. Can create new */
        ll = axutil_linked_list_create(env);
        property = axutil_property_create(env);
        axutil_property_set_value(property, env, ll);
        axis2_ctx_set_property(ctx, env, RAMPART_RD_LL_PROP, property);
        return ll;
    }
}

/**
 * Checks whether given id is available in the linked list
 */
static axis2_bool_t
rampart_replay_detector_linked_list_contains(
    axutil_linked_list_t *linked_list,
    const axutil_env_t *env,
    const axis2_char_t *id)
{
    int count = 0;
    int i = 0;

    count = axutil_linked_list_size(linked_list, env);
    for(i=0; i<count; i++)
    {
        axis2_char_t *tmp_id = NULL;
        tmp_id = (axis2_char_t*)axutil_linked_list_get(linked_list, env, i);
        if(!axutil_strcmp(id, tmp_id))
        {
            return AXIS2_TRUE;
        }
    }
    return AXIS2_FALSE;
}

/**
 * A linked list based implementation for replay detection.
 * This doesnt require addressing headers to be present. If the user doesn't give any replay
 * detection function, then this will be used.
 * @param env pointer to environment struct,Must not be NULL.
 * @param msg_ctx message context structure
 * @param rampart_context rampart context structure
 * @param user_params parameters given by user. (Not used in this method)
 * @returns status of the op. AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_replay_detector_default(
    const axutil_env_t *env,
    axis2_msg_ctx_t* msg_ctx,
    rampart_context_t *rampart_context,
    void *user_params)
{
    axutil_linked_list_t *ll = NULL;
    const axis2_char_t *msg_id = NULL;
    const axis2_char_t *ts = NULL;
    const axis2_char_t *addr_msg_id = NULL;
    int max_rcds = RAMPART_RD_DEF_MAX_RCDS;
    axis2_status_t status = AXIS2_FAILURE;
	
    /* since replay details have to be stored until the application finished, 
     * they have to be created in golbal pool. If those are created in msg's pool, 
     * then it will be deleted after the request is served. (specially when using 
     * with apache, current_pool will denote the message's pool) */
    axutil_allocator_switch_to_global_pool(env->allocator);

    /* By using just Timestamps we dont need addressing. But there is a chance that
     * two messages might generated exactly at the same time */

    /* get the timestamp from security processed results */
    ts = rampart_get_security_processed_result(env, msg_ctx, RAMPART_SPR_TS_CREATED);
    addr_msg_id = axis2_msg_ctx_get_wsa_message_id(msg_ctx, env);

    if(!ts && addr_msg_id)
    {
        msg_id = addr_msg_id;
    }
    else if(ts && !addr_msg_id)
    {
        msg_id = ts;
    }
    else if(ts && addr_msg_id)
    {
        msg_id = axutil_stracat(env, addr_msg_id, ts);
    }
    else
    {
        msg_id = NULL;
    }

    if(!msg_id)
    {
        msg_id = "RAMPART-DEFAULT-TS";
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
            "[rampart]NO msg_id specified, using default = %s", msg_id);
    }

    ll = rampart_replay_detector_get_linked_list(env, msg_ctx);
    if(!ll)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot get the linked list storage for replay detection from msg_ctx");
		axutil_allocator_switch_to_local_pool(env->allocator);
        return AXIS2_FAILURE;
    }
    else
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
            "[rampart][rrd] Number of records =%d", axutil_linked_list_size(ll, env));
        
        /* Get the number of records to be stored */
        if(rampart_context_get_rd_val(rampart_context, env))
        {
            max_rcds = axutil_atoi(rampart_context_get_rd_val(rampart_context, env));
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                "[rampart]Using the specified max_rcds  %d\n", max_rcds );
        }
        else
        {
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                "[rampart]Using the default max_rcds  %d\n", max_rcds );
        }

        /* If the table already have the same key it's a replay */
        if(rampart_replay_detector_linked_list_contains(ll, env, msg_id))
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"[rampart]For ID=%s, a replay detected", msg_id);
			axutil_allocator_switch_to_local_pool(env->allocator);
            return AXIS2_FAILURE;
        }

        /* If the number of records are more than allowed, delete old records */
        while(axutil_linked_list_size(ll, env) > max_rcds)
        {
            axis2_char_t *tmp_msg_id = NULL;
            tmp_msg_id = (axis2_char_t*)axutil_linked_list_remove_first(ll, env);
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart]Deleting record  %s\n", tmp_msg_id );
            AXIS2_FREE(env->allocator, tmp_msg_id);
            tmp_msg_id = NULL;
        }

        /* Add current record */
        status = axutil_linked_list_add(ll, env, (void*)axutil_strdup(env,msg_id));
		axutil_allocator_switch_to_local_pool(env->allocator);
        if(AXIS2_SUCCESS == status)
        {
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart]Adding record  %s\n", msg_id );
            return AXIS2_SUCCESS;
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Cannot add record %s\n", msg_id);
            return AXIS2_FAILURE;
        }
    }
}
