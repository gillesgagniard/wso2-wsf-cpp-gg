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
 
#include <sandesha2_msg_retrans_adjuster.h>
#include <sandesha2_utils.h>
#include <sandesha2_constants.h>
#include <sandesha2_spec_specific_consts.h>
#include <sandesha2_msg_init.h>
#include <axutil_property.h>
#include <sandesha2_terminate_mgr.h>
#include <sandesha2_seq_mgr.h>
#include <sandesha2_seq_property_mgr.h>
#include <sandesha2_create_seq_mgr.h>
#include <sandesha2_sender_mgr.h>

sandesha2_sender_bean_t * AXIS2_CALL
sandesha2_msg_retrans_adjuster_adjust_next_retrans_time(
    const axutil_env_t *env, 
    sandesha2_sender_bean_t *sender_bean, 
    sandesha2_property_bean_t *property_bean);

long AXIS2_CALL
sandesha2_msg_retrans_adjuster_next_exp_backoff_diff(
    const axutil_env_t *env,
    int count,
    long initial_interval);
                        
static axis2_status_t AXIS2_CALL
sandesha2_msg_retrans_adjuster_finalize_timedout_seq(
    const axutil_env_t *env,
    axis2_char_t *internal_sequence_id,
    axis2_conf_ctx_t *conf_ctx,
    sandesha2_storage_mgr_t *storage_mgr,
    sandesha2_seq_property_mgr_t *seq_prop_mgr,
    sandesha2_create_seq_mgr_t *create_seq_mgr,
    sandesha2_sender_mgr_t *sender_mgr);

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
sandesha2_msg_retrans_adjuster_adjust_retrans(
    const axutil_env_t *env,
    sandesha2_sender_bean_t *sender_bean,
    axis2_conf_ctx_t *conf_ctx, 
    sandesha2_storage_mgr_t *storage_mgr,
    sandesha2_seq_property_mgr_t *seq_prop_mgr,
    sandesha2_create_seq_mgr_t *create_seq_mgr,
    sandesha2_sender_mgr_t *sender_mgr,
    axis2_svc_t *svc)
{
    axis2_char_t *stored_key = NULL;
    axis2_char_t *internal_sequence_id = NULL;
    sandesha2_property_bean_t *property_bean = NULL;
    int max_attempts = -1;
    int sent_count = -1;
    axis2_bool_t timeout_seq = AXIS2_FALSE;
    axis2_bool_t seq_timed_out = AXIS2_FALSE;
    axis2_bool_t continue_sending = AXIS2_TRUE;
    
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[sandesha2]Entry:sandesha2_msg_retrans_adjuster_adjust_retrans");
    AXIS2_PARAM_CHECK(env->error, sender_bean, AXIS2_FALSE);
    AXIS2_PARAM_CHECK(env->error, conf_ctx, AXIS2_FALSE);
    AXIS2_PARAM_CHECK(env->error, storage_mgr, AXIS2_FALSE);
    AXIS2_PARAM_CHECK(env->error, seq_prop_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, create_seq_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, sender_mgr, AXIS2_FAILURE);
    
    stored_key = sandesha2_sender_bean_get_msg_ctx_ref_key(sender_bean, env);
    if(!stored_key)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[sandesha2] Stored Key not present in the retransmittable message");
        return AXIS2_FALSE;
    }

    internal_sequence_id = sandesha2_sender_bean_get_internal_seq_id(sender_bean, env);
  
    property_bean = sandesha2_utils_get_property_bean(env, svc);
    if(property_bean)
    {
        max_attempts = sandesha2_property_bean_get_max_retrans_count(property_bean, env);
    }

    sent_count = sandesha2_sender_bean_get_sent_count(sender_bean, env) + 1;
    sandesha2_sender_bean_set_sent_count(sender_bean, env, sent_count);

    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "max_attempts:%d", max_attempts);
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "sent_count:%d", sent_count);
    if(max_attempts > 0 &&  sent_count > max_attempts)
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
            "[sandesha2] Sent count %d > %d specified in module.xml for sequence with internal "\
            "sequence id %s", sent_count, max_attempts, internal_sequence_id);

        timeout_seq = AXIS2_TRUE;
    }

    seq_timed_out = sandesha2_seq_mgr_has_seq_timedout(env, internal_sequence_id, seq_prop_mgr, 
            /*conf_ctx*/svc);
    
    if(seq_timed_out)
    {
        timeout_seq = AXIS2_TRUE;
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
            "[sandesha2]Sequence with internal_sequence_id %s timed out", internal_sequence_id);
    }
        
    if(timeout_seq)
    {
        sandesha2_sender_bean_set_send(sender_bean, env, AXIS2_FALSE);
        sandesha2_msg_retrans_adjuster_finalize_timedout_seq(env, internal_sequence_id, 
            conf_ctx, storage_mgr, seq_prop_mgr, create_seq_mgr, sender_mgr);
        continue_sending = AXIS2_FALSE;
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[sandesha2] Exit:sandesha2_msg_retrans_adjuster_adjust_retrans");

    return continue_sending;
}

sandesha2_sender_bean_t * AXIS2_CALL
sandesha2_msg_retrans_adjuster_adjust_next_retrans_time(
    const axutil_env_t *env, 
    sandesha2_sender_bean_t *sender_bean, 
    sandesha2_property_bean_t *property_bean)
{
    int count = -1;
    long base_interval = -1;
    long new_interval = -1;
    long new_time_to_send = 0;
    long time_now = -1;
   
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[sandesha2] Entry:sandesha2_msg_retrans_adjuster_adjust_next_retrans_time");

    AXIS2_PARAM_CHECK(env->error, sender_bean, NULL);
    AXIS2_PARAM_CHECK(env->error, property_bean, NULL);
    
    count = sandesha2_sender_bean_get_sent_count(sender_bean, env);
    base_interval = sandesha2_property_bean_get_retrans_interval(property_bean, env);
    new_interval = base_interval;
    if(sandesha2_property_bean_is_exp_backoff(property_bean, env))
    {
        new_interval = sandesha2_msg_retrans_adjuster_next_exp_backoff_diff(env, count, 
                base_interval);
    }

    time_now = sandesha2_utils_get_current_time_in_millis(env);
    
    new_time_to_send = time_now + new_interval;
    sandesha2_sender_bean_set_time_to_send(sender_bean, env, new_time_to_send);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[sandesha2] Exit:sandesha2_msg_retrans_adjuster_adjust_next_retrans_time");

    return sender_bean;
}



long AXIS2_CALL
sandesha2_msg_retrans_adjuster_next_exp_backoff_diff(
    const axutil_env_t *env,
    int count,
    long initial_interval)
{
    long interval = initial_interval;
    
    interval = initial_interval * (2^count);
    return interval;
}

static axis2_status_t AXIS2_CALL
sandesha2_msg_retrans_adjuster_finalize_timedout_seq(
    const axutil_env_t *env,
    axis2_char_t *internal_sequence_id,
    axis2_conf_ctx_t *conf_ctx,
    sandesha2_storage_mgr_t *storage_mgr,
    sandesha2_seq_property_mgr_t *seq_prop_mgr,
    sandesha2_create_seq_mgr_t *create_seq_mgr,
    sandesha2_sender_mgr_t *sender_mgr)
{
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[sandesha2] Entry:sandesha2_msg_retrans_adjuster_finalize_timedout_seq");

    AXIS2_PARAM_CHECK(env->error, internal_sequence_id, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, conf_ctx, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, storage_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, seq_prop_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, create_seq_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, sender_mgr, AXIS2_FAILURE);
    
    sandesha2_terminate_mgr_time_out_sending_side_seq(env, conf_ctx, internal_sequence_id,
        AXIS2_FALSE, storage_mgr, seq_prop_mgr, create_seq_mgr, sender_mgr);
 
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[sandesha2]Exit:sandesha2_msg_retrans_adjuster_finalize_timedout_seq");
    return AXIS2_SUCCESS;
}

