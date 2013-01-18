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
 
#include <sandesha2_utils.h>
#include <sandesha2_terminate_mgr.h>
#include <sandesha2_terminate_seq.h>
#include <sandesha2_constants.h>
#include <sandesha2_property_bean.h>
#include <sandesha2_seq_property_bean.h>
#include <sandesha2_ack_range.h>
#include <sandesha2_spec_specific_consts.h>
#include <sandesha2_invoker_mgr.h>
#include <sandesha2_next_msg_mgr.h>
#include <sandesha2_seq_property_mgr.h>
#include <sandesha2_create_seq_mgr.h>
#include <sandesha2_sender_mgr.h>
#include <sandesha2_sender_bean.h>
#include <sandesha2_msg_init.h>
#include <axutil_string.h>
#include <axutil_uuid_gen.h>
#include <axis2_addr.h>
#include <axutil_property.h>
#include <axutil_array_list.h>
#include <axis2_engine.h>
#include <sandesha2_msg_creator.h>
#include <sandesha2_ack_mgr.h>
#include <sandesha2_msg_retrans_adjuster.h>
#include <axis2_transport_out_desc.h>
#include <axiom_soap_const.h>
#include <axis2_http_transport_utils.h>
#include <axis2_core_utils.h>

axutil_hash_t *sandesha2_terminate_mgr_rcv_side_clean_map = NULL;

static axis2_status_t
sandesha2_terminate_mgr_clean_sending_side_data(
    const axutil_env_t *env,
    axis2_conf_ctx_t *conf_ctx,
    axis2_char_t *internal_sequence_id,
    axis2_bool_t svr_side,
    sandesha2_storage_mgr_t *storage_mgr,
    sandesha2_seq_property_mgr_t *seq_prop_mgr,
    sandesha2_create_seq_mgr_t *create_seq_mgr,
    sandesha2_sender_mgr_t *sender_mgr);
                        
static axis2_status_t
sandesha2_terminate_mgr_complete_termination_of_recv_side(
    const axutil_env_t *env,
    axis2_conf_ctx_t *conf_ctx,
    axis2_char_t *seq_id,
    sandesha2_storage_mgr_t *storage_mgr,
    sandesha2_seq_property_mgr_t *seq_prop_mgr,
    sandesha2_next_msg_mgr_t *next_msg_mgr);
                        
static axis2_status_t
sandesha2_terminate_mgr_remove_recv_side_properties(
    const axutil_env_t *env,
    axis2_conf_ctx_t *conf_ctx,
    axis2_char_t *seq_id,
    sandesha2_storage_mgr_t *storage_mgr,
    sandesha2_seq_property_mgr_t *seq_prop_mgr);

static axis2_bool_t
sandesha2_terminate_mgr_is_property_deletable(
    const axutil_env_t *env,
    axis2_char_t *name);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
sandesha2_terminate_mgr_clean_recv_side_after_terminate_msg(
    const axutil_env_t *env,
    axis2_conf_ctx_t *conf_ctx,
    axis2_char_t *seq_id,
    sandesha2_storage_mgr_t *storage_mgr,
    sandesha2_seq_property_mgr_t *seq_prop_mgr,
    sandesha2_next_msg_mgr_t *next_msg_mgr)
{
    /*axis2_bool_t in_order_invoke = AXIS2_FALSE;
    sandesha2_property_bean_t *prop_bean = NULL;*/
    
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI,
        "[sandesha2]Entry:sandesha2_terminate_mgr_clean_recv_side_after_terminate_msg");
    AXIS2_PARAM_CHECK(env->error, conf_ctx, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, seq_id, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, storage_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, next_msg_mgr, AXIS2_FAILURE);
   
    /*if(!sandesha2_terminate_mgr_rcv_side_clean_map)
    {
        axutil_allocator_switch_to_global_pool(env->allocator);
        sandesha2_terminate_mgr_rcv_side_clean_map = axutil_hash_make(env);
        axutil_allocator_switch_to_local_pool(env->allocator);
    }*/
    
    /*prop_bean = sandesha2_utils_get_property_bean(env, axis2_conf_ctx_get_conf(
        conf_ctx, env));
    in_order_invoke = sandesha2_property_bean_is_in_order(prop_bean, env);
    if(!in_order_invoke)*/
    {
        /*axutil_allocator_switch_to_global_pool(env->allocator);
        axutil_hash_set(sandesha2_terminate_mgr_rcv_side_clean_map, seq_id,
            AXIS2_HASH_KEY_STRING, axutil_strdup(env, SANDESHA2_CLEANED_ON_TERMINATE_MSG));
        axutil_allocator_switch_to_local_pool(env->allocator);*/
        sandesha2_terminate_mgr_clean_recv_side_after_invocation(env, conf_ctx,
            seq_id, storage_mgr, seq_prop_mgr, next_msg_mgr);
    }
    /*else
    {	axis2_char_t *clean_status = NULL;
        axutil_allocator_switch_to_global_pool(env->allocator);
        clean_status = axutil_hash_get(
            sandesha2_terminate_mgr_rcv_side_clean_map, seq_id, 
            AXIS2_HASH_KEY_STRING);
        axutil_allocator_switch_to_local_pool(env->allocator);
        if(clean_status && 0 == axutil_strcmp(clean_status, 
            SANDESHA2_CLEANED_AFTER_INVOCATION))
        {
            sandesha2_terminate_mgr_complete_termination_of_recv_side(env, conf_ctx, seq_id,
                storage_mgr);
        }
        else
        {
            axutil_allocator_switch_to_global_pool(env->allocator);
            axutil_hash_set(sandesha2_terminate_mgr_rcv_side_clean_map, seq_id,
                AXIS2_HASH_KEY_STRING, axutil_strdup(env, 
                SANDESHA2_CLEANED_ON_TERMINATE_MSG));
            axutil_allocator_switch_to_local_pool(env->allocator);
        }
    }*/
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[sandesha2]Exit:sandesha2_terminate_mgr_clean_recv_side_after_terminate_msg");
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
sandesha2_terminate_mgr_clean_recv_side_after_invocation(
    const axutil_env_t *env,
    axis2_conf_ctx_t *conf_ctx,
    axis2_char_t *seq_id,
    sandesha2_storage_mgr_t *storage_mgr,
    sandesha2_seq_property_mgr_t *seq_prop_mgr,
    sandesha2_next_msg_mgr_t *next_msg_mgr)
{
    /*sandesha2_invoker_mgr_t *invoker_mgr = NULL;
    sandesha2_invoker_bean_t *find_bean = NULL;
    axutil_array_list_t *found_list = NULL;
    int i = 0;
    axis2_char_t *clean_status = NULL;*/
    
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI,
        "[sandesha2]Entry:sandesha2_terminate_mgr_clean_recv_side_after_invocation");
    AXIS2_PARAM_CHECK(env->error, conf_ctx, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, seq_id, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, storage_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, next_msg_mgr, AXIS2_FAILURE);
    
    /*if(!sandesha2_terminate_mgr_rcv_side_clean_map)
    {
        axutil_allocator_switch_to_global_pool(env->allocator);
        sandesha2_terminate_mgr_rcv_side_clean_map = axutil_hash_make(env);
        axutil_allocator_switch_to_local_pool(env->allocator);
    }*/
    
    /*invoker_mgr = sandesha2_storage_mgr_get_storage_map_mgr(storage_mgr, env);
    find_bean = sandesha2_invoker_bean_create(env);
    
    sandesha2_invoker_bean_set_seq_id(find_bean, env, seq_id);
    sandesha2_invoker_bean_set_invoked(find_bean, env, AXIS2_TRUE);
    
    found_list = sandesha2_invoker_mgr_find(invoker_mgr, env, find_bean);
    for(i = 0; i < axutil_array_list_size(found_list, env); i++)
    {
        sandesha2_invoker_bean_t *map_bean = NULL;
        axis2_char_t *msg_store_key = NULL;
        
        map_bean = axutil_array_list_get(found_list, env, i);
        msg_store_key = sandesha2_invoker_bean_get_msg_ctx_ref_key(
            map_bean, env);
        sandesha2_storage_mgr_remove_msg_ctx(storage_mgr, env, msg_store_key);
        sandesha2_invoker_mgr_remove(invoker_mgr, env, 
            sandesha2_invoker_bean_get_msg_ctx_ref_key(map_bean, env));
    }*/
    /*axutil_allocator_switch_to_global_pool(env->allocator);
    clean_status = axutil_hash_get(sandesha2_terminate_mgr_rcv_side_clean_map,
        seq_id, AXIS2_HASH_KEY_STRING);
    axutil_allocator_switch_to_local_pool(env->allocator);*/
                    
    /*if(clean_status && 0 == axutil_strcmp(clean_status, 
        SANDESHA2_CLEANED_ON_TERMINATE_MSG))
    {*/
        sandesha2_terminate_mgr_complete_termination_of_recv_side(env, conf_ctx, seq_id,
            storage_mgr, seq_prop_mgr, next_msg_mgr);
    /*}
    else
    {
        axutil_allocator_switch_to_global_pool(env->allocator);
        axutil_hash_set(sandesha2_terminate_mgr_rcv_side_clean_map, seq_id,
            AXIS2_HASH_KEY_STRING, axutil_strdup(env, 
                SANDESHA2_CLEANED_AFTER_INVOCATION));
        axutil_allocator_switch_to_local_pool(env->allocator);
    }*/

    
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[sandesha2]Exit:sandesha2_terminate_mgr_clean_recv_side_after_invocation");
    return AXIS2_SUCCESS;
}
                        
static axis2_status_t
sandesha2_terminate_mgr_complete_termination_of_recv_side(
    const axutil_env_t *env,
    axis2_conf_ctx_t *conf_ctx,
    axis2_char_t *seq_id,
    sandesha2_storage_mgr_t *storage_mgr,
    sandesha2_seq_property_mgr_t *seq_prop_mgr,
    sandesha2_next_msg_mgr_t *next_msg_mgr)
{
    sandesha2_next_msg_bean_t *find_bean = NULL;
    axutil_array_list_t *found_list = NULL;
    axis2_char_t *highest_in_msg_key = NULL;
    int i = 0, size = 0;
    
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI,
        "[sandesha2]Entry:sandesha2_terminate_mgr_complete_termination_of_recv_side");
    AXIS2_PARAM_CHECK(env->error, conf_ctx, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, seq_id, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, storage_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, seq_prop_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, next_msg_mgr, AXIS2_FAILURE);
    
    find_bean = sandesha2_next_msg_bean_create(env);
    if(find_bean)
    {
        sandesha2_next_msg_bean_set_seq_id(find_bean, env, seq_id);
    
        found_list = sandesha2_next_msg_mgr_find(next_msg_mgr, env, find_bean);
        sandesha2_next_msg_bean_free(find_bean, env);
    }

    if(found_list)
    {
        size = axutil_array_list_size(found_list, env);

        for(i = 0; i < size; i++)
        {
            sandesha2_next_msg_bean_t *bean = axutil_array_list_get(found_list, env, i);
            if(bean)
            {
                axis2_char_t *key = NULL;
                axis2_char_t *temp_seq_id = NULL;

                key = sandesha2_next_msg_bean_get_ref_msg_key(bean, env);
                if(key)
                {
                    sandesha2_storage_mgr_remove_msg_ctx(storage_mgr, env, key, conf_ctx, -1);
                }

                temp_seq_id = sandesha2_next_msg_bean_get_seq_id(bean, env);
                if(temp_seq_id)
                {
                    sandesha2_next_msg_mgr_remove(next_msg_mgr, env, temp_seq_id);
                }

                sandesha2_next_msg_bean_free(bean, env);
            }
        }

        axutil_array_list_free(found_list, env);
    }

    highest_in_msg_key = sandesha2_utils_get_seq_property(env, seq_id,
        SANDESHA2_SEQ_PROP_HIGHEST_IN_MSG_KEY, seq_prop_mgr);
    if(highest_in_msg_key)
    {
        sandesha2_storage_mgr_remove_msg_ctx(storage_mgr, env, highest_in_msg_key, conf_ctx, -1);
        if(highest_in_msg_key)
        {
            AXIS2_FREE(env->allocator, highest_in_msg_key);
        }
    }

    sandesha2_terminate_mgr_remove_recv_side_properties(env, conf_ctx, seq_id, storage_mgr, 
            seq_prop_mgr);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[sandesha2]Exit:sandesha2_terminate_mgr_complete_termination_of_recv_side");
    return AXIS2_SUCCESS;
}
                        
static axis2_status_t
sandesha2_terminate_mgr_remove_recv_side_properties(
    const axutil_env_t *env,
    axis2_conf_ctx_t *conf_ctx,
    axis2_char_t *seq_id,
    sandesha2_storage_mgr_t *storage_mgr,
    sandesha2_seq_property_mgr_t *seq_prop_mgr)
{
    sandesha2_seq_property_bean_t *all_seq_bean = NULL;
    axutil_array_list_t *found_list = NULL;
    sandesha2_seq_property_bean_t *find_seq_prop_bean = NULL;
    
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI,
        "[sandesha2]Entry:sandesha2_terminate_mgr_remove_recv_side_properties");
    AXIS2_PARAM_CHECK(env->error, conf_ctx, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, seq_id, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, storage_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, seq_prop_mgr, AXIS2_FAILURE);
    
    all_seq_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env, 
        SANDESHA2_SEQ_PROP_ALL_SEQS, SANDESHA2_SEQ_PROP_INCOMING_SEQ_LIST);

    if(all_seq_bean)
    {
        axutil_array_list_t *all_seq_list = NULL;
        axis2_char_t *all_seq_str = NULL;
        
        all_seq_list = sandesha2_utils_get_array_list_from_string(env, 
            sandesha2_seq_property_bean_get_value(all_seq_bean, env));
        if(all_seq_list)
        {
            int i = 0, j = 0, size = 0;

            size = axutil_array_list_size(all_seq_list, env);

            for(i = 0; i < size; i++)
            {
                axis2_char_t *value = axutil_array_list_get(all_seq_list, env, i);
                
                if(value)
                {
                    if(!axutil_strcmp(value, seq_id))
                    {
                        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                            "[sandesha2] Removing seq id:%s from the all incoming sequence list", 
                            value);

                        axutil_array_list_remove(all_seq_list, env, i);
                        AXIS2_FREE(env->allocator, value);
                        break;
                    }

                    AXIS2_FREE(env->allocator, value);
                }
            }

            for(j = i++; j < size; j++)
            {
                axis2_char_t *value = axutil_array_list_get(all_seq_list, env, i);
                if(value)
                {
                    AXIS2_FREE(env->allocator, value);
                }
            }

            all_seq_str = sandesha2_utils_array_list_to_string(env, all_seq_list,
                SANDESHA2_ARRAY_LIST_STRING);

            sandesha2_seq_property_bean_set_value(all_seq_bean, env, all_seq_str);
            if(all_seq_str)
            {
                AXIS2_FREE(env->allocator, all_seq_str);
            }

            sandesha2_seq_property_mgr_update(seq_prop_mgr, env, all_seq_bean);
            axutil_array_list_free(all_seq_list, env);
        }

        sandesha2_seq_property_bean_free(all_seq_bean, env);
    }

    find_seq_prop_bean = sandesha2_seq_property_bean_create(env);
    if(find_seq_prop_bean)
    {
        sandesha2_seq_property_bean_set_seq_id(find_seq_prop_bean, env, seq_id);
        found_list = sandesha2_seq_property_mgr_find(seq_prop_mgr, env, find_seq_prop_bean);
        sandesha2_seq_property_bean_free(find_seq_prop_bean, env);
    }

    if(found_list)
    {
        int i = 0, size = 0;
        size = axutil_array_list_size(found_list, env);
        for(i = 0; i < size; i++)
        {
            sandesha2_seq_property_bean_t *seq_prop_bean = NULL;
            
            seq_prop_bean = axutil_array_list_get(found_list, env, i);
            /*sandesha2_terminate_mgr_do_updates_if_needed(env, out_seq_id,
                seq_prop_bean, seq_prop_mgr);*/
            if(sandesha2_terminate_mgr_is_property_deletable(env,
                sandesha2_seq_property_bean_get_name(seq_prop_bean, env)))
            {
                axis2_char_t *highest_in_msg_key_str = NULL;
                axis2_char_t *temp_seq_id = sandesha2_seq_property_bean_get_seq_id(seq_prop_bean, env);
                axis2_char_t *name = sandesha2_seq_property_bean_get_name(seq_prop_bean, env);

                if(!axutil_strcmp(name, SANDESHA2_SEQ_PROP_HIGHEST_IN_MSG_NUMBER))
                {
                    highest_in_msg_key_str = 
                        sandesha2_seq_property_bean_get_value(seq_prop_bean, env);
                    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                        "[sandesha2] Removing the message context for the highest in message number");
                    sandesha2_storage_mgr_remove_msg_ctx(storage_mgr, env, 
                        highest_in_msg_key_str, conf_ctx, -1);
                }

                AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                        "[sandesha2] Removing the sequence property named %s in the sequence %s", 
                        name, temp_seq_id);

                sandesha2_seq_property_mgr_remove(seq_prop_mgr, env, temp_seq_id, name);
            }
            
            sandesha2_seq_property_bean_free(seq_prop_bean, env);
        }

        axutil_array_list_free(found_list, env);
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[sandesha2]Exit:sandesha2_terminate_mgr_remove_recv_side_properties");

    return AXIS2_SUCCESS;
}
                        
AXIS2_EXTERN axis2_status_t AXIS2_CALL
sandesha2_terminate_mgr_terminate_sending_side(
    const axutil_env_t *env,
    axis2_conf_ctx_t *conf_ctx,
    axis2_char_t *internal_sequence_id,
    axis2_bool_t svr_side,
    sandesha2_storage_mgr_t *storage_mgr,
    sandesha2_seq_property_mgr_t *seq_prop_mgr,
    sandesha2_create_seq_mgr_t *create_seq_mgr,
    sandesha2_sender_mgr_t *sender_mgr)
{
    sandesha2_seq_property_bean_t *seq_term_bean = NULL;
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI,
        "[sandesha2]Entry:sandesha2_terminate_mgr_terminate_sending_side");
    AXIS2_PARAM_CHECK(env->error, conf_ctx, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, internal_sequence_id, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, storage_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, seq_prop_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, create_seq_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, sender_mgr, AXIS2_FAILURE);
    
    seq_term_bean = sandesha2_seq_property_bean_create_with_data(env, 
        internal_sequence_id, SANDESHA2_SEQ_PROP_SEQ_TERMINATED, AXIS2_VALUE_TRUE);

    if(seq_term_bean)
    {
        sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, seq_term_bean);
        sandesha2_seq_property_bean_free(seq_term_bean, env);
    }
    
    sandesha2_terminate_mgr_clean_sending_side_data(env, conf_ctx, internal_sequence_id, 
        svr_side, storage_mgr, seq_prop_mgr, create_seq_mgr, sender_mgr);
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[sandesha2]Exit:sandesha2_terminate_mgr_terminate_sending_side");
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
sandesha2_terminate_mgr_do_updates_if_needed(
    const axutil_env_t *env,
    axis2_char_t *rms_sequence_id,
    sandesha2_seq_property_bean_t *prop_bean,
    sandesha2_seq_property_mgr_t *seq_prop_mgr)
{
    axis2_bool_t add_entry_with_seq_id = AXIS2_FALSE;
    axis2_char_t *name = NULL;
    
    AXIS2_PARAM_CHECK(env->error, prop_bean, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, rms_sequence_id, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, seq_prop_mgr, AXIS2_FAILURE);
    
    name = sandesha2_seq_property_bean_get_name(prop_bean, env);
    if(NULL == name)
    {
        return AXIS2_FAILURE;
    }
    
    if(!axutil_strcmp(name, SANDESHA2_SEQ_PROP_CLIENT_COMPLETED_MESSAGES))
    {
        add_entry_with_seq_id = AXIS2_TRUE;
    }
    if(!axutil_strcmp(name, SANDESHA2_SEQ_PROP_SEQ_TERMINATED))
    {
        add_entry_with_seq_id = AXIS2_TRUE;
    }
    if(!axutil_strcmp(name, SANDESHA2_SEQ_PROP_SEQ_CLOSED))
    {
        add_entry_with_seq_id = AXIS2_TRUE;
    }
    if(!axutil_strcmp(name, SANDESHA2_SEQ_PROP_SEQ_TIMED_OUT))
    {
        add_entry_with_seq_id = AXIS2_TRUE;
    }
        
    if(add_entry_with_seq_id && rms_sequence_id)
    {
        sandesha2_seq_property_bean_t *new_bean = NULL;

        new_bean = sandesha2_seq_property_bean_create(env);
        sandesha2_seq_property_bean_set_seq_id(new_bean, env, rms_sequence_id);
        sandesha2_seq_property_bean_set_name(new_bean, env, name);
        sandesha2_seq_property_bean_set_value(new_bean, env, 
                        sandesha2_seq_property_bean_get_value(prop_bean, env));
        sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, new_bean);
        sandesha2_seq_property_mgr_remove(seq_prop_mgr, env, 
                    sandesha2_seq_property_bean_get_seq_id(prop_bean, env), name);
        if(new_bean)
        {
            sandesha2_seq_property_bean_free(new_bean, env);
        }
    }

    return AXIS2_SUCCESS;
}


static axis2_bool_t
sandesha2_terminate_mgr_is_property_deletable(
    const axutil_env_t *env,
    axis2_char_t *name)
{
    axis2_bool_t deletable = AXIS2_TRUE;
        
    if(0 == axutil_strcasecmp(name, SANDESHA2_SEQ_PROP_TERMINATE_ADDED))
    {
        deletable = AXIS2_FALSE;
    }

    if(0 == axutil_strcasecmp(name, SANDESHA2_SEQ_PROP_NO_OF_OUTGOING_MSGS_ACKED))
    {
        deletable = AXIS2_FALSE;
    }

    if(0 == axutil_strcasecmp(name, SANDESHA2_SEQUENCE_PROPERTY_OUTGOING_INTERNAL_SEQUENCE_ID))
    {
        deletable = AXIS2_FALSE;
    }

    if(0 == axutil_strcasecmp(name, SANDESHA2_SEQ_PROP_SEQ_TERMINATED))
    {
        deletable = AXIS2_FALSE;
    }

    if(0 == axutil_strcasecmp(name, SANDESHA2_SEQ_PROP_SEQ_CLOSED))
    {
        deletable = AXIS2_FALSE;
    }

    if(0 == axutil_strcasecmp(name, SANDESHA2_SEQ_PROP_SEQ_TIMED_OUT))
    {
        deletable = AXIS2_FALSE;
    }

    return deletable;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
sandesha2_terminate_mgr_time_out_sending_side_seq(
    const axutil_env_t *env,
    axis2_conf_ctx_t *conf_ctx,
    axis2_char_t *internal_sequence_id,
    axis2_bool_t svr_side,
    sandesha2_storage_mgr_t *storage_mgr,
    sandesha2_seq_property_mgr_t *seq_prop_mgr,
    sandesha2_create_seq_mgr_t *create_seq_mgr,
    sandesha2_sender_mgr_t *sender_mgr)
{
    sandesha2_seq_property_bean_t *seq_term_bean = NULL;
    
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[sandesha2] Entry:sandesha2_terminate_mgr_time_out_sending_side_seq");

    AXIS2_PARAM_CHECK(env->error, conf_ctx, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, internal_sequence_id, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, storage_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, seq_prop_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, create_seq_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, sender_mgr, AXIS2_FAILURE);
    
    seq_term_bean = sandesha2_seq_property_bean_create_with_data(env, internal_sequence_id,
        SANDESHA2_SEQ_PROP_SEQ_TIMED_OUT, AXIS2_VALUE_TRUE);
    
    sandesha2_terminate_mgr_clean_sending_side_data(env, conf_ctx, internal_sequence_id, svr_side, 
            storage_mgr, seq_prop_mgr, create_seq_mgr, sender_mgr);

    sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, seq_term_bean);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[sandesha2] Exit:sandesha2_terminate_mgr_time_out_sending_side_seq");

    return AXIS2_SUCCESS;
}

/* Clean all sending side data stored in the database. This includes all sequence properties,
 * all create sequence beans and all sender beans set using internal sequence id.
 */
static axis2_status_t
sandesha2_terminate_mgr_clean_sending_side_data(
    const axutil_env_t *env,
    axis2_conf_ctx_t *conf_ctx,
    axis2_char_t *internal_sequence_id,
    axis2_bool_t svr_side,
    sandesha2_storage_mgr_t *storage_mgr,
    sandesha2_seq_property_mgr_t *seq_prop_mgr,
    sandesha2_create_seq_mgr_t *create_seq_mgr,
    sandesha2_sender_mgr_t *sender_mgr)
{
    axis2_char_t *rms_sequence_id = NULL;
    axutil_array_list_t *found_list = NULL;
    sandesha2_create_seq_bean_t *find_create_seq_bean = NULL;
    sandesha2_seq_property_bean_t *find_seq_prop_bean = NULL;
    
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI,
        "[sandesha2] Entry:sandesha2_terminate_mgr_clean_sending_side_data");

    AXIS2_PARAM_CHECK(env->error, conf_ctx, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, internal_sequence_id, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, storage_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, seq_prop_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, create_seq_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, sender_mgr, AXIS2_FAILURE);
     
    rms_sequence_id = sandesha2_utils_get_seq_property(env, internal_sequence_id, 
        SANDESHA2_SEQUENCE_PROPERTY_OUTGOING_SEQUENCE_ID, seq_prop_mgr);

    /*if(!svr_side)
    {
        sandesha2_seq_property_bean_t *acks_to_bean = NULL;
        axis2_bool_t stop_listner_for_async = AXIS2_FALSE;
        
        acks_to_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env,
            internal_sequence_id, SANDESHA2_SEQ_PROP_ACKS_TO_EPR);
        if(acks_to_bean)
        {
            axis2_char_t *acks_to = NULL;

            acks_to = sandesha2_seq_property_bean_get_value(acks_to_bean, env);
            if(sandesha2_utils_is_anon_uri(env, acks_to))
            {
                stop_listner_for_async = AXIS2_TRUE;
            }
            sandesha2_seq_property_bean_free(acks_to_bean, env);
        }
        
    }*/

    /* Remove all sender beans set using internal sequence id and stored in the database. */
    found_list = sandesha2_sender_mgr_find_by_internal_seq_id(sender_mgr, env, internal_sequence_id);
    if(found_list)
    {
        int i = 0;
        for(i = 0; i < axutil_array_list_size(found_list, env); i++)
        {
            sandesha2_sender_bean_t *retrans_bean = NULL;
            axis2_char_t *msg_store_key = NULL;
            axis2_char_t *msg_id = NULL;
            
            retrans_bean = axutil_array_list_get(found_list, env, i);
            msg_id = sandesha2_sender_bean_get_msg_id(retrans_bean, env);

            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                    "[sandesha2] Removing the sender bean with msg_id %s and internal_sequence_id %s", 
                    msg_id, internal_sequence_id);

            sandesha2_sender_mgr_remove(sender_mgr, env, msg_id);
            msg_store_key = sandesha2_sender_bean_get_msg_ctx_ref_key(retrans_bean, env);
            sandesha2_storage_mgr_remove_msg_ctx(storage_mgr, env, msg_store_key, conf_ctx, -1);
            if(retrans_bean)
            {
                sandesha2_sender_bean_free(retrans_bean, env);
            }
        }

        if(found_list)
        {
            axutil_array_list_free(found_list, env);
        }
    }
   
    /* Removing the create seqence beans created and stored in the database. */
    find_create_seq_bean = sandesha2_create_seq_bean_create(env);
    sandesha2_create_seq_bean_set_internal_sequence_id(find_create_seq_bean, env, internal_sequence_id);
    found_list = sandesha2_create_seq_mgr_find(create_seq_mgr, env, find_create_seq_bean);
    if(found_list)
    {
        int i = 0;
        for(i = 0; i < axutil_array_list_size(found_list, env); i++)
        {
            axis2_char_t *key = NULL;
            axis2_char_t *msg_id = NULL;
            sandesha2_create_seq_bean_t *create_seq_bean = NULL;
            
            create_seq_bean = axutil_array_list_get(found_list, env, i);
            key = sandesha2_create_seq_bean_get_ref_msg_store_key(create_seq_bean, env);
            if(key)
            {
               sandesha2_storage_mgr_remove_msg_ctx(storage_mgr, env, key, conf_ctx, -1);
            }

            msg_id = sandesha2_create_seq_bean_get_create_seq_msg_id(create_seq_bean, env);
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                    "[sandesha2] Removing the create_seq_bean with msg_id %s and internal_sequence_id %s", 
                    msg_id, internal_sequence_id);

            sandesha2_create_seq_mgr_remove(create_seq_mgr, env, msg_id);
            if(create_seq_bean)
            {
                sandesha2_create_seq_bean_free(create_seq_bean, env);
            }
        }
        
        axutil_array_list_free(found_list, env);
    }

    if(find_create_seq_bean)
    {
        sandesha2_create_seq_bean_free(find_create_seq_bean, env);
    }
    
    /* Remove all sequence properties set using internal sequence id and stored in the database.
     * This includes all properties set in sandesha2_seq_mgr_setup_new_outgoing_sequence() function.
     */
    find_seq_prop_bean = sandesha2_seq_property_bean_create(env);
    sandesha2_seq_property_bean_set_seq_id(find_seq_prop_bean, env, internal_sequence_id);

    found_list = sandesha2_seq_property_mgr_find(seq_prop_mgr, env, find_seq_prop_bean);
    if(find_seq_prop_bean)
    {
        sandesha2_seq_property_bean_free(find_seq_prop_bean, env);
    }

    if(found_list)
    {
        int i = 0, size = 0;
        size = axutil_array_list_size(found_list, env);
        for(i = 0; i < size; i++)
        {
            sandesha2_seq_property_bean_t *seq_prop_bean = NULL;
            
            seq_prop_bean = axutil_array_list_get(found_list, env, i);

            /* I have only vague idea what this do:damitha. */
            sandesha2_terminate_mgr_do_updates_if_needed(env, rms_sequence_id, seq_prop_bean, 
                    seq_prop_mgr);

            /* There are terminate/close sequence related properties that we do not remove at this 
             * stage from database. When we remove them?:damitha*/
            if(sandesha2_terminate_mgr_is_property_deletable(env,
                sandesha2_seq_property_bean_get_name(seq_prop_bean, env)))
            {
                axis2_char_t *highest_in_msg_key_str = NULL;
                axis2_char_t *temp_internal_sequence_id = NULL;
                axis2_char_t *name = NULL;

                temp_internal_sequence_id = sandesha2_seq_property_bean_get_seq_id(seq_prop_bean, env);
                name = sandesha2_seq_property_bean_get_name(seq_prop_bean, env);

                if(!axutil_strcmp(name, SANDESHA2_SEQ_PROP_HIGHEST_IN_MSG_NUMBER))
                {
                    highest_in_msg_key_str = sandesha2_seq_property_bean_get_value(seq_prop_bean, env);

                    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                            "[sandesha2] Removing the message context for the highest in message number");

                    sandesha2_storage_mgr_remove_msg_ctx(storage_mgr, env, highest_in_msg_key_str, 
                            conf_ctx, -1);
                }

                AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                        "[sandesha2] Removing the sequence property named %s in the sequence %s", 
                        name, temp_internal_sequence_id);

                sandesha2_seq_property_mgr_remove(seq_prop_mgr, env, temp_internal_sequence_id, name);
            }

            if(seq_prop_bean)
            {
                sandesha2_seq_property_bean_free(seq_prop_bean, env);
            }
        }
        
        axutil_array_list_free(found_list, env);
    }

    if(rms_sequence_id)
    {
        AXIS2_FREE(env->allocator, rms_sequence_id);
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[sandesha2] Exit:sandesha2_terminate_mgr_clean_sending_side_data");

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
sandesha2_terminate_mgr_send_terminate_seq_msg(
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *rm_msg_ctx,
    axis2_char_t *rms_sequence_id,
    axis2_char_t *internal_sequence_id,
    sandesha2_storage_mgr_t *storage_mgr,
    sandesha2_seq_property_mgr_t *seq_prop_mgr,
    sandesha2_create_seq_mgr_t *create_seq_mgr,
    sandesha2_sender_mgr_t *sender_mgr)
{
    axis2_msg_ctx_t *msg_ctx = NULL;
    axis2_msg_ctx_t *terminate_msg_ctx = NULL;
    axis2_conf_ctx_t *conf_ctx = NULL;
    sandesha2_msg_ctx_t *terminate_rm_msg_ctx = NULL;
    axutil_property_t *property = NULL;
    axis2_endpoint_ref_t *to_epr = NULL;
    sandesha2_seq_property_bean_t *to_bean = NULL;
    axis2_char_t *rm_ver = NULL;
    sandesha2_seq_property_bean_t *transport_to_bean = NULL;
    axis2_char_t *key = NULL;
    sandesha2_sender_bean_t *terminate_sender_bean = NULL;
    sandesha2_seq_property_bean_t *terminate_added = NULL;
    sandesha2_seq_property_bean_t *replay_bean = NULL;
    axis2_engine_t *engine = NULL;
    axis2_char_t *temp_action = NULL;
    axutil_string_t *soap_action = NULL;
    axis2_status_t status = AXIS2_FALSE;
    const axis2_char_t *to_addr = NULL;
    long send_time = -1;
    int terminate_delay = -1;
    sandesha2_property_bean_t *property_bean = NULL;
    axis2_endpoint_ref_t *reply_to_epr = NULL;
    axis2_bool_t is_svr_side = AXIS2_FALSE;
    axis2_char_t *msg_id = NULL;
    axis2_svc_t *svc = NULL;
    long retrans_delay = -1;


    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[sandesha2] Entry:sandesha2_terminate_mgr_send_terminate_seq_msg");

    AXIS2_PARAM_CHECK(env->error, rm_msg_ctx, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, rms_sequence_id, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, internal_sequence_id, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, storage_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, seq_prop_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, create_seq_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, sender_mgr, AXIS2_FAILURE);
    
    msg_ctx = sandesha2_msg_ctx_get_msg_ctx(rm_msg_ctx, env);
    conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);

    svc = axis2_msg_ctx_get_svc(msg_ctx, env);
    if(!svc)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] Service is NULL");
        return AXIS2_FAILURE;
    }

    property_bean = sandesha2_utils_get_property_bean(env, svc);
    if(!property_bean)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] Property bean is NULL");
        return AXIS2_FAILURE;
    }
    
    terminate_delay = sandesha2_property_bean_get_terminate_delay(property_bean, env); 
    retrans_delay = sandesha2_property_bean_get_retrans_interval(property_bean, env); 
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "retrans_delay:%ld", retrans_delay);
    
    terminate_rm_msg_ctx = sandesha2_msg_creator_create_terminate_seq_msg(env, rm_msg_ctx, 
            rms_sequence_id, internal_sequence_id, seq_prop_mgr);

    if(!terminate_rm_msg_ctx)
    {
        return AXIS2_FAILURE;
    }
    
    terminate_msg_ctx = sandesha2_msg_ctx_get_msg_ctx(terminate_rm_msg_ctx, env);

    sandesha2_msg_ctx_set_flow(terminate_rm_msg_ctx, env, AXIS2_OUT_FLOW);
    property = axutil_property_create_with_args(env, 0, 0, 0, AXIS2_VALUE_TRUE);
    sandesha2_msg_ctx_set_property(terminate_rm_msg_ctx, env, SANDESHA2_APPLICATION_PROCESSING_DONE, 
            property);
    
    to_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env, internal_sequence_id, 
            SANDESHA2_SEQ_PROP_TO_EPR);

    if(to_bean)
    {
        axis2_char_t *temp_addr = NULL;

        temp_addr = sandesha2_seq_property_bean_get_value(to_bean, env);
        to_epr = axis2_endpoint_ref_create(env, temp_addr);
        /*if(!sandesha2_utils_is_anon_uri(env, temp_addr))
        {
            to_epr = axis2_endpoint_ref_create(env, temp_addr);
        }*/
        sandesha2_seq_property_bean_free(to_bean, env);
    }

    if(to_epr)
    {
        to_addr = axis2_endpoint_ref_get_address(to_epr, env);
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "to_addr:%s", to_addr);
        sandesha2_msg_ctx_set_to(terminate_rm_msg_ctx, env, to_epr);
    }

    rm_ver = sandesha2_utils_get_rm_version(env, msg_ctx);
    if(!rm_ver)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] Cannot find the rm version for msg");
        if(terminate_rm_msg_ctx)
        {
            sandesha2_msg_ctx_free(terminate_rm_msg_ctx, env);
        }

        if(terminate_msg_ctx)
        {
            axis2_endpoint_ref_t *temp_epr = NULL;

            temp_epr = axis2_msg_ctx_get_to(terminate_msg_ctx, env);
            if(temp_epr)
            {
                axis2_endpoint_ref_free(temp_epr, env);
            }

            /* Reset the message context to avoid double freeing of transport out stream */
            axis2_core_utils_reset_out_msg_ctx(env, terminate_msg_ctx);
            axis2_msg_ctx_free(terminate_msg_ctx, env);
        }

        return AXIS2_FAILURE;
    }

    sandesha2_msg_ctx_set_wsa_action(terminate_rm_msg_ctx, env, 
        sandesha2_spec_specific_consts_get_terminate_seq_action(env, rm_ver));

    temp_action = sandesha2_spec_specific_consts_get_terminate_seq_soap_action(env, rm_ver);
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "temp_action:%s", temp_action);
    soap_action = axutil_string_create(env, temp_action);
    if(soap_action)
    {
        sandesha2_msg_ctx_set_soap_action(terminate_rm_msg_ctx, env, soap_action);
        axutil_string_free(soap_action, env);
    }

    transport_to_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env, internal_sequence_id, 
            SANDESHA2_SEQ_PROP_TRANSPORT_TO);

    if(transport_to_bean)
    {
        axis2_char_t *value = sandesha2_seq_property_bean_get_value(transport_to_bean, env);
        property = axutil_property_create_with_args(env, 0, 0, 0, value);
        sandesha2_msg_ctx_set_property(terminate_rm_msg_ctx, env, AXIS2_TRANSPORT_URL, property);
    }
    
    terminate_added = sandesha2_seq_property_bean_create(env);
    if(terminate_added)
    {
        sandesha2_seq_property_bean_set_name(terminate_added, env, SANDESHA2_SEQ_PROP_TERMINATE_ADDED);
        sandesha2_seq_property_bean_set_seq_id(terminate_added, env, internal_sequence_id);
        sandesha2_seq_property_bean_set_value(terminate_added, env, AXIS2_VALUE_TRUE);
        sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, terminate_added);
        sandesha2_seq_property_bean_free(terminate_added, env);
    }
    
    /* If server side and single channel duplex mode send the terminate sequence message.
     */
    if(sandesha2_utils_is_rm_1_0_anonymous_acks_to(env, rm_ver, to_addr))
    {
        sandesha2_msg_ctx_add_soap_envelope(terminate_rm_msg_ctx, env);
        axis2_op_ctx_set_response_written(axis2_msg_ctx_get_op_ctx(terminate_msg_ctx, env), env, AXIS2_TRUE);
        axis2_msg_ctx_set_paused(msg_ctx, env, AXIS2_TRUE);
        axis2_op_ctx_set_response_written(axis2_msg_ctx_get_op_ctx(msg_ctx, env), env, AXIS2_TRUE);
        engine = axis2_engine_create(env, conf_ctx);

        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] axis2_engine_send");

        axis2_engine_send(engine, env, terminate_msg_ctx);
        if(engine)
        {
            axis2_engine_free(engine, env);
            engine = NULL;
        }

        /* We should not go and clean the database. */
        /*sandesha2_terminate_mgr_terminate_sending_side(env, conf_ctx, internal_sequence_id, 
                is_svr_side, storage_mgr, seq_prop_mgr, create_seq_mgr, sender_mgr);*/

        if(terminate_rm_msg_ctx)
        {
            sandesha2_msg_ctx_free(terminate_rm_msg_ctx, env);
        }

        /* We have created this message context using sandesha2_utils_create_new_related_msg_ctx(). It is our
         * reponsiblity to free it after use.
         */
        if(terminate_msg_ctx)
        {
            axis2_endpoint_ref_t *temp_epr = NULL;

            temp_epr = axis2_msg_ctx_get_to(terminate_msg_ctx, env);
            if(temp_epr)
            {
                axis2_endpoint_ref_free(temp_epr, env);
            }

            /* Reset the message context to avoid double freeing of transport out stream */
            axis2_core_utils_reset_out_msg_ctx(env, terminate_msg_ctx);
            axis2_msg_ctx_free(terminate_msg_ctx, env);
        }

        return AXIS2_SUCCESS;
    }
 
    if(!sandesha2_util_is_ack_already_piggybacked(env, terminate_rm_msg_ctx))
    {
        sandesha2_ack_mgr_piggyback_acks_if_present(env, rms_sequence_id, terminate_rm_msg_ctx, 
                storage_mgr, seq_prop_mgr, sender_mgr);
    }
    
    sandesha2_msg_ctx_add_soap_envelope(terminate_rm_msg_ctx, env);

    key = axutil_uuid_gen(env);
    terminate_sender_bean = sandesha2_sender_bean_create(env);
    sandesha2_sender_bean_set_msg_ctx_ref_key(terminate_sender_bean, env, key);
    /*sandesha2_storage_mgr_store_msg_ctx(storage_mgr, env, key, terminate_msg_ctx, AXIS2_TRUE);*/
    send_time = sandesha2_utils_get_current_time_in_millis(env) + terminate_delay;
    sandesha2_sender_bean_set_time_to_send(terminate_sender_bean, env, send_time);

    msg_id = sandesha2_msg_ctx_get_msg_id(terminate_rm_msg_ctx, env);
    sandesha2_sender_bean_set_msg_id(terminate_sender_bean, env, msg_id);

    sandesha2_sender_bean_set_send(terminate_sender_bean, env, AXIS2_TRUE);

    sandesha2_sender_bean_set_seq_id(terminate_sender_bean, env, rms_sequence_id);
    sandesha2_sender_bean_set_internal_seq_id(terminate_sender_bean, env, internal_sequence_id);

    sandesha2_sender_bean_set_msg_type(terminate_sender_bean, env, SANDESHA2_MSG_TYPE_TERMINATE_SEQ);
                            
    sandesha2_sender_bean_set_resend(terminate_sender_bean, env, AXIS2_FALSE);
    sandesha2_sender_mgr_insert(sender_mgr, env, terminate_sender_bean);
    
    property = axutil_property_create_with_args(env, 0, AXIS2_TRUE, 0, key);
    axis2_msg_ctx_set_property(terminate_msg_ctx, env, SANDESHA2_MESSAGE_STORE_KEY, property);
                        
    /*property = axutil_property_create_with_args(env, 0, 0, 0, AXIS2_VALUE_TRUE);
    axis2_msg_ctx_set_property(terminate_msg_ctx, env, SANDESHA2_SET_SEND_TO_TRUE, property);*/
                        
    is_svr_side = sandesha2_msg_ctx_get_server_side(rm_msg_ctx, env); /* Do we need this?:damitha */
    engine = axis2_engine_create(env, conf_ctx);

    /* Check whether this is replay mode. This value set when sending application message */
    replay_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env, 
        rms_sequence_id, SANDESHA2_SEQ_PROP_REPLAY);
    if(replay_bean)
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] replay on");
    }
    if(sandesha2_utils_is_anon_uri(env, to_addr))
    {
        axis2_transport_out_desc_t *sandesha2_transport_out = NULL;

        sandesha2_transport_out = sandesha2_utils_get_transport_out(env);
        axis2_msg_ctx_set_transport_out_desc(terminate_msg_ctx, env, sandesha2_transport_out);
        axis2_engine_send(engine, env, terminate_msg_ctx);
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] RM 1.1 replay");
    }
    else
    {
        sandesha2_seq_property_bean_t *reply_to_bean = NULL;

        reply_to_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env, internal_sequence_id, 
            SANDESHA2_SEQ_PROP_REPLY_TO_EPR);
        if(reply_to_bean)
        {
            axis2_char_t *reply_to_addr = NULL;
            axis2_endpoint_ref_t *reply_to_epr = NULL;

            reply_to_addr = axutil_strdup(env, sandesha2_seq_property_bean_get_value(reply_to_bean, env));
            reply_to_epr = axis2_endpoint_ref_create(env, reply_to_addr);
            sandesha2_msg_ctx_set_reply_to(terminate_rm_msg_ctx, env, reply_to_epr);

            sandesha2_seq_property_bean_free(reply_to_bean, env);
        }

        /*reply_to_epr = axis2_msg_ctx_get_to(msg_ctx, env);
        if(reply_to_epr)
        {
            axis2_msg_ctx_set_reply_to(terminate_msg_ctx, env, sandesha2_util_endpoint_ref_clone(
                    env, reply_to_epr));
        }*/
        if(AXIS2_SUCCESS == axis2_engine_send(engine, env, terminate_msg_ctx))
        {
            /* We need to resend the terminate sequence message or process the response in the back 
             * channel only in the replay mode.
             */
            /*if(replay_bean && axutil_strcmp(SANDESHA2_SPEC_VERSION_1_0, rm_ver))
            {
                axiom_soap_envelope_t *res_envelope = NULL;
                axis2_char_t *soap_ns_uri = NULL;
                axis2_transport_out_desc_t *transport_out = NULL;
                axis2_transport_sender_t *transport_sender = NULL;
                sandesha2_sender_bean_set_resend(terminate_sender_bean, env, AXIS2_TRUE);
                soap_ns_uri = axis2_msg_ctx_get_is_soap_11(terminate_msg_ctx, env) ?
                     AXIOM_SOAP11_SOAP_ENVELOPE_NAMESPACE_URI:
                     AXIOM_SOAP12_SOAP_ENVELOPE_NAMESPACE_URI;

                res_envelope = axis2_msg_ctx_get_response_soap_envelope(terminate_msg_ctx, env);
                if(!res_envelope)
                {
                    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] Response envelope not found");

                    res_envelope = (axiom_soap_envelope_t *) axis2_http_transport_utils_create_soap_msg(env, 
                            terminate_msg_ctx, soap_ns_uri);
                }

                if(res_envelope)
                {
                    status = sandesha2_terminate_mgr_process_response(env, terminate_msg_ctx, storage_mgr);
                    if(AXIS2_SUCCESS != status)
                    {
                        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                            "[sandesha2] Terminate message response process failed for sequence %s", 
                            internal_sequence_id);
                    }
                }
                transport_out = axis2_msg_ctx_get_transport_out_desc(terminate_msg_ctx, env);
                if(transport_out)
                {
                    transport_sender = axis2_transport_out_desc_get_sender(transport_out, env);
                }

                while(!res_envelope)
                {
                    axis2_bool_t continue_sending = AXIS2_FALSE;

                    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                        "[sandesha2] Terminate Sequence response message not found. So continuing");

                    continue_sending = sandesha2_msg_retrans_adjuster_adjust_retrans(env, terminate_sender_bean, 
                            conf_ctx, storage_mgr, seq_prop_mgr, create_seq_mgr, sender_mgr, svc);

                    sandesha2_sender_mgr_update(sender_mgr, env, terminate_sender_bean);

                    if(!continue_sending)
                    {
                        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                                "[sandesha2] Do not continue sending the terminate sequence message");
                        break;
                    }

                    AXIS2_SLEEP(retrans_delay);

                    if(transport_sender)
                    {
                        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] Resending the terminate message");
                        // This is neccessary to avoid a double free
                        axis2_msg_ctx_set_property(terminate_msg_ctx, env, AXIS2_TRANSPORT_IN, NULL);
                        if(!AXIS2_TRANSPORT_SENDER_INVOKE(transport_sender, env, terminate_msg_ctx))
                        {
                            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                                    "[sandesha2] Transport sender invoke failed in sending terminate sequence message");
                        }
                    }

                    res_envelope = axis2_msg_ctx_get_response_soap_envelope(terminate_msg_ctx, env);
                    if(!res_envelope)
                    {
                        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] Response envelope not found");

                        res_envelope = (axiom_soap_envelope_t *) axis2_http_transport_utils_create_soap_msg(env, 
                                terminate_msg_ctx, soap_ns_uri);
                    }
                    
                    if(res_envelope)
                    {
                        status = sandesha2_terminate_mgr_process_response(env, 
                                terminate_msg_ctx, storage_mgr);

                        if(AXIS2_SUCCESS != status)
                        {
                            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                                "[sandesha2] Terminate message response process failed for sequence %s", 
                                internal_sequence_id);

                            continue;
                        }
                            
                        break;
                    }
                }

                sandesha2_seq_property_bean_free(replay_bean, env);
            }*/
        }
    }
    
    sandesha2_storage_mgr_store_msg_ctx(storage_mgr, env, key, terminate_msg_ctx, AXIS2_TRUE);

    if(terminate_sender_bean)
    {
        sandesha2_sender_bean_free(terminate_sender_bean, env);
    }

    /*sandesha2_terminate_mgr_terminate_sending_side(env, conf_ctx, internal_sequence_id, is_svr_side, 
            storage_mgr, seq_prop_mgr, create_seq_mgr, sender_mgr);*/

    if(engine)
    {
        axis2_engine_free(engine, env);
    }

    if(terminate_rm_msg_ctx)
    {
        sandesha2_msg_ctx_free(terminate_rm_msg_ctx, env);
    }

    /* We have created this message context using sandesha2_utils_create_new_related_msg_ctx(). It is our
     * reponsiblity to free if after use.
     */
    if(terminate_msg_ctx)
    {
        axis2_endpoint_ref_t *temp_epr = NULL;

        temp_epr = axis2_msg_ctx_get_to(terminate_msg_ctx, env);
        if(temp_epr)
        {
            axis2_endpoint_ref_free(temp_epr, env);
            temp_epr = NULL;
        }
        
        temp_epr = axis2_msg_ctx_get_reply_to(terminate_msg_ctx, env);
        if(temp_epr)
        {
            axis2_endpoint_ref_free(temp_epr, env);
        }

        axis2_core_utils_reset_out_msg_ctx(env, terminate_msg_ctx);
        axis2_msg_ctx_free(terminate_msg_ctx, env);
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[sandesha2] Exit:sandesha2_terminate_mgr_send_terminate_seq_msg");

    return status;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
sandesha2_terminate_mgr_process_response(
    const axutil_env_t *env, 
    axis2_msg_ctx_t *msg_ctx,
    sandesha2_storage_mgr_t *storage_mgr)
{
    axis2_char_t *soap_ns_uri = NULL;
    axis2_msg_ctx_t *response_msg_ctx = NULL;
    axiom_soap_envelope_t *response_envelope = NULL;
    axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_engine_t *engine = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    axis2_endpoint_ref_t *to = NULL;
   
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI,
        "[sandesha2] Entry:sandesha2_terminate_mgr_process_response");

    AXIS2_PARAM_CHECK(env->error, msg_ctx, AXIS2_FAILURE);

    conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);

    soap_ns_uri = axis2_msg_ctx_get_is_soap_11(msg_ctx, env) ?
         AXIOM_SOAP11_SOAP_ENVELOPE_NAMESPACE_URI:
         AXIOM_SOAP12_SOAP_ENVELOPE_NAMESPACE_URI;

    response_envelope = axis2_msg_ctx_get_response_soap_envelope(msg_ctx, env);
    if(!response_envelope)
    {
        response_envelope = (axiom_soap_envelope_t *) axis2_http_transport_utils_create_soap_msg(env, 
                msg_ctx, soap_ns_uri);
        if(!response_envelope)
        {
            /* There is no response message context. */

            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] Response envelope not found");

            return AXIS2_SUCCESS;
        }
    }

    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
        "[sandesha2] Response envelope for TerminateSequenceResponse message found");

    response_msg_ctx = axis2_msg_ctx_create(env, conf_ctx, axis2_msg_ctx_get_transport_in_desc(msg_ctx, 
                env), axis2_msg_ctx_get_transport_out_desc(msg_ctx, env));
    
    to = axis2_endpoint_ref_create(env, 
        "http://localhost/axis2/services/__ANONYMOUS_SERVICE__/__OPERATION_OUT_IN__");
    axis2_msg_ctx_set_to(response_msg_ctx, env, to);

    axis2_msg_ctx_set_wsa_action(response_msg_ctx, env, 
            "http://localhost/axis2/services/__ANONYMOUS_SERVICE__/__OPERATION_OUT_IN__");

    axis2_msg_ctx_set_soap_envelope(response_msg_ctx, env, response_envelope);

    axis2_msg_ctx_set_op_ctx(response_msg_ctx, env, axis2_msg_ctx_get_op_ctx(msg_ctx, env));
    axis2_msg_ctx_set_svc_ctx(response_msg_ctx, env, axis2_msg_ctx_get_svc_ctx(msg_ctx, env));
    axis2_msg_ctx_set_svc_grp_ctx(response_msg_ctx, env, axis2_msg_ctx_get_svc_grp_ctx(msg_ctx, env));
    axis2_msg_ctx_set_conf_ctx(response_msg_ctx, env, conf_ctx);


    engine = axis2_engine_create(env, conf_ctx);
    if(engine)
    {
        if(sandesha2_util_is_fault_envelope(env, response_envelope))
        {
            status = axis2_engine_receive_fault(engine, env, response_msg_ctx);
        }
        else
        {
            status = axis2_engine_receive(engine, env, response_msg_ctx);
        }
            axis2_engine_free(engine, env);
    }

    /* We are not interested about the message context after now. So pause it. */
    axis2_msg_ctx_set_paused(response_msg_ctx, env, AXIS2_FALSE);
    axis2_msg_ctx_free(response_msg_ctx, env);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI,
        "[sandesha2] Exit:sandesha2_terminate_mgr_process_response");

    return AXIS2_SUCCESS;
}


