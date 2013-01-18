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
#include <sandesha2_ack_mgr.h>
#include <sandesha2_constants.h>
#include <sandesha2_property_bean.h>
#include <sandesha2_seq_property_bean.h>
#include <sandesha2_ack_range.h>
#include <sandesha2_spec_specific_consts.h>
#include <sandesha2_seq_property_mgr.h>
#include <sandesha2_sender_mgr.h>
#include <sandesha2_sender_bean.h>
#include <axutil_string.h>
#include <axutil_uuid_gen.h>
#include <axis2_addr.h>
#include <axis2_core_utils.h>
#include <axutil_property.h>
#include <axutil_array_list.h>
#include <sandesha2_msg_init.h>
#include <sandesha2_seq_ack.h>
#include <axis2_op.h>
#include <sandesha2_msg_creator.h>
#include <axis2_transport_out_desc.h>

AXIS2_EXTERN sandesha2_msg_ctx_t *AXIS2_CALL
sandesha2_ack_mgr_generate_ack_msg(
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *ref_rm_msg,
    axis2_char_t *seq_id,
    sandesha2_seq_property_mgr_t *seq_prop_mgr)
{
    axis2_msg_ctx_t *ref_msg = NULL;
    axis2_conf_ctx_t *conf_ctx = NULL;

    axis2_endpoint_ref_t *to = NULL;
    axis2_endpoint_ref_t *temp_to = NULL;
    axis2_msg_ctx_t *ack_msg_ctx = NULL;
    axutil_property_t *property = NULL;
    axutil_property_t *new_property = NULL;
    sandesha2_msg_ctx_t *ack_rm_msg = NULL;
    /*axiom_soap_envelope_t *soap_env = NULL;*/
    axis2_op_ctx_t *op_ctx = NULL;
    axis2_char_t *uuid = NULL;
    sandesha2_seq_property_bean_t *ref_param_bean = NULL;
    
    AXIS2_PARAM_CHECK(env->error, seq_id, NULL);
    AXIS2_PARAM_CHECK(env->error, seq_prop_mgr, NULL);
    
    ref_msg = sandesha2_msg_ctx_get_msg_ctx(ref_rm_msg, env);
    conf_ctx = axis2_msg_ctx_get_conf_ctx(ref_msg, env);
   
    temp_to = axis2_msg_ctx_get_reply_to(ref_msg, env);
    if(temp_to)
    {
        to = axis2_endpoint_ref_create(env, axis2_endpoint_ref_get_address(temp_to, env));
    }
    if(!to)
    {
        sandesha2_seq_property_bean_t *acks_to_bean = NULL;
        axis2_char_t *acks_to_str = NULL;

        acks_to_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env,
            seq_id, SANDESHA2_SEQ_PROP_ACKS_TO_EPR);
        if(acks_to_bean)
        {
            acks_to_str = sandesha2_seq_property_bean_get_value(acks_to_bean, env);
            to = axis2_endpoint_ref_create(env, acks_to_str);
            sandesha2_seq_property_bean_free(acks_to_bean, env);
        }
    }

    ack_msg_ctx = sandesha2_utils_create_new_related_msg_ctx(env, ref_rm_msg);
    property = axis2_msg_ctx_get_property(ref_msg, env, RAMPART_CONTEXT);
    if(property)
    {
        new_property = axutil_property_create_with_args(env, AXIS2_SCOPE_REQUEST, AXIS2_FALSE, 0, 
            axutil_property_get_value(property, env));
        if(new_property)
        {
            axis2_msg_ctx_set_property(ack_msg_ctx, env, RAMPART_CONTEXT, new_property);
        }
    }

    property = axutil_property_create_with_args(env, AXIS2_SCOPE_REQUEST, AXIS2_FALSE, 0, 
            AXIS2_VALUE_TRUE);
    if(property)
    {
        axis2_msg_ctx_set_property(ack_msg_ctx, env, SANDESHA2_APPLICATION_PROCESSING_DONE, property);
        property = NULL;
    }

    ack_rm_msg = sandesha2_msg_init_init_msg(env, ack_msg_ctx);
    sandesha2_msg_ctx_set_rm_ns_val(ack_rm_msg, env, 
        sandesha2_msg_ctx_get_rm_ns_val(ref_rm_msg, env));

    uuid = axutil_uuid_gen(env);
    if(uuid)
    {
        axis2_msg_ctx_set_wsa_message_id(ack_msg_ctx, env, uuid);
        AXIS2_FREE(env->allocator, uuid);
    }

    /*soap_env = axiom_soap_envelope_create_default_soap_envelope(env, 
     * sandesha2_utils_get_soap_version(env, axis2_msg_ctx_get_soap_envelope(ref_msg, env)));
    axis2_msg_ctx_set_soap_envelope(ack_msg_ctx, env, soap_env);*/
    
    ref_param_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env, 
            seq_id, SANDESHA2_SEQ_PROP_ACKS_TO_REF_PARAM);

    if(ref_param_bean)
    {
        axis2_char_t *ref_param_str = NULL;
        axutil_array_list_t *ref_param_list = NULL;
        int i = 0, size = 0;
    

        ref_param_str = sandesha2_seq_property_bean_get_value(ref_param_bean, env);
        ref_param_list = sandesha2_util_get_node_list_from_string(env, ref_param_str);

        if(ref_param_list)
        {
            size = axutil_array_list_size(ref_param_list, env);

            for(i = 0; i < size; i++)
            {
                axiom_node_t *node = NULL;

                node = axutil_array_list_get(ref_param_list, env, i);
                axis2_endpoint_ref_add_ref_param(to, env, node);
            }

            axutil_array_list_free(ref_param_list, env);
        }

        sandesha2_seq_property_bean_free(ref_param_bean, env);
    }

    axis2_msg_ctx_set_to(ack_msg_ctx, env, to);

    /* Adding the sequence acknowledgement part */
    sandesha2_msg_creator_add_ack_msg(env, ack_rm_msg, seq_id, seq_prop_mgr);
    axis2_msg_ctx_set_property(ack_msg_ctx, env, AXIS2_TRANSPORT_IN, NULL);
    
    op_ctx = axis2_msg_ctx_get_op_ctx(ref_msg, env);
    axis2_op_ctx_set_response_written(op_ctx, env, AXIS2_TRUE);
    
    property = axutil_property_create_with_args(env, AXIS2_SCOPE_REQUEST, 
        AXIS2_FALSE, 0, AXIS2_VALUE_TRUE);
    axis2_msg_ctx_set_property(ref_msg, env, SANDESHA2_ACK_WRITTEN, property);
    axis2_msg_ctx_set_server_side(ack_msg_ctx, env, AXIS2_TRUE);

    return ack_rm_msg;
}

/**
 * This is used to get the acked messages of a sequence. If this is an outgoing 
 * message the sequence_identifier should be the outgoing sequenceID.
 * 
 * @param sequence_identifier
 * @param out_going_msg
 * @return
 */
AXIS2_EXTERN axutil_array_list_t *AXIS2_CALL
sandesha2_ack_mgr_get_client_completed_msgs_list(
        const axutil_env_t *env,
        axis2_char_t *rms_seq_id,
        sandesha2_seq_property_mgr_t *seq_prop_mgr)
{
    sandesha2_seq_property_bean_t *internal_seq_bean = NULL;
    axis2_char_t *internal_seq_id = NULL;
    sandesha2_seq_property_bean_t *completed_msgs_bean = NULL;
    axutil_array_list_t *completed_msg_list = NULL;
    
    /* First trying to get it from the internal sequence id.*/
    internal_seq_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env, 
            rms_seq_id, SANDESHA2_SEQUENCE_PROPERTY_OUTGOING_INTERNAL_SEQUENCE_ID);
    if(internal_seq_bean != NULL)
    {
        internal_seq_id = sandesha2_seq_property_bean_get_value(
                internal_seq_bean, env);
    }
    if(internal_seq_id != NULL)
    {
        completed_msgs_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, 
                env, internal_seq_id, 
                SANDESHA2_SEQ_PROP_CLIENT_COMPLETED_MESSAGES);
    }
    if(completed_msgs_bean == NULL)
    {
        completed_msgs_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, 
                env, rms_seq_id, 
                SANDESHA2_SEQ_PROP_CLIENT_COMPLETED_MESSAGES);
    }
    if(completed_msgs_bean != NULL)
    {
        axis2_char_t *value = sandesha2_seq_property_bean_get_value(
            completed_msgs_bean, env);
        completed_msg_list = sandesha2_utils_get_array_list_from_string(env, value);
    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[sandesha2]completed_msgs_bean is NULL");
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_COMPLETED_MSGS_BEAN_IS_NULL, 
            AXIS2_FAILURE);
        return NULL;
    }
    return completed_msg_list;
}
 
AXIS2_EXTERN axutil_array_list_t *AXIS2_CALL
sandesha2_ack_mgr_get_svr_completed_msgs_list(
    const axutil_env_t *env,
    axis2_char_t *rmd_seq_id,
    sandesha2_seq_property_mgr_t *seq_prop_mgr)
{
    sandesha2_seq_property_bean_t *completed_msgs_bean = NULL;
    axutil_array_list_t *completed_msg_list = NULL;
    
    completed_msgs_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, 
        env, rmd_seq_id, 
        SANDESHA2_SEQ_PROP_SERVER_COMPLETED_MESSAGES);
    if(completed_msgs_bean)
    {
        axis2_char_t *value = sandesha2_seq_property_bean_get_value(
            completed_msgs_bean, env);
        completed_msg_list = sandesha2_utils_get_array_list_from_string(env, value);
    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[sandesha2]completed_msgs_bean is NULL");
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_COMPLETED_MSGS_BEAN_IS_NULL, 
            AXIS2_FAILURE);
        return NULL;
    }
    return completed_msg_list;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
sandesha2_ack_mgr_verify_seq_completion(
    const axutil_env_t *env,
    axutil_array_list_t *ack_ranges,
    long last_msg_no)
{
    axutil_hash_t *hash = NULL;
    axis2_char_t tmp[32];
    int i = 0;
    long start = 1;
    
    AXIS2_PARAM_CHECK(env->error, ack_ranges, AXIS2_FALSE);
    
    hash = axutil_hash_make(env);
    for(i  = 0; i< axutil_array_list_size(ack_ranges, env); i++)
    {
        sandesha2_ack_range_t *ack_range = NULL;
        
        ack_range = axutil_array_list_get(ack_ranges, env, i);
        sprintf(tmp, "%ld", sandesha2_ack_range_get_lower_value(ack_range, env));
        axutil_hash_set(hash, tmp, AXIS2_HASH_KEY_STRING, ack_range);
    }
    
    while(AXIS2_TRUE)
    {
        sandesha2_ack_range_t *ack_range = NULL;
		long upper_value = -1;

        sprintf(tmp, "%ld", start);
        ack_range = axutil_hash_get(hash, tmp, AXIS2_HASH_KEY_STRING);
        
        
        if(!ack_range)
        {
            break;
        }
        upper_value = sandesha2_ack_range_get_upper_value(ack_range, env);
        if(upper_value >= last_msg_no)
        {
            if(hash)
            {
                axutil_hash_free(hash, env);
            }
            return AXIS2_TRUE;
        }
        start = sandesha2_ack_range_get_upper_value(ack_range, env) + 1;        
    }

    if(hash)
    {
        axutil_hash_free(hash, env);
    }
    return AXIS2_FALSE;
}

/* We piggyback the ack messages stored for the same sequence with the sequence id */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
sandesha2_ack_mgr_piggyback_acks_if_present(
    const axutil_env_t *env,
    axis2_char_t *outgoing_sequence_id,
    sandesha2_msg_ctx_t *target_rm_msg_ctx,
    sandesha2_storage_mgr_t *storage_mgr,
    sandesha2_seq_property_mgr_t *seq_prop_mgr,
    sandesha2_sender_mgr_t *sender_mgr)
{
    axis2_conf_ctx_t *conf_ctx = NULL;
    sandesha2_sender_bean_t *find_bean = NULL;
    axis2_char_t *to_str = NULL;
    axis2_msg_ctx_t *target_msg_ctx = NULL;
    axis2_endpoint_ref_t *to_epr = NULL;
    axutil_array_list_t *found_list = NULL;
    
    AXIS2_PARAM_CHECK(env->error, target_rm_msg_ctx, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, storage_mgr, AXIS2_FAILURE);
    
    target_msg_ctx = sandesha2_msg_ctx_get_msg_ctx(target_rm_msg_ctx, env);
    conf_ctx = axis2_msg_ctx_get_conf_ctx(target_msg_ctx, env);

    find_bean = sandesha2_sender_bean_create(env);
    sandesha2_sender_bean_set_msg_type(find_bean, env, SANDESHA2_MSG_TYPE_ACK);
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "outgoing_sequence_id:%s", outgoing_sequence_id);
    sandesha2_sender_bean_set_seq_id(find_bean, env, outgoing_sequence_id);
    sandesha2_sender_bean_set_send(find_bean, env, AXIS2_TRUE);
    sandesha2_sender_bean_set_resend(find_bean, env, AXIS2_FALSE);

    to_epr = sandesha2_msg_ctx_get_to(target_rm_msg_ctx, env);
    if(to_epr)
    {
        to_str = (axis2_char_t*)axis2_endpoint_ref_get_address(to_epr, env);
    }
                        
    found_list = sandesha2_sender_mgr_find_by_sender_bean(sender_mgr, env, find_bean);
    if(find_bean)
    {
        sandesha2_sender_bean_free(find_bean, env);
    }

    if(found_list)
    {
        int i = 0, j = 0, size = 0;

        size = axutil_array_list_size(found_list, env);
        for(i = 0; i < size; i++)
        {
            sandesha2_sender_bean_t *sender_bean = NULL;
            long timenow = 0;
            
            timenow = sandesha2_utils_get_current_time_in_millis(env);
            sender_bean = axutil_array_list_get(found_list, env, i);
            
            if(sender_bean && sandesha2_sender_bean_get_time_to_send(sender_bean, env) <= timenow)
            {
                axis2_msg_ctx_t *ack_msg_ctx = NULL;
                axis2_char_t *to = NULL;
                sandesha2_msg_ctx_t *ack_rm_msg_ctx = NULL;
                sandesha2_seq_ack_t *seq_ack = NULL;
                axis2_char_t *msg_ctx_ref_key = NULL;
                axis2_endpoint_ref_t *to_ref = NULL;
                
                msg_ctx_ref_key = sandesha2_sender_bean_get_msg_ctx_ref_key(sender_bean, env);
                ack_msg_ctx = sandesha2_storage_mgr_retrieve_msg_ctx(storage_mgr, env, msg_ctx_ref_key, 
                        conf_ctx, AXIS2_FALSE);

                if(ack_msg_ctx)
                {
                    to_ref = axis2_msg_ctx_get_to(ack_msg_ctx, env);
                }

                if(to_ref)
                {
                    to = (axis2_char_t*)axis2_endpoint_ref_get_address(to_ref, env);
                }
                else
                {
                    if(ack_msg_ctx)
                    {
                        axis2_msg_ctx_free(ack_msg_ctx, env);
                    }
                
                    sandesha2_sender_bean_free(sender_bean, env);
                    continue;
                }

                if(axutil_strcmp(to, to_str))
                {
                    if(ack_msg_ctx)
                    {
                        axis2_msg_ctx_free(ack_msg_ctx, env);
                    }
                    
                    sandesha2_sender_bean_free(sender_bean, env);
                    continue; 
                }

                sandesha2_sender_mgr_remove(sender_mgr, env, sandesha2_sender_bean_get_msg_id(
                            sender_bean, env));

                sandesha2_storage_mgr_remove_msg_ctx(storage_mgr, env, msg_ctx_ref_key, conf_ctx, -1);
                ack_rm_msg_ctx = sandesha2_msg_init_init_msg(env, ack_msg_ctx);

                if(SANDESHA2_MSG_TYPE_ACK != sandesha2_msg_ctx_get_msg_type(ack_rm_msg_ctx, env))
                {
                    AXIS2_LOG_WARNING(env->log, AXIS2_LOG_SI, "[sandesha2] Invalid ack message entry");
                    if(ack_msg_ctx)
                    {
                        axis2_msg_ctx_free(ack_msg_ctx, env);
                    }

                    if(ack_rm_msg_ctx)
                    {
                        sandesha2_msg_ctx_free(ack_rm_msg_ctx, env);
                    }

                    sandesha2_sender_bean_free(sender_bean, env);
                    continue;
                }

                seq_ack = sandesha2_msg_ctx_get_seq_ack(ack_rm_msg_ctx, env);
                /* When we set seq_ack to target rm message context taken from acknowledgment rm message 
                 * context ,there happen freeing at both contexts if we do not increment ref.*/
                sandesha2_seq_ack_increment_ref(seq_ack, env);
                sandesha2_msg_ctx_set_seq_ack(target_rm_msg_ctx, env, seq_ack);

                /* This will be added just before message is sent, to make sure that the function is
                 * not called multiple times causing message dupplication in the soap message.
                 */
                /*sandesha2_msg_ctx_add_soap_envelope(target_rm_msg_ctx, env);*/

                if(ack_msg_ctx)
                {
                    axis2_msg_ctx_free(ack_msg_ctx, env);
                }

                if(ack_rm_msg_ctx)
                {
                    sandesha2_msg_ctx_free(ack_rm_msg_ctx, env);
                }

                sandesha2_sender_bean_free(sender_bean, env);
                break;
            }

            for(j = i++; j < size; j++)
            {
                sandesha2_sender_bean_t *sender_bean = NULL;
                
                sender_bean = axutil_array_list_get(found_list, env, j);

                if(sender_bean)
                {
                    sandesha2_sender_bean_free(sender_bean, env);
                    sender_bean = NULL;
                }
            }

            if(sender_bean)
            {
                sandesha2_sender_bean_free(sender_bean, env);
            }
        }

        axutil_array_list_free(found_list, env);
    }

    return AXIS2_SUCCESS;
}

