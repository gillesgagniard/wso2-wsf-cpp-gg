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
#include <sandesha2_terminate_seq_msg_processor.h>
#include <sandesha2_app_msg_processor.h>
#include <sandesha2_seq_property_mgr.h>
#include <sandesha2_create_seq_mgr.h>
#include <sandesha2_sender_mgr.h>
#include <sandesha2_permanent_seq_property_mgr.h>
#include <sandesha2_permanent_create_seq_mgr.h>
#include <sandesha2_permanent_sender_mgr.h>
#include <sandesha2_permanent_next_msg_mgr.h>
#include <sandesha2_seq_property_bean.h>
#include <sandesha2_storage_mgr.h>
#include <sandesha2_fault_mgr.h>
#include <sandesha2_constants.h>
#include <sandesha2_utils.h>
#include <sandesha2_msg_ctx.h>
#include <sandesha2_terminate_seq.h>
#include <sandesha2_sender_bean.h>
#include <axis2_msg_ctx.h>
#include <axutil_string.h>
#include <axis2_engine.h>
#include <axiom_soap_const.h>
#include <stdio.h>
#include <sandesha2_storage_mgr.h>
#include <axis2_msg_ctx.h>
#include <axis2_conf_ctx.h>
#include <axis2_core_utils.h>
#include <sandesha2_seq_ack.h>
#include <sandesha2_create_seq_res.h>
#include <axutil_uuid_gen.h>
#include <sandesha2_create_seq_bean.h>
#include <axis2_endpoint_ref.h>
#include <axis2_op_ctx.h>
#include <sandesha2_spec_specific_consts.h>
#include <sandesha2_ack_msg_processor.h>
#include <sandesha2_seq.h>
#include <sandesha2_client_constants.h>
#include <sandesha2_msg_init.h>
#include <sandesha2_msg_creator.h>
#include <sandesha2_ack_mgr.h>
#include <sandesha2_terminate_mgr.h>
#include <sandesha2_seq_mgr.h>
#include <axis2_transport_out_desc.h>
/** 
 * @brief Terminate Sequence Message Processor struct impl
 *	Sandesha2 Terminate Sequence Msg Processor
 */
typedef struct sandesha2_terminate_seq_msg_processor_impl 
    sandesha2_terminate_seq_msg_processor_impl_t;  
  
struct sandesha2_terminate_seq_msg_processor_impl
{
	sandesha2_msg_processor_t msg_processor;
};

#define SANDESHA2_INTF_TO_IMPL(msg_proc) \
    ((sandesha2_terminate_seq_msg_processor_impl_t *)\
    (msg_proc))

static axis2_status_t AXIS2_CALL 
sandesha2_terminate_seq_msg_processor_process_in_msg (
    sandesha2_msg_processor_t *msg_processor,
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *rm_msg_ctx);

static axis2_status_t AXIS2_CALL 
sandesha2_terminate_seq_msg_processor_process_out_msg(
    sandesha2_msg_processor_t *msg_processor,
    const axutil_env_t *env, 
    sandesha2_msg_ctx_t *rm_msg_ctx);
    
static axis2_status_t AXIS2_CALL 
sandesha2_terminate_seq_msg_processor_setup_highest_msg_nums(
    const axutil_env_t *env, 
    axis2_conf_ctx_t *conf_ctx,
    sandesha2_storage_mgr_t *storage_mgr,
    axis2_char_t *seq_id,
    sandesha2_msg_ctx_t *rm_msg_ctx,
    sandesha2_seq_property_mgr_t *seq_prop_mgr,
    sandesha2_create_seq_mgr_t *create_seq_mgr,
    sandesha2_sender_mgr_t *sender_mgr);

static axis2_status_t AXIS2_CALL 
sandesha2_terminate_seq_msg_processor_add_terminate_seq_res(
    const axutil_env_t *env, 
    sandesha2_msg_ctx_t *rm_msg_ctx,
    axis2_char_t *seq_id,
    sandesha2_seq_property_mgr_t *seq_prop_mgr);
                    
static axis2_status_t AXIS2_CALL 
sandesha2_terminate_seq_msg_processor_free (
    sandesha2_msg_processor_t *msg_processor, 
	const axutil_env_t *env);								


AXIS2_EXTERN sandesha2_msg_processor_t* AXIS2_CALL
sandesha2_terminate_seq_msg_processor_create(
    const axutil_env_t *env)
{
    sandesha2_terminate_seq_msg_processor_impl_t *msg_proc_impl = NULL;
              
    msg_proc_impl =  ( sandesha2_terminate_seq_msg_processor_impl_t *)AXIS2_MALLOC 
        (env->allocator, 
        sizeof( sandesha2_terminate_seq_msg_processor_impl_t));
	
    if(!msg_proc_impl)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}
    
    msg_proc_impl->msg_processor.ops = AXIS2_MALLOC(env->allocator,
        sizeof(sandesha2_msg_processor_ops_t));
    if(!msg_proc_impl->msg_processor.ops)
	{
        sandesha2_terminate_seq_msg_processor_free((sandesha2_msg_processor_t*)
            msg_proc_impl, env);
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}
    
    msg_proc_impl->msg_processor.ops->process_in_msg = 
        sandesha2_terminate_seq_msg_processor_process_in_msg;
    msg_proc_impl->msg_processor.ops->process_out_msg = 
    	sandesha2_terminate_seq_msg_processor_process_out_msg;
    msg_proc_impl->msg_processor.ops->free = 
        sandesha2_terminate_seq_msg_processor_free;
                        
	return &(msg_proc_impl->msg_processor);
}


static axis2_status_t AXIS2_CALL 
sandesha2_terminate_seq_msg_processor_free (
    sandesha2_msg_processor_t *msg_processor, 
    const axutil_env_t *env)
{
    sandesha2_terminate_seq_msg_processor_impl_t *msg_proc_impl = NULL;
    msg_proc_impl = SANDESHA2_INTF_TO_IMPL(msg_processor);
    
    if(msg_processor->ops)
        AXIS2_FREE(env->allocator, msg_processor->ops);
    
	AXIS2_FREE(env->allocator, SANDESHA2_INTF_TO_IMPL(msg_processor));
	return AXIS2_SUCCESS;
}


static axis2_status_t AXIS2_CALL 
sandesha2_terminate_seq_msg_processor_process_in_msg (
    sandesha2_msg_processor_t *msg_processor,
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *rm_msg_ctx)
{
    axis2_msg_ctx_t *terminate_msg_ctx = NULL;
    sandesha2_terminate_seq_t *term_seq = NULL;
    axis2_char_t *rmd_sequence_id = NULL;
    axis2_conf_ctx_t *conf_ctx = NULL;
    sandesha2_storage_mgr_t *storage_mgr = NULL;
    sandesha2_seq_property_mgr_t *seq_prop_mgr = NULL;
    sandesha2_create_seq_mgr_t *create_seq_mgr = NULL;
    sandesha2_sender_mgr_t *sender_mgr = NULL;
    sandesha2_next_msg_mgr_t *next_msg_mgr = NULL;
    sandesha2_msg_ctx_t *fault_ctx = NULL;
    axis2_char_t *spec_version = NULL;
    axis2_char_t *dbname = NULL;
    sandesha2_seq_ack_t *seq_ack = NULL;
    axis2_op_ctx_t *op_ctx = NULL;
    /*sandesha2_seq_property_bean_t *term_rcvd_bean = NULL;*/
  
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI,  
        "[sandesha2]Entry:sandesha2_terminate_seq_msg_processor_process_in_msg");

    AXIS2_PARAM_CHECK(env->error, rm_msg_ctx, AXIS2_FAILURE);

    terminate_msg_ctx = sandesha2_msg_ctx_get_msg_ctx(rm_msg_ctx, env);

    if(axis2_msg_ctx_get_server_side(terminate_msg_ctx, env))
    {
        axis2_msg_ctx_t **msg_ctx_map = NULL;

        op_ctx = axis2_msg_ctx_get_op_ctx(terminate_msg_ctx, env);
        msg_ctx_map = axis2_op_ctx_get_msg_ctx_map(op_ctx, env);
        msg_ctx_map[AXIS2_WSDL_MESSAGE_LABEL_IN] = terminate_msg_ctx;
    }
    
    term_seq = sandesha2_msg_ctx_get_terminate_seq(rm_msg_ctx, env);
    if(!term_seq)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[sandesha2] Terminate Sequence part is not available");

        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_REQD_MSG_PART_MISSING, AXIS2_FAILURE);

        return AXIS2_FAILURE;
    }

    rmd_sequence_id = sandesha2_identifier_get_identifier(sandesha2_terminate_seq_get_identifier(
        term_seq, env), env);
    if(!rmd_sequence_id || 0 == axutil_strlen(rmd_sequence_id))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] Invalid sequence id");

        return AXIS2_FAILURE;
    }

    conf_ctx = axis2_msg_ctx_get_conf_ctx(terminate_msg_ctx, env);
    dbname = sandesha2_util_get_dbname(env, conf_ctx);
    storage_mgr = sandesha2_utils_get_storage_mgr(env, dbname);
    if(!storage_mgr)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] Could not create storage manager.");
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_COULD_NOT_CREATE_STORAGE_MANAGER, 
                AXIS2_FAILURE);
        return AXIS2_FAILURE;
    }
    seq_prop_mgr = sandesha2_permanent_seq_property_mgr_create(env, dbname);
    create_seq_mgr = sandesha2_permanent_create_seq_mgr_create(env, dbname);
    sender_mgr = sandesha2_permanent_sender_mgr_create(env, dbname);
    next_msg_mgr = sandesha2_permanent_next_msg_mgr_create(env, dbname);
    fault_ctx = sandesha2_fault_mgr_check_for_unknown_seq(env, rm_msg_ctx, rmd_sequence_id, seq_prop_mgr, 
            create_seq_mgr, next_msg_mgr);

    if(fault_ctx)
    {
        axis2_engine_t *engine = NULL;

        engine = axis2_engine_create(env, conf_ctx);

        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] Send fault occurred");

        axis2_engine_send_fault(engine, env, sandesha2_msg_ctx_get_msg_ctx(fault_ctx, env));
        sandesha2_msg_ctx_free(fault_ctx, env);
        if(engine)
        {
            axis2_engine_free(engine, env);
        }

        axis2_msg_ctx_set_paused(terminate_msg_ctx, env, AXIS2_TRUE);

        if(seq_prop_mgr)
        {
            sandesha2_seq_property_mgr_free(seq_prop_mgr, env);
        }
        if(create_seq_mgr)
        {
            sandesha2_create_seq_mgr_free(create_seq_mgr, env);
        }
        if(sender_mgr)
        {
            sandesha2_sender_mgr_free(sender_mgr, env);
        }
        if(next_msg_mgr)
        {
            sandesha2_next_msg_mgr_free(next_msg_mgr, env);
        }
        if(storage_mgr)
        {
            sandesha2_storage_mgr_free(storage_mgr, env);
        }

        return AXIS2_SUCCESS;
    }

    /*term_rcvd_bean = sandesha2_seq_property_bean_create(env);
    sandesha2_seq_property_bean_set_seq_id(term_rcvd_bean, env, rmd_sequence_id);
    sandesha2_seq_property_bean_set_name(term_rcvd_bean, env, SANDESHA2_SEQ_PROP_TERMINATE_RECEIVED);
    sandesha2_seq_property_bean_set_value(term_rcvd_bean, env, AXIS2_VALUE_TRUE);
    sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, term_rcvd_bean);*/

    spec_version = sandesha2_msg_ctx_get_rm_spec_ver(rm_msg_ctx, env);
    if(sandesha2_spec_specific_consts_is_term_seq_res_reqd(env, spec_version))
    {
        sandesha2_terminate_seq_msg_processor_add_terminate_seq_res(env, rm_msg_ctx, rmd_sequence_id, 
                seq_prop_mgr);
    }

    seq_ack = sandesha2_msg_ctx_get_seq_ack(rm_msg_ctx, env);
    /* If we have received a sequence acknowldegment with the incoming terminate message then we may
     * decide to send the terminate sequence message.
     */
    if(seq_ack)
    {
        axis2_char_t *internal_sequence_id = NULL;
        axis2_char_t *rms_sequence_id = NULL;
        axis2_char_t *last_out_msg_no_str = NULL;
        long highest_out_msg_no = 0;
        sandesha2_seq_property_bean_t *terminated_bean = NULL;
        
        /* If there is a sequence acknowledgement element present in the sequence we will check
         * whether the sequence is completed. If so send a terminate sequence message.
         */
        rms_sequence_id = sandesha2_identifier_get_identifier(sandesha2_seq_ack_get_identifier(
                    seq_ack, env), env);

        internal_sequence_id = sandesha2_utils_get_seq_property(env, rms_sequence_id, 
                SANDESHA2_SEQUENCE_PROPERTY_OUTGOING_INTERNAL_SEQUENCE_ID, seq_prop_mgr);

        terminated_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env, internal_sequence_id, 
                SANDESHA2_SEQ_PROP_TERMINATE_ADDED);
        if(terminated_bean)
        {
            axis2_char_t *value = sandesha2_seq_property_bean_get_value(terminated_bean, env);

            if(value && !axutil_strcmp(AXIS2_VALUE_TRUE, value))
            {
                AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                    "[sandesha2] Terminate sequence message was added previously");
            }

            sandesha2_seq_property_bean_free(terminated_bean, env);
        }
        else
        {
            /* Retrieve the message number of the RM 1.0 last message */
            last_out_msg_no_str = sandesha2_utils_get_seq_property(env, internal_sequence_id,
                SANDESHA2_SEQ_PROP_LAST_OUT_MESSAGE_NO, seq_prop_mgr);

            if(last_out_msg_no_str)
            {
                highest_out_msg_no = atol(last_out_msg_no_str);
                if(last_out_msg_no_str)
                {
                    AXIS2_FREE(env->allocator, last_out_msg_no_str);
                }
            }
            else
            {
                highest_out_msg_no = sandesha2_app_msg_processor_get_prev_msg_no(env, 
                    internal_sequence_id, seq_prop_mgr);
            }

            if(highest_out_msg_no > 0)
            {
                axis2_bool_t completed = AXIS2_FALSE;
                axutil_array_list_t *ack_range_list = NULL;

                AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] highest_out_msg_no:%ld", 
                        highest_out_msg_no);

                ack_range_list = sandesha2_seq_ack_get_ack_range_list(seq_ack, env);
                completed = sandesha2_ack_mgr_verify_seq_completion(env, ack_range_list, 
                        highest_out_msg_no);

                if(completed)
                {
                    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                            "[sandesha2] Sequence %s is completed. So adding terminate msg", 
                            rms_sequence_id); 

                    sandesha2_terminate_mgr_send_terminate_seq_msg(env, rm_msg_ctx, rms_sequence_id, 
                            internal_sequence_id, storage_mgr, seq_prop_mgr, create_seq_mgr, sender_mgr);
                }
            }

            if(internal_sequence_id)
            {
                AXIS2_FREE(env->allocator, internal_sequence_id);
            }
        }
    }
    else
    {
        sandesha2_terminate_seq_msg_processor_setup_highest_msg_nums(env, conf_ctx, storage_mgr, 
                rmd_sequence_id, rm_msg_ctx, seq_prop_mgr, create_seq_mgr, sender_mgr);
    }

    /*sandesha2_terminate_mgr_clean_recv_side_after_terminate_msg(env, conf_ctx, rmd_sequence_id, storage_mgr, 
            seq_prop_mgr, next_msg_mgr);*/

    /*transmit_bean = sandesha2_seq_property_bean_create_with_data(env, rmd_sequence_id,
        SANDESHA2_SEQ_PROP_SEQ_TERMINATED, AXIS2_VALUE_TRUE);
    sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, transmit_bean);
    sandesha2_seq_mgr_update_last_activated_time(env, rmd_sequence_id, storage_mgr);
    */

    /* We have no intention to pass this message beyond Sandesha2/C handler. So pause the message 
     * context */
    sandesha2_msg_ctx_set_paused(rm_msg_ctx, env, AXIS2_TRUE);

    if(seq_prop_mgr)
    {
        sandesha2_seq_property_mgr_free(seq_prop_mgr, env);
    }

    if(create_seq_mgr)
    {
        sandesha2_create_seq_mgr_free(create_seq_mgr, env);
    }

    if(sender_mgr)
    {
        sandesha2_sender_mgr_free(sender_mgr, env);
    }

    if(next_msg_mgr)
    {
        sandesha2_next_msg_mgr_free(next_msg_mgr, env);
    }

    if(storage_mgr)
    {
        sandesha2_storage_mgr_free(storage_mgr, env);
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI,  
        "[sandesha2]Exit:sandesha2_terminate_seq_msg_processor_process_in_msg");

    return AXIS2_SUCCESS;
}

/*
 * Since we have received the terminate sequence message we determine the last in message which
 * arrived prior to this terminate message. Then we mark it as the last message. We also determine if
 * an out message is already sent related to that highest in comming message. If so then we determine
 * whether we have received ack messages for them. If so send the terminate sequence message.
 */
static axis2_status_t AXIS2_CALL 
sandesha2_terminate_seq_msg_processor_setup_highest_msg_nums(
    const axutil_env_t *env, 
    axis2_conf_ctx_t *conf_ctx,
    sandesha2_storage_mgr_t *storage_mgr,
    axis2_char_t *seq_id,
    sandesha2_msg_ctx_t *rm_msg_ctx,
    sandesha2_seq_property_mgr_t *seq_prop_mgr,
    sandesha2_create_seq_mgr_t *create_seq_mgr,
    sandesha2_sender_mgr_t *sender_mgr)
{
    axis2_char_t *highest_in_msg_num_str = NULL;
    axis2_char_t *highest_in_msg_id = NULL;
    long highest_in_msg_num = 0;
    long highest_out_msg_num = 0;
    axis2_char_t *rec_side_int_seq_id = NULL;
    axis2_bool_t add_rec_side_term = AXIS2_FALSE;
    axis2_char_t *out_seq_id = NULL;
    
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[sandesha2] Entry:sandesha2_terminate_seq_msg_processor_setup_highest_msg_nums");
    AXIS2_PARAM_CHECK(env->error, conf_ctx, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, storage_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, seq_prop_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, create_seq_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, sender_mgr, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, seq_id, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, rm_msg_ctx, AXIS2_FAILURE);
   
    /* Message number of the highest in comming message so far */
    highest_in_msg_num_str = sandesha2_utils_get_seq_property(env, seq_id,
        SANDESHA2_SEQ_PROP_HIGHEST_IN_MSG_NUMBER, seq_prop_mgr);

    /* Message id of the highest in comming message so far */
    highest_in_msg_id = sandesha2_utils_get_seq_property(env, seq_id,
        SANDESHA2_SEQ_PROP_HIGHEST_IN_MSG_ID, seq_prop_mgr);

    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] Highest_in_msg_num_str:%s",
        highest_in_msg_num_str);

    if(highest_in_msg_num_str)
    {
        if(!highest_in_msg_id)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                    "[sandesha2] highest in msg id has not been stored");

            if(highest_in_msg_num_str)
            {
                AXIS2_FREE(env->allocator, highest_in_msg_num_str);
            }

            return AXIS2_FAILURE;
        }

        highest_in_msg_num = atol(highest_in_msg_num_str);
        if(highest_in_msg_num_str)
        {
            AXIS2_FREE(env->allocator, highest_in_msg_num_str);
        }
    }

    rec_side_int_seq_id = sandesha2_utils_get_internal_sequence_id(env, seq_id);
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] rec_side_int_seq_id:%s", 
        rec_side_int_seq_id);

    if(0 == highest_in_msg_num)
    {
        add_rec_side_term = AXIS2_FALSE;
    }
    else
    {
        /* Mark up the highest inbound message as if it had the last message 
         * flag on it. We can do this because we have received the terminate sequence message. So
         * we can treat the highest in-comming message as the last message. 
         */
        sandesha2_seq_property_bean_t *last_in_msg_bean = NULL;
        axis2_char_t *highest_out_relates_to = NULL;

        last_in_msg_bean = sandesha2_seq_property_bean_create_with_data(env, seq_id, 
                SANDESHA2_SEQ_PROP_LAST_IN_MESSAGE_ID, highest_in_msg_id);

        if(last_in_msg_bean)
        {
            sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, last_in_msg_bean);
            sandesha2_seq_property_bean_free(last_in_msg_bean, env);
        }

        /* If an outbound message has already gone out which relates to the highest in message id, 
         * then we can terminate right away.
         */
        highest_out_relates_to = sandesha2_utils_get_seq_property(env, rec_side_int_seq_id, 
                SANDESHA2_SEQ_PROP_HIGHEST_OUT_RELATES_TO, seq_prop_mgr);

        if(highest_out_relates_to && 0 == axutil_strcmp(highest_out_relates_to, highest_in_msg_id))
        {
            axis2_char_t *highest_out_msg_num_str = NULL;

            highest_out_msg_num_str = sandesha2_utils_get_seq_property(env, rec_side_int_seq_id, 
                    SANDESHA2_SEQ_PROP_HIGHEST_OUT_MSG_NUMBER, seq_prop_mgr);

            highest_out_msg_num = atol(highest_out_msg_num_str);
            add_rec_side_term = AXIS2_TRUE;
            if(highest_out_msg_num_str)
            {
                AXIS2_FREE(env->allocator, highest_out_msg_num_str);
            }
        }

        if(highest_out_relates_to)
        {
            AXIS2_FREE(env->allocator, highest_out_relates_to);
        }
    }

    if(highest_in_msg_id)
    {
        AXIS2_FREE(env->allocator, highest_in_msg_id);
    }

    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] add_rec_side_term:%d", add_rec_side_term);

    out_seq_id = sandesha2_utils_get_seq_property(env, rec_side_int_seq_id,
        SANDESHA2_SEQUENCE_PROPERTY_OUTGOING_SEQUENCE_ID, seq_prop_mgr);

    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] out_seq_id:%s", out_seq_id);
    if(rec_side_int_seq_id)
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] rec_side_int_seq_id:%s", rec_side_int_seq_id);
    }
        
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] highest_out_msg_num:%d", highest_out_msg_num);

    /*if(add_rec_side_term && highest_out_msg_num > 0 && rec_side_int_seq_id && out_seq_id)*/
    if(/*highest_out_msg_num > 0 &&*/ rec_side_int_seq_id && out_seq_id)
    {
        axis2_bool_t all_acked = AXIS2_FALSE;

        all_acked = sandesha2_utils_is_all_msgs_acked_upto(env, highest_out_msg_num, 
                rec_side_int_seq_id, seq_prop_mgr);
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] all_acked:%d", all_acked);
        if(!all_acked)
        {
            all_acked = sandesha2_utils_is_all_msgs_acked_upto(env, highest_out_msg_num, out_seq_id, 
                    seq_prop_mgr);
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] all_acked:%d", all_acked);
        }

        if(all_acked)
        {
            sandesha2_terminate_mgr_send_terminate_seq_msg(env, rm_msg_ctx, out_seq_id, 
                    rec_side_int_seq_id, storage_mgr, seq_prop_mgr, create_seq_mgr, sender_mgr);
        }
    }

    if(rec_side_int_seq_id)
    {
        AXIS2_FREE(env->allocator, rec_side_int_seq_id);
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[sandesha2] Exit:sandesha2_terminate_seq_msg_processor_setup_highest_msg_nums");

    return AXIS2_SUCCESS;    
}

static axis2_status_t AXIS2_CALL 
sandesha2_terminate_seq_msg_processor_add_terminate_seq_res(
    const axutil_env_t *env, 
    sandesha2_msg_ctx_t *rm_msg_ctx,
    axis2_char_t *seq_id,
    sandesha2_seq_property_mgr_t *seq_prop_mgr)
{
    axis2_msg_ctx_t *msg_ctx = NULL;
    axis2_msg_ctx_t *out_msg_ctx = NULL;
    sandesha2_msg_ctx_t *out_rm_msg = NULL;
    sandesha2_msg_ctx_t *ack_rm_msg = NULL;
    sandesha2_seq_ack_t *seq_ack = NULL;
    axutil_property_t *property = NULL;
    axis2_engine_t *engine = NULL;
    axis2_op_ctx_t *op_ctx = NULL;
    axis2_endpoint_ref_t *to_epr = NULL;
    /*axis2_transport_out_desc_t *orig_trans_out = NULL;
    axis2_transport_out_desc_t *trans_out = NULL;
    sandesha2_sender_bean_t *term_res_bean = NULL;
    axis2_char_t *key = NULL;
    sandesha2_sender_mgr_t *retrans_mgr = NULL;*/

    AXIS2_PARAM_CHECK(env->error, rm_msg_ctx, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, seq_id, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, seq_prop_mgr, AXIS2_FAILURE);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[sandesha2] Entry:sandesha2_terminate_seq_msg_processor_add_terminate_seq_res");
    
    msg_ctx = sandesha2_msg_ctx_get_msg_ctx(rm_msg_ctx, env);
    out_msg_ctx = sandesha2_utils_create_out_msg_ctx(env, msg_ctx);
    out_rm_msg = sandesha2_msg_creator_create_terminate_seq_res_msg(env, rm_msg_ctx, out_msg_ctx, 
            seq_prop_mgr);
    if(!out_rm_msg)
    {
        return AXIS2_FAILURE;
    }

    ack_rm_msg = sandesha2_ack_mgr_generate_ack_msg(env, rm_msg_ctx, seq_id, seq_prop_mgr);
    if(ack_rm_msg)
    {
        seq_ack = sandesha2_msg_ctx_get_seq_ack(ack_rm_msg, env);
        sandesha2_msg_ctx_set_seq_ack(out_rm_msg, env, seq_ack);
    }

    sandesha2_msg_ctx_add_soap_envelope(out_rm_msg, env);
    sandesha2_msg_ctx_set_flow(out_rm_msg, env, AXIS2_OUT_FLOW);
    
    property = axutil_property_create_with_args(env, 0, 0, 0, AXIS2_VALUE_TRUE);
    axis2_msg_ctx_set_property(out_msg_ctx, env, SANDESHA2_APPLICATION_PROCESSING_DONE, property);

    /* test code */
    /*
    to_epr = axis2_msg_ctx_get_to(out_msg_ctx, env);
    if(to_epr && !sandesha2_utils_is_anon_uri(env, 
        axis2_endpoint_ref_get_address(to_epr, env)))
    {   
        axis2_msg_ctx_t *tsr_msg_ctx = axis2_core_utils_create_out_msg_ctx(env, msg_ctx);
        orig_trans_out = axis2_msg_ctx_get_transport_out_desc(tsr_msg_ctx, env);
        property = axutil_property_create_with_args(env, 0, 0, 0, orig_trans_out);
        axis2_msg_ctx_set_property(tsr_msg_ctx, env, SANDESHA2_ORIGINAL_TRANSPORT_OUT_DESC, property);
        trans_out = sandesha2_utils_get_transport_out(env);
        axis2_msg_ctx_set_transport_out_desc(tsr_msg_ctx, env, trans_out);

        key = axutil_uuid_gen(env);
        term_res_bean = sandesha2_sender_bean_create(env);
        sandesha2_sender_bean_set_msg_ctx_ref_key(term_res_bean, env, key);
        property = axutil_property_create_with_args(env, 0, 0, 0, key);
        axis2_msg_ctx_set_property(tsr_msg_ctx, env, SANDESHA2_MESSAGE_STORE_KEY, property);
        sandesha2_storage_mgr_store_msg_ctx(storage_mgr, env, key, tsr_msg_ctx);
        */  
        /* TODO: refine the terminate delay */
        /*
        sandesha2_sender_bean_set_time_to_send(term_res_bean, env, 
            sandesha2_utils_get_current_time_in_millis(env) + SANDESHA2_TERMINATE_DELAY);
        sandesha2_sender_bean_set_msg_id(term_res_bean, env,
            (axis2_char_t *) axis2_msg_ctx_get_msg_id(tsr_msg_ctx, env));
        sandesha2_sender_bean_set_send(term_res_bean, env, AXIS2_TRUE);

        property = axutil_property_create_with_args(env, 0, 0, 0, AXIS2_VALUE_TRUE);
        axis2_msg_ctx_set_property(msg_ctx, env, SANDESHA2_QUALIFIED_FOR_SENDING, property);
        sandesha2_sender_bean_set_resend(term_res_bean, env, AXIS2_FALSE);
        retrans_mgr = sandesha2_storage_mgr_get_retrans_mgr(storage_mgr, env);
        sandesha2_sender_mgr_insert(retrans_mgr, env, term_res_bean);
    }*/
    /* end test code */
    
    engine = axis2_engine_create(env, axis2_msg_ctx_get_conf_ctx(msg_ctx, env));

    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2]axis2_engine_send");

    axis2_engine_send(engine, env, out_msg_ctx); 
    op_ctx = axis2_msg_ctx_get_op_ctx(out_msg_ctx, env);
    if(to_epr)
    {
        if(sandesha2_utils_is_anon_uri(env, axis2_endpoint_ref_get_address(to_epr, 
            env)))
        {
            axis2_op_ctx_set_response_written(op_ctx, env, AXIS2_TRUE);
        }
        else
        {
            axis2_op_ctx_set_response_written(op_ctx, env, AXIS2_FALSE);
        }
    }
    else
    {
        axis2_op_ctx_set_response_written(op_ctx, env, AXIS2_TRUE);
    }

    if(engine)
    {
        axis2_engine_free(engine, env);
    }

    if(out_rm_msg)
    {
        sandesha2_msg_ctx_free(out_rm_msg, env);
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[sandesha2] Exit:sandesha2_terminate_seq_msg_processor_add_terminate_seq_res");

    return AXIS2_SUCCESS;
}

/**
 * This function is invoked in RM 1.1 where client explicitly send the 
 * terminate sequence message
 */
static axis2_status_t AXIS2_CALL 
sandesha2_terminate_seq_msg_processor_process_out_msg(
    sandesha2_msg_processor_t *msg_processor,
    const axutil_env_t *env, 
    sandesha2_msg_ctx_t *rm_msg_ctx)
{
    axis2_msg_ctx_t *msg_ctx = NULL;
    axis2_conf_ctx_t *conf_ctx = NULL;
    sandesha2_storage_mgr_t *storage_mgr = NULL;
    sandesha2_seq_property_mgr_t *seq_prop_mgr = NULL;
    sandesha2_create_seq_mgr_t *create_seq_mgr = NULL;
    sandesha2_sender_mgr_t *sender_mgr = NULL;
    axis2_char_t *to_address = NULL;
    axis2_char_t *seq_key = NULL;
    axis2_char_t *int_seq_id = NULL;
    axis2_char_t *out_seq_id = NULL;
    axutil_property_t *property = NULL;
    axis2_char_t *terminated = NULL;
    axis2_op_t *old_op = NULL;
    axis2_op_t *out_in_op = NULL;
    axutil_qname_t *qname = NULL;
    sandesha2_terminate_seq_t *term_seq_part = NULL;
    axis2_char_t *rm_version = NULL;
    axis2_char_t *transport_to = NULL;
    sandesha2_seq_property_bean_t *term_added = NULL;
    axis2_char_t *temp_action = NULL;
    axutil_string_t *soap_action = NULL;
    axis2_char_t *dbname = NULL;
    
    AXIS2_PARAM_CHECK(env->error, rm_msg_ctx, AXIS2_FAILURE);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI,  
        "[sandesha2]Entry:sandesha2_terminate_seq_msg_processor_process_out_msg.");
    
    msg_ctx = sandesha2_msg_ctx_get_msg_ctx(rm_msg_ctx, env);
    conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);
    
    dbname = sandesha2_util_get_dbname(env, conf_ctx);
    storage_mgr = sandesha2_utils_get_storage_mgr(env, dbname);
    if(!storage_mgr)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] Could not create storage manager.");
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_COULD_NOT_CREATE_STORAGE_MANAGER, 
                AXIS2_FAILURE);
        return AXIS2_FAILURE;
    }
    seq_prop_mgr = sandesha2_permanent_seq_property_mgr_create(env, dbname);
    create_seq_mgr = sandesha2_permanent_create_seq_mgr_create(env, dbname);
    sender_mgr = sandesha2_permanent_sender_mgr_create(env, dbname);
    to_address = (axis2_char_t*)axis2_endpoint_ref_get_address(axis2_msg_ctx_get_to(msg_ctx, env), 
            env);

    property = axis2_msg_ctx_get_property(msg_ctx, env, SANDESHA2_CLIENT_SEQ_KEY);
    if(property)
    {
        seq_key = axutil_property_get_value(property, env);
    }

    int_seq_id = sandesha2_utils_get_client_internal_sequence_id(env, to_address, seq_key);
    out_seq_id = sandesha2_utils_get_seq_property(env, int_seq_id, 
        SANDESHA2_SEQUENCE_PROPERTY_OUTGOING_SEQUENCE_ID, seq_prop_mgr);

    if(!out_seq_id)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[sandesha2]seq_id was not found. Cannot send the terminate message");

        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_CANNOT_FIND_SEQ_ID, AXIS2_FAILURE);
        if(seq_prop_mgr)
        {
            sandesha2_seq_property_mgr_free(seq_prop_mgr, env);
        }

        if(create_seq_mgr)
        {
            sandesha2_create_seq_mgr_free(create_seq_mgr, env);
        }

        if(sender_mgr)
        {
            sandesha2_sender_mgr_free(sender_mgr, env);
        }

        if(storage_mgr)
        {
            sandesha2_storage_mgr_free(storage_mgr, env);
        }

        return AXIS2_FAILURE;
    }

    terminated = sandesha2_utils_get_seq_property(env, int_seq_id, 
            SANDESHA2_SEQ_PROP_TERMINATE_ADDED, seq_prop_mgr);
    old_op = axis2_msg_ctx_get_op(msg_ctx, env);
    
    qname = axutil_qname_create(env, "temp", NULL, NULL); 
    out_in_op = axis2_op_create_with_qname(env, qname);
    if(qname)
    {
        axutil_qname_free(qname, env);
    }

    axis2_op_set_msg_exchange_pattern(out_in_op, env, AXIS2_MEP_URI_OUT_IN);
    axis2_op_set_in_flow(out_in_op, env, axis2_op_get_in_flow(old_op, env));

    if(terminated && !axutil_strcmp(terminated, AXIS2_VALUE_TRUE))
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] Terminate was added previously");
        if(terminated)
        {
            AXIS2_FREE(env->allocator, terminated);
        }

        if(out_seq_id)
        {
            AXIS2_FREE(env->allocator, out_seq_id);
        }

        if(seq_prop_mgr)
        {
            sandesha2_seq_property_mgr_free(seq_prop_mgr, env);
        }

        if(create_seq_mgr)
        {
            sandesha2_create_seq_mgr_free(create_seq_mgr, env);
        }

        if(sender_mgr)
        {
            sandesha2_sender_mgr_free(sender_mgr, env);
        }

        if(storage_mgr)
        {
            sandesha2_storage_mgr_free(storage_mgr, env);
        }

        return AXIS2_SUCCESS;
    }

    if(terminated)
    {
        AXIS2_FREE(env->allocator, terminated);
    }

    term_seq_part = sandesha2_msg_ctx_get_terminate_seq(rm_msg_ctx, env);
    sandesha2_identifier_set_identifier(sandesha2_terminate_seq_get_identifier(term_seq_part, env), 
            env, out_seq_id);

    sandesha2_msg_ctx_set_flow(rm_msg_ctx, env, AXIS2_OUT_FLOW);
    property = axutil_property_create_with_args(env, 0, 0, 0, AXIS2_VALUE_TRUE);
    axis2_msg_ctx_set_property(msg_ctx, env, SANDESHA2_APPLICATION_PROCESSING_DONE, property);
    axis2_msg_ctx_set_to(msg_ctx, env, axis2_endpoint_ref_create(env, to_address));
    rm_version = sandesha2_utils_get_rm_version(env, msg_ctx);
    if(!rm_version)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[sandesha2] Cant find the rm_version of the given message");

        if(out_seq_id)
        {
            AXIS2_FREE(env->allocator, out_seq_id);
        }

        if(seq_prop_mgr)
        {
            sandesha2_seq_property_mgr_free(seq_prop_mgr, env);
        }

        if(create_seq_mgr)
        {
            sandesha2_create_seq_mgr_free(create_seq_mgr, env);
        }

        if(sender_mgr)
        {
            sandesha2_sender_mgr_free(sender_mgr, env);
        }

        if(storage_mgr)
        {
            sandesha2_storage_mgr_free(storage_mgr, env);
        }

        return AXIS2_FAILURE;
    }

    axis2_msg_ctx_set_wsa_action(msg_ctx, env, 
            sandesha2_spec_specific_consts_get_terminate_seq_action(env, rm_version));

    temp_action = sandesha2_spec_specific_consts_get_terminate_seq_soap_action(env, rm_version);

    soap_action = axutil_string_create(env, temp_action);
    axis2_msg_ctx_set_soap_action(msg_ctx, env, soap_action);
    transport_to = sandesha2_utils_get_seq_property(env, int_seq_id, 
        SANDESHA2_SEQ_PROP_TRANSPORT_TO, seq_prop_mgr);

    if(transport_to)
    {
        axis2_msg_ctx_set_transport_url(msg_ctx, env, transport_to);
        AXIS2_FREE(env->allocator, transport_to);
    }

    if(!sandesha2_util_is_ack_already_piggybacked(env, rm_msg_ctx))
    {
        sandesha2_ack_mgr_piggyback_acks_if_present(env, out_seq_id, rm_msg_ctx, storage_mgr, 
                seq_prop_mgr, sender_mgr);
    }
    
    term_added = sandesha2_seq_property_bean_create(env);
    sandesha2_seq_property_bean_set_name(term_added, env, SANDESHA2_SEQ_PROP_TERMINATE_ADDED);
    sandesha2_seq_property_bean_set_seq_id(term_added, env, int_seq_id);
    if(out_seq_id)
    {
        AXIS2_FREE(env->allocator, out_seq_id);
    }

    sandesha2_seq_property_bean_set_value(term_added, env, AXIS2_VALUE_TRUE); 
    sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, term_added);

    if(seq_prop_mgr)
    {
        sandesha2_seq_property_mgr_free(seq_prop_mgr, env);
    }

    if(create_seq_mgr)
    {
        sandesha2_create_seq_mgr_free(create_seq_mgr, env);
    }

    if(sender_mgr)
    {
        sandesha2_sender_mgr_free(sender_mgr, env);
    }

    if(storage_mgr)
    {
        sandesha2_storage_mgr_free(storage_mgr, env);
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI,  
        "[sandesha2] Exit:sandesha2_terminate_seq_msg_processor_process_out_msg");

    return AXIS2_SUCCESS;
}

