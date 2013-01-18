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
#include <sandesha2_close_seq_msg_processor.h>
#include <sandesha2_seq_property_bean.h>
#include <sandesha2_storage_mgr.h>
#include <sandesha2_seq_property_mgr.h>
#include <sandesha2_create_seq_mgr.h>
#include <sandesha2_sender_mgr.h>
#include <sandesha2_next_msg_mgr.h>
#include <sandesha2_terminate_mgr.h>
#include <sandesha2_permanent_seq_property_mgr.h>
#include <sandesha2_permanent_create_seq_mgr.h>
#include <sandesha2_permanent_sender_mgr.h>
#include <sandesha2_permanent_next_msg_mgr.h>
#include <sandesha2_fault_mgr.h>
#include <sandesha2_constants.h>
#include <sandesha2_utils.h>
#include <sandesha2_msg_ctx.h>
#include <axis2_msg_ctx.h>
#include <axis2_http_transport_utils.h>
#include <axutil_string.h>
#include <axis2_engine.h>
#include <axiom_soap_const.h>
#include <stdio.h>
#include <axis2_msg_ctx.h>
#include <axis2_conf_ctx.h>
#include <sandesha2_seq_ack.h>
#include <sandesha2_close_seq.h>
#include <axutil_uuid_gen.h>
#include <sandesha2_create_seq_bean.h>
#include <sandesha2_create_seq_mgr.h>
#include <axis2_endpoint_ref.h>
#include <axis2_op_ctx.h>
#include <sandesha2_spec_specific_consts.h>
#include <axis2_core_utils.h>
#include <sandesha2_ack_mgr.h>
#include <sandesha2_msg_creator.h>
#include <sandesha2_client_constants.h>

/** 
 * @brief Close Sequence Message Processor struct impl
 *	Sandesha2 Close Sequence Msg Processor
 */
typedef struct sandesha2_close_seq_msg_processor_impl sandesha2_close_seq_msg_processor_impl_t;  
  
struct sandesha2_close_seq_msg_processor_impl
{
	sandesha2_msg_processor_t msg_processor;
};

#define SANDESHA2_INTF_TO_IMPL(msg_proc) \
						((sandesha2_close_seq_msg_processor_impl_t *)(msg_proc))

static axis2_status_t AXIS2_CALL
sandesha2_close_seq_msg_processor_process_in_msg (
    sandesha2_msg_processor_t *msg_processor,
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *rm_msg_ctx);
    
static axis2_status_t
sandesha2_close_seq_msg_processor_add_close_seq_res(
    const axutil_env_t *env, 
    sandesha2_msg_ctx_t *rm_msg_ctx,
    axis2_char_t *seq_id,
    sandesha2_seq_property_mgr_t *seq_prop_mgr);

static axis2_status_t AXIS2_CALL
sandesha2_close_seq_msg_processor_process_out_msg(
    sandesha2_msg_processor_t *msg_processor,
    const axutil_env_t *env, 
    sandesha2_msg_ctx_t *rm_msg_ctx);
                    	
static axis2_status_t AXIS2_CALL
sandesha2_close_seq_msg_processor_free (
    sandesha2_msg_processor_t *element, 
    const axutil_env_t *env);								

AXIS2_EXTERN sandesha2_msg_processor_t* AXIS2_CALL
sandesha2_close_seq_msg_processor_create(
    const axutil_env_t *env)
{
    sandesha2_close_seq_msg_processor_impl_t *msg_proc_impl = NULL;
              
    msg_proc_impl =  (sandesha2_close_seq_msg_processor_impl_t *)AXIS2_MALLOC(env->allocator, 
        sizeof(sandesha2_close_seq_msg_processor_impl_t));
	
    if(!msg_proc_impl)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}
    
    msg_proc_impl->msg_processor.ops = AXIS2_MALLOC(env->allocator,
        sizeof(sandesha2_msg_processor_ops_t));

    if(!msg_proc_impl->msg_processor.ops)
	{
		sandesha2_close_seq_msg_processor_free((sandesha2_msg_processor_t*) msg_proc_impl, env);
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}
    
    msg_proc_impl->msg_processor.ops->process_in_msg = 
                        sandesha2_close_seq_msg_processor_process_in_msg;

    msg_proc_impl->msg_processor.ops->process_out_msg = 
    					sandesha2_close_seq_msg_processor_process_out_msg;

    msg_proc_impl->msg_processor.ops->free = sandesha2_close_seq_msg_processor_free;
                        
	return &(msg_proc_impl->msg_processor);
}


static axis2_status_t AXIS2_CALL
sandesha2_close_seq_msg_processor_free(
        sandesha2_msg_processor_t *msg_processor, 
	    const axutil_env_t *env)
{
    sandesha2_close_seq_msg_processor_impl_t *msg_proc_impl = NULL;
    
    msg_proc_impl = SANDESHA2_INTF_TO_IMPL(msg_processor);
    
    if(msg_processor->ops)
    {
        AXIS2_FREE(env->allocator, msg_processor->ops);
    }
    
	AXIS2_FREE(env->allocator, SANDESHA2_INTF_TO_IMPL(msg_processor));

	return AXIS2_SUCCESS;
}


static axis2_status_t AXIS2_CALL
sandesha2_close_seq_msg_processor_process_in_msg (
    sandesha2_msg_processor_t *msg_processor,
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *rm_msg_ctx)
{
    axis2_msg_ctx_t *msg_ctx = NULL;
    axis2_conf_ctx_t *conf_ctx = NULL;
    sandesha2_seq_property_mgr_t *seq_prop_mgr = NULL;
    sandesha2_create_seq_mgr_t *create_seq_mgr = NULL;
    sandesha2_next_msg_mgr_t *next_msg_mgr = NULL;
    sandesha2_close_seq_t *close_seq = NULL;
    axis2_char_t *seq_id = NULL;
    sandesha2_msg_ctx_t *fault_rm_msg_ctx = NULL;
    sandesha2_seq_property_bean_t *close_seq_bean = NULL;
    axis2_char_t *dbname = NULL;
    
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI,  
        "[sandesha2] Entry:sandesha2_close_seq_msg_processor_process_in_msg");

    AXIS2_PARAM_CHECK(env->error, rm_msg_ctx, AXIS2_FAILURE);
    
    msg_ctx = sandesha2_msg_ctx_get_msg_ctx(rm_msg_ctx, env);
    conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);
    
    dbname = sandesha2_util_get_dbname(env, conf_ctx);
    seq_prop_mgr = sandesha2_permanent_seq_property_mgr_create(env, dbname);
    create_seq_mgr = sandesha2_permanent_create_seq_mgr_create(env, dbname);
    next_msg_mgr = sandesha2_permanent_next_msg_mgr_create(env, dbname);

    close_seq = sandesha2_msg_ctx_get_close_seq(rm_msg_ctx, env);
    
    seq_id = sandesha2_identifier_get_identifier(sandesha2_close_seq_get_identifier(close_seq, env),
            env);
    
    fault_rm_msg_ctx = sandesha2_fault_mgr_check_for_unknown_seq(env, rm_msg_ctx, seq_id, 
            seq_prop_mgr, create_seq_mgr, next_msg_mgr);

    if(fault_rm_msg_ctx)
    {
        axis2_engine_t *engine = NULL;

        engine = axis2_engine_create(env, conf_ctx);

        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2]axis2_engine_send");

        axis2_engine_send(engine, env, sandesha2_msg_ctx_get_msg_ctx(fault_rm_msg_ctx, env));
        if(fault_rm_msg_ctx)
        {
            sandesha2_msg_ctx_free(fault_rm_msg_ctx, env);
        }

        if(engine)
        {
            axis2_engine_free(engine, env);
            engine = NULL;
        }

        axis2_msg_ctx_set_paused(msg_ctx, env, AXIS2_TRUE);
        if(seq_prop_mgr)
        {
            sandesha2_seq_property_mgr_free(seq_prop_mgr, env);
        }

        if(create_seq_mgr)
        {
            sandesha2_create_seq_mgr_free(create_seq_mgr, env);
        }

        if(next_msg_mgr)
        {
            sandesha2_next_msg_mgr_free(next_msg_mgr, env);
        }

        return AXIS2_SUCCESS;
    }

    close_seq_bean = sandesha2_seq_property_bean_create(env);
    sandesha2_seq_property_bean_set_seq_id(close_seq_bean, env, seq_id);
    sandesha2_seq_property_bean_set_name(close_seq_bean, env, SANDESHA2_SEQ_PROP_SEQ_CLOSED);
    sandesha2_seq_property_bean_set_value(close_seq_bean, env, AXIS2_VALUE_TRUE);
    
    sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, close_seq_bean);
    
    sandesha2_close_seq_msg_processor_add_close_seq_res(env, rm_msg_ctx, seq_id, seq_prop_mgr);
    
    axis2_msg_ctx_set_paused(msg_ctx, env, AXIS2_TRUE);

    if(seq_prop_mgr)
    {
        sandesha2_seq_property_mgr_free(seq_prop_mgr, env);
    }

    if(create_seq_mgr)
    {
        sandesha2_create_seq_mgr_free(create_seq_mgr, env);
    }

    if(next_msg_mgr)
    {
        sandesha2_next_msg_mgr_free(next_msg_mgr, env);
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI,  
        "[sandesha2] Exit:sandesha2_close_seq_msg_processor_process_in_msg");

    return AXIS2_SUCCESS;
}
    
static axis2_status_t
sandesha2_close_seq_msg_processor_add_close_seq_res(
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

    AXIS2_PARAM_CHECK(env->error, rm_msg_ctx, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, seq_id, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, seq_prop_mgr, AXIS2_FAILURE);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[sandesha2] Entry:sandesha2_close_seq_msg_processor_add_close_seq_res");
    
    msg_ctx = sandesha2_msg_ctx_get_msg_ctx(rm_msg_ctx, env);
    out_msg_ctx = sandesha2_utils_create_out_msg_ctx(env, msg_ctx);
    out_rm_msg = sandesha2_msg_creator_create_close_seq_res_msg(env, rm_msg_ctx, out_msg_ctx, 
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

    engine = axis2_engine_create(env, axis2_msg_ctx_get_conf_ctx(msg_ctx, env));

    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] axis2_engine_send");

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
            "[sandesha2] Exit:sandesha2_close_seq_msg_processor_add_close_seq_res");

    return AXIS2_SUCCESS;
}

/**
 * This function is invoked in RM 1.1 where client explicitly send the 
 * close sequence message
 */
static axis2_status_t AXIS2_CALL
sandesha2_close_seq_msg_processor_process_out_msg(
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
    axis2_op_t *old_op = NULL;
    axis2_op_t *out_in_op = NULL;
    axutil_qname_t *qname = NULL;
    sandesha2_close_seq_t *close_seq = NULL;
    sandesha2_identifier_t *identifier = NULL;
    axis2_char_t *rm_version = NULL;
    axis2_char_t *rm_ns_value = NULL;
    axis2_char_t *transport_to = NULL;
    axis2_char_t *temp_action = NULL;
    axutil_string_t *soap_action = NULL;
    axis2_char_t *dbname = NULL;
    axiom_soap_envelope_t *envelope = NULL;
    sandesha2_seq_property_bean_t *last_out_msg_no_bean = NULL;
    axis2_char_t *reply_to_addr = NULL;
    sandesha2_seq_property_bean_t *reply_to_bean = NULL;
    axis2_bool_t is_svr_side = AXIS2_FALSE;
    
    AXIS2_PARAM_CHECK(env->error, rm_msg_ctx, AXIS2_FAILURE);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI,  
        "[sandesha2] Entry:sandesha2_close_seq_msg_processor_process_out_msg");
    
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
                "[sandesha2] seq_id was not found. Cannot send the close sequence message");

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

    old_op = axis2_msg_ctx_get_op(msg_ctx, env);
    
    qname = axutil_qname_create(env, "temp", NULL, NULL); 
    out_in_op = axis2_op_create_with_qname(env, qname);
    if(qname)
    {
        axutil_qname_free(qname, env);
    }

    axis2_op_set_msg_exchange_pattern(out_in_op, env, AXIS2_MEP_URI_OUT_IN);
    axis2_op_set_in_flow(out_in_op, env, axis2_op_get_in_flow(old_op, env));

    /*close_seq = sandesha2_msg_ctx_get_close_seq(rm_msg_ctx, env);
    sandesha2_identifier_set_identifier(sandesha2_close_seq_get_identifier(close_seq, env), 
            env, out_seq_id);*/

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

    /* Handling the case where reply to address is anonymous */
    reply_to_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env, int_seq_id, 
            SANDESHA2_SEQ_PROP_REPLY_TO_EPR);
    if(reply_to_bean)
    {
        reply_to_addr = axutil_strdup(env, sandesha2_seq_property_bean_get_value(reply_to_bean, env));
    }
    is_svr_side = axis2_msg_ctx_get_server_side(msg_ctx, env);
    if(!is_svr_side && (!reply_to_addr || sandesha2_utils_is_anon_uri(env, reply_to_addr)))
    {
        sandesha2_seq_property_bean_t *to_bean = NULL;
        axis2_endpoint_ref_t *to_epr = NULL;
        sandesha2_seq_property_bean_t *transport_to_bean = NULL;
        axis2_char_t *temp_action = NULL;
        axutil_string_t *soap_action = NULL;
        axis2_engine_t *engine = NULL;
        sandesha2_msg_ctx_t *close_rm_msg_ctx = NULL;
        axis2_msg_ctx_t *close_msg_ctx = NULL;

        close_rm_msg_ctx = sandesha2_msg_creator_create_close_seq_msg(env, rm_msg_ctx, 
            out_seq_id, int_seq_id, seq_prop_mgr);

        if(!close_rm_msg_ctx)
        {
            axis2_msg_ctx_set_paused(msg_ctx, env, AXIS2_TRUE);
            return AXIS2_FAILURE;
        }
    
        close_msg_ctx = sandesha2_msg_ctx_get_msg_ctx(close_rm_msg_ctx, env);
        sandesha2_msg_ctx_set_flow(rm_msg_ctx, env, AXIS2_OUT_FLOW);
        property = axutil_property_create_with_args(env, 0, 0, 0, AXIS2_VALUE_TRUE);
        axis2_msg_ctx_set_property(msg_ctx, env, SANDESHA2_APPLICATION_PROCESSING_DONE, property);
        to_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env, int_seq_id, 
            SANDESHA2_SEQ_PROP_TO_EPR);

        if(to_bean)
        {
            axis2_char_t *temp_addr = NULL;

            temp_addr = sandesha2_seq_property_bean_get_value(to_bean, env);
            to_epr = axis2_endpoint_ref_create(env, temp_addr);
            sandesha2_seq_property_bean_free(to_bean, env);
        }

        if(to_epr)
        {
            const axis2_char_t *to_addr = NULL;

            to_addr = axis2_endpoint_ref_get_address(to_epr, env);
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "to_addr:%s", to_addr);
            sandesha2_msg_ctx_set_to(close_rm_msg_ctx, env, to_epr);
        }
        sandesha2_msg_ctx_set_wsa_action(close_rm_msg_ctx, env, 
            sandesha2_spec_specific_consts_get_close_seq_action(env, rm_version));

        temp_action = sandesha2_spec_specific_consts_get_close_seq_action(env, rm_version);
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "temp_action:%s", temp_action);
        soap_action = axutil_string_create(env, temp_action);
        if(soap_action)
        {
            sandesha2_msg_ctx_set_soap_action(close_rm_msg_ctx, env, soap_action);
            axutil_string_free(soap_action, env);
        }

        transport_to_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env, int_seq_id, 
            SANDESHA2_SEQ_PROP_TRANSPORT_TO);

        if(transport_to_bean)
        {
            axis2_char_t *value = sandesha2_seq_property_bean_get_value(transport_to_bean, env);
            property = axutil_property_create_with_args(env, 0, 0, 0, value);
            sandesha2_msg_ctx_set_property(close_rm_msg_ctx, env, AXIS2_TRANSPORT_URL, property);
        }

        if(!sandesha2_util_is_ack_already_piggybacked(env, close_rm_msg_ctx))
        {
            sandesha2_ack_mgr_piggyback_acks_if_present(env, out_seq_id, close_rm_msg_ctx, 
                storage_mgr, seq_prop_mgr, sender_mgr);
        }
    
        sandesha2_msg_ctx_add_soap_envelope(close_rm_msg_ctx, env);
        engine = axis2_engine_create(env, conf_ctx);
        if(AXIS2_SUCCESS == axis2_engine_send(engine, env, close_msg_ctx))
        {
            axiom_soap_envelope_t *res_envelope = NULL;
            axis2_char_t *soap_ns_uri = NULL;
            
            soap_ns_uri = axis2_msg_ctx_get_is_soap_11(close_msg_ctx, env) ?
                 AXIOM_SOAP11_SOAP_ENVELOPE_NAMESPACE_URI:
                 AXIOM_SOAP12_SOAP_ENVELOPE_NAMESPACE_URI;

            res_envelope = axis2_msg_ctx_get_response_soap_envelope(close_msg_ctx, env);
            if(!res_envelope)
            {
                AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] Response envelope not found");

                res_envelope = (axiom_soap_envelope_t *) axis2_http_transport_utils_create_soap_msg(
                        env, close_msg_ctx, soap_ns_uri);
            }

            if(res_envelope)
            {
                if(AXIS2_SUCCESS != sandesha2_terminate_mgr_process_response(env, 
                            close_msg_ctx, storage_mgr))
                {
                    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                        "[sandesha2] Close message response process failed for sequence %s", 
                        int_seq_id);
                }
            }
        }

        axis2_msg_ctx_set_paused(msg_ctx, env, AXIS2_TRUE);
        
        return AXIS2_SUCCESS;

    }

    /* Continue if reply to address is not anonymous */

    rm_ns_value = sandesha2_spec_specific_consts_get_rm_ns_val(env, rm_version);
    close_seq = sandesha2_close_seq_create(env, rm_ns_value);
    identifier = sandesha2_identifier_create(env, rm_ns_value);
    sandesha2_identifier_set_identifier(identifier, env, out_seq_id);
    sandesha2_close_seq_set_identifier(close_seq, env, identifier);
    last_out_msg_no_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env, 
        int_seq_id, SANDESHA2_SEQ_PROP_LAST_OUT_MESSAGE_NUMBER);
    if(last_out_msg_no_bean)
    {
        axis2_char_t *last_msg_num_str = NULL;

        last_msg_num_str = sandesha2_seq_property_bean_get_value(last_out_msg_no_bean, env);
        if(last_msg_num_str)
        {
            sandesha2_last_msg_number_t *last_msg_number = NULL;
            
            last_msg_number = sandesha2_last_msg_number_create(env, rm_ns_value);
            if(last_msg_number)
            {
                long last_msg_num = -1;

                AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "last msg no:%s", last_msg_num_str);
                last_msg_num = axutil_atol(last_msg_num_str);
                
                sandesha2_last_msg_number_set_last_msg_number(last_msg_number, env, last_msg_num);
                sandesha2_close_seq_set_last_msg_number(close_seq, env, last_msg_number);
            }
        }
    }
    envelope = axis2_msg_ctx_get_soap_envelope(msg_ctx, env);
    sandesha2_close_seq_to_soap_envelope(close_seq, env, envelope);
    axis2_msg_ctx_set_wsa_action(msg_ctx, env, 
            sandesha2_spec_specific_consts_get_close_seq_action(env, rm_version));

    temp_action = sandesha2_spec_specific_consts_get_close_seq_action(env, rm_version);

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
        sandesha2_msg_ctx_add_soap_envelope(rm_msg_ctx, env);
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

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI,  
        "[sandesha2] Exit:sandesha2_close_seq_msg_processor_process_out_msg");

    return AXIS2_SUCCESS;
}

