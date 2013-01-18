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
#include <sandesha2_create_seq_msg_processor.h>
#include <sandesha2_create_seq_res_msg_processor.h>
#include <sandesha2_seq_property_mgr.h>
#include <sandesha2_create_seq_mgr.h>
#include <sandesha2_permanent_seq_property_mgr.h>
#include <sandesha2_permanent_create_seq_mgr.h>
#include <sandesha2_permanent_next_msg_mgr.h>
#include <sandesha2_seq_property_bean.h>
#include <sandesha2_fault_mgr.h>
#include <sandesha2_constants.h>
#include <sandesha2_utils.h>
#include <sandesha2_msg_ctx.h>
#include <axis2_msg_ctx.h>
#include <axutil_string.h>
#include <axis2_engine.h>
#include <axiom_soap_const.h>
#include <stdio.h>
#include <axis2_msg_ctx.h>
#include <sandesha2_create_seq.h>
#include <axis2_conf_ctx.h>
#include <axis2_core_utils.h>
#include <sandesha2_create_seq_res.h>
#include <sandesha2_seq_offer.h>
#include <sandesha2_accept.h>
#include <sandesha2_address.h>
#include <sandesha2_acks_to.h>
#include <sandesha2_create_seq_res.h>
#include <axutil_uuid_gen.h>
#include <sandesha2_create_seq_bean.h>
#include <axis2_endpoint_ref.h>
#include <axis2_op_ctx.h>
#include <sandesha2_spec_specific_consts.h>
#include <sandesha2_msg_creator.h>
#include <sandesha2_seq_mgr.h>

/** 
 * @brief Create Sequence Message Processor struct impl
 *	Sandesha2 Create Sequence Msg Processor
 */
typedef struct sandesha2_create_seq_msg_processor_impl 
                        sandesha2_create_seq_msg_processor_impl_t;  
  
struct sandesha2_create_seq_msg_processor_impl
{
	sandesha2_msg_processor_t msg_processor;
};

#define SANDESHA2_INTF_TO_IMPL(msg_proc) \
						((sandesha2_create_seq_msg_processor_impl_t *)(msg_proc))

static axis2_status_t AXIS2_CALL 
sandesha2_create_seq_msg_processor_process_in_msg (
    sandesha2_msg_processor_t *msg_processor,
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *rm_msg_ctx);
    
static axis2_status_t AXIS2_CALL 
sandesha2_create_seq_msg_processor_process_out_msg(
    sandesha2_msg_processor_t *msg_processor,
    const axutil_env_t *env, 
    sandesha2_msg_ctx_t *rm_msg_ctx);
    
static axis2_status_t AXIS2_CALL 
sandesha2_create_seq_msg_processor_create_seq_msg_already_received(
    const axutil_env_t *env, 
    axis2_char_t *seq_id,
    sandesha2_msg_ctx_t *rm_msg_ctx,
    sandesha2_create_seq_mgr_t *create_seq_mgr,
    sandesha2_seq_property_mgr_t *seq_property_mgr);

static axis2_bool_t AXIS2_CALL 
sandesha2_create_seq_msg_processor_offer_accepted(
    const axutil_env_t *env, 
    axis2_char_t *seq_id,
    sandesha2_msg_ctx_t *rm_msg_ctx,
    sandesha2_create_seq_mgr_t *create_seq_mgr);
                    
static axis2_status_t AXIS2_CALL 
sandesha2_create_seq_msg_processor_free (
    sandesha2_msg_processor_t *msg_processor, 
    const axutil_env_t *env);								

AXIS2_EXTERN sandesha2_msg_processor_t* AXIS2_CALL
sandesha2_create_seq_msg_processor_create(
    const axutil_env_t *env)
{
    sandesha2_create_seq_msg_processor_impl_t *msg_proc_impl = NULL;
    AXIS2_ENV_CHECK(env, NULL);
              
    msg_proc_impl =  (sandesha2_create_seq_msg_processor_impl_t *)AXIS2_MALLOC 
                        (env->allocator, 
                        sizeof(sandesha2_create_seq_msg_processor_impl_t));
	
    if(NULL == msg_proc_impl)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}
    
    msg_proc_impl->msg_processor.ops = AXIS2_MALLOC(env->allocator,
        sizeof(sandesha2_msg_processor_ops_t));
    if(NULL == msg_proc_impl->msg_processor.ops)
	{
		sandesha2_create_seq_msg_processor_free((sandesha2_msg_processor_t*)
                         msg_proc_impl, env);
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}
    
    msg_proc_impl->msg_processor.ops->process_in_msg = 
                        sandesha2_create_seq_msg_processor_process_in_msg;
    msg_proc_impl->msg_processor.ops->process_out_msg = 
    					sandesha2_create_seq_msg_processor_process_out_msg;
    msg_proc_impl->msg_processor.ops->free = sandesha2_create_seq_msg_processor_free;
                        
	return &(msg_proc_impl->msg_processor);
}


static axis2_status_t AXIS2_CALL 
sandesha2_create_seq_msg_processor_free (
    sandesha2_msg_processor_t *msg_processor, 
	const axutil_env_t *env)
{
    sandesha2_create_seq_msg_processor_impl_t *msg_proc_impl = NULL;
	AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    msg_proc_impl = SANDESHA2_INTF_TO_IMPL(msg_processor);
    
    if(NULL != msg_processor->ops)
        AXIS2_FREE(env->allocator, msg_processor->ops);
    
	AXIS2_FREE(env->allocator, SANDESHA2_INTF_TO_IMPL(msg_processor));
	return AXIS2_SUCCESS;
}


static axis2_status_t AXIS2_CALL 
sandesha2_create_seq_msg_processor_process_in_msg (
    sandesha2_msg_processor_t *msg_processor,
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *rm_msg_ctx)
{
    axis2_msg_ctx_t *create_seq_msg_ctx = NULL;
    sandesha2_create_seq_t *create_seq_part = NULL;
    axis2_conf_ctx_t *conf_ctx = NULL;
    sandesha2_msg_ctx_t *fault_rm_msg_ctx = NULL;
    axis2_msg_ctx_t *out_msg_ctx = NULL;
    sandesha2_seq_property_mgr_t *seq_prop_mgr = NULL;
    sandesha2_next_msg_mgr_t *next_msg_mgr = NULL;
    axutil_property_t *property = NULL;
    axis2_char_t *incoming_sequence_id = NULL;
    sandesha2_msg_ctx_t *rm_create_seq_res_msg_ctx = NULL;
    sandesha2_create_seq_res_t *create_seq_res_part = NULL;
    sandesha2_seq_offer_t *seq_offer = NULL;
    axis2_endpoint_ref_t *acks_to_epr = NULL;
    sandesha2_acks_to_t *acks_to = NULL;
    sandesha2_seq_property_bean_t *acks_to_bean = NULL;
    sandesha2_seq_property_bean_t *acks_to_ref_param_bean = NULL;
    axutil_array_list_t *ref_param_list = NULL;
    axis2_char_t *ref_param_list_str = NULL;
    sandesha2_seq_property_bean_t *to_bean = NULL;
    axis2_engine_t *engine = NULL;
    axis2_char_t *addr_ns_uri = NULL;
    axis2_char_t *anon_uri = NULL;
    axis2_char_t *to_addr = NULL;
    axis2_op_ctx_t *op_ctx = NULL;
    axis2_char_t *dbname = NULL;
    sandesha2_create_seq_mgr_t *create_seq_mgr = NULL;
    axis2_msg_ctx_t **msg_ctx_map = NULL;
     
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI,  
        "[sandesha2] Start:sandesha2_create_seq_msg_processor_process_in_msg");
    
    AXIS2_PARAM_CHECK(env->error, rm_msg_ctx, AXIS2_FAILURE);
    
    create_seq_msg_ctx = sandesha2_msg_ctx_get_msg_ctx(rm_msg_ctx, env);
    
    op_ctx = axis2_msg_ctx_get_op_ctx(create_seq_msg_ctx, env);
    msg_ctx_map = axis2_op_ctx_get_msg_ctx_map(op_ctx, env);
    msg_ctx_map[AXIS2_WSDL_MESSAGE_LABEL_IN] = create_seq_msg_ctx;

    create_seq_part = sandesha2_msg_ctx_get_create_seq(rm_msg_ctx, env);
    if(!create_seq_part)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] create_seq_part is NULL");
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_REQD_MSG_PART_MISSING, AXIS2_FAILURE);
        return AXIS2_FAILURE;
    }

    conf_ctx = axis2_msg_ctx_get_conf_ctx(create_seq_msg_ctx, env);
    dbname = sandesha2_util_get_dbname(env, conf_ctx);
    seq_prop_mgr = sandesha2_permanent_seq_property_mgr_create(env, dbname);
    create_seq_mgr = sandesha2_permanent_create_seq_mgr_create(env, dbname);
    next_msg_mgr = sandesha2_permanent_next_msg_mgr_create(env, dbname);
    
    /*fault_rm_msg_ctx = sandesha2_fault_mgr_check_for_create_seq_refused(env, rm_msg_ctx, seq_prop_mgr);*/
    fault_rm_msg_ctx = sandesha2_fault_mgr_check_for_create_seq_refused(env, rm_msg_ctx, seq_prop_mgr);
    if(fault_rm_msg_ctx)
    {
        axis2_engine_t *engine = NULL;

        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] A fault occurred"); 

        engine = axis2_engine_create(env, conf_ctx);
        axis2_engine_send_fault(engine, env, sandesha2_msg_ctx_get_msg_ctx(fault_rm_msg_ctx, env));
        if(fault_rm_msg_ctx)
        {
            sandesha2_msg_ctx_free(fault_rm_msg_ctx, env);
        }

        if(engine)
        {
            axis2_engine_free(engine, env);
            engine = NULL;
        }

        axis2_msg_ctx_set_paused(create_seq_msg_ctx, env, AXIS2_TRUE);

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

    out_msg_ctx = sandesha2_utils_create_out_msg_ctx(env, create_seq_msg_ctx);

    incoming_sequence_id = sandesha2_seq_mgr_setup_new_incoming_sequence(env, rm_msg_ctx, 
            seq_prop_mgr, next_msg_mgr);

    rm_create_seq_res_msg_ctx = sandesha2_msg_creator_create_create_seq_res_msg(env, rm_msg_ctx, 
            out_msg_ctx, incoming_sequence_id, seq_prop_mgr);

    axis2_msg_ctx_set_flow(out_msg_ctx, env, AXIS2_OUT_FLOW);

    if(!rm_create_seq_res_msg_ctx)
    {
        if(incoming_sequence_id)
        {
            AXIS2_FREE(env->allocator, incoming_sequence_id);
        }

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

        return AXIS2_FAILURE;
    }

    property = axutil_property_create_with_args(env, 0, 0, 0, AXIS2_VALUE_TRUE);

    /* For making sure that this won't be processed again */
    sandesha2_msg_ctx_set_property(rm_create_seq_res_msg_ctx, env, 
            SANDESHA2_APPLICATION_PROCESSING_DONE, property); 
    
    create_seq_res_part = sandesha2_msg_ctx_get_create_seq_res(rm_create_seq_res_msg_ctx, env);
    seq_offer = sandesha2_create_seq_get_seq_offer(create_seq_part, env);

    /* Offer processing */ 
    if(seq_offer)
    {
        sandesha2_accept_t *accept = NULL;
        axis2_char_t *outgoing_sequence_id = NULL;
        axis2_bool_t offer_accepted = AXIS2_FALSE;

        if(create_seq_res_part)
        {
            accept = sandesha2_create_seq_res_get_accept(create_seq_res_part, env);
        }
        if(!accept)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                    "[sandesha2] Accept part has not genereated for a message with offer");
            AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_REQD_MSG_PART_MISSING, AXIS2_FAILURE);

            if(rm_create_seq_res_msg_ctx)
            {
                sandesha2_msg_ctx_free(rm_create_seq_res_msg_ctx, env);
            }

            if(incoming_sequence_id)
            {
                AXIS2_FREE(env->allocator, incoming_sequence_id);
            }

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

            return AXIS2_FAILURE;
        }

        outgoing_sequence_id = sandesha2_identifier_get_identifier(sandesha2_seq_offer_get_identifier(
                    seq_offer, env), env);

        /* Check whether offered sequence id is valid or create sequence bean already created */
        offer_accepted = sandesha2_create_seq_msg_processor_offer_accepted(env, outgoing_sequence_id, 
                rm_msg_ctx, create_seq_mgr);

        if(offer_accepted)
        {
            /*sandesha2_create_seq_bean_t *create_seq_bean = NULL;*/
            axis2_char_t *outgoing_internal_sequence_id = NULL;
            sandesha2_seq_property_bean_t *outgoing_sequence_bean = NULL;
            sandesha2_seq_property_bean_t *outgoing_internal_sequence_bean = NULL;
    
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] Offer Accepted"); 

            /*
             * If previously a create sequence message has arrived with an offer then there is
             * a create sequence bean already created in the database. Free it. Also free
             * outgoing_internal_sequence_bean, and outgoing_sequence_bean.
             */
            sandesha2_create_seq_msg_processor_create_seq_msg_already_received(env, 
                    outgoing_sequence_id, rm_msg_ctx, create_seq_mgr, seq_prop_mgr);
            /* Note that outgoing_internal_sequence_id is derived from incoming_sequence_id. This
             * is server side. So it should be noted that in server side 
             * incoming_internal_sequence_id and outgoing_internal_sequence_id are same
             */
            outgoing_internal_sequence_id = sandesha2_utils_get_internal_sequence_id(env, 
                    incoming_sequence_id);

            /*create_seq_bean = sandesha2_create_seq_bean_create(env);
            sandesha2_create_seq_bean_set_outgoing_sequence_id(create_seq_bean, env, 
                outgoing_sequence_id);
            sandesha2_create_seq_bean_set_internal_sequence_id(create_seq_bean, env, 
                    outgoing_internal_sequence_id);

            sandesha2_create_seq_bean_set_create_seq_msg_id(create_seq_bean, env, 
                    axutil_uuid_gen(env));

            sandesha2_create_seq_mgr_insert(create_seq_mgr, env, create_seq_bean);*/
            
            outgoing_sequence_bean = sandesha2_seq_property_bean_create(env);
            if(outgoing_sequence_bean)
            {
                sandesha2_seq_property_bean_set_name(outgoing_sequence_bean, env, 
                        SANDESHA2_SEQUENCE_PROPERTY_OUTGOING_SEQUENCE_ID);

                sandesha2_seq_property_bean_set_seq_id(outgoing_sequence_bean, env, 
                        outgoing_internal_sequence_id);
                sandesha2_seq_property_bean_set_value(outgoing_sequence_bean, env, 
                        outgoing_sequence_id);
                AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] incoming_sequence_id:%s", 
                        incoming_sequence_id); 
                sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, outgoing_sequence_bean);
                sandesha2_seq_property_bean_free(outgoing_sequence_bean, env);
            }

            outgoing_internal_sequence_bean = sandesha2_seq_property_bean_create(env);
            if(outgoing_internal_sequence_bean)
            {
                sandesha2_seq_property_bean_set_name(outgoing_internal_sequence_bean, env, 
                    SANDESHA2_SEQUENCE_PROPERTY_OUTGOING_INTERNAL_SEQUENCE_ID);

                sandesha2_seq_property_bean_set_seq_id(outgoing_internal_sequence_bean, env, 
                        outgoing_sequence_id);
                sandesha2_seq_property_bean_set_value(outgoing_internal_sequence_bean, env, 
                        outgoing_internal_sequence_id);
                sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, outgoing_internal_sequence_bean);
                sandesha2_seq_property_bean_free(outgoing_internal_sequence_bean, env);
            }

            if(outgoing_internal_sequence_id)
            {
                AXIS2_FREE(env->allocator, outgoing_internal_sequence_id);
            }
        }
        else
        {
            sandesha2_msg_ctx_add_soap_envelope(rm_create_seq_res_msg_ctx, env);
        }
    }

    acks_to = sandesha2_create_seq_get_acks_to(create_seq_part, env);
    acks_to_epr = sandesha2_address_get_epr(sandesha2_acks_to_get_address(acks_to, env), env);

    if(!acks_to_epr || !axis2_endpoint_ref_get_address(acks_to_epr, env))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2]Acks to is null");
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_INVALID_EPR, AXIS2_FAILURE);

        if(rm_create_seq_res_msg_ctx)
        {
            sandesha2_msg_ctx_free(rm_create_seq_res_msg_ctx, env);
        }

        if(incoming_sequence_id)
        {
            AXIS2_FREE(env->allocator, incoming_sequence_id);
        }

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

        return AXIS2_FAILURE;
    }

    acks_to_bean = sandesha2_seq_property_bean_create_with_data(env, incoming_sequence_id, 
            SANDESHA2_SEQ_PROP_ACKS_TO_EPR, (axis2_char_t*)axis2_endpoint_ref_get_address(
                acks_to_epr, env));

    if(acks_to_bean)
    {
        sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, acks_to_bean);
        sandesha2_seq_property_bean_free(acks_to_bean, env);
    }

    ref_param_list = sandesha2_acks_to_get_ref_param_list(acks_to, env);
    if(ref_param_list)
    {
        ref_param_list_str = sandesha2_util_get_string_from_node_list(env, ref_param_list);
        acks_to_ref_param_bean = sandesha2_seq_property_bean_create_with_data(env, 
                incoming_sequence_id, SANDESHA2_SEQ_PROP_ACKS_TO_REF_PARAM, ref_param_list_str);
        
        if(ref_param_list_str)
        {
            AXIS2_FREE(env->allocator, ref_param_list_str);
        }

        if(acks_to_ref_param_bean)
        {
            sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, acks_to_ref_param_bean);
            sandesha2_seq_property_bean_free(acks_to_ref_param_bean, env);
        }
    }

    axis2_op_ctx_set_response_written(op_ctx, env, AXIS2_TRUE);
    sandesha2_seq_mgr_update_last_activated_time(env, incoming_sequence_id, seq_prop_mgr);

    engine = axis2_engine_create(env, conf_ctx);

    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2]axis2_engine_send");

    axis2_engine_send(engine, env, out_msg_ctx);
    if(engine)
    {
        axis2_engine_free(engine, env);
    }

    if(out_msg_ctx)
    {
        axis2_core_utils_reset_out_msg_ctx(env, out_msg_ctx);
        /*axis2_msg_ctx_reset_transport_out_stream(out_msg_ctx, env);*/
        axis2_msg_ctx_free(out_msg_ctx, env);
    }

    if(rm_create_seq_res_msg_ctx)
    {
        sandesha2_msg_ctx_free(rm_create_seq_res_msg_ctx, env);
    }

    to_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env, incoming_sequence_id, 
            SANDESHA2_SEQ_PROP_TO_EPR);
    if(!to_bean)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] wsa:To is not set");

        if(incoming_sequence_id)
        {
            AXIS2_FREE(env->allocator, incoming_sequence_id);
        }

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

        return AXIS2_FAILURE;
    }

    to_addr = sandesha2_seq_property_bean_get_value(to_bean, env);
    addr_ns_uri = sandesha2_utils_get_seq_property(env, incoming_sequence_id, 
            SANDESHA2_SEQ_PROP_ADDRESSING_NAMESPACE_VALUE, seq_prop_mgr);

    anon_uri = sandesha2_spec_specific_consts_get_anon_uri(env, addr_ns_uri);
    if(addr_ns_uri)
    {
        AXIS2_FREE(env->allocator, addr_ns_uri);
    }
    
    if(sandesha2_utils_is_anon_uri(env, to_addr))
    {
        axis2_op_ctx_set_response_written(op_ctx, env, AXIS2_TRUE);
    }
    else
    {
        axis2_op_ctx_set_response_written(op_ctx, env, AXIS2_FALSE);
    }

    sandesha2_seq_property_bean_free(to_bean, env);
   
    /* Pausing the flow here so that it won't go to a message receiver which is not set for this flow */
    sandesha2_msg_ctx_set_paused(rm_msg_ctx, env, AXIS2_TRUE);

    if(incoming_sequence_id)
    {
        AXIS2_FREE(env->allocator, incoming_sequence_id);
    }

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
        "[sandesha2] Exit: sandesha2_create_seq_msg_processor_process_in_msg");

    return AXIS2_SUCCESS;
    
}
    
static axis2_status_t AXIS2_CALL 
sandesha2_create_seq_msg_processor_process_out_msg(
    sandesha2_msg_processor_t *msg_processor,
    const axutil_env_t *env, 
    sandesha2_msg_ctx_t *rm_msg_ctx)
{
    AXIS2_PARAM_CHECK(env->error, rm_msg_ctx, AXIS2_FAILURE);
    
    /* TODO
     * adding the SANDESHA_LISTENER
     */
    return AXIS2_SUCCESS;
}

static axis2_status_t AXIS2_CALL 
sandesha2_create_seq_msg_processor_create_seq_msg_already_received(
    const axutil_env_t *env, 
    axis2_char_t *seq_id,
    sandesha2_msg_ctx_t *rm_msg_ctx,
    sandesha2_create_seq_mgr_t *create_seq_mgr,
    sandesha2_seq_property_mgr_t *seq_property_mgr)
{
    sandesha2_seq_property_bean_t *find_seq_property_bean = NULL;
    sandesha2_create_seq_bean_t *find_create_seq_bean = NULL;
    axutil_array_list_t *list = NULL;
    int size = 0;
    
    AXIS2_PARAM_CHECK(env->error, seq_id, AXIS2_FALSE);
    AXIS2_PARAM_CHECK(env->error, rm_msg_ctx, AXIS2_FALSE);
    AXIS2_PARAM_CHECK(env->error, create_seq_mgr, AXIS2_FALSE);
    
    find_create_seq_bean = sandesha2_create_seq_bean_create_with_data(env, NULL, NULL, seq_id);
    if(find_create_seq_bean)
    {
        list = sandesha2_create_seq_mgr_find(create_seq_mgr, env, find_create_seq_bean);
        sandesha2_create_seq_bean_free(find_create_seq_bean, env);
    }
    
    if(list)
    {
        size = axutil_array_list_size(list, env);
    }
    if(list && 0 < size)
    {
        int i = 0;
        sandesha2_create_seq_bean_t *create_seq_bean = NULL;
       
        for(i = 0; i < size; i++)
        {
            create_seq_bean = (sandesha2_create_seq_bean_t *) axutil_array_list_get(list, env, i);
            if(create_seq_bean)
            {
                sandesha2_create_seq_bean_free(create_seq_bean, env);
            }
        }
    }

    if(list)
    {
        axutil_array_list_free(list, env);
    }

    find_seq_property_bean = sandesha2_seq_property_bean_create_with_data(env, NULL, NULL, seq_id);
    if(find_seq_property_bean)
    {
        list = sandesha2_seq_property_mgr_find(seq_property_mgr, env, find_seq_property_bean);
        sandesha2_seq_property_bean_free(find_seq_property_bean, env);
    }
    
    if(list)
    {
        size = axutil_array_list_size(list, env);
    }
    if(list && 0 < size)
    {
        int i = 0;
        sandesha2_seq_property_bean_t *seq_prop_bean = NULL;
       
        for(i = 0; i < size; i++)
        {
            seq_prop_bean = (sandesha2_seq_property_bean_t *) axutil_array_list_get(list, env, i);
            if(seq_prop_bean)
            {
                axis2_char_t *internal_seq_id = NULL;
                axis2_char_t *name = NULL;

                name = sandesha2_seq_property_bean_get_name(seq_prop_bean, env);
                if(!axutil_strcmp(name, SANDESHA2_SEQUENCE_PROPERTY_OUTGOING_INTERNAL_SEQUENCE_ID))
                {
                    axutil_array_list_t *temp_list = NULL;
                    int temp_size = 0;
                    sandesha2_seq_property_bean_t *temp_find_bean = NULL;

                    internal_seq_id = sandesha2_seq_property_bean_get_value(seq_prop_bean, env);

                    temp_find_bean = sandesha2_seq_property_bean_create_with_data(env, NULL, NULL, internal_seq_id);
                    if(temp_find_bean)
                    {
                        temp_list = sandesha2_seq_property_mgr_find(seq_property_mgr, env, temp_find_bean);
                        sandesha2_seq_property_bean_free(temp_find_bean, env);
                    }
                
                    if(temp_list)
                    {
                        temp_size = axutil_array_list_size(list, env);
                    }
                    if(temp_list && 0 < temp_size)
                    {
                        int j = 0;
                        sandesha2_seq_property_bean_t *temp_seq_prop_bean = NULL;
                   
                        for(j = 0; j < temp_size; j++)
                        {
                            temp_seq_prop_bean = (sandesha2_seq_property_bean_t *) axutil_array_list_get(temp_list, env, i);
                            if(temp_seq_prop_bean)
                            {
                                sandesha2_seq_property_bean_free(temp_seq_prop_bean, env);
                            }
                        }
                    }

                    if(temp_list)
                    {
                        axutil_array_list_free(temp_list, env);
                    }
                }
                sandesha2_seq_property_bean_free(seq_prop_bean, env);
            }
        }
    }

    if(list)
    {
        axutil_array_list_free(list, env);
    }

    return AXIS2_SUCCESS;
}


static axis2_bool_t AXIS2_CALL 
sandesha2_create_seq_msg_processor_offer_accepted(
    const axutil_env_t *env, 
    axis2_char_t *seq_id,
    sandesha2_msg_ctx_t *rm_msg_ctx,
    sandesha2_create_seq_mgr_t *create_seq_mgr)
{
    AXIS2_PARAM_CHECK(env->error, seq_id, AXIS2_FALSE);
    AXIS2_PARAM_CHECK(env->error, rm_msg_ctx, AXIS2_FALSE);
    AXIS2_PARAM_CHECK(env->error, create_seq_mgr, AXIS2_FALSE);
    
    /* Single char offerings are not accepted */
    if(1 >= axutil_strlen(seq_id))
    {
        return AXIS2_FALSE;
    }
        
    return AXIS2_TRUE;
}

