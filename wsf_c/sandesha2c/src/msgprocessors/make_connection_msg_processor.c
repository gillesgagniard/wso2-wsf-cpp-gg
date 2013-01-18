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
#include <sandesha2_make_connection_msg_processor.h>
#include <sandesha2_make_connection.h>
#include <sandesha2_seq_property_mgr.h>
#include <sandesha2_sender_mgr.h>
#include <sandesha2_permanent_seq_property_mgr.h>
#include <sandesha2_permanent_create_seq_mgr.h>
#include <sandesha2_permanent_sender_mgr.h>
#include "../storage/sqlite/sandesha2_permanent_bean_mgr.h"
#include <sandesha2_seq_property_bean.h>
#include <sandesha2_storage_mgr.h>
#include <sandesha2_fault_mgr.h>
#include <sandesha2_constants.h>
#include <sandesha2_utils.h>
#include <sandesha2_msg_ctx.h>
#include <sandesha2_spec_specific_consts.h>
#include <sandesha2_address.h>
#include <sandesha2_identifier.h>
#include <sandesha2_msg_pending.h>
#include <sandesha2_msg_init.h>
#include <sandesha2_sender_bean.h>
#include <sandesha2_terminate_seq.h>
#include <sandesha2_terminate_seq_res.h>
#include <sandesha2_seq.h>
#include <axis2_msg_ctx.h>
#include <axutil_string.h>
#include <axis2_engine.h>
#include <axiom_soap_const.h>
#include <axis2_msg_ctx.h>
#include <axis2_conf_ctx.h>
#include <axis2_core_utils.h>
#include <axutil_uuid_gen.h>
#include <axis2_endpoint_ref.h>
#include <axis2_op_ctx.h>
#include <axis2_transport_out_desc.h>
#include <axis2_http_transport.h>
#include <axis2_http_out_transport_info.h>
#include <axutil_types.h>
#include <sandesha2_msg_retrans_adjuster.h>
#include <sandesha2_terminate_mgr.h>


/** 
 * @brief Make Connection Message Processor struct impl
 *	Sandesha2 Make Connection Msg Processor
 */
typedef struct sandesha2_make_connection_msg_processor_impl 
                        sandesha2_make_connection_msg_processor_impl_t;  
  
struct sandesha2_make_connection_msg_processor_impl
{
	sandesha2_msg_processor_t msg_processor;
};

#define SANDESHA2_INTF_TO_IMPL(msg_proc) \
    ((sandesha2_make_connection_msg_processor_impl_t *)(msg_proc))

static int 
sandesha2_make_connection_msg_processor_find_callback(
    void *not_used, 
    int argc, 
    char **argv, 
    char **col_name)
{
    int i = 0;
    sandesha2_sender_bean_t *bean = NULL;
    sandesha2_bean_mgr_args_t *args = (sandesha2_bean_mgr_args_t *) not_used;
    const axutil_env_t *env = args->env;
    axutil_array_list_t *data_list = (axutil_array_list_t *) args->data;
    if(argc < 1)
    {
        args->data = NULL;
        return 0;
    }
    if(!data_list)
    {
        data_list = axutil_array_list_create(env, 0);
        args->data = data_list;
    }
    bean = sandesha2_sender_bean_create(env);
    for(i = 0; i < argc; i++)
    {
        if(0 == axutil_strcmp(col_name[i], "msg_id"))
            sandesha2_sender_bean_set_msg_id(bean, env, argv[i]);
        if(0 == axutil_strcmp(col_name[i], "msg_ctx_ref_key"))
            if(argv[i])
                sandesha2_sender_bean_set_msg_ctx_ref_key(bean, env, argv[i]);
        if(0 == axutil_strcmp(col_name[i], "internal_seq_id"))
            if(argv[i])
                sandesha2_sender_bean_set_internal_seq_id(bean, env, argv[i]);
        if(0 == axutil_strcmp(col_name[i], "sent_count"))
            sandesha2_sender_bean_set_sent_count(bean, env, AXIS2_ATOI(argv[i]));
        if(0 == axutil_strcmp(col_name[i], "msg_no"))
            sandesha2_sender_bean_set_msg_no(bean, env, atol(argv[i]));
        if(0 == axutil_strcmp(col_name[i], "send"))
            sandesha2_sender_bean_set_send(bean, env, AXIS2_ATOI(argv[i]));
        if(0 == axutil_strcmp(col_name[i], "resend"))
            sandesha2_sender_bean_set_resend(bean, env, AXIS2_ATOI(argv[i]));
        if(0 == axutil_strcmp(col_name[i], "time_to_send"))
            sandesha2_sender_bean_set_time_to_send(bean, env, atol(argv[i]));
        if(0 == axutil_strcmp(col_name[i], "msg_type"))
            sandesha2_sender_bean_set_msg_type(bean, env, AXIS2_ATOI(argv[i]));
        if(0 == axutil_strcmp(col_name[i], "seq_id"))
            if(argv[i])
                sandesha2_sender_bean_set_seq_id(bean, env, argv[i]);
        if(0 == axutil_strcmp(col_name[i], "wsrm_anon_uri"))
            if(argv[i])
                sandesha2_sender_bean_set_wsrm_anon_uri(bean, env, argv[i]);
        if(0 == axutil_strcmp(col_name[i], "to_address"))
            if(argv[i])
                sandesha2_sender_bean_set_to_address(bean, env, argv[i]);
    }
    axutil_array_list_add(data_list, env, bean);
    return 0;
}

static sandesha2_sender_bean_t *AXIS2_CALL
sandesha2_make_connection_msg_processor_get_next_msg_to_send(
    const axutil_env_t *env,
    const axis2_char_t *internal_seq_id,
    axis2_bool_t *pending,
    axis2_char_t *dbname);

static axis2_status_t AXIS2_CALL 
sandesha2_make_connection_msg_processor_process_in_msg (
    sandesha2_msg_processor_t *msg_processor,
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *rm_msg_ctx);

static void 
add_msg_pending_header(
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *return_msg_ctx,
    axis2_bool_t pending);
    
static void
set_transport_properties(
    const axutil_env_t *env,
    axis2_msg_ctx_t *return_msg_ctx,
    sandesha2_msg_ctx_t *make_conn_msg_ctx);

static axis2_status_t AXIS2_CALL 
sandesha2_make_connection_msg_processor_free (
    sandesha2_msg_processor_t *msg_processor, 
	const axutil_env_t *env);								


AXIS2_EXTERN sandesha2_msg_processor_t* AXIS2_CALL
sandesha2_make_connection_msg_processor_create(
    const axutil_env_t *env)
{
    sandesha2_make_connection_msg_processor_impl_t *msg_proc_impl = NULL;
    AXIS2_ENV_CHECK(env, NULL);
              
    msg_proc_impl =  (sandesha2_make_connection_msg_processor_impl_t *)AXIS2_MALLOC 
                        (env->allocator, 
                        sizeof(sandesha2_make_connection_msg_processor_impl_t));
	
    if(!msg_proc_impl)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}
    
    msg_proc_impl->msg_processor.ops = AXIS2_MALLOC(env->allocator,
        sizeof(sandesha2_msg_processor_ops_t));
    if(!msg_proc_impl->msg_processor.ops)
	{
		sandesha2_make_connection_msg_processor_free((sandesha2_msg_processor_t*)
                         msg_proc_impl, env);
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}
    
    msg_proc_impl->msg_processor.ops->process_in_msg = 
                        sandesha2_make_connection_msg_processor_process_in_msg;
    msg_proc_impl->msg_processor.ops->free = sandesha2_make_connection_msg_processor_free;
                        
	return &(msg_proc_impl->msg_processor);
}


static axis2_status_t AXIS2_CALL 
sandesha2_make_connection_msg_processor_free (
    sandesha2_msg_processor_t *msg_processor, 
	const axutil_env_t *env)
{
    sandesha2_make_connection_msg_processor_impl_t *msg_proc_impl = NULL;
	AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    msg_proc_impl = SANDESHA2_INTF_TO_IMPL(msg_processor);
    
    if(msg_processor->ops)
        AXIS2_FREE(env->allocator, msg_processor->ops);
    
	AXIS2_FREE(env->allocator, SANDESHA2_INTF_TO_IMPL(msg_processor));
	return AXIS2_SUCCESS;
}

/**
 * Prosesses incoming MakeConnection request messages.
 * A message is selected by the set of SenderBeans that are waiting to be sent.
 * This is processed using a SenderWorker.
 */
static axis2_status_t AXIS2_CALL 
sandesha2_make_connection_msg_processor_process_in_msg (
    sandesha2_msg_processor_t *msg_processor,
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *rm_msg_ctx)
{
    sandesha2_make_connection_t *make_conn = NULL;
    sandesha2_storage_mgr_t *storage_mgr = NULL;
    sandesha2_sender_mgr_t *sender_mgr = NULL;
    sandesha2_seq_property_mgr_t *seq_prop_mgr = NULL;
    sandesha2_create_seq_mgr_t *create_seq_mgr = NULL;
    sandesha2_sender_bean_t *sender_bean = NULL;
    sandesha2_sender_bean_t *bean1 = NULL;
    sandesha2_mc_address_t *address = NULL;
    sandesha2_identifier_t *identifier = NULL;
    sandesha2_msg_ctx_t *return_rm_msg_ctx = NULL;
    axutil_property_t *property = NULL;
    axis2_msg_ctx_t *msg_ctx = NULL;
    axis2_msg_ctx_t *return_msg_ctx = NULL;
    axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_bool_t pending = AXIS2_FALSE;
    axis2_transport_out_desc_t *transport_out = NULL;
    axis2_char_t *msg_storage_key = NULL;
    axis2_char_t *seq_id = NULL;
    axis2_char_t *internal_seq_id = NULL;
    axis2_op_ctx_t *op_ctx = NULL;
    axis2_char_t *msg_id = NULL;
    axis2_transport_sender_t *transport_sender = NULL;
    int msg_type = -1;
    axis2_bool_t continue_sending = AXIS2_TRUE;
    axis2_char_t *qualified_for_sending = NULL;
    sandesha2_property_bean_t *prop_bean = NULL;
    sandesha2_seq_property_bean_t *int_seq_bean = NULL;
    axutil_array_list_t *msgs_not_to_send = NULL;
    axis2_char_t *dbname = NULL;
    /*const axis2_char_t *wsa_action = NULL;
    axutil_string_t *soap_action = NULL;*/
    axis2_svc_t *svc = NULL;

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI,  
        "[sandesha2]Entry:sandesha2_make_connection_msg_processor_process_in_msg");

    AXIS2_PARAM_CHECK(env->error, rm_msg_ctx, AXIS2_FAILURE);

    make_conn = sandesha2_msg_ctx_get_make_connection(rm_msg_ctx, env);
    if(!make_conn)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] make_connection part is null");
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_REQD_MSG_PART_MISSING, AXIS2_FAILURE);
        return AXIS2_FAILURE;        
    }

    address = sandesha2_make_connection_get_address(make_conn, env);
    identifier = sandesha2_make_connection_get_identifier(make_conn, env);
    if(identifier)
    {
        seq_id = sandesha2_identifier_get_identifier(identifier, env);
    }

    msg_ctx = sandesha2_msg_ctx_get_msg_ctx(rm_msg_ctx, env);
    if(msg_ctx)
    {
        conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);
        axis2_msg_ctx_set_paused(msg_ctx, env, AXIS2_TRUE);
    }

    if(conf_ctx)
    {
        dbname = sandesha2_util_get_dbname(env, conf_ctx);
    }

    storage_mgr = sandesha2_utils_get_storage_mgr(env, dbname);
    if(!storage_mgr)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] Could not create storage manager.");
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_COULD_NOT_CREATE_STORAGE_MANAGER, 
                AXIS2_FAILURE);
        return AXIS2_FAILURE;
    }
    if(storage_mgr)
    {
        seq_prop_mgr = sandesha2_permanent_seq_property_mgr_create(env, dbname);
        create_seq_mgr = sandesha2_permanent_create_seq_mgr_create(env, dbname);
        sender_mgr = sandesha2_permanent_sender_mgr_create(env, dbname);
    }

    int_seq_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env, seq_id, 
            SANDESHA2_SEQUENCE_PROPERTY_OUTGOING_INTERNAL_SEQUENCE_ID);

    if(int_seq_bean)
    {
        internal_seq_id = sandesha2_seq_property_bean_get_value(int_seq_bean, env);
    }

    sender_bean = sandesha2_make_connection_msg_processor_get_next_msg_to_send(env, internal_seq_id, 
            &pending, dbname);

    if(!sender_bean)
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2]sender_bean is NULL. So returning");

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

    svc = axis2_msg_ctx_get_svc(msg_ctx, env);

    transport_out = axis2_msg_ctx_get_transport_out_desc(msg_ctx, env);
    if(!transport_out)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[sandesha2] Cannot infer transport for the make connection request");

        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_CANNOT_INFER_TRANSPORT, AXIS2_FAILURE);

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

    msg_storage_key = sandesha2_sender_bean_get_msg_ctx_ref_key(sender_bean, env);

    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "dam_msg_storage_key:%s", msg_storage_key);

    return_msg_ctx = sandesha2_storage_mgr_retrieve_msg_ctx(storage_mgr, env, msg_storage_key, 
            conf_ctx, AXIS2_TRUE);

    if(!return_msg_ctx)
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                "[sandesha2] msg_ctx not found for the msg_storage_key:%s", msg_storage_key);

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

    /*wsa_action = axis2_msg_ctx_get_wsa_action(return_msg_ctx, env);
    soap_action = axutil_string_create(env, wsa_action);
    if(soap_action)
    {
        axis2_msg_ctx_set_soap_action(return_msg_ctx, env, soap_action);
        axutil_string_free(soap_action, env);
    }*/

    return_rm_msg_ctx = sandesha2_msg_init_init_msg(env, return_msg_ctx);
    add_msg_pending_header(env, return_rm_msg_ctx, pending);
    set_transport_properties(env, return_msg_ctx, rm_msg_ctx);
    /* Setting that the response gets written. This will be used by transports.*/
    if(msg_ctx)
    {
        op_ctx = axis2_msg_ctx_get_op_ctx(msg_ctx, env);
        axis2_op_ctx_set_response_written(op_ctx, env, AXIS2_TRUE);
    }

    msg_id = sandesha2_sender_bean_get_msg_id(sender_bean, env);
    
    continue_sending = sandesha2_msg_retrans_adjuster_adjust_retrans(env, sender_bean, conf_ctx, 
            storage_mgr, seq_prop_mgr, create_seq_mgr, sender_mgr, svc);

    if(!continue_sending)
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
            "[sandesha2] Do not continue sending the message as response to MakeConnection message");

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
    
    property = axis2_msg_ctx_get_property(msg_ctx, env, SANDESHA2_QUALIFIED_FOR_SENDING);

    if(property)
    {
        qualified_for_sending = axutil_property_get_value(property, env);
    }

    if(qualified_for_sending && 0 != axutil_strcmp(qualified_for_sending, AXIS2_VALUE_TRUE))
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
            "[sandesha2] Message is not qualified for sending as reply to MakeConnection message");

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
    
    prop_bean = sandesha2_utils_get_property_bean(env, svc);
    if(prop_bean)
    {
        msgs_not_to_send = sandesha2_property_bean_get_msg_types_to_drop(prop_bean, env);
    }

    if(msgs_not_to_send)
    {
        int j = 0;
        axis2_bool_t continue_sending = AXIS2_FALSE;

        for(j = 0; j < axutil_array_list_size(msgs_not_to_send, env); j++)
        {
            axis2_char_t *value = NULL;
            int int_val = -1;
            int msg_type = -1;
            
            value = axutil_array_list_get(msgs_not_to_send, env, j);
            int_val = atoi(value);
            msg_type = sandesha2_msg_ctx_get_msg_type(return_rm_msg_ctx, env);
            if(msg_type == int_val)
            {
                continue_sending = AXIS2_TRUE;
            }
        }

        if(continue_sending)
        {
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                    "[sandesha2] Continue Sending is true. So returning from make_connection_msg_processor");

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
    }

    msg_type = sandesha2_msg_ctx_get_msg_type(return_rm_msg_ctx, env);
    if(msg_type == SANDESHA2_MSG_TYPE_APPLICATION)
    {
        sandesha2_seq_t *seq = NULL;
        axis2_char_t *seq_id = NULL;
        sandesha2_identifier_t *identifier = NULL;
        
        seq = sandesha2_msg_ctx_get_sequence(return_rm_msg_ctx, env);
        identifier = sandesha2_seq_get_identifier(seq, env);
        seq_id = sandesha2_identifier_get_identifier(identifier, env);
    }

    transport_sender = axis2_transport_out_desc_get_sender(transport_out, env);
    AXIS2_TRANSPORT_SENDER_INVOKE(transport_sender, env, return_msg_ctx);
    bean1 = sandesha2_sender_mgr_retrieve(sender_mgr, env, msg_id);
    if(bean1)
    {
        axis2_bool_t resend = AXIS2_FALSE;
        
        resend = sandesha2_sender_bean_is_resend(sender_bean, env);
        if(resend)
        {
            sandesha2_sender_bean_set_sent_count(bean1, env, 
                sandesha2_sender_bean_get_sent_count(sender_bean, env));
            sandesha2_sender_bean_set_time_to_send(bean1, env, 
                sandesha2_sender_bean_get_time_to_send(sender_bean, env));
            sandesha2_sender_mgr_update(sender_mgr, env, bean1);
        }
        else
        {
            axis2_char_t *msg_stored_key = NULL;
            
            msg_id = sandesha2_sender_bean_get_msg_id(bean1, env);
            sandesha2_sender_mgr_remove(sender_mgr, env, msg_id);
            /* Removing the message from the storage */
            msg_stored_key = sandesha2_sender_bean_get_msg_ctx_ref_key(bean1, env);
            sandesha2_storage_mgr_remove_msg_ctx(storage_mgr, env, msg_stored_key, conf_ctx, -1);
        }

        if(bean1)
        {
            sandesha2_sender_bean_free(bean1, env);
        }
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
        "[sandesha2]Exit:sandesha2_make_connection_msg_processor_process_in_msg");

    return AXIS2_SUCCESS;
}

static void 
add_msg_pending_header(
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *return_msg_ctx,
    axis2_bool_t pending)
{
    axis2_char_t *rm_ns = NULL;
    sandesha2_msg_pending_t *msg_pending = NULL; 
    axiom_soap_envelope_t *soap_env = NULL; 
    if(return_msg_ctx)
    {
        soap_env = sandesha2_msg_ctx_get_soap_envelope(
            return_msg_ctx, env);
        rm_ns = sandesha2_msg_ctx_get_rm_ns_val(return_msg_ctx, env);
        msg_pending = sandesha2_msg_pending_create(env, rm_ns);
    }
    if(msg_pending)
    {
        sandesha2_msg_pending_set_pending(msg_pending, env, pending);
        sandesha2_msg_pending_to_soap_envelope(msg_pending, env, soap_env);
    }
}

static void
set_transport_properties(
    const axutil_env_t *env,
    axis2_msg_ctx_t *return_msg_ctx,
    sandesha2_msg_ctx_t *make_conn_msg_ctx)
{
    axutil_stream_t *out_stream = NULL;
    if(make_conn_msg_ctx && return_msg_ctx)
    {
        axis2_out_transport_info_t *out_info = NULL;
        axis2_out_transport_info_t *temp_out_info = NULL;
        out_stream = sandesha2_msg_ctx_get_transport_out_stream(make_conn_msg_ctx, 
            env);
        axis2_msg_ctx_set_transport_out_stream(return_msg_ctx, env, out_stream);
        temp_out_info = (axis2_out_transport_info_t *) 
            axis2_msg_ctx_get_out_transport_info(return_msg_ctx, env);
        if(!temp_out_info)
        {
            out_info = (axis2_out_transport_info_t *) 
                sandesha2_msg_ctx_get_out_transport_info(make_conn_msg_ctx, env);
            axis2_msg_ctx_set_out_transport_info(return_msg_ctx, env, out_info);
        }
    }
}

static sandesha2_sender_bean_t *AXIS2_CALL
sandesha2_make_connection_msg_processor_get_next_msg_to_send(
    const axutil_env_t *env,
    const axis2_char_t *internal_seq_id,
    axis2_bool_t *pending,
    axis2_char_t *dbname)
{
    int i = 0;
    int index = -1;
    int match_list_size = 0;
    axutil_array_list_t *match_list = NULL;
    axis2_char_t sql_find[1024];
    long time_now = 0;
    sandesha2_sender_bean_t *result = NULL;
    sandesha2_permanent_bean_mgr_t *bean_mgr = NULL;

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[sandesha2] Entry:sandesha2_make_connection_msg_processor_get_next_msg_to_send");

    sprintf(sql_find, "select msg_id, msg_ctx_ref_key, "\
        "internal_seq_id, sent_count, msg_no, send, resend, "\
        "time_to_send, msg_type, seq_id, wsrm_anon_uri, "\
        "to_address from sender where ");

    time_now = sandesha2_utils_get_current_time_in_millis(env);
    if(time_now > 0)
    {
        sprintf(sql_find + axutil_strlen(sql_find), "time_to_send <= %ld ", time_now);
    }

    if(internal_seq_id)
    {
        sprintf(sql_find + axutil_strlen(sql_find), "and internal_seq_id='%s'", internal_seq_id);
    }

    sprintf(sql_find + axutil_strlen(sql_find), " and send=%d", AXIS2_TRUE);

    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "sql_find:%s", sql_find);

    bean_mgr = sandesha2_permanent_bean_mgr_create(env, dbname, SANDESHA2_BEAN_MAP_RETRANSMITTER);

    match_list = sandesha2_permanent_bean_mgr_find(bean_mgr, env, 
            sandesha2_make_connection_msg_processor_find_callback, sql_find);

    match_list_size = axutil_array_list_size(match_list, env);

    if(match_list_size > 1)
    {
        *pending = AXIS2_TRUE;
    }

    /*
     * We either return an application message or an RM message. If we find
     * an application message first then we carry on through the list to be
     * sure that we send the lowest app message avaliable. If we hit a RM
     * message first then we are done.
     */
    for(i = 0; i < match_list_size; i++)
    {
        sandesha2_sender_bean_t *bean = NULL;
        int msg_type = -1;

        bean = (sandesha2_sender_bean_t *) axutil_array_list_get(match_list, env, i);
        msg_type = sandesha2_sender_bean_get_msg_type(bean, env);
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] msg_type:%d", msg_type);

        if(msg_type == SANDESHA2_MSG_TYPE_ACK)
        {
            /* For the time being we do not send acknowledgement messages in the make connection 
             * back channel 
             */
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                    "[sandesha2] ack msg type is still not supported for MakeConnection channel");

            continue;
        }
        
        if(msg_type == SANDESHA2_MSG_TYPE_MAKE_CONNECTION_MSG)
        {
            continue;
        }

        if(msg_type == SANDESHA2_MSG_TYPE_APPLICATION)
        {
            long msg_no = sandesha2_sender_bean_get_msg_no(bean, env);
            long result_msg_no = -1;

            if(result)
            {
                result_msg_no = sandesha2_sender_bean_get_msg_no(result, env);
            }

            if(!result || result_msg_no > msg_no)
            {
                result = bean;
                index = i;
            }
        }
        else if(!result)
        {
            result = bean;
            index = i;
        }
    }

    result = axutil_array_list_remove(match_list, env, index);
    if(match_list)
    {
        int j = 0, sizej = 0;

        sizej = axutil_array_list_size(match_list, env);
        for(j = 0; j < sizej; j++)
        {
            sandesha2_sender_bean_t *temp_bean = NULL;
            temp_bean = axutil_array_list_get(match_list, env, j);
            sandesha2_sender_bean_free(temp_bean, env);
        }

        axutil_array_list_free(match_list, env);
    }

    if(bean_mgr)
    {
        sandesha2_permanent_bean_mgr_free(bean_mgr, env);
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[sandesha2] Exit:sandesha2_make_connection_msg_processor_get_next_msg_to_send");

    return result;
}

