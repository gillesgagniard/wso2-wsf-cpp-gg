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
#include <sandesha2_polling_mgr.h>
#include <sandesha2_constants.h>
#include <sandesha2_utils.h>
#include <sandesha2_storage_mgr.h>
#include <sandesha2_terminate_mgr.h>
#include <sandesha2_seq_property_bean.h>
#include <sandesha2_seq_property_mgr.h>
#include <sandesha2_sender_mgr.h>
#include <sandesha2_next_msg_mgr.h>
#include <sandesha2_permanent_seq_property_mgr.h>
#include <sandesha2_permanent_sender_mgr.h>
#include <sandesha2_permanent_next_msg_mgr.h>
#include <sandesha2_msg_ctx.h>
#include <sandesha2_seq.h>
#include <sandesha2_msg_init.h>
#include <sandesha2_msg_creator.h>
#include <sandesha2_sender_bean.h>
#include <axis2_addr.h>
#include <axis2_engine.h>
#include <axutil_uuid_gen.h>
#include <axutil_rand.h>
#include <stdio.h>
#include <platforms/axutil_platform_auto_sense.h>
#include <axutil_types.h>
#include <axiom_soap_const.h>
#include <axis2_http_transport_utils.h>


/** 
 * @brief Polling Manager struct impl
 *	Sandesha2 Polling Manager
 */
typedef struct sandesha2_polling_mgr_args sandesha2_polling_mgr_args_t;

struct sandesha2_polling_mgr_args
{
    axutil_env_t *env;
	axis2_conf_ctx_t *conf_ctx;
    sandesha2_msg_ctx_t *rm_msg_ctx;
    axis2_char_t *internal_sequence_id;
    axis2_char_t *sequence_id;
};
            
static axis2_status_t AXIS2_CALL
sandesha2_polling_mgr_process_make_connection_msg_response(
    const axutil_env_t *env, 
    axis2_msg_ctx_t *msg_ctx,
    sandesha2_storage_mgr_t *storage_mgr);

/**
 * Thread worker function.
 */
static void * AXIS2_THREAD_FUNC
sandesha2_polling_mgr_worker_func(
    axutil_thread_t *thd, 
    void *data);

axis2_status_t AXIS2_CALL 
sandesha2_polling_mgr_start (
    const axutil_env_t *env,
    axis2_conf_ctx_t *conf_ctx,
    sandesha2_storage_mgr_t *storage_mgr,
    sandesha2_sender_mgr_t *sender_mgr,
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axis2_char_t *internal_sequence_id,
    axis2_char_t *sequence_id,
    const axis2_char_t *reply_to)
{
    axutil_thread_t *worker_thread = NULL;
    sandesha2_polling_mgr_args_t *args = NULL;
    axis2_char_t *wsmc_anon_reply_to_uri = NULL;
    sandesha2_msg_ctx_t *make_conn_rm_msg_ctx = NULL;
    axis2_char_t *make_conn_msg_store_key = NULL;
    axis2_msg_ctx_t *make_conn_msg_ctx = NULL;
    sandesha2_sender_bean_t *make_conn_sender_bean = NULL;
    axis2_status_t status = AXIS2_SUCCESS;
    axis2_engine_t *engine = NULL;
    axiom_soap_envelope_t *res_envelope = NULL;
    axutil_property_t *property = NULL;
    
    args = AXIS2_MALLOC(env->allocator, sizeof(sandesha2_polling_mgr_args_t)); 
    args->env = axutil_init_thread_env(env);
    args->conf_ctx = conf_ctx;
    args->internal_sequence_id = (axis2_char_t *) internal_sequence_id;
    args->sequence_id = (axis2_char_t *) sequence_id;

    if(sandesha2_utils_is_wsrm_anon_reply_to(env, reply_to))
    {
        wsmc_anon_reply_to_uri = axutil_strcat(env, AXIS2_WS_RM_ANONYMOUS_URL, sequence_id, NULL);
    }

    make_conn_rm_msg_ctx = sandesha2_msg_creator_create_make_connection_msg(env, rm_msg_ctx, 
        sequence_id, internal_sequence_id, wsmc_anon_reply_to_uri, NULL);
   
    if(wsmc_anon_reply_to_uri)
    {
        AXIS2_FREE(env->allocator, wsmc_anon_reply_to_uri);
    }

    args->rm_msg_ctx = make_conn_rm_msg_ctx;

    make_conn_msg_ctx = sandesha2_msg_ctx_get_msg_ctx(make_conn_rm_msg_ctx, env);

    property = axutil_property_create_with_args(env, 0, 0, 0, AXIS2_VALUE_TRUE);
    axis2_msg_ctx_set_property(make_conn_msg_ctx, env, SANDESHA2_SEQ_PROP_MAKE_CONNECTION_OUT_PATH, 
            property);

    make_conn_sender_bean = sandesha2_sender_bean_create(env);
    if(make_conn_sender_bean)
    {
        axis2_char_t *msg_id = NULL;
        long millisecs = 0;
        axis2_endpoint_ref_t *to = NULL;

        millisecs = sandesha2_utils_get_current_time_in_millis(env);
        sandesha2_sender_bean_set_time_to_send(make_conn_sender_bean, env, millisecs);
        make_conn_msg_store_key = axutil_uuid_gen(env);
        sandesha2_sender_bean_set_msg_ctx_ref_key(make_conn_sender_bean, env, 
                make_conn_msg_store_key);
        msg_id = sandesha2_msg_ctx_get_msg_id(make_conn_rm_msg_ctx, env);
        sandesha2_sender_bean_set_msg_id(make_conn_sender_bean, env, msg_id);
        sandesha2_sender_bean_set_msg_type(make_conn_sender_bean, env, 
            SANDESHA2_MSG_TYPE_MAKE_CONNECTION_MSG);
        sandesha2_sender_bean_set_resend(make_conn_sender_bean, env, AXIS2_FALSE);
        sandesha2_sender_bean_set_send(make_conn_sender_bean, env, AXIS2_TRUE);
        sandesha2_sender_bean_set_internal_seq_id(make_conn_sender_bean, env, 
                (axis2_char_t *) internal_sequence_id);

        to = sandesha2_msg_ctx_get_to(make_conn_rm_msg_ctx, env);
        if(to)
        {
            axis2_char_t *address = NULL;
            
            address = (axis2_char_t *) axis2_endpoint_ref_get_address(
                    (const axis2_endpoint_ref_t *) to, env);
            sandesha2_sender_bean_set_to_address(make_conn_sender_bean, env, address);
        }
    }
    else
    {
        return AXIS2_FAILURE;
    }

    if(sender_mgr)
    {
        sandesha2_sender_mgr_insert(sender_mgr, env, make_conn_sender_bean);
        sandesha2_sender_bean_free(make_conn_sender_bean, env);
    }
    
    engine = axis2_engine_create(env, conf_ctx);
    status = axis2_engine_send(engine, env, make_conn_msg_ctx);
    if(engine)
    {
        axis2_engine_free(engine, env);
    }

    sandesha2_storage_mgr_store_msg_ctx(storage_mgr, env, make_conn_msg_store_key, make_conn_msg_ctx, 
            AXIS2_TRUE);

    res_envelope = axis2_msg_ctx_get_response_soap_envelope(make_conn_msg_ctx, env);

    if(!res_envelope)
    {
        axis2_char_t *soap_ns_uri = NULL;

        soap_ns_uri = axis2_msg_ctx_get_is_soap_11(make_conn_msg_ctx, env) ?
             AXIOM_SOAP11_SOAP_ENVELOPE_NAMESPACE_URI:
             AXIOM_SOAP12_SOAP_ENVELOPE_NAMESPACE_URI;

        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] Response envelope not found");

        res_envelope = (axiom_soap_envelope_t *) axis2_http_transport_utils_create_soap_msg(env, 
                make_conn_msg_ctx, soap_ns_uri);
    }

    if(res_envelope)
    {
        axis2_msg_ctx_set_response_soap_envelope(make_conn_msg_ctx, env, res_envelope);
        status = sandesha2_polling_mgr_process_make_connection_msg_response(env, make_conn_msg_ctx, 
                storage_mgr);

        if(AXIS2_SUCCESS != status)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[sandesha2] Make connection message response process failed for sequence %s", 
                internal_sequence_id);

            return AXIS2_FAILURE;
        }
    }

    worker_thread = axutil_thread_pool_get_thread(env->thread_pool, 
            sandesha2_polling_mgr_worker_func, (void*)args);

    if(!worker_thread)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "Thread creation failed sandesha2_polling_mgr_run");

        return AXIS2_FAILURE;
    }

    axutil_thread_pool_thread_detach(env->thread_pool, worker_thread); 
        
    return AXIS2_SUCCESS;
}

/**
 * Thread worker function.
 */
static void * AXIS2_THREAD_FUNC
sandesha2_polling_mgr_worker_func(
    axutil_thread_t *thd, 
    void *data)
{
    axis2_char_t *dbname = NULL;
    axis2_char_t *internal_sequence_id = NULL;
    axis2_char_t *sequence_id = NULL;
    axis2_conf_ctx_t *conf_ctx = NULL;
    sandesha2_storage_mgr_t *storage_mgr = NULL;
    sandesha2_seq_property_mgr_t *seq_prop_mgr = NULL;
    sandesha2_sender_mgr_t *sender_mgr = NULL;
    sandesha2_next_msg_mgr_t *next_msg_mgr = NULL;
    axis2_msg_ctx_t *make_conn_msg_ctx = NULL;
    sandesha2_property_bean_t *property_bean = NULL;
    axis2_conf_t *conf = NULL;
    int wait_time = 0;
    axis2_status_t status = AXIS2_FAILURE;
    sandesha2_sender_bean_t *find_sender_bean = NULL;
    sandesha2_sender_bean_t *sender_bean = NULL;
    axis2_char_t *key = NULL;
    
    sandesha2_polling_mgr_args_t *args = (sandesha2_polling_mgr_args_t*)data;
    axutil_env_t *env = args->env;
    conf_ctx = args->conf_ctx;
    internal_sequence_id = axutil_strdup(env, args->internal_sequence_id);
    sequence_id = axutil_strdup(env, args->sequence_id);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[sandesha2] Entry:sandesha2_polling_mgr_worker_func");

    dbname = sandesha2_util_get_dbname(env, conf_ctx);
    
    storage_mgr = sandesha2_utils_get_storage_mgr(env, dbname);
    if(!storage_mgr)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] Could not create storage manager.");
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_COULD_NOT_CREATE_STORAGE_MANAGER, 
                AXIS2_FAILURE);
        return NULL;
    }
    seq_prop_mgr = sandesha2_permanent_seq_property_mgr_create(env, dbname);
    sender_mgr = sandesha2_permanent_sender_mgr_create(env, dbname);
    next_msg_mgr = sandesha2_permanent_next_msg_mgr_create(env, dbname);
 
    conf = axis2_conf_ctx_get_conf(conf_ctx, env);
    /*property_bean = sandesha2_utils_get_property_bean(env, conf);*/
    wait_time = sandesha2_property_bean_get_polling_delay(property_bean, env);

    find_sender_bean = sandesha2_sender_bean_create(env);
    sandesha2_sender_bean_set_msg_type(find_sender_bean, env, SANDESHA2_MSG_TYPE_MAKE_CONNECTION_MSG);
    sandesha2_sender_bean_set_internal_seq_id(find_sender_bean, env, internal_sequence_id);
    sandesha2_sender_bean_set_send(find_sender_bean, env, AXIS2_TRUE);

    sender_bean = sandesha2_sender_mgr_find_unique(sender_mgr, env, find_sender_bean);
    if(find_sender_bean)
    {
        sandesha2_sender_bean_free(find_sender_bean, env);
    }
    if(sender_bean)
    {
        key = sandesha2_sender_bean_get_msg_ctx_ref_key(sender_bean, env);
    }

    while(AXIS2_TRUE)
    {
        axiom_soap_envelope_t *res_envelope = NULL;
        axis2_char_t *soap_ns_uri = NULL;
        axutil_property_t *property = NULL;

        axis2_transport_out_desc_t *transport_out = NULL;
        axis2_transport_sender_t *transport_sender = NULL;
        axis2_bool_t successfully_sent = AXIS2_FALSE;

        AXIS2_SLEEP(wait_time);
        
        make_conn_msg_ctx = sandesha2_storage_mgr_retrieve_msg_ctx(storage_mgr, env, key, conf_ctx, 
                AXIS2_TRUE);

        property = axutil_property_create_with_args(env, 0, 0, 0, AXIS2_VALUE_TRUE);
        axis2_msg_ctx_set_property(make_conn_msg_ctx, env, SANDESHA2_SEQ_PROP_MAKE_CONNECTION_OUT_PATH, 
                property);

        soap_ns_uri = axis2_msg_ctx_get_is_soap_11(make_conn_msg_ctx, env) ?
             AXIOM_SOAP11_SOAP_ENVELOPE_NAMESPACE_URI:
             AXIOM_SOAP12_SOAP_ENVELOPE_NAMESPACE_URI;

        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
            "[sandesha2] Sending make connection message for sequence with internal sequence id %s", 
            internal_sequence_id);

        transport_out = axis2_msg_ctx_get_transport_out_desc(make_conn_msg_ctx, env);
        if(transport_out)
        {
            transport_sender = axis2_transport_out_desc_get_sender(transport_out, env);
        }
        if(transport_sender)
        {
            /* This is neccessary to avoid a double free at http_sender.c */
            axis2_msg_ctx_set_property(make_conn_msg_ctx, env, AXIS2_TRANSPORT_IN, NULL);
            if(AXIS2_TRANSPORT_SENDER_INVOKE(transport_sender, env, make_conn_msg_ctx))
            {
                successfully_sent = AXIS2_TRUE;
            }else
            {
                successfully_sent = AXIS2_FALSE;
            }
        }

        if(successfully_sent)
        {
            res_envelope = axis2_msg_ctx_get_response_soap_envelope(make_conn_msg_ctx, env);
        }

        if(!res_envelope)
        {
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] Response envelope not found");

            res_envelope = (axiom_soap_envelope_t *) axis2_http_transport_utils_create_soap_msg(env, 
                    make_conn_msg_ctx, soap_ns_uri);
        }
        
        if(res_envelope)
        {
            axis2_msg_ctx_set_response_soap_envelope(make_conn_msg_ctx, env, res_envelope);
            status = sandesha2_polling_mgr_process_make_connection_msg_response(env, make_conn_msg_ctx, 
                    storage_mgr);

            if(AXIS2_SUCCESS != status)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                    "[sandesha2] Make connection message response process failed for sequence %s", 
                    internal_sequence_id);

                break;
            }
        }
    }

    if(seq_prop_mgr)
    {
        sandesha2_seq_property_mgr_free(seq_prop_mgr, env);
    }

    if(sender_mgr)
    {
        sandesha2_sender_mgr_free(sender_mgr, env);
    }

    if(next_msg_mgr)
    {
        sandesha2_next_msg_mgr_free(next_msg_mgr, env);
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[sandesha2] Exit:sandesha2_polling_mgr_worker_func");

    return NULL;
}

static axis2_status_t AXIS2_CALL
sandesha2_polling_mgr_process_make_connection_msg_response(
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
        "[sandesha2] Entry:sandesha2_polling_mgr_process_make_connection_msg_response");

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
        "[sandesha2] Response envelope for make connection message found");

    response_msg_ctx = axis2_msg_ctx_create(env, conf_ctx, axis2_msg_ctx_get_transport_in_desc(msg_ctx, 
                env), axis2_msg_ctx_get_transport_out_desc(msg_ctx, env));
   
    to = axis2_endpoint_ref_create(env, 
        "http://localhost/axis2/services/__ANONYMOUS_SERVICE__/__OPERATION_OUT_IN__");
    axis2_msg_ctx_set_to(response_msg_ctx, env, to);

    axis2_msg_ctx_set_wsa_action(response_msg_ctx, env, 
            "http://localhost/axis2/services/__ANONYMOUS_SERVICE__/__OPERATION_OUT_IN__");

    axis2_msg_ctx_set_soap_envelope(response_msg_ctx, env, response_envelope);

    /*axis2_msg_ctx_set_server_side(response_msg_ctx, env, AXIS2_TRUE);*/

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

    axis2_msg_ctx_set_paused(response_msg_ctx, env, AXIS2_FALSE);
    axis2_msg_ctx_free(response_msg_ctx, env);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI,
        "[sandesha2] Exit:sandesha2_polling_mgr_process_make_connection_msg_response");

    return AXIS2_SUCCESS;
}


