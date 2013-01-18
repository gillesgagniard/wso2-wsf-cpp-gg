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
 
#include <sandesha2_create_seq_mgr.h>
#include <sandesha2_seq_property_mgr.h>
#include <sandesha2_next_msg_mgr.h>
#include <sandesha2_create_seq_mgr.h>
#include <sandesha2_spec_specific_consts.h>
#include <sandesha2_utils.h>
#include <sandesha2_ack_mgr.h>
#include <sandesha2_constants.h>
#include <sandesha2_msg_ctx.h>
#include <sandesha2_create_seq.h>
#include <sandesha2_acks_to.h>
#include <sandesha2_address.h>

#include <axis2_conf_ctx.h>
#include <axis2_ctx.h>
#include <axis2_msg_ctx.h>
#include <axutil_property.h>
#include <axutil_log.h>
#include <axutil_uuid_gen.h>
#include <axis2_msg_ctx.h>
#include <axis2_addr.h>
#include <sandesha2_client_constants.h>
#include <axis2_options.h>
#include <axis2_listener_manager.h>
#include <axis2_ctx.h>

long AXIS2_CALL
sandesha2_seq_mgr_get_last_activated_time(
    const axutil_env_t *env,
    axis2_char_t *property_key,
    sandesha2_seq_property_mgr_t *seq_prop_mgr);

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
sandesha2_seq_mgr_setup_new_incoming_sequence(
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *create_seq_msg, 
    sandesha2_seq_property_mgr_t *seq_prop_mgr,
    sandesha2_next_msg_mgr_t *next_msg_mgr)
{
    axis2_char_t *rmd_sequence_id = NULL;
    axis2_endpoint_ref_t *to = NULL;
    axis2_endpoint_ref_t *reply_to = NULL;
    axis2_endpoint_ref_t *acks_to = NULL;
    sandesha2_acks_to_t *temp_acks_to = NULL;
    sandesha2_address_t *temp_address = NULL;
    sandesha2_create_seq_t *create_seq = NULL;
    axis2_msg_ctx_t *msg_ctx = NULL;
    axis2_conf_ctx_t *conf_ctx = NULL;
    sandesha2_seq_property_bean_t *received_msg_bean = NULL;
    sandesha2_seq_property_bean_t *addressing_ns_bean = NULL;
    sandesha2_seq_property_bean_t *reply_to_bean = NULL;
    sandesha2_seq_property_bean_t *acks_to_bean = NULL;
    sandesha2_seq_property_bean_t *to_bean = NULL;
    sandesha2_next_msg_bean_t *next_msg_bean = NULL;
    axis2_char_t *addressing_ns_value = NULL;
    axis2_char_t *anonymous_uri = NULL;
    axis2_char_t *create_seq_msg_action = NULL;
    axis2_char_t *msg_rm_ns = NULL;
    axis2_char_t *spec_version = NULL;
    axis2_char_t *address = NULL;
    axis2_char_t *reply_to_addr = NULL;

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[sandesha2]Entry:sandesha2_seq_mgr_setup_new_incoming_sequence");

    rmd_sequence_id = axutil_uuid_gen(env);
    to = sandesha2_msg_ctx_get_to(create_seq_msg, env);
    if(!to)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "To is NULL");
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_TO_IS_NULL, AXIS2_FAILURE);
        return NULL; 
    }

    reply_to = sandesha2_msg_ctx_get_reply_to(create_seq_msg, env);
    create_seq = sandesha2_msg_ctx_get_create_seq(create_seq_msg, env);
    if(!create_seq)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] Create Sequence Part is NULL");
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_CREATE_SEQ_PART_IS_NULL, AXIS2_FAILURE);
        return NULL; 
    }

    temp_acks_to = sandesha2_create_seq_get_acks_to(create_seq, env);
    temp_address = sandesha2_acks_to_get_address(temp_acks_to, env);
    acks_to = sandesha2_address_get_epr(temp_address, env);
    if(!acks_to)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] Acks To is NULL");
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_ACKS_TO_IS_NULL, AXIS2_FAILURE);
        return NULL; 
    }

    msg_ctx = sandesha2_msg_ctx_get_msg_ctx(create_seq_msg, env);
    conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);

    /* Setting the addressing version */
    addressing_ns_value = sandesha2_msg_ctx_get_addr_ns_val(create_seq_msg, env);
    addressing_ns_bean = sandesha2_seq_property_bean_create_with_data(env, rmd_sequence_id, 
            SANDESHA2_SEQ_PROP_ADDRESSING_NAMESPACE_VALUE, addressing_ns_value);
    if(addressing_ns_bean)
    {
        sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, addressing_ns_bean);
        sandesha2_seq_property_bean_free(addressing_ns_bean, env);
    }
    anonymous_uri = sandesha2_spec_specific_consts_get_anon_uri(env, addressing_ns_value); 

    /* If no replyTo value. Send responses as sync. */
    if(reply_to)
    {
        reply_to_addr = (axis2_char_t*)axis2_endpoint_ref_get_address(reply_to, env);
        to_bean = sandesha2_seq_property_bean_create_with_data(env, rmd_sequence_id, 
                SANDESHA2_SEQ_PROP_TO_EPR, reply_to_addr);
    }
    else
    {
        to_bean = sandesha2_seq_property_bean_create_with_data(env, rmd_sequence_id, 
                SANDESHA2_SEQ_PROP_TO_EPR, anonymous_uri);
    }

    if(to_bean)
    {
        sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, to_bean);
        sandesha2_seq_property_bean_free(to_bean, env);
    }

    address = (axis2_char_t*)axis2_endpoint_ref_get_address(to, env);
    reply_to_bean = sandesha2_seq_property_bean_create_with_data(env, rmd_sequence_id, 
        SANDESHA2_SEQ_PROP_REPLY_TO_EPR, address);
    if(reply_to_bean)
    {
        sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, reply_to_bean);
        sandesha2_seq_property_bean_free(reply_to_bean, env);
    }

    address = (axis2_char_t*)axis2_endpoint_ref_get_address(acks_to, env);
    acks_to_bean = sandesha2_seq_property_bean_create_with_data(env, rmd_sequence_id, 
        SANDESHA2_SEQ_PROP_ACKS_TO_EPR, address);

    if(acks_to_bean)
    {
        sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, acks_to_bean);
        sandesha2_seq_property_bean_free(acks_to_bean, env);
    }

    received_msg_bean = sandesha2_seq_property_bean_create_with_data(env, rmd_sequence_id, 
            SANDESHA2_SEQ_PROP_SERVER_COMPLETED_MESSAGES, "");
    if(received_msg_bean)
    {
        sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, received_msg_bean);
        sandesha2_seq_property_bean_free(received_msg_bean, env);
    }


    next_msg_bean = sandesha2_next_msg_bean_create_with_data(env, rmd_sequence_id, 1); 
                                                    /* 1 will be the next */
    if(next_msg_bean)
    {
        axis2_char_t *internal_sequence_id = NULL;

        internal_sequence_id = sandesha2_utils_get_internal_sequence_id(env, rmd_sequence_id);
        if(internal_sequence_id)
        {
            sandesha2_next_msg_bean_set_internal_seq_id(next_msg_bean, env, internal_sequence_id);
            AXIS2_FREE(env->allocator, internal_sequence_id);
        }

        sandesha2_next_msg_mgr_insert(next_msg_mgr, env, next_msg_bean);
        sandesha2_next_msg_bean_free(next_msg_bean, env);
    }

    /* Message to invoke. This will apply for only in-order invocations */
    /*if(!axis2_msg_ctx_get_server_side(msg_ctx, env) || !sandesha2_utils_is_anon_uri(env, 
     * reply_to_addr))
     * {
     *   sandesha2_utils_start_sender_for_seq(env, conf_ctx, rmd_sequence_id);
     *}*/

    /* Setting the RM Spec version for this sequence */
    create_seq_msg_action = sandesha2_msg_ctx_get_wsa_action(create_seq_msg, env);
    if(!create_seq_msg_action)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_CREATE_SEQ_MSG_DOES_NOT_HAVE_WSA_ACTION_VALUE, 
            AXIS2_FAILURE);

        return NULL;
    }

    msg_rm_ns = sandesha2_create_seq_get_namespace_value(create_seq, env);

    if(!axutil_strcmp(SANDESHA2_SPEC_2005_02_NS_URI, msg_rm_ns))
    {
        spec_version = axutil_strdup(env, SANDESHA2_SPEC_VERSION_1_0);
    }
    else if(!axutil_strcmp(SANDESHA2_SPEC_2007_02_NS_URI, msg_rm_ns))
    {
        spec_version = axutil_strdup(env, SANDESHA2_SPEC_VERSION_1_1);
    }
    else
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_CREATE_SEQ_MSG_DOES_NOT_HAVE_VALID_RM_NS_VALUE,
            AXIS2_FAILURE);

        return NULL;
    }

    if(spec_version)
    {
        AXIS2_FREE(env->allocator, spec_version);
    }

    /* TODO Get the SOAP version from the creaet sequence message */

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[sandesha2]Entry:sandesha2_seq_mgr_setup_new_incoming_sequence");

    return rmd_sequence_id;
}
       
/**
 * Takes the internal_seq_id as the param. Not the seq_id
 * @param internal_seq_id
 * @param config_ctx
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
sandesha2_seq_mgr_update_last_activated_time(
        const axutil_env_t *env,
        axis2_char_t *property_key,
        sandesha2_seq_property_mgr_t *seq_prop_mgr)
{
    sandesha2_seq_property_bean_t *last_activated_bean = NULL;
    axis2_bool_t added = AXIS2_FALSE;
    long current_time = -1;
    axis2_char_t current_time_str[32];
    
    last_activated_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env, 
            property_key, SANDESHA2_SEQ_PROP_LAST_ACTIVATED_TIME);

    if(!last_activated_bean)
    {
        added = AXIS2_TRUE;
        last_activated_bean = sandesha2_seq_property_bean_create(env);
        sandesha2_seq_property_bean_set_seq_id(last_activated_bean, env, property_key);
        sandesha2_seq_property_bean_set_name(last_activated_bean, env, 
                SANDESHA2_SEQ_PROP_LAST_ACTIVATED_TIME);
    }

    current_time = sandesha2_utils_get_current_time_in_millis(env);
    sprintf(current_time_str, "%ld", current_time);
    sandesha2_seq_property_bean_set_value(last_activated_bean, env, current_time_str); 
    if(added)
    {
        sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, last_activated_bean);
    }
    else
    {
        sandesha2_seq_property_mgr_update(seq_prop_mgr, env, last_activated_bean);
    }
    if(last_activated_bean)
    {
        sandesha2_seq_property_bean_free(last_activated_bean, env);
    }
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
sandesha2_seq_mgr_has_seq_timedout(
    const axutil_env_t *env,
    axis2_char_t *property_key,
    sandesha2_seq_property_mgr_t *seq_prop_mgr,
    axis2_svc_t *svc)
{
    sandesha2_property_bean_t *property_bean = NULL;
    axis2_bool_t seq_timedout = AXIS2_FALSE;
    long last_activated_time = -1;
    long current_time = -1;
    long timeout_interval = -1;
    
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[sandesha2] Entry:sandesha2_seq_mgr_has_seq_timedout");

    AXIS2_PARAM_CHECK(env->error, property_key, AXIS2_FALSE);
    AXIS2_PARAM_CHECK(env->error, seq_prop_mgr, AXIS2_FALSE);
    
    property_bean = sandesha2_utils_get_property_bean(env, svc);
    timeout_interval = sandesha2_property_bean_get_inactive_timeout_interval(property_bean, env);
    if(timeout_interval <= 0)
    {
        return AXIS2_FALSE;
    }

    last_activated_time = sandesha2_seq_mgr_get_last_activated_time(env, property_key, seq_prop_mgr);
    current_time = sandesha2_utils_get_current_time_in_millis(env);

    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2]timeout_interval:%ld", timeout_interval);
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2]last_activated_time:%ld", last_activated_time);
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2]current_time:%ld", current_time);

    if(last_activated_time > 0 && ((last_activated_time + timeout_interval) < current_time))
    {
        seq_timedout = AXIS2_TRUE;
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[sandesha2] Exit:sandesha2_seq_mgr_has_seq_timedout");

    return seq_timedout;
}

long AXIS2_CALL
sandesha2_seq_mgr_get_last_activated_time(
    const axutil_env_t *env,
    axis2_char_t *property_key,
    sandesha2_seq_property_mgr_t *seq_prop_mgr)
{
    long last_activated_time = -1;
    sandesha2_seq_property_bean_t *seq_prop_bean = NULL;
    
    AXIS2_PARAM_CHECK(env->error, property_key, -1);
    AXIS2_PARAM_CHECK(env->error, seq_prop_mgr, -1);
    
    seq_prop_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env, 
        property_key, SANDESHA2_SEQ_PROP_LAST_ACTIVATED_TIME);
    if(seq_prop_bean)
    {
        axis2_char_t *value = NULL;
        
        value = sandesha2_seq_property_bean_get_value(seq_prop_bean, env);
        if(value)
            last_activated_time = atol(value);
        sandesha2_seq_property_bean_free(seq_prop_bean, env);
    }
    return last_activated_time;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
sandesha2_seq_mgr_setup_new_outgoing_sequence(
    const axutil_env_t *env,
    axis2_msg_ctx_t *first_app_msg,
    axis2_char_t *internal_sequence_id,
    axis2_char_t *spec_version,
    sandesha2_seq_property_mgr_t *seq_prop_mgr)
{
    axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_char_t *addr_ns_val = NULL;
    axutil_property_t *property = NULL;
    sandesha2_seq_property_bean_t *addr_ns_bean = NULL;
    axis2_char_t *anon_uri = NULL;
    axis2_endpoint_ref_t *to_epr = NULL;
    axis2_char_t *acks_to_str = NULL;
    sandesha2_seq_property_bean_t *to_bean = NULL;
    sandesha2_seq_property_bean_t *reply_to_bean = NULL;
    sandesha2_seq_property_bean_t *acks_to_bean = NULL;
    sandesha2_seq_property_bean_t *msgs_bean = NULL;
    axis2_char_t *transport_to = NULL;
    axis2_endpoint_ref_t *reply_to_epr = NULL;
    axis2_bool_t is_svr_side = AXIS2_FALSE;
   
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "Entry:sandesha2_seq_mgr_setup_new_outgoing_sequence");

    AXIS2_PARAM_CHECK(env->error, first_app_msg, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, internal_sequence_id, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, spec_version, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, seq_prop_mgr, AXIS2_FAILURE);
    
    conf_ctx = axis2_msg_ctx_get_conf_ctx(first_app_msg, env);
    
    property = axis2_msg_ctx_get_property(first_app_msg, env, AXIS2_WSA_VERSION);
    if(property)
    {
        addr_ns_val = axutil_property_get_value(property, env);
    }

    if(!addr_ns_val)
    {
        axis2_op_ctx_t *op_ctx = NULL;
        axis2_msg_ctx_t *req_msg_ctx = NULL;

        op_ctx = axis2_msg_ctx_get_op_ctx(first_app_msg, env);
        req_msg_ctx =  axis2_op_ctx_get_msg_ctx(op_ctx, env, AXIS2_WSDL_MESSAGE_LABEL_IN);

        if(req_msg_ctx)
        {
            property = axis2_msg_ctx_get_property(req_msg_ctx, env, AXIS2_WSA_VERSION);
            if(property)
            {
                addr_ns_val = axutil_property_get_value(property, env);
            }
        }
    }

    if(!addr_ns_val)
    {
        addr_ns_val = AXIS2_WSA_NAMESPACE;
    }
        
    addr_ns_bean = sandesha2_seq_property_bean_create_with_data(env, internal_sequence_id, 
            SANDESHA2_SEQ_PROP_ADDRESSING_NAMESPACE_VALUE, addr_ns_val);

    sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, addr_ns_bean);
    if(addr_ns_bean)
    {
        sandesha2_seq_property_bean_free(addr_ns_bean, env);
    }

    anon_uri = sandesha2_spec_specific_consts_get_anon_uri(env, addr_ns_val);
    
    to_epr = axis2_msg_ctx_get_to(first_app_msg, env);
    property = axis2_msg_ctx_get_property(first_app_msg, env, SANDESHA2_CLIENT_ACKS_TO);
    if(property)
    {
        acks_to_str = axutil_property_get_value(property, env);
    }

    if (to_epr)
    {
        to_bean = sandesha2_seq_property_bean_create_with_data(env, internal_sequence_id, 
                SANDESHA2_SEQ_PROP_TO_EPR, (axis2_char_t*)axis2_endpoint_ref_get_address(to_epr, 
                       env));
        sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, to_bean);
        sandesha2_seq_property_bean_free(to_bean, env);
    }
    
    is_svr_side = axis2_msg_ctx_get_server_side(first_app_msg, env);

    if(is_svr_side)
    {
        axis2_op_ctx_t *op_ctx = NULL;
        axis2_msg_ctx_t *req_msg_ctx = NULL;
        
        op_ctx = axis2_msg_ctx_get_op_ctx(first_app_msg, env);

        req_msg_ctx =  axis2_op_ctx_get_msg_ctx(op_ctx, env, AXIS2_WSDL_MESSAGE_LABEL_IN);
        if(!req_msg_ctx)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                    "[sandesha2] Cannot find the request message from the operation context");
            return AXIS2_FAILURE;
        }

        reply_to_epr = axis2_msg_ctx_get_to(req_msg_ctx, env);

        if(reply_to_epr)
        {
            const axis2_char_t *temp_epr_addr = axis2_endpoint_ref_get_address(reply_to_epr, env);
            
            if(temp_epr_addr)
            {
                AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "temp_epr_address:%s", temp_epr_addr);
                acks_to_str = (axis2_char_t *) temp_epr_addr;
                reply_to_bean = sandesha2_seq_property_bean_create_with_data(env, internal_sequence_id, 
                    SANDESHA2_SEQ_PROP_REPLY_TO_EPR, (axis2_char_t*) temp_epr_addr);
                sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, reply_to_bean);
                sandesha2_seq_property_bean_free(reply_to_bean, env);
            }
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                    "[sandesha2] Cannot get request message from the operation context");

            return AXIS2_FAILURE;
        }        
    }
    else /* Not server side */
    {
        reply_to_epr = axis2_msg_ctx_get_reply_to(first_app_msg, env);

        if(reply_to_epr)
        {
            const axis2_char_t *temp_epr_addr = axis2_endpoint_ref_get_address(reply_to_epr, env);
            if(temp_epr_addr)
            {
                AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "temp_epr_address:%s", temp_epr_addr);
                reply_to_bean = sandesha2_seq_property_bean_create_with_data(env, internal_sequence_id, 
                    SANDESHA2_SEQ_PROP_REPLY_TO_EPR, (axis2_char_t*) temp_epr_addr);
                sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, reply_to_bean);
                sandesha2_seq_property_bean_free(reply_to_bean, env);
            }
        } 
    }

    if(!acks_to_str)
    {
        acks_to_str = anon_uri;
    }
    
    acks_to_bean = sandesha2_seq_property_bean_create_with_data(env, internal_sequence_id, 
            SANDESHA2_SEQ_PROP_ACKS_TO_EPR, acks_to_str);

    msgs_bean = sandesha2_seq_property_bean_create_with_data(env, internal_sequence_id, 
                        SANDESHA2_SEQ_PROP_CLIENT_COMPLETED_MESSAGES, "");
    if(msgs_bean)
    {
        sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, msgs_bean);
        sandesha2_seq_property_bean_free(msgs_bean, env);
    }
    
    if(acks_to_bean)
    {
        sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, acks_to_bean);
        sandesha2_seq_property_bean_free(acks_to_bean, env);
    }

    transport_to = axis2_msg_ctx_get_transport_url(first_app_msg, env);
    
    if(transport_to)
    {
        sandesha2_seq_property_bean_t *transport_to_bean = NULL;
        transport_to_bean = sandesha2_seq_property_bean_create_with_data(env, internal_sequence_id, 
                SANDESHA2_SEQ_PROP_TRANSPORT_TO, transport_to);

        sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, transport_to_bean);
    }

    sandesha2_seq_mgr_update_last_activated_time(env, internal_sequence_id, seq_prop_mgr);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "Exit:sandesha2_seq_mgr_setup_new_outgoing_sequence");

    return AXIS2_SUCCESS;
}

