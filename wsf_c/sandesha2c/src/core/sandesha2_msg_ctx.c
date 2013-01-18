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
#include <sandesha2_msg_ctx.h>
#include <sandesha2_constants.h>
#include <axutil_hash.h>
#include <axiom_soap_const.h>
#include <stdio.h>
#include <sandesha2_close_seq.h>
#include <sandesha2_close_seq_res.h>
#include <sandesha2_create_seq.h>
#include <sandesha2_create_seq_res.h>
#include <sandesha2_make_connection.h>
#include <sandesha2_msg_pending.h>
#include <sandesha2_seq_ack.h>
#include <sandesha2_seq.h>
#include <sandesha2_terminate_seq.h>
#include <sandesha2_terminate_seq_res.h>

/** 
 * @brief Msg Ctx struct impl
 *	Sandesha2 Message Context
 */
struct sandesha2_msg_ctx_t
{
    int msg_type;
    axis2_char_t *rm_ns_val;
    axis2_char_t *addr_ns_val;
    axis2_char_t *spec_ver;
	axis2_msg_ctx_t *msg_ctx;
    sandesha2_close_seq_t *close_seq;
    sandesha2_close_seq_res_t *close_seq_res;
    sandesha2_create_seq_t *create_seq;
    sandesha2_create_seq_res_t *create_seq_res;
    sandesha2_make_connection_t *make_connection;
    sandesha2_msg_pending_t *msg_pending;
    sandesha2_seq_ack_t *seq_ack;
    sandesha2_seq_t *seq;
    sandesha2_terminate_seq_t *terminate_seq;
    sandesha2_terminate_seq_res_t *terminate_seq_res;
    sandesha2_ack_requested_t *ack_requested;
    axis2_bool_t is_server_side;
};

AXIS2_EXTERN sandesha2_msg_ctx_t* AXIS2_CALL
sandesha2_msg_ctx_create(
    const axutil_env_t *env, 
    axis2_msg_ctx_t *msg_ctx)
{
    sandesha2_msg_ctx_t *rm_msg_ctx = NULL;
    
    rm_msg_ctx =  (sandesha2_msg_ctx_t *)AXIS2_MALLOC(env->allocator, sizeof(sandesha2_msg_ctx_t));
	
    if(!rm_msg_ctx)
	{
		AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
	}
    rm_msg_ctx->rm_ns_val = NULL;
    rm_msg_ctx->addr_ns_val = NULL;
    rm_msg_ctx->msg_ctx = NULL;
    rm_msg_ctx->spec_ver = NULL;
    rm_msg_ctx->create_seq = NULL;
    rm_msg_ctx->create_seq_res = NULL;
    rm_msg_ctx->close_seq = NULL;
    rm_msg_ctx->close_seq_res = NULL;
    rm_msg_ctx->terminate_seq = NULL;
    rm_msg_ctx->terminate_seq_res = NULL;
    rm_msg_ctx->make_connection = NULL;
    rm_msg_ctx->msg_pending = NULL;
    rm_msg_ctx->seq = NULL;
    rm_msg_ctx->seq_ack = NULL;
    rm_msg_ctx->ack_requested = NULL;
    
    rm_msg_ctx->msg_type = SANDESHA2_MSG_TYPE_UNKNOWN;
    rm_msg_ctx->msg_ctx = msg_ctx;
    rm_msg_ctx->is_server_side = AXIS2_FALSE;

	return rm_msg_ctx;
}


axis2_status_t AXIS2_CALL 
sandesha2_msg_ctx_free(
    sandesha2_msg_ctx_t *rm_msg_ctx, 
    const axutil_env_t *env)
{
    if(rm_msg_ctx->addr_ns_val)
    {
        AXIS2_FREE(env->allocator, rm_msg_ctx->addr_ns_val);
        rm_msg_ctx->addr_ns_val = NULL;
    }
    if(rm_msg_ctx->rm_ns_val)
    {
        AXIS2_FREE(env->allocator, rm_msg_ctx->rm_ns_val);
        rm_msg_ctx->rm_ns_val = NULL;
    }
    if(rm_msg_ctx->spec_ver)
    {
        AXIS2_FREE(env->allocator, rm_msg_ctx->spec_ver);
        rm_msg_ctx->spec_ver = NULL;
    }
    if(rm_msg_ctx->close_seq)
    {
        sandesha2_close_seq_free(rm_msg_ctx->close_seq, env);
        rm_msg_ctx->close_seq = NULL;
    }
    if(rm_msg_ctx->close_seq_res)
    {
        sandesha2_close_seq_res_free(rm_msg_ctx->close_seq_res, env);
        rm_msg_ctx->close_seq_res = NULL;
    }
    if(rm_msg_ctx->create_seq)
    {
        sandesha2_create_seq_free(rm_msg_ctx->create_seq, env);
        rm_msg_ctx->create_seq = NULL;
    }
    if(rm_msg_ctx->create_seq_res)
    {
        sandesha2_create_seq_res_free(rm_msg_ctx->create_seq_res, env);
        rm_msg_ctx->create_seq_res = NULL;
    }
    if(rm_msg_ctx->make_connection)
    {
        sandesha2_make_connection_free(rm_msg_ctx->make_connection, env);
        rm_msg_ctx->make_connection = NULL;
    }
    if(rm_msg_ctx->msg_pending)
    {
        sandesha2_msg_pending_free(rm_msg_ctx->msg_pending, env);
        rm_msg_ctx->msg_pending = NULL;
    }
    if(rm_msg_ctx->seq_ack)
    {
        sandesha2_seq_ack_free(rm_msg_ctx->seq_ack, env);
        rm_msg_ctx->seq_ack = NULL;
    }
    if(rm_msg_ctx->seq)
    {
        sandesha2_seq_free(rm_msg_ctx->seq, env);
        rm_msg_ctx->seq = NULL;
    }
    if(rm_msg_ctx->terminate_seq)
    {
        sandesha2_terminate_seq_free(rm_msg_ctx->terminate_seq, env);
        rm_msg_ctx->terminate_seq = NULL;
    }
    if(rm_msg_ctx->terminate_seq_res)
    {
        sandesha2_terminate_seq_res_free(rm_msg_ctx->terminate_seq_res, env);
        rm_msg_ctx->terminate_seq = NULL;
    }
    if(rm_msg_ctx->ack_requested)
    {
        sandesha2_ack_requested_free(rm_msg_ctx->ack_requested, env);
        rm_msg_ctx->ack_requested = NULL;
    }

	AXIS2_FREE(env->allocator, rm_msg_ctx);
	return AXIS2_SUCCESS;
}

axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_msg_ctx(
    sandesha2_msg_ctx_t *rm_msg_ctx, 
    const axutil_env_t *env, 
    axis2_msg_ctx_t *msg_ctx)
{
    AXIS2_PARAM_CHECK(env->error, msg_ctx, AXIS2_FAILURE);
    
    rm_msg_ctx->msg_ctx = msg_ctx;
    return AXIS2_SUCCESS;
}
            
axis2_msg_ctx_t *AXIS2_CALL
sandesha2_msg_ctx_get_msg_ctx(
    sandesha2_msg_ctx_t *rm_msg_ctx, 
    const axutil_env_t *env)
{
    return rm_msg_ctx->msg_ctx;
}
    
axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_add_soap_envelope(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    int soap_ver = AXIOM_SOAP11;
    axiom_soap_envelope_t *soap_envelope = NULL;
    
    if(!axis2_msg_ctx_get_is_soap_11(rm_msg_ctx->msg_ctx, env))
    {
        soap_ver = AXIOM_SOAP12;
    }

    soap_envelope = axis2_msg_ctx_get_soap_envelope(rm_msg_ctx->msg_ctx, env);
    if(!soap_envelope)
    {
        soap_envelope = axiom_soap_envelope_create_default_soap_envelope(env, soap_ver);
        axis2_msg_ctx_set_soap_envelope(rm_msg_ctx->msg_ctx, env, soap_envelope);
    }
    
    if(rm_msg_ctx->close_seq)
    {
        sandesha2_close_seq_to_soap_envelope(rm_msg_ctx->close_seq, env, 
            soap_envelope);
    }

    if(rm_msg_ctx->close_seq_res)
    {
        sandesha2_close_seq_res_to_soap_envelope(rm_msg_ctx->close_seq_res, env, soap_envelope);
    }
    if(rm_msg_ctx->create_seq)
    {
        sandesha2_create_seq_to_soap_envelope(rm_msg_ctx->create_seq, env, soap_envelope);
    }
    if(rm_msg_ctx->create_seq_res)
    {
        sandesha2_create_seq_res_to_soap_envelope(rm_msg_ctx->create_seq_res, env, soap_envelope);
    }
    if(rm_msg_ctx->make_connection)
    {
        sandesha2_make_connection_to_soap_envelope(rm_msg_ctx->make_connection, env, soap_envelope);
    }
    if(rm_msg_ctx->msg_pending)
    {
        sandesha2_msg_pending_to_soap_envelope(rm_msg_ctx->msg_pending, env, soap_envelope);
    }
    if(rm_msg_ctx->seq_ack)
    {
        sandesha2_seq_ack_to_soap_envelope(rm_msg_ctx->seq_ack, env, soap_envelope);
    }
    if(rm_msg_ctx->seq)
    {
        sandesha2_seq_to_soap_envelope(rm_msg_ctx->seq, env, soap_envelope);
    }
    if(rm_msg_ctx->terminate_seq)
    {
        sandesha2_terminate_seq_to_soap_envelope(rm_msg_ctx->terminate_seq, env, soap_envelope);
    }
    if(rm_msg_ctx->terminate_seq_res)
    {
        sandesha2_terminate_seq_res_to_soap_envelope(rm_msg_ctx->terminate_seq_res, env, soap_envelope);
    }
    return AXIS2_SUCCESS;
}
            
int AXIS2_CALL
sandesha2_msg_ctx_get_msg_type (
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    return rm_msg_ctx->msg_type;
}
            
axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_msg_type (
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env, int msg_type)
{
    rm_msg_ctx->msg_type = msg_type;
    return AXIS2_SUCCESS;
}
                          
axis2_endpoint_ref_t *AXIS2_CALL
sandesha2_msg_ctx_get_from(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    return axis2_msg_ctx_get_from(rm_msg_ctx->msg_ctx, env);
}

axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_from(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env, 
    axis2_endpoint_ref_t *from)
{
    AXIS2_PARAM_CHECK(env->error, from, AXIS2_FAILURE);
    
    return axis2_msg_ctx_set_from(rm_msg_ctx->msg_ctx, env, from);;
}
    
axis2_endpoint_ref_t *AXIS2_CALL
sandesha2_msg_ctx_get_to (
    sandesha2_msg_ctx_t *rm_msg_ctx, 
    const axutil_env_t *env)
{
    return axis2_msg_ctx_get_to(rm_msg_ctx->msg_ctx, env);
}

axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_to(
    sandesha2_msg_ctx_t *rm_msg_ctx, 
    const axutil_env_t *env, 
    axis2_endpoint_ref_t *to)
{
    AXIS2_PARAM_CHECK(env->error, to, AXIS2_FAILURE);
    
    return axis2_msg_ctx_set_to(rm_msg_ctx->msg_ctx, env, to);
}
    
axis2_endpoint_ref_t *AXIS2_CALL
sandesha2_msg_ctx_get_reply_to(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    return axis2_msg_ctx_get_reply_to(rm_msg_ctx->msg_ctx, env);
}

axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_reply_to(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env, axis2_endpoint_ref_t *reply_to)
{
    AXIS2_PARAM_CHECK(env->error, reply_to, AXIS2_FAILURE);
    
    return axis2_msg_ctx_set_reply_to(rm_msg_ctx->msg_ctx, env, reply_to);
}
    
axis2_endpoint_ref_t *AXIS2_CALL
sandesha2_msg_ctx_get_fault_to(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    return axis2_msg_ctx_get_fault_to(rm_msg_ctx->msg_ctx, env);
}

axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_fault_to(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env, axis2_endpoint_ref_t *fault_to)
{
    AXIS2_PARAM_CHECK(env->error, fault_to, AXIS2_FAILURE);
    
    return axis2_msg_ctx_set_fault_to(rm_msg_ctx->msg_ctx, env, fault_to);
}
    
axis2_relates_to_t *AXIS2_CALL
sandesha2_msg_ctx_get_relates_to(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    return axis2_msg_ctx_get_relates_to(rm_msg_ctx->msg_ctx, env);
}

axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_relates_to(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env, axis2_relates_to_t *relates_to)
{
    AXIS2_PARAM_CHECK(env->error, relates_to, AXIS2_FAILURE);
    
    return axis2_msg_ctx_set_relates_to(rm_msg_ctx->msg_ctx, env, relates_to);
}
    
axis2_char_t *AXIS2_CALL
sandesha2_msg_ctx_get_msg_id(
    sandesha2_msg_ctx_t *rm_msg_ctx, 
    const axutil_env_t *env)
{
    return (axis2_char_t*)axis2_msg_ctx_get_wsa_message_id(
                        rm_msg_ctx->msg_ctx, env);
}

axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_msg_id(
    sandesha2_msg_ctx_t *rm_msg_ctx, 
    const axutil_env_t *env, 
    axis2_char_t *msg_id)
{
    AXIS2_PARAM_CHECK(env->error, msg_id, AXIS2_FAILURE);
    
    return axis2_msg_ctx_set_message_id(rm_msg_ctx->msg_ctx, env, msg_id);
}
    
axiom_soap_envelope_t *AXIS2_CALL
sandesha2_msg_ctx_get_soap_envelope(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    return axis2_msg_ctx_get_soap_envelope(rm_msg_ctx->msg_ctx, env);
}

axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_soap_envelope(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env, 
    axiom_soap_envelope_t *soap_envelope)
{
    AXIS2_PARAM_CHECK(env->error, soap_envelope, AXIS2_FAILURE);
    
    return axis2_msg_ctx_set_soap_envelope(rm_msg_ctx->msg_ctx, env, 
                        soap_envelope);
}
            
axis2_char_t *AXIS2_CALL
sandesha2_msg_ctx_get_wsa_action(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    return (axis2_char_t*)axis2_msg_ctx_get_wsa_action(rm_msg_ctx->msg_ctx, env);
}

axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_wsa_action(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env, axis2_char_t *action)
{
    AXIS2_PARAM_CHECK(env->error, action, AXIS2_FAILURE);
    
    return axis2_msg_ctx_set_wsa_action(rm_msg_ctx->msg_ctx, env, action);
}
            
void *AXIS2_CALL
sandesha2_msg_ctx_get_property(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env, axis2_char_t *key)
{
    AXIS2_PARAM_CHECK(env->error, key, NULL);
    
    return axis2_msg_ctx_get_property(rm_msg_ctx->msg_ctx, env, key);
}

axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_property(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env, 
    axis2_char_t *key, 
    void *val)
{
    AXIS2_PARAM_CHECK(env->error, key, AXIS2_FAILURE);
    
    return axis2_msg_ctx_set_property(rm_msg_ctx->msg_ctx, env, key, val);
}
    
axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_soap_action(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env, 
    axutil_string_t *soap_action)
{
    AXIS2_PARAM_CHECK(env->error, soap_action, AXIS2_FAILURE);
    
    if(NULL == rm_msg_ctx->msg_ctx)
        return AXIS2_FAILURE;
    
    return axis2_msg_ctx_set_soap_action(rm_msg_ctx->msg_ctx, env, 
        soap_action);
}
    
axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_paused(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env, 
    axis2_bool_t paused)
{
    if(NULL == rm_msg_ctx->msg_ctx)
        return AXIS2_FAILURE;
    return axis2_msg_ctx_set_paused(rm_msg_ctx->msg_ctx, env, paused);    
}
    
axis2_char_t *AXIS2_CALL
sandesha2_msg_ctx_get_rm_ns_val(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    return rm_msg_ctx->rm_ns_val;
}

axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_rm_ns_val(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env, 
    axis2_char_t *ns_val)
{
    AXIS2_PARAM_CHECK(env->error, ns_val, AXIS2_FAILURE);
    
    if(NULL != rm_msg_ctx->rm_ns_val)
    {
        AXIS2_FREE(env->allocator, rm_msg_ctx->rm_ns_val);
        rm_msg_ctx->rm_ns_val = NULL;
    }
    rm_msg_ctx->rm_ns_val = axutil_strdup(env, ns_val);
    if(0 == axutil_strcmp(ns_val, SANDESHA2_SPEC_2005_02_NS_URI))
        rm_msg_ctx->spec_ver = axutil_strdup(env, SANDESHA2_SPEC_VERSION_1_0);
    if(0 == axutil_strcmp(ns_val, SANDESHA2_SPEC_2007_02_NS_URI))
        rm_msg_ctx->spec_ver = axutil_strdup(env, SANDESHA2_SPEC_VERSION_1_1);
        
    return AXIS2_SUCCESS;
}
    
axis2_char_t *AXIS2_CALL
sandesha2_msg_ctx_get_addr_ns_val(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    return rm_msg_ctx->addr_ns_val;
}

axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_addr_ns_val(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env, axis2_char_t *ns_val)
{
    AXIS2_PARAM_CHECK(env->error, ns_val, AXIS2_FAILURE);
    
    if(NULL != rm_msg_ctx->addr_ns_val)
    {
        AXIS2_FREE(env->allocator, rm_msg_ctx->addr_ns_val);
        rm_msg_ctx->addr_ns_val = NULL;
    }
    rm_msg_ctx->addr_ns_val = axutil_strdup(env, ns_val);
    return AXIS2_SUCCESS;
}
            
int AXIS2_CALL
sandesha2_msg_ctx_get_flow(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    if(NULL == rm_msg_ctx->msg_ctx)
        return -1;
    return axis2_msg_ctx_get_flow(rm_msg_ctx->msg_ctx, env);     
}

axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_flow(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env, int flow)
{
    if(NULL == rm_msg_ctx->msg_ctx)
        return AXIS2_FAILURE;
        
    return axis2_msg_ctx_set_flow(rm_msg_ctx->msg_ctx, env, flow); 
}

axis2_char_t *AXIS2_CALL
sandesha2_msg_ctx_get_rm_spec_ver(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    return rm_msg_ctx->spec_ver;
}

AXIS2_EXTERN axutil_stream_t *AXIS2_CALL
sandesha2_msg_ctx_get_transport_out_stream(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    if(!rm_msg_ctx->msg_ctx)
        return NULL;
    return axis2_msg_ctx_get_transport_out_stream(rm_msg_ctx->msg_ctx, env);
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_transport_out_stream(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env,
    axutil_stream_t *stream)
{
    if(!rm_msg_ctx->msg_ctx)
        return AXIS2_FAILURE;
    return axis2_msg_ctx_set_transport_out_stream(rm_msg_ctx->msg_ctx, env, 
        stream);
}

AXIS2_EXTERN struct axis2_out_transport_info *AXIS2_CALL
sandesha2_msg_ctx_get_out_transport_info(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    if(!rm_msg_ctx->msg_ctx)
        return NULL;
    return axis2_msg_ctx_get_out_transport_info(rm_msg_ctx->msg_ctx, env);
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_out_transport_info(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env,
    struct axis2_out_transport_info *out_transport_info)
{
    if(!rm_msg_ctx->msg_ctx)
        return AXIS2_FAILURE;
    return axis2_msg_ctx_set_out_transport_info(rm_msg_ctx->msg_ctx, 
        env, out_transport_info);
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_reset_out_transport_info(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    if(!rm_msg_ctx->msg_ctx)
        return AXIS2_FAILURE;
    return axis2_msg_ctx_reset_out_transport_info(rm_msg_ctx->msg_ctx, env);
}

axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_create_seq(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env,
    sandesha2_create_seq_t *create_seq)
{
    AXIS2_PARAM_CHECK(env->error, create_seq, AXIS2_FAILURE);
    
    rm_msg_ctx->create_seq = create_seq;
    return AXIS2_SUCCESS;
}
 
sandesha2_create_seq_t *AXIS2_CALL
sandesha2_msg_ctx_get_create_seq(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    return rm_msg_ctx->create_seq;
}
 
axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_create_seq_res(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env,
    sandesha2_create_seq_res_t *create_seq_res)
{
    AXIS2_PARAM_CHECK(env->error, create_seq_res, AXIS2_FAILURE);
   
    if(rm_msg_ctx->create_seq_res)
    {
        sandesha2_create_seq_res_free(rm_msg_ctx->create_seq_res, env);
        rm_msg_ctx->create_seq_res = NULL;
    }

    rm_msg_ctx->create_seq_res = create_seq_res;
    return AXIS2_SUCCESS;
}
 
sandesha2_create_seq_res_t *AXIS2_CALL
sandesha2_msg_ctx_get_create_seq_res(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    return rm_msg_ctx->create_seq_res;
}

axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_close_seq(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env,
    sandesha2_close_seq_t *close_seq)
{
    AXIS2_PARAM_CHECK(env->error, close_seq, AXIS2_FAILURE);
    
    rm_msg_ctx->close_seq = close_seq;
    return AXIS2_SUCCESS;
}
 
sandesha2_close_seq_t *AXIS2_CALL
sandesha2_msg_ctx_get_close_seq(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    return rm_msg_ctx->close_seq;
}

axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_close_seq_res(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env,
    sandesha2_close_seq_res_t *close_seq_res)
{
    AXIS2_PARAM_CHECK(env->error, close_seq_res, AXIS2_FAILURE);
    
    rm_msg_ctx->close_seq_res = close_seq_res;
    return AXIS2_SUCCESS;
}
 
sandesha2_close_seq_res_t *AXIS2_CALL
sandesha2_msg_ctx_get_close_seq_res(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    return rm_msg_ctx->close_seq_res;
}

axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_terminate_seq(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env,
    sandesha2_terminate_seq_t *terminate_seq)
{
    AXIS2_PARAM_CHECK(env->error, terminate_seq, AXIS2_FAILURE);
    
    rm_msg_ctx->terminate_seq = terminate_seq;
    return AXIS2_SUCCESS;
}
 
sandesha2_terminate_seq_t *AXIS2_CALL
sandesha2_msg_ctx_get_terminate_seq(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    return rm_msg_ctx->terminate_seq;
}

axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_terminate_seq_res(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env,
    sandesha2_terminate_seq_res_t *terminate_seq_res)
{
    AXIS2_PARAM_CHECK(env->error, terminate_seq_res, AXIS2_FAILURE);
    
    rm_msg_ctx->terminate_seq_res = terminate_seq_res;
    return AXIS2_SUCCESS;
}
 
sandesha2_terminate_seq_res_t *AXIS2_CALL
sandesha2_msg_ctx_get_terminate_seq_res(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    return rm_msg_ctx->terminate_seq_res;
}

axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_make_connection(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env,
    sandesha2_make_connection_t *make_connection)
{
    AXIS2_PARAM_CHECK(env->error, make_connection, AXIS2_FAILURE);
    
    rm_msg_ctx->make_connection = make_connection;
    return AXIS2_SUCCESS;
}
 
sandesha2_make_connection_t *AXIS2_CALL
sandesha2_msg_ctx_get_make_connection(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    return rm_msg_ctx->make_connection;
}

axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_msg_pending(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env,
    sandesha2_msg_pending_t *msg_pending)
{
    AXIS2_PARAM_CHECK(env->error, msg_pending, AXIS2_FAILURE);
    
    rm_msg_ctx->msg_pending = msg_pending;
    return AXIS2_SUCCESS;
}
 
sandesha2_msg_pending_t *AXIS2_CALL
sandesha2_msg_ctx_get_msg_pending(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    return rm_msg_ctx->msg_pending;
}

axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_sequence(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env,
    sandesha2_seq_t *seq)
{
    AXIS2_PARAM_CHECK(env->error, seq, AXIS2_FAILURE);
    
    rm_msg_ctx->seq = seq;
    return AXIS2_SUCCESS;
}
 
sandesha2_seq_t *AXIS2_CALL
sandesha2_msg_ctx_get_sequence(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    return rm_msg_ctx->seq;
}

axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_seq_ack(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env,
    sandesha2_seq_ack_t *seq_ack)
{
    AXIS2_PARAM_CHECK(env->error, seq_ack, AXIS2_FAILURE);
    
    rm_msg_ctx->seq_ack = seq_ack;
    return AXIS2_SUCCESS;
}
 
sandesha2_seq_ack_t *AXIS2_CALL
sandesha2_msg_ctx_get_seq_ack(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    return rm_msg_ctx->seq_ack;
}

axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_ack_requested(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env,
    sandesha2_ack_requested_t *ack_requested)
{
    AXIS2_PARAM_CHECK(env->error, ack_requested, AXIS2_FAILURE);
    
    rm_msg_ctx->ack_requested = ack_requested;
    return AXIS2_SUCCESS;
}
 
sandesha2_ack_requested_t *AXIS2_CALL
sandesha2_msg_ctx_get_ack_requested(
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axutil_env_t *env)
{
    return rm_msg_ctx->ack_requested;
}

axis2_bool_t AXIS2_CALL
sandesha2_msg_ctx_get_server_side(
    const sandesha2_msg_ctx_t * rm_msg_ctx,
    const axutil_env_t * env)
{
    return axis2_msg_ctx_get_server_side(rm_msg_ctx->msg_ctx, env);
}

axis2_status_t AXIS2_CALL
sandesha2_msg_ctx_set_server_side(
    const sandesha2_msg_ctx_t * rm_msg_ctx,
    const axutil_env_t * env,
    const axis2_bool_t server_side)
{
    return axis2_msg_ctx_set_server_side(rm_msg_ctx->msg_ctx, env, server_side);
}

