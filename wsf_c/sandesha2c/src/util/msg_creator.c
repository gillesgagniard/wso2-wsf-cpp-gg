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
 
#include <sandesha2_msg_creator.h>
#include <sandesha2_storage_mgr.h>
#include <sandesha2_seq_property_mgr.h>
#include <sandesha2_spec_specific_consts.h>
#include <sandesha2_utils.h>
#include <sandesha2_ack_mgr.h>
#include <sandesha2_seq_ack.h>
#include <sandesha2_constants.h>
#include <sandesha2_msg_ctx.h>
#include <sandesha2_create_seq.h>
#include <sandesha2_create_seq_res.h>
#include <sandesha2_close_seq.h>
#include <sandesha2_close_seq_res.h>
#include <sandesha2_acks_to.h>
#include <sandesha2_address.h>
#include <sandesha2_seq_offer.h>
#include <sandesha2_accept.h>
#include <sandesha2_msg_init.h>
#include <sandesha2_spec_specific_consts.h>
#include <sandesha2_terminate_seq.h>
#include <sandesha2_identifier.h>
#include <sandesha2_make_connection.h>
#include <sandesha2_client_constants.h>

#include <axis2_conf_ctx.h>
#include <axis2_ctx.h>
#include <axis2_msg_ctx.h>
#include <axutil_property.h>
#include <axutil_log.h>
#include <axutil_uuid_gen.h>
#include <axis2_addr.h>
#include <axis2_options.h>
#include <axiom_soap_envelope.h>
#include <axiom_soap_header.h>
#include <axiom_soap_body.h>
#include <axiom_node.h>
#include <sandesha2_terminate_seq_res.h>

  
static axis2_status_t
sandesha2_msg_creator_finalize_creation(
    const axutil_env_t *env,
    axis2_msg_ctx_t *related_msg,
    axis2_msg_ctx_t *new_msg);
 
static axis2_status_t
sandesha2_msg_creator_init_creation(
    const axutil_env_t *env,
    axis2_msg_ctx_t *related_msg,
    axis2_msg_ctx_t *new_msg);

/**
 * Create a new create_seq_msg
 * @param env
 * @param application_rm_msg
 * @param internal_seq_id
 * @param acks_to
 * @param seq_prop_mgr
 * @return sandesha2_msg_ctx_t
 */
sandesha2_msg_ctx_t *AXIS2_CALL
sandesha2_msg_creator_create_create_seq_msg(
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *application_rm_msg, 
    axis2_char_t *internal_seq_id,
    axis2_char_t *acks_to,
    sandesha2_seq_property_mgr_t *seq_prop_mgr)
{
    axis2_msg_ctx_t *application_msg_ctx = NULL;
    axis2_msg_ctx_t *create_seq_msg_ctx = NULL;
    axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_op_t *app_msg_op_desc = NULL;
    axis2_op_ctx_t *op_ctx = NULL;
    axis2_char_t *create_seq_msg_id = NULL;
    axis2_char_t *rm_version = NULL;
    axis2_char_t *rm_ns_value = NULL;
    axis2_char_t *addressing_ns_value = NULL;
    axis2_char_t *anonymous_uri = NULL;
    axis2_char_t *temp_value = NULL;
    axis2_char_t *temp_action = NULL;
    axutil_string_t *temp_soap_action = NULL;
    axis2_endpoint_ref_t *to_epr = NULL;
    axis2_endpoint_ref_t *temp_to = NULL;
    axis2_endpoint_ref_t *acks_to_epr = NULL;
    axis2_endpoint_ref_t *temp_reply_to = NULL;
    sandesha2_create_seq_t *create_seq_part = NULL;
    sandesha2_seq_property_bean_t *reply_to_bean = NULL;
    sandesha2_seq_property_bean_t *to_bean = NULL;
    sandesha2_msg_ctx_t *create_seq_rm_msg = NULL;
    sandesha2_address_t *temp_address = NULL;
    sandesha2_acks_to_t *temp_acks_to = NULL;
    axutil_property_t *property = NULL;
    const axis2_char_t *reply_to_address = NULL;

    application_msg_ctx = sandesha2_msg_ctx_get_msg_ctx(application_rm_msg, env);
    if(!application_msg_ctx)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_APPLICATION_MSG_NULL, AXIS2_FAILURE);
        return NULL;
    }

    conf_ctx = axis2_msg_ctx_get_conf_ctx(application_msg_ctx, env);
    if(!conf_ctx)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_CONF_CTX_NULL, AXIS2_FAILURE);
        return NULL;
    }

    /* Creating by copying common contents.
     */
    create_seq_msg_ctx = sandesha2_utils_create_new_related_msg_ctx(env, application_rm_msg);

    sandesha2_msg_creator_init_creation(env, application_msg_ctx, create_seq_msg_ctx);

    create_seq_msg_id = axutil_uuid_gen(env);
    axis2_msg_ctx_set_message_id(create_seq_msg_ctx, env, create_seq_msg_id);
    AXIS2_FREE(env->allocator, create_seq_msg_id);

    app_msg_op_desc = axis2_msg_ctx_get_op(application_msg_ctx, env);

    property = axis2_msg_ctx_get_property(application_msg_ctx, env, AXIS2_TARGET_EPR);
    if(property)
    {
        temp_to = axutil_property_get_value(property, env);
        to_epr = axis2_endpoint_ref_create(env, axis2_endpoint_ref_get_address(temp_to, env));
    }

    if (!to_epr)
    {
        temp_to = sandesha2_msg_ctx_get_to(application_rm_msg, env); 
        if (temp_to)
        {
            to_epr = axis2_endpoint_ref_create(env, axis2_endpoint_ref_get_address(temp_to, env));
        }
    }

    if (to_epr)
    {
        axis2_msg_ctx_set_to(create_seq_msg_ctx, env, to_epr);
        to_epr = NULL;
    }
    
    temp_reply_to = sandesha2_msg_ctx_get_reply_to(application_rm_msg, env); 
    if(temp_reply_to)
    {
        axis2_endpoint_ref_t *reply_to_epr = NULL;

        reply_to_address = axis2_endpoint_ref_get_address(temp_reply_to, env);
        reply_to_epr = axis2_endpoint_ref_create(env, reply_to_address);
        if(reply_to_epr)
        {
            axis2_msg_ctx_set_reply_to(create_seq_msg_ctx, env, reply_to_epr);
        }
    }

    create_seq_rm_msg = sandesha2_msg_ctx_create(env, create_seq_msg_ctx);

        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "create_seq_internal_seq_id:%s", internal_seq_id);
    rm_version = sandesha2_utils_get_rm_version(env, application_msg_ctx);

    if(!rm_version)
    {
        AXIS2_ERROR_SET(env->error, 
                SANDESHA2_ERROR_CANNOT_FIND_RM_VERSION_OF_GIVEN_MSG, AXIS2_FAILURE);
        return NULL;
    }

    rm_ns_value = sandesha2_spec_specific_consts_get_rm_ns_val(env, rm_version);

    addressing_ns_value = sandesha2_utils_get_seq_property(env, internal_seq_id, 
        SANDESHA2_SEQ_PROP_ADDRESSING_NAMESPACE_VALUE, seq_prop_mgr);

    create_seq_part = sandesha2_create_seq_create(env, addressing_ns_value, rm_ns_value);
    if(!create_seq_part)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] creating create sequence message failed");
        return NULL;
    }

    /* Adding sequence offer if present */
    op_ctx = axis2_msg_ctx_get_op_ctx(application_msg_ctx, env);
    if(op_ctx)
    {
        axis2_op_t *operation = NULL;
        int mep = -1;
        axis2_char_t *offered_seq_id = NULL;
        /*axutil_property_t *property = NULL;
        axis2_ctx_t *ctx = NULL;

        ctx = axis2_msg_ctx_get_base(application_msg_ctx, env);
        property = axis2_ctx_get_property(ctx, env, SANDESHA2_CLIENT_OFFERED_SEQ_ID);
        if(property)
        {
            offered_seq_id = axutil_property_get_value(property, env);
        }*/
        operation = axis2_op_ctx_get_op(op_ctx, env);
        mep = axis2_op_get_axis_specific_mep_const(operation, env);
        if(mep == AXIS2_MEP_CONSTANT_OUT_IN)
        {
            offered_seq_id = axutil_uuid_gen(env);
        }

        /*if(offered_seq_id && 0 != axutil_strcmp("", offered_seq_id))*/
        if(offered_seq_id)
        {
            sandesha2_seq_offer_t *offer_part = NULL;
            sandesha2_identifier_t *identifier = NULL;
            sandesha2_endpoint_t *endpoint = NULL;

            offer_part = sandesha2_seq_offer_create(env, rm_ns_value, addressing_ns_value);
            identifier = sandesha2_identifier_create(env, rm_ns_value);
            sandesha2_identifier_set_identifier(identifier, env, offered_seq_id);
            sandesha2_seq_offer_set_identifier(offer_part, env, identifier);

            if(!axutil_strcmp(SANDESHA2_SPEC_VERSION_1_1, rm_version))
            {
                axis2_endpoint_ref_t *reply_to_epr = NULL;
                sandesha2_address_t *address = NULL;

                reply_to_epr = axis2_endpoint_ref_create(env, reply_to_address);
                address = sandesha2_address_create(env, addressing_ns_value, reply_to_epr);
                endpoint = sandesha2_endpoint_create(env, address, rm_ns_value, 
                        addressing_ns_value);

                sandesha2_seq_offer_set_endpoint(offer_part, env, endpoint);
            }

            sandesha2_create_seq_set_seq_offer(create_seq_part, env, offer_part);
        }
    }

    reply_to_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env, internal_seq_id, 
            SANDESHA2_SEQ_PROP_REPLY_TO_EPR);

    to_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env, internal_seq_id, 
            SANDESHA2_SEQ_PROP_TO_EPR);
    if (to_bean)
    {
        temp_value = sandesha2_seq_property_bean_get_value(to_bean, env);
    
        if (temp_value)
        {
            to_epr = axis2_endpoint_ref_create(env, temp_value);
        }

        sandesha2_seq_property_bean_free(to_bean, env);
    }

    anonymous_uri = sandesha2_spec_specific_consts_get_anon_uri(env, addressing_ns_value);
    if(reply_to_bean)
    {
        axis2_endpoint_ref_t *reply_to_epr = NULL;

        temp_value = sandesha2_seq_property_bean_get_value(reply_to_bean, env);
        if(temp_value)
        {
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "dam_reply_to:%s", temp_value);
            reply_to_epr = axis2_endpoint_ref_create(env, temp_value);
            acks_to = axutil_strdup(env, temp_value);
        }

        if(reply_to_epr)
        {
            sandesha2_msg_ctx_set_reply_to(create_seq_rm_msg, env, reply_to_epr);
        }
        
        sandesha2_seq_property_bean_free(reply_to_bean, env);
    }
    
    if(!acks_to || !axutil_strcmp("", acks_to))
    {
        acks_to = axutil_strdup(env, anonymous_uri);
    }

    acks_to_epr = axis2_endpoint_ref_create(env, acks_to);

    temp_to = sandesha2_msg_ctx_get_to(create_seq_rm_msg, env);
    if(!temp_to && to_epr)
    {
        sandesha2_msg_ctx_set_to(create_seq_rm_msg, env, to_epr);
    }
    else
    {
        axis2_endpoint_ref_free(to_epr, env);
    }


    temp_address = sandesha2_address_create(env, addressing_ns_value, acks_to_epr);
    temp_acks_to = sandesha2_acks_to_create(env, temp_address, rm_ns_value, addressing_ns_value);

    if(addressing_ns_value)
    {
        AXIS2_FREE(env->allocator, addressing_ns_value);
    }

    sandesha2_create_seq_set_acks_to(create_seq_part, env,  temp_acks_to);
    sandesha2_msg_ctx_set_create_seq(create_seq_rm_msg, env, create_seq_part);
    sandesha2_msg_ctx_add_soap_envelope(create_seq_rm_msg, env);
    temp_action = sandesha2_spec_specific_consts_get_create_seq_action(env, rm_version);

    sandesha2_msg_ctx_set_wsa_action(create_seq_rm_msg, env, temp_action);

    temp_soap_action = axutil_string_create(env, temp_action);
    if(temp_soap_action)
    {
        sandesha2_msg_ctx_set_soap_action(create_seq_rm_msg, env, temp_soap_action);
        axutil_string_free(temp_soap_action, env);
    }

    /*sandesha2_msg_creator_finalize_creation(env, application_msg_ctx, create_seq_msg_ctx);*/

    return create_seq_rm_msg;
}

/**
 * Create a new create_seq_response message.
 * @param env axis2 environment struct
 * @param create_seq_msg
 * @param out_msg
 * @param new_seq_id
 * @param seq_prop_mgr
 * @return sandesha2_msg_ctx_t
 */
sandesha2_msg_ctx_t *
sandesha2_msg_creator_create_create_seq_res_msg(
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *create_seq_msg,
    axis2_msg_ctx_t *out_msg,
    axis2_char_t *new_seq_id,
    sandesha2_seq_property_mgr_t *seq_prop_mgr)
{
    axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_msg_ctx_t *temp_msg_ctx = NULL;
    axis2_char_t *rm_version = NULL;
    axis2_char_t *rm_ns_value = NULL;
    axis2_char_t *addressing_ns_value = NULL;
    axis2_char_t *new_msg_id = NULL;
    axis2_char_t *temp_action = NULL;
    axutil_string_t *soap_action = NULL;
    axiom_soap_envelope_t *envelope = NULL;
    axiom_soap_envelope_t *temp_envelope = NULL;
    axiom_soap_body_t *temp_soap_body = NULL;
    axiom_node_t *temp_om_node = NULL;
    sandesha2_create_seq_res_t *create_seq_res = NULL;
    sandesha2_identifier_t *identifier = NULL;
    sandesha2_seq_offer_t *offer = NULL;
    sandesha2_msg_ctx_t *create_seq_res_rm_msg_ctx = NULL;
    sandesha2_create_seq_t *cs = NULL;
    int soap_version = -1;

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[sandesha2] Entry:sandesha2_msg_creator_create_create_seq_res_msg");

    temp_msg_ctx = sandesha2_msg_ctx_get_msg_ctx(create_seq_msg, env);
    conf_ctx = axis2_msg_ctx_get_conf_ctx(temp_msg_ctx, env);
    cs = sandesha2_msg_ctx_get_create_seq(create_seq_msg, env);
    rm_version = sandesha2_utils_get_rm_version(env, temp_msg_ctx);

    if(!rm_version)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] Cannot find rm version of given message");
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_CANNOT_FIND_RM_VERSION_OF_GIVEN_MSG, 
                AXIS2_FAILURE);
        return NULL;
    }

    rm_ns_value = sandesha2_spec_specific_consts_get_rm_ns_val(env, rm_version);
    addressing_ns_value = sandesha2_utils_get_seq_property(env, new_seq_id, 
        SANDESHA2_SEQ_PROP_ADDRESSING_NAMESPACE_VALUE, seq_prop_mgr);
    if(!addressing_ns_value)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] Cannot find addressing namespace value");
        return NULL;
    }

    create_seq_res = sandesha2_create_seq_res_create(env, rm_ns_value, addressing_ns_value);
    identifier = sandesha2_identifier_create(env, rm_ns_value);
    sandesha2_identifier_set_identifier(identifier, env, new_seq_id);
    sandesha2_create_seq_res_set_identifier(create_seq_res, env, identifier);
    offer = sandesha2_create_seq_get_seq_offer(cs, env);

    if(offer)
    {
        axis2_char_t *out_seq_id = NULL;
        sandesha2_identifier_t *temp_identifier = NULL;
        
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] Offer present");

        temp_identifier = sandesha2_seq_offer_get_identifier(offer, env);
        out_seq_id = sandesha2_identifier_get_identifier(temp_identifier, env);
        if(out_seq_id && axutil_strcmp("", out_seq_id))
        {
            sandesha2_accept_t *accept = NULL;
            axis2_endpoint_ref_t *acks_to_epr = NULL;
            sandesha2_acks_to_t *acks_to = NULL;
            sandesha2_address_t *address = NULL;

            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] out_seq_id present");

            accept = sandesha2_accept_create(env, rm_ns_value, addressing_ns_value);
            if(accept)
            {
                axis2_endpoint_ref_t *temp_to_epr = NULL;

                acks_to_epr = sandesha2_msg_ctx_get_to(create_seq_msg, env);
                if(acks_to_epr)
                {
                    temp_to_epr = sandesha2_util_endpoint_ref_clone(env, acks_to_epr);
                }

                address = sandesha2_address_create(env, addressing_ns_value, temp_to_epr);
                acks_to = sandesha2_acks_to_create(env, address, rm_ns_value, addressing_ns_value);
                sandesha2_accept_set_acks_to(accept, env, acks_to);
                sandesha2_create_seq_res_set_accept(create_seq_res, env, accept);
            }
            else
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] Could not create accept element");
                return NULL;
            }
        }
    }

    temp_envelope = sandesha2_msg_ctx_get_soap_envelope(create_seq_msg, env); 
    soap_version = sandesha2_utils_get_soap_version(env, temp_envelope);
    envelope = axiom_soap_envelope_create_default_soap_envelope(env, soap_version);
    temp_soap_body = axiom_soap_envelope_get_body(envelope, env);
    temp_om_node = axiom_soap_body_get_base_node(temp_soap_body, env);
    sandesha2_create_seq_res_to_om_node(create_seq_res, env, temp_om_node);
    temp_action = sandesha2_spec_specific_consts_get_create_seq_res_action(env, rm_version);

    axis2_msg_ctx_set_wsa_action(out_msg, env, temp_action);

    soap_action = axutil_string_create(env, temp_action);
    /*if(soap_action)
    {
        axis2_msg_ctx_set_soap_action(out_msg, env, soap_action);
        axutil_string_free(soap_action, env);
    }*/

    if(addressing_ns_value)
    {
        AXIS2_FREE(env->allocator, addressing_ns_value);
    }

    new_msg_id = axutil_uuid_gen(env);
    if(new_msg_id)
    {
        axis2_msg_ctx_set_message_id(out_msg, env, new_msg_id);
        AXIS2_FREE(env->allocator, new_msg_id);
    }

    axis2_msg_ctx_set_soap_envelope(out_msg, env, envelope);
    temp_msg_ctx = sandesha2_msg_ctx_get_msg_ctx(create_seq_msg, env);
    sandesha2_msg_creator_init_creation(env, temp_msg_ctx, out_msg);
    create_seq_res_rm_msg_ctx = sandesha2_msg_init_init_msg(env, out_msg);
    sandesha2_msg_ctx_set_create_seq_res(create_seq_res_rm_msg_ctx, env, create_seq_res);
    temp_msg_ctx = sandesha2_msg_ctx_get_msg_ctx(create_seq_msg, env);
    sandesha2_msg_creator_finalize_creation(env, temp_msg_ctx, out_msg);
    axis2_msg_ctx_set_server_side(temp_msg_ctx, env, AXIS2_TRUE);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[sandesha2] Exit:sandesha2_msg_creator_create_create_seq_res_msg");

    return create_seq_res_rm_msg_ctx;
}
 
/**
 * Create a new create_close_seq_msg
 * @param env
 * @param ref_rm_msg
 * @param seq_id
 * @param internal_seq_id
 * @param seq_prop_mgr
 * @return
 */
sandesha2_msg_ctx_t *AXIS2_CALL
sandesha2_msg_creator_create_close_seq_msg(
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *ref_rm_msg, 
    axis2_char_t *seq_id,
    axis2_char_t *internal_seq_id,
    sandesha2_seq_property_mgr_t *seq_prop_mgr)
{
    axis2_msg_ctx_t *ref_msg_ctx = NULL;
    axis2_msg_ctx_t *close_seq_msg_ctx = NULL;
    axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_char_t *close_seq_msg_id = NULL;
    axis2_char_t *temp_msg_id = NULL;
    axis2_char_t *rm_version = NULL;
    axis2_char_t *rm_ns_value = NULL;
    axis2_bool_t is_seq_res_reqd = AXIS2_FALSE;
    axiom_soap_envelope_t *temp_envelope = NULL;
    sandesha2_msg_ctx_t *close_rm_msg = NULL;
    sandesha2_close_seq_t *close_seq = NULL;
    int soap_version = -1;
    sandesha2_identifier_t *identifier = NULL;
    sandesha2_last_msg_number_t *last_msg_number = NULL;
    sandesha2_seq_property_bean_t *last_out_msg_no_bean = NULL;

    ref_msg_ctx = sandesha2_msg_ctx_get_msg_ctx(ref_rm_msg, env);
    /*axis2_msg_ctx_set_keep_alive(ref_msg_ctx, env, AXIS2_TRUE);*/
    if(!ref_msg_ctx)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_MSG_CTX,
                AXIS2_FAILURE);
        return NULL;
    }

    conf_ctx = axis2_msg_ctx_get_conf_ctx(ref_msg_ctx, env);
    if(!conf_ctx)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_CONF_CTX_NULL, AXIS2_FAILURE);
        return NULL;
    }
    close_seq_msg_ctx = sandesha2_utils_create_new_related_msg_ctx(env, ref_rm_msg);
    close_seq_msg_id = (axis2_char_t*)axis2_msg_ctx_get_msg_id(
                        close_seq_msg_ctx, env);

    rm_version = sandesha2_utils_get_rm_version(env, ref_msg_ctx);
    if(!rm_version)
    {
        AXIS2_ERROR_SET(env->error, 
            SANDESHA2_ERROR_CANNOT_FIND_RM_VERSION_OF_GIVEN_MSG, AXIS2_FAILURE);
        return NULL;
    }

    rm_ns_value = sandesha2_spec_specific_consts_get_rm_ns_val(env, rm_version);
    sandesha2_msg_creator_init_creation(env, ref_msg_ctx, close_seq_msg_ctx);

    is_seq_res_reqd = sandesha2_spec_specific_consts_is_term_seq_res_reqd(env, rm_version);

    if(!is_seq_res_reqd)
    {
        axis2_msg_ctx_set_property(close_seq_msg_ctx, env, AXIS2_TRANSPORT_IN, NULL);
    }

    close_rm_msg = sandesha2_msg_init_init_msg(env, close_seq_msg_ctx);
    if(!close_rm_msg)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_MSG_CTX, AXIS2_FAILURE);
        return NULL;
    }

    temp_msg_id = axutil_uuid_gen(env);
    axis2_msg_ctx_set_message_id(close_seq_msg_ctx, env, temp_msg_id);
    AXIS2_FREE(env->allocator, temp_msg_id);
    temp_envelope = sandesha2_msg_ctx_get_soap_envelope(ref_rm_msg, env);
    soap_version = sandesha2_utils_get_soap_version(env, temp_envelope);

    close_seq = sandesha2_close_seq_create(env, rm_ns_value);
    identifier = sandesha2_identifier_create(env, rm_ns_value);
    sandesha2_identifier_set_identifier(identifier, env, seq_id);
    sandesha2_close_seq_set_identifier(close_seq, env, identifier);
    sandesha2_msg_ctx_set_close_seq(close_rm_msg, env, close_seq);

    if(is_seq_res_reqd)
    {
        last_out_msg_no_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env, 
            internal_seq_id, SANDESHA2_SEQ_PROP_LAST_OUT_MESSAGE_NUMBER);
    }

    if(last_out_msg_no_bean)
    {
        axis2_char_t *msg_no_str = NULL;
        long last_msg_num = -1;

        msg_no_str = sandesha2_seq_property_bean_get_value(last_out_msg_no_bean, env);
        if(msg_no_str)
        {
            last_msg_num = atol(msg_no_str);
        }

        last_msg_number = sandesha2_last_msg_number_create(env, rm_ns_value);
        if(last_msg_number)
        {
            sandesha2_last_msg_number_set_last_msg_number(last_msg_number, env, last_msg_num);
            sandesha2_close_seq_set_last_msg_number(close_seq, env, last_msg_number);
        }

        sandesha2_seq_property_bean_free(last_out_msg_no_bean, env);
    }

    sandesha2_msg_creator_finalize_creation(env, ref_msg_ctx, close_seq_msg_ctx);
    axis2_msg_ctx_set_property(close_seq_msg_ctx, env, AXIS2_TRANSPORT_IN, NULL);

    return close_rm_msg;
}


/**
 * Create a new close_seq_response message.
 * @param close_seq_msg
 * @param out_msg
 * @param seq_prop_mgr
 * @return
 */
sandesha2_msg_ctx_t *
sandesha2_msg_creator_create_close_seq_res_msg(
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *close_seq_msg,
    axis2_msg_ctx_t *out_msg,
    sandesha2_seq_property_mgr_t *seq_prop_mgr)
{
    axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_msg_ctx_t *temp_msg_ctx = NULL;
    axis2_char_t *rm_version = NULL;
    axis2_char_t *rm_ns_val = NULL;
    axis2_char_t *temp_action = NULL;
    axutil_string_t *soap_action = NULL;
    axis2_char_t *seq_id = NULL;
    axiom_soap_envelope_t *envelope = NULL;
    axiom_soap_envelope_t *temp_envelope = NULL;
    sandesha2_close_seq_t *cs = NULL;
    sandesha2_msg_ctx_t *close_seq_res_rm_msg_ctx = NULL;
    sandesha2_identifier_t *identifier = NULL;
    sandesha2_identifier_t *temp_identifier = NULL;
    sandesha2_close_seq_res_t *close_seq_res = NULL;
    int soap_version = -1;

    close_seq_res_rm_msg_ctx = sandesha2_msg_ctx_create(env, out_msg);
    temp_msg_ctx = sandesha2_msg_ctx_get_msg_ctx(close_seq_msg, env);
    conf_ctx = axis2_msg_ctx_get_conf_ctx(temp_msg_ctx, env);
    cs = (sandesha2_close_seq_t *) sandesha2_msg_ctx_get_close_seq(close_seq_msg, env);
    temp_identifier = sandesha2_close_seq_get_identifier(cs, env);
    seq_id = sandesha2_identifier_get_identifier(temp_identifier, env);
    rm_ns_val = sandesha2_msg_ctx_get_rm_ns_val(close_seq_msg, env);
    sandesha2_msg_ctx_set_rm_ns_val(close_seq_res_rm_msg_ctx, env, rm_ns_val);
    close_seq_res = sandesha2_close_seq_res_create(env, rm_ns_val);
    identifier = sandesha2_identifier_create(env, rm_ns_val);
    sandesha2_identifier_set_identifier(identifier, env, seq_id);
    sandesha2_close_seq_res_set_identifier(close_seq_res, env, identifier);
    temp_envelope = sandesha2_msg_ctx_get_soap_envelope(close_seq_msg, env); 
    soap_version = sandesha2_utils_get_soap_version(env, temp_envelope);
    envelope = axiom_soap_envelope_create_default_soap_envelope(env, soap_version);
    sandesha2_msg_ctx_set_soap_envelope(close_seq_res_rm_msg_ctx, env, envelope);
    sandesha2_msg_ctx_set_close_seq_res(close_seq_res_rm_msg_ctx, env, close_seq_res);
    rm_version = sandesha2_utils_get_rm_version(env, temp_msg_ctx);
    temp_action = sandesha2_spec_specific_consts_get_close_seq_res_action(env, rm_version);
    axis2_msg_ctx_set_wsa_action(out_msg, env, temp_action);
    temp_action = sandesha2_spec_specific_consts_get_close_seq_res_action(env, rm_version);

    soap_action = axutil_string_create(env, temp_action);
    axis2_msg_ctx_set_soap_action(out_msg, env, soap_action);


    temp_msg_ctx = sandesha2_msg_ctx_get_msg_ctx(close_seq_msg, env);
    sandesha2_msg_creator_init_creation(env, temp_msg_ctx,out_msg);
    sandesha2_msg_ctx_add_soap_envelope(close_seq_res_rm_msg_ctx, env);
    sandesha2_msg_creator_finalize_creation(env, temp_msg_ctx, out_msg);
    axis2_msg_ctx_set_server_side(temp_msg_ctx, env, AXIS2_TRUE);
    return close_seq_res_rm_msg_ctx;
}
  
/**
 * Create a new create_terminate_seq_msg
 * @param env
 * @param ref_rm_msg
 * @param seq_id
 * @param internal_seq_id
 * @param seq_prop_mgr
 * @return
 */
sandesha2_msg_ctx_t *AXIS2_CALL
sandesha2_msg_creator_create_terminate_seq_msg(
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *ref_rm_msg, 
    axis2_char_t *seq_id,
    axis2_char_t *internal_seq_id,
    sandesha2_seq_property_mgr_t *seq_prop_mgr)
{
    axis2_msg_ctx_t *ref_msg_ctx = NULL;
    axis2_msg_ctx_t *terminate_seq_msg_ctx = NULL;
    axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_char_t *terminate_seq_msg_id = NULL;
    axis2_char_t *temp_msg_id = NULL;
    axis2_char_t *rm_version = NULL;
    axis2_char_t *rm_ns_value = NULL;
    axis2_bool_t is_seq_res_reqd = AXIS2_FALSE;
    axiom_soap_envelope_t *temp_envelope = NULL;
    sandesha2_msg_ctx_t *terminate_rm_msg = NULL;
    sandesha2_terminate_seq_t *terminate_seq = NULL;
    int soap_version = -1;
    sandesha2_identifier_t *identifier = NULL;
    sandesha2_last_msg_number_t *last_msg_number = NULL;
    sandesha2_seq_property_bean_t *last_out_msg_no_bean = NULL;

    ref_msg_ctx = sandesha2_msg_ctx_get_msg_ctx(ref_rm_msg, env);
    /*axis2_msg_ctx_set_keep_alive(ref_msg_ctx, env, AXIS2_TRUE);*/
    if(!ref_msg_ctx)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_MSG_CTX,
                AXIS2_FAILURE);
        return NULL;
    }

    conf_ctx = axis2_msg_ctx_get_conf_ctx(ref_msg_ctx, env);
    if(!conf_ctx)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_CONF_CTX_NULL, AXIS2_FAILURE);
        return NULL;
    }
    terminate_seq_msg_ctx = sandesha2_utils_create_new_related_msg_ctx(env, ref_rm_msg);
    terminate_seq_msg_id = (axis2_char_t*)axis2_msg_ctx_get_msg_id(
                        terminate_seq_msg_ctx, env);

    rm_version = sandesha2_utils_get_rm_version(env, ref_msg_ctx);
    if(!rm_version)
    {
        AXIS2_ERROR_SET(env->error, 
            SANDESHA2_ERROR_CANNOT_FIND_RM_VERSION_OF_GIVEN_MSG, AXIS2_FAILURE);
        return NULL;
    }

    rm_ns_value = sandesha2_spec_specific_consts_get_rm_ns_val(env, rm_version);
    sandesha2_msg_creator_init_creation(env, ref_msg_ctx, terminate_seq_msg_ctx);

    is_seq_res_reqd = sandesha2_spec_specific_consts_is_term_seq_res_reqd(env, rm_version);

    if(!is_seq_res_reqd)
    {
        axis2_msg_ctx_set_property(terminate_seq_msg_ctx, env, AXIS2_TRANSPORT_IN, NULL);
    }

    terminate_rm_msg = sandesha2_msg_init_init_msg(env, terminate_seq_msg_ctx);
    if(!terminate_rm_msg)
    {
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_NULL_MSG_CTX, AXIS2_FAILURE);
        return NULL;
    }

    temp_msg_id = axutil_uuid_gen(env);
    axis2_msg_ctx_set_message_id(terminate_seq_msg_ctx, env, temp_msg_id);
    AXIS2_FREE(env->allocator, temp_msg_id);
    temp_envelope = sandesha2_msg_ctx_get_soap_envelope(ref_rm_msg, env);
    soap_version = sandesha2_utils_get_soap_version(env, temp_envelope);

    terminate_seq = sandesha2_terminate_seq_create(env, rm_ns_value);
    identifier = sandesha2_identifier_create(env, rm_ns_value);
    sandesha2_identifier_set_identifier(identifier, env, seq_id);
    sandesha2_terminate_seq_set_identifier(terminate_seq, env, identifier);
    sandesha2_msg_ctx_set_terminate_seq(terminate_rm_msg, env, terminate_seq);

    if(is_seq_res_reqd)
    {
        last_out_msg_no_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env, 
            internal_seq_id, SANDESHA2_SEQ_PROP_LAST_OUT_MESSAGE_NUMBER);
    }

    if(last_out_msg_no_bean)
    {
        axis2_char_t *msg_no_str = NULL;
        long last_msg_num = -1;

        msg_no_str = sandesha2_seq_property_bean_get_value(last_out_msg_no_bean, env);
        if(msg_no_str)
        {
            last_msg_num = atol(msg_no_str);
        }

        last_msg_number = sandesha2_last_msg_number_create(env, rm_ns_value);
        if(last_msg_number)
        {
            sandesha2_last_msg_number_set_last_msg_number(last_msg_number, env, last_msg_num);
            sandesha2_terminate_seq_set_last_msg_number(terminate_seq, env, last_msg_number);
        }

        sandesha2_seq_property_bean_free(last_out_msg_no_bean, env);
    }

    sandesha2_msg_creator_finalize_creation(env, ref_msg_ctx, terminate_seq_msg_ctx);
    axis2_msg_ctx_set_property(terminate_seq_msg_ctx, env, AXIS2_TRANSPORT_IN, NULL);

    return terminate_rm_msg;
}

sandesha2_msg_ctx_t *AXIS2_CALL
sandesha2_msg_creator_create_terminate_seq_res_msg(
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *ref_rm_msg,
    axis2_msg_ctx_t *out_msg,
    sandesha2_seq_property_mgr_t *seq_prop_mgr)
{
    sandesha2_msg_ctx_t *res_rm_msg = NULL;
    sandesha2_terminate_seq_t *terminate_seq = NULL;
    axis2_char_t *seq_id = NULL;
    axis2_char_t *rm_ns_val = NULL;
    sandesha2_terminate_seq_res_t *terminate_seq_res = NULL;
    sandesha2_identifier_t *identifier = NULL;
    axiom_soap_envelope_t *soap_envelope = NULL;
    axis2_char_t *rm_version = NULL;
    axis2_char_t *temp_action = NULL;
    axutil_string_t *soap_action = NULL;
    
    res_rm_msg = sandesha2_msg_ctx_create(env, out_msg);
    terminate_seq = sandesha2_msg_ctx_get_terminate_seq(ref_rm_msg, env);
    seq_id = sandesha2_identifier_get_identifier(
                        sandesha2_terminate_seq_get_identifier(terminate_seq,
                        env), env);
    rm_ns_val = sandesha2_msg_ctx_get_rm_ns_val(ref_rm_msg, env);
    sandesha2_msg_ctx_set_rm_ns_val(res_rm_msg, env, rm_ns_val);
    
    terminate_seq_res = sandesha2_terminate_seq_res_create(env, rm_ns_val);
    identifier = sandesha2_identifier_create(env, rm_ns_val);
    sandesha2_identifier_set_identifier(identifier, env, seq_id);
    sandesha2_terminate_seq_res_set_identifier(terminate_seq_res, env, 
                        identifier);
    soap_envelope = axiom_soap_envelope_create_default_soap_envelope(env,
                        sandesha2_utils_get_soap_version(env,
                        sandesha2_msg_ctx_get_soap_envelope(ref_rm_msg, env)));
    sandesha2_msg_ctx_set_soap_envelope(res_rm_msg, env, soap_envelope);
    sandesha2_msg_ctx_set_terminate_seq_res(res_rm_msg, env, 
        terminate_seq_res);
    rm_version = sandesha2_utils_get_rm_version(env, sandesha2_msg_ctx_get_msg_ctx(ref_rm_msg, env));
    if(!rm_version)
    {
        rm_version = axutil_strdup(env, sandesha2_msg_ctx_get_rm_spec_ver(ref_rm_msg, env));
    }

    temp_action = sandesha2_spec_specific_consts_get_teminate_seq_res_action(env, rm_version);

    axis2_msg_ctx_set_wsa_action(out_msg, env, temp_action);
    soap_action = axutil_string_create(env, temp_action);
    axis2_msg_ctx_set_soap_action(out_msg, env, soap_action);
    axutil_string_free(soap_action, env);
    sandesha2_msg_creator_init_creation(env, sandesha2_msg_ctx_get_msg_ctx(ref_rm_msg, env), 
            out_msg);

    sandesha2_msg_ctx_add_soap_envelope(ref_rm_msg, env);
    sandesha2_msg_creator_finalize_creation(env, sandesha2_msg_ctx_get_msg_ctx(ref_rm_msg, env), 
            out_msg);

    axis2_msg_ctx_set_server_side(sandesha2_msg_ctx_get_msg_ctx(ref_rm_msg, env), env, AXIS2_TRUE);
    return res_rm_msg;
}

static axis2_status_t
sandesha2_msg_creator_finalize_creation(
    const axutil_env_t *env,
    axis2_msg_ctx_t *related_msg,
    axis2_msg_ctx_t *new_msg)
{
    /*axis2_op_t *old_op = NULL;*/
    /*axis2_op_ctx_t *old_op_ctx = NULL;*/
    axis2_bool_t temp_bool = AXIS2_FALSE;
    /*axutil_hash_t *related_msg_props = NULL;
    axutil_hash_t *new_msg_props = NULL;
    axis2_ctx_t *related_ctx = NULL;
    axis2_ctx_t *new_ctx = NULL;*/

    temp_bool = axis2_msg_ctx_get_server_side(related_msg, env);
    axis2_msg_ctx_set_server_side(new_msg, env, temp_bool);
    /* Adding all parameters from old message to the new one */
    /*old_op = axis2_msg_ctx_get_op(related_msg, env);
    if(old_op)
    {
        axutil_array_list_t *op_params = NULL;

        op_params = axis2_op_get_all_params(old_op, env);
        if(op_params)
        {
            axis2_op_t *new_op = NULL;
            int i = 0, size = 0;

            new_op = axis2_msg_ctx_get_op(new_msg, env);
            size = axutil_array_list_size(op_params, env);
            for(i = 0; i < size; i++)
            {
                axutil_param_t *next_param = NULL;
                axutil_param_t *new_param = NULL;
                axis2_char_t *temp_name = NULL;
                void *temp_value = NULL;

                next_param = (axutil_param_t *) axutil_array_list_get(op_params, 
                        env, i);
                temp_name = axutil_param_get_name(next_param, env);
                temp_value = axutil_param_get_value(next_param, env);
                new_param = axutil_param_create(env, temp_name, temp_value);
                axutil_param_set_value_free(new_param, env, 
                    axutil_param_dummy_free_fn);
                axis2_op_add_param(new_op, env, new_param); 
            }
        }
    }*/
    /* Operation context properties */
    /*old_op_ctx = axis2_msg_ctx_get_op_ctx(related_msg, env);
    if(old_op_ctx)
    {
        axutil_hash_t *old_op_ctx_props = NULL;
        axis2_ctx_t *ctx = NULL;

        ctx = axis2_op_ctx_get_base(old_op_ctx, env);
        old_op_ctx_props = axis2_ctx_get_all_properties(ctx, env);
        if(old_op_ctx_props)
        {
            axis2_op_ctx_t *new_op_ctx = NULL;
            axutil_hash_index_t *hi = NULL;

            new_op_ctx = axis2_msg_ctx_get_op_ctx(new_msg, env);
            for (hi = axutil_hash_first (old_op_ctx_props, env); hi; hi = 
                    axutil_hash_next (env, hi))
            {
                void *v = NULL;
                void *k = NULL;
                axis2_char_t *key = NULL;
                axutil_property_t *prop = NULL;
                axutil_property_t *new_prop = NULL;
                axis2_ctx_t *ctx = NULL;

                axutil_hash_this (hi, (const void **)&k, NULL, &v);
                key = (axis2_char_t *) k;
                prop = (axutil_property_t *) v;
                ctx = axis2_op_ctx_get_base(new_op_ctx, env);
                if(prop)
                    new_prop = axutil_property_clone(prop, env);
                if(new_prop)
                {
                    if(0 == axutil_strcmp(AXIS2_TRANSPORT_IN, key))
                    {
                        axutil_property_set_own_value(new_prop, env, AXIS2_FALSE);
                    }
                    axis2_ctx_set_property(ctx, env, key, new_prop);
                }
            }
        }
    }*/
    /* Setting options with properties copied from the old one */
    /*if(related_msg && new_msg)
    {
        related_ctx = axis2_msg_ctx_get_base(related_msg, env);
        related_msg_props = axis2_ctx_get_all_properties(related_ctx, env);
        new_ctx = axis2_msg_ctx_get_base(new_msg, env);
        new_msg_props = axis2_ctx_get_all_properties(new_ctx, env);
        if(related_msg_props)
        {
            axutil_hash_index_t *i = NULL;

            for (i = axutil_hash_first (related_msg_props, env); i; i = 
                    axutil_hash_next (env, i))
            {
                void *v = NULL;
                void *k = NULL;
                axis2_char_t *key = NULL;
                axutil_property_t *prop = NULL;
                axutil_property_t *new_prop = NULL;

                axutil_hash_this (i, (const void **)&k, NULL, &v);
                key = (axis2_char_t *) k;
                prop = (axutil_property_t *) v;
                if(prop)
                    new_prop = axutil_property_clone(prop, env);
                if(new_prop)
                {
                    if(0 == axutil_strcmp(AXIS2_TRANSPORT_IN, key))
                    {
                        axutil_property_set_own_value(new_prop, env, AXIS2_FALSE);
                    }
                    if(0 == axutil_strcmp(AXIS2_HTTP_CLIENT, key))
                    {
                        axutil_property_set_own_value(new_prop, env, AXIS2_FALSE);
                    }
                    axutil_hash_set(new_msg_props, key, AXIS2_HASH_KEY_STRING, new_prop);
                }
            }
        }
    }*/
    return AXIS2_SUCCESS;
}
 
static axis2_status_t
sandesha2_msg_creator_init_creation(
    const axutil_env_t *env,
    axis2_msg_ctx_t *related_msg,
    axis2_msg_ctx_t *new_msg)
{
    /*axis2_svc_t *related_svc = NULL;
    axis2_svc_t *new_svc = NULL;

    related_svc = axis2_msg_ctx_get_svc(related_msg, env);
    new_svc = axis2_msg_ctx_get_svc(new_msg, env);
    if(related_svc && new_svc && related_svc != new_svc)
    {
        axutil_param_t *ref_policy_param = NULL;

        ref_policy_param = axis2_svc_get_param(related_svc, env, SANDESHA2_SANDESHA_PROPERTY_BEAN);
        if(ref_policy_param)
        {
            void *value = NULL;
            axutil_param_t *new_policy_param = NULL;

            value = axutil_param_get_value(ref_policy_param, env);
            new_policy_param = axutil_param_create(env, SANDESHA2_SANDESHA_PROPERTY_BEAN, value);
        }
        
    }*/
    return AXIS2_SUCCESS;
}

/**
 * Adds an ack message to the given application message.
 * 
 * @param app_msg
 * @param sequence_id
 */
axis2_status_t AXIS2_CALL
sandesha2_msg_creator_add_ack_msg(
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *target_rm_msg_ctx,
    axis2_char_t *seq_id,
    sandesha2_seq_property_mgr_t *seq_prop_mgr)
{
    axiom_soap_envelope_t *envelope = NULL;
    axiom_soap_header_t *soap_header = NULL;
    axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_char_t *rm_version = NULL;
    axis2_char_t *rm_ns_value = NULL;
    axis2_char_t *msg_no_list = NULL;
    axis2_char_t *ack_req_action = NULL;
    axis2_char_t *temp_action = NULL;
    axutil_string_t *ack_req_soap_action = NULL;
    axis2_char_t *str_value = NULL;
    axis2_char_t *uuid = NULL;
    sandesha2_identifier_t *id = NULL;
    sandesha2_seq_ack_t *seq_ack = NULL;
    sandesha2_seq_property_bean_t *seq_bean = NULL;
    sandesha2_seq_property_bean_t *seq_closed_bean = NULL;
    axis2_msg_ctx_t *msg_ctx = NULL;
    axutil_array_list_t *ack_range_list = NULL;
    int i = 0, size = 0;
    
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[sandesha2] Entry:sandesha2_msg_creator_add_ack_msg");

    envelope = sandesha2_msg_ctx_get_soap_envelope(target_rm_msg_ctx, env);
    if(!envelope)
    {
        AXIS2_ERROR_SET(env->error, 
                AXIS2_ERROR_NULL_SOAP_ENVELOPE_IN_MSG_CTX, AXIS2_FAILURE);
        return AXIS2_FAILURE;
    }

    msg_ctx = sandesha2_msg_ctx_get_msg_ctx(target_rm_msg_ctx, env);
    conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);
    rm_version = sandesha2_utils_get_rm_version(env, msg_ctx);
    if(!rm_version)
    {
        AXIS2_ERROR_SET(env->error, 
                SANDESHA2_ERROR_CANNOT_FIND_RM_VERSION_OF_GIVEN_MSG, AXIS2_FAILURE);
        return AXIS2_FAILURE;
    }

    rm_ns_value = sandesha2_spec_specific_consts_get_rm_ns_val(env, rm_version);
    seq_ack = sandesha2_seq_ack_create(env, rm_ns_value);
    id = sandesha2_identifier_create(env, rm_ns_value);
    sandesha2_identifier_set_identifier(id, env, seq_id);
    sandesha2_seq_ack_set_identifier(seq_ack, env, id);
    seq_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env, seq_id, 
            SANDESHA2_SEQ_PROP_SERVER_COMPLETED_MESSAGES);

    if(seq_bean)
    {
        msg_no_list = (axis2_char_t *) sandesha2_seq_property_bean_get_value(seq_bean, env); 
    }

    ack_range_list = sandesha2_utils_get_ack_range_list(env, msg_no_list, rm_ns_value);
    if(seq_bean)
    {
        sandesha2_seq_property_bean_free(seq_bean, env);
    }

    if(ack_range_list)
    {
        size = axutil_array_list_size(ack_range_list, env);
    }

    for(i = 0; i < size; i++)
    {
        sandesha2_ack_range_t *ack_range = NULL;

        ack_range = axutil_array_list_get(ack_range_list, env, i);
        sandesha2_seq_ack_add_ack_range(seq_ack, env, ack_range);
    }

    if(ack_range_list)
    {
        axutil_array_list_free(ack_range_list, env);
    }

    seq_closed_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env, seq_id, 
            SANDESHA2_SEQ_PROP_SEQ_CLOSED);

    if(seq_closed_bean)
    {
        str_value = sandesha2_seq_property_bean_get_value(seq_closed_bean, env);
    }

    if(seq_closed_bean && 0 == axutil_strcmp(AXIS2_VALUE_TRUE, str_value))
    {
        axis2_bool_t is_allowed = AXIS2_FALSE;
        
        /* sequence is closed. so add the 'Final' part. */
        is_allowed = sandesha2_spec_specific_consts_is_ack_final_allowed(env, rm_version);
        if(is_allowed)
        {
            sandesha2_ack_final_t *ack_final = NULL;

            ack_final = sandesha2_ack_final_create(env,rm_ns_value);
            sandesha2_seq_ack_set_ack_final(seq_ack, env, ack_final);
        }
    }

    if(seq_closed_bean)
    {
        sandesha2_seq_property_bean_free(seq_closed_bean, env);
    }

    sandesha2_msg_ctx_set_seq_ack(target_rm_msg_ctx, env, seq_ack);
    soap_header = axiom_soap_envelope_get_header(envelope, env);
    sandesha2_seq_ack_to_om_node(seq_ack, env, soap_header);

    ack_req_action = sandesha2_msg_ctx_get_wsa_action(target_rm_msg_ctx, env);
    if((!ack_req_action) || (!axutil_strcmp(ack_req_action, "")))
    {
        ack_req_action = sandesha2_spec_specific_consts_get_seq_ack_action(env, rm_version);
        sandesha2_msg_ctx_set_wsa_action(target_rm_msg_ctx, env, ack_req_action); 
    }

    temp_action = sandesha2_spec_specific_consts_get_seq_ack_soap_action(env, rm_version);

    ack_req_soap_action = axutil_string_create(env, temp_action);
    if(ack_req_soap_action)
    {
        sandesha2_msg_ctx_set_soap_action(target_rm_msg_ctx, env, ack_req_soap_action); 
        axutil_string_free(ack_req_soap_action, env);
    }

    uuid = axutil_uuid_gen(env);
    sandesha2_msg_ctx_set_msg_id(target_rm_msg_ctx, env, uuid);

    if(uuid)
    {
        AXIS2_FREE(env->allocator, uuid);
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[sandesha2] Exit:sandesha2_msg_creator_add_ack_msg");

    return AXIS2_SUCCESS;
}

sandesha2_msg_ctx_t *AXIS2_CALL
sandesha2_msg_creator_create_make_connection_msg(
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *ref_rm_msg_ctx, 
    axis2_char_t *make_conn_seq_id,
    const axis2_char_t *internal_seq_id,
    axis2_char_t *make_conn_anon_uri,
    sandesha2_seq_property_mgr_t *seq_prop_mgr)
{
    axis2_msg_ctx_t *ref_msg_ctx = NULL;
    axis2_msg_ctx_t *make_conn_msg_ctx = NULL;
    axis2_char_t *rm_ns_value = NULL;
    axis2_char_t *mc_ns_value = NULL;
    axis2_char_t *wsa_action = NULL;
    sandesha2_make_connection_t *make_conn = NULL;
    sandesha2_msg_ctx_t *make_conn_rm_msg_ctx = NULL;
   
    rm_ns_value = sandesha2_spec_specific_consts_get_rm_ns_val(env, SANDESHA2_SPEC_VERSION_1_1);
    
    mc_ns_value = MAKE_CONNECTION_SPEC_2007_02_NS_URI;

    if(ref_rm_msg_ctx)
    {
        ref_msg_ctx = sandesha2_msg_ctx_get_msg_ctx(ref_rm_msg_ctx, env);
    }
    
    make_conn_msg_ctx = sandesha2_utils_create_new_related_msg_ctx(env, ref_rm_msg_ctx);
    if(make_conn_msg_ctx)
    {
        make_conn_rm_msg_ctx = sandesha2_msg_init_init_msg(env, make_conn_msg_ctx);
    }

    /* This if block is an hack to add the addressing handlers to the outflow.
     * Check whether this is not a hack
     */
    /*if(ref_msg_ctx)
    {
        axis2_op_t *op = axis2_msg_ctx_get_op(ref_msg_ctx, env);
        axis2_op_t *make_conn_op = axis2_msg_ctx_get_op(make_conn_msg_ctx, env);
        axutil_array_list_t *out_flow = axis2_op_get_out_flow(op, env);
        axutil_array_list_t *in_flow = axis2_op_get_in_flow(op, env);
        int size = axutil_array_list_size(out_flow, env);
        if(size > 0)
        {
            int i = 0;
            axutil_array_list_t *new_flow = axutil_array_list_create(env, 0);
            for(i = 0; i < size; i++)
            {
                const axis2_phase_t *phase = axutil_array_list_get(out_flow, env, i);
                const axis2_char_t *phase_name = axis2_phase_get_name(phase, env);
                if(0 == axutil_strcmp(phase_name, AXIS2_PHASE_MESSAGE_OUT))
                {
                    axutil_array_list_add(new_flow, env, phase);
                }
            }
            axis2_op_set_out_flow(make_conn_op, env, new_flow);
        }
        size = axutil_array_list_size(in_flow, env);
        if(size > 0)
        {
            int i = 0;
            axutil_array_list_t *new_flow = axutil_array_list_create(env, 0);
            for(i = 0; i < size; i++)
            {
                const axis2_phase_t *phase = axutil_array_list_get(in_flow, env, i);
                const axis2_char_t *phase_name = axis2_phase_get_name(phase, env);
                if(0 == axutil_strcmp(phase_name, "RMPhase"))
                {
                    axutil_array_list_add(new_flow, env, phase);
                }
            }
            axis2_op_set_in_flow(make_conn_op, env, new_flow);
        }
    }*/

    make_conn = sandesha2_make_connection_create(env, mc_ns_value);
    if(make_conn_seq_id)
    {
        sandesha2_identifier_t *identifier = sandesha2_identifier_create(env, 
            rm_ns_value);
        if(identifier)
            sandesha2_identifier_set_identifier(identifier, env, 
                make_conn_seq_id);
        if(make_conn)
            sandesha2_make_connection_set_identifier(make_conn, env, identifier);
    }

    if(make_conn_anon_uri)
    {
        sandesha2_mc_address_t *address = NULL;
        axis2_endpoint_ref_t *epr = NULL;

        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] make_conn_anon_uri:%s", 
                make_conn_anon_uri);

        address = sandesha2_mc_address_create(env, mc_ns_value, NULL);
        epr = axis2_endpoint_ref_create(env, make_conn_anon_uri);

        if(address)
        {
            sandesha2_mc_address_set_epr(address, env, epr);
        }

        if(make_conn)
        {
            sandesha2_make_connection_set_address(make_conn, env, address);
        }
    }

    if(make_conn_msg_ctx)
    {
        axis2_endpoint_ref_t *to = NULL;
        axis2_endpoint_ref_t *reply_to = NULL;
        axis2_char_t *address = NULL;
        axutil_string_t *soap_action = NULL;

        /* Setting the addressing properties */
        to = axis2_msg_ctx_get_to(ref_msg_ctx, env);
        address = (axis2_char_t *) axis2_endpoint_ref_get_address((const axis2_endpoint_ref_t *) to, env);
        to = axis2_endpoint_ref_create(env, address);
        axis2_msg_ctx_set_to(make_conn_msg_ctx, env, to);
        reply_to = axis2_endpoint_ref_create(env, AXIS2_WSA_ANONYMOUS_URL);
        axis2_msg_ctx_set_reply_to(make_conn_msg_ctx, env, reply_to);
        wsa_action = sandesha2_spec_specific_consts_get_make_connection_action(env, SANDESHA2_SPEC_VERSION_1_1);
        axis2_msg_ctx_set_wsa_action(make_conn_msg_ctx, env, wsa_action);
        soap_action = axutil_string_create(env, wsa_action);
        axis2_msg_ctx_set_soap_action(make_conn_msg_ctx, env, soap_action);
        axis2_msg_ctx_set_message_id(make_conn_msg_ctx, env, axutil_uuid_gen(env));
    
        sandesha2_msg_ctx_set_make_connection(make_conn_rm_msg_ctx, env, make_conn);

       /* Generating the soap envelope */
        sandesha2_msg_ctx_add_soap_envelope(make_conn_rm_msg_ctx, env);
        return make_conn_rm_msg_ctx;
    }

    return NULL;
}


