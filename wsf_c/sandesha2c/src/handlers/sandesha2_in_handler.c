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

#include <axis2_engine.h>
#include <axis2_handler_desc.h>
#include <axutil_array_list.h>
#include <axis2_msg_ctx.h>
#include <axutil_property.h>
#include <axis2_conf_ctx.h>
#include <axiom_soap_body.h>
#include <sandesha2_storage_mgr.h>
#include <sandesha2_permanent_storage_mgr.h>
#include <sandesha2_permanent_seq_property_mgr.h>
#include <sandesha2_permanent_sender_mgr.h>
#include <sandesha2_seq_property_mgr.h>
#include <sandesha2_sender_mgr.h>
#include <sandesha2_msg_ctx.h>
#include <sandesha2_msg_processor.h>
#include <sandesha2_ack_msg_processor.h>
#include <sandesha2_ack_req_msg_processor.h>
#include <sandesha2_msg_init.h>
#include <sandesha2_msg_creator.h>
#include <sandesha2_seq.h>
#include <sandesha2_constants.h>
#include <sandesha2_utils.h>
#include <sandesha2_seq_ack.h>
#include <sandesha2_ack_requested.h>
#include <sandesha2_app_msg_processor.h>
#include <axutil_types.h>

static axis2_status_t AXIS2_CALL
sandesha2_in_handler_invoke(
    struct axis2_handler *handler, 
    const axutil_env_t *env,
    struct axis2_msg_ctx *msg_ctx);
 
static axis2_bool_t AXIS2_CALL
sandesha2_in_handler_drop_if_duplicate(
    struct axis2_handler *handler, 
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *rm_msg_ctx,
    sandesha2_storage_mgr_t *storage_mgr,
    sandesha2_seq_property_mgr_t *seq_prop_mgr,
    sandesha2_sender_mgr_t *sender_mgr);                                             

static axis2_status_t AXIS2_CALL
sandesha2_in_handler_process_dropped_msg(
    struct axis2_handler *handler, 
    const axutil_env_t *env,
    axis2_conf_ctx_t *conf_ctx,
    sandesha2_msg_ctx_t *rm_msg_ctx,
    sandesha2_storage_mgr_t *storage_mgr,
    sandesha2_seq_property_mgr_t *seq_prop_mgr,
    sandesha2_sender_mgr_t *sender_mgr);
                                            
AXIS2_EXTERN axis2_handler_t* AXIS2_CALL
sandesha2_in_handler_create(
    const axutil_env_t *env, 
    axutil_qname_t *qname) 
{
    axis2_handler_t *handler = NULL;
    
    handler = axis2_handler_create(env);
    if (!handler)
    {
        return NULL;
    }
   
    /* handler init is handled by conf loading, so no need to do it here */
    
    /* set the base struct's invoke op */
    axis2_handler_set_invoke(handler, env, sandesha2_in_handler_invoke);
    return handler;
}


static axis2_status_t AXIS2_CALL
sandesha2_in_handler_invoke(
    struct axis2_handler *handler, 
    const axutil_env_t *env,
    struct axis2_msg_ctx *msg_ctx)
{
    axutil_property_t *temp_prop = NULL;
    axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_conf_t *conf = NULL;
    axis2_ctx_t *ctx = NULL;
    axis2_char_t *str_done = NULL;
    axis2_char_t *reinjected_msg = NULL;
    sandesha2_msg_ctx_t *rm_msg_ctx = NULL;
    sandesha2_msg_processor_t *msg_processor = NULL;
    sandesha2_seq_ack_t *seq_ack = NULL;
    sandesha2_ack_requested_t *ack_requested = NULL;
    sandesha2_storage_mgr_t *storage_mgr = NULL;
    sandesha2_seq_property_mgr_t *seq_prop_mgr = NULL;
    sandesha2_sender_mgr_t *sender_mgr = NULL;
    axis2_char_t *dbname = NULL;
    axis2_bool_t isolated_last_msg = AXIS2_FALSE;
    axis2_bool_t dropped = AXIS2_FALSE;
    axis2_char_t *value = NULL;
    axutil_property_t *property = NULL;

    AXIS2_PARAM_CHECK(env->error, msg_ctx, AXIS2_FAILURE);
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[sandesha2] Start:sandesha2_in_handler_invoke");

    conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);
    if(!conf_ctx)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2]Configuration Context is NULL");
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_CONF_CTX_NULL, AXIS2_FAILURE);
        return AXIS2_FAILURE;
    }

    if(!sandesha2_permanent_storage_mgr_create_db(env, conf_ctx))
    {
        return AXIS2_FAILURE;
    }

    ctx = axis2_msg_ctx_get_base(msg_ctx, env);
    temp_prop = axis2_ctx_get_property(ctx, env, SANDESHA2_APPLICATION_PROCESSING_DONE);
    if(temp_prop)
    {
        str_done = (axis2_char_t *) axutil_property_get_value(temp_prop, env); 
    }

    if(str_done && !axutil_strcmp(AXIS2_VALUE_TRUE, str_done))
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] Application processing done");
        return AXIS2_SUCCESS;
    }

    temp_prop = axis2_ctx_get_property(ctx, env, SANDESHA2_REINJECTED_MESSAGE);
    if(temp_prop)
    {
        reinjected_msg = (axis2_char_t *) axutil_property_get_value(temp_prop, env);
    }

    if(reinjected_msg && !axutil_strcmp(AXIS2_VALUE_TRUE, reinjected_msg))
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] Reinjected_msg. So return here");

        return AXIS2_SUCCESS; /* Reinjected Messages are not processed by sandesha2 inflow handlers */
    }

    conf = axis2_conf_ctx_get_conf(conf_ctx, env);

    rm_msg_ctx = sandesha2_msg_init_init_msg(env, msg_ctx);
    dbname = sandesha2_util_get_dbname(env, conf_ctx);
    storage_mgr = sandesha2_utils_get_storage_mgr(env, dbname);
    seq_prop_mgr = sandesha2_permanent_seq_property_mgr_create(env, dbname);
    sender_mgr = sandesha2_permanent_sender_mgr_create(env, dbname);
    property = axis2_msg_ctx_get_property(msg_ctx, env, SANDESHA2_ISOLATED_LAST_MSG);
    if(property)
    {
        value = axutil_property_get_value(property, env);
    }

    if(value && !axutil_strcmp(AXIS2_VALUE_TRUE, value))
    {
        isolated_last_msg = AXIS2_TRUE;
    }

    if(!isolated_last_msg)
    {
        dropped = sandesha2_in_handler_drop_if_duplicate(handler, env, rm_msg_ctx, storage_mgr, 
                seq_prop_mgr, sender_mgr);
    }

    if(dropped)
    {
        sandesha2_in_handler_process_dropped_msg(handler, env, conf_ctx, rm_msg_ctx, storage_mgr, 
                seq_prop_mgr, sender_mgr);

        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] msg_ctx dropped. So return here");

        if(rm_msg_ctx)
        {
            sandesha2_msg_ctx_free(rm_msg_ctx, env);
        }

        if(seq_prop_mgr)
        {
            sandesha2_seq_property_mgr_free(seq_prop_mgr, env);
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

    /* 
     * TODO Validate the message
     * sandesha2_msg_validator_validate(env, rm_msg_ctx);
     */
    /*seq_ack = sandesha2_msg_ctx_get_seq_ack(rm_msg_ctx, env);
    if(seq_ack)
    {
        sandesha2_msg_processor_t *ack_proc = NULL;
        ack_proc = sandesha2_ack_msg_processor_create(env);
        sandesha2_msg_processor_process_in_msg(ack_proc, env, rm_msg_ctx);
        sandesha2_msg_processor_free(ack_proc, env);
    }*/

    ack_requested = sandesha2_msg_ctx_get_ack_requested(rm_msg_ctx, env);
    if(ack_requested)
    {
        sandesha2_ack_requested_set_must_understand(ack_requested, env, 
            AXIS2_FALSE);
        sandesha2_msg_ctx_add_soap_envelope(rm_msg_ctx, env);
    }

    seq_ack = sandesha2_msg_ctx_get_seq_ack(rm_msg_ctx, env);
    if(seq_ack)
    {
        sandesha2_msg_processor_t *ack_proc = NULL;

        ack_proc = sandesha2_ack_msg_processor_create(env);
        sandesha2_msg_processor_process_in_msg(ack_proc, env, rm_msg_ctx);
        sandesha2_msg_processor_free(ack_proc, env);
    }

    msg_processor = sandesha2_msg_processor_create_msg_processor(env, rm_msg_ctx);
    if(msg_processor)
    {
        sandesha2_msg_processor_process_in_msg(msg_processor, env, rm_msg_ctx);
        sandesha2_msg_processor_free(msg_processor, env);
    }

    if(rm_msg_ctx)
    {
        sandesha2_msg_ctx_free(rm_msg_ctx, env);
    }

    if(seq_prop_mgr)
    {
        sandesha2_seq_property_mgr_free(seq_prop_mgr, env);
    }

    if(sender_mgr)
    {
        sandesha2_sender_mgr_free(sender_mgr, env);
    }

    if(storage_mgr)
    {
        sandesha2_storage_mgr_free(storage_mgr, env);
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[sandesha2] Exit:sandesha2_in_handler_invoke");

    return AXIS2_SUCCESS;
}

static axis2_bool_t AXIS2_CALL
sandesha2_in_handler_drop_if_duplicate(
    struct axis2_handler *handler, 
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *rm_msg_ctx,
    sandesha2_storage_mgr_t *storage_mgr,
    sandesha2_seq_property_mgr_t *seq_prop_mgr,
    sandesha2_sender_mgr_t *sender_mgr)
{
    axis2_bool_t drop = AXIS2_FALSE;
    
    AXIS2_PARAM_CHECK(env->error, rm_msg_ctx, AXIS2_FALSE);
    AXIS2_PARAM_CHECK(env->error, storage_mgr, AXIS2_FALSE);
    
    if(SANDESHA2_MSG_TYPE_APPLICATION == sandesha2_msg_ctx_get_msg_type(rm_msg_ctx, env))
    {
        sandesha2_seq_t *sequence = NULL;
        long msg_no = -1;
        axis2_char_t *rmd_sequence_id = NULL;
        
        sequence = sandesha2_msg_ctx_get_sequence(rm_msg_ctx, env);
        if(sequence)
        {
            rmd_sequence_id = sandesha2_identifier_get_identifier(sandesha2_seq_get_identifier(sequence, 
                        env), env);

            msg_no = sandesha2_msg_number_get_msg_num(sandesha2_seq_get_msg_num(sequence, env), env);
        }
        if(rmd_sequence_id && 0 < msg_no)
        {
            sandesha2_seq_property_bean_t *rcvd_msgs_bean = NULL;
            
            if(seq_prop_mgr)
            {
                rcvd_msgs_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env, rmd_sequence_id, 
                        SANDESHA2_SEQ_PROP_SERVER_COMPLETED_MESSAGES);
            }

            if(rcvd_msgs_bean)
            {
                axis2_char_t *rcvd_msgs_str = NULL;
                axutil_array_list_t *msg_no_list = NULL;
                int i = 0, size = 0;
                
                rcvd_msgs_str = sandesha2_seq_property_bean_get_value(rcvd_msgs_bean, env);

                AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "rcvd_msgs_str:%s", rcvd_msgs_str);

                msg_no_list = sandesha2_utils_get_array_list_from_string(env, rcvd_msgs_str);
                if(msg_no_list)
                {
                    size = axutil_array_list_size(msg_no_list, env);
                    for(i = 0; i < size; i++)
                    {
                        axis2_char_t *temp = NULL;
                        
                        temp = axutil_array_list_get(msg_no_list, env, i);
                        if(axutil_atol(temp) == msg_no)
                        {
                            drop = AXIS2_TRUE;
                        }

                        AXIS2_FREE(env->allocator, temp);
                    }

                    axutil_array_list_free(msg_no_list, env);
                }

            }

            if(!drop)
            {
                axiom_soap_body_t *soap_body = NULL;
                axiom_node_t *body_node = NULL;
                axiom_element_t *body_element = NULL;
                axiom_children_iterator_t *children_iterator = NULL;
                axis2_bool_t empty_body = AXIS2_FALSE;
            
                soap_body = axiom_soap_envelope_get_body(sandesha2_msg_ctx_get_soap_envelope(
                        rm_msg_ctx, env), env);
                body_node = axiom_soap_body_get_base_node(soap_body, env);
                body_element = axiom_node_get_data_element(body_node, env);
                children_iterator = axiom_element_get_children(body_element, env, body_node);
                if(!axiom_children_iterator_has_next(children_iterator, env))
                {
                    empty_body = AXIS2_TRUE;
                }

                if(empty_body)
                {
                    axis2_char_t *rcvd_msgs_str1 = NULL;
                    axis2_char_t *bean_value = NULL;
                    axis2_char_t msg_no_str[32];
                    sandesha2_msg_processor_t *app_msg_processor = NULL;
                    
                    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                            "[sandesha2] Empty body last msg recieved");
                    
                    sandesha2_msg_ctx_set_wsa_action(rm_msg_ctx, env, 
                            SANDESHA2_SPEC_2005_02_SOAP_ACTION_LAST_MESSAGE);

                    if(!rcvd_msgs_bean)
                    {
                        rcvd_msgs_bean = sandesha2_seq_property_bean_create_with_data(env, 
                                rmd_sequence_id, SANDESHA2_SEQ_PROP_SERVER_COMPLETED_MESSAGES, "");
                        sandesha2_seq_property_mgr_insert(seq_prop_mgr, env, rcvd_msgs_bean);
                    }

                    rcvd_msgs_str1 = sandesha2_seq_property_bean_get_value(rcvd_msgs_bean, env);
                    sprintf(msg_no_str, "%ld", msg_no);
                    if(rcvd_msgs_str1 && 0 < axutil_strlen(rcvd_msgs_str1))
                    {
                        bean_value = axutil_strcat(env, rcvd_msgs_str1, ",", msg_no_str, NULL);
                    }
                    else
                    {
                        bean_value = axutil_strdup(env, msg_no_str);
                    }
                    
                    sandesha2_seq_property_bean_set_value(rcvd_msgs_bean, env, bean_value);
                    sandesha2_seq_property_mgr_update(seq_prop_mgr, env, rcvd_msgs_bean);
                    if(drop)
                    {
                        app_msg_processor = sandesha2_app_msg_processor_create(env);
                        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                            "[sandesha2] Applicatoin message already received. So current "\
                            "application message dropped. Sending an ack message");
                        sandesha2_app_msg_processor_send_ack_if_reqd(env, rm_msg_ctx, bean_value, 
                            rmd_sequence_id, storage_mgr, sender_mgr, seq_prop_mgr, -1);
                        sandesha2_msg_processor_free(app_msg_processor, env);
                    }
                }
            }

            if(rcvd_msgs_bean)
            {
                sandesha2_seq_property_bean_free(rcvd_msgs_bean, env);
            }
        }        
    } 
    else if(SANDESHA2_MSG_TYPE_UNKNOWN == sandesha2_msg_ctx_get_msg_type(
        rm_msg_ctx, env))
    {
        axis2_relates_to_t *relates_to = NULL;
        axis2_conf_ctx_t *conf_ctx = NULL;
        relates_to = sandesha2_msg_ctx_get_relates_to(rm_msg_ctx, env);
        if(relates_to)
        {
            const axis2_char_t *relates_to_val = NULL;
            axis2_op_ctx_t *op_ctx = NULL;
            axis2_op_ctx_t *op_ctx1 = NULL;
            
            relates_to_val = axis2_relates_to_get_value(relates_to, env);
            conf_ctx = axis2_msg_ctx_get_conf_ctx(sandesha2_msg_ctx_get_msg_ctx(
                rm_msg_ctx, env), env);
            op_ctx = axis2_conf_ctx_get_op_ctx(conf_ctx, env, relates_to_val);
            op_ctx1 = axis2_msg_ctx_get_op_ctx(sandesha2_msg_ctx_get_msg_ctx(
                        rm_msg_ctx, env), env);
            if(!op_ctx && !op_ctx1)
            {
                AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] Dropping duplicate RM message");
                drop = AXIS2_TRUE;
            }
        }
    }
    if(drop)
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] Pausing message context");
        sandesha2_msg_ctx_set_paused(rm_msg_ctx, env, AXIS2_TRUE);
        return AXIS2_TRUE;
    }

    return AXIS2_FALSE;
}

/* In this function appropriately respond for the dropeed message. In two way messaging if the
 * response for the dropped application message is not acknowledged then take the the response
 * message from the database and append acknowledgment for the dropped message to it.
 * Otherwise send the acknowledgment for the dropped message.
 */
static axis2_status_t AXIS2_CALL
sandesha2_in_handler_process_dropped_msg(
    struct axis2_handler *handler, 
    const axutil_env_t *env,
    axis2_conf_ctx_t *conf_ctx,
    sandesha2_msg_ctx_t *rm_msg_ctx,
    sandesha2_storage_mgr_t *storage_mgr,
    sandesha2_seq_property_mgr_t *seq_prop_mgr,
    sandesha2_sender_mgr_t *sender_mgr)
{
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI,  
        "[sandesha2] Entry:sandesha2_in_handler_process_dropped_msg");

    AXIS2_PARAM_CHECK(env->error, rm_msg_ctx, AXIS2_FALSE);
    AXIS2_PARAM_CHECK(env->error, storage_mgr, AXIS2_FALSE);
    
    if(SANDESHA2_MSG_TYPE_APPLICATION == sandesha2_msg_ctx_get_msg_type(rm_msg_ctx, env))
    {
        sandesha2_seq_t *sequence = NULL;
        axis2_char_t *rmd_sequence_id = NULL;
        
        sequence = sandesha2_msg_ctx_get_sequence(rm_msg_ctx, env);
        if(sequence)
        {
            rmd_sequence_id = sandesha2_identifier_get_identifier(sandesha2_seq_get_identifier(sequence, 
                        env), env);
        }
            
        if(rmd_sequence_id)
        {
            sandesha2_seq_property_bean_t *rcvd_msgs_bean = NULL;
            axis2_char_t *rcvd_msgs_str = NULL;
            sandesha2_msg_processor_t *app_msg_processor = NULL;
            
            rcvd_msgs_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env, rmd_sequence_id, 
                    SANDESHA2_SEQ_PROP_SERVER_COMPLETED_MESSAGES);

            if(rcvd_msgs_bean)
            {
                sandesha2_sender_bean_t *sender_bean = NULL;
                axis2_char_t *internal_sequence_id = NULL;
                long msg_no = -1;
                sandesha2_sender_bean_t *find_sender_bean = NULL;

                rcvd_msgs_str = sandesha2_seq_property_bean_get_value(rcvd_msgs_bean, env);
                
                msg_no = sandesha2_msg_number_get_msg_num(sandesha2_seq_get_msg_num(sequence, env), env);
                internal_sequence_id = sandesha2_utils_get_internal_sequence_id(env, rmd_sequence_id);
                find_sender_bean = sandesha2_sender_bean_create(env);
                sandesha2_sender_bean_set_msg_no(find_sender_bean, env, msg_no);
                sandesha2_sender_bean_set_internal_seq_id(find_sender_bean, env, internal_sequence_id);
                sandesha2_sender_bean_set_send(find_sender_bean, env, AXIS2_TRUE);

                sender_bean = sandesha2_sender_mgr_find_unique(sender_mgr, env, find_sender_bean);
                if(sender_bean)
                {
                    axis2_char_t *storage_key = NULL;
                    axis2_msg_ctx_t *app_msg_ctx = NULL;
                    sandesha2_msg_ctx_t *app_rm_msg_ctx = NULL;
                    axis2_engine_t *engine = NULL;
                    axis2_op_ctx_t *op_ctx = NULL;
                    axis2_msg_ctx_t *in_msg_ctx = NULL;

                    storage_key = sandesha2_sender_bean_get_msg_ctx_ref_key(sender_bean, env);
                    app_msg_ctx = sandesha2_storage_mgr_retrieve_msg_ctx(storage_mgr, env, storage_key, 
                            conf_ctx, AXIS2_TRUE);

                    in_msg_ctx = sandesha2_msg_ctx_get_msg_ctx(rm_msg_ctx, env);

                    axis2_msg_ctx_set_transport_out_stream(app_msg_ctx, env, 
                            axis2_msg_ctx_get_transport_out_stream(in_msg_ctx, env));

                    axis2_msg_ctx_set_out_transport_info(app_msg_ctx, env, 
                            axis2_msg_ctx_get_out_transport_info(in_msg_ctx, env));

                    op_ctx = axis2_msg_ctx_get_op_ctx(in_msg_ctx, env);

                    axis2_op_ctx_set_response_written(op_ctx, env, AXIS2_TRUE);

                    app_rm_msg_ctx = sandesha2_msg_init_init_msg(env, app_msg_ctx);
                    sandesha2_msg_creator_add_ack_msg(env, app_rm_msg_ctx, rmd_sequence_id, seq_prop_mgr);
                    engine = axis2_engine_create(env, conf_ctx);
                    axis2_engine_send(engine, env, app_msg_ctx);
                    sandesha2_msg_ctx_free(app_rm_msg_ctx, env);
                }
                else
                {
                    app_msg_processor = sandesha2_app_msg_processor_create(env);
                    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                        "[sandesha2] Applicatoin message already received. So current application"\
                        "message dropped. Sending an ack message");
                    sandesha2_app_msg_processor_send_ack_if_reqd(env, rm_msg_ctx, rcvd_msgs_str, 
                        rmd_sequence_id, storage_mgr, sender_mgr, seq_prop_mgr, -1);
                    
                    sandesha2_msg_processor_free(app_msg_processor, env);
                }
            }
        }
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI,  
        "[sandesha2] Exit:sandesha2_in_handler_process_dropped_msg");

    return AXIS2_SUCCESS;
}

