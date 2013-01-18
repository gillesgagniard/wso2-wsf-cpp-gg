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

#include <axis2_handler_desc.h>
#include <axutil_array_list.h>
#include <axis2_svc.h>
#include <axis2_msg_ctx.h>
#include <axutil_property.h>
#include <axis2_const.h>
#include <axis2_conf_ctx.h>
#include <sandesha2_seq.h>
#include <sandesha2_msg_ctx.h>
#include <sandesha2_msg_processor.h>
#include <sandesha2_msg_init.h>
#include <sandesha2_constants.h>
#include <sandesha2_utils.h>
#include <axis2_relates_to.h>
#include <axiom_soap_fault.h>
#include <axiom_soap_body.h>
#include <axiom_soap_header.h>
#include <stdlib.h>
#include <sandesha2_seq.h>
#include <sandesha2_msg_number.h>
#include <sandesha2_identifier.h>
#include <sandesha2_app_msg_processor.h>

static axis2_status_t AXIS2_CALL
sandesha2_global_in_handler_invoke(
    struct axis2_handler *handler, 
    const axutil_env_t *env,
    struct axis2_msg_ctx *msg_ctx);
    
AXIS2_EXTERN axis2_handler_t* AXIS2_CALL
sandesha2_global_in_handler_create(
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
    axis2_handler_set_invoke(handler, env, sandesha2_global_in_handler_invoke);

    return handler;
}


static axis2_status_t AXIS2_CALL
sandesha2_global_in_handler_invoke(
    struct axis2_handler *handler, 
    const axutil_env_t *env,
    struct axis2_msg_ctx *msg_ctx)
{
    
    axis2_conf_ctx_t *conf_ctx = NULL;
    /*axis2_ctx_t *ctx = NULL;*/
    /*axis2_char_t *reinjected_msg = AXIS2_FALSE;*/
    /*axutil_property_t *property = NULL;*/
    axiom_soap_envelope_t *soap_envelope = NULL;
    axiom_soap_fault_t *fault_part = NULL;
    const axutil_string_t *str_soap_action = NULL;
    const axis2_char_t *wsa_action = NULL;
    const axis2_char_t *soap_action = NULL;
    axis2_bool_t is_rm_global_msg = AXIS2_FALSE;

    AXIS2_PARAM_CHECK(env->error, msg_ctx, AXIS2_FAILURE);
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[sandesha2]Entry:sandesha2_global_in_handler");

   /* This handler needs to identify messages which follow the WSRM 1.0 
    * convention for sending 'LastMessage' when the sender doesn't have a 
    * reliable message to piggyback the last message marker onto.
    * Normally they will identify this scenario with an action marker, but if
    * there is no action at all then we have to check the soap body.
    * Either way, all that this handler need do is set the action back onto
    * the message, so that the dispatchers can allow it to continue. The real
    * processing will be done in the app_msg_processor.
    */
    str_soap_action = axis2_msg_ctx_get_soap_action(msg_ctx, env);
    soap_action = axutil_string_get_buffer(str_soap_action, env);
    wsa_action = axis2_msg_ctx_get_wsa_action(msg_ctx, env);
    if(wsa_action && !axutil_strcmp(wsa_action, SANDESHA2_SPEC_2005_02_SOAP_ACTION_LAST_MESSAGE))
    {
        axutil_property_t *property = NULL;
        property = axutil_property_create_with_args(env, 0, 0, 0, AXIS2_VALUE_TRUE);
        axis2_msg_ctx_set_property(msg_ctx, env, SANDESHA2_ISOLATED_LAST_MSG, property);
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] Isolated last message");
        return AXIS2_SUCCESS;
    }
    if(!soap_action && !wsa_action)
    {
        axiom_soap_envelope_t *envelope = NULL;
        envelope = axis2_msg_ctx_get_soap_envelope(msg_ctx, env);
        if(envelope)
        {
            axis2_bool_t last_msg_header = AXIS2_FALSE;
            axiom_soap_header_t *header = NULL;

            header = axiom_soap_envelope_get_header(envelope, env);
            if(header)
            {
                sandesha2_seq_t *sequence = NULL;
                axiom_node_t *seq_node = NULL;
                axiom_node_t *header_node = NULL;

                sequence = sandesha2_seq_create(env, SANDESHA2_SPEC_2005_02_NS_URI);
                header_node = axiom_soap_header_get_base_node(header, env);
                if(header_node)
                {
                    axutil_qname_t *seq_qname = NULL;
                    axiom_element_t *header_element = NULL;
    
                    seq_qname = axutil_qname_create(env, SANDESHA2_WSRM_COMMON_SEQ, 
                            SANDESHA2_SPEC_2005_02_NS_URI, NULL);
                    if(seq_qname)
                    {
                        axiom_element_t *seq_element = NULL;

                        header_element = axiom_node_get_data_element(header_node, env);
                        seq_element = axiom_element_get_first_child_with_qname(header_element, env,
                            seq_qname, header_node, &seq_node);

                        axutil_qname_free(seq_qname, env);
                    }
                }

                if(sequence && seq_node)
                {
                    sandesha2_seq_from_om_node(sequence, env, seq_node);
                }

                if(sandesha2_seq_get_last_msg(sequence, env))
                {
                    last_msg_header = AXIS2_TRUE;
                }
            }

            if(last_msg_header)
            {
                axiom_soap_body_t *body = NULL;
                axiom_node_t *body_node = NULL;

                body = axiom_soap_envelope_get_body(envelope, env);
                body_node = axiom_soap_body_get_base_node(body, env);
                if(body && !axiom_node_get_first_element(body_node, env))
                {
                    axutil_property_t *property = NULL;
                    axutil_string_t *temp_soap_action = NULL;

                    /* There is an empty body so we know this is the kind of message that we are 
                     * looking for.
                     */
                    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                            "[sandesha2] Setting SOAP Action for a WSRM 1.0 last message");

                    temp_soap_action = axutil_string_create(env, 
                            SANDESHA2_SPEC_2005_02_SOAP_ACTION_LAST_MESSAGE);
                    if(temp_soap_action)
                    {
                        axis2_msg_ctx_set_soap_action(msg_ctx, env, temp_soap_action);
                        axutil_string_free(temp_soap_action, env);
                    }
                    
                    axis2_msg_ctx_set_wsa_action(msg_ctx, env, 
                            SANDESHA2_SPEC_2005_02_SOAP_ACTION_LAST_MESSAGE);

                    property = axutil_property_create_with_args(env, 0, 0, 0, AXIS2_VALUE_TRUE);
                    axis2_msg_ctx_set_property(msg_ctx, env, SANDESHA2_ISOLATED_LAST_MSG, property);
                }
            }
        }

        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
            "[sandesha2]soap::action and wsa::action are NULL. So return here");

        return AXIS2_SUCCESS;
    }

    is_rm_global_msg = sandesha2_utils_is_rm_global_msg(env, msg_ctx);
    if(!is_rm_global_msg)
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] Not a global RM Message");
        return AXIS2_SUCCESS;
    }

    conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);
    if(!conf_ctx)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] Configuration Context is NULL");

        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_CONF_CTX_NULL, AXIS2_FAILURE);
        return AXIS2_FAILURE;
    }

    /*ctx = axis2_msg_ctx_get_base(msg_ctx, env);
    if(!axis2_msg_ctx_get_server_side(msg_ctx, env))
    {
        axis2_ctx_t *conf_ctx_base = axis2_conf_ctx_get_base(conf_ctx, env);
        axutil_property_t *property = axutil_property_create_with_args(env, 0, 
            0, 0, NULL);
        axis2_ctx_set_property(conf_ctx_base, env, SANDESHA2_IS_SVR_SIDE, 
            property);
    }*/
    
    soap_envelope = axis2_msg_ctx_get_soap_envelope(msg_ctx, env);
    if(!soap_envelope)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2]SOAP envelope is NULL");
        return AXIS2_FAILURE;
    }

    /*property = axis2_ctx_get_property(ctx, env, SANDESHA2_REINJECTED_MESSAGE);
    if(property)
        reinjected_msg = (axis2_char_t *) axutil_property_get_value(property, env); 
    if(reinjected_msg && 0 == axutil_strcmp(AXIS2_VALUE_TRUE, reinjected_msg))
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] Detected"\
             " reinjected_msg. So return here.");
        return AXIS2_SUCCESS; // Reinjected Messages are not processed by 
                                 sandesha2 inflow handlers
    }*/

    fault_part = axiom_soap_body_get_fault(axiom_soap_envelope_get_body(soap_envelope, env), env);
    if(fault_part)
    {
        axis2_relates_to_t *relates_to = NULL;
        relates_to = axis2_msg_ctx_get_relates_to(msg_ctx, env);
        if(relates_to)
        {
            const axis2_char_t *relates_to_val = NULL;
            axis2_op_ctx_t *op_ctx = NULL;
            
            relates_to_val = axis2_relates_to_get_value(relates_to, env);
            op_ctx = axis2_conf_ctx_get_op_ctx(conf_ctx, env, relates_to_val);
            if(op_ctx)
            {
                axis2_msg_ctx_t *req_msg_ctx = NULL;
                req_msg_ctx =  axis2_op_ctx_get_msg_ctx(op_ctx, env, AXIS2_WSDL_MESSAGE_LABEL_OUT);
                if(req_msg_ctx)
                {
                    if(sandesha2_utils_is_retrievable_on_faults(env, req_msg_ctx))
                    {
                        /* TODO we need to notify the listeners */
                        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] soap fault generated");
                        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] Pausing message context");
                        axis2_msg_ctx_set_paused(msg_ctx, env, AXIS2_TRUE);
                        return AXIS2_SUCCESS;
                    }
                }
            }
        }
    }

    /*Process if global processing possible. - Currently none*/
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[sandesha2]Exit:sandesha2_global_in_handler");
       
    return AXIS2_SUCCESS;
}



