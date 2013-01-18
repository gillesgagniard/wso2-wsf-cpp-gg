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
#include <axis2_conf_ctx.h>
#include <sandesha2_storage_mgr.h>
#include <sandesha2_permanent_storage_mgr.h>
#include <sandesha2_seq.h>
#include <sandesha2_msg_ctx.h>
#include <sandesha2_msg_processor.h>
#include <sandesha2_msg_init.h>
#include <sandesha2_constants.h>
#include <sandesha2_utils.h>
#include <sandesha2_app_msg_processor.h>
#include <sandesha2_client_constants.h>
#include <sandesha2_sender_mgr.h>
#include <platforms/axutil_platform_auto_sense.h>
#include <axis2_rm_assertion.h>
#include <sandesha2_spec_specific_consts.h>
#include <sandesha2_property_mgr.h>

axis2_status_t AXIS2_CALL
sandesha2_out_handler_invoke(
    struct axis2_handler *handler, 
    const axutil_env_t *env,
    struct axis2_msg_ctx *msg_ctx);
                                         
AXIS2_EXTERN axis2_handler_t* AXIS2_CALL
sandesha2_out_handler_create(
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
    axis2_handler_set_invoke(handler, env, sandesha2_out_handler_invoke);

    return handler;
}


axis2_status_t AXIS2_CALL
sandesha2_out_handler_invoke(
    struct axis2_handler *handler, 
    const axutil_env_t *env,
    struct axis2_msg_ctx *msg_ctx)
{
    axutil_property_t *temp_prop = NULL;
    axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_conf_t *conf = NULL;
    axis2_char_t *str_done = NULL;
    axis2_char_t *dummy_msg_str = NULL;
    axis2_bool_t dummy_msg = AXIS2_FALSE;
    axis2_svc_t *svc = NULL;
    axutil_qname_t *module_qname = NULL;
    sandesha2_msg_ctx_t *rm_msg_ctx = NULL;
    sandesha2_msg_processor_t *msg_processor = NULL;
    int msg_type = -1;

    AXIS2_PARAM_CHECK(env->error, msg_ctx, AXIS2_FAILURE);
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[sandesha2] Entry:sandesha2_out_handler_invoke");
            
    temp_prop = axis2_msg_ctx_get_property(msg_ctx, env, SANDESHA2_SEQ_PROP_MAKE_CONNECTION_OUT_PATH);
    if (temp_prop)
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
            "[sandesha2] In make connection out path. So return here.");
        return AXIS2_SUCCESS;
        temp_prop = NULL;
    }

    if(sandesha2_util_is_rstr_msg(env, msg_ctx))
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI,
            "[sandesha2] A RSTR message. Sandesha don't process.");
        return AXIS2_SUCCESS;
    }

    conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);
    if(!conf_ctx)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[sandesha2] Configuration Context is NULL");
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_CONF_CTX_NULL, AXIS2_FAILURE);
        return AXIS2_FAILURE;
    }
    svc = axis2_msg_ctx_get_svc(msg_ctx, env);
    if(!svc)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2]Axis2 Service is NULL");
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_SVC_NULL, AXIS2_FAILURE);
        return AXIS2_FAILURE;
    }
    module_qname = axutil_qname_create(env, SANDESHA2_MODULE, NULL, NULL);
    if(!axis2_svc_is_module_engaged(svc, env, module_qname))
    {
        if(module_qname)
        {
            axutil_qname_free(module_qname, env);
        }

        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2]RM is not engaged. So return here");
        return AXIS2_SUCCESS;
    }

    if(module_qname)
    {
        axutil_qname_free(module_qname, env);
    }

    temp_prop = axis2_msg_ctx_get_property(msg_ctx, env, SANDESHA2_APPLICATION_PROCESSING_DONE);
    if(temp_prop)
    {
        str_done = (axis2_char_t *) axutil_property_get_value(temp_prop, env); 
    }

    if(str_done && 0 == axutil_strcmp(AXIS2_VALUE_TRUE, str_done))
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
            "[sandesha2]Application Processing Done. So return here.");
        return AXIS2_SUCCESS; 
    }

    temp_prop = axutil_property_create_with_args(env, 0, 0, 0, AXIS2_VALUE_TRUE);
    axis2_msg_ctx_set_property(msg_ctx, env, SANDESHA2_APPLICATION_PROCESSING_DONE, temp_prop);
    conf = axis2_conf_ctx_get_conf(conf_ctx, env);
    if(!sandesha2_permanent_storage_mgr_create_db(env, conf_ctx))
    {
        return AXIS2_FAILURE;
    }

    /* Getting rm message */ 
    rm_msg_ctx = sandesha2_msg_init_init_msg(env, msg_ctx);
    temp_prop = axis2_msg_ctx_get_property(msg_ctx, env, SANDESHA2_CLIENT_DUMMY_MESSAGE);
    if(NULL != temp_prop)
    {
        dummy_msg_str = (axis2_char_t *) axutil_property_get_value(temp_prop, env); 
    }

    if(dummy_msg_str && 0 == axutil_strcmp(AXIS2_VALUE_TRUE, dummy_msg_str))
    {
        dummy_msg = AXIS2_TRUE;
    }

    temp_prop = axis2_msg_ctx_get_property(msg_ctx, env, AXIS2_SVC_CLIENT_CLOSED);
    if(temp_prop)
    {
        axis2_char_t *spec_version = NULL;

        axis2_endpoint_ref_t *reply_to = axis2_msg_ctx_get_reply_to(msg_ctx, env);
        if(reply_to)
        {
            axis2_char_t *address = axis2_endpoint_ref_get_address(reply_to, env);
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "dam_reply_to_address:%s", address);
        }
        spec_version = sandesha2_utils_get_rm_version(env, msg_ctx);

        if(!axutil_strcmp(SANDESHA2_SPEC_VERSION_1_1, spec_version))
        {
            axis2_char_t *action = NULL;
            axutil_string_t *str_action = NULL;

            action = sandesha2_spec_specific_consts_get_terminate_seq_action(env, spec_version);
            str_action = axutil_string_create(env, action);
            axis2_msg_ctx_set_soap_action(msg_ctx, env, str_action);
            axutil_string_free(str_action, env);
            /*axis2_msg_ctx_set_reply_to(msg_ctx, env, NULL);*/
            msg_type = sandesha2_msg_ctx_set_msg_type(rm_msg_ctx, env, 
                SANDESHA2_MSG_TYPE_CLOSE_SEQ);
        }
        else if(!axutil_strcmp(SANDESHA2_SPEC_VERSION_1_0, spec_version))
        {
            axutil_property_t *property = NULL;
            axutil_string_t *str_action = NULL;
            
            /*axis2_msg_info_headers_set_action(axis2_msg_ctx_get_msg_info_headers(msg_ctx, env), 
             * env, SANDESHA2_SPEC_2005_02_SOAP_ACTION_LAST_MESSAGE); */
            str_action = axutil_string_create(env, SANDESHA2_SPEC_2005_02_SOAP_ACTION_LAST_MESSAGE);
            axis2_msg_ctx_set_soap_action(msg_ctx, env, str_action);
            axutil_string_free(str_action, env);
            property = axutil_property_create_with_args(env, 0, 0, 0, AXIS2_VALUE_TRUE);
            axis2_msg_ctx_set_property(msg_ctx, env, "Sandesha2LastMessage", property);
            /*axis2_msg_ctx_set_reply_to(msg_ctx, env, NULL);*/
        }
    }

    msg_type = sandesha2_msg_ctx_get_msg_type(rm_msg_ctx, env);
    if(msg_type == SANDESHA2_MSG_TYPE_UNKNOWN)
    {
        axis2_msg_ctx_t *req_msg_ctx = NULL;
        axis2_op_ctx_t *op_ctx = NULL;

        op_ctx = axis2_msg_ctx_get_op_ctx(msg_ctx, env);
        req_msg_ctx =  axis2_op_ctx_get_msg_ctx(op_ctx, env, AXIS2_WSDL_MESSAGE_LABEL_IN);
        if(req_msg_ctx) /* For the server side */
        {
            sandesha2_msg_ctx_t *req_rm_msg_ctx = NULL;
            sandesha2_seq_t *seq_part = NULL;

            req_rm_msg_ctx = sandesha2_msg_init_init_msg(env, req_msg_ctx);
            seq_part = sandesha2_msg_ctx_get_sequence(req_rm_msg_ctx, env);
            if(seq_part)
            {
                msg_processor = (sandesha2_msg_processor_t *) 
                sandesha2_app_msg_processor_create(env); /* rm intended msg */
            }
            if(req_rm_msg_ctx)
                sandesha2_msg_ctx_free(req_rm_msg_ctx, env);
        }
        else if(!axis2_msg_ctx_get_server_side(msg_ctx, env))
        {
            msg_processor = (sandesha2_msg_processor_t *) sandesha2_app_msg_processor_create(env);
        }
    }
    else
    {
        msg_processor = sandesha2_msg_processor_create_msg_processor(env, rm_msg_ctx);
    }
    if(msg_processor)
    {
        sandesha2_msg_processor_process_out_msg(msg_processor, env, rm_msg_ctx);
        sandesha2_msg_processor_free(msg_processor, env);
    }
    if(AXIS2_SUCCESS != AXIS2_ERROR_GET_STATUS_CODE(env->error))
    {
        /* Message should not be sent in an exception situation */

        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] Pausing message context");
        axis2_msg_ctx_set_paused(msg_ctx, env, AXIS2_TRUE);
        if(rm_msg_ctx)
        {
            sandesha2_msg_ctx_free(rm_msg_ctx, env);
        }
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] Error in processing the message");
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_CANNOT_PROCESS_MSG, AXIS2_FAILURE);
        return AXIS2_FAILURE;
    }
    
    temp_prop = axis2_msg_ctx_get_property(msg_ctx, env, SANDESHA2_APPLICATION_PROCESSING_DONE);
    if(temp_prop)
    {
        axutil_property_set_value(temp_prop, env, AXIS2_VALUE_FALSE);
    }

    if(rm_msg_ctx)
    {
        sandesha2_msg_ctx_free(rm_msg_ctx, env);
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[sandesha2]Exit:sandesha2_out_handler_invoke");

    return AXIS2_SUCCESS;
}

