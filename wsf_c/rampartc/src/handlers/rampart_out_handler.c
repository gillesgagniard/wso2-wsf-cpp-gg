/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
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
#include <axiom_soap.h>
#include <rampart_sec_header_builder.h>
#include <rampart_context.h>
#include <rampart_engine.h>
#include <rampart_handler_util.h>

axis2_status_t AXIS2_CALL
rampart_out_handler_invoke(
    struct axis2_handler *handler,
    const axutil_env_t * env,
    struct axis2_msg_ctx *msg_ctx);

/**
 * Creates Out handler
 * @param env pointer to environment struct
 * @param name handler name 
 * @return Created Out handler
 */
AXIS2_EXTERN axis2_handler_t *AXIS2_CALL
rampart_out_handler_create(
    const axutil_env_t *env,
    axutil_string_t *name)
{
    axis2_handler_t *handler = NULL;

    handler = axis2_handler_create(env);
    if(!handler)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Cannot create out-handler.");
        return NULL;
    }

    /* Set the base struct's invoke op */
    axis2_handler_set_invoke(handler, env, rampart_out_handler_invoke);

    return handler;
}

/**
 * Invokes out handler logic. This will build security headers for out going message
 * @param handler rampart out handler
 * @param env pointer to environment struct
 * @param msg_ctx message context
 */
axis2_status_t AXIS2_CALL
rampart_out_handler_invoke(
    struct axis2_handler * handler,
    const axutil_env_t * env,
    axis2_msg_ctx_t * msg_ctx)
{
    axiom_soap_envelope_t *soap_envelope = NULL;
    axiom_soap_header_t *soap_header = NULL;
    axiom_node_t *soap_header_node = NULL;
    axiom_element_t *soap_header_ele = NULL;
    rampart_context_t *rampart_context = NULL;

    if(!msg_ctx)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]message context is invalid");
        return AXIS2_FAILURE;
    }

    /* 
     * Since rampart out_handler is a global handler we should
     * first check whether the rampart module is engaged.If not we
     * should not process the message and return success.
     */
    if(!rampart_is_rampart_engaged(env, msg_ctx))
    {
        AXIS2_LOG_INFO(env->log, "[rampart]Rampart is not engaged. No security support is needed.");
        return AXIS2_SUCCESS;
    }

    soap_envelope = axis2_msg_ctx_get_soap_envelope(msg_ctx, env);
    if(!soap_envelope)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]SOAP envelope cannot be found.");
        return AXIS2_FAILURE;
    }

    soap_header = axiom_soap_envelope_get_header(soap_envelope, env);
    if(!soap_header)
    {
        /*No SOAP header, so no point of proceeding. FAIL*/
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]SOAP header cannot be found.");
        return AXIS2_FAILURE;
    }

    soap_header_node = axiom_soap_header_get_base_node(soap_header, env);
    if(!soap_header_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Cannot get soap header node.");
        return AXIS2_FAILURE;
    }

    soap_header_ele = (axiom_element_t *)axiom_node_get_data_element(soap_header_node, env);
    if(!soap_header_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Cannot get soap header element.");
        return AXIS2_FAILURE;
    }

    rampart_context = rampart_engine_build_configuration(env, msg_ctx, AXIS2_FALSE);
    if(!rampart_context)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]ramaprt_context creation failed.");
        return AXIS2_FAILURE;
    }

    if(rampart_shb_build_message(env, msg_ctx, rampart_context, soap_envelope) != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Security header building failed.");
        return AXIS2_FAILURE;
    }

    return AXIS2_SUCCESS;
}
