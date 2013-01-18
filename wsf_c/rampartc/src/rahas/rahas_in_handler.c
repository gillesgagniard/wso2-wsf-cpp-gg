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
#include <axis2_core_utils.h>
#include <axiom_soap_envelope.h>
#include <axiom_soap_body.h>
#include <trust_constants.h>
#include <axis2_engine.h>
#include <trust_rst.h>
#include <trust_rstr.h>
#include <rahas_request_processor.h>
#include <rampart_handler_util.h>
#include <rampart_constants.h>

static axis2_status_t
rahas_send_reply(
    axiom_node_t *body_node,
    const axutil_env_t *env, 
    axis2_msg_ctx_t *msg_ctx);

static void
rahas_find_trust_version_specific_details(
    const axutil_env_t *env, 
    axis2_char_t *action,
    int *trust_version, 
    int *request_type, 
    axis2_char_t **reply_action);

static axiom_node_t *
rahas_request_security_token(
    const axutil_env_t *env, 
    axiom_node_t *node, 
    axis2_msg_ctx_t *msg_ctx, 
    int trust_version, 
    int request_type);

axis2_status_t AXIS2_CALL
rahas_in_handler_invoke(
    struct axis2_handler *handler,
    const axutil_env_t *env,
    struct axis2_msg_ctx *msg_ctx);

AXIS2_EXTERN axis2_handler_t *AXIS2_CALL
rahas_in_handler_create(
    const axutil_env_t *env,
    axutil_string_t *name)
{
    axis2_handler_t *handler = NULL;
    AXIS2_ENV_CHECK(env, NULL);

    handler = axis2_handler_create(env);
    if (!handler)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rahas] Cannot create in-handler.");
        return NULL;
    }

    /*Set the function to invoke*/
    axis2_handler_set_invoke(handler, env, rahas_in_handler_invoke);
    
    return handler;
}

axis2_status_t AXIS2_CALL
rahas_in_handler_invoke(
    struct axis2_handler *handler,
    const axutil_env_t *env,
    struct axis2_msg_ctx *msg_ctx)
{
    axutil_string_t *soap_action = NULL;
    axis2_char_t *action = NULL;
    axiom_soap_envelope_t *soap_envelope = NULL;
    axiom_soap_body_t *soap_body = NULL;
    axiom_node_t *body_node = NULL;
    axiom_node_t *body_child_node = NULL;
    axiom_node_t *reply_body_child_node = NULL;
    int trust_version = TRUST_VERSION_INVALID;
    int request_type = SECCONV_ACTION_INVALID;
    axis2_char_t *reply_action = NULL;

    AXIS2_PARAM_CHECK(env->error, msg_ctx, AXIS2_FAILURE);
    AXIS2_LOG_INFO(env->log, "[rahas]Rahas in handler is called. ");

    /* check whether this is server side. Rahas is not needed in client side */
    if(!axis2_msg_ctx_get_server_side(msg_ctx, env))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rahas]Rahas is engaged in client side. It is not supported in client side.");
        return AXIS2_FAILURE;
    }

    /* check whether the action is valid secure conversation related action. First check soap action
     * and if it is not valid, check for wsa action. To proceed, either should be valid. 
     * If neither of them are valid, then it is not a secure conversation request. It could be 
     * application message. So return success. If action is valid secure conversation action, then
     * we can find trust version using action
     */
    soap_action = axis2_msg_ctx_get_soap_action(msg_ctx, env);
    if(soap_action)
    {
        action = (axis2_char_t *)axutil_string_get_buffer(soap_action, env);
    }

    if(!action)
    {
        action = (axis2_char_t *)axis2_msg_ctx_get_wsa_action(msg_ctx, env);
    }
    
    
    if(action)
    {
        rahas_find_trust_version_specific_details(
            env, action, &trust_version, &request_type, &reply_action);
    }

    if(!trust_version)
    {
        /* this is not a secure conversation related message. So can return without proceeding */
        AXIS2_LOG_INFO(env->log, "[rahas] Message with action %s will not be processed by rahas.",
            action);
        return AXIS2_SUCCESS;
    }

    soap_envelope =  axis2_msg_ctx_get_soap_envelope(msg_ctx, env);
    if(!soap_envelope)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rahas]SOAP envelope cannot be found.");
        rampart_create_fault_envelope(env, RAMPART_FAULT_TRUST_REQUEST_INVALID, 
            "The request was invalid or malformed", RAMPART_FAULT_TRUST_REQUEST_INVALID, msg_ctx);
        return AXIS2_FAILURE;
    }

    soap_body = axiom_soap_envelope_get_body(soap_envelope, env);
    if(!soap_body)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rahas]SOAP body cannot be found.");
        rampart_create_fault_envelope(env, RAMPART_FAULT_TRUST_REQUEST_INVALID, 
            "The request was invalid or malformed", RAMPART_FAULT_TRUST_REQUEST_INVALID, msg_ctx);
        return AXIS2_FAILURE;
    }

    body_node = axiom_soap_body_get_base_node(soap_body, env);
    if(!body_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rahas]SOAP body node cannot be found.");
        rampart_create_fault_envelope(env, RAMPART_FAULT_TRUST_REQUEST_INVALID, 
            "The request was invalid or malformed", RAMPART_FAULT_TRUST_REQUEST_INVALID, msg_ctx);
        return AXIS2_FAILURE;
    }
    
    body_child_node = axiom_node_get_first_element(body_node, env);
    if(!body_child_node)
    {
        /* body node is empty. Secure conversation related messages should have a non empty body */
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rahas]SOAP body node is empty.");
        rampart_create_fault_envelope(env, RAMPART_FAULT_TRUST_REQUEST_INVALID, 
            "The request was invalid or malformed", RAMPART_FAULT_TRUST_REQUEST_INVALID, msg_ctx);
        return AXIS2_FAILURE;
    }

    /* We got a valid secure conversation related message. Check the request and build the reply */
    reply_body_child_node = rahas_request_security_token(
        env, body_child_node, msg_ctx, trust_version, request_type);
    
    if(!reply_body_child_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rahas]Cannot process SecureConversation request.");
        return AXIS2_FAILURE;
    }

    /* set the reply action in to message context */
    axis2_msg_ctx_set_wsa_action(msg_ctx, env, reply_action);

    /* no need to proceed in in_flow. We can send above node as response. When axis2 get the 
     * control from here, it should continue to out_flow and send the reply
     */
    if(rahas_send_reply(reply_body_child_node, env, msg_ctx) != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rahas]Cannot send reply from rahas.");
        return AXIS2_FAILURE;
    }

    return AXIS2_SUCCESS;
}

static axis2_status_t
rahas_send_reply(
    axiom_node_t *body_node,
    const axutil_env_t *env, 
    axis2_msg_ctx_t *msg_ctx)
{
    axis2_msg_ctx_t *out_msg_ctx = NULL;
    axiom_soap_envelope_t *soap_envelope = NULL;
    axiom_soap_body_t *soap_body = NULL;
    axiom_node_t *body_parent_node = NULL;
    axis2_engine_t *engine = NULL;

    /* find soap envelop and set the body node */
    out_msg_ctx = axis2_core_utils_create_out_msg_ctx(env, msg_ctx);
    if(!out_msg_ctx)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rahas]Cannot create out message context.");
        return AXIS2_FAILURE;
    }

    soap_envelope = axis2_msg_ctx_get_soap_envelope(out_msg_ctx, env);
    if(!soap_envelope)
    {
        int soap_version = AXIOM_SOAP12;
        if(axis2_msg_ctx_get_is_soap_11(msg_ctx, env))
        {
            soap_version = AXIOM_SOAP11;
        }
        soap_envelope = axiom_soap_envelope_create_default_soap_envelope(env, soap_version);
        axis2_msg_ctx_set_soap_envelope(out_msg_ctx, env, soap_envelope);
    }

    soap_body = axiom_soap_envelope_get_body(soap_envelope, env);
    if(!soap_body)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rahas]SOAP body cannot be found from out message context.");
        return AXIS2_FAILURE;
    }

    body_parent_node = axiom_soap_body_get_base_node(soap_body, env);
    if(!body_parent_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rahas]SOAP body node cannot be found from out message context.");
        return AXIS2_FAILURE;
    }

    axiom_node_add_child(body_parent_node, env, body_node);

    /* Now we have to tell axis2 not to continue in in_flow, go to out_flow */
    axis2_msg_ctx_set_paused(msg_ctx, env, AXIS2_TRUE);
    axis2_msg_ctx_set_flow(out_msg_ctx, env, AXIS2_OUT_FLOW);

    /* Send the reply */
    engine = axis2_engine_create(env, axis2_msg_ctx_get_conf_ctx(out_msg_ctx, env));
    axis2_engine_send(engine, env, out_msg_ctx);
    if(engine)
    {
        axis2_engine_free(engine, env);
    }

    return AXIS2_SUCCESS;

}

static axiom_node_t *
rahas_request_security_token(
    const axutil_env_t *env, 
    axiom_node_t *node, 
    axis2_msg_ctx_t *msg_ctx, 
    int trust_version, 
    int request_type)
{
    axis2_char_t *trust_xml_ns = NULL;
    trust_rst_t* rst = NULL;
    trust_rstr_t* rstr = NULL;
    axiom_node_t* rstr_node = NULL;
    axis2_status_t status = AXIS2_SUCCESS;
    
    /* Get trust version specific values */
    if(trust_version == TRUST_VERSION_05_02)
    {
        trust_xml_ns = TRUST_WST_XMLNS_05_02;
    }
    else
    {
        trust_xml_ns = TRUST_WST_XMLNS_05_12;
    }

    /* create rst and set trust version. Trust version is needed to populate rst structure with 
     * given node. After setting them, populate rst structure */
    rst = trust_rst_create(env);
    if(!rst)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rahas]Cannot create RequestSecurityToken structure. Insufficient memory.");
        rampart_create_fault_envelope(env, RAMPART_FAULT_TRUST_REQUEST_FAILED, 
            "The specified request failed", RAMPART_FAULT_TRUST_REQUEST_FAILED, msg_ctx);
        return NULL;
    }

    trust_rst_set_wst_ns_uri(rst, env, trust_xml_ns);
    status = trust_rst_populate_rst(rst, env, node);
    if(status != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rahas]Cannot populate RequestSecurityToken structure. Given message might not "
            "be a valid security token request. ");
        rampart_create_fault_envelope(env, RAMPART_FAULT_TRUST_REQUEST_FAILED, 
            "The specified request failed", RAMPART_FAULT_TRUST_REQUEST_FAILED, msg_ctx);
        trust_rst_free(rst, env);
        return NULL;
    }
    
    /*create rstr and populate*/
    rstr = trust_rstr_create(env);
    if(!rstr)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rahas]Cannot create RequestSecurityTokenResponse structure.");
        rampart_create_fault_envelope(env, RAMPART_FAULT_TRUST_REQUEST_FAILED, 
            "The specified request failed", RAMPART_FAULT_TRUST_REQUEST_FAILED, msg_ctx);
        trust_rst_free(rst, env);
        return NULL;
    }

    /* set request type and namespace */
    trust_rstr_set_wst_ns_uri(rstr, env, trust_xml_ns);
    trust_rstr_set_request_type(rstr, env, trust_rst_get_request_type(rst, env));

    /* call request processor */
    if(request_type == SECCONV_ACTION_ISSUE)
    {
        status = rahas_process_issue_request(env, rst, rstr, msg_ctx, trust_version);
    }
    else if(request_type == SECCONV_ACTION_CANCEL)
    {
        /* TODO implement cancel method */
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rahas]Inidentified security context token request type. "
            "Only 'issue' is supported.");
        rampart_create_fault_envelope(env, RAMPART_FAULT_TRUST_REQUEST_INVALID, 
            "The request was invalid or malformed", RAMPART_FAULT_TRUST_REQUEST_INVALID, msg_ctx);
        status = AXIS2_FAILURE;
    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rahas]Inidentified security context token request type. "
            "Only 'issue' and 'cancel' are supported.");
        rampart_create_fault_envelope(env, RAMPART_FAULT_TRUST_REQUEST_INVALID, 
            "The request was invalid or malformed", RAMPART_FAULT_TRUST_REQUEST_INVALID, msg_ctx);
        status = AXIS2_FAILURE;
    }

    if(status != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rahas]Cannot Process security context token request.");
        trust_rst_free(rst, env);
        trust_rstr_free(rstr, env);
        return NULL;
    }

    /* build the rstr node */
    rstr_node = trust_rstr_build_rstr(rstr, env, NULL);
    if(!rstr_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rahas]Creation of RequestSecurityTokenResponse node failed.");
        rampart_create_fault_envelope(env, RAMPART_FAULT_TRUST_REQUEST_FAILED, 
            "The specified request failed", RAMPART_FAULT_TRUST_REQUEST_FAILED, msg_ctx);
    }

    /* clear stuff */
    trust_rstr_free(rstr, env);
    trust_rst_free(rst, env);

    return rstr_node;
}


/* This method will find trust_version, request_type and reply_action based on given action.
 * trust_version, request_type, reply_action are output parameters. action is input parameter */
static void
rahas_find_trust_version_specific_details(
    const axutil_env_t *env, 
    axis2_char_t *action,
    int *trust_version, 
    int *request_type, 
    axis2_char_t **reply_action)
{
    if(!axutil_strcmp(action, SECCONV_200502_REQUEST_ISSUE_ACTION))
    {
        *trust_version = TRUST_VERSION_05_02;
        *request_type = SECCONV_ACTION_ISSUE;
        *reply_action = SECCONV_200502_REPLY_ISSUE_ACTION;
    }
    else if(!axutil_strcmp(action, SECCONV_200502_REQUEST_CANCEL_ACTION))
    {
        *trust_version = TRUST_VERSION_05_02;
        *request_type = SECCONV_ACTION_CANCEL;
        *reply_action = SECCONV_200502_REPLY_CANCEL_ACTION;
    }
    else if(!axutil_strcmp(action, SECCONV_200512_REQUEST_ISSUE_ACTION))
    {
        *trust_version = TRUST_VERSION_05_12;
        *request_type = SECCONV_ACTION_ISSUE;
        *reply_action = SECCONV_200512_REPLY_ISSUE_ACTION;
    }
    else if(!axutil_strcmp(action, SECCONV_200512_REQUEST_CANCEL_ACTION))
    {
        *trust_version = TRUST_VERSION_05_12;
        *request_type = SECCONV_ACTION_CANCEL;
        *reply_action = SECCONV_200512_REPLY_CANCEL_ACTION;
    }
     /* TODO: we still don't support amend and renew. Implement them */
}

