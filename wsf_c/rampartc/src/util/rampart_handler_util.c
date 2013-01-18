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

#include <rampart_handler_util.h>
#include <axiom_soap_header_block.h>
#include <rampart_constants.h>
#include <axiom_soap_body.h>
#include <oxs_axiom.h>
#include <axis2_svc.h>
#include <axis2_conf_ctx.h>

/**
 * Get the security header from the header block
 * @param env pointer to environment struct
 * @param msg_ctx message context
 * @param soap_header header block 
 * @return security soap header node
 */
axiom_node_t *AXIS2_CALL
rampart_get_security_header(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    axiom_soap_header_t *soap_header)
{
    axutil_hash_index_t *hash_index =  NULL;
    axutil_hash_t *header_block_ht = NULL;
    axiom_element_t *header_block_ele = NULL;
    axiom_node_t *header_block_node = NULL;

    header_block_ht = axiom_soap_header_get_all_header_blocks(soap_header, env);
    if(!header_block_ht)
    {
        return NULL;
    }

    /* BETTER IF : If there are multiple security header elements, get the one with @role=rampart */
    for(hash_index = axutil_hash_first(header_block_ht, env); hash_index;
            hash_index = axutil_hash_next(env, hash_index))
    {
        void *hb = NULL;
        axiom_soap_header_block_t *header_block =    NULL;
        axis2_char_t *ele_localname = NULL;

        axutil_hash_this(hash_index, NULL, NULL, &hb);
        header_block = (axiom_soap_header_block_t *)hb;
        header_block_node = axiom_soap_header_block_get_base_node(header_block, env);
        header_block_ele  = (axiom_element_t*)axiom_node_get_data_element(header_block_node, env);
        ele_localname = axiom_element_get_localname(header_block_ele, env);

        if(!axutil_strcmp(ele_localname, RAMPART_SECURITY))
        {
            /* Set mustUnderstand = 0 since we are going to process the header */
            axiom_soap_header_block_set_must_understand_with_bool(header_block, env, AXIS2_FALSE);
            AXIS2_FREE(env->allocator, hash_index);
            return header_block_node;
        }
    }/* End of for */

    return NULL;
}

/**
 * Creates a SOAP fault based on params described below and store in msg_ctx
 * @param env pointer to environment struct
 * @param sub_code the text of the Subcode element of a SOAP fault message
 * @param reason_text the text in soapenv:Reason element
 * @param detail_node_text the text in the soapenv:Detail element
 * @param msg_ctx the msg_ctx 
 * @return void
 */
AXIS2_EXTERN void AXIS2_CALL
rampart_create_fault_envelope(
    const axutil_env_t *env,
    const axis2_char_t *sub_code,
    const axis2_char_t *reason_text,
    const axis2_char_t *detail_node_text,
    axis2_msg_ctx_t *msg_ctx)
{
    axiom_soap_envelope_t *envelope = NULL;
    int soap_version = AXIOM_SOAP12;
    axiom_node_t* text_om_node = NULL;
    axiom_element_t * text_om_ele = NULL;
    axiom_namespace_t *ns1 = NULL;
    axutil_array_list_t *sub_codes = NULL;
    axiom_soap_body_t *body = NULL;

    /* Creating the detailed node in the fault envelope */
    ns1 = axiom_namespace_create(env, RAMPART_WSSE_XMLNS, RAMPART_WSSE);
    text_om_ele = axiom_element_create(
        env, NULL, RAMPART_FAULT_ELEMENT_LOCAL_NAME, ns1, &text_om_node);
    axiom_element_set_text(text_om_ele, env, detail_node_text, text_om_node);

    if(axis2_msg_ctx_get_is_soap_11(msg_ctx, env))
    {
        /* In SOAP11 sub code is the faultcode and no soapenv:sender */
        soap_version = AXIOM_SOAP11;
        envelope = axiom_soap_envelope_create_default_soap_fault_envelope(
            env, sub_code, reason_text,soap_version, NULL, text_om_node);
    }
    else
    {
        /* In SOAP12 we need to create subcodes. subcode/value is the faultcode in SOAP12 and 
        fault/code/value is soapenv:Sender */
        sub_codes = axutil_array_list_create(env, 1);
        axutil_array_list_add(sub_codes, env, sub_code);

        envelope = axiom_soap_envelope_create_default_soap_fault_envelope(
            env, "soapenv:Sender", reason_text, soap_version, sub_codes, text_om_node);

        if(envelope)
        {
            body = axiom_soap_envelope_get_body(envelope, env);
            if(body)
            {
                axiom_node_t *body_node = NULL;
                body_node = axiom_soap_body_get_base_node(body, env);
                if(body_node)
                {
                    axiom_node_t *subcode_node = NULL;
                    subcode_node = oxs_axiom_get_node_by_local_name(
                        env, body_node, AXIOM_SOAP12_SOAP_FAULT_SUB_CODE_LOCAL_NAME);
                    if(subcode_node)
                    {
                        axiom_element_t *subcode_ele = NULL;
                        subcode_ele = axiom_node_get_data_element(subcode_node, env);
                        if(subcode_ele)
                        {
                            axiom_element_declare_namespace(subcode_ele, env, subcode_node, ns1);
                        }
                    }
                }
            }
        }
    }

    if(envelope)
    {
        axis2_msg_ctx_set_fault_soap_envelope(msg_ctx, env, envelope);
    }

    if(sub_codes)
    {
	    axutil_array_list_free(sub_codes, env);
    }
}

/**
 * Get rampart configurations from the message context
 * @param env pointer to environment struct
 * @param msg_ctx message context
 * @param param_name name of the parameter of the configuration
 * @return the loaded configuration params
 */
AXIS2_EXTERN void *AXIS2_CALL
rampart_get_rampart_configuration(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    axis2_char_t *param_name)

{
    axutil_param_t *param = NULL;
    void *value = NULL;

    param = axis2_msg_ctx_get_parameter(msg_ctx, env, param_name);

    if (!param)
    {
        return NULL;
    }

    value = axutil_param_get_value(param, env);
    return value;
}

/**
 * Check wether rampart is engaged or not
 * @param env pointer to environment struct
 * @param msg_ctx message context
 * @return if engaged returns AXIS2_TRUE, else returns AXIS2_FALSE
 */
AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rampart_is_rampart_engaged(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx)
{
    struct axis2_svc *svc = NULL;
    axutil_array_list_t *engaged_modules = NULL;
    int size = 0;
    int i = 0;
    const axutil_qname_t *qname = NULL;
    axis2_char_t *local_name = NULL;
    axis2_conf_t *conf = NULL;
    struct axis2_conf_ctx *conf_ctx = NULL;

    conf_ctx =  axis2_msg_ctx_get_conf_ctx(msg_ctx,env);
    if(!conf_ctx)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Conf context is NULL ");
        return AXIS2_FALSE;
    }

    conf =  axis2_conf_ctx_get_conf(conf_ctx, env);
    if(!conf)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot get the axis2 conf from conf context. ");
        return AXIS2_FALSE;
    }

    /* checked for globally engaged modules */
    engaged_modules =  axis2_conf_get_all_engaged_modules(conf, env);
    if(engaged_modules)
    {
        size = axutil_array_list_size(engaged_modules,env);
        for(i=0; i<size; i++)
        {
            qname = (axutil_qname_t *) axutil_array_list_get(engaged_modules,env,i);
            local_name = axutil_qname_get_localpart(qname,env);
            if(!axutil_strcmp(local_name,RAMPART_RAMPART))
            {
                return AXIS2_TRUE;
            }
        }
    }

    /* If not engaed gloabally check whether it is engaged at service level.
     * And If service is not there check whether the rampart is enabled by 
     * previous invocation of a handler. */

    svc =  axis2_msg_ctx_get_svc(msg_ctx,env);
    if(!svc)
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
            "[rampart][rhu] Service is NULL. Check if the security is enabled in the Conf ");
        return axis2_conf_get_enable_security(conf,env);
    }

    engaged_modules = axis2_svc_get_all_module_qnames(svc,env);
    if(engaged_modules)
    {
        size = axutil_array_list_size(engaged_modules,env);
        for(i=0; i<size; i++)
        {
            qname = (axutil_qname_t *) axutil_array_list_get(engaged_modules,env,i);
            local_name = axutil_qname_get_localpart(qname,env);
            if(!axutil_strcmp(local_name,RAMPART_RAMPART))
            {
                axis2_conf_set_enable_security(conf,env,AXIS2_TRUE);
                return AXIS2_TRUE;
            }
        }
    }
    return AXIS2_FALSE;
}

