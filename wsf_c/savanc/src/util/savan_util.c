/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
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

#include <axis2_msg_info_headers.h>
#include <axis2_options.h>
#include <axis2_engine.h>
#include <axis2_core_utils.h>
#include <axis2_endpoint_ref.h>
#include <axis2_svc_client.h>
#include <axis2_addr.h>
#include <platforms/axutil_platform_auto_sense.h>
#include <axiom_soap.h>
#include <axiom_soap_const.h>
#include <axiom_soap_envelope.h>
#include <axiom_element.h>
#include <axiom_node.h>

#include <savan_util.h>
#include <savan_msg_recv.h>
#include <savan_error.h>

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_util_create_fault_envelope(
    axis2_msg_ctx_t *msg_ctx,
    const axutil_env_t *env,
    axis2_char_t *code,
    axis2_char_t *subcode,
    axis2_char_t *reason,
    axis2_char_t *detail)
{

    axiom_soap_envelope_t *envelope = NULL;
    /*axiom_node_t* detail_om_node = NULL;
    axiom_element_t * detail_om_ele = NULL;
    axis2_msg_info_headers_t* info_header = NULL;
    int soap_version = AXIOM_SOAP12;
    axutil_array_list_t *sub_codes = NULL;
    axiom_namespace_t *soap_ns = NULL;
    axiom_namespace_t *ns1 = NULL;*/
    axiom_soap_body_t *body = NULL;
    axiom_node_t *body_node = NULL;
    axiom_node_t *fault_node = NULL;

    envelope = axiom_soap_envelope_create_default_soap_envelope(env,
        AXIOM_SOAP12);

    /*info_header =  axis2_msg_ctx_get_msg_info_headers(msg_ctx, env);
    axis2_msg_info_headers_set_action(info_header, env, SAVAN_ACTIONS_FAULT);

    axis2_msg_ctx_set_msg_info_headers(msg_ctx, env, info_header);*/

    body = axiom_soap_envelope_get_body(envelope, env);
    body_node = axiom_soap_body_get_base_node(body, env);

    fault_node = savan_util_build_fault_msg(env, code, subcode, reason, detail);

    axiom_node_add_child(body_node , env, fault_node);
    axis2_msg_ctx_set_fault_soap_envelope(msg_ctx, env, envelope);

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
savan_util_build_fault_msg(
    const axutil_env_t *env,
    axis2_char_t * code,
    axis2_char_t * subcode,
    axis2_char_t * reason,
    axis2_char_t * detail)
{
    axiom_node_t *fault_node = NULL;
    axiom_element_t *fault_ele = NULL;
    axiom_node_t *code_node = NULL;
    axiom_element_t *code_ele = NULL;
    axiom_node_t *code_value_node = NULL;
    axiom_element_t *code_value_ele = NULL;
    axiom_node_t *sub_code_node = NULL;
    axiom_element_t *sub_code_ele = NULL;
    axiom_node_t *sub_code_value_node = NULL;
    axiom_element_t *sub_code_value_ele = NULL;
    axiom_node_t *reason_node = NULL;
    axiom_element_t *reason_ele = NULL;
    axiom_node_t *reason_text_node = NULL;
    axiom_element_t *reason_text_ele = NULL;
    axiom_node_t *detail_node = NULL;
    axiom_element_t *detail_ele = NULL;

    fault_ele = axiom_element_create(env, NULL, "Fault", NULL, &fault_node);

   	code_ele = axiom_element_create(env, fault_node, "Code", NULL, &code_node);
	code_value_ele = axiom_element_create(env, code_node, "Value", NULL, &code_value_node);
   	axiom_element_set_text(code_value_ele, env, code, code_value_node);
	sub_code_ele = axiom_element_create(env, code_node, "Subcode", NULL, &sub_code_node);
    sub_code_value_ele = axiom_element_create(env, sub_code_node, "Value", NULL, 
            &sub_code_value_node);

   	axiom_element_set_text(sub_code_value_ele, env, subcode, sub_code_value_node);
	reason_ele = axiom_element_create(env, fault_node, "Reason", NULL, &reason_node);
	reason_text_ele = axiom_element_create(env, reason_node, "Text", NULL, &reason_text_node);
	axiom_element_set_text(reason_text_ele, env, reason, reason_text_node);
	detail_ele = axiom_element_create(env, fault_node, "Detail", NULL, &detail_node);	
	axiom_element_set_text(detail_ele, env, detail, detail_node);

    return fault_node;
}

AXIS2_EXTERN savan_message_types_t AXIS2_CALL
savan_util_get_message_type(
    axis2_msg_ctx_t *msg_ctx,
    const axutil_env_t *env)
{
    const axis2_char_t *action = NULL;
    axis2_msg_info_headers_t *info_header = NULL;

    info_header =  axis2_msg_ctx_get_msg_info_headers(msg_ctx, env);
    if (!info_header)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Cannot extract message info headers"); 
        return SAVAN_MSG_TYPE_UNKNOWN;
    }
    
    action = axis2_msg_info_headers_get_action(info_header, env);
    if( ! action)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Cannot extract soap action"); 
        AXIS2_ERROR_SET(env->error, SAVAN_ERROR_SOAP_ACTION_NULL, AXIS2_FAILURE);
        return SAVAN_MSG_TYPE_UNKNOWN;
    }
    
    if (axutil_strcmp(action, SAVAN_ACTIONS_SUB) == 0)
        return SAVAN_MSG_TYPE_SUB;
    else if (axutil_strcmp(action, SAVAN_ACTIONS_SUB_RESPONSE) == 0)
        return SAVAN_MSG_TYPE_SUB_RESPONSE;
    else if (axutil_strcmp(action, SAVAN_ACTIONS_UNSUB) == 0)
        return SAVAN_MSG_TYPE_UNSUB;
    else if (axutil_strcmp(action, SAVAN_ACTIONS_UNSUB_RESPONSE) == 0)
        return SAVAN_MSG_TYPE_UNSUB_RESPONSE;
    else if (axutil_strcmp(action, SAVAN_ACTIONS_GET_STATUS) == 0)
        return SAVAN_MSG_TYPE_GET_STATUS;
    else if (axutil_strcmp(action, SAVAN_ACTIONS_GET_STATUS_RESPONSE) == 0)
        return SAVAN_MSG_TYPE_GET_STATUS_RESPONSE;
    else if (axutil_strcmp(action, SAVAN_ACTIONS_RENEW) == 0)
        return SAVAN_MSG_TYPE_RENEW;
    else if (axutil_strcmp(action, SAVAN_ACTIONS_RENEW_RESPONSE) == 0)
        return SAVAN_MSG_TYPE_RENEW_RESPONSE;
    
    return SAVAN_MSG_TYPE_UNKNOWN;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
savan_util_get_subscription_id_from_msg(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx)
{
    axis2_char_t *sub_id = NULL;
    axiom_soap_envelope_t *envelope = NULL;
    axiom_soap_header_t *header = NULL;
    axutil_qname_t *qname = NULL;
    axiom_node_t *header_node = NULL;
    axiom_node_t *id_node = NULL;
    axiom_element_t *header_elem = NULL;
    axiom_element_t *id_elem = NULL;
    
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[savan] Entry:savan_util_get_subscription_id_from_msg");
    
    /* Get soap envelop and extract the subscription id */

    envelope =  axis2_msg_ctx_get_soap_envelope(msg_ctx, env);
    if (!envelope)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Failed to extract the soap envelop");
        return NULL;
    }
    
    header = axiom_soap_envelope_get_header(envelope, env);
    if (!header)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[savan] Failed to extract the soap header"); 
        return NULL;
    }
    
    /* Get header element from header node */
    header_node = axiom_soap_header_get_base_node(header, env);
    header_elem = (axiom_element_t*)axiom_node_get_data_element(header_node, env);
    
    /* Get Identifier element from header */
    qname = axutil_qname_create(env, ELEM_NAME_ID, EVENTING_NAMESPACE, NULL);
    id_elem = axiom_element_get_first_child_with_qname(header_elem, env, qname,
        header_node, &id_node);
    axutil_qname_free(qname, env);
    
    /* Now read the id */
    sub_id = axiom_element_get_text(id_elem, env, id_node);
    
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[savan] Exit:savan_util_get_subscription_id_from_msg");
    return sub_id;    
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL 
savan_util_set_store(
    axis2_svc_t *svc,
    const axutil_env_t *env,
    axis2_char_t *store_name)
{
    axutil_hash_t *store = NULL;
    axutil_param_t *param = NULL;
    
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Entry:set_sub_store");
    
    /* Create a hash map */
    store = axutil_hash_make(env);
    if (!store)
    {
        /* TODO : error reporting */
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Could not create subscriber store");
        return AXIS2_FAILURE;
    }
    
    /* Add the hash map as a parameter to the given service */
    param = axutil_param_create(env, store_name, (void*)store);
    if (!param)
    {
        /* TODO : error reporting */
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Could not create subscriber store param");
        return AXIS2_FAILURE;
    }
    
    axis2_svc_add_param(svc, env, param);
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Exit:set_sub_store");
    
    return AXIS2_SUCCESS;       
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
savan_util_get_expiry_time(
    const axutil_env_t *env)
{
    /* TODO: decide how to set expiry time */
    
    return "*";
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
savan_util_get_renewed_expiry_time(
    const axutil_env_t *env,
    axis2_char_t *expiry)
{
    /* TODO: Decide how to renew expiry time, may be using policy. Currently honor the requested. */
 
    return expiry;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
savan_util_get_topic_name_from_topic_url(
    const axutil_env_t *env,
    axis2_char_t *topic_url)
{
    axis2_char_t *topic = NULL;
    axis2_char_t *temp = NULL;

    temp = axutil_rindex(topic_url, AXIS2_PATH_SEP_CHAR) + 1;
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "topic:%s", temp);
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "topic2:%s", topic_url);
    if(temp)
    {
        if(axutil_strchr(temp, '"'))
        {
            int len = axutil_strlen(temp) -1;
            temp[len] = '\0';
        }

        topic  = axutil_strdup(env, temp);
    }

    return topic;
}

AXIS2_EXTERN void *AXIS2_CALL
savan_util_get_svc_client(
    const axutil_env_t *env)
{
    const axis2_char_t *client_home = NULL;
    axis2_options_t *options = NULL;
    axis2_svc_client_t *svc_client = NULL;

    client_home = AXIS2_GETENV("AXIS2C_HOME");
    if (!client_home)
    {
        client_home = "../../deploy";
    }

    options = axis2_options_create(env);
    axis2_options_set_xml_parser_reset(options, env, AXIS2_FALSE);
    svc_client = axis2_svc_client_create(env, client_home);
    if (!svc_client)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[savan] Stub invoke FAILED: Error code:"
            " %d :: %s", env->error->error_number,
            AXIS2_ERROR_GET_MESSAGE(env->error));
        return NULL;
    }
    axis2_svc_client_set_options(svc_client, env, options);    
    axis2_svc_client_engage_module(svc_client, env, AXIS2_MODULE_ADDRESSING);
    return svc_client;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
savan_util_get_resource_connection_string(
    const axutil_env_t *env,
    axis2_conf_t *conf)
{
    axis2_char_t *resource_str = NULL;
    axis2_module_desc_t *module_desc = NULL;
    axutil_qname_t *qname = NULL;

    qname = axutil_qname_create(env, SAVAN_MODULE, NULL, NULL);
    module_desc = axis2_conf_get_module(conf, env, qname);
    if(module_desc)
    {
        axutil_param_t *resource_param = NULL;
        resource_param = axis2_module_desc_get_param(module_desc, env, SAVAN_RESOURCE);
        if(resource_param)
        {
            resource_str = axutil_strdup(
                env, (axis2_char_t *) axutil_param_get_value(resource_param, env));
        }
    }
    axutil_qname_free(qname, env);
    
    if(!resource_str)
    {
        axis2_char_t *home = NULL;
        home = AXIS2_GETENV("AXIS2C_HOME");
        if(home)
        {
            resource_str = axutil_stracat(env, home, "/savan_db");
        }
        else
        {
            resource_str = axutil_strdup(env, "./savan_db");
        }
    }

    return resource_str;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
savan_util_get_resource_username(
    const axutil_env_t *env,
    axis2_conf_t *conf)
{
    axis2_char_t *username = "admin";
    axis2_module_desc_t *module_desc = NULL;
    axutil_qname_t *qname = NULL;

    qname = axutil_qname_create(env, SAVAN_MODULE, NULL, NULL);
    module_desc = axis2_conf_get_module(conf, env, qname);
    if(module_desc)
    {
        axutil_param_t *param = NULL;
        param = axis2_module_desc_get_param(module_desc, env, SAVAN_RESOURCE_USERNAME);
        if(param)
        {
            username = (axis2_char_t *) axutil_param_get_value(param, env);
        }
    }
    axutil_qname_free(qname, env);
    
    return username;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
savan_util_get_resource_password(
    const axutil_env_t *env,
    axis2_conf_t *conf)
{
    axis2_char_t *password = "password";
    axis2_module_desc_t *module_desc = NULL;
    axutil_qname_t *qname = NULL;

    qname = axutil_qname_create(env, SAVAN_MODULE, NULL, NULL);
    module_desc = axis2_conf_get_module(conf, env, qname);
    if(module_desc)
    {
        axutil_param_t *param = NULL;
        param = axis2_module_desc_get_param(module_desc, env, SAVAN_RESOURCE_PASSWORD);
        if(param)
        {
            password = (axis2_char_t *) axutil_param_get_value(param, env);
        }
    }
    axutil_qname_free(qname, env);
    
    return password;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
savan_util_get_module_param(
    const axutil_env_t *env,
    axis2_conf_t *conf,
    axis2_char_t *name)
{
    axis2_char_t *value = NULL;
    axis2_module_desc_t *module_desc = NULL;
    axutil_qname_t *qname = NULL;

    qname = axutil_qname_create(env, SAVAN_MODULE, NULL, NULL);
    module_desc = axis2_conf_get_module(conf, env, qname);
    if(module_desc)
    {
        axutil_param_t *param = NULL;
        param = axis2_module_desc_get_param(module_desc, env, name);
        if(param)
        {
            value = (axis2_char_t *) axutil_param_get_value(param, env);
        }
    }
    axutil_qname_free(qname, env);
    
    return value;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_util_process_subscriber_node(
    const axutil_env_t *env,
    axiom_node_t *sub_node,
    axiom_element_t *sub_elem,
    savan_subscriber_t *subscriber)
{
    axutil_qname_t *qname = NULL;
    axiom_node_t *endto_node = NULL;
    axiom_node_t *delivery_node = NULL;
    axiom_node_t *notify_node = NULL;
    axiom_node_t *address_node = NULL;
    axiom_node_t *filter_node = NULL;
    axiom_node_t *expires_node = NULL;
    
    axiom_element_t *endto_elem = NULL;
    axiom_element_t *delivery_elem = NULL;
    axiom_element_t *notify_elem = NULL;
    axiom_element_t *address_elem = NULL;
    axiom_element_t *expires_elem = NULL;
    axiom_element_t *filter_elem = NULL;
    
    axis2_char_t *endto = NULL;
    axis2_char_t *notify = NULL;
    axis2_char_t *expires = NULL;
    axis2_char_t *filter = NULL;
    axis2_char_t *filter_dialect = NULL;
    
    axis2_endpoint_ref_t *endto_epr = NULL;
    axis2_endpoint_ref_t *notify_epr = NULL;

    axis2_status_t status = AXIS2_SUCCESS;

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_util_process_subscriber_node");

    if(sub_elem)
    {
        /* EndTo */
        qname = axutil_qname_create(env, ELEM_NAME_ENDTO, EVENTING_NAMESPACE, NULL);
        endto_elem = axiom_element_get_first_child_with_qname(sub_elem, env, qname, sub_node, 
                &endto_node);
        axutil_qname_free(qname, env);
       
        if(endto_elem)
        {
            endto = axiom_element_get_text(endto_elem, env, endto_node);
            if(endto)
            {
                endto_epr = axis2_endpoint_ref_create(env, endto);
                savan_subscriber_set_end_to(subscriber, env, endto_epr);
            }
        }
        
        /* Get Delivery element and read NotifyTo */
        qname = axutil_qname_create(env, ELEM_NAME_DELIVERY, EVENTING_NAMESPACE, NULL);
        delivery_elem = axiom_element_get_first_child_with_qname(sub_elem, env, qname, sub_node, 
                &delivery_node);

        axutil_qname_free(qname, env);
        if(delivery_elem)
        {
            qname = axutil_qname_create(env, ELEM_NAME_NOTIFYTO, EVENTING_NAMESPACE, NULL);
            notify_elem = axiom_element_get_first_child_with_qname(delivery_elem, env, qname,
                                                                   delivery_node, &notify_node);
            axutil_qname_free(qname, env);
            if(notify_elem)
            {
                qname = axutil_qname_create(env, ELEM_NAME_ADDR, AXIS2_WSA_NAMESPACE_SUBMISSION, NULL);
                address_elem = axiom_element_get_first_child_with_qname(notify_elem, env, qname, 
                        notify_node, &address_node);
                axutil_qname_free(qname, env);

                notify = axiom_element_get_text(address_elem, env, address_node);
                if(notify)
                {
                    notify_epr = axis2_endpoint_ref_create(env, notify);
                    savan_subscriber_set_notify_to(subscriber, env, notify_epr);
                }
            }
        }

        /* Expires */
        qname = axutil_qname_create(env, ELEM_NAME_EXPIRES, EVENTING_NAMESPACE, NULL);
        expires_elem = axiom_element_get_first_child_with_qname(sub_elem, env, qname,
                                                                sub_node, &expires_node);
        axutil_qname_free(qname, env);
        if(expires_elem)
        {
            expires = axiom_element_get_text(expires_elem, env, expires_node);
            if(expires)
            {
                savan_subscriber_set_expires(subscriber, env, expires);
            }
        }
        
        /* Filter */
        qname = axutil_qname_create(env, ELEM_NAME_FILTER, EVENTING_NAMESPACE, NULL);
        filter_elem = axiom_element_get_first_child_with_qname(sub_elem, env, 
                                                               qname,
                                                               sub_node, 
                                                               &filter_node);
        axutil_qname_free(qname, env);
        if(filter_elem)
        {
            qname = axutil_qname_create(env, SAVAN_FILTER_DIALECT, NULL, NULL);
            filter = axiom_element_get_text(filter_elem, env, filter_node);
            filter_dialect = axiom_element_get_attribute_value(filter_elem,
                                                               env, qname);
            axutil_qname_free(qname, env);
            if(filter_dialect)
            {
                savan_subscriber_set_filter_dialect(subscriber, env, 
                                                    filter_dialect);
            }

            if(filter)
            {
                savan_subscriber_set_filter(subscriber, env, filter);
            }
        }
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Exit:savan_util_process_subscriber_node");
    return status;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
savan_util_create_subscriber_node(
    const axutil_env_t *env,
    savan_subscriber_t *subscriber,
    axiom_node_t *parent_node)
{
	axiom_attribute_t *dialect = NULL;
    axiom_namespace_t *ns = NULL;
    axiom_namespace_t *addr_ns = NULL;
    axiom_node_t *sub_node = NULL;
    axiom_node_t *endto_node = NULL;
    axiom_node_t *delivery_node = NULL;
    axiom_node_t *notify_node = NULL;
    axiom_node_t *address_node = NULL;
    axiom_node_t *filter_node = NULL;
    axiom_node_t *expires_node = NULL;
    axiom_element_t* sub_elem = NULL;
    axiom_element_t* endto_elem = NULL;
    axiom_element_t* delivery_elem = NULL;
    axiom_element_t* notify_elem = NULL;
    axiom_element_t* address_elem = NULL;
    axiom_element_t* filter_elem = NULL;
    axiom_element_t* expires_elem = NULL;
    axis2_char_t *endto = NULL;
    axis2_char_t *notify = NULL;
    axis2_char_t *filter = NULL;
    axis2_char_t *filter_dialect = NULL;
    axis2_char_t *expires = NULL;
    axis2_endpoint_ref_t *endpoint_ref = NULL;

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_util_create_subscriber_node");
    if(!subscriber)
    {
        AXIS2_ERROR_SET(env->error, SAVAN_ERROR_SUBSCRIBER_NOT_FOUND, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Subscriber structure passed is NULL");
        return NULL;
    }

    endpoint_ref = savan_subscriber_get_end_to(subscriber, env);
    if(endpoint_ref)
    {
        endto = (axis2_char_t *) axis2_endpoint_ref_get_address(endpoint_ref, env);
    }
    endpoint_ref = savan_subscriber_get_notify_to(subscriber, env);
    notify = (axis2_char_t *) axis2_endpoint_ref_get_address(endpoint_ref, env);
    filter = savan_subscriber_get_filter(subscriber, env);
    filter_dialect = savan_subscriber_get_filter_dialect(subscriber, env);
    expires = savan_subscriber_get_expires(subscriber, env);

    /* create the body of the Subscribe request */
    ns = axiom_namespace_create (env, EVENTING_NAMESPACE, EVENTING_NS_PREFIX);
    sub_elem = axiom_element_create(env, parent_node, ELEM_NAME_SUBSCRIBE, ns, &sub_node);
    
    /* EndTo element */
    if(endto)
    {
        endto_elem = axiom_element_create(env, sub_node, ELEM_NAME_ENDTO, ns, &endto_node);
        axiom_element_set_text(endto_elem, env, endto, endto_node);
    }

    /* Delivery element */
    delivery_elem = axiom_element_create(env, sub_node, ELEM_NAME_DELIVERY, ns, &delivery_node);
        
    notify_elem = axiom_element_create(env, delivery_node, ELEM_NAME_NOTIFYTO, ns, &notify_node);
    addr_ns = axiom_namespace_create (env, AXIS2_WSA_NAMESPACE_SUBMISSION, ADDRESSING_NS_PREFIX);
    address_elem = axiom_element_create(env, notify_node, ELEM_NAME_ADDR, addr_ns, &address_node);
    axiom_element_set_text(address_elem, env, notify, address_node);
    
    /* Expires element */
    if(expires)
    {
        expires_elem = axiom_element_create(env, sub_node, ELEM_NAME_EXPIRES, ns, &expires_node);
        axiom_element_set_text(expires_elem, env, expires, expires_node);
    }

    /* Filter element */
    if(filter && filter_dialect)
    {
        filter_elem = axiom_element_create(env, sub_node, ELEM_NAME_FILTER, ns, &filter_node);
        axiom_element_set_text(filter_elem, env, filter, filter_node);

		dialect = axiom_attribute_create(env, "Dialect", filter_dialect, NULL);
	    axiom_element_add_attribute(filter_elem, env, dialect ,filter_node);
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Exit:savan_util_create_subscriber_node");
    return sub_node;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
savan_util_create_savan_specific_subscriber_node(
    const axutil_env_t *env, 
    savan_subscriber_t *subscriber,
    axiom_node_t *parent_node)
{
    axiom_node_t *subs_node = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    axiom_namespace_t *ns1 = NULL;
    axiom_namespace_t *ns2 = NULL;
    axiom_namespace_t *ns3 = NULL;
    axiom_node_t *sub_node = NULL;
    axiom_node_t *id_node = NULL;
    axiom_node_t *topic_node = NULL;
    axiom_element_t *subs_elem = NULL;
    axiom_element_t* id_elem = NULL;
    axiom_element_t* topic_elem = NULL;
    axis2_char_t *id = NULL;
    axis2_char_t *topic_name = NULL;

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Entry:savan_util_create_savan_specific_subscriber_node");

    if(!subscriber)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Subscriber structure must be present");
        AXIS2_ERROR_SET(env->error, SAVAN_ERROR_SUBSCRIBER_NOT_FOUND, AXIS2_FAILURE);
        return NULL;
    }

    ns1 = axiom_namespace_create (env, SAVAN_NAMESPACE, SAVAN_NS_PREFIX);
    subs_elem = axiom_element_create(env, parent_node, ELEM_NAME_SUBSCRIBER, ns1, &subs_node);
    if(!subs_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[savan] Could not create Savan specific subscriber node");
        status = axutil_error_get_status_code(env->error);
        if(AXIS2_SUCCESS != status)
        {
            return NULL;
        }
    }

    /* Id element */
    id = savan_subscriber_get_id(subscriber, env);
    ns2 = axiom_namespace_create (env, SAVAN_NAMESPACE, SAVAN_NS_PREFIX);
    id_elem = axiom_element_create(env, subs_node, ELEM_NAME_ID, ns2, &id_node);
    axiom_element_set_text(id_elem, env, id, id_node);
    
    /* Topic Url element */
    topic_name = savan_subscriber_get_filter(subscriber, env);
    ns3 = axiom_namespace_create (env, SAVAN_NAMESPACE, SAVAN_NS_PREFIX);
    topic_elem = axiom_element_create(env, subs_node, ELEM_NAME_FILTER, ns3, &topic_node);
    axiom_element_set_text(topic_elem, env, topic_name, topic_node);

    sub_node = savan_util_create_subscriber_node(env, subscriber, subs_node);
    if(!sub_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Creating subscriber node failed");
        return NULL;
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Exit:savan_util_create_savan_specific_subscriber_node");
    return subs_node;
}

AXIS2_EXTERN savan_filter_mod_t * AXIS2_CALL
savan_util_get_filter_module(
    const axutil_env_t *env,
    axis2_conf_t *conf)
{
    axutil_param_t *filter_param = NULL;
    savan_filter_mod_t *filtermod = NULL;

    if(conf)
    {
        filter_param = axis2_conf_get_param(conf, env, SAVAN_FILTER);
        if(filter_param)
        {
            filtermod = (savan_filter_mod_t *) axutil_param_get_value(filter_param, env);
        }
    }

    return filtermod;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
savan_util_is_valid_duration(
    const axutil_env_t *env,
    const axis2_char_t *duration)
{
    return AXIS2_TRUE;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
savan_util_is_valid_date_time(
    const axutil_env_t *env,
    const axis2_char_t *duration)
{
    return AXIS2_TRUE;
}

