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

#include <axiom_xml_writer.h>
#include <axiom_soap_envelope.h>
#include <axiom_soap_body.h>
#include <axis2_svc.h>
#include <stdio.h>
#include <savan_subscriber.h>
#include <savan_util.h>
#include <savan_error.h>
#include <savan_constants.h>
#include <savan_subs_mgr.h>
#include "savan_subs_mgr_svc.h"

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
savan_subs_mgr_svc_add_subscriber(
    const axutil_env_t *env,
    axiom_node_t *add_sub_node,
    axis2_msg_ctx_t *msg_ctx)
{
    axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_conf_t *conf = NULL;
    savan_subscriber_t *subscriber = NULL;
    axis2_status_t status = AXIS2_SUCCESS;

    axutil_qname_t *qname = NULL;
    
    axiom_node_t *sub_node = NULL;
    axiom_node_t *id_node = NULL;
    
    axiom_element_t *sub_elem = NULL;
    axiom_element_t *id_elem = NULL;
    axiom_element_t *add_sub_elem = NULL;
    savan_subs_mgr_t *subs_mgr = NULL;
    
    axis2_char_t *id = NULL;

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_subs_mgr_svc_add_subscriber");

    conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);
    conf = axis2_conf_ctx_get_conf(conf_ctx, env);
    subscriber = savan_subscriber_create(env);
    if(!subscriber)
    {
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Cound not create subscriber");
        return NULL;
    }

    if(add_sub_node)
    {
        add_sub_elem = (axiom_element_t*)axiom_node_get_data_element(add_sub_node, env);
    }

    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
        "[savan] node:%s", axiom_node_to_string(add_sub_node, env));

    /* Get Id element from AddSubscriber*/
    qname = axutil_qname_create(env, ELEM_NAME_ID, SAVAN_NAMESPACE, NULL);
    id_elem = axiom_element_get_first_child_with_qname(add_sub_elem, env, qname,
        add_sub_node, &id_node);
    axutil_qname_free(qname, env);
  
    if(id_elem)
    {
        id = axiom_element_get_text(id_elem, env, id_node);
        savan_subscriber_set_id(subscriber, env, id);
    }

    /* Get subscriber element from Body */
    qname = axutil_qname_create(env, ELEM_NAME_SUBSCRIBE, EVENTING_NAMESPACE, NULL);
    sub_elem = axiom_element_get_first_child_with_qname(add_sub_elem, env, qname,
        add_sub_node, &sub_node);
    axutil_qname_free(qname, env);
    
    if(sub_elem)
    {
        status = savan_util_process_subscriber_node(env, sub_node, sub_elem, subscriber);
        if(AXIS2_SUCCESS != status)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Parsing subscriber node failed");
            AXIS2_ERROR_SET(env->error, SAVAN_ERROR_PARSING_SUBSCRIBER_NODE_FAILED, AXIS2_FAILURE);
            return NULL;
        }
    }

    subs_mgr = savan_subs_mgr_get_subs_mgr(env, conf_ctx, conf);
    if(!subs_mgr)
    {
        AXIS2_HANDLE_ERROR(env, SAVAN_ERROR_DATABASE_CREATION_ERROR, AXIS2_FAILURE);
        return NULL;
    }
    if(savan_subs_mgr_insert_subscriber(subs_mgr, env, subscriber))
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
            "[savan] Subscriber %s added", id);
    }
    else
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                "[savan] Subscriber %s could not be added", id);
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Exit:savan_subs_mgr_svc_add_subscriber");
    return NULL;   
}

AXIS2_EXTERN void * AXIS2_CALL
savan_subs_mgr_svc_remove_subscriber(
    const axutil_env_t *env,
    axiom_node_t *remove_sub_node,
    axis2_msg_ctx_t *msg_ctx)
{
    axutil_qname_t *qname = NULL;
    
    axiom_node_t *id_node = NULL;
    
    axiom_element_t *id_elem = NULL;
    axiom_element_t *remove_sub_elem = NULL;
    
    const axis2_char_t *subscriber_id = NULL;
    axis2_char_t sql_remove[256];
    axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_conf_t *conf = NULL;
    savan_subs_mgr_t *subs_mgr = NULL;

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_subs_mgr_svc_remove_subscriber");

    conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);
    conf = axis2_conf_ctx_get_conf(conf_ctx, env);
    remove_sub_elem = (axiom_element_t*)axiom_node_get_data_element(
        remove_sub_node, env);
    
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[savan] node:%s", 
        axiom_node_to_string(remove_sub_node, env));

    /* Get Id element from RemoveSubscriber*/
    qname = axutil_qname_create(env, ELEM_NAME_ID, SAVAN_NAMESPACE, NULL);
    id_elem = axiom_element_get_first_child_with_qname(remove_sub_elem, env, 
        qname, remove_sub_node, &id_node);
    axutil_qname_free(qname, env);
    
    subscriber_id = axiom_element_get_text(id_elem, env, id_node);
    
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
        "[savan] Removing subscriber with id %s", subscriber_id);
    
    sprintf(sql_remove, "delete from subscriber where id='%s'", subscriber_id);

    subs_mgr = savan_subs_mgr_get_subs_mgr(env, conf_ctx, conf);
    if(!subs_mgr)
    {
        AXIS2_HANDLE_ERROR(env, SAVAN_ERROR_DATABASE_CREATION_ERROR, AXIS2_FAILURE);
        return NULL;
    }

    savan_subs_mgr_remove_subscriber(subs_mgr, env, subscriber_id);

    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
        "[savan] Subscriber %s removed", subscriber_id);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[savan] Exit:savan_subs_mgr_svc_remove_subscriber");

    return NULL;   
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
savan_subs_mgr_svc_get_subscriber(
    const axutil_env_t *env,
    axiom_node_t *node,
    axis2_msg_ctx_t *msg_ctx)
{
    axiom_node_t *subs_id_parent_node = NULL;
    axiom_node_t *subs_id_node = NULL;
    savan_subscriber_t *subscriber = NULL;
    const axis2_char_t *subs_id = NULL;
    axiom_node_t *subs_node = NULL;
    axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_conf_t *conf = NULL;
    axis2_status_t status = AXIS2_SUCCESS;
    savan_subs_mgr_t *subs_mgr = NULL;

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[savan] Entry:savan_subs_mgr_svc_get_subscriber");

    /* Expected request format is :-
     * <ns1:get_subscriber xmlns:ns1="http://ws.apache.org/savan">
     *      <SubscriberId>subscriber id</SubscriberId>
     * </ns1:get_subscriber>
     */
    conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);
    conf = axis2_conf_ctx_get_conf(conf_ctx, env);
    if (!node) /* 'get_subscriber' node */
    {
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_SVC_SKEL_INPUT_OM_NODE_NULL, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Input parameter NULL");
        return NULL;
    }

    subs_id_parent_node = axiom_node_get_first_element(node, env);
    if (!subs_id_parent_node) 
    {
        AXIS2_ERROR_SET(env->error, 
            AXIS2_ERROR_SVC_SKEL_INVALID_XML_FORMAT_IN_REQUEST, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Invalid XML in request");
        return NULL;
    }

    subs_id_node = axiom_node_get_first_child(subs_id_parent_node, env);
    if (!subs_id_node) /* actual subs_id text */
    {
        AXIS2_ERROR_SET(env->error, 
            AXIS2_ERROR_SVC_SKEL_INVALID_XML_FORMAT_IN_REQUEST, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] invalid XML in request");
        return NULL;
    }

    if (axiom_node_get_node_type(subs_id_node, env) == AXIOM_TEXT)
    {
        axiom_text_t *subs_id_text = 
            (axiom_text_t *)axiom_node_get_data_element(subs_id_node, env);
        if (subs_id_text && axiom_text_get_value(subs_id_text , env))
        {
            subs_id = (axis2_char_t *)axiom_text_get_value(subs_id_text, env);
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[savan] Requested Subscriber's id:%s", subs_id);
        }
    }
    else
    {
        AXIS2_ERROR_SET(env->error, 
            AXIS2_ERROR_SVC_SKEL_INVALID_XML_FORMAT_IN_REQUEST, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Invalid XML in request");
        return NULL;
    }

    subs_mgr = savan_subs_mgr_get_subs_mgr(env, conf_ctx, conf);
    if(!subs_mgr)
    {
        AXIS2_HANDLE_ERROR(env, SAVAN_ERROR_DATABASE_CREATION_ERROR, AXIS2_FAILURE);
        return NULL;
    }
    subscriber = savan_subs_mgr_retrieve_subscriber(subs_mgr, env, subs_id);
    
    subs_node = savan_util_create_savan_specific_subscriber_node(env, subscriber, NULL);
    if(!subs_node)
    {
        status = axutil_error_get_status_code(env->error);
        if(AXIS2_SUCCESS != status)
        {
            return NULL;
        }
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Exit:savan_subs_mgr_svc_get_subscriber");
    return subs_node;
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
savan_subs_mgr_svc_get_subscriber_list(
    const axutil_env_t *env,
    axiom_node_t *node,
    axis2_msg_ctx_t *msg_ctx)
{
    axutil_array_list_t *subs_store = NULL;
    axiom_namespace_t *ns1 = NULL;
    axiom_node_t *subs_list_node = NULL;
    axiom_element_t* subs_list_elem = NULL;
    axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_conf_t *conf = NULL;
    int i = 0, size = 0;
    savan_subs_mgr_t *subs_mgr = NULL;
    axiom_node_t *filter_parent_node = NULL;
    axiom_node_t *filter_node = NULL;
    axis2_char_t *filter = NULL;

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_subs_mgr_svc_get_subscriber_list");
    /* Expected request format is :-
     * <ns1:get_subscriber_list xmlns:ns1="http://ws.apache.org/savan">
     *      <ns:Susbscriber xmlns:ns="http://schemas.xmlsoap.org/ws/2004/08/eventing">
     *      ...
     *      </ns:Subscriber>
     *      <ns:Susbscriber xmlns:ns="http://schemas.xmlsoap.org/ws/2004/08/eventing">
     *      ...
     *      </ns:Subscriber>
     * </ns1:get_subscriber_list>
     */
    conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);
    conf = axis2_conf_ctx_get_conf(conf_ctx, env);
    if (!node) /* 'get_subscriber_list' node */
    {
        AXIS2_HANDLE_ERROR(env, AXIS2_ERROR_SVC_SKEL_INPUT_OM_NODE_NULL, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Axiom node is null, unable to continue");
        return NULL;
    }

    filter_parent_node = axiom_node_get_first_element(node, env);
    if (!filter_parent_node) 
    {
        AXIS2_HANDLE_ERROR(env, AXIS2_ERROR_SVC_SKEL_INVALID_XML_FORMAT_IN_REQUEST, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[savan] filter parent node is null, unable to continue");
        return NULL;
    }

    filter_node = axiom_node_get_first_child(filter_parent_node, env);
    if (!filter_node) /* actual filter text */
    {
        AXIS2_HANDLE_ERROR(env, AXIS2_ERROR_SVC_SKEL_INVALID_XML_FORMAT_IN_REQUEST, AXIS2_FAILURE);
        return NULL;
    }

    if (axiom_node_get_node_type(filter_node, env) == AXIOM_TEXT)
    {
        axiom_text_t *filter_text = (axiom_text_t *)axiom_node_get_data_element(
            filter_node, env);
        if (filter_text && axiom_text_get_value(filter_text , env))
        {
            filter = (axis2_char_t *)axiom_text_get_value(filter_text, env);
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[savan] Requested Filter:%s", filter);
        }
    }
    else
    {
        AXIS2_HANDLE_ERROR(env, AXIS2_ERROR_SVC_SKEL_INVALID_XML_FORMAT_IN_REQUEST, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Invalid XML in request");
        return NULL;
    }

    subs_mgr = savan_subs_mgr_get_subs_mgr(env, conf_ctx, conf);
    if(!subs_mgr)
    {
        AXIS2_HANDLE_ERROR(env, SAVAN_ERROR_DATABASE_CREATION_ERROR, AXIS2_FAILURE);
        return NULL;
    }
    subs_store = savan_subs_mgr_retrieve_all_subscribers(subs_mgr, env, filter);

    /* create the body of the subscribers element */
    ns1 = axiom_namespace_create (env, SAVAN_NAMESPACE, SAVAN_NS_PREFIX);
    subs_list_elem = axiom_element_create(env, NULL, ELEM_NAME_SUBSCRIBERS, ns1, 
        &subs_list_node);    
    
    if(subs_store)
    {
        size = axutil_array_list_size(subs_store, env);
        if(size > 0)
        {
            for(i = 0; i < size; i++)
            {
                axiom_node_t *subs_node = NULL;
                savan_subscriber_t *subscriber = axutil_array_list_get(subs_store, env, i);

                if (subscriber)
                {
                    subs_node = savan_util_create_savan_specific_subscriber_node(env, subscriber, 
                            subs_list_node);
                    if(!subs_node)
                    {
                        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                                "[savan] Creating Savan specific Subscriber node failed");
                        AXIS2_ERROR_SET(env->error, SAVAN_ERROR_FAILED_TO_CREATE_SUBSCRIBER, AXIS2_FAILURE);
                        return NULL;
                    }
                }
            }
        }
    }
 
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Exit:savan_subs_mgr_svc_get_subscriber_list");
    return subs_list_node;
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
savan_subs_mgr_svc_get_topic_list(
    const axutil_env_t *env,
    axiom_node_t *node,
    axis2_msg_ctx_t *msg_ctx)
{
	return NULL;
}

