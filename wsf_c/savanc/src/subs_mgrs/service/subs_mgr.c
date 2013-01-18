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
 
#include <savan_subs_mgr.h>
#include <axutil_log.h>
#include <axutil_hash.h>
#include <axutil_property.h>
#include <axutil_types.h>
#include <axutil_file_handler.h>
#include <platforms/axutil_platform_auto_sense.h>
#include <savan_constants.h>
#include <savan_util.h>
#include <savan_error.h>
#include <axis2_svc_client.h>

/**
 * Savan service based subscription manager communicate with the savan subscription manager service for
 * resources subscriber and topic.
 *
 */
/** 
 * @brief Savan Permanent Storage Manager Struct Impl
 *   Savan Permanent Storage Manager 
 */
typedef struct savan_service_subs_mgr
{
    savan_subs_mgr_t subs_mgr;
    axis2_char_t *subs_mgr_url;
    axis2_conf_t *conf;
} savan_service_subs_mgr_t;

typedef AXIS2_DECLARE_DATA struct savan_service_subs_mgr_args
{
    const axutil_env_t *env;
    void *data;
} savan_service_subs_mgr_args_t;

#define SAVAN_INTF_TO_IMPL(trans) ((savan_service_subs_mgr_t *) trans)

static axis2_status_t
savan_service_subs_mgr_add_subscriber_to_subs_mgr(
    const axutil_env_t *env,
    savan_subscriber_t *subscriber,
    axis2_char_t *subs_mgr_url);

static axiom_node_t *
savan_service_subs_mgr_build_add_subscriber_om_payload(
    const axutil_env_t *env,
    savan_subscriber_t *subscriber);

static axutil_array_list_t *
savan_service_subs_mgr_process_subscriber_list_node(
    const axutil_env_t *env,
    axiom_node_t *subs_list_node);

static savan_subscriber_t *AXIS2_CALL
savan_service_subs_mgr_process_savan_specific_subscriber_node(
    const axutil_env_t *env,
    axiom_node_t *subs_node);

static axiom_node_t *
savan_service_subs_mgr_build_subscriber_request_om_payload(
    const axutil_env_t *env,
    const axis2_char_t *subs_id);

static axiom_node_t *
savan_service_subs_mgr_build_subscribers_request_om_payload(
    const axutil_env_t *env,
    const axis2_char_t *topic);

static axiom_node_t *
savan_service_subs_mgr_build_topics_request_om_payload(
    const axutil_env_t *env);

static axutil_array_list_t *
savan_service_subs_mgr_process_topic_list_node(
    const axutil_env_t *env,
    axiom_node_t *topic_list_node);

AXIS2_EXTERN void AXIS2_CALL
savan_service_subs_mgr_free(
    savan_subs_mgr_t *subs_mgr,
    const axutil_env_t *env);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_service_subs_mgr_insert_subscriber(
    savan_subs_mgr_t *subs_mgr,
    const axutil_env_t *env,
    savan_subscriber_t *subscriber);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_service_subs_mgr_update_subscriber(
    savan_subs_mgr_t *subs_mgr,
    const axutil_env_t *env,
    savan_subscriber_t *subscriber);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_service_subs_mgr_remove_subscriber(
    savan_subs_mgr_t *subs_mgr,
    const axutil_env_t *env,
    const axis2_char_t *subscriber_id);

AXIS2_EXTERN savan_subscriber_t *AXIS2_CALL
savan_service_subs_mgr_retrieve_subscriber(
    savan_subs_mgr_t *subs_mgr,
    const axutil_env_t *env,
    const axis2_char_t *subcriber_id);

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL
savan_service_subs_mgr_retrieve_all_subscribers(
    savan_subs_mgr_t *subs_mgr,
    const axutil_env_t *env,
    const axis2_char_t *filter);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_service_subs_mgr_insert_topic(
    savan_subs_mgr_t *subs_mgr,
    const axutil_env_t *env,
    const axis2_char_t *topic_name,
    const axis2_char_t *topic_url);

static const savan_subs_mgr_ops_t subs_mgr_ops = 
{
    savan_service_subs_mgr_free,
    savan_service_subs_mgr_insert_subscriber,
    savan_service_subs_mgr_update_subscriber,
    savan_service_subs_mgr_remove_subscriber,
    savan_service_subs_mgr_retrieve_subscriber,
    savan_service_subs_mgr_retrieve_all_subscribers,
    savan_service_subs_mgr_insert_topic
};

AXIS2_EXTERN savan_subs_mgr_t * AXIS2_CALL
savan_subs_mgr_create(
    const axutil_env_t *env,
    axis2_conf_t *conf)
{
    savan_service_subs_mgr_t *subs_mgr_impl = NULL;
    
    subs_mgr_impl = AXIS2_MALLOC(env->allocator, sizeof(savan_service_subs_mgr_t));
    if (!subs_mgr_impl)
    {
        AXIS2_HANDLE_ERROR(env, SAVAN_ERROR_STORAGE_MANAGER_CREATION_FAILED, AXIS2_FAILURE);
        return NULL;
    }

    memset ((void *) subs_mgr_impl, 0, sizeof(savan_service_subs_mgr_t));

    subs_mgr_impl->subs_mgr_url = savan_util_get_resource_connection_string(env, conf);
    subs_mgr_impl->conf = conf;
    subs_mgr_impl->subs_mgr.ops = &subs_mgr_ops;

    return (savan_subs_mgr_t *) subs_mgr_impl;
}

AXIS2_EXTERN savan_subs_mgr_t * AXIS2_CALL
savan_subs_mgr_create_with_connection_info(
    const axutil_env_t *env,
    axis2_char_t *connection_string,
    axis2_char_t *username,
    axis2_char_t *password)
{
	return NULL;
}

AXIS2_EXTERN void AXIS2_CALL
savan_service_subs_mgr_free(
    savan_subs_mgr_t *subs_mgr,
    const axutil_env_t *env)
{
    savan_service_subs_mgr_t *subs_mgr_impl = NULL;
    subs_mgr_impl = SAVAN_INTF_TO_IMPL(subs_mgr);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_service_subs_mgr_free");

    if(subs_mgr_impl->subs_mgr_url)
    {
        AXIS2_FREE(env->allocator, subs_mgr_impl->subs_mgr_url);
        subs_mgr_impl->subs_mgr_url = NULL;
    }

    subs_mgr_impl->conf = NULL;

    if(subs_mgr_impl)
    {
        AXIS2_FREE(env->allocator, subs_mgr_impl);
        subs_mgr_impl = NULL;
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Exit:savan_service_subs_mgr_free");
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_service_subs_mgr_insert_subscriber(
    savan_subs_mgr_t *subs_mgr,
    const axutil_env_t *env,
    savan_subscriber_t *subscriber)
{
    axis2_status_t status = AXIS2_FAILURE;
    savan_service_subs_mgr_t *subs_mgr_impl = NULL;
    subs_mgr_impl = SAVAN_INTF_TO_IMPL(subs_mgr);

    status = savan_service_subs_mgr_add_subscriber_to_subs_mgr(env, subscriber, 
            subs_mgr_impl->subs_mgr_url);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Exit:savan_service_subs_mgr_insert_subscriber");
    return status;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_service_subs_mgr_update_subscriber(
    savan_subs_mgr_t *subs_mgr,
    const axutil_env_t *env,
    savan_subscriber_t *subscriber)
{
    savan_service_subs_mgr_t *subs_mgr_impl = NULL;
    subs_mgr_impl = SAVAN_INTF_TO_IMPL(subs_mgr);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Entry:savan_service_subs_mgr_update_subscriber");

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Entry:savan_service_subs_mgr_update_subscriber");
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_service_subs_mgr_remove_subscriber(
    savan_subs_mgr_t *subs_mgr,
    const axutil_env_t *env,
    const axis2_char_t *subscriber_id)
{
    savan_service_subs_mgr_t *subs_mgr_impl = NULL;
    subs_mgr_impl = SAVAN_INTF_TO_IMPL(subs_mgr);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Entry:savan_service_subs_mgr_remove_subscriber");

    
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Exit:savan_service_subs_mgr_remove_subscriber");
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN savan_subscriber_t *AXIS2_CALL
savan_service_subs_mgr_retrieve_subscriber(
    savan_subs_mgr_t *subs_mgr,
    const axutil_env_t *env,
    const axis2_char_t *subs_id)
{
    axis2_endpoint_ref_t* endpoint_ref = NULL;
    axis2_options_t *options = NULL;
    axis2_svc_client_t* svc_client = NULL;
    axiom_node_t *payload = NULL;
    axiom_node_t *ret_node = NULL;
    savan_subscriber_t *subscriber = NULL;

    savan_service_subs_mgr_t *subs_mgr_impl = NULL;
    subs_mgr_impl = SAVAN_INTF_TO_IMPL(subs_mgr);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[savan] Entry:savan_service_subs_mgr_retrieve_subscriber");

    svc_client = (axis2_svc_client_t *) savan_util_get_svc_client(env);
    options = (axis2_options_t *) axis2_svc_client_get_options(svc_client, env);
    endpoint_ref = axis2_endpoint_ref_create(env, subs_mgr_impl->subs_mgr_url);
    axis2_options_set_to(options, env, endpoint_ref);
    
    payload = savan_service_subs_mgr_build_subscriber_request_om_payload(env, subs_id);
    ret_node = axis2_svc_client_send_receive(svc_client, env, payload);
    if (ret_node)
    {
        subscriber = savan_service_subs_mgr_process_savan_specific_subscriber_node(env, ret_node);
    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Stub invoke FAILED: Error code:"
            " %d :: %s", env->error->error_number, AXIS2_ERROR_GET_MESSAGE(env->error));
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Exit:savan_service_subs_mgr_retrieve_subscriber");
    return subscriber;
}

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL
savan_service_subs_mgr_retrieve_all_subscribers(
    savan_subs_mgr_t *subs_mgr,
    const axutil_env_t *env,
    const axis2_char_t *filter)
{
    savan_service_subs_mgr_t *subs_mgr_impl = NULL;
   
    
    axis2_endpoint_ref_t* endpoint_ref = NULL;
    axis2_options_t *options = NULL;
    axis2_svc_client_t* svc_client = NULL;
    axiom_node_t *payload = NULL;
    axiom_node_t *ret_node = NULL;
    axutil_array_list_t *subscriber_list = NULL;
	subs_mgr_impl = SAVAN_INTF_TO_IMPL(subs_mgr);
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Entry:savan_service_subs_mgr_retrieve_all_subscribers");
    
    svc_client = (axis2_svc_client_t *) savan_util_get_svc_client(env);
    options = (axis2_options_t *)axis2_svc_client_get_options(svc_client, env);
    endpoint_ref = axis2_endpoint_ref_create(env, subs_mgr_impl->subs_mgr_url);
    axis2_options_set_to(options, env, endpoint_ref);
    
    payload = savan_service_subs_mgr_build_subscribers_request_om_payload(env, filter);
    ret_node = axis2_svc_client_send_receive(svc_client, env, payload);
    if (ret_node)
    {
        subscriber_list = savan_service_subs_mgr_process_subscriber_list_node(env, ret_node);
    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Stub invoke FAILED: Error code:"
            " %d :: %s", env->error->error_number, AXIS2_ERROR_GET_MESSAGE(env->error));
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Exit:savan_service_subs_mgr_retrieve_all_subscribers");
    return subscriber_list;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_service_subs_mgr_insert_topic(
    savan_subs_mgr_t *subs_mgr,
    const axutil_env_t *env,
    const axis2_char_t *topic_name,
    const axis2_char_t *topic_url)
{
    savan_service_subs_mgr_t *subs_mgr_impl = NULL;
    subs_mgr_impl = SAVAN_INTF_TO_IMPL(subs_mgr);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Entry:savan_service_subs_mgr_insert_topic");

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Exit:savan_service_subs_mgr_insert_topic");
    return AXIS2_SUCCESS;
}


/*static axis2_status_t
remove_subscriber_from_subs_mgr(
    const axutil_env_t *env,
    savan_subscriber_t *subscriber,
    axis2_char_t *subs_mgr_url)
{
    const axis2_char_t *address = NULL;
    axis2_endpoint_ref_t* endpoint_ref = NULL;
    axis2_options_t *options = NULL;
    axis2_svc_client_t* svc_client = NULL;
    axiom_node_t *payload = NULL;

    svc_client = (axis2_svc_client_t *) savan_util_get_svc_client(env);
    options = (axis2_options_t *) axis2_svc_client_get_options(svc_client, env);
    address = subs_mgr_url;
    endpoint_ref = axis2_endpoint_ref_create(env, address);
    axis2_options_set_to(options, env, endpoint_ref);
    axis2_options_set_action(options, env,
        "http://ws.apache.org/axis2/c/subscription/remove_subscriber");

    payload = build_remove_subscriber_om_payload(env, subscriber);
    // Send request
    axis2_svc_client_send_robust(svc_client, env, payload);
    if(svc_client)
        axis2_svc_client_free(svc_client, env);

    return AXIS2_SUCCESS;
}*/

axutil_array_list_t *AXIS2_CALL
savan_service_subs_mgr_get_topic_list_from_subs_mgr(
    const axutil_env_t *env,
    axis2_char_t *subs_mgr_url,
    void *s_client)
{
    axis2_endpoint_ref_t* endpoint_ref = NULL;
    axis2_options_t *options = NULL;
    axis2_svc_client_t* svc_client = NULL;
    axiom_node_t *payload = NULL;
    axiom_node_t *ret_node = NULL;
    axutil_array_list_t *topic_list = NULL;

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[savan] Entry:savan_service_subs_mgr_get_topic_list_from_subs_mgr");

    if(!s_client)
    {
        svc_client = (axis2_svc_client_t *) savan_util_get_svc_client(env);
    }
    else
    {
        svc_client = (axis2_svc_client_t *) s_client;
    }
    options = (axis2_options_t *) axis2_svc_client_get_options(svc_client, env);
    endpoint_ref = axis2_endpoint_ref_create(env, subs_mgr_url);
    axis2_options_set_to(options, env, endpoint_ref);
    
    payload = savan_service_subs_mgr_build_topics_request_om_payload(env);
    ret_node = axis2_svc_client_send_receive(svc_client, env, payload);
    if (ret_node)
    {
        topic_list = savan_service_subs_mgr_process_topic_list_node(env, ret_node);
    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[savan] Stub invoke FAILED: Error code:"
            " %d :: %s", env->error->error_number,
            AXIS2_ERROR_GET_MESSAGE(env->error));
    }
    if(!s_client && svc_client)
    {
        /*axis2_svc_client_free(svc_client, env);*/
    }
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[savan] Exit:savan_service_subs_mgr_get_topic_list_from_subs_mgr");
    return topic_list;
}

static axis2_status_t
savan_service_subs_mgr_add_subscriber_to_subs_mgr(
    const axutil_env_t *env,
    savan_subscriber_t *subscriber,
    axis2_char_t *subs_mgr_url)
{
    const axis2_char_t *address = NULL;
    axis2_endpoint_ref_t* endpoint_ref = NULL;
    axis2_options_t *options = NULL;
    axis2_svc_client_t* svc_client = NULL;
    axiom_node_t *payload = NULL;

    svc_client = (axis2_svc_client_t *) savan_util_get_svc_client(env);
    options = (axis2_options_t *) axis2_svc_client_get_options(svc_client, env);
    address = subs_mgr_url;
    endpoint_ref = axis2_endpoint_ref_create(env, address);
    axis2_options_set_to(options, env, endpoint_ref);
    axis2_options_set_action(options, env, SAVAN_SUBS_MGR_ADD_SUBSCRIBER_URL);

    payload = savan_service_subs_mgr_build_add_subscriber_om_payload(env, subscriber);
    /* Send request */
    axis2_svc_client_send_robust(svc_client, env, payload);
    if(svc_client)
    {
        axis2_svc_client_free(svc_client, env);
    }

    return AXIS2_SUCCESS;
}

static axiom_node_t *
savan_service_subs_mgr_build_add_subscriber_om_payload(
    const axutil_env_t *env,
    savan_subscriber_t *subscriber)
{
    axiom_node_t *add_node = NULL;
    axiom_element_t* add_ele = NULL;
    axiom_namespace_t *ns = NULL;
    axiom_namespace_t *ns1 = NULL;
    axiom_node_t *sub_node = NULL;
    axiom_node_t *id_node = NULL;
    axiom_node_t *endto_node = NULL;
    axiom_node_t *delivery_node = NULL;
    axiom_node_t *notify_node = NULL;
    axiom_node_t *filter_node = NULL;
    axiom_node_t *expires_node = NULL;
    axiom_element_t* sub_elem = NULL;
    axiom_element_t* id_elem = NULL;
    axiom_element_t* endto_elem = NULL;
    axiom_element_t* delivery_elem = NULL;
    axiom_element_t* notify_elem = NULL;
    axiom_element_t* filter_elem = NULL;
    axiom_element_t* expires_elem = NULL;
    const axis2_char_t *endto = NULL;
    const axis2_char_t *notify = NULL;
    axis2_char_t *filter = NULL;
    const axis2_char_t *expires = NULL;
    axis2_char_t *topic_name = NULL;
    axis2_char_t *id = NULL;
	axis2_endpoint_ref_t *notify_ref = NULL;
    axis2_endpoint_ref_t *endto_ref = savan_subscriber_get_end_to(subscriber, env);

    if(endto_ref)
    {
        endto = axis2_endpoint_ref_get_address(endto_ref, env);
    }

    notify_ref = savan_subscriber_get_notify_to(subscriber, env);
    if(notify_ref)
    {
        notify = axis2_endpoint_ref_get_address(notify_ref, env);
    }

    filter = savan_subscriber_get_filter(subscriber, env); 
    expires = savan_subscriber_get_expires(subscriber, env); 
    id = savan_subscriber_get_id(subscriber, env);

    ns = axiom_namespace_create (env, EVENTING_NAMESPACE, EVENTING_NS_PREFIX);
    ns1 = axiom_namespace_create (env, SAVAN_NAMESPACE, SAVAN_NS_PREFIX);
    add_ele = axiom_element_create(env, NULL, ELEM_NAME_ADD_SUBSCRIBER, ns1, &add_node);
    
    /* create the id element */
    if(id)
    {
        id_elem = axiom_element_create(env, add_node, ELEM_NAME_ID, ns1, &id_node);
            axiom_element_set_text(id_elem, env, id, id_node);
    }

    /* create the subscriber element */
    sub_elem = axiom_element_create(env, add_node, ELEM_NAME_SUBSCRIBE, ns, &sub_node);
    
    /* EndTo element */
    endto_elem = axiom_element_create(env, sub_node, ELEM_NAME_ENDTO, ns, &endto_node);
    axiom_element_set_text(endto_elem, env, endto, endto_node);
    
    /* Delivery element */
    delivery_elem = axiom_element_create(env, sub_node, ELEM_NAME_DELIVERY, ns, &delivery_node);
        
    notify_elem = axiom_element_create(env, delivery_node, ELEM_NAME_NOTIFYTO, ns, &notify_node);
    axiom_element_set_text(notify_elem, env, notify, notify_node);
    
    /* Expires element */
    expires_elem = axiom_element_create(env, sub_node, ELEM_NAME_EXPIRES, ns, &expires_node);
    axiom_element_set_text(expires_elem, env, expires, expires_node);

    /* Filter element */
    filter_elem = axiom_element_create(env, sub_node, ELEM_NAME_FILTER, ns, &filter_node);
    axiom_element_set_text(filter_elem, env, filter, filter_node);
    
    return add_node;
}

static axutil_array_list_t *
savan_service_subs_mgr_process_subscriber_list_node(
    const axutil_env_t *env,
    axiom_node_t *subs_list_node)
{
    axiom_element_t *subs_list_element = NULL;
    axiom_children_qname_iterator_t *subs_iter = NULL;
    axutil_qname_t *qname = NULL;
    axutil_array_list_t *subscriber_list = NULL;
    axis2_status_t status = AXIS2_SUCCESS;

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[savan] Entry:savan_service_subs_mgr_process_subscriber_list_node");
    subs_list_element = axiom_node_get_data_element(subs_list_node, env); 
         
    /* Get Subscriber elements from subscriber list */
    qname = axutil_qname_create(env, ELEM_NAME_SUBSCRIBER, SAVAN_NAMESPACE, NULL);
    subs_iter = axiom_element_get_children_with_qname(subs_list_element, env,
        qname, subs_list_node);
    axutil_qname_free(qname, env);
    if(!subs_iter)
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[savan] Subscribers list is empty");
        return NULL;
    }

    if(axiom_children_qname_iterator_has_next(subs_iter, env))
    {
        subscriber_list = axutil_array_list_create(env, 0);
    }

    while(axiom_children_qname_iterator_has_next(subs_iter, env))
    {
        savan_subscriber_t *subscriber = NULL;
        axiom_node_t *subs_node = NULL;
     
        subs_node = axiom_children_qname_iterator_next(subs_iter, env);
        if(subs_node) /* Iterate Savan specific subscriber elements */
        {
            /* Now read Savan specific Subscribe element */
            subscriber = savan_service_subs_mgr_process_savan_specific_subscriber_node(env, subs_node);
            if(!subscriber)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                        "[savan] Failed process Savan specific Subscriber element");
                status = axutil_error_get_status_code(env->error);
                return NULL;

            }

            axutil_array_list_add(subscriber_list, env, subscriber);
        }
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] savan_service_subs_mgr_process_subscriber_list_node");
    return subscriber_list;
}

static savan_subscriber_t *AXIS2_CALL
savan_service_subs_mgr_process_savan_specific_subscriber_node(
    const axutil_env_t *env,
    axiom_node_t *subs_node)
{
    axiom_element_t *subs_elem = NULL;
    axiom_node_t *sub_node = NULL;
    axiom_element_t *sub_elem = NULL;
    axutil_qname_t *qname = NULL;
    axiom_node_t *id_node = NULL;
    axiom_element_t *id_elem = NULL;
    axis2_char_t *id = NULL;
    axiom_node_t *topic_node = NULL;
    axiom_element_t *topic_elem = NULL;
    savan_subscriber_t *subscriber = NULL;
    axis2_status_t status = AXIS2_SUCCESS;

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Entry:savan_service_subs_mgr_process_savan_specific_subscriber_node");

    AXIS2_PARAM_CHECK(env->error, subs_node, NULL);

    subscriber = savan_subscriber_create(env);
    if (!subscriber)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Failed to create a subscriber instance");
        AXIS2_ERROR_SET(env->error, SAVAN_ERROR_FAILED_TO_CREATE_SUBSCRIBER, AXIS2_FAILURE);
        return NULL;
    }

    subs_elem = axiom_node_get_data_element(subs_node, env); 

    /* Id */
    qname = axutil_qname_create(env, ELEM_NAME_ID, SAVAN_NAMESPACE, NULL);
    id_elem = axiom_element_get_first_child_with_qname(subs_elem, env, qname, subs_node, &id_node);
    axutil_qname_free(qname, env);
    id = axiom_element_get_text(id_elem, env, id_node);
    savan_subscriber_set_id(subscriber, env, id);
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[savan] Received subscriber id:%s", id);
    
    /* Topic */
    qname = axutil_qname_create(env, ELEM_NAME_TOPIC, SAVAN_NAMESPACE, NULL);
    topic_elem = axiom_element_get_first_child_with_qname(subs_elem, env, qname, subs_node, &topic_node);
    axutil_qname_free(qname, env);
    if(topic_elem)
    {
        /*axis2_char_t *topic_url = NULL;

        topic_url = axiom_element_get_text(topic_elem, env, topic_node);
        savan_subscriber_set_topic_url(subscriber, env, topic_url);*/
        /* Until design is finalized don't store the topic(event source) */
        /*status = savan_util_populate_topic(env, topic_url, conf);
        if(status != AXIS2_SUCCESS)
        {
            AXIS2_ERROR_SET(env->error, SAVAN_ERROR_COULD_NOT_POPULATE_TOPIC, AXIS2_FAILURE);
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Could not populate topic");
            return NULL;
        }*/

        /*AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[savan] Received subscriber topic:%s", topic_url);*/
    }

    qname = axutil_qname_create(env, ELEM_NAME_SUBSCRIBE, EVENTING_NAMESPACE, NULL);
    sub_elem = axiom_element_get_first_child_with_qname(subs_elem, env, qname, subs_node, &sub_node);
    axutil_qname_free(qname, env);
    
    if(sub_node)
    {
        /* Now read each sub element of Subscribe element */
        status = savan_util_process_subscriber_node(env, sub_node, sub_elem, subscriber);
        if(AXIS2_SUCCESS != status)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Parsing subscriber node failed");
            AXIS2_ERROR_SET(env->error, SAVAN_ERROR_PARSING_SUBSCRIBER_NODE_FAILED, AXIS2_FAILURE);
            return NULL;
        }
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Exit:savan_service_subs_mgr_process_savan_specific_subscriber_node");
    return subscriber;
}

static axiom_node_t *
savan_service_subs_mgr_build_subscriber_request_om_payload(
    const axutil_env_t *env,
    const axis2_char_t *subs_id)
{
    axiom_node_t *om_node = NULL;
    axiom_element_t* om_ele = NULL;
    axiom_node_t* subs_id_om_node = NULL;
    axiom_element_t * subs_id_om_ele = NULL;
    axiom_namespace_t *ns1 = NULL;
    axis2_char_t *om_str = NULL;

    ns1 = axiom_namespace_create (env, SAVAN_NAMESPACE, SAVAN_NS_PREFIX);
    om_ele = axiom_element_create(env, NULL, ELEM_NAME_GET_SUBSCRIBER, ns1, &om_node);
    subs_id_om_ele = axiom_element_create(env, om_node, ELEM_NAME_SUBSCRIBER_ID, ns1, 
        &subs_id_om_node);
    axiom_element_set_text(subs_id_om_ele, env, subs_id, subs_id_om_node);

    om_str = axiom_node_to_string(om_node, env);
    if (om_str)
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "Sending OM : %s", om_str);
        AXIS2_FREE(env->allocator, om_str);
        om_str =  NULL;
    }
    return om_node;
}

static axiom_node_t *
savan_service_subs_mgr_build_subscribers_request_om_payload(
    const axutil_env_t *env,
    const axis2_char_t *topic)
{
    axiom_node_t *om_node = NULL;
    axiom_element_t* om_ele = NULL;
    axiom_node_t* topic_om_node = NULL;
    axiom_element_t * topic_om_ele = NULL;
    axiom_namespace_t *ns1 = NULL;
    axis2_char_t *om_str = NULL;

    ns1 = axiom_namespace_create (env, SAVAN_NAMESPACE, SAVAN_NS_PREFIX);
    om_ele = axiom_element_create(env, NULL, ELEM_NAME_GET_SUBSCRIBER_LIST, ns1, &om_node);
    topic_om_ele = axiom_element_create(env, om_node, ELEM_NAME_TOPIC, ns1, 
        &topic_om_node);
    axiom_element_set_text(topic_om_ele, env, topic, topic_om_node);

    om_str = axiom_node_to_string(om_node, env);
    if (om_str)
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "Sending OM : %s", om_str);
        AXIS2_FREE(env->allocator, om_str);
        om_str =  NULL;
    }
    return om_node;
}

/*static axiom_node_t *
build_remove_subscriber_om_payload(
    const axutil_env_t *env,
    savan_subscriber_t *subscriber)
{
    axiom_node_t *remove_node = NULL;
    axiom_element_t* remove_ele = NULL;
    axiom_namespace_t *ns = NULL;
    axiom_namespace_t *ns1 = NULL;
    axiom_node_t *id_node = NULL;
    axiom_node_t *topic_node = NULL;
    axiom_element_t* id_elem = NULL;
    axiom_element_t* topic_elem = NULL;
    axis2_char_t *topic = NULL;
    axis2_char_t *id = NULL;

    id = savan_subscriber_get_id(subscriber, env);

    ns = axiom_namespace_create (env, EVENTING_NAMESPACE, EVENTING_NS_PREFIX);
    ns1 = axiom_namespace_create (env, SAVAN_NAMESPACE, SAVAN_NS_PREFIX);
    remove_ele = axiom_element_create(env, NULL, ELEM_NAME_REMOVE_SUBSCRIBER, 
        ns1, &remove_node);
    
    // create the id element
    if(id)
    {
        id_elem = axiom_element_create(env, remove_node, ELEM_NAME_ID, ns1, &id_node);
            axiom_element_set_text(id_elem, env, id, id_node);
    }
    // create the topic element
    topic_elem = axiom_element_create(env, remove_node, ELEM_NAME_TOPIC, ns1, &topic_node);
    topic = savan_subscriber_get_topic(subscriber, env);
    if(topic)
        axiom_element_set_text(topic_elem, env, topic, topic_node);
    
    return remove_node;
}*/

static axiom_node_t *
savan_service_subs_mgr_build_topics_request_om_payload(
    const axutil_env_t *env)
{
    axiom_node_t *om_node = NULL;
    axiom_element_t* om_ele = NULL;
    axiom_namespace_t *ns1 = NULL;
    axis2_char_t *om_str = NULL;

    ns1 = axiom_namespace_create (env, SAVAN_NAMESPACE, SAVAN_NS_PREFIX);
    om_ele = axiom_element_create(env, NULL, ELEM_NAME_GET_TOPIC_LIST, ns1, &om_node);
    om_str = axiom_node_to_string(om_node, env);
    if (om_str)
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
            "[savan] Sending topics_request_om_payload: %s", om_str);
        AXIS2_FREE(env->allocator, om_str);
        om_str =  NULL;
    }
    return om_node;
}

static axutil_array_list_t *
savan_service_subs_mgr_process_topic_list_node(
    const axutil_env_t *env,
    axiom_node_t *topic_list_node)
{
    axiom_element_t *topic_list_element = NULL;
    axiom_children_qname_iterator_t *topic_iter = NULL;
    axutil_qname_t *qname = NULL;
    axutil_array_list_t *topic_list = NULL;

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Entry:savan_service_subs_mgr_process_topic_list_node");

    topic_list_element = axiom_node_get_data_element(topic_list_node, env); 
         
    /* Get topic elements from topic list */
    qname = axutil_qname_create(env, ELEM_NAME_TOPIC, SAVAN_NAMESPACE, NULL);
    topic_iter = axiom_element_get_children_with_qname(topic_list_element, env, qname, 
            topic_list_node);

    axutil_qname_free(qname, env);
    if(!topic_iter)
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[savan] Topic list is empty");
        return NULL;
    }

    if(axiom_children_qname_iterator_has_next(topic_iter, env))
    {
        topic_list = axutil_array_list_create(env, 0);
    }

    while(axiom_children_qname_iterator_has_next(topic_iter, env))
    {
        axiom_node_t *topic_node = NULL;
        axiom_element_t *topic_elem = NULL;
        axis2_char_t *topic_url_str = NULL;

        topic_node = axiom_children_qname_iterator_next(topic_iter, env);
        if(topic_node)
        {
            topic_elem = axiom_node_get_data_element(topic_node, env);
            topic_url_str = axiom_element_get_text(topic_elem, env, topic_node);
            axutil_array_list_add(topic_list, env, axutil_strdup(env, topic_url_str));
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "topic_url_str:%s", topic_url_str);
        }
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Exit:savan_service_subs_mgr_process_topic_list_node");
    return topic_list;
}


