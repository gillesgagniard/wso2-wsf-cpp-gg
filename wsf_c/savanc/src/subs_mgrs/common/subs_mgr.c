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
#include <savan_constants.h>
#include <savan_error.h>
#include <savan_util.h>
#include <axutil_log.h>
#include <axutil_hash.h>
#include <axutil_property.h>
#include <axutil_uuid_gen.h>
#include <axis2_conf_ctx.h>
#include <axiom_soap_envelope.h>
#include <axiom_soap_header.h>
#include <axiom_soap_body.h>

AXIS2_EXTERN void AXIS2_CALL
savan_subs_mgr_free(
    savan_subs_mgr_t *subs_mgr,
    const axutil_env_t *env)
{
     return subs_mgr->ops->free(subs_mgr, env);
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_subs_mgr_insert_subscriber(
    savan_subs_mgr_t *subs_mgr, 
    const axutil_env_t *env,
    savan_subscriber_t *subscriber)
{
    return subs_mgr->ops->insert_subscriber(subs_mgr, env, subscriber);
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_subs_mgr_update_subscriber(
    savan_subs_mgr_t *subs_mgr, 
    const axutil_env_t *env,
    savan_subscriber_t *subscriber)
{
    return subs_mgr->ops->update_subscriber(subs_mgr, env, subscriber);
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_subs_mgr_remove_subscriber(
    savan_subs_mgr_t *subs_mgr, 
    const axutil_env_t *env,
    const axis2_char_t *subscriber_id)
{
    return subs_mgr->ops->remove_subscriber(subs_mgr, env, subscriber_id);
}

AXIS2_EXTERN savan_subscriber_t *AXIS2_CALL
savan_subs_mgr_retrieve_subscriber(
    savan_subs_mgr_t *subs_mgr, 
    const axutil_env_t *env,
    const axis2_char_t *subscriber_id)
{
    return subs_mgr->ops->retrieve_subscriber(subs_mgr, env, subscriber_id);
}

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL
savan_subs_mgr_retrieve_all_subscribers(
    savan_subs_mgr_t *subs_mgr, 
    const axutil_env_t *env,
    const axis2_char_t *filter)
{
    return subs_mgr->ops->retrieve_all_subscribers(subs_mgr, env, filter);
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_subs_mgr_insert_topic(
    savan_subs_mgr_t *subs_mgr, 
    const axutil_env_t *env,
    const axis2_char_t *topic_name,
    const axis2_char_t *topic_url)
{
    return subs_mgr->ops->insert_topic(subs_mgr, env, topic_name, topic_url);
}

AXIS2_EXTERN savan_subscriber_t *AXIS2_CALL
savan_subs_mgr_get_subscriber_from_msg(
        const axutil_env_t *env,
        axis2_msg_ctx_t *msg_ctx,
        savan_subs_mgr_t *subs_mgr,
        const axis2_char_t *sub_id)
{
    savan_subscriber_t *subscriber = NULL;

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_subs_mgr_get_subscriber_from_msg");

    /* Extract subscription id from msg if not already given */
    if (!sub_id)
    {
        sub_id = savan_util_get_subscription_id_from_msg(env, msg_ctx);
    }

    axutil_allocator_switch_to_global_pool(env->allocator);
    subscriber = savan_subs_mgr_retrieve_subscriber(subs_mgr, env, sub_id);
    axutil_allocator_switch_to_local_pool(env->allocator);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_subs_mgr_get_subscriber_from_msg");
    
    return subscriber;
}

AXIS2_EXTERN savan_subscriber_t *AXIS2_CALL
savan_subs_mgr_get_subscriber_from_renew_msg(
        const axutil_env_t *env,
        axis2_msg_ctx_t *msg_ctx,
        savan_subs_mgr_t *subs_mgr,
        const axis2_char_t *sub_id)
{
    savan_subscriber_t *subscriber = NULL;
    axiom_soap_envelope_t *envelope = NULL;
    axiom_soap_header_t *header = NULL;
    axutil_qname_t *qname = NULL;
    axiom_node_t *header_node = NULL;
    axiom_node_t *id_node = NULL;
    axiom_element_t *id_elem = NULL;
    axiom_node_t *expires_node = NULL;
    axiom_element_t *expires_elem = NULL;
    axiom_node_t *renew_node = NULL;
    axiom_element_t *renew_elem = NULL;
    axiom_element_t *header_elem = NULL;
    axis2_char_t *expires = NULL;
    axis2_char_t *renewed_expires = NULL;
    axiom_soap_body_t *body = NULL;
    axiom_node_t *body_node = NULL;
    axiom_element_t *body_elem = NULL;

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_subs_mgr_get_subscriber_from_renew_msg");

    /* Extract subscription id from msg if not already given */
    if (!sub_id)
    {
        sub_id = savan_util_get_subscription_id_from_msg(env, msg_ctx);
    }

    axutil_allocator_switch_to_global_pool(env->allocator);
    subscriber = savan_subs_mgr_retrieve_subscriber(subs_mgr, env, sub_id);
    axutil_allocator_switch_to_local_pool(env->allocator);
   
    if(!subscriber)
    {
        AXIS2_HANDLE_ERROR(env, SAVAN_ERROR_SUBSCRIBER_RETRIEVE_ERROR, AXIS2_FAILURE);
        return NULL;
    }
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
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Failed to extract the soap header"); 
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
    
    /* Get Expires element from body */
    body = axiom_soap_envelope_get_body(envelope, env);
    if (!body)
    {
        AXIS2_HANDLE_ERROR(env, AXIS2_ERROR_SOAP_ENVELOPE_OR_SOAP_BODY_NULL, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Failed to extract the soap body"); 
        return NULL;
    }
    
    body_node = axiom_soap_body_get_base_node(body, env);
    body_elem = (axiom_element_t*)axiom_node_get_data_element(body_node, env);
    
    /* Get Subscribe element from Body */
    qname = axutil_qname_create(env, ELEM_NAME_RENEW, EVENTING_NAMESPACE, NULL);
    renew_elem = axiom_element_get_first_child_with_qname(body_elem, env, qname, body_node, 
            &renew_node);
    axutil_qname_free(qname, env);
 
    qname = axutil_qname_create(env, ELEM_NAME_EXPIRES, EVENTING_NAMESPACE, NULL);
    expires_elem = axiom_element_get_first_child_with_qname(renew_elem, env, qname, renew_node, 
            &expires_node);
    axutil_qname_free(qname, env);
    if(expires_elem)
    {
        expires = axiom_element_get_text(expires_elem, env, expires_node);
        if(expires)
        {
            /* Check whether the subscription can be renewed. If renewable, set the new
             * expiry time in the subscriber */
            savan_subscriber_set_expires(subscriber, env, expires);
            renewed_expires = savan_util_get_renewed_expiry_time(env, expires);
            savan_subscriber_set_expires(subscriber, env, renewed_expires);
        }
    }
 
    savan_subscriber_set_renew_status(subscriber, env, AXIS2_TRUE);
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_subs_mgr_get_subscriber_from_renew_msg");
    
    return subscriber;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_subs_mgr_add_subscriber(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    savan_subs_mgr_t *subs_mgr,
    savan_subscriber_t *subscriber)
{
    axis2_status_t status = AXIS2_FAILURE;

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_subs_mgr_add_subscriber");
    
    axutil_allocator_switch_to_global_pool(env->allocator);
    status = savan_subs_mgr_insert_subscriber(subs_mgr, env, subscriber);
    if(status)
    {
        axutil_property_t *subs_prop = NULL;
        subs_prop = axutil_property_create_with_args(env, 0, 0, 
            savan_subscriber_free_void_arg, subscriber);
        axis2_msg_ctx_set_property(msg_ctx, env, SAVAN_SUBSCRIBER, subs_prop);
    }
    axutil_allocator_switch_to_local_pool(env->allocator);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Exit:savan_subs_mgr_add_subscriber"); 
    return status;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_subs_mgr_update_subscriber_with_msg_ctx(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    savan_subs_mgr_t *subs_mgr,
    savan_subscriber_t *subscriber)
{
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_subs_mgr_update_subscriber");

    axutil_allocator_switch_to_global_pool(env->allocator);
    savan_subs_mgr_update_subscriber(subs_mgr, env, subscriber);
    axutil_allocator_switch_to_local_pool(env->allocator);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Exit:savan_subs_mgr_update_subscriber"); 
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_subs_mgr_remove_subscriber_with_msg_ctx(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    savan_subs_mgr_t *subs_mgr,
    savan_subscriber_t *subscriber)
{
    const axis2_char_t *subs_id = NULL;

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_subs_mgr_remove_subscriber");

    axutil_allocator_switch_to_global_pool(env->allocator);
    subs_id = savan_subscriber_get_id(subscriber, env);

    savan_subs_mgr_remove_subscriber(subs_mgr, env, subs_id);
    axutil_allocator_switch_to_local_pool(env->allocator);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Exit:savan_subs_mgr_remove_subscriber");
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN savan_subs_mgr_t * AXIS2_CALL
savan_subs_mgr_get_subs_mgr(
    const axutil_env_t *env,
    axis2_conf_ctx_t *conf_ctx,
    axis2_conf_t *conf)
{
    axutil_property_t *subs_mgr_prop = NULL;
    savan_subs_mgr_t *subs_mgr = NULL;

    axutil_allocator_switch_to_global_pool(env->allocator);
    if(conf_ctx)
    {
        subs_mgr_prop = axis2_conf_ctx_get_property(conf_ctx, env, SAVAN_STORAGE_MANAGER);
        if(subs_mgr_prop)
        {
            subs_mgr = (savan_subs_mgr_t *) axutil_property_get_value(subs_mgr_prop, env);
        }
    }

    if(!subs_mgr)
    {
        subs_mgr = savan_subs_mgr_create(env, conf);

        if(subs_mgr && conf_ctx)
        {
            subs_mgr_prop = axutil_property_create_with_args(env, 0, 0, 0, subs_mgr);
            axis2_conf_ctx_set_property(conf_ctx, env, SAVAN_STORAGE_MANAGER, subs_mgr_prop);
        }
    }
        
    axutil_allocator_switch_to_local_pool(env->allocator);

    return subs_mgr;
}


