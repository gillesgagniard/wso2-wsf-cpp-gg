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
 
#include <savan_publisher.h>
#include <axutil_log.h>
#include <axutil_hash.h>
#include <axutil_property.h>
#include <axutil_types.h>
#include <axutil_file_handler.h>
#include <platforms/axutil_platform_auto_sense.h>
#include <savan_constants.h>
#include <savan_util.h>
#include <savan_error.h>
#include <libxslt/xsltutils.h>
#include <axiom_soap.h>
#include <axiom_soap_const.h>
#include <axiom_soap_envelope.h>
#include <axiom_element.h>
#include <axiom_node.h>
#include <esb_sender.h>
#include <esb_runtime.h>

/**
 *
 */
/** 
 * @brief Savan XPath Publisher Struct Impl
 *   Savan XPath Publisher 
 */
typedef struct savan_esb_publisher
{
    savan_publisher_t publishermod;
    axis2_conf_t *conf;
} savan_esb_publisher_t;

#define SAVAN_INTF_TO_IMPL(publishermod) ((savan_esb_publisher_t *) publishermod)

static axis2_status_t
savan_esb_publisher_publish_to_subscriber(
    savan_publisher_t *publishermod,
    const axutil_env_t *env,
    void *msg_ctx,
    savan_subscriber_t *subscriber);

AXIS2_EXTERN void AXIS2_CALL
savan_esb_publisher_free(
    savan_publisher_t *publishermod,
    const axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL
savan_esb_publisher_publish(
    savan_publisher_t *publishermod,
    const axutil_env_t *env,
    void *msg_ctx,
    savan_subs_mgr_t *subs_mgr);

static const savan_publisher_ops_t savan_publisher_ops = 
{
    savan_esb_publisher_free,
    savan_esb_publisher_publish
};

AXIS2_EXTERN savan_publisher_t * AXIS2_CALL
savan_publisher_create(
    const axutil_env_t *env)
{
    savan_esb_publisher_t *publishermodimpl = NULL;
    
    publishermodimpl = AXIS2_MALLOC(env->allocator, sizeof(savan_esb_publisher_t));
    if (!publishermodimpl)
    {
        AXIS2_HANDLE_ERROR(env, SAVAN_ERROR_FILTER_CREATION_FAILED, AXIS2_FAILURE);
        return NULL;
    }

    memset ((void *) publishermodimpl, 0, sizeof(savan_esb_publisher_t));

    publishermodimpl->conf = NULL;
    publishermodimpl->publishermod.ops = &savan_publisher_ops;

    return (savan_publisher_t *) publishermodimpl;
}

AXIS2_EXTERN savan_publisher_t * AXIS2_CALL
savan_publisher_create_with_conf(
    const axutil_env_t *env,
    axis2_conf_t *conf)
{
    savan_esb_publisher_t *publishermodimpl = NULL;
    
    publishermodimpl = AXIS2_MALLOC(env->allocator, sizeof(savan_esb_publisher_t));
    if (!publishermodimpl)
    {
        AXIS2_HANDLE_ERROR(env, SAVAN_ERROR_FILTER_CREATION_FAILED, AXIS2_FAILURE);
        return NULL;
    }

    memset ((void *) publishermodimpl, 0, sizeof(savan_esb_publisher_t));

    publishermodimpl->conf = conf;
    publishermodimpl->publishermod.ops = &savan_publisher_ops;

    return (savan_publisher_t *) publishermodimpl;
}

AXIS2_EXTERN void AXIS2_CALL
savan_esb_publisher_free(
    savan_publisher_t *publishermod,
    const axutil_env_t *env)
{
    savan_esb_publisher_t *publishermodimpl = NULL;
    publishermodimpl = SAVAN_INTF_TO_IMPL(publishermod);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_esb_publisher_free");

    publishermodimpl->conf = NULL;

    if(publishermodimpl)
    {
        AXIS2_FREE(env->allocator, publishermodimpl);
        publishermodimpl = NULL;
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Exit:savan_esb_publisher_free");
}

AXIS2_EXTERN void AXIS2_CALL
savan_esb_publisher_publish(
    savan_publisher_t *publishermod,
    const axutil_env_t *env,
    void *esb_ctx,
    savan_subs_mgr_t *subs_mgr)
{
    savan_esb_publisher_t *publishermodimpl = NULL;

    axutil_array_list_t *subs_store = NULL;
    int i = 0, size = 0;
    axis2_char_t *filter = NULL;

    publishermodimpl = SAVAN_INTF_TO_IMPL(publishermod);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_esb_publisher_publish");

    axutil_allocator_switch_to_global_pool(env->allocator);
    if(subs_mgr)
    {
        subs_store = savan_subs_mgr_retrieve_all_subscribers(subs_mgr, env, filter);
    }

    if (!subs_store)
    {
        axutil_allocator_switch_to_local_pool(env->allocator);
        AXIS2_LOG_WARNING(env->log, AXIS2_LOG_SI, "[savan] Subscriber store is NULL"); 
    }

    size = axutil_array_list_size(subs_store, env);
    for(i = 0; i < size; i++)
    {
        savan_subscriber_t *sub = NULL;

        sub = (savan_subscriber_t *)axutil_array_list_get(subs_store, env, i);
        if (sub)
        {
            axis2_char_t *id = savan_subscriber_get_id(sub, env);
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[savan] Publishing to:%s", id);

            /* Ideally publishing to each subscriber should happen within a thread for each 
             * subscriber. However until Axis2/C provide a good thread pool to handle
             * such tasks I use this sequential publishing to subscribers.
             */
            if(!savan_esb_publisher_publish_to_subscriber(publishermod, env, esb_ctx, sub))
            {
                axis2_endpoint_ref_t *notifyto = savan_subscriber_get_notify_to(sub, env);
                const axis2_char_t *address = NULL;

                if(notifyto)
                {
                    address = axis2_endpoint_ref_get_address(notifyto, env);
                }

                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                        "Publishing to the Data Sink:%s proviced by subscriber:%s Failed. Check "\
                        "whether the Data Sink url is correct", address, id);
            }
        }
    }

    axutil_allocator_switch_to_local_pool(env->allocator);


    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Exit:savan_esb_publisher_publish");
}

static axis2_status_t
savan_esb_publisher_publish_to_subscriber(
    savan_publisher_t *publishermod,
    const axutil_env_t *env,
    void *esb_ctx,
    savan_subscriber_t *subscriber)
{
    axis2_status_t status = AXIS2_SUCCESS;
    const axis2_char_t *address = NULL;
    axis2_endpoint_ref_t *notifyto = NULL;
    esb_rt_epr_t *epr = NULL;
    axiom_soap_envelope_t *envelope = NULL;
    axiom_soap_body_t *body = NULL;
    axiom_node_t *body_node = NULL;
    axiom_node_t *payload = NULL;
    axis2_msg_ctx_t *msg_ctx = NULL;
    msg_ctx = ((esb_ctx_t *) esb_ctx)->in_in_msg_ctx;

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_esb_publisher_publish_to_subscriber");

    notifyto = savan_subscriber_get_notify_to(subscriber, env);
    if(notifyto)
    {
        address = axis2_endpoint_ref_get_address(notifyto, env);
        if(address)
        {
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[savan] Publishing to:%s", address);
            epr = esb_rt_epr_create(env);
            epr->uri = axutil_strdup(env, address);
        }
    }

    envelope = axis2_msg_ctx_get_soap_envelope(msg_ctx, env);    
    body = axiom_soap_envelope_get_body(envelope, env);
    body_node = axiom_soap_body_get_base_node(body, env);
    payload = axiom_node_get_first_element(body_node, env);


    esb_send_on_out_only(env, epr, (esb_ctx_t *) esb_ctx);
	
    axiom_node_detach(payload, env); /*insert this to prevent payload corruption in subsequent 
                                       "publish" calls with some payload.*/

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Exit:savan_esb_publisher_publish_to_subscriber");

    return status;
}

