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
#include <axis2_svc_client.h>
#include <axis2_conf.h>
#include <axis2_options.h>
#include <axutil_array_list.h>
#include <savan_constants.h>
#include <savan_util.h>
#include <savan_subscriber.h>
#include <savan_subs_mgr.h>
#include <savan_error.h>
#include <axiom_soap.h>
#include <axiom_soap_const.h>
#include <axiom_soap_envelope.h>
#include <axiom_element.h>
#include <axiom_node.h>

/**
 *
 */
/** 
 * @brief Savan Default Publisher Struct Impl
 *   Savan Default Publisher 
 */
typedef struct savan_default_publisher
{
    savan_publisher_t publishermod;
    axis2_conf_t *conf;
} savan_default_publisher_t;

#define SAVAN_INTF_TO_IMPL(publishermod) ((savan_default_publisher_t *) publishermod)

AXIS2_EXTERN void AXIS2_CALL
savan_default_publisher_free(
    savan_publisher_t *publishermod,
    const axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL
savan_default_publisher_publish(
    savan_publisher_t *publishermod,
    const axutil_env_t *env,
    void *msg_ctx,
    savan_subs_mgr_t *subs_mgr);

static axis2_status_t
savan_default_publisher_publish_to_subscriber(
    savan_publisher_t *publishermod,
    const axutil_env_t *env,
    axis2_svc_client_t *svc_client,
    savan_subscriber_t *subscriber,
    savan_filter_mod_t *filtermod,
    axiom_node_t *payload);

static const savan_publisher_ops_t savan_publisher_ops = 
{
    savan_default_publisher_free,
    savan_default_publisher_publish
};

AXIS2_EXTERN savan_publisher_t * AXIS2_CALL
savan_publisher_create_with_conf(
    const axutil_env_t *env,
    axis2_conf_t *conf)
{
    savan_default_publisher_t *publishermodimpl = NULL;
    
    publishermodimpl = AXIS2_MALLOC(env->allocator, sizeof(savan_default_publisher_t));
    if (!publishermodimpl)
    {
        AXIS2_HANDLE_ERROR(env, SAVAN_ERROR_FILTER_CREATION_FAILED, AXIS2_FAILURE);
        return NULL;
    }

    memset ((void *) publishermodimpl, 0, sizeof(savan_default_publisher_t));

    publishermodimpl->conf = conf;
    publishermodimpl->publishermod.ops = &savan_publisher_ops;

    return (savan_publisher_t *) publishermodimpl;
}

AXIS2_EXTERN savan_publisher_t * AXIS2_CALL
savan_publisher_create(
    const axutil_env_t *env)
{
    return NULL;
}

AXIS2_EXTERN void AXIS2_CALL
savan_default_publisher_free(
    savan_publisher_t *publishermod,
    const axutil_env_t *env)
{
    savan_default_publisher_t *publishermodimpl = NULL;
    publishermodimpl = SAVAN_INTF_TO_IMPL(publishermod);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_default_publisher_free");

    publishermodimpl->conf = NULL;

    if(publishermodimpl)
    {
        AXIS2_FREE(env->allocator, publishermodimpl);
        publishermodimpl = NULL;
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Exit:savan_default_publisher_free");
}

AXIS2_EXTERN void AXIS2_CALL
savan_default_publisher_publish(
    savan_publisher_t *publishermod,
    const axutil_env_t *env,
    void *msg_ctx,
    savan_subs_mgr_t *subs_mgr)
{
    savan_default_publisher_t *publishermodimpl = NULL;
    axutil_array_list_t *subs_store = NULL;
    int i = 0, size = 0;
    savan_filter_mod_t *filtermod = NULL;
    const axis2_char_t *path = NULL;
    axiom_node_t *payload = NULL;
    axiom_soap_envelope_t *envelope = NULL;
    axiom_soap_body_t *body = NULL;
    axiom_node_t *body_node = NULL;
    const axis2_char_t *filter = NULL;
    axis2_conf_ctx_t *conf_ctx = NULL;
    axutil_property_t *topic_property = NULL;

    publishermodimpl = SAVAN_INTF_TO_IMPL(publishermod);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_default_publisher_publish");

    topic_property = axis2_msg_ctx_get_property(msg_ctx, env, ELEM_NAME_TOPIC);
    if(topic_property)
    {
        filter = axutil_property_get_value(topic_property, env);
    }
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

    conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);
    path = axis2_conf_ctx_get_root_dir(conf_ctx, env);
    if(!path)
    {
        path = AXIS2_GETENV("AXIS2C_HOME");
    }

    envelope =  axis2_msg_ctx_get_soap_envelope((axis2_msg_ctx_t *) msg_ctx, env);
    if (!envelope)
    {
        axutil_allocator_switch_to_local_pool(env->allocator);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Failed to extract the soap envelop");
    }
    
    body = axiom_soap_envelope_get_body(envelope, env);
    if (!body)
    {
        axutil_allocator_switch_to_local_pool(env->allocator);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Failed to extract the soap body"); 
    }
    
    body_node = axiom_soap_body_get_base_node(body, env);

    payload = axiom_node_get_first_child(body_node, env);
    size = axutil_array_list_size(subs_store, env);
    for(i = 0; i < size; i++)
    {
        axis2_svc_client_t *svc_client = NULL;
        savan_subscriber_t *sub = NULL;

        sub = (savan_subscriber_t *)axutil_array_list_get(subs_store, env, i);
        if (sub)
        {
            axis2_char_t *id = savan_subscriber_get_id(sub, env);
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[savan] Publishing to:%s", id);

            svc_client = axis2_svc_client_create(env, path);
            filtermod = savan_util_get_filter_module(env, publishermodimpl->conf);
            /* Ideally publishing to each subscriber should happen within a thread for each 
             * subscriber. However until Axis2/C provide a good thread pool to handle
             * such tasks I use this sequential publishing to subscribers.
             */
            if(!savan_default_publisher_publish_to_subscriber(publishermod, env, svc_client, sub, 
                        filtermod, payload))
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
            if(svc_client)
            {
                axis2_svc_client_free(svc_client, env);
            }
        }
    }

    axutil_allocator_switch_to_local_pool(env->allocator);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Exit:savan_default_publisher_publish");
}

static axis2_status_t
savan_default_publisher_publish_to_subscriber(
    savan_publisher_t *publishermod,
    const axutil_env_t *env,
    axis2_svc_client_t *svc_client,
    savan_subscriber_t *subscriber,
    savan_filter_mod_t *filtermod,
    axiom_node_t *payload)
{
    axis2_options_t *options = NULL;
    axis2_status_t status = AXIS2_SUCCESS;
    axis2_endpoint_ref_t *to = NULL;
    const axis2_char_t *address = NULL;
    axis2_bool_t filter_apply = AXIS2_TRUE;
    axis2_endpoint_ref_t *notifyto = NULL;

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_default_publisher_publish_to_subscriber");

    options = (axis2_options_t *) axis2_svc_client_get_options(svc_client, env);
    if(!options)
    {
        options = axis2_options_create(env);
        axis2_svc_client_set_options(svc_client, env, options);
    }
    axis2_options_set_action(options, env, "http://ws.apache.org/ws/2007/05/eventing-extended/Publish");
    axis2_svc_client_engage_module(svc_client, env, AXIS2_MODULE_ADDRESSING);

    notifyto = savan_subscriber_get_notify_to(subscriber, env);
    if(notifyto)
    {
        address = axis2_endpoint_ref_get_address(notifyto, env);
        if(address)
        {
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[savan] Publishing to:%s", address);
            to = axis2_endpoint_ref_create(env, address);
            axis2_options_set_to(options, env, to);
        }
    }
    axis2_options_set_xml_parser_reset(options, env, AXIS2_FALSE);

#ifdef SAVAN_FILTERING
    /* If this is a filtering request and filter module is defined then filter the request.
     */
    {
        axis2_char_t *filter_dialect = NULL;
        filter_dialect = savan_subscriber_get_filter_dialect(subscriber, env);
        if(!axutil_strcmp(filter_dialect, SYNAPSE_FILTER_DIALECT))
        {
            /* Do nothing */
        }
        else if(filtermod && savan_subscriber_get_filter(subscriber, env))
        {
            /* Apply the filter, and check whether it evaluates to success */
            filter_apply = savan_filter_mod_apply(filtermod ,env, subscriber, payload);
            if(!filter_apply)
            {
                status = axutil_error_get_status_code(env->error);
                if(AXIS2_SUCCESS != status)
                {
                    axiom_node_detach(payload, env);
                    return status;
                }
            }
        }
        else
        {
            AXIS2_HANDLE_ERROR(env, SAVAN_ERROR_FILTER_MODULE_COULD_NOT_BE_RETRIEVED, 
                    AXIS2_FAILURE);
            return AXIS2_FAILURE;
        }
    }
#endif

    if(filter_apply)
    {
        axis2_svc_client_fire_and_forget(svc_client, env, payload);
    }

    axiom_node_detach(payload, env); /*insert this to prevent payload corruption in subsequent 
                                       "publish" calls with some payload.*/

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Exit:savan_default_publisher_publish_to_subscriber");

    return status;
}


