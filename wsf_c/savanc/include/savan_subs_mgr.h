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
 
#ifndef SAVAN_SUBS_MGR_H
#define SAVAN_SUBS_MGR_H

/**
  * @file savan_subs_mgr.h
  * @brief 
  */
#include <platforms/axutil_platform_auto_sense.h>
#include <axutil_utils_defines.h>
#include <axutil_env.h>
#include <axis2_conf.h>
#include <savan_subscriber.h>

#ifdef __cplusplus
extern "C"
{
#endif

/** 
 * @ingroup savan subscription manager
 * @{
 */
 
typedef struct savan_subs_mgr savan_subs_mgr_t;
typedef struct savan_subs_mgr_ops savan_subs_mgr_ops_t;
struct axis2_conf_ctx;

 /**
 * @brief Subscription Manager ops struct
 * Encapsulator struct for ops of savan_subs_mgr
 */
AXIS2_DECLARE_DATA struct savan_subs_mgr_ops
{ 
    void (AXIS2_CALL * 
            free)(
                savan_subs_mgr_t *subs_mgr,
                const axutil_env_t *env);

    axis2_status_t (AXIS2_CALL *
            insert_subscriber)(
                savan_subs_mgr_t *subs_mgr, 
                const axutil_env_t *env,
                savan_subscriber_t *subscriber);

    axis2_status_t (AXIS2_CALL *
            update_subscriber)(
                savan_subs_mgr_t *subs_mgr, 
                const axutil_env_t *env,
                savan_subscriber_t *subscriber);

    axis2_status_t (AXIS2_CALL *
            remove_subscriber)(
                savan_subs_mgr_t *subs_mgr, 
                const axutil_env_t *env,
                const axis2_char_t *subscription_id);

    savan_subscriber_t *(AXIS2_CALL *
            retrieve_subscriber)(
                savan_subs_mgr_t *subs_mgr, 
                const axutil_env_t *env,
                const axis2_char_t *subscription_id);

    axutil_array_list_t *(AXIS2_CALL *
            retrieve_all_subscribers)(
                savan_subs_mgr_t *subs_mgr, 
                const axutil_env_t *env,
                const axis2_char_t *topic_name);

    axis2_status_t (AXIS2_CALL *
            insert_topic)(
                savan_subs_mgr_t *subs_mgr, 
                const axutil_env_t *env,
                const axis2_char_t *topic_name,
                const axis2_char_t *topic_url);

};

AXIS2_DECLARE_DATA struct savan_subs_mgr
{
    const savan_subs_mgr_ops_t *ops;
};


/**
 * Create the savan subscription manager.
 * @param env environment object
 * @param conf axis2 configuration
 * @return status of the operation
 */
AXIS2_EXTERN savan_subs_mgr_t * AXIS2_CALL
savan_subs_mgr_create(
    const axutil_env_t *env,
    axis2_conf_t *conf);

AXIS2_EXTERN savan_subs_mgr_t * AXIS2_CALL
savan_subs_mgr_create_with_connection_info(
    const axutil_env_t *env,
    axis2_char_t *connection_string,
    axis2_char_t *username,
    axis2_char_t *password);

/**
 * Deallocate the subscription manager.
 * @param subs_mgr
 * @param env environment object
 */
AXIS2_EXTERN void AXIS2_CALL 
savan_subs_mgr_free(
    savan_subs_mgr_t *subs_mgr,
    const axutil_env_t *envv);

/**
 * Insert a subscriber.
 * @param subs_mgr
 * @param env environment object
 * @param subscriber subscriber instant
 * @return status of the operation
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_subs_mgr_insert_subscriber(
    savan_subs_mgr_t *subs_mgr, 
    const axutil_env_t *env,
    savan_subscriber_t *subscriber);

/**
 * Update a subscriber.
 * @param subs_mgr
 * @param env environment object
 * @param subscriber subscriber instant
 * @return status of the operation
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_subs_mgr_update_subscriber(
    savan_subs_mgr_t *subs_mgr, 
    const axutil_env_t *env,
    savan_subscriber_t *subscriber);

/**
 * Remove a subscriber.
 * @param subs_mgr
 * @param env environment object
 * @param subscription_id subscriber's id
 * @return status of the operation
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_subs_mgr_remove_subscriber(
    savan_subs_mgr_t *subs_mgr, 
    const axutil_env_t *env,
    const axis2_char_t *subscription_id);

/**
 * Retrieve a subscriber.
 * @param subs_mgr
 * @param env environment object
 * @param subscription_id subscriber's id
 * @return subscriber corresponding to the passed subscription id
 */
AXIS2_EXTERN savan_subscriber_t *AXIS2_CALL
savan_subs_mgr_retrieve_subscriber(
    savan_subs_mgr_t *subs_mgr, 
    const axutil_env_t *env,
    const axis2_char_t *subscription_id);

/**
 * Retrive all subscribers for a topic(event source).
 * @param subs_mgr
 * @param env environment object
 * @param topic_name topoic_name
 * @return all subscribers for the event source
 */
AXIS2_EXTERN axutil_array_list_t *AXIS2_CALL
savan_subs_mgr_retrieve_all_subscribers(
    savan_subs_mgr_t *subs_mgr, 
    const axutil_env_t *env,
    const axis2_char_t *filter);

/**
 * Insert topic. Event source is mapped to a topic
 * @param subs_mgr
 * @param env environment object
 * @param topic_name topoic name
 * @param topic_url topoic url
 * @return status of the operation
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_subs_mgr_insert_topic(
    savan_subs_mgr_t *subs_mgr, 
    const axutil_env_t *env,
    const axis2_char_t *topic_name,
    const axis2_char_t *topic_url);

AXIS2_EXTERN savan_subscriber_t *AXIS2_CALL
savan_subs_mgr_get_subscriber_from_msg(
        const axutil_env_t *env,
        axis2_msg_ctx_t *msg_ctx,
        savan_subs_mgr_t *subs_mgr,
        const axis2_char_t *sub_id);

AXIS2_EXTERN savan_subscriber_t *AXIS2_CALL
savan_subs_mgr_get_subscriber_from_renew_msg(
        const axutil_env_t *env,
        axis2_msg_ctx_t *msg_ctx,
        savan_subs_mgr_t *subs_mgr,
        const axis2_char_t *sub_id);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_subs_mgr_add_subscriber(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    savan_subs_mgr_t *subs_mgr,
    savan_subscriber_t *subscriber);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_subs_mgr_update_subscriber_with_msg_ctx(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    savan_subs_mgr_t *subs_mgr,
    savan_subscriber_t *subscriber);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_subs_mgr_remove_subscriber_with_msg_ctx(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    savan_subs_mgr_t *subs_mgr,
    savan_subscriber_t *subscriber);

/**
 * Retrieve subs mgr. If it is already created for this request scope then it should be 
 * available as a message context property. Otherwise create it and set as message context
 * property.
 * @param env environment object
 * @param conf_ctx configuration context instance
 * @param conf Axis2 main configuration instance
 * @return subs manager
 */
AXIS2_EXTERN struct savan_subs_mgr * AXIS2_CALL
savan_subs_mgr_get_subs_mgr(
    const axutil_env_t *env,
    struct axis2_conf_ctx *conf_ctx,
    axis2_conf_t *conf);


/** @} */
#ifdef __cplusplus
}
#endif

#endif /*SAVAN_SUBS_MGR_H*/
