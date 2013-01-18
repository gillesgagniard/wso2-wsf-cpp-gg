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
 
#ifndef SAVAN_SUBSCRIBER_H
#define SAVAN_SUBSCRIBER_H
 
/**
* @defgroup savan_subscribers 
* @ingroup savan_subscribers
* subscriber represents a client subscribing to an eventing service
* @{
*/

/**
* @file savan_sub_processor.h
*/

#include <axis2_defines.h>
#include <axutil_env.h>

#ifdef __cplusplus
extern "C"
{
#endif

    struct savan_filter_mod;
    typedef struct savan_subscriber_t savan_subscriber_t;

	/* Set the filter dialect
	 * @param subscriber pointer to the subscriber
	 * @param env pointer to the environment
	 * @param filter_dailect pointer to the dialect
	 */

	AXIS2_EXTERN axis2_status_t AXIS2_CALL
	savan_subscriber_set_filter_dialect(
		savan_subscriber_t *subscriber,
    	const axutil_env_t *env,
    	const axis2_char_t *filter_dialect);

	/* Get the filter dialect
	 * @param subscriber pointer to the filter dialect
	 * @param env pointer to the enviornment
	 */

	AXIS2_EXTERN axis2_char_t * AXIS2_CALL
	savan_subscriber_get_filter_dialect(
		savan_subscriber_t *subscriber,
    	const axutil_env_t *env);

	/*
	* Get the delivery mode
	* @param subscriber pointer to the subscriber
	* @param env pointer to the environment
	*/ 

	AXIS2_EXTERN axis2_char_t * AXIS2_CALL
		savan_subscriber_get_delivery_mode(
    	savan_subscriber_t *subscriber,
    	const axutil_env_t *env);

    /**
     * Retrive subscriber id.
     * @param subscriber pointer to subscriber
     * @param env pointer to environment struct
     * @return the unique id assigned to the subscriber 
     */
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    savan_subscriber_get_id(
        savan_subscriber_t *subscriber,
        const axutil_env_t *env);
    
    /**
     * Set id.
     * @param subscriber pointer to subscriber
     * @param env pointer to environment struct
     * @param id the id
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    savan_subscriber_set_id(
        savan_subscriber_t *subscriber,
        const axutil_env_t *env,
        const axis2_char_t *id);
    
    /**
     * Set EndTo end point.
     * @param subscriber pointer to subscriber
     * @param env pointer to environment struct
     * @param end_to the EndTo reference
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    savan_subscriber_set_end_to(
        savan_subscriber_t *subscriber,
        const axutil_env_t *env,
        axis2_endpoint_ref_t *end_to);
 
    /**
     * Get EndTo end point.
     * @param subscriber pointer to subscriber
     * @param env pointer to environment struct
     * @return end_to 
     */
    AXIS2_EXTERN axis2_endpoint_ref_t *AXIS2_CALL
    savan_subscriber_get_end_to(
        savan_subscriber_t *subscriber,
        const axutil_env_t *env);
               
    /**
     * Set NotifyTo end point.
     * @param subscriber pointer to subscriber
     * @param env pointer to environment struct
     * @param notify_to the NotifyTo reference
     */
	AXIS2_EXTERN axis2_status_t AXIS2_CALL
    savan_subscriber_set_notify_to(
        savan_subscriber_t *subscriber,
        const axutil_env_t *env,
        axis2_endpoint_ref_t *notify_to);

    /**
     * Get NotifyTo end point.
     * @param subscriber pointer to subscriber
     * @param env pointer to environment struct
     * @return notify_to
     */
    AXIS2_EXTERN axis2_endpoint_ref_t *AXIS2_CALL
    savan_subscriber_get_notify_to(
        savan_subscriber_t *subscriber,
        const axutil_env_t *env);

    /**
     * Set delivery mode.
     * @param subscriber pointer to subscriber
     * @param env pointer to environment struct
     * @param mode the delivery mode
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    savan_subscriber_set_delivery_mode(
        savan_subscriber_t *subscriber,
        const axutil_env_t *env,
        const axis2_char_t *mode);

    /**
     * Set expires.
     * @param subscriber pointer to subscriber
     * @param env pointer to environment struct
     * @param expires the expires date and time
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    savan_subscriber_set_expires(
        savan_subscriber_t *subscriber,
        const axutil_env_t *env,
        const axis2_char_t *expires);

    /**
     * Get expires.
     * @param subscriber pointer to subscriber
     * @param env pointer to environment struct
     * @return expire date and time as string
     */
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    savan_subscriber_get_expires(
        savan_subscriber_t *subscriber,
        const axutil_env_t *env);

    /**
     * Set filter.
     * @param subscriber pointer to subscriber
     * @param env pointer to environment struct
     * @param filter the filter string
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    savan_subscriber_set_filter(
        savan_subscriber_t *subscriber,
        const axutil_env_t *env,
        const axis2_char_t *filter);

    /**
     * Get filter.
     * @param subscriber pointer to subscriber
     * @param env pointer to environment struct
     * @return filter the filter string
     */
    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    savan_subscriber_get_filter(
        savan_subscriber_t *subscriber,
        const axutil_env_t *env);

    /**
     * Set whether the subscription is renewed or not.
     * @param subscriber pointer to subscriber
     * @param env pointer to environment struct
     * @param msg_ctx the msg to be published
     * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE 
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    savan_subscriber_set_renew_status(
        savan_subscriber_t *subscriber,
        const axutil_env_t *env,
        axis2_bool_t renewed);

    /**
     * Check whether the subscription is renewed or not.
     * @param subscriber pointer to subscriber
     * @param env pointer to environment struct
     * @param msg_ctx the msg to be published
     * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE 
     */
    AXIS2_EXTERN axis2_bool_t AXIS2_CALL
    savan_subscriber_get_renew_status(
        savan_subscriber_t *subscriber,
        const axutil_env_t *env);

    /**
     * Creates a subscriber instance.
     * @param env pointer to environment struct
     * @return pointer to newly created subscriber struct
     */
    AXIS2_EXTERN savan_subscriber_t * AXIS2_CALL
    savan_subscriber_create(
        const axutil_env_t *env);
   
    AXIS2_EXTERN void AXIS2_CALL
    savan_subscriber_free(
        savan_subscriber_t *subscriber, 
        const axutil_env_t *env);

    AXIS2_EXTERN void AXIS2_CALL
    savan_subscriber_free_void_arg(
        void *subscriber, 
        const axutil_env_t *env);

/** @} */
#ifdef __cplusplus
}
#endif

#endif /* SAVAN_SUBSCRIBER_H */
