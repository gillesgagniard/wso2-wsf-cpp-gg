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
 
#ifndef SAVAN_UTIL_H
#define SAVAN_UTIL_H

#include <axis2_const.h>
#include <axutil_error.h>
#include <axutil_hash.h>
#include <axis2_defines.h>
#include <axutil_utils_defines.h>
#include <axutil_env.h>
#include <axutil_allocator.h>
#include <axis2_msg_ctx.h>

#include <savan_constants.h>
#include <savan_subscriber.h>
#include <savan_sub_processor.h>
#include <savan_subs_mgr.h>
#include <savan_publisher.h>
#include <savan_filter_mod.h>
#include <axiom_node.h>
#include <axiom_element.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @defgroup savan_util
 * @ingroup Savan Util
 * @{
 */

struct savan_subs_mgr;

	/**
     * Create the fault envelope, to be sent
     * to the client.
     * @param msg_ctx msg context
     * @param env environment
     * @param code, fault code
     * @param subcode, fault sub code
     * @param reason, fault reason
     * @param detail, fault deails.
	*/

	AXIS2_EXTERN axis2_status_t AXIS2_CALL
	savan_util_create_fault_envelope(
		axis2_msg_ctx_t *msg_ctx,
		const axutil_env_t *env,
		axis2_char_t *code,
		axis2_char_t *subcode,
		axis2_char_t *reason,
		axis2_char_t *detail);

	/**
 	* Build a savan fault message and send.
 	* @param env, pointer to the environment
 	* @param code, SOAP12:Sender
 	* @param subcode, fault subcode
 	* @param reason, fault reason
 	* @param detail, details about fault,
 	* and solution to avoid.
 	*/ 

    /*
	int AXIS2_CALL
	savan_util_send_fault_notification(
    	savan_subscriber_t *subscriber,
    	const axutil_env_t *env,
    	axis2_char_t * code,
    	axis2_char_t * subcode,
    	axis2_char_t * reason,
    	axis2_char_t * detail);
    */

	/**
 	* Build a savan fault message
 	* @param env, pointer to the environment
 	* @param code, SOAP12:Sender
 	* @param subcode, fault subcode
 	* @param reason, fault reason
 	* @param detail, details about fault,
 	* and solution to avoid.
 	*/ 

	AXIS2_EXTERN axiom_node_t * AXIS2_CALL
	savan_util_build_fault_msg(
		const axutil_env_t *env,
		axis2_char_t * code,
		axis2_char_t * subcode,
		axis2_char_t * reason,
		axis2_char_t * detail);

    AXIS2_EXTERN savan_message_types_t AXIS2_CALL
    savan_util_get_message_type(
        axis2_msg_ctx_t *msg_ctx,
        const axutil_env_t *env);
    
    /**
    * Extracts the subscription ID from the given messsage
    * context.
    * @param env pointer to environment struct
    * @param msg_ctx pointer to message context
    * @return the ID on success, else NULL
    */

    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    savan_util_get_subscription_id_from_msg(
        const axutil_env_t *env,
        axis2_msg_ctx_t *msg_ctx);

    /**
    * Get the subscriber store from the service
    * Note that if the subscription manager is a separate service from
    * the publisher service then both SubscriptionMgrName and SubscriptionMgrURL
    * must be set in the publishers services.xml
    * @param env pointer to environment struct
    * @param msg_ctx pointer to message context
    * @return the store on success, else NULL
    */

    AXIS2_EXTERN axutil_hash_t * AXIS2_CALL
    savan_util_get_subscriber_store(
        const axutil_env_t *env,
        axis2_msg_ctx_t *msg_ctx);

    /**
    * Calculate and return an expiry time for the subscription
    * @param env pointer to environment struct
    * @return the expiry time on success, else NULL
    */

    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    savan_util_get_expiry_time(
        const axutil_env_t *env);

     /**
    * Calculate and return a new expiry time for the subscription based on the
    * current expiry time.
    * @param env pointer to environment struct
    * @param expiry current expiry time
    * @return the new expiry time on success, else NULL
    */
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    savan_util_get_renewed_expiry_time(
        const axutil_env_t *env,
        axis2_char_t *expiry);
    
    /**
    * Create subs hash and set as a service parameter.
    * @param env pointer to environment struct
    * @param svc subscription service
    * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE 
    */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL 
    savan_util_set_store(
        axis2_svc_t *svc,
        const axutil_env_t *env,
        axis2_char_t *store_name);

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    savan_util_get_topic_name_from_topic_url(
        const axutil_env_t *env,
        axis2_char_t *topic_url);

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    savan_util_get_resource_connection_string(
        const axutil_env_t *env,
        axis2_conf_t *conf);
    
    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    savan_util_get_resource_username(
        const axutil_env_t *env,
        axis2_conf_t *conf);
    
    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    savan_util_get_resource_password(
        const axutil_env_t *env,
        axis2_conf_t *conf);

    /**
    * Get the module parameter value by passing the module parameter name.
    * @param env pointer to environment struct
    * @param conf Axis2/C configuration structure
    * @param name module parameter name
    * @return module parameter value
    */
    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    savan_util_get_module_param(
        const axutil_env_t *env,
        axis2_conf_t *conf,
        axis2_char_t *name);

    AXIS2_EXTERN void *AXIS2_CALL
    savan_util_get_svc_client(
        const axutil_env_t *env);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    savan_util_process_subscriber_node(
        const axutil_env_t *env,
        axiom_node_t *sub_node,
        axiom_element_t *sub_elem,
        savan_subscriber_t *subscriber);

    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    savan_util_create_subscriber_node(
        const axutil_env_t *env,
        savan_subscriber_t *subscriber,
        axiom_node_t *parent_node);

    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    savan_util_create_savan_specific_subscriber_node(
        const axutil_env_t *env, 
        savan_subscriber_t *subscriber,
        axiom_node_t *parent_node);

    /**
     * Retrieve filter handler. If it is already created for this request scope then it should be 
     * available as a message context property. Otherwise create it and set as message context
     * property.
     * @param env environment object
     * @param conf Axis2 main configuration instance
     * @return filter handler
     */
    AXIS2_EXTERN savan_filter_mod_t * AXIS2_CALL
    savan_util_get_filter_module(
        const axutil_env_t *env,
        axis2_conf_t *conf);

/** @} */
#ifdef __cplusplus
}
#endif
 
#endif /*SAVAN_UTIL_H*/
