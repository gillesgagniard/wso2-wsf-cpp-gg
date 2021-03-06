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

#include <axiom_node.h>
#include <axiom_element.h>
#include <axiom_soap_body.h>
#include <axis2_options.h>
#include <axis2_addr.h>

#include <savan_client.h>
#include <savan_util.h>
#include <savan_constants.h>
#include <savan_subscriber.h>

struct savan_client_t
{
    axis2_char_t *sub_id;
    axis2_char_t *sub_url;
};

/******************************************************************************/

axis2_status_t AXIS2_CALL
savan_client_add_sub_id_to_soap_header(
    savan_client_t *client,
    const axutil_env_t *env,
    axis2_svc_client_t *svc_client);

axis2_char_t * AXIS2_CALL
savan_client_get_sub_id_from_response(
    axiom_element_t *response_elem, 
    axiom_node_t *response_node,
    const axutil_env_t *env);

axis2_char_t * AXIS2_CALL
savan_client_get_sub_url_from_response(
    axiom_element_t *response_elem, 
    axiom_node_t *response_node,
    const axutil_env_t *env);

AXIS2_EXTERN savan_client_t * AXIS2_CALL
savan_client_create(
    const axutil_env_t *env)
{
    savan_client_t *client = NULL;
    
    AXIS2_ENV_CHECK(env, NULL);
    
    client = AXIS2_MALLOC(env->allocator, sizeof(savan_client_t));
     
    if (!client)
    { 
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
           "[savan] Memory allocation failed for Savan Client");
        return NULL;        
    }
    
    client->sub_id = NULL;
        
    return client;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_client_subscribe(
    savan_client_t *client,
    const axutil_env_t *env,
    axis2_svc_client_t *svc_client,
    axutil_hash_t *options)
{
    axis2_options_t *wsa_options = NULL;
    const axis2_char_t *old_action = NULL;
    axiom_node_t *reply = NULL;
    axiom_node_t *sub_node = NULL;
    axiom_element_t *body_elem = NULL;
    axis2_char_t *sub_id = NULL;
    axis2_char_t *sub_url = NULL;
    axis2_char_t *sub_elem_local_name = NULL;
    savan_subscriber_t *subscriber = NULL;
    /*axis2_char_t *endto = NULL;*/
    axis2_char_t *notify = NULL;
    axis2_char_t *filter = NULL;
    axis2_char_t *filter_dialect = NULL;
    axis2_char_t *expires = NULL;
    axis2_status_t status = AXIS2_SUCCESS;
    axis2_endpoint_ref_t *endpoint_ref = NULL;

    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_client_subscribe");
    
    /* set wsa action as Subscribe. remember the old action */
    wsa_options = (axis2_options_t*)axis2_svc_client_get_options(svc_client, env);
    old_action = axis2_options_get_action(wsa_options, env);
    axis2_options_set_action(wsa_options, env, SAVAN_ACTIONS_SUB);
    
    /* extract the values from the options map */
    /* endto endpoint reference is used by the event source to send a subscription end message. Default is not
     * to send this message by the event source. How this should be provided by the client?
     */
    /*endto = axutil_hash_get(options, SAVAN_OP_KEY_ENDTO_EPR, AXIS2_HASH_KEY_STRING);*/
    notify = axutil_hash_get(options, SAVAN_OP_KEY_NOTIFY_EPR, AXIS2_HASH_KEY_STRING);
    filter = axutil_hash_get(options, SAVAN_OP_KEY_FILTER, AXIS2_HASH_KEY_STRING);
    filter_dialect = axutil_hash_get(options, SAVAN_OP_KEY_FILTER_DIALECT, AXIS2_HASH_KEY_STRING);
    expires = axutil_hash_get(options, SAVAN_OP_KEY_EXPIRES, AXIS2_HASH_KEY_STRING);

    subscriber = savan_subscriber_create(env);
    /*endpoint_ref = axis2_endpoint_ref_create(env, endto);
    savan_subscriber_set_end_to(subscriber, env, endpoint_ref);*/
    endpoint_ref = axis2_endpoint_ref_create(env, notify);
    savan_subscriber_set_notify_to(subscriber, env, endpoint_ref);
    savan_subscriber_set_filter(subscriber, env, filter);
    savan_subscriber_set_filter_dialect(subscriber, env, filter_dialect);
    if(expires)
    {
        savan_subscriber_set_expires(subscriber, env, expires);
    }

    /* Create the Subscriber node */
    sub_node = savan_util_create_subscriber_node(env, subscriber, NULL);
    if(!sub_node)
    {
        status = axutil_error_get_status_code(env->error);
        savan_subscriber_free(subscriber, env);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Could not create the subscriber node");
        return status;
    }

    /* send the Subscription and wait for the response */
    reply = axis2_svc_client_send_receive(svc_client, env, sub_node);
    
    /* reset the old action */
    axis2_options_set_action(wsa_options, env, old_action);
    
    if (!reply)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[savan] Failed to send subscription request. Error: %d Reason: %s", 
                env->error->error_number,
        AXIS2_ERROR_GET_MESSAGE(env->error));
        return AXIS2_FAILURE;
    }

    /* Extract the subscription id from the response and store for future
     * requests */
    
    /* Get Body element from body node */
    body_elem = (axiom_element_t*)axiom_node_get_data_element(reply, env);
    
    /* Check whether we have received a SubscribeResponse */
    sub_elem_local_name = axiom_element_get_localname(body_elem, env);

    if (axutil_strcmp(ELEM_NAME_SUB_RESPONSE, sub_elem_local_name))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Subscription failed");
        return AXIS2_FAILURE;
    }

    sub_id = savan_client_get_sub_id_from_response(body_elem, reply, env);
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "sub_id3:%s", sub_id); 
    client->sub_id = axutil_strdup(env, sub_id);
    sub_url = savan_client_get_sub_url_from_response(body_elem, reply, env);
    client->sub_url = axutil_strdup(env, sub_url);

    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[savan] Exit:savan_client_subscribe");
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
savan_client_renew(
    savan_client_t *client,
    const axutil_env_t *env,
    axis2_svc_client_t *svc_client,
    axutil_hash_t *options)
{
    axis2_options_t *wsa_options = NULL;
    const axis2_char_t *old_action = NULL;
    axiom_namespace_t *ns = NULL;
    axiom_node_t *reply = NULL;
    axiom_node_t *renew_node = NULL;
    axiom_node_t *expires_node = NULL;
    axiom_element_t *renew_elem = NULL;
    axiom_element_t *expires_elem = NULL;
    axis2_char_t *expires = NULL;
    axis2_char_t *renew_elem_localname = NULL;
    axutil_qname_t *qname = NULL;

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_client_renew");
    
    /* Set wsa action as Renew. remember the old action */
    wsa_options = (axis2_options_t*)axis2_svc_client_get_options(svc_client, env);
    old_action = axis2_options_get_action(wsa_options, env);
    axis2_options_set_action(wsa_options, env, SAVAN_ACTIONS_RENEW);
     
    /* Create the body of the Renew request */
    ns = axiom_namespace_create (env, EVENTING_NAMESPACE, EVENTING_NS_PREFIX);
    renew_elem = axiom_element_create(env, NULL, ELEM_NAME_RENEW, ns, &renew_node);
        
    /* Extract the values from the options map */
    expires = axutil_hash_get(options, SAVAN_OP_KEY_EXPIRES, AXIS2_HASH_KEY_STRING);
    if(expires)
    {
        /* Expires element */
        expires_elem = axiom_element_create(env, renew_node, ELEM_NAME_EXPIRES, ns,
            &expires_node);
        axiom_element_set_text(expires_elem, env, expires, expires_node);
    }

    savan_client_add_sub_id_to_soap_header(client, env, svc_client);

    /* send the Renew request and wait for the response */
    reply = axis2_svc_client_send_receive(svc_client, env, renew_node);
    
    /* reset the old action */
    axis2_options_set_action(wsa_options, env, old_action);
   
    if (!reply)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[savan] Failed to send renew request. Error: %d Reason: %s", 
                env->error->error_number, AXIS2_ERROR_GET_MESSAGE(env->error));
        return NULL;
    }
   
    renew_elem = (axiom_element_t*)axiom_node_get_data_element(reply, env);
    /* Check whether we have received a RenewResponse */
    renew_elem_localname = axiom_element_get_localname(renew_elem, env);

    if (axutil_strcmp(ELEM_NAME_RENEW_RESPONSE, renew_elem_localname))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Failed to retrieve RenewResponse"\
            "element. Error: %d Reason: %s", env->error->error_number,
            AXIS2_ERROR_GET_MESSAGE(env->error));
        return NULL;
    }

    /* Get Expires element from RenewResponse element */
    qname = axutil_qname_create(env, ELEM_NAME_EXPIRES, EVENTING_NAMESPACE, NULL);
    expires_elem = axiom_element_get_first_child_with_qname(renew_elem, env, qname, reply, 
            &expires_node);
    axutil_qname_free(qname, env);
    if(!expires_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Failed to retrieve Expires"\
            "element. Error: %d Reason: %s", env->error->error_number,
            AXIS2_ERROR_GET_MESSAGE(env->error));
        return NULL;
    }
   
    expires = axiom_element_get_text(expires_elem, env, expires_node);
    
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Exit:savan_client_renew");
    return expires;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_client_unsubscribe(
    savan_client_t *client,
    const axutil_env_t *env,
    axis2_svc_client_t *svc_client)
{
    axis2_options_t *wsa_options = NULL;
    const axis2_char_t *old_action = NULL;
    axiom_namespace_t *ns = NULL;
    axiom_node_t *reply = NULL;
    axiom_node_t *unsub_node = NULL;
    axiom_element_t *unsub_elem = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_client_unsubscribe");
    
    /* set wsa action as Unsub. remember the old action */
    wsa_options = (axis2_options_t*)axis2_svc_client_get_options(svc_client, env);
    old_action = axis2_options_get_action(wsa_options, env);
    axis2_options_set_action(wsa_options, env, SAVAN_ACTIONS_UNSUB);
    
    /* create the body of the Unsub request */
    ns = axiom_namespace_create (env, EVENTING_NAMESPACE, EVENTING_NS_PREFIX);
    unsub_elem = axiom_element_create(env, NULL, ELEM_NAME_UNSUB, ns, &unsub_node);
        
    savan_client_add_sub_id_to_soap_header(client, env, svc_client);

    /* send the Unsub request and wait for the response */
    reply = axis2_svc_client_send_receive(svc_client, env, unsub_node);
    
    /* reset the old action */
    axis2_options_set_action(wsa_options, env, old_action);
    
    if (!reply)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Failed to send unsubscribe "
            "request. Error: %d Reason: %s", env->error->error_number,
            AXIS2_ERROR_GET_MESSAGE(env->error));
        status = AXIS2_FAILURE;
    }
    else
        status = AXIS2_SUCCESS;
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[savan] Exit:savan_client_unsubscribe");
    return status;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
savan_client_get_status(
    savan_client_t *client,
    const axutil_env_t *env,
    axis2_svc_client_t *svc_client)
{
    axis2_options_t *wsa_options = NULL;
    const axis2_char_t *old_action = NULL;
    axutil_qname_t *qname = NULL;
    axiom_namespace_t *ns = NULL;
    axiom_node_t *reply = NULL;
    axiom_node_t *status_node = NULL;
    axiom_node_t *expires_node = NULL;
    axiom_element_t *status_elem = NULL;
    axiom_element_t *expires_elem = NULL;
    axis2_char_t *expires = NULL;
    axis2_char_t *status_elem_localname = NULL;

    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_client_get_status");
    
    /* Set wsa action as GetStatus. remember the old action */
    wsa_options = (axis2_options_t*)axis2_svc_client_get_options(svc_client, env);
    old_action = axis2_options_get_action(wsa_options, env);
    axis2_options_set_action(wsa_options, env, SAVAN_ACTIONS_GET_STATUS);
    
    /* Create the body of the GetStatus request */
    ns = axiom_namespace_create (env, EVENTING_NAMESPACE, EVENTING_NS_PREFIX);
    status_elem = axiom_element_create(env, NULL, ELEM_NAME_GETSTATUS, ns, &status_node);
    
    savan_client_add_sub_id_to_soap_header(client, env, svc_client);

    /* Send the GetStatus request and wait for the response */
    reply = axis2_svc_client_send_receive(svc_client, env, status_node);
    
    /* Reset the old action */
    axis2_options_set_action(wsa_options, env, old_action);
    
    if (!reply)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Failed to send get status "
            "request. Error: %d Reason: %s", env->error->error_number,
            AXIS2_ERROR_GET_MESSAGE(env->error));
        return NULL;
    }
    
    status_elem = (axiom_element_t*)axiom_node_get_data_element(reply, env);
    
    /* Check whether we have received a GetStatusResponse */
    status_elem_localname = axiom_element_get_localname(status_elem, env);

    if (axutil_strcmp(ELEM_NAME_GETSTATUS_RESPONSE, status_elem_localname))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Failed to retrieve GetStatusResponse"\
            "element. Error: %d Reason: %s", env->error->error_number,
            AXIS2_ERROR_GET_MESSAGE(env->error));
        return NULL;
    }
    
    /* Now read Expires sub element */
    qname = axutil_qname_create(env, ELEM_NAME_EXPIRES, EVENTING_NAMESPACE, NULL);
    expires_elem = axiom_element_get_first_child_with_qname(status_elem, env, qname, reply, 
            &expires_node);
    axutil_qname_free(qname, env);
    if(!expires_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Failed to retrieve Expires"\
            "element. Error: %d Reason: %s", env->error->error_number,
            AXIS2_ERROR_GET_MESSAGE(env->error));
        return NULL;
    }
   
    expires_elem = (axiom_element_t *) axiom_node_get_data_element(expires_node, env);

    expires = axiom_element_get_text(expires_elem, env, expires_node);
    
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[savan] Exit:savan_client_get_status");
    return expires;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
savan_client_get_sub_id(
    savan_client_t *client)
{
    return client->sub_id;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
savan_client_get_sub_url(
    savan_client_t *client)
{
    return client->sub_url;
}

axis2_status_t AXIS2_CALL
savan_client_add_sub_id_to_soap_header(
    savan_client_t *client,
    const axutil_env_t *env,
    axis2_svc_client_t *svc_client)
{
    axiom_namespace_t *ns = NULL;
    axiom_node_t *id_node = NULL;
    axiom_element_t *id_elem = NULL;

    /* Create a node with the subscription id and attach it as a soap header
     * to the service client */

    ns = axiom_namespace_create(env, EVENTING_NAMESPACE, EVENTING_NS_PREFIX);
    id_elem = axiom_element_create(env, NULL, ELEM_NAME_ID, ns, &id_node);
    if (!id_elem)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] [client] Failed to "
            "create element for Identifier node");
        return AXIS2_FAILURE;
    }

    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "client->sub_id:%s\n", client->sub_id);
    axiom_element_set_text(id_elem, env, client->sub_id, id_node);

    axis2_svc_client_add_header(svc_client, env, id_node);

    return AXIS2_SUCCESS;

}

axis2_char_t * AXIS2_CALL
savan_client_get_sub_id_from_response(
    axiom_element_t *response_elem, 
    axiom_node_t *response_node,
    const axutil_env_t *env)
{
    axutil_qname_t *qname = NULL;
    axiom_element_t *submgr_elem = NULL;
    axiom_element_t *refparam_elem = NULL;
    axiom_element_t *id_elem = NULL;
    axiom_node_t *submgr_node = NULL;
    axiom_node_t *refparam_node = NULL;
    axiom_node_t *id_node = NULL;
    axis2_char_t *sub_id = NULL;

    /* Format:
     *  <SubscribeResponse>
     *    <SubscriptionManager>
     *      <ReferenceParameters>
     *        <Identifier>
     */

    /* Get Sub Mgr sub element */
    qname = axutil_qname_create(env, ELEM_NAME_SUB_MGR, EVENTING_NAMESPACE, NULL);
    submgr_elem = axiom_element_get_first_child_with_qname(response_elem, env, qname,
        response_node, &submgr_node);
    axutil_qname_free(qname, env);
    
    /* Get Ref Param sub element */
    qname = axutil_qname_create(env, ELEM_NAME_REF_PARAM,
        AXIS2_WSA_NAMESPACE_SUBMISSION, NULL);
    refparam_elem = axiom_element_get_first_child_with_qname(submgr_elem, env, qname,
        submgr_node, &refparam_node);
    axutil_qname_free(qname, env);

    /* Get Identifier sub element */
    qname = axutil_qname_create(env, ELEM_NAME_ID, EVENTING_NAMESPACE, NULL);
    id_elem = axiom_element_get_first_child_with_qname(refparam_elem, env, qname,
        refparam_node, &id_node);
    axutil_qname_free(qname, env);

    sub_id = axiom_element_get_text(id_elem, env, id_node);

    return sub_id;
}

axis2_char_t * AXIS2_CALL
savan_client_get_sub_url_from_response(
    axiom_element_t *response_elem, 
    axiom_node_t *response_node,
    const axutil_env_t *env)
{
    axutil_qname_t *qname = NULL;
    axiom_element_t *submgr_elem = NULL;
    axiom_element_t *address_elem = NULL;
    axiom_node_t *submgr_node = NULL;
    axiom_node_t *address_node = NULL;
    axis2_char_t *address = NULL;

    /* Format:
     *  <SubscribeResponse>
     *    <SubscriptionManager>
     *      <Address>
     */
    /* Get Sub Mgr sub element */
    qname = axutil_qname_create(env, ELEM_NAME_SUB_MGR, EVENTING_NAMESPACE, NULL);
    submgr_elem = axiom_element_get_first_child_with_qname(response_elem, env, qname,
        response_node, &submgr_node);
    axutil_qname_free(qname, env);
    
    /* Get Address sub element */
    qname = axutil_qname_create(env, ELEM_NAME_ADDR,
        AXIS2_WSA_NAMESPACE_SUBMISSION, NULL);
    address_elem = axiom_element_get_first_child_with_qname(submgr_elem, env, qname,
        submgr_node, &address_node);
    axutil_qname_free(qname, env);

    address = axiom_element_get_text(address_elem, env, address_node);

    return address;
}

