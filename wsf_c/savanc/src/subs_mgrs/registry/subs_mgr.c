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
#include <remote_registry.h>
#include <remote_registry_resource.h>

#define SYNAPSE_NAMESPACE "http://ws.apache.org/ns/synapse"
#define SYNAPSE_NS_PREFIX "syn"
#define ELEM_NAME_SUBSCRIPTION "subscription"
#define ELEM_NAME_ENDPOINT "endpoint"
#define ELEM_NAME_ADDRESS "address"
#define ATTR_NAME_URL "uri"
#define EPR_TYPE "application/vnd.epr"
#define TOPIC_INDEX_PARENT_PATH "/eventing/index"
#define SUBSCRIPTION_COLLECTION_NAME "system.subscriptions"
#define TOPIC_INDEX "/eventing/index/TopicIndex"

/**
 * Savan registry based subscription manager dependes on the WSO2 registry for subscription storation.
 * This use WSF/C registry cache client to communicate with the WSO2 registry. Registry cache
 * client reduce the overhead of each time fetching records from the registry which is very 
 * expensive by caching the records locally.
 */
/** 
 * @brief Savan Registry Storage Manager Struct Impl
 *   Savan Registry Storage Manager 
 */
typedef struct savan_registry_subs_mgr
{
    savan_subs_mgr_t subsmgr;
    axis2_char_t *reg_url;
    axis2_char_t *username;
    axis2_char_t *password;
    axis2_conf_t *conf;
    remote_registry_t *remote_registry;
} savan_registry_subs_mgr_t;

typedef AXIS2_DECLARE_DATA struct savan_registry_subs_mgr_args
{
    const axutil_env_t *env;
    void *data;
} savan_registry_subs_mgr_args_t;

#define SAVAN_INTF_TO_IMPL(subsmgr) ((savan_registry_subs_mgr_t *) subsmgr)

static savan_subscriber_t *savan_registry_subs_mgr_extract_subscriber(
        const axutil_env_t *env,
        remote_registry_resource_t *resource);

static axis2_char_t *savan_registry_subs_mgr_serialize_endpoint(
        const axutil_env_t *env,
        const savan_subscriber_t *subscriber);

static axis2_status_t
savan_registry_subs_mgr_init_resource(
    savan_subs_mgr_t *subsmgr,
    const axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL
savan_registry_subs_mgr_free(
    savan_subs_mgr_t *subsmgr,
    const axutil_env_t *env);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_registry_subs_mgr_insert_subscriber(
    savan_subs_mgr_t *subsmgr,
    const axutil_env_t *env,
    savan_subscriber_t *subscriber);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_registry_subs_mgr_update_subscriber(
    savan_subs_mgr_t *subsmgr,
    const axutil_env_t *env,
    savan_subscriber_t *subscriber);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_registry_subs_mgr_remove_subscriber(
    savan_subs_mgr_t *subsmgr,
    const axutil_env_t *env,
    const axis2_char_t *subscriber_id);

AXIS2_EXTERN savan_subscriber_t *AXIS2_CALL
savan_registry_subs_mgr_retrieve_subscriber(
    savan_subs_mgr_t *subsmgr,
    const axutil_env_t *env,
    const axis2_char_t *subscriber_id);

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL
savan_registry_subs_mgr_retrieve_all_subscribers(
    savan_subs_mgr_t *subsmgr,
    const axutil_env_t *env,
    const axis2_char_t *filter);

static const savan_subs_mgr_ops_t subs_mgr_ops = 
{
    savan_registry_subs_mgr_free,
    savan_registry_subs_mgr_insert_subscriber,
    savan_registry_subs_mgr_update_subscriber,
    savan_registry_subs_mgr_remove_subscriber,
    savan_registry_subs_mgr_retrieve_subscriber,
    savan_registry_subs_mgr_retrieve_all_subscribers,
    NULL
};

AXIS2_EXTERN savan_subs_mgr_t * AXIS2_CALL
savan_subs_mgr_create(
    const axutil_env_t *env,
    axis2_conf_t *conf)
{
    savan_registry_subs_mgr_t *subsmgrimpl = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    
    subsmgrimpl = AXIS2_MALLOC(env->allocator, sizeof(savan_registry_subs_mgr_t));
    if (!subsmgrimpl)
    {
        AXIS2_HANDLE_ERROR(env, SAVAN_ERROR_STORAGE_MANAGER_CREATION_FAILED, AXIS2_FAILURE);
        return NULL;
    }

    memset ((void *) subsmgrimpl, 0, sizeof(savan_registry_subs_mgr_t));

    subsmgrimpl->remote_registry = NULL;
    subsmgrimpl->reg_url = savan_util_get_resource_connection_string(env, conf);
    subsmgrimpl->username = axutil_strdup(env, savan_util_get_resource_username(env, conf));
    subsmgrimpl->password = axutil_strdup(env, savan_util_get_resource_password(env, conf));
    subsmgrimpl->conf = conf;
    subsmgrimpl->subsmgr.ops = &subs_mgr_ops;

    status = savan_registry_subs_mgr_init_resource((savan_subs_mgr_t *) subsmgrimpl, env);
    if(status != AXIS2_SUCCESS)
    {
        savan_registry_subs_mgr_free((savan_subs_mgr_t *) subsmgrimpl, env);
        return NULL;
    }
    return (savan_subs_mgr_t *) subsmgrimpl;
}

AXIS2_EXTERN savan_subs_mgr_t * AXIS2_CALL
savan_subs_mgr_create_with_connection_info(
    const axutil_env_t *env,
    axis2_char_t *connection_string,
    axis2_char_t *username,
    axis2_char_t *password)
{
    savan_registry_subs_mgr_t *subsmgrimpl = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    
    subsmgrimpl = AXIS2_MALLOC(env->allocator, sizeof(savan_registry_subs_mgr_t));
    if (!subsmgrimpl)
    {
        AXIS2_HANDLE_ERROR(env, SAVAN_ERROR_STORAGE_MANAGER_CREATION_FAILED, AXIS2_FAILURE);
        return NULL;
    }

    memset ((void *) subsmgrimpl, 0, sizeof(savan_registry_subs_mgr_t));

    subsmgrimpl->remote_registry = NULL;
    subsmgrimpl->reg_url = axutil_strdup(env, connection_string);
    subsmgrimpl->username = axutil_strdup(env, username);
    subsmgrimpl->password = axutil_strdup(env, password);
    subsmgrimpl->conf = NULL;
    subsmgrimpl->subsmgr.ops = &subs_mgr_ops;

    status = savan_registry_subs_mgr_init_resource((savan_subs_mgr_t *) subsmgrimpl, env);
    if(status != AXIS2_SUCCESS)
    {
        savan_registry_subs_mgr_free((savan_subs_mgr_t *) subsmgrimpl, env);
        return NULL;
    }
    return (savan_subs_mgr_t *) subsmgrimpl;
}

AXIS2_EXTERN void AXIS2_CALL
savan_registry_subs_mgr_free(
    savan_subs_mgr_t *subsmgr,
    const axutil_env_t *env)
{
    savan_registry_subs_mgr_t *subsmgrimpl = NULL;
    subsmgrimpl = SAVAN_INTF_TO_IMPL(subsmgr);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_registry_subs_mgr_free");

    if(subsmgrimpl->reg_url)
    {
        AXIS2_FREE(env->allocator, subsmgrimpl->reg_url);
        subsmgrimpl->reg_url = NULL;
    }
    
    if(subsmgrimpl->username)
    {
        AXIS2_FREE(env->allocator, subsmgrimpl->username);
        subsmgrimpl->username = NULL;
    }
    
    if(subsmgrimpl->password)
    {
        AXIS2_FREE(env->allocator, subsmgrimpl->password);
        subsmgrimpl->password = NULL;
    }

    subsmgrimpl->conf = NULL;

    if(subsmgrimpl)
    {
        AXIS2_FREE(env->allocator, subsmgrimpl);
        subsmgrimpl = NULL;
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Exit:savan_registry_subs_mgr_free");
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_registry_subs_mgr_insert_subscriber(
    savan_subs_mgr_t *subsmgr,
    const axutil_env_t *env,
    savan_subscriber_t *subscriber)
{
    axis2_char_t *subscription_id = NULL;
    axis2_char_t *expires = NULL;
    axis2_char_t *filter = NULL;
    axis2_char_t *id = NULL;
    axis2_char_t *path = NULL; 
    remote_registry_resource_t *res = NULL;
    axutil_hash_t *properties = NULL;
    char *content = NULL;
    
    savan_registry_subs_mgr_t *subsmgrimpl = NULL;
    subsmgrimpl = SAVAN_INTF_TO_IMPL(subsmgr);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Entry:savan_registry_subs_mgr_insert_subscriber");
	
    subscription_id = savan_subscriber_get_id(subscriber, env);
    filter = savan_subscriber_get_filter(subscriber, env);
    path = axutil_strcat(env, AXIS2_PATH_SEP_STR, filter, AXIS2_PATH_SEP_STR, 
            SUBSCRIPTION_COLLECTION_NAME, AXIS2_PATH_SEP_STR, subscription_id, NULL);
    id = axutil_strcat(env, subsmgrimpl->reg_url, AXIS2_PATH_SEP_STR, filter, 
            AXIS2_PATH_SEP_STR, SUBSCRIPTION_COLLECTION_NAME, AXIS2_PATH_SEP_STR, subscription_id, 
            NULL);

    res = remote_registry_resource_create(env);
    content = savan_registry_subs_mgr_serialize_endpoint(env, subscriber);
    remote_registry_resource_set_content(res, env, content);
    remote_registry_resource_set_content_len(res, env, axutil_strlen(content));
    remote_registry_resource_set_media_type(res, env, EPR_TYPE);
    remote_registry_resource_set_description(res, env, "");

    properties = axutil_hash_make(env);
    if(properties)
    {
        axis2_char_t *endto = NULL;
        axis2_endpoint_ref_t *endto_epr = NULL;
        axis2_char_t *filter_dialect = NULL;


        expires = savan_subscriber_get_expires(subscriber, env);
        if(expires)
        {
            axutil_hash_set(properties, axutil_strdup(env, "expires"), AXIS2_HASH_KEY_STRING, 
                    axutil_strdup(env, expires));
        }
        else
        {
            axutil_hash_set(properties, axutil_strdup(env, "expires"), AXIS2_HASH_KEY_STRING, 
                    axutil_strdup(env, "*"));
        }

        axutil_hash_set(properties, axutil_strdup(env, "staticFlag"), AXIS2_HASH_KEY_STRING, 
                axutil_strdup(env, "false"));
        axutil_hash_set(properties, axutil_strdup(env, "filterValue"), AXIS2_HASH_KEY_STRING, 
                axutil_strdup(env, filter));

        endto_epr = savan_subscriber_get_end_to(subscriber, env);
        if(endto_epr)
        {
            endto = (axis2_char_t *) axis2_endpoint_ref_get_address(endto_epr, env);
        }
        if(endto)
        {
            axutil_hash_set(properties, axutil_strdup(env, "subManagerURI"), AXIS2_HASH_KEY_STRING, 
                axutil_strdup(env, endto));
        }

        filter_dialect = savan_subscriber_get_filter_dialect(subscriber, env);
        if(filter_dialect)
        {
            axutil_hash_set(properties, axutil_strdup(env, "filterDialect"), AXIS2_HASH_KEY_STRING, 
                    axutil_strdup(env, filter_dialect));
        }

        remote_registry_resource_set_properties(res, env, properties);
    }

    remote_registry_put(subsmgrimpl->remote_registry, env, path, res);
    if(id)
    {
        AXIS2_FREE(env->allocator, id);
    }
    if(path)
    {
        AXIS2_FREE(env->allocator, path);
        path = NULL;
    }
    if(res)
    {
        remote_registry_resource_free(res, env);
        res = NULL;
    }

    res = remote_registry_get(subsmgrimpl->remote_registry, env, TOPIC_INDEX, NULL);
    if(!res)
    {
        AXIS2_HANDLE_ERROR(env, SAVAN_ERROR_SUBSCRIBER_INSERT_ERROR, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Could not retrive resource TopicIndex");
        return AXIS2_FAILURE;
    }
    id = axutil_strcat(env, subsmgrimpl->reg_url, TOPIC_INDEX, NULL);
    properties = remote_registry_resource_get_properties(res, env);
    if(properties)
    {
        path = axutil_strcat(env, AXIS2_PATH_SEP_STR, filter, AXIS2_PATH_SEP_STR, 
                SUBSCRIPTION_COLLECTION_NAME, NULL);
        axutil_hash_set(properties, subscription_id, AXIS2_HASH_KEY_STRING, path);
        remote_registry_resource_set_properties(res, env, properties);
    }

    remote_registry_resource_set_content(res, env, NULL);
    remote_registry_resource_set_content_len(res, env, 0);
    remote_registry_put(subsmgrimpl->remote_registry, env, TOPIC_INDEX, res);

    if(id)
    {
        AXIS2_FREE(env->allocator, id);
    }
    if(res)
    {
        remote_registry_resource_free(res, env);
        res = NULL;
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Exit:savan_registry_subs_mgr_insert_subscriber");
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_registry_subs_mgr_update_subscriber(
    savan_subs_mgr_t *subsmgr,
    const axutil_env_t *env,
    savan_subscriber_t *subscriber)
{
    axis2_char_t *expires = NULL;
    axis2_char_t *filter = NULL;
    axis2_char_t *subscriber_id = NULL;
    axis2_char_t *path = NULL; 
    remote_registry_resource_t *res = NULL;
    remote_registry_resource_t *index_res = NULL;
    axutil_hash_t *properties = NULL;
    axis2_char_t *val = NULL;
 
    savan_registry_subs_mgr_t *subsmgrimpl = NULL;
    subsmgrimpl = SAVAN_INTF_TO_IMPL(subsmgr);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Entry:savan_registry_subs_mgr_update_subscriber");

    index_res = remote_registry_get(subsmgrimpl->remote_registry, env, TOPIC_INDEX, NULL);
    if(!index_res)
    {
        AXIS2_HANDLE_ERROR(env, SAVAN_ERROR_SUBSCRIBER_INSERT_ERROR, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Could not retrive resource TopicIndex");
        return AXIS2_FAILURE;
    }

    subscriber_id = savan_subscriber_get_id(subscriber, env);
    filter = savan_subscriber_get_filter(subscriber, env);
    val = remote_registry_resource_get_property(index_res, env, subscriber_id);
    if(val)
    {
        path = axutil_strcat(env, val, AXIS2_PATH_SEP_STR, subscriber_id, NULL);
    }

    res = remote_registry_get(subsmgrimpl->remote_registry, env, path, NULL);
    if(!res)
    {
        AXIS2_HANDLE_ERROR(env, SAVAN_ERROR_SUBSCRIBER_UPDATE_ERROR, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[savan] Could not retrive resource subscriber path:%s in registry", path);
        return AXIS2_FAILURE;
    }

    remote_registry_resource_set_description(res, env, "");
    properties = remote_registry_resource_get_properties(res, env);
    if(properties)
    {
        axis2_char_t *endto = NULL;
        axis2_endpoint_ref_t *endto_epr = NULL;
        axis2_char_t *filter_dialect = NULL;

        expires = savan_subscriber_get_expires(subscriber, env);
        if(expires)
        {
            axutil_hash_set(properties, axutil_strdup(env, "expires"), AXIS2_HASH_KEY_STRING, 
                    axutil_strdup(env, expires));
        }

        axutil_hash_set(properties, axutil_strdup(env, "staticFlag"), AXIS2_HASH_KEY_STRING, 
                axutil_strdup(env, "false"));
        axutil_hash_set(properties, axutil_strdup(env, "filterValue"), AXIS2_HASH_KEY_STRING, 
                axutil_strdup(env, filter));

        endto_epr = savan_subscriber_get_end_to(subscriber, env);
        if(endto_epr)
        {
            endto = (axis2_char_t *) axis2_endpoint_ref_get_address(endto_epr, env);
        }
        if(endto)
        {
            axutil_hash_set(properties, axutil_strdup(env, "subManagerURI"), AXIS2_HASH_KEY_STRING, 
                axutil_strdup(env, endto));
        }

        filter_dialect = savan_subscriber_get_filter_dialect(subscriber, env);
        if(filter_dialect)
        {
            axutil_hash_set(properties, axutil_strdup(env, "filterDialect"), AXIS2_HASH_KEY_STRING, 
                    axutil_strdup(env, filter_dialect));
        }

        remote_registry_resource_set_properties(res, env, properties);
    }

    remote_registry_put(subsmgrimpl->remote_registry, env, path, res);
    
    if(path)
    {
        AXIS2_FREE(env->allocator, path);
        path = NULL;
    }
    if(res)
    {
        remote_registry_resource_free(res, env);
        res = NULL;
    }

    savan_subscriber_set_renew_status(subscriber, env, AXIS2_TRUE);
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Exit:savan_registry_subs_mgr_update_subscriber");
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_registry_subs_mgr_remove_subscriber(
    savan_subs_mgr_t *subsmgr,
    const axutil_env_t *env,
    const axis2_char_t *subscriber_id)
{
    remote_registry_resource_t *res = NULL;
    axis2_char_t *val;
    axis2_status_t status = AXIS2_FAILURE;
    axis2_char_t *path = NULL;

    savan_registry_subs_mgr_t *subsmgrimpl = NULL;
    subsmgrimpl = SAVAN_INTF_TO_IMPL(subsmgr);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Entry:savan_registry_subs_mgr_remove_subscriber");

    res = remote_registry_get(subsmgrimpl->remote_registry, env, TOPIC_INDEX, NULL);
    if(!res)
    {
        AXIS2_HANDLE_ERROR(env, SAVAN_ERROR_SUBSCRIBER_UPDATE_ERROR, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[savan] Could not retrive resource TopicIndex");
        return AXIS2_FAILURE;
    }

    val = remote_registry_resource_get_property(res, env, subscriber_id);
    if(val)
    {
        path = axutil_strcat(env, val, AXIS2_PATH_SEP_STR, subscriber_id, NULL);
        status = remote_registry_delete(subsmgrimpl->remote_registry, env, path);
    }
    
    remote_registry_resource_free(res, env);
    if(AXIS2_SUCCESS != status)
    {
        AXIS2_HANDLE_ERROR(env, SAVAN_ERROR_SUBSCRIBER_REMOVE_ERROR, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[savan] Could not remove subscriber for id %s", subscriber_id);
        return AXIS2_FAILURE;
    }

    res = remote_registry_get(subsmgrimpl->remote_registry, env, TOPIC_INDEX, NULL);
    if(!res)
    {
        AXIS2_HANDLE_ERROR(env, SAVAN_ERROR_SUBSCRIBER_UPDATE_ERROR, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[savan] Could not retrive resource TopicIndex");
        return AXIS2_FAILURE;
    }

    remote_registry_resource_remove_property(res, env, subscriber_id);
    remote_registry_put(subsmgrimpl->remote_registry, env, TOPIC_INDEX, res);
    remote_registry_resource_free(res, env);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Exit:savan_registry_subs_mgr_remove_subscriber");
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN savan_subscriber_t *AXIS2_CALL
savan_registry_subs_mgr_retrieve_subscriber(
    savan_subs_mgr_t *subsmgr,
    const axutil_env_t *env,
    const axis2_char_t *subscriber_id)
{
    remote_registry_resource_t *res = NULL;
    remote_registry_resource_t *root_res = NULL;
    axis2_char_t *val;
    axis2_char_t *path = NULL;
    savan_subscriber_t *subscriber = NULL;

    savan_registry_subs_mgr_t *subsmgrimpl = NULL;
    subsmgrimpl = SAVAN_INTF_TO_IMPL(subsmgr);


    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Entry:savan_registry_subs_mgr_retrieve_subscriber");

    root_res = remote_registry_get(subsmgrimpl->remote_registry, env, TOPIC_INDEX, NULL);
    if(!root_res)
    {
        AXIS2_HANDLE_ERROR(env, SAVAN_ERROR_SUBSCRIBER_UPDATE_ERROR, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[savan] Could not retrive resource TopicIndex");
        return AXIS2_FAILURE;
    }

    val = remote_registry_resource_get_property(root_res, env, subscriber_id);
    if(val)
    {
        path = axutil_strcat(env, val, AXIS2_PATH_SEP_STR, subscriber_id, NULL);
        res = remote_registry_get(subsmgrimpl->remote_registry, env, path, NULL);
    }

    if(res)
    {
        subscriber = savan_registry_subs_mgr_extract_subscriber(env, res);
        if(subscriber)
        {
            savan_subscriber_set_id(subscriber, env, subscriber_id);
        }
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Exit:savan_registry_subs_mgr_retrieve_subscriber");
    return subscriber;
}

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL
savan_registry_subs_mgr_retrieve_all_subscribers(
    savan_subs_mgr_t *subsmgr,
    const axutil_env_t *env,
    const axis2_char_t *filter)
{
    remote_registry_resource_t *root_res = NULL;
    axis2_char_t *path = NULL;
    axutil_array_list_t *data_list = NULL;

    savan_registry_subs_mgr_t *subsmgrimpl = NULL;
    subsmgrimpl = SAVAN_INTF_TO_IMPL(subsmgr);
 
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Entry:savan_registry_subs_mgr_retrieve_all_subscribers");

    /* Get subscribers for the filter from registry. Eg. /weather/4/system.subscriptions */
    if(filter)
    {
        root_res = remote_registry_get(subsmgrimpl->remote_registry, env, 
                (axis2_char_t *) filter, NULL);
        if(root_res)
        {
            axutil_array_list_t *child_entries = NULL;
            int i = 0;

            child_entries = remote_registry_resource_get_entries(root_res, env);
            if(child_entries)
            {
                data_list = axutil_array_list_create(env, 0);

                /* load the child entries recursively */
                for(i = 0; i < axutil_array_list_size(child_entries, env); i ++)
                {
                    remote_registry_resource_t *res = NULL;

                    res = (remote_registry_resource_t*)axutil_array_list_get(child_entries, env, i);
                    if(res)
                    {
                        savan_subscriber_t *subscriber = NULL;

                        subscriber = savan_registry_subs_mgr_extract_subscriber(env, res);
                        axutil_array_list_add(data_list, env, subscriber);
                    }
                }
            }
        }
    }
    else /* Get subscribers for the topic root from registry(/eventing/index/TopicIndex);*/
    {
        axutil_hash_t *properties = NULL;

        root_res = remote_registry_get(subsmgrimpl->remote_registry, env, TOPIC_INDEX, NULL);
        if(!root_res)
        {
            AXIS2_HANDLE_ERROR(env, SAVAN_ERROR_SUBSCRIBER_UPDATE_ERROR, AXIS2_FAILURE);
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                    "[savan] Could not retrive resource TopicIndex");
            return AXIS2_FAILURE;
        }
        properties = remote_registry_resource_get_properties(root_res, env);
        if(properties)
        {
            savan_subscriber_t *subscriber = NULL;
            axutil_hash_index_t *hi;
            void *val;
            void *key;

            data_list = axutil_array_list_create(env, 0);

            for (hi = axutil_hash_first(properties, env); hi; hi = axutil_hash_next(env, hi)) 
            {
                remote_registry_resource_t *res = NULL;
                axis2_char_t *subscriber_id = NULL;

                axutil_hash_this(hi, (const void**)&key, NULL, &val);
                subscriber_id = (axis2_char_t *) key;
                path = axutil_strcat(env, val, AXIS2_PATH_SEP_STR, key, NULL);
                res = remote_registry_get(subsmgrimpl->remote_registry, env, path, NULL);
                if(res)
                {
                    if(res)
                    {
                        subscriber = savan_registry_subs_mgr_extract_subscriber(env, res);
                        savan_subscriber_set_id(subscriber, env, subscriber_id);
                        axutil_array_list_add(data_list, env, subscriber);
                    }
                }
            }
        }
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Exit:savan_registry_subs_mgr_retrieve_all_subscribers");
    return data_list;
}

static axis2_status_t
savan_registry_subs_mgr_init_resource(
    savan_subs_mgr_t *subsmgr,
    const axutil_env_t *env)
{
    remote_registry_resource_t *res = NULL;
    axis2_char_t *id = NULL;
    
    savan_registry_subs_mgr_t *subsmgrimpl = NULL;
    subsmgrimpl = SAVAN_INTF_TO_IMPL(subsmgr);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_registry_subs_mgr_init_resource");

    subsmgrimpl->remote_registry = remote_registry_create(env, subsmgrimpl->reg_url, 
            subsmgrimpl->username, subsmgrimpl->password);
    if(!subsmgrimpl->remote_registry)
    {
        AXIS2_HANDLE_ERROR(env, SAVAN_ERROR_DATABASE_CREATION_ERROR, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[savan] Creating remote registry instance failed");
        return AXIS2_FAILURE;
    }

    res = remote_registry_get(subsmgrimpl->remote_registry, env, TOPIC_INDEX, NULL);
    if(!res)
    {
        res = remote_registry_resource_create(env);
        id = axutil_strcat(env, subsmgrimpl->reg_url, TOPIC_INDEX, NULL);
        remote_registry_resource_set_properties(res, env, axutil_hash_make(env));
        remote_registry_resource_set_description(res, env, "");
        remote_registry_put(subsmgrimpl->remote_registry, env, TOPIC_INDEX, res);
    }

    if(id)
    {
        AXIS2_FREE(env->allocator, id);
    }
    if(res)
    {
        remote_registry_resource_free(res, env);
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Exit:savan_registry_subs_mgr_init_resource");

    return AXIS2_SUCCESS;
}

static axis2_char_t *savan_registry_subs_mgr_serialize_endpoint(
        const axutil_env_t *env,
        const savan_subscriber_t *subscriber)
{
    axiom_namespace_t *ns = NULL;
    axiom_node_t *subs_node = NULL;
    axiom_element_t *subs_elem = NULL;
    axiom_node_t *endpoint_node = NULL;
    axiom_element_t *endpoint_elem = NULL;
    axiom_node_t *addr_node = NULL;
    axiom_element_t *addr_elem = NULL;
    axiom_attribute_t *url_attr = NULL;
    axis2_char_t *notifyto = NULL;
    char *content = NULL;
    
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Entry:savan_registry_subs_mgr_serialize_endpoint");
    
    /* Format of the message is as 
     * <subscription><syn:endpoint xmlns:syn="http://ws.apache.org/ns/synapse"><syn:address uri=
     * "http://localhost:9000/services/SimpleStockQuoteService" /></syn:endpoint></subscription>
     */
    ns = axiom_namespace_create (env, SYNAPSE_NAMESPACE, SYNAPSE_NS_PREFIX);
    if(subscriber)
    {
        axis2_endpoint_ref_t *notifyto_epr = NULL;

        notifyto_epr = savan_subscriber_get_notify_to((savan_subscriber_t *) subscriber, env);
        if(notifyto_epr)
        {
            notifyto = (axis2_char_t *) axis2_endpoint_ref_get_address(notifyto_epr, env);
        }
    }

    subs_elem = axiom_element_create(env, NULL, ELEM_NAME_SUBSCRIPTION, NULL, &subs_node);
    endpoint_elem = axiom_element_create(env, subs_node, ELEM_NAME_ENDPOINT, ns, &endpoint_node);
    addr_elem = axiom_element_create(env, endpoint_node, ELEM_NAME_ADDRESS, ns, &addr_node);
    url_attr = axiom_attribute_create(env, ATTR_NAME_URL, notifyto, NULL);
    axiom_element_add_attribute(addr_elem, env, url_attr, addr_node);

    content = (char *) axiom_node_to_string(subs_node, env);
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Exit:savan_registry_subs_mgr_serialize_endpoint");

    return content; 
}

static savan_subscriber_t *savan_registry_subs_mgr_extract_subscriber(
        const axutil_env_t *env,
        remote_registry_resource_t *resource)
{
    savan_subscriber_t *subscriber = NULL;
    axis2_char_t *content = NULL;
    axutil_qname_t *qname = NULL;
    axiom_node_t *subs_node = NULL;
    axiom_element_t *subs_element = NULL;
    axiom_node_t *endpoint_node = NULL;
    axiom_element_t *endpoint_element = NULL;
    axiom_node_t *address_node = NULL;
    axiom_element_t *address_element = NULL;
    axis2_char_t *address = NULL;
    axutil_hash_t *properties = NULL;
    axis2_char_t *static_flag = NULL;
    axis2_char_t *subs_mgr_uri = NULL;
    axis2_char_t *filter = NULL;
    axis2_char_t *filter_dialect = NULL;
    axis2_char_t *expires = NULL;
    axis2_endpoint_ref_t *notifyto_epr = NULL;

    content = remote_registry_resource_get_content(resource, env);
    subs_node = axiom_node_create_from_buffer(env, content);
    subs_element = axiom_node_get_data_element(subs_node, env);
    if(!subs_element)
    {
        AXIS2_HANDLE_ERROR(env, AXIS2_ERROR_OM_ELEMENT_EXPECTED, AXIS2_FAILURE);
        return NULL;
    }

    qname = axutil_qname_create(env, ELEM_NAME_ENDPOINT, SYNAPSE_NAMESPACE, NULL);
    if(!qname)
    {
        AXIS2_HANDLE_ERROR(env, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
    }

    endpoint_element = axiom_element_get_first_child_with_qname(subs_element, env, qname, 
            subs_node, &endpoint_node);

    if(qname)
    {
        axutil_qname_free(qname, env);
    }

    qname = axutil_qname_create(env, ELEM_NAME_ADDRESS, SYNAPSE_NAMESPACE, NULL);
    if(!qname)
    {
        AXIS2_HANDLE_ERROR(env, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
    }

    address_element = axiom_element_get_first_child_with_qname(endpoint_element, env, qname, 
            endpoint_node, &address_node);

    if(qname)
    {
        axutil_qname_free(qname, env);
    }

    address = axiom_element_get_attribute_value_by_name(address_element, env, ATTR_NAME_URL);
    
    if(!address)
    {
        AXIS2_HANDLE_ERROR(env, AXIS2_ERROR_OM_ELEMENT_INVALID_STATE, AXIS2_FAILURE);
        return NULL; 
    }

    notifyto_epr = axis2_endpoint_ref_create(env, address);
    if(!notifyto_epr)
    {
        AXIS2_HANDLE_ERROR(env, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
    }

    subscriber = savan_subscriber_create(env);
    if(!subscriber)
    {
        return NULL;
    }

    savan_subscriber_set_notify_to(subscriber, env, notifyto_epr);

    properties = remote_registry_resource_get_properties(resource, env);
    if(!properties)
    {
        savan_subscriber_free(subscriber, env);
        AXIS2_HANDLE_ERROR(env, SAVAN_ERROR_PARSING_SUBSCRIBER_NODE_FAILED, AXIS2_FAILURE);
        return NULL;
    }
    
    expires = remote_registry_resource_get_property(resource, env, "expires");
    if(expires)
    {
        savan_subscriber_set_expires(subscriber, env, expires);
    }

    static_flag = remote_registry_resource_get_property(resource, env, "staticFlag");
    filter = remote_registry_resource_get_property(resource, env, "filterValue");
    if(filter)
    {
        savan_subscriber_set_filter(subscriber, env, filter);
    }

    filter_dialect = remote_registry_resource_get_property(resource, env, "filterDialect");
    if(filter_dialect)
    {
        savan_subscriber_set_filter_dialect(subscriber, env, filter_dialect);
    }

    subs_mgr_uri = remote_registry_resource_get_property(resource, env, "subManagerURI");

    return subscriber;
}

