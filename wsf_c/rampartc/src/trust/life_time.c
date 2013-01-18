/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <trust_life_time.h>

struct trust_life_time
{
    int ttl;
    axutil_date_time_t *created;
    axutil_date_time_t *expires;
    axis2_char_t *wst_ns_uri;
    axis2_char_t *wsu_ns_uri;
};

AXIS2_EXTERN trust_life_time_t * AXIS2_CALL
trust_life_time_create(
        const axutil_env_t *env)
{
    trust_life_time_t *life_time = NULL;
    
    life_time = (trust_life_time_t*)AXIS2_MALLOC(env->allocator, sizeof(trust_life_time_t));
    
    life_time->ttl = -1;
    life_time->created = NULL;
    life_time->expires = NULL;
    life_time->wst_ns_uri = NULL;
    life_time->wsu_ns_uri = NULL;
    
    return life_time;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_life_time_free(
        trust_life_time_t *life_time,
        const axutil_env_t *env)
{
    return AXIS2_SUCCESS;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_life_time_deserialize(
        trust_life_time_t *life_time,
        const axutil_env_t *env,
        axiom_node_t *life_time_node)
{
    axiom_element_t *life_time_ele = NULL;
    axutil_qname_t *created_qname = NULL;
    axutil_qname_t *expires_qname = NULL;
    axiom_element_t *created_ele = NULL;
    axiom_element_t *expires_ele = NULL;
    axiom_node_t *created_node = NULL;
    axiom_node_t *expires_node = NULL;
    axis2_char_t *created_str = NULL;
    axis2_char_t *expires_str = NULL;
    axutil_date_time_t *created = NULL;
    axutil_date_time_t *expires = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    
    life_time_ele = axiom_node_get_data_element(life_time_node, env);
    
    if(life_time_ele)
    {
        created_qname = axutil_qname_create(env, TRUST_LIFE_TIME_CREATED, TRUST_WSU_XMLNS, TRUST_WSU);
        if(!created_qname)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Created Qname creation failed.");
            return AXIS2_FAILURE;
        }
        
        created_ele = axiom_element_get_first_child_with_qname(life_time_ele, env, created_qname, life_time_node, &created_node);
        if(created_ele)
        {
            created_str = axiom_element_get_text(created_ele, env, created_node);
            if(created_str)
            {
                created = axutil_date_time_create(env);
                if(AXIS2_SUCCESS == axutil_date_time_deserialize_date_time(created, env, created_str))
                {
                    life_time->created = created;
                    status = AXIS2_SUCCESS;
                }
                else
                {
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Deserializing created time failed.");
                    return AXIS2_FAILURE;
                }
            }
        }
               
        expires_qname = axutil_qname_create(env, TRUST_LIFE_TIME_EXPIRES, TRUST_WSU_XMLNS, TRUST_WSU);
        if(!created_qname)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Expires Qname creation failed.");
            return AXIS2_FAILURE;
        }
        
        expires_ele = axiom_element_get_first_child_with_qname(life_time_ele, env, expires_qname, life_time_node, &expires_node);
        if(expires_ele)
        {
            expires_str = axiom_element_get_text(expires_ele, env, expires_node);
            if(created_str)
            {
                expires = axutil_date_time_create(env);
                if(AXIS2_SUCCESS == axutil_date_time_deserialize_date_time(expires, env, expires_str))
                {
                    life_time->expires = expires;
                    status = AXIS2_SUCCESS;
                }
                else
                {
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Deserializing created time failed.");
                    return AXIS2_FAILURE;
                }
            }            
        }
        
        if(status == AXIS2_SUCCESS)
            return AXIS2_SUCCESS;
    }
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_life_time_serialize(
        trust_life_time_t *life_time,
        const axutil_env_t *env,
        axiom_node_t *parent)
{
    axiom_node_t *life_time_node = NULL;
    axiom_node_t *created_node = NULL;
    axiom_node_t *expires_node = NULL;
    axiom_element_t *life_time_ele = NULL;
    axiom_element_t *created_ele = NULL;
    axiom_element_t *expires_ele = NULL;
    axiom_namespace_t *wsu_ns = NULL;
    axiom_namespace_t *wst_ns = NULL;
    axis2_status_t status = AXIS2_SUCCESS;
    axis2_char_t *created_str = NULL;
    axis2_char_t *expires_str = NULL;
    
    if(life_time->ttl != -1 && life_time->ttl > 0)
    {
        life_time_node = (axiom_node_t*)trust_util_create_life_time_element(env, parent, life_time->wst_ns_uri, life_time->ttl);
        if(!life_time_node)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Life time element creation failed for ttl.");
            return NULL;
        }
        
        return life_time_node;
    }
    else
    {
        if(life_time->created || life_time->expires)
        {
            wsu_ns = axiom_namespace_create(env, TRUST_WSU_XMLNS, TRUST_WSU);
            wst_ns = axiom_namespace_create(env, life_time->wst_ns_uri, TRUST_WST);
            life_time_ele = axiom_element_create(env, parent, TRUST_LIFE_TIME, wst_ns, &life_time_node);
            if(life_time_ele)
            {
                if(life_time->created)
                {                
                    created_ele = axiom_element_create(env, life_time_node, TRUST_LIFE_TIME_CREATED, wsu_ns, &created_node);
                    if(created_ele)
                    {
                        created_str = axutil_date_time_serialize_date_time(life_time->created, env);
                        status = axiom_element_set_text(created_ele, env, created_str, created_node);
                        if (status == AXIS2_FAILURE)
                        {
                            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                            "[trust] Created Element's setting text failed.");
                            return NULL;
                        }

                        AXIS2_FREE(env->allocator, created_str);            
                    }               
                }
                
                if(life_time->expires)
                {
                    expires_ele = axiom_element_create(env, life_time_node, TRUST_LIFE_TIME_EXPIRES, wsu_ns, &expires_node);
                    if(expires_ele)
                    {
                        expires_str = axutil_date_time_serialize_date_time(life_time->expires, env);
                        status = axiom_element_set_text(expires_ele, env, expires_str, expires_node);
                        if (status == AXIS2_FAILURE)
                        {
                            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                            "[trust] Expires Element's setting text failed.");
                            return NULL;
                        }

                        AXIS2_FREE(env->allocator, expires_str);            
                    }
                }
                
                return life_time_node;
            }
            else
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] LifeTime element creation failed.");
                return NULL;
            }
        }
    }
    
    return NULL;    
}

AXIS2_EXTERN int AXIS2_CALL
trust_life_time_get_ttl(
    trust_life_time_t *life_time,
    const axutil_env_t *env)
{
    return life_time->ttl;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_life_time_set_ttl(
        trust_life_time_t *life_time,
        const axutil_env_t *env,
        int ttl)
{
    if(ttl>0)
    {
        life_time->ttl = ttl;
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axutil_date_time_t * AXIS2_CALL
trust_life_time_get_created(
        trust_life_time_t *life_time,
        const axutil_env_t *env)
{
    return life_time->created;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_life_time_set_created(
        trust_life_time_t *life_time,
        const axutil_env_t *env,
        axutil_date_time_t *created)
{
    if(created)
    {
        life_time->created = created;
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axutil_date_time_t * AXIS2_CALL
trust_life_time_get_expires(
        trust_life_time_t *life_time,
        const axutil_env_t *env)
{
    return life_time->expires;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_life_time_set_expires(
        trust_life_time_t *life_time,
        const axutil_env_t *env,
        axutil_date_time_t *expires)
{
    if(expires)
    {
        life_time->expires = expires;
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_life_time_get_ns_uri(
        trust_life_time_t *life_time,
        const axutil_env_t *env)
{
    return life_time->wst_ns_uri;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_life_time_set_ns_uri(
        trust_life_time_t *life_time,
        const axutil_env_t *env,
        axis2_char_t *ns_uri)
{
    if(ns_uri)
    {
        life_time->wst_ns_uri = ns_uri;
        
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;
}
