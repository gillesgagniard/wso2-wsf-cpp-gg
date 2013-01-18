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
 
#ifndef SAVAN_FILTER_MOD_H
#define SAVAN_FILTER_MOD_H

/**
  * @file savan_filter_mod.h
  * @brief 
  */
#include <platforms/axutil_platform_auto_sense.h>
#include <axutil_utils_defines.h>
#include <axutil_env.h>
#include <axis2_conf.h>
#include <savan_subscriber.h>
#include <axiom_node.h>

#ifdef __cplusplus
extern "C"
{
#endif

/** 
 * @ingroup savan_filter_mod
 * @{
 */
 
typedef struct savan_filter_mod savan_filter_mod_t;
typedef struct savan_filter_mod_ops savan_filter_mod_ops_t;

 /**
 * @brief Filter ops struct
 * Encapsulator struct for ops of savan_filter_mod
 */
AXIS2_DECLARE_DATA struct savan_filter_mod_ops
{ 
    void (AXIS2_CALL * 
            free)(
                savan_filter_mod_t *filter,
                const axutil_env_t *env);

    axis2_bool_t (AXIS2_CALL *
            apply)(
                savan_filter_mod_t *filter, 
                const axutil_env_t *env,
                savan_subscriber_t *subscriber,
                axiom_node_t *payload);


};

AXIS2_DECLARE_DATA struct savan_filter_mod
{
    const savan_filter_mod_ops_t *ops;
};


/**
 * Create the savan filter.
 * @param env environment object
 * @param conf axis2 configuration
 * @return status of the operation
 */
AXIS2_EXTERN savan_filter_mod_t * AXIS2_CALL
savan_filter_mod_create(
    const axutil_env_t *env,
    axis2_conf_t *conf);

/**
 * Deallocate the filter.
 * @param filter
 * @param env environment object
 */
AXIS2_EXTERN void AXIS2_CALL 
savan_filter_mod_free(
    savan_filter_mod_t *filtermod,
    const axutil_env_t *envv);

/**
 * Apply filter to payload.
 * @param filter
 * @param env environment object
 * @param subscriber subscriber instant
 * @param payload payload to which the filter is applied
 * @return filter apply or not
 */
AXIS2_EXTERN axis2_bool_t AXIS2_CALL
savan_filter_mod_apply(
    savan_filter_mod_t *filtermod, 
    const axutil_env_t *env,
    savan_subscriber_t *subscriber,
    axiom_node_t *payload);

/** @} */
#ifdef __cplusplus
}
#endif

#endif /*SAVAN_FILTER_MOD_H*/
