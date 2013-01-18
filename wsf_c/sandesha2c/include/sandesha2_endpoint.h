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
 
#ifndef SANDESHA2_ENDPOINT_H
#define SANDESHA2_ENDPOINT_H

/**
  * @file sandesha2_endpoint.h
  * @brief 
  */

#include <axutil_utils_defines.h>
#include <axutil_env.h>
#include <axiom_soap_envelope.h>
#include <sandesha2_address.h>


#ifdef __cplusplus
extern "C"
{
#endif

/** @defgroup sandesha2_endpoint
 * @ingroup sandesha2_wsrm
 * @{
 */
typedef struct sandesha2_endpoint_t sandesha2_endpoint_t;

/**
 * @brief sandesha2_endpoint
 *    sandesha2_endpoint
 */

AXIS2_EXTERN sandesha2_endpoint_t * AXIS2_CALL
sandesha2_endpoint_create(
    const axutil_env_t *env, 
    sandesha2_address_t *address,
    axis2_char_t *rm_ns_value, 
    axis2_char_t *addr_ns_value);

axis2_status_t AXIS2_CALL 
sandesha2_endpoint_free(
    sandesha2_endpoint_t *endpoint, 
    const axutil_env_t *env);								

sandesha2_address_t * AXIS2_CALL
sandesha2_endpoint_get_address(
    sandesha2_endpoint_t *endpoint,
    const axutil_env_t *env);
                    	
axis2_status_t AXIS2_CALL 
sandesha2_endpoint_set_address (
    sandesha2_endpoint_t *endpoint, 
    const axutil_env_t *env, 
    sandesha2_address_t *address);								
 
axis2_char_t* AXIS2_CALL 
sandesha2_endpoint_get_namespace_value(
    sandesha2_endpoint_t *endpoint,
	const axutil_env_t *env);

void* AXIS2_CALL 
sandesha2_endpoint_from_om_node(
    sandesha2_endpoint_t *endpoint,
    const axutil_env_t *env, 
    axiom_node_t *om_node);
    
axiom_node_t* AXIS2_CALL 
sandesha2_endpoint_to_om_node(
    sandesha2_endpoint_t *endpoint,
   	const axutil_env_t *env, 
    void *om_node);
 
/** @} */
#ifdef __cplusplus
}
#endif

#endif                          /* SANDESHA2_ENDPOINT_H */

