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
 
#ifndef SANDESHA2_ACK_NONE_H
#define SANDESHA2_ACK_NONE_H

/**
  * @file sandesha2_ack_none.h
  * @brief 
  */

#include <axutil_utils_defines.h>
#include <axutil_env.h>
#include <sandesha2_error.h>
#include <axiom_node.h>


#ifdef __cplusplus
extern "C"
{
#endif

/** @defgroup sandesha2_ack_none
 * @ingroup sandesha2_wsrm
 * @{
 */
typedef struct sandesha2_ack_none_t sandesha2_ack_none_t;
 
/**
 * @brief sandesha2_ack_none
 *    sandesha2_ack_none
 */
AXIS2_EXTERN sandesha2_ack_none_t * AXIS2_CALL
sandesha2_ack_none_create(
    const axutil_env_t *env, 
    axis2_char_t *ns_value);

axis2_status_t AXIS2_CALL 
sandesha2_ack_none_free(
    sandesha2_ack_none_t *ack_none, 
    const axutil_env_t *env);								

axis2_char_t* AXIS2_CALL 
sandesha2_ack_none_get_namespace_value(
    sandesha2_ack_none_t *ack_none,
	const axutil_env_t *env);

void* AXIS2_CALL 
sandesha2_ack_none_from_om_node(
    sandesha2_ack_none_t *ack_none,
    const axutil_env_t *env, 
    axiom_node_t *om_node);
    
axiom_node_t* AXIS2_CALL 
sandesha2_ack_none_to_om_node(
    sandesha2_ack_none_t *ack_none,
    const axutil_env_t *env, 
    void *om_node);
 
/** @} */
#ifdef __cplusplus
}
#endif

#endif                          /* SANDESHA2_ACK_NONE_H */

