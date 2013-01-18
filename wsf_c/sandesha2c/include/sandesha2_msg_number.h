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
 
#ifndef SANDESHA2_MSG_NUMBER_H
#define SANDESHA2_MSG_NUMBER_H

/**
  * @file sandesha2_msg_number.h
  * @brief 
  */

#include <sandesha2_error.h>
#include <axutil_env.h>
#include <axiom_node.h>


#ifdef __cplusplus
extern "C"
{
#endif

/** @defgroup sandesha2_msg_number
 * @ingroup sandesha2_wsrm
 * @{
 */
typedef struct sandesha2_msg_number_t sandesha2_msg_number_t;
 
/**
 * @brief Message Number ops struct
 * Encapsulator struct for ops of sandesha2_msg_number
 */

/**
 * @brief sandesha2_msg_number
 *    sandesha2_msg_number
 */

AXIS2_EXTERN sandesha2_msg_number_t* AXIS2_CALL
sandesha2_msg_number_create(
    const axutil_env_t *env,
    axis2_char_t *ns_value);

AXIS2_EXTERN sandesha2_msg_number_t* AXIS2_CALL
sandesha2_msg_number_clone(
    const axutil_env_t *env,  
    sandesha2_msg_number_t *msg_number);

axis2_status_t AXIS2_CALL
sandesha2_msg_number_free_void_arg(
    void *msg_num,
    const axutil_env_t *env);

axis2_status_t AXIS2_CALL 
sandesha2_msg_number_free(
    sandesha2_msg_number_t *msg_num, 
	const axutil_env_t *env);

axis2_char_t* AXIS2_CALL 
sandesha2_msg_number_get_namespace_value(
    sandesha2_msg_number_t *msg_num,
	const axutil_env_t *env);

axis2_status_t AXIS2_CALL                 
sandesha2_msg_number_set_msg_num(
    sandesha2_msg_number_t *msg_num,
   	const axutil_env_t *env, 
    long value);
                    	
long AXIS2_CALL
sandesha2_msg_number_get_msg_num(
    sandesha2_msg_number_t *msg_num,
   	const axutil_env_t *env);

void* AXIS2_CALL 
sandesha2_msg_number_from_om_node(
    sandesha2_msg_number_t *msg_num,
   	const axutil_env_t *env, 
    axiom_node_t *om_node);
    
axiom_node_t* AXIS2_CALL 
sandesha2_msg_number_to_om_node(
    sandesha2_msg_number_t *msg_num,
   	const axutil_env_t *env, 
    void *om_node);


/** @} */
#ifdef __cplusplus
}
#endif

#endif                          /* SANDESHA2_MSG_NUMBER_H */

