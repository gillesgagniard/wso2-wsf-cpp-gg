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

#ifndef RAHAS_MOD_H
#define RAHAS_MOD_H

/**
 * @file rahas_mod.h
 * @brief Axis2 rahas module interface
 */

/**
* @defgroup rahas_mod Rahas Module 
* @{
*/
#include <axis2_handler.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * Creates In handler
     * @param env pointer to environment struct
     * @param name 
     * @return Created In handler
     */
    AXIS2_EXTERN axis2_handler_t* AXIS2_CALL
    rahas_in_handler_create(
        const axutil_env_t *env,
        axutil_string_t *name);

    /** @} */

#ifdef __cplusplus
}
#endif

#endif    /* RAHAS_MOD_H */
