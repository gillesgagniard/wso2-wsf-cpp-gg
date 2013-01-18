/*
 * copyright 1999-2004 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

#ifndef SANDESHA2_SEQ_PROPERTY_BEAN_H
#define SANDESHA2_SEQ_PROPERTY_BEAN_H

#include <axutil_utils_defines.h>
#include <axutil_env.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct sandesha2_seq_property_bean sandesha2_seq_property_bean_t ;

/* constructors 
 */
AXIS2_EXTERN sandesha2_seq_property_bean_t* AXIS2_CALL
sandesha2_seq_property_bean_create(
    const axutil_env_t *env);

AXIS2_EXTERN sandesha2_seq_property_bean_t* AXIS2_CALL
sandesha2_seq_property_bean_create_with_data(
    const axutil_env_t *env,
    axis2_char_t *seq_id,
    axis2_char_t *prop_name,
    axis2_char_t *value);

void AXIS2_CALL
sandesha2_seq_property_bean_free (
    sandesha2_seq_property_bean_t *seq_property,
    const axutil_env_t *env);

axis2_char_t *AXIS2_CALL
sandesha2_seq_property_bean_get_name (
    sandesha2_seq_property_bean_t *seq_property,
    const axutil_env_t *env);

void AXIS2_CALL 
sandesha2_seq_property_bean_set_name (
    sandesha2_seq_property_bean_t *seq_property,
    const axutil_env_t *env,
    axis2_char_t *name);

axis2_char_t *AXIS2_CALL
sandesha2_seq_property_bean_get_seq_id (
    sandesha2_seq_property_bean_t *seq_property,
    const axutil_env_t *env);

void AXIS2_CALL
sandesha2_seq_property_bean_set_seq_id (
    sandesha2_seq_property_bean_t *seq_property,
    const axutil_env_t *env,
    axis2_char_t *seq_id);

axis2_char_t* AXIS2_CALL
sandesha2_seq_property_bean_get_value (
    sandesha2_seq_property_bean_t *seq_property,
    const axutil_env_t *env);

void AXIS2_CALL
sandesha2_seq_property_bean_set_value (
    sandesha2_seq_property_bean_t *seq_property,
    const axutil_env_t *env,
    axis2_char_t *value);

#ifdef __cplusplus
}

#endif
	
#endif /* End of SANDESHA2_SEQ_PROPERTY_BEAN_H */
