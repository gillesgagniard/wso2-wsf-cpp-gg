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
 
#ifndef RAMPART_ERROR_H
#define RAMPART_ERROR_H

#include <axutil_error.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
  * @file rampart_error.h
  * @brief Rampart specific error codes
  */

/**
 * @defgroup rampart_error
 * @ingroup rampart_utils
 * @{
 */
	/**
    * \brief rampart error codes
    *
    * Set of error codes for rampart
    */
    enum rampart_error_codes
    { 
        /* No error */
        RAMPART_ERROR_NONE = RAMPART_ERROR_CODES_START,
        RAMPART_ERROR_UNSUPPORTED_SECURITY_TOKEN,
        RAMPART_ERROR_INVALID_SECURITY,
        RAMPART_ERROR_INVALID_SECURITY_TOKEN,
        RAMPART_ERROR_FAILED_AUTHENTICATION,
        RAMPART_ERROR_FAILED_CHECK,
        RAMPART_ERROR_SECURITY_TOKEN_UNAVAILABLE,
        RAMPART_ERROR_RAMPART_ERROR_LAST,
        RAMPART_ERROR_IN_TIMESTAMP,
        RAMPART_ERROR_IN_USERNAMETOKEN ,
        RAMPART_ERROR_IN_ENCRYPTED_KEY  ,
        RAMPART_ERROR_IN_ENCRYPTED_DATA ,
        RAMPART_ERROR_IN_SIGNATURE ,
        RAMPART_ERROR_MSG_REPLAYED ,
        RAMPART_ERROR_IN_POLICY ,
        RAMPART_ERROR_LAST
    };
      
    typedef enum rampart_error_codes rampart_error_codes_t;

    /**
     * initialising method for error
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_error_init();

/** @} */
#ifdef __cplusplus
}
#endif
 
#endif /*RAMPART_ERROR_H*/
