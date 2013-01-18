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

#include <stdlib.h>
#include <rampart_error.h>
#include <axutil_error_default.h>

AXIS2_IMPORT extern const axis2_char_t* axutil_error_messages[];

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_error_init()
{
    /* A namespace that is not supported by Sandesha2 */
    axutil_error_messages[RAMPART_ERROR_NONE] =  "Unidentified error in Rampart";
    
    axutil_error_messages[RAMPART_ERROR_UNSUPPORTED_SECURITY_TOKEN] = "Unsupported security token";

    axutil_error_messages[RAMPART_ERROR_INVALID_SECURITY]= "Invalid security";

    axutil_error_messages[RAMPART_ERROR_INVALID_SECURITY_TOKEN]= "Invalid security token";

    axutil_error_messages[RAMPART_ERROR_LAST]= "Last error of the stack in rampart";

    axutil_error_messages[RAMPART_ERROR_FAILED_AUTHENTICATION]= "Failed authentication";

    axutil_error_messages[RAMPART_ERROR_FAILED_CHECK]=  "Failed check";

    axutil_error_messages[RAMPART_ERROR_SECURITY_TOKEN_UNAVAILABLE]= "Security token unavailable";

    axutil_error_messages[RAMPART_ERROR_IN_TIMESTAMP]= "Error in timestamp";

    axutil_error_messages[RAMPART_ERROR_IN_USERNAMETOKEN]= "Error in username token";
    
    axutil_error_messages[RAMPART_ERROR_IN_ENCRYPTED_KEY]= "Error in Encrypted Key";

    axutil_error_messages[RAMPART_ERROR_IN_ENCRYPTED_DATA]= "Error in Encrypted Data";

    axutil_error_messages[RAMPART_ERROR_IN_SIGNATURE]= "Error in Signature";

    axutil_error_messages[RAMPART_ERROR_MSG_REPLAYED]=  "Message probarbly be replayed";

    axutil_error_messages[RAMPART_ERROR_IN_POLICY]= "Error in security policy";

    axutil_error_messages[RAMPART_ERROR_LAST]=
        "Error last";

    return AXIS2_SUCCESS;
}

