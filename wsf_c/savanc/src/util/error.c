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
#include <savan_error.h>
#include <axutil_error_default.h>

AXIS2_IMPORT extern const axis2_char_t* axutil_error_messages[];

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_error_init()
{
    axutil_error_messages[SAVAN_ERROR_SOAP_ACTION_NULL] = 
        "The soap action of an eventing message was missing";
    
    axutil_error_messages[SAVAN_ERROR_FAILED_TO_CREATE_SUBSCRIBER] = 
        "Failed to create an instance of subscriber";

    axutil_error_messages[SAVAN_ERROR_UNHANDLED_MSG_TYPE] = 
        "Unhandled message type";

    axutil_error_messages[SAVAN_ERROR_FAILED_TO_BUILD_SOAP_ENV] = 
        "Failed to build a default soap envelope";
    
    axutil_error_messages[SAVAN_ERROR_REQUESTED_DELIVERY_MODE_NOT_SUPPORTED] = 
        "Requested delivery mode is not supported";

    axutil_error_messages[SAVAN_ERROR_EXPIRATION_TIME_REQUESTED_IS_INVALID] = 
        "Expiration time requested is invalid";

    axutil_error_messages[SAVAN_ERROR_ONLY_EXPIRATION_DURATIONS_ARE_SUPPORTED] = 
        "Only expiration durations are supported";

    axutil_error_messages[SAVAN_ERROR_FILTERING_IS_NOT_SUPPORTED] = 
        "Filtering is not supported";

    axutil_error_messages[SAVAN_ERROR_REQUESTED_FILTER_DIALECT_IS_NOT_SUPPORTED] = 
        "Requested filter dialect is not supported";

    axutil_error_messages[SAVAN_ERROR_MESSAGE_IS_NOT_VALID_AND_CANNOT_BE_PROCESSED] = 
        "Messsage is not valid and cannot be processed";

    axutil_error_messages[SAVAN_ERROR_MESSAGE_CANNOT_BE_PROCESSED_BY_EVENT_SOURCE] = 
        "Message cannot be processed by the event source";
    
    axutil_error_messages[SAVAN_ERROR_UNABLE_TO_RENEW] = 
        "Unable to Renew";
    
    axutil_error_messages[SAVAN_ERROR_SUBSCRIBER_NOT_FOUND] = 
        "Subscriber is not found";
        
    axutil_error_messages[SAVAN_ERROR_COULD_NOT_POPULATE_TOPIC] = 
        "Could not populate Topic";
    
    axutil_error_messages[SAVAN_ERROR_PARSING_SUBSCRIBER_NODE_FAILED] = 
        "Parsing subsriber node failed";
    
    axutil_error_messages[SAVAN_ERROR_APPLYING_FILTER_FAILED] = 
        "Applying filter failed";
        
    axutil_error_messages[SAVAN_ERROR_STORAGE_MANAGER_CREATION_FAILED] =
        "Memory allocation failed for Savan Storage Manager";
    
    axutil_error_messages[SAVAN_ERROR_SUBSCRIBER_RETRIEVE_ERROR] =
        "Could not retrieve subscriber from storage";
    
    axutil_error_messages[SAVAN_ERROR_SUBSCRIBER_REMOVE_ERROR] =
        "Could not remove subscriber from storage";
    
    axutil_error_messages[SAVAN_ERROR_SUBSCRIBER_UPDATE_ERROR] =
        "Could not update subscriber to storage";
    
    axutil_error_messages[SAVAN_ERROR_SUBSCRIBER_INSERT_ERROR] =
        "Could not insert subscriber into storage";
    
    axutil_error_messages[SAVAN_ERROR_TOPIC_INSERT_ERROR] =
        "Could not insert topic into storage";
    
    axutil_error_messages[SAVAN_ERROR_DATABASE_TABLE_CREATION_ERROR] =
        "Could not create database table";
    
    axutil_error_messages[SAVAN_ERROR_DATABASE_CREATION_ERROR] =
        "Could not create database";

    axutil_error_messages[SAVAN_ERROR_FILTER_CREATION_FAILED] =
        "Could not create the filter";
    
    axutil_error_messages[SAVAN_ERROR_FILTER_MODULE_COULD_NOT_BE_RETRIEVED] =
        "Could not create the filter module";

    return AXIS2_SUCCESS;
}

