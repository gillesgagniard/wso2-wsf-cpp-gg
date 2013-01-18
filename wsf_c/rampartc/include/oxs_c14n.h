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

#ifndef OXS_C14N_H
#define OXS_C14N_H

/** @defgroup oxs_c14n C14N
 * @ingroup oxs
 * XML Canonicalization (XML-C14N).
 * @{
 */

/**
 * @file oxs_c14n.h
 * @brief Cannonicalization implementation for OMXMLSecurity
 */

#include <axis2_const.h>
#include <axutil_error.h>
#include <axutil_utils_defines.h>
#include <axutil_utils.h>
#include <axutil_env.h>
#include <axutil_string.h>
#include <axiom_document.h>
#include <axutil_array_list.h>
#include <axutil_stream.h>


#ifdef __cplusplus
extern "C"
{
#endif
    
    /**
     * Perform given XML-Canonicalization (XML-C14N) method and returns the
     * result as an <pre>axis2_char_t</pre> buffer.
     *
     * @param env Pointer to the Axis2/C environment.
     * @param doc Document on which the canonicalization is performed.
     * @param outbuf Output buffer. A new buffer is allocated by the function,
     *               should be free'd by the caller.
     * @param ns_prefixes List of inclusive namespace prefixes.
     * @param node Node that defines the subdocument to be canonicalized.
     *             When it is <pre>NULL</pre> the whole document will be
     *             canonicalized.
     * @param algo Canonicalization method to be used.
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    oxs_c14n_apply_algo(
        const axutil_env_t *env,
        const axiom_document_t *doc,
        axis2_char_t **outbuf,
        const axutil_array_list_t *ns_prefixes,
        const axiom_node_t *node,
        const axis2_char_t *algo
    );

#if 0 /* these doesn't need to be public methods */
    /**
     * Perform given XML-Canonicalization (XML-C14N) method and returns the
     * result as an <pre>axutil_stream</pre>.
     *
     * @param env Pointer to the Axis2/C environment.
     * @param doc Document on which the canonicalization is performed.
     * @param comments <pre>TRUE</pre> if comments should be included in the
     *                 output; <pre>FALSE</pre> otherwise.
     * @param stream Output stream.
     * @param ns_prefixes List of inclusive namespace prefixes.
     * @param exclusive <pre>TRUE</pre> if exclusive cannonicalization should
     *                  be used; <pre>FALSE</pre> otherwise.
     * @param node Node that defines the subdocument to be canonicalized.
     *             When it is <pre>NULL</pre> the whole document will be
     *             canonicalized.
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    oxs_c14n_apply_stream(
        const axutil_env_t *env,
        const axiom_document_t *doc,
        axis2_bool_t comments,
        axutil_stream_t *stream,
        const axis2_bool_t exclusive,
        const axutil_array_list_t *ns_prefixes,
        const axiom_node_t *node
    );


    /**
     * Perform given XML-Canonicalization (XML-C14N) method and returns the
     * result as an <pre>axis2_char_t</pre> buffer.
     *
     * @param env Pointer to the Axis2/C environment.
     * @param doc Document on which the canonicalization is performed.
     * @param comments <pre>TRUE</pre> if comments should be included in the
     *                 output; <pre>FALSE</pre> otherwise.
     * @param outbuf Output buffer. A new buffer is allocated by the function,
     *               should be free'd by the caller.
     * @param ns_prefixes List of inclusive namespace prefixes.
     * @param exclusive <pre>TRUE</pre> if exclusive cannonicalization should
     *                  be used; <pre>FALSE</pre> otherwise.
     * @param node Node that defines the subdocument to be canonicalized.
     *             When it is <pre>NULL</pre> the whole document will be
     *             canonicalized.
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    oxs_c14n_apply (
        const axutil_env_t *env,
        const axiom_document_t *doc,
        const axis2_bool_t comments,
        axis2_char_t **outbuf,
        const axis2_bool_t exclusive,
        const axutil_array_list_t *ns_prefixes,
        const axiom_node_t *node
    );

    /**
     * Perform given XML-Canonicalization (XML-C14N) method and returns the
     * result as an <pre>axutil_stream</pre>.
     *
     * @param env Pointer to the Axis2/C environment.
     * @param doc Document on which the canonicalization is performed.
     * @param stream Output stream.
     * @param ns_prefixes List of inclusive namespace prefixes.
     * @param node Node that defines the subdocument to be canonicalized.
     *             When it is <pre>NULL</pre> the whole document will be
     *             canonicalized.
     * @param algo Canonicalization method to be used.
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    oxs_c14n_apply_stream_algo(
        const axutil_env_t *env,
        const axiom_document_t *doc,
        axutil_stream_t *stream,
        const axutil_array_list_t *ns_prefixes,
        const axiom_node_t *node,
        const axis2_char_t* algo
    );
#endif


#ifdef __cplusplus
}
/** @} */
#endif
#endif  /* OXS_C14N_H */
