/*
* ModSecurity for Apache 2.x, http://www.modsecurity.org/
* Copyright (c) 2004-2013 Trustwave Holdings, Inc. (http://www.trustwave.com/)
*
* You may not use this file except in compliance with
* the License.  You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* If any of the files related to licensing are missing or if you have any
* other questions related to licensing please contact Trustwave Holdings, Inc.
* directly using the email address security@modsecurity.org.
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "apr_global_mutex.h"

#include "modsecurity.h"
#include "msc_parsers.h"
#include "msc_util.h"
#include "msc_json.h"
#include "msc_xml.h"
#include "apr_version.h"


#ifdef WITH_CURL
#include <curl/curl.h>
#endif



unsigned long int DSOLOCAL unicode_codepage = 0;

int DSOLOCAL *unicode_map_table = NULL;
const apr_array_header_t *arr = NULL;
const apr_table_entry_t *te = NULL;
int fields_rq; //So dac trung request den;
const char *field_value; // gia tri cua dac trung
char *url; //url path;
char *method_name;
int field_rq; // so dac trung request den
const char * key_url; // key_url = method+path (trong mau)
const char * key_fields; //ten cac dac trung mau
char * attr_value;
double threshold_cd_smd = 0.0;
double *mean_cd_smd, *deviation;
int i=0, j=0,ii=0;
yajl_val node; //cau truc co so du lieu
yajl_val fields;// cau truc dac trung mau
yajl_val attr; //cau truc gia tri dac trung mau key - value
char *metric;
int nfields_pattern;
double alpha = 0.0001;
yajl_val method_request; // cau truc phuong thuc request
yajl_val type_param; // cau truc cac loai tham so: rest, body, query, header, cookie
yajl_val attr;
yajl_val key_algorithm;
yajl_val value_algorithm;
int n_method_request;
int n_type_param; // so cac loai tham so
size_t n_attr; // so luong cac thuoc tinh
int n_value; // so luong cac gia tri
double *length; //Array luu gia tri trung binh, gia tri phuong sai
double **distribution_array; //Array 2 chiu chua gia tri trung binh, gia tri do lech chuan
double length_threshold, distribution_threshold, combin_threshold; 
/**
 * Format an alert message.
 */
const char * msc_alert_message(modsec_rec *msr, msre_actionset *actionset, const char *action_message,
    const char *rule_message)
{
    const char *message = NULL;

    if (rule_message == NULL) rule_message = "Unknown error.";

    if (action_message == NULL) {
        message = apr_psprintf(msr->mp, "%s%s",
            rule_message, msre_format_metadata(msr, actionset));
    }
    else {
        message = apr_psprintf(msr->mp, "%s %s%s", action_message,
            rule_message, msre_format_metadata(msr, actionset));
    }

    return message;
}

/**
 * Log an alert message to the log, adding the rule metadata at the end.
 */
void msc_alert(modsec_rec *msr, int level, msre_actionset *actionset, const char *action_message,
    const char *rule_message)
{
    const char *message = msc_alert_message(msr, actionset, action_message, rule_message);

    msr_log(msr, level, "%s", message);
}

#if 0
/**
 * Return phase name associated with the given phase number.
 */
static const char *phase_name(int phase) {
    switch(phase) {
        case 1 :
            return "REQUEST_HEADERS";
            break;
        case 2 :
            return "REQUEST_BODY";
            break;
        case 3 :
            return "RESPONSE_HEADERS";
            break;
        case 4 :
            return "RESPONSE_BODY";
            break;
        case 5 :
            return "LOGGING";
            break;
    }
    
    return "INVALID";
}
#endif

/**
 * Creates and initialises a ModSecurity engine instance.
 */
msc_engine *modsecurity_create(apr_pool_t *mp, int processing_mode) {
    msc_engine *msce = NULL;

    msce = apr_pcalloc(mp, sizeof(msc_engine));
    if (msce == NULL) return NULL;

    msce->mp = mp;
    msce->processing_mode = processing_mode;

    msce->msre = msre_engine_create(msce->mp);
    if (msce->msre == NULL) return NULL;
    msre_engine_register_default_variables(msce->msre);
    msre_engine_register_default_operators(msce->msre);
    msre_engine_register_default_tfns(msce->msre);
    msre_engine_register_default_actions(msce->msre);
    // TODO: msre_engine_register_default_reqbody_processors(msce->msre);

    return msce;
}

/**
 * Initialise the modsecurity engine. This function must be invoked
 * after configuration processing is complete as Apache needs to know the
 * username it is running as.
 */
int modsecurity_init(msc_engine *msce, apr_pool_t *mp) {
    apr_status_t rc;

    /**
     * Notice that curl is initialized here but never cleaned up. First version
     * of this implementation curl was initialized and cleaned for every
     * utilization. Turns out that it was not only cleaning stuff that was
     * utilized by Curl but also other OpenSSL stuff that was utilized by
     * mod_ssl leading the SSL support to crash.
     */
#ifdef WITH_CURL
    curl_global_init(CURL_GLOBAL_ALL);
#endif
    /* Serial audit log mutext */
    rc = apr_global_mutex_create(&msce->auditlog_lock, NULL, APR_LOCK_DEFAULT, mp);
    if (rc != APR_SUCCESS) {
        //ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, "mod_security: Could not create modsec_auditlog_lock");
        //return HTTP_INTERNAL_SERVER_ERROR;
        return -1;
    }

#if !defined(MSC_TEST)
#ifdef __SET_MUTEX_PERMS
#if AP_SERVER_MAJORVERSION_NUMBER > 1 && AP_SERVER_MINORVERSION_NUMBER > 2
    rc = ap_unixd_set_global_mutex_perms(msce->auditlog_lock);
#else
    rc = unixd_set_global_mutex_perms(msce->auditlog_lock);
#endif
    if (rc != APR_SUCCESS) {
        // ap_log_error(APLOG_MARK, APLOG_ERR, rc, s, "mod_security: Could not set permissions on modsec_auditlog_lock; check User and Group directives");
        // return HTTP_INTERNAL_SERVER_ERROR;
        return -1;
    }
#endif /* SET_MUTEX_PERMS */

    rc = apr_global_mutex_create(&msce->geo_lock, NULL, APR_LOCK_DEFAULT, mp);
    if (rc != APR_SUCCESS) {
        return -1;
    }

#ifdef __SET_MUTEX_PERMS
#if AP_SERVER_MAJORVERSION_NUMBER > 1 && AP_SERVER_MINORVERSION_NUMBER > 2
    rc = ap_unixd_set_global_mutex_perms(msce->geo_lock);
#else
    rc = unixd_set_global_mutex_perms(msce->geo_lock);
#endif
    if (rc != APR_SUCCESS) {
        return -1;
    }
#endif /* SET_MUTEX_PERMS */

#ifdef GLOBAL_COLLECTION_LOCK
    rc = apr_global_mutex_create(&msce->dbm_lock, NULL, APR_LOCK_DEFAULT, mp);
    if (rc != APR_SUCCESS) {
        return -1;
    }

#ifdef __SET_MUTEX_PERMS
#if AP_SERVER_MAJORVERSION_NUMBER > 1 && AP_SERVER_MINORVERSION_NUMBER > 2
    rc = ap_unixd_set_global_mutex_perms(msce->dbm_lock);
#else
    rc = unixd_set_global_mutex_perms(msce->dbm_lock);
#endif
    if (rc != APR_SUCCESS) {
        return -1;
    }
#endif /* SET_MUTEX_PERMS */
#endif
#endif

    return 1;
}

/**
 * Performs per-child (new process) initialisation.
 */
void modsecurity_child_init(msc_engine *msce) {
    /* Need to call this once per process before any other XML calls. */
    xmlInitParser();

    if (msce->auditlog_lock != NULL) {
        apr_status_t rc = apr_global_mutex_child_init(&msce->auditlog_lock, NULL, msce->mp);
        if (rc != APR_SUCCESS) {
            // ap_log_error(APLOG_MARK, APLOG_ERR, rs, s, "Failed to child-init auditlog mutex");
        }
    }

    if (msce->geo_lock != NULL) {
        apr_status_t rc = apr_global_mutex_child_init(&msce->geo_lock, NULL, msce->mp);
        if (rc != APR_SUCCESS) {
            // ap_log_error(APLOG_MARK, APLOG_ERR, rs, s, "Failed to child-init geo mutex");
        }
    }

#ifdef GLOBAL_COLLECTION_LOCK
    if (msce->dbm_lock != NULL) {
        apr_status_t rc = apr_global_mutex_child_init(&msce->dbm_lock, NULL, msce->mp);
        if (rc != APR_SUCCESS) {
            // ap_log_error(APLOG_MARK, APLOG_ERR, rs, s, "Failed to child-init dbm mutex");
        }
    }
#endif

}

/**
 * Releases resources held by engine instance.
 */
void modsecurity_shutdown(msc_engine *msce) {
    if (msce == NULL) return;
}

/**
 *
 */
static void modsecurity_persist_data(modsec_rec *msr) {
    const apr_array_header_t *arr;
    apr_table_entry_t *te;
    apr_time_t time_before, time_after;
    int i;

    time_before = apr_time_now();

    /* Collections, store & remove stale. */
    arr = apr_table_elts(msr->collections);
    te = (apr_table_entry_t *)arr->elts;
    for (i = 0; i < arr->nelts; i++) {
        apr_table_t *col = (apr_table_t *)te[i].val;

        /* Only store those collections that changed. */
        if (apr_table_get(msr->collections_dirty, te[i].key)) {
            collection_store(msr, col);
        }
    }

    time_after = apr_time_now();

    msr->time_storage_write += time_after - time_before;

    if (msr->txcfg->debuglog_level >= 4) {
        msr_log(msr, 4, "Recording persistent data took %" APR_TIME_T_FMT
            " microseconds.", msr->time_gc);
    }

    /* Remove stale collections. */
#if AP_SERVER_MAJORVERSION_NUMBER > 1 && AP_SERVER_MINORVERSION_NUMBER > 3
    if (ap_random_pick(0, RAND_MAX) < RAND_MAX/100) {
#else
    if (rand() < RAND_MAX/100) {
#endif
        arr = apr_table_elts(msr->collections);
        te = (apr_table_entry_t *)arr->elts;
        for (i = 0; i < arr->nelts; i++) {
            collections_remove_stale(msr, te[i].key);
        }

        msr->time_gc = apr_time_now() - time_after;

        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Garbage collection took %" APR_TIME_T_FMT
                " microseconds.", msr->time_gc);
        }
    }
}

/**
 *
 */
static apr_status_t modsecurity_tx_cleanup(void *data) {
    modsec_rec *msr = (modsec_rec *)data;
    char *my_error_msg = NULL;
    
    if (msr == NULL) return APR_SUCCESS;    

    /* Multipart processor cleanup. */
    if (msr->mpd != NULL) multipart_cleanup(msr);

    /* XML processor cleanup. */
    if (msr->xml != NULL) xml_cleanup(msr);

#ifdef WITH_YAJL
    /* JSON processor cleanup. */
    if (msr->json != NULL) json_cleanup(msr);
#endif

    // TODO: Why do we ignore return code here?
    modsecurity_request_body_clear(msr, &my_error_msg);
    if (my_error_msg != NULL) {
        msr_log(msr, 1, "%s", my_error_msg);
    }

    if (msr->msc_full_request_length > 0 &&
            msr->msc_full_request_buffer != NULL) {
        msr->msc_full_request_length = 0;
        free(msr->msc_full_request_buffer);
    }

#if defined(WITH_LUA)
    #ifdef CACHE_LUA
    if(msr->L != NULL)  lua_close(msr->L);
    #endif
#endif

    return APR_SUCCESS;
}

/**
 *
 */
apr_status_t modsecurity_tx_init(modsec_rec *msr) {
    const char *s = NULL;
    const apr_array_header_t *arr;
    char *semicolon = NULL;
    char *comma = NULL;
    apr_table_entry_t *te;
    int i;

    /* Register TX cleanup */
    apr_pool_cleanup_register(msr->mp, msr, modsecurity_tx_cleanup, apr_pool_cleanup_null);

    /* Initialise C-L */
    msr->request_content_length = -1;
    s = apr_table_get(msr->request_headers, "Content-Length");
    if (s != NULL) {
        msr->request_content_length = strtol(s, NULL, 10);
    }

    /* Figure out whether this request has a body */
    msr->reqbody_chunked = 0;
    msr->reqbody_should_exist = 0;
    if (msr->request_content_length == -1) {
        /* There's no C-L, but is chunked encoding used? */
        char *transfer_encoding = (char *)apr_table_get(msr->request_headers, "Transfer-Encoding");
        if ((transfer_encoding != NULL)&&(m_strcasestr(transfer_encoding, "chunked") != NULL)) {
            msr->reqbody_should_exist = 1;
            msr->reqbody_chunked = 1;
        }
    } else {
        /* C-L found */
        msr->reqbody_should_exist = 1;
    }

    /* Initialise C-T */
    msr->request_content_type = NULL;
    s = apr_table_get(msr->request_headers, "Content-Type");
    if (s != NULL) msr->request_content_type = s;

    /* Decide what to do with the request body. */
    if ((msr->request_content_type != NULL)
       && (strncasecmp(msr->request_content_type, "application/x-www-form-urlencoded", 33) == 0))
    {
        /* Always place POST requests with
         * "application/x-www-form-urlencoded" payloads in memory.
         */
        msr->msc_reqbody_storage = MSC_REQBODY_MEMORY;
        msr->msc_reqbody_spilltodisk = 0;
        msr->msc_reqbody_processor = "URLENCODED";
    } else {
        /* If the C-L is known and there's more data than
         * our limit go to disk straight away.
         */
        if ((msr->request_content_length != -1)
           && (msr->request_content_length > msr->txcfg->reqbody_inmemory_limit))
        {
            msr->msc_reqbody_storage = MSC_REQBODY_DISK;
        }

        /* In all other cases, try using the memory first
         * but switch over to disk for larger bodies.
         */
        msr->msc_reqbody_storage = MSC_REQBODY_MEMORY;
        msr->msc_reqbody_spilltodisk = 1;

        if (msr->request_content_type != NULL) {
            if (strncasecmp(msr->request_content_type, "multipart/form-data", 19) == 0) {
                msr->msc_reqbody_processor = "MULTIPART";
            }
        }
    }

    /* Check if we are forcing buffering, then use memory only. */
    if (msr->txcfg->reqbody_buffering != REQUEST_BODY_FORCEBUF_OFF) {
        msr->msc_reqbody_storage = MSC_REQBODY_MEMORY;
        msr->msc_reqbody_spilltodisk = 0;
    }

    /* Initialise arguments */
    msr->arguments = apr_table_make(msr->mp, 32);
    if (msr->arguments == NULL) return -1;
    if (msr->query_string != NULL) {
        int invalid_count = 0;

        if (parse_arguments(msr, msr->query_string, strlen(msr->query_string),
            msr->txcfg->argument_separator, "QUERY_STRING", msr->arguments,
            &invalid_count) < 0)
        {
            msr_log(msr, 1, "Initialisation: Error occurred while parsing QUERY_STRING arguments.");
            return -1;
        }

        if (invalid_count) {
            msr->urlencoded_error = 1;
        }
    }

    msr->arguments_to_sanitize = apr_table_make(msr->mp, 16);
    if (msr->arguments_to_sanitize == NULL) return -1;
    msr->request_headers_to_sanitize = apr_table_make(msr->mp, 16);
    if (msr->request_headers_to_sanitize == NULL) return -1;
    msr->response_headers_to_sanitize = apr_table_make(msr->mp, 16);
    if (msr->response_headers_to_sanitize == NULL) return -1;
    msr->pattern_to_sanitize = apr_table_make(msr->mp, 32);
    if (msr->pattern_to_sanitize == NULL) return -1;

    /* remove targets */
    msr->removed_targets = apr_table_make(msr->mp, 16);
    if (msr->removed_targets == NULL) return -1;

    /* Initialise cookies */
    msr->request_cookies = apr_table_make(msr->mp, 16);
    if (msr->request_cookies == NULL) return -1;

    /* Initialize matched vars */
    msr->matched_vars = apr_table_make(msr->mp, 8);
    if (msr->matched_vars == NULL) return -1;
    apr_table_clear(msr->matched_vars);

    msr->perf_rules = apr_table_make(msr->mp, 8);
    if (msr->perf_rules == NULL) return -1;
    apr_table_clear(msr->perf_rules);

    /* Locate the cookie headers and parse them */
    arr = apr_table_elts(msr->request_headers);
    te = (apr_table_entry_t *)arr->elts;
    for (i = 0; i < arr->nelts; i++) {
        if (strcasecmp(te[i].key, "Cookie") == 0) {
            if (msr->txcfg->cookie_format == COOKIES_V0) {
                semicolon = apr_pstrdup(msr->mp, te[i].val);
                while((*semicolon != 0)&&(*semicolon != ';')) semicolon++;
                if(*semicolon == ';')    {
                    parse_cookies_v0(msr, te[i].val, msr->request_cookies, ";");
                } else  {
                    comma = apr_pstrdup(msr->mp, te[i].val);
                    while((*comma != 0)&&(*comma != ',')) comma++;
                    if(*comma == ',')    {
                        comma++;
                        if(*comma == 0x20)   {// looks like comma is the separator
                            if (msr->txcfg->debuglog_level >= 5) {
                                msr_log(msr, 5, "Cookie v0 parser: Using comma as a separator. Semi-colon was not identified!");
                            }
                            parse_cookies_v0(msr, te[i].val, msr->request_cookies, ",");
                        } else {
                            parse_cookies_v0(msr, te[i].val, msr->request_cookies, ";");
                        }
                    } else  {
                        parse_cookies_v0(msr, te[i].val, msr->request_cookies, ";");
                    }
                }
            } else {
                parse_cookies_v1(msr, te[i].val, msr->request_cookies);
            }
        }
    }

    /* Collections. */
    msr->tx_vars = apr_table_make(msr->mp, 32);
    if (msr->tx_vars == NULL) return -1;

    msr->geo_vars = apr_table_make(msr->mp, 8);
    if (msr->geo_vars == NULL) return -1;

    msr->collections_original = apr_table_make(msr->mp, 8);
    if (msr->collections_original == NULL) return -1;
    msr->collections = apr_table_make(msr->mp, 8);
    if (msr->collections == NULL) return -1;
    msr->collections_dirty = apr_table_make(msr->mp, 8);
    if (msr->collections_dirty == NULL) return -1;

    /* Other */
    msr->tcache = NULL;
    msr->tcache_items = 0;

    msr->matched_rules = apr_array_make(msr->mp, 16, sizeof(void *));
    if (msr->matched_rules == NULL) return -1;

    msr->matched_var = (msc_string *)apr_pcalloc(msr->mp, sizeof(msc_string));
    if (msr->matched_var == NULL) return -1;

    msr->highest_severity = 255; /* high, invalid value */

    msr->removed_rules = apr_array_make(msr->mp, 16, sizeof(char *));
    if (msr->removed_rules == NULL) return -1;

    msr->removed_rules_tag = apr_array_make(msr->mp, 16, sizeof(char *));
    if (msr->removed_rules_tag == NULL) return -1;

    msr->removed_rules_msg = apr_array_make(msr->mp, 16, sizeof(char *));
    if (msr->removed_rules_msg == NULL) return -1;

    return 1;
}

/**
 *
 */
static int is_response_status_relevant(modsec_rec *msr, int status) {
    char *my_error_msg = NULL;
    apr_status_t rc;
    char buf[32];

    /* ENH: Setting is_relevant here will cause an audit even if noauditlog
     * was set for the last rule that matched.  Is this what we want?
     */

    if ((msr->txcfg->auditlog_relevant_regex == NULL)
        ||(msr->txcfg->auditlog_relevant_regex == NOT_SET_P))
    {
        return 0;
    }

    apr_snprintf(buf, sizeof(buf), "%d", status);

    rc = msc_regexec(msr->txcfg->auditlog_relevant_regex, buf, strlen(buf), &my_error_msg);
    if (rc >= 0) return 1;
    if (rc == PCRE_ERROR_NOMATCH) return 0;

    msr_log(msr, 1, "Regex processing failed (rc %d): %s", rc, my_error_msg);
    
    return 0;
}

/*Tinh tan suat phan bo ky tu*/

static double * distribution(const char *arg, int len)
{
    int i, j;
    double *mean_mt = (double *)calloc(6, sizeof(double));
    const char *group4 = "*=<>/\\.()\'\"";
    for(i = 0; i<len; ++i)
    {
        char c = arg[i];
        if((c >= 9 && c <= 13) || c == 32)
        {
            *(mean_mt+0) += 1;
        }
        else if(isdigit(c))
        {
            *(mean_mt+1) += 1;
        }
        else if(isalpha(c))
        {
            *(mean_mt+2) += 1;
        }
        else if(strchr(group4, c) ||  ispunct(c))
        {
            *(mean_mt+3) += 1;
        }
        else if((c >= 0 && c <= 8) || (c >= 14 && c < 32))
        {
            *(mean_mt+4) += 1;
        }
        else
        {
            *(mean_mt+5) += 1;
        }
    }
    for(j = 0; j<6; ++j) 
    {
        *(mean_mt+j) /= len;
    }
    return mean_mt;
}

/*Nhan ma tran*/
/*
double matrix(double mean_tb[7][1], double mean_mt[7][1], double inv_covariance[7][7])
{
    double sub[7][1];
    double sub_T[1][7];
    double temp[1][7];
    double product = 0.0;
    // tru 2 ma tran
    for(i = 0, j = 0; i<7; i++)
    {
        sub[i][j] = mean_mt[i][j] - mean_tb[i][j];
    }
    // ma tran chuyen vi
    for(i=0, j=0; i<7; i++)
    {
        sub_T[j][i] = sub[i][j];
    }
    //nhan 2 ma tran
    for(i=0, j=0; i<7; i++)
    {
        temp[i][j] = 0.0;
        for(ii =0; ii<7; ii++)
        {
            temp[i][j] += sub_T[i][ii] * inv_covariance[ii][j];
        }
    }
    for(i = 0, j = 0; j<7; j++)
    {
        for(ii = 0; ii<7; ii++)
        {
            product += temp[i][j] * sub[j][ii];
        }
    }
    return product;
}*/

static char* load_requestpattern( char* filename, char* result){
    if(node != NULL){
        strcpy(result, "Request Pattern is loaded");
        return "Request Pattern is loaded";
    }   
    FILE* input;
    input = fopen(filename, "rb");
    size_t file_size;
    char* buf;
    char errbuf[1024];
    size_t result_fread;
    if(input == NULL)
        return "[TEST JSON] Can't open file";
    fseek(input, 0, SEEK_END);
    file_size = ftell(input);
    buf = (char*) malloc(sizeof(char) * file_size +1);
    fseek(input, 0, SEEK_SET);
    result_fread = fread(buf, 1, file_size, input);
    buf[file_size] = 0;
    node = yajl_tree_parse((const char *) buf, errbuf, sizeof(errbuf));
    if(node == NULL){
        strcpy(result, errbuf);
        return "JSON err";
    }
    const char * path[] = {"GET/tienda1/global/creditos.jsp", "Host", "metric",(const char *)0};
    yajl_val v = yajl_tree_get(node, path, yajl_t_string);
    char* str = (char*) malloc(1024);
    sprintf(str, "Database size (Request Pattern) = %zu", file_size);
    strcpy(result, str);
    return "TEST_JSON OK";
}

/**
 *
 */

static double get_probility_length(int length_attr, double mean, double variacne ){
    double probability =0;
    mean = mean +2;
    if(length_attr <= mean){
        probability = 1;
    }else{
        probability = variacne / ((length_attr-mean)*(length_attr-mean));
    }
    if(probability > 1){
        probability = 1;
    }
    probability = 1 - probability;

}

static double get_distance_distribution(double *attr_value_cd, double **array_mean_diviation){
    double distance = 0;
    int count = 0;
    for(count = 0; count <6; count++){
        if((attr_value_cd[count] - array_mean_diviation[count][0]) >=0 ){
            distance += (attr_value_cd[count] - array_mean_diviation[count][0])/(array_mean_diviation[count][1] +alpha);
        }else{
            distance -= (attr_value_cd[count] - array_mean_diviation[count][0])/(array_mean_diviation[count][1] +alpha);
        }
    }
    distance = distance /20;
    // if(distance>1){
    //     distance = 1;
    // }
    return distance;
}

/*
static int check_anomal_request(char *url_request, char  *method_request, modsec_rec *msr){
    int key_url_match = 0;
    for(int i=0; i< num_rp; ++i){
        
        key_url = node->u.object.keys[i];
        method_request = node->u.object.values[i];
        n_method_request = method_request->u.object.len;
        msr_log(msr, 4, "%s", key_url);
        if(strcmp(key_url, url_request) ==0){
            // Duyet cac phuong thuc 
            for(int j=0; j<n_method_request; ++j){
                type_param = method_request->u.object.values[j];
                size_t n_type_param = type_param->u.object.len; 
                msr_log(msr, 4,"%s", method_request->u.object.keys[j]);
                if(strcmp(method_request->u.object.keys[j], method_request) == 0){
                    //Duyet cac loai tham so. Co 5 loai la: rest, body, query, header, cookie
                    for(int jj=0; jj< n_type_param; ++jj){
                        msr_log(msr, 4, "TYPE-PARAM %s", type_param->u.object.keys[jj]);
                        attr = type_param->u.object.values[jj];
                        n_attr = attr->u.object.len;
                        // Duyet cac thuoc tinh co trong loai tham so. Vi du: header thuong co "Content, Language"        
                        for(int h =0; h < n_attr; ++h){
                            msr_log(msr, 4, "ATTR: %s",attr->u.object.keys[h] );
                            key_algorithm = attr->u.object.values[h];
                            const char *key_value = malloc(20);
                            
                            if(strcmp(attr->u.object.keys[h], "JSESSIONID") == 0){
                                msr_log(msr, 4, "Tach JSESSIONID");
                                char *attr_value_temp = (char *)apr_table_get(msr->request_headers,"Cookie");
                                msr_log(msr, 4, "%s", attr_value_temp);
                                attr_value = (char*)malloc(strlen(attr_value_temp)-11);
                                memcpy(attr_value, &attr_value_temp[11], strlen(attr_value_temp)-11);
                                attr_value[strlen(attr_value_temp)-11] = '\0';
                                msr_log(msr, 4,"attr-Value :%s", attr_value);
                            }else{
                                attr_value = (char *)apr_table_get(msr->request_headers,attr->u.object.keys[h]);    
                            }
                            if(attr_value != NULL){
                                // Duyet cac thong so cua cac thuat toan. Vi du: Distribution chua mang cac gia tri trung binh va do lech chuan
                                for(int k = 0; k < 3; ++k){
                                    key_value = key_algorithm->u.object.keys[k];
                                    value_algorithm  = key_algorithm->u.object.values[k];
                                    if(strcmp(key_value, "distribution") == 0){
                                        size_t len = value_algorithm->u.array.len;
                                        distribution_array = (double **) calloc(6, sizeof(double));
                                        for(int kk =0; kk < len ; ++kk){
                                            yajl_val obj = value_algorithm->u.array.values[kk];
                                            size_t wide = obj->u.array.len;
                                            distribution_array[kk] = (double*) calloc(2, sizeof(double));
                                            for(int tt = 0; tt < wide; ++tt){
                                                    
                                                yajl_val obj1 = obj->u.array.values[tt];
                                                distribution_array[kk][tt] = obj1->u.number.d;
                                                printf("%lf\n", obj1->u.number.d);
                                                printf("%lf\n", distribution_array[kk][tt] );
                                            }
                                            printf("---------------\n");
                                        }
                                    }
                                    if(strcmp(key_value, "threshold") == 0){
                                        size_t len = value_algorithm->u.object.len;
                                        for(int kk =0; kk < len; ++kk){
                                            const char *key_threshold = value_algorithm->u.object.keys[kk];
                                            if(strcmp(key_threshold, "combined") == 0){
                                                yajl_val obj = value_algorithm->u.object.values[kk];
                                                printf("combined-threshold %lf \n", obj->u.number.d );
                                                combin_threshold = obj->u.number.d;
                                            }
                                            if(strcmp(key_threshold, "length") == 0){
                                                yajl_val obj = value_algorithm->u.object.values[kk];
                                                printf("length-threshold %lf \n", obj->u.number.d );
                                                length_threshold = obj->u.number.d;
                                            }
                                            if(strcmp(key_threshold, "distribution") == 0){
                                                yajl_val obj = value_algorithm->u.object.values[kk];
                                                printf("combined-threshold  %lf \n", obj->u.number.d );
                                                distribution_threshold = obj->u.number.d;
                                            }
                                            
                                               
                                        }
                                    }
                                    if(strcmp(key_value, "length") == 0){
                                        size_t len = value_algorithm->u.array.len;
                                        length = (double *) calloc(2, sizeof(double));
                                        for(int kk =0; kk < len; ++kk){
                                            yajl_val obj = value_algorithm->u.array.values[kk];
                                            printf("length-mean-varian %lf\n", obj->u.number.d );
                                            length[kk] = obj->u.number.d;
                                        }
                                    }    
                                }
                                double probability = 0;
                                // Calculate the probabulity for length model
                                int len_attr_value = strlen(attr_value);
                                probability = get_probility_length(len_attr_value, length[0], length[1] );
                                // Calculate the distance for distribution model
                                double distance = 0;    
                                double *field_value_cd = (double *)calloc(6, sizeof(double));
                                field_value_cd = distribution(attr_value, len_attr_value);                                
                                distance = get_distance_distribution(field_value_cd, distribution_array);
                                //Calculate combine 
                                double combined = distance + probability;
                                if(combined >= combin_threshold && combined!= 0){
                                    msr->response_status = HTTP_BAD_REQUEST;
                                    msr_log(msr, 4, "anormaly because not allow over threshold");
                                    msr_log(msr, 4, "It is an Invalid Request.Deny with code (%d)", HTTP_BAD_REQUEST);
                                    return 1;
                                }
                                msr_log(msr, 4, "COMBINE-RESULT: %lf", combined);
                            }   
                            
                        }    
                    }
                    msr->allow_scope = ACTION_ALLOW_REQUEST;
                    msr->response_status = HTTP_OK;
                    return 0;  
                }
            }
        }else{
            key_url_match = key_url_match + 1;
        }
    }
    if(key_url_match == num_rp){
        msr->response_status = HTTP_BAD_REQUEST;
        msr_log(msr, 4, "anormaly because arg not in pattern");
        msr_log(msr, 4, "It is an Invalid Request.Deny with code (%d)", HTTP_BAD_REQUEST);
        return 1;
    }   
} **/
/**
 *
 */
static apr_status_t modsecurity_process_phase_request_headers(modsec_rec *msr) {

    apr_time_t time_before;
    apr_status_t rc = 0;
    char result[1024];
    load_requestpattern("/usr/src/serverside/profile1.json", result);

    if (msr->txcfg->debuglog_level >= 4) {
        msr_log(msr, 4, "Starting phase REQUEST_HEADERS. lytuan ");
    
    }
    
    // time_before = apr_time_now();

    // if (msr->txcfg->ruleset != NULL) {
        // rc = msre_ruleset_process_phase(msr->txcfg->ruleset, msr);
    // }
    
    // msr->time_phase1 = apr_time_now() - time_before;
    if(msr->txcfg->debuglog_level >= 4){
          msr_log(msr, 4, "START ANALYSIS REQUEST HEADER");
    }
    field_value = (char*)malloc(1024);
    msr_log(msr,4, "Request_line:%s", msr->request_line);
    url = (char*) malloc(strlen(msr->request_uri)+1);
    method_name = (char*) malloc(strlen(msr->request_method)+1);
    strcpy(url, msr->request_uri);
    strcpy(method_name, msr->request_method);
    msr_log(msr,4, "URL:%s", url);
    msr_log(msr,4, "MSR-METHOD:%s", msr->request_method);
    msr_log(msr,4, "MSR-METHOD:%s", method_name);
    msr_log(msr, 4, "So dac trung ban dau cua request den: %d", apr_table_elts(msr->request_headers)->nelts);
    size_t num_rp = node->u.object.len; //so luong mau request
    int h =0,k=0;

//----------------------------------------------------------------------------------------------------------
    if(msr->query_string != NULL){
        arr = apr_table_elts(msr->arguments);
        msr_log(msr, 4, "So luong doi so (header): %d", arr->nelts);
        te = (apr_table_entry_t *)arr->elts;
        for(int i =0; i< arr->nelts; i++){
            msc_arg * arg_header = (msc_arg *)te[i].val;
            msr_log(msr, 4, "PARAM:%s", arg_header->value);            

            // field_value = arg_header->value;
            apr_table_set(msr->request_headers, (char *)arg_header->name, (char *)arg_header->value);
            //Duyet cac duong dan toi tai nguyen
            
            for(h=0; h<num_rp;++h){
                key_url = node->u.object.keys[h];
                method_request = node->u.object.values[h];
                n_method_request = method_request->u.object.len;
                if(strcmp(key_url, url) == 0){
            // Duyet cac phuong thuc 
                    int key_method_match = 0;
                    for(k=0; k<n_method_request; ++k){
                        int key_attr_match = 0;
                        int sum_attr = 0;
                        const char* key_method = method_request->u.object.keys[k];
                        if(strcmp(method_name, key_method) == 0){
                            type_param = method_request->u.object.values[k];
                            size_t n_type_param = type_param->u.object.len; 
                            msr_log(msr, 4,"%s",  method_request->u.object.keys[k]);
            //Duyet cac loai tham so. Co 5 loai la: rest, body, query, header, cookie
                            for(int jj = 0; jj < n_type_param; ++jj){
                                msr_log(msr, 4,"%s",  type_param->u.object.keys[jj]);
                                attr = type_param->u.object.values[jj];
                                n_attr = attr->u.object.len;
                                sum_attr += n_attr;
            // // Duyet cac thuoc tinh co trong loai tham so. Vi du: header thuong co "Content, Language" 
                                if(strcmp(arg_header->name, "Cookie")!=0){
                                    for(int kk =0; kk < n_attr; ++kk){
                                        // msr_log(msr, 4, "%s", attr->u.object.keys[kk]);
                                        const char* key_attr = attr->u.object.keys[kk];
                                        msr_log(msr, 4, "%s - %s", key_attr, arg_header->name);
                                        if(strcmp(key_attr, arg_header->name)!=0){
                                            key_attr_match = key_attr_match+1;
                                        }
                                    }       
                                }
                             
                            }
                            msr_log(msr, 4,"sum_attr: %d, key_attr_match: %d", sum_attr, key_attr_match);
                            if(key_attr_match == sum_attr){
                                msr->response_status = HTTP_BAD_REQUEST;
                                msr_log(msr, 4, "anormaly because arg not in pattern");
                                msr_log(msr, 4, "It is an Invalid Request.Deny with code (%d)", HTTP_BAD_REQUEST);
                                return 1;
                            }    
                        }else{
                            key_method_match = key_method_match+1;
                        }
                    }
                    if(key_method_match == n_method_request){
                        msr->response_status = HTTP_BAD_REQUEST;
                        msr_log(msr, 4, "anormaly because arg not in pattern");
                        msr_log(msr, 4, "It is an Invalid Request.Deny with code (%d)", HTTP_BAD_REQUEST);
                        return 1;
                    }
                }
            }
        }
        apr_table_clear(msr->arguments);
    }
    
    if(apr_table_get(msr->request_headers, "Referer")){
        fields_rq = apr_table_elts(msr->request_headers)->nelts-1;
    }else{
        fields_rq = apr_table_elts(msr->request_headers)->nelts;
    }

//---------------------------------------------------------------------------
    int key_url_match = 0;
    for(int i=0; i< num_rp; ++i){
        
        key_url = node->u.object.keys[i];
        method_request = node->u.object.values[i];
        n_method_request = method_request->u.object.len;
        msr_log(msr, 4, "%s", key_url);
        if(strcmp(key_url, url) ==0){
            // Duyet cac phuong thuc 
            for(int j=0; j<n_method_request; ++j){
                type_param = method_request->u.object.values[j];
                size_t n_type_param = type_param->u.object.len; 
                msr_log(msr, 4,"%s", method_request->u.object.keys[j]);
                if(strcmp(method_request->u.object.keys[j], "GET") == 0){
                    //Duyet cac loai tham so. Co 5 loai la: rest, body, query, header, cookie
                    for(int jj=0; jj< n_type_param; ++jj){
                        msr_log(msr, 4, "TYPE-PARAM %s", type_param->u.object.keys[jj]);
                        attr = type_param->u.object.values[jj];
                        n_attr = attr->u.object.len;
                        // Duyet cac thuoc tinh co trong loai tham so. Vi du: header thuong co "Content, Language"        
                        for(int h =0; h < n_attr; ++h){
                            msr_log(msr, 4, "ATTR: %s",attr->u.object.keys[h] );
                            key_algorithm = attr->u.object.values[h];
                            const char *key_value = malloc(20);
                            
                            if(strcmp(attr->u.object.keys[h], "JSESSIONID") == 0){
                                msr_log(msr, 4, "Tach JSESSIONID");
                                char *attr_value_temp = (char *)apr_table_get(msr->request_headers,"Cookie");
                                msr_log(msr, 4, "%s", attr_value_temp);
                                attr_value = (char*)malloc(strlen(attr_value_temp)-11);
                                memcpy(attr_value, &attr_value_temp[11], strlen(attr_value_temp)-11);
                                attr_value[strlen(attr_value_temp)-11] = '\0';
                                msr_log(msr, 4,"attr-Value :%s", attr_value);
                            }else{
                                attr_value = (char *)apr_table_get(msr->request_headers,attr->u.object.keys[h]);    
                            }
                            if(attr_value != NULL){
                                // Duyet cac thong so cua cac thuat toan. Vi du: Distribution chua mang cac gia tri trung binh va do lech chuan
                                for(int k = 0; k < 3; ++k){
                                    key_value = key_algorithm->u.object.keys[k];
                                    value_algorithm  = key_algorithm->u.object.values[k];
                                    if(strcmp(key_value, "distribution") == 0){
                                        size_t len = value_algorithm->u.array.len;
                                        distribution_array = (double **) calloc(6, sizeof(double));
                                        for(int kk =0; kk < len ; ++kk){
                                            yajl_val obj = value_algorithm->u.array.values[kk];
                                            size_t wide = obj->u.array.len;
                                            distribution_array[kk] = (double*) calloc(2, sizeof(double));
                                            for(int tt = 0; tt < wide; ++tt){
                                                    
                                                yajl_val obj1 = obj->u.array.values[tt];
                                                distribution_array[kk][tt] = obj1->u.number.d;
                                                printf("%lf\n", obj1->u.number.d);
                                                printf("%lf\n", distribution_array[kk][tt] );
                                            }
                                            printf("---------------\n");
                                        }
                                    }
                                    if(strcmp(key_value, "threshold") == 0){
                                        size_t len = value_algorithm->u.object.len;
                                        for(int kk =0; kk < len; ++kk){
                                            const char *key_threshold = value_algorithm->u.object.keys[kk];
                                            if(strcmp(key_threshold, "combined") == 0){
                                                yajl_val obj = value_algorithm->u.object.values[kk];
                                                printf("combined-threshold %lf \n", obj->u.number.d );
                                                combin_threshold = obj->u.number.d;
                                            }
                                            if(strcmp(key_threshold, "length") == 0){
                                                yajl_val obj = value_algorithm->u.object.values[kk];
                                                printf("length-threshold %lf \n", obj->u.number.d );
                                                length_threshold = obj->u.number.d;
                                            }
                                            if(strcmp(key_threshold, "distribution") == 0){
                                                yajl_val obj = value_algorithm->u.object.values[kk];
                                                printf("combined-threshold  %lf \n", obj->u.number.d );
                                                distribution_threshold = obj->u.number.d;
                                            }
                                            
                                               
                                        }
                                    }
                                    if(strcmp(key_value, "length") == 0){
                                        size_t len = value_algorithm->u.array.len;
                                        length = (double *) calloc(2, sizeof(double));
                                        for(int kk =0; kk < len; ++kk){
                                            yajl_val obj = value_algorithm->u.array.values[kk];
                                            printf("length-mean-varian %lf\n", obj->u.number.d );
                                            length[kk] = obj->u.number.d;
                                        }
                                    }    
                                }
                                double probability = 0;
                                // Calculate the probabulity for length model
                                int len_attr_value = strlen(attr_value);
                                probability = get_probility_length(len_attr_value, length[0], length[1] );
                                // Calculate the distance for distribution model
                                double distance = 0;    
                                double *field_value_cd = (double *)calloc(6, sizeof(double));
                                field_value_cd = distribution(attr_value, len_attr_value);                                
                                distance = get_distance_distribution(field_value_cd, distribution_array);
                                //Calculate combine 
                                double combined = distance + probability;
                                if(combined >= combin_threshold && combined!= 0){
                                    msr->response_status = HTTP_BAD_REQUEST;
                                    msr_log(msr, 4, "anormaly because not allow over threshold");
                                    msr_log(msr, 4, "It is an Invalid Request.Deny with code (%d)", HTTP_BAD_REQUEST);
                                    return 1;
                                }
                                msr_log(msr, 4, "COMBINE-RESULT: %lf", combined);
                            }   
                            
                        }    
                    }
                    msr->allow_scope = ACTION_ALLOW_REQUEST;
                    msr->response_status = HTTP_OK;
                    return 0;  
                }
            }
        }else{
            key_url_match = key_url_match + 1;
        }
    }
    if(key_url_match == num_rp){
        msr->response_status = HTTP_BAD_REQUEST;
        msr_log(msr, 4, "anormaly because arg not in pattern");
        msr_log(msr, 4, "It is an Invalid Request.Deny with code (%d)", HTTP_BAD_REQUEST);
        return 1;
    }

//--------------------------------------------------------------------------------
    
    msr->response_status = HTTP_OK;
    msr_log(msr, 4, "IT IS A VALID REQUEST. STATUS CODE (%d)", HTTP_OK);
    return 0;
}

  







/**
*
*/

static apr_status_t modsecurity_process_phase_request_body(modsec_rec *msr) {
    msr_log(msr, 4, "lytuan da them ");
//    apr_time_t time_before;
 //   apr_status_t rc = 0;

/*
    if ((msr->allow_scope == ACTION_ALLOW_REQUEST)||(msr->allow_scope == ACTION_ALLOW)) {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Skipping phase REQUEST_BODY (allow used).");
        }
        
        return 0;
    } else {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Starting phase REQUEST_BODY. Lytuan da them");
        }
    }*/
    // node = msr->node;
    
    field_value = (char*)malloc(1024);
    msr_log(msr,4, "Request_line-PHASE-BODY:%s", msr->request_line);
    url = (char*) malloc(strlen(msr->request_uri) +1);
    method_name = (char*) malloc(strlen(msr->request_method)+1);
    strcpy(url, msr->request_uri);
    strcpy(method_name, msr->request_method);
    msr_log(msr,4, "URL-PHASE-BODY:%s", url);
    size_t num_rp = node->u.object.len;
    int h =0,k=0;
    if(msr->query_string != NULL){
        arr = apr_table_elts(msr->arguments);
        msr_log(msr, 4, "So luong doi so (header)-PHASE_BODY: %d", arr->nelts);
        te = (apr_table_entry_t *)arr->elts;
        for(int i=0; i< arr->nelts; i++){
            msc_arg *arg_body = (msc_arg *)te[i].val;
            msr_log(msr, 4, "Body parameters %d: %s %s", i, arg_body->name, arg_body->value);
            apr_table_set(msr->request_headers, (char *)arg_body->name, (char *)arg_body->value);
                
            
            
            for(h=0; h<num_rp;++h){
                key_url = node->u.object.keys[h];
                method_request = node->u.object.values[h];
                n_method_request = method_request->u.object.len;
                if(strcmp(key_url, url) == 0){
                    int key_method_match = 0;
            // Duyet cac phuong thuc 
                    for(k=0; k<n_method_request; ++k){
                        int key_attr_match = 0;
                        int sum_attr = 0;
                        const char* key_method = method_request->u.object.keys[k];
                        if(strcmp(method_name, key_method) == 0){
                            type_param = method_request->u.object.values[k];
                            size_t n_type_param = type_param->u.object.len; 
                            msr_log(msr, 4,"%s",  method_request->u.object.keys[k]);
            //Duyet cac loai tham so. Co 5 loai la: rest, body, query, header, cookie
                            for(int jj = 0; jj < n_type_param; ++jj){
                                msr_log(msr, 4,"%s",  type_param->u.object.keys[jj]);
                                attr = type_param->u.object.values[jj];
                                n_attr = attr->u.object.len;
                                sum_attr += n_attr;
            // // Duyet cac thuoc tinh co trong loai tham so. Vi du: header thuong co "Content, Language" 
                                if(strcmp(arg_body->name, "Cookie") !=0){
                                    for(int kk =0; kk < n_attr; ++kk){
                                        // msr_log(msr, 4, "%s", attr->u.object.keys[kk]);
                                        const char* key_attr = attr->u.object.keys[kk];
                                        if(strcmp(key_attr, arg_body->name)!=0){
                                            key_attr_match += 1;
                                        }
                                    }    
                                }
                                
                            }
                            if(key_attr_match == sum_attr){
                                msr->response_status = HTTP_BAD_REQUEST;
                                msr_log(msr, 4, "anormaly because arg not in pattern");
                                msr_log(msr, 4, "It is an Invalid Request.Deny with code (%d)", HTTP_BAD_REQUEST);
                                return 1;
                            }    
                        }else{
                            key_method_match = key_method_match+1;
                        }
                    }
                    if(key_method_match == n_method_request){
                        msr->response_status = HTTP_BAD_REQUEST;
                        msr_log(msr, 4, "anormaly because arg not in pattern");
                        msr_log(msr, 4, "It is an Invalid Request.Deny with code (%d)", HTTP_BAD_REQUEST);
                        return 1;
                    }
                }
            }

            
        }
       apr_table_clear(msr->arguments);
    }
    fields_rq = apr_table_elts(msr->request_headers)->nelts;
    msr_log(msr, 4, "So luong dac trung request-PHASE-BODY %d", fields_rq);
    if(apr_table_get(msr->request_headers, "Content-Type")){
        field_value = (char *)apr_table_get(msr->request_headers, "Content-Type");
        msr_log(msr, 4, "Content-Type: %s", field_value);
    }
    if(apr_table_get(msr->request_headers, "Content-Length")){
        field_value = (char *)apr_table_get(msr->request_headers,"Content-Length");
        msr_log(msr, 4, "Content-Length-PHASE-BODY: %s", field_value);
    }
    /*
    time_before = apr_time_now();

    if (msr->txcfg->ruleset != NULL) {
        rc = msre_ruleset_process_phase(msr->txcfg->ruleset, msr);
    }
    
    msr->time_phase2 = apr_time_now() - time_before;

*/ 
    
   if(strcmp(method_name,"POST")==0){
        int key_url_match = 0; // Kiem tra url co trong profile khong
        msr_log(msr, 4,"Da vao day");
        for(i=0; i< num_rp; ++i){
            key_url = node->u.object.keys[i];
            method_request = node->u.object.values[i];
            
            n_method_request = method_request->u.object.len;
            msr_log(msr, 4, "%s", key_url);
            if(strcmp(url, key_url) == 0){
                    // Duyet cac phuong thuc 
                msr_log(msr, 4, "Da Vao so sanh url va key_url");
               for(int j=0; j<n_method_request; ++j){
                    type_param = method_request->u.object.values[j];
                    size_t n_type_param = type_param->u.object.len;
                    if(strcmp(method_request->u.object.keys[j], "POST") == 0){
                       // msr_log(msr, 4, "%s", method_request->u.object.keys[j]);
                // Duyet cac loai tham so. Co 5 loai la: rest, body, query, header, cookie
                        for(int jj=0; jj< n_type_param; ++jj){
                            printf("%s:\t", type_param->u.object.keys[jj]);
                            msr_log(msr, 4, "TYPE-PARAM: %s", type_param->u.object.keys[jj]);
                            attr = type_param->u.object.values[jj];
                            n_attr = attr->u.object.len;
                // Duyet cac thuoc tinh co trong loai tham so. Vi du: header thuong co "Content, Language"        
                            for(int h =0; h < n_attr; ++h){
                                msr_log(msr, 4, "ATTR: %s", attr->u.object.keys[h]);
                                key_algorithm = attr->u.object.values[h];
                                const char *key_value = malloc(20);
                                // attr_value = (char*)malloc(1024);

                                
                                if(strcmp(attr->u.object.keys[h], "JSESSIONID") == 0){
                                    msr_log(msr, 4, "Tach JSESSIONID");
                                    char *attr_value_temp = (char *)apr_table_get(msr->request_headers,"Cookie");
                                    attr_value = (char*) malloc(strlen(attr_value_temp)-11);
                                    memcpy(attr_value, &attr_value_temp[11], strlen(attr_value_temp)-11);
                                    attr_value[strlen(attr_value_temp)-11] = '\0';
                                    msr_log(msr, 4, "%s", attr_value);
                                }else{
                                    attr_value = (char *)apr_table_get(msr->request_headers,attr->u.object.keys[h]);    
                                }
                                
                // Duyet cac thong so cua cac thuat toan. Vi du: Distribution chua mang cac gia tri trung binh va do lech chuan
                                if(attr_value != NULL){
                                    for(int k = 0; k < 3; ++k){
                                        key_value = key_algorithm->u.object.keys[k];
                                        value_algorithm  = key_algorithm->u.object.values[k];
                                        if(strcmp(key_value, "distribution") == 0){
                                            size_t len = value_algorithm->u.array.len;
                                            distribution_array = (double **) calloc(6, sizeof(double));
                                            // deviation = (double *)calloc(6, sizeof(double));
                                            // mean_cd_smd = (double *)calloc(6, sizeof(double));
                                            for(int kk =0; kk < len ; ++kk){
                                                yajl_val obj = value_algorithm->u.array.values[kk];
                                                size_t wide = obj->u.array.len;
                                                distribution_array[kk] = (double *)calloc(2, sizeof(double));
                                                for(int tt = 0; tt < wide; ++tt){
                                                    
                                                    yajl_val obj1 = obj->u.array.values[tt];
                                                    distribution_array[kk][tt] = obj1->u.number.d;

                                                    printf("%lf\n", obj1->u.number.d);
                                                    msr_log(msr, 4, "Distribution-array: %lf", obj1->u.number.d);
                                                }
                                                printf("---------------\n");
                                            }
                                        }
                                        if(strcmp(key_value, "threshold") == 0){
                                            size_t len = value_algorithm->u.object.len;
                                            for(int kk =0; kk < len; ++kk){
                                                const char *key_threshold = value_algorithm->u.object.keys[kk];
                                                if(strcmp(key_threshold, "combined") == 0){
                                                    yajl_val obj = value_algorithm->u.object.values[kk];
                                                    combin_threshold = obj->u.number.d;
                                                    msr_log(msr, 4, "combined-threshold: %lf", obj->u.number.d);
                                                }
                                                if(strcmp(key_threshold, "length") == 0){
                                                    yajl_val obj = value_algorithm->u.object.values[kk];
                                                    length_threshold = obj->u.number.d;
                                                }
                                                if(strcmp(key_threshold, "distribution") == 0){
                                                    yajl_val obj = value_algorithm->u.object.values[kk];
                                                     distribution_threshold = obj->u.number.d;

                                                }
                                                
                                                   
                                            }
                                        }
                                        // Get the value of length algorithm. Length[0] is mean, length[1] is variacne
                                        if(strcmp(key_value, "length") == 0){
                                            size_t len = value_algorithm->u.array.len;
                                            length = (double *) calloc(2, sizeof(double));
                                            for(int kk =0; kk < len; ++kk){
                                                yajl_val obj = value_algorithm->u.array.values[kk];
                                                length[kk] = obj->u.number.d;
                                                msr_log(msr, 4, "length-mean-varian: %lf", obj->u.number.d);
                                            }
                                        }    
                                    }
                                    
                                }
                                double probability = 0;
                                // Calculate the probabulity for length model
                                int len_attr_value = strlen(attr_value);
                                probability = get_probility_length(len_attr_value, length[0], length[1] );
                                // Calculate the distance for distribution model
                                double distance = 0;    
                                double *field_value_cd = (double *)calloc(6, sizeof(double));
                                field_value_cd = distribution(attr_value, len_attr_value);                                
                                distance = get_distance_distribution(field_value_cd, distribution_array);
                                //Calculate combine 
                                double combined = distance + probability;
                                if(combined >= combin_threshold && combined!= 0){
                                    msr->response_status = HTTP_BAD_REQUEST;
                                    msr_log(msr, 4, "anormaly because not allow over threshold");
                                    msr_log(msr, 4, "It is an Invalid Request.Deny with code (%d)", HTTP_BAD_REQUEST);
                                    return 1;
                                }
                                msr_log(msr, 4, "COMBINE-RESULT: %lf", combined);
                                
                            }    
                          
                        }
                        msr->allow_scope = ACTION_ALLOW_REQUEST;
                        msr->response_status = HTTP_OK;
                        return 0; 

                    } 
                    
               }
            }else{
                key_url_match = key_url_match+1;
            }
        }
        if(key_url_match == num_rp){
            msr->response_status = HTTP_BAD_REQUEST;
            msr_log(msr, 4, "anormaly because arg not in pattern");
            msr_log(msr, 4, "It is an Invalid Request.Deny with code (%d)", HTTP_BAD_REQUEST);
            return 1;
        }

    }
    msr->response_status = HTTP_OK;
    msr_log(msr, 4, "IT IS A VALID REQUEST. phase_request_body STATUS CODE (%d)", HTTP_OK);
    return 0;

}

/**
*
*/



/**
 *
 */
static apr_status_t modsecurity_process_phase_response_headers(modsec_rec *msr) {
/*    apr_time_t time_before;
    apr_status_t rc = 0;
    
    if (msr->allow_scope == ACTION_ALLOW) {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Skipping phase RESPONSE_HEADERS (allow used).");
        }
        
        return 0;
    } else {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Starting phase RESPONSE_HEADERS. lytuan da them");
        }
    }
    
    time_before = apr_time_now();

    if (msr->txcfg->ruleset != NULL) {
        rc = msre_ruleset_process_phase(msr->txcfg->ruleset, msr);
    }
    
    msr->time_phase3 = apr_time_now() - time_before;

    return rc;
*/
return 0;
}

/**
 *
 */
static apr_status_t modsecurity_process_phase_response_body(modsec_rec *msr) {
/*    apr_time_t time_before;
    apr_status_t rc = 0;
    
    if (msr->allow_scope == ACTION_ALLOW) {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Skipping phase RESPONSE_BODY (allow used).");
        }
        
        return 0;
    } else {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Starting phase RESPONSE_BODY. lytuan da them ");
        }
    }
    
    time_before = apr_time_now();

    if (msr->txcfg->ruleset != NULL) {
        rc = msre_ruleset_process_phase(msr->txcfg->ruleset, msr);
    }
    
    msr->time_phase4 = apr_time_now() - time_before;


    return rc;
*/
return 0;
}

/**
 *
 */
static apr_status_t modsecurity_process_phase_logging(modsec_rec *msr) {
    apr_time_t time_before, time_after;

    if (msr->txcfg->debuglog_level >= 4) {
        msr_log(msr, 4, "Starting phase LOGGING. lytuan da them");
    }
    
    time_before = apr_time_now();

    if (msr->txcfg->ruleset != NULL) {
        msre_ruleset_process_phase(msr->txcfg->ruleset, msr);
    }
    
    modsecurity_persist_data(msr);
    
    time_after = apr_time_now();
    msr->time_phase5 = time_after - time_before;

    /* Is this request relevant for logging purposes? */
    if (msr->is_relevant == 0) {
        /* Check the status */
        msr->is_relevant += is_response_status_relevant(msr, msr->r->status);

        /* If we processed two requests and statuses are different then
         * check the other status too.
         */
        if (msr->r_early->status != msr->r->status) {
            msr->is_relevant += is_response_status_relevant(msr, msr->r_early->status);
        }
    }

    /* Figure out if we want to keep the files (if there are any, of course). */
    if ((msr->txcfg->upload_keep_files == KEEP_FILES_ON)
        || ((msr->txcfg->upload_keep_files == KEEP_FILES_RELEVANT_ONLY)&&(msr->is_relevant)))
    {
        msr->upload_remove_files = 0;
    } else {
        msr->upload_remove_files = 1;
    }

    /* Are we configured for audit logging? */
    switch(msr->txcfg->auditlog_flag) {
        case AUDITLOG_OFF :
            if (msr->txcfg->debuglog_level >= 4) {
                msr_log(msr, 4, "Audit log: Not configured to run for this request.");
            }
            
            return DECLINED;
            break;

        case AUDITLOG_RELEVANT :
            if (msr->is_relevant == 0) {
                if (msr->txcfg->debuglog_level >= 4) {
                    msr_log(msr, 4, "Audit log: Ignoring a non-relevant request.");
                }
                
                return DECLINED;
            }
            break;

        case AUDITLOG_ON :
            /* All right, do nothing */
            break;

        default :
            msr_log(msr, 1, "Internal error: Could not determine if auditing is needed, so forcing auditing.");
            break;
    }

    /* Invoke the Audit logger */
    if (msr->txcfg->debuglog_level >= 4) {
        msr_log(msr, 4, "Audit log: Logging this transaction.");
    }

    sec_audit_logger(msr);
    
    msr->time_logging = apr_time_now() - time_after;    

    return 0;
}

/**
 * Processes one transaction phase. The phase number does not
 * need to be explicitly provided since it's already available
 * in the modsec_rec structure.
 */
apr_status_t modsecurity_process_phase(modsec_rec *msr, unsigned int phase) {
    /* Check if we should run. */
    if ((msr->was_intercepted)&&(phase != PHASE_LOGGING)) {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Skipping phase %d as request was already intercepted.", phase);
        }
        
        return 0;
    }

    /* Do not process the same phase twice. */
    if (msr->phase >= phase) {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Skipping phase %d because it was previously run (at %d now).",
                phase, msr->phase);
        }
        
        return 0;
    }

    msr->phase = phase;

    /* Clear out the transformation cache at the start of each phase */
    if (msr->txcfg->cache_trans == MODSEC_CACHE_ENABLED) {
        if (msr->tcache) {
            apr_hash_index_t *hi;
            void *dummy;
            apr_table_t *tab;
            const void *key;
            apr_ssize_t klen;
            #ifdef CACHE_DEBUG
            apr_pool_t *mp = msr->msc_rule_mptmp;
            const apr_array_header_t *ctarr;
            const apr_table_entry_t *ctelts;
            msre_cache_rec *rec;
            int cn = 0;
            int ri;
            #else
            apr_pool_t *mp = msr->mp;
            #endif

            for (hi = apr_hash_first(mp, msr->tcache); hi; hi = apr_hash_next(hi)) {
                apr_hash_this(hi, &key, &klen, &dummy);
                tab = (apr_table_t *)dummy;

                if (tab == NULL) continue;

                #ifdef CACHE_DEBUG
                /* Dump the cache out as we clear */
                ctarr = apr_table_elts(tab);
                ctelts = (const apr_table_entry_t*)ctarr->elts;
                for (ri = 0; ri < ctarr->nelts; ri++) {
                    cn++;
                    rec = (msre_cache_rec *)ctelts[ri].val;
                    if (rec->changed) {
                        if (msr->txcfg->debuglog_level >= 9) {
                            msr_log(msr, 9, "CACHE: %5d) hits=%d key=%pp %x;%s=\"%s\" (%pp - %pp)",
                                cn, rec->hits, key, rec->num, rec->path, log_escape_nq_ex(mp, rec->val, rec->val_len),
                                rec->val, rec->val + rec->val_len);
                        }
                    }
                    else {
                        if (msr->txcfg->debuglog_level >= 9) {
                            msr_log(msr, 9, "CACHE: %5d) hits=%d key=%pp %x;%s=<no change>",
                                cn, rec->hits, key, rec->num, rec->path);
                        }
                    }
                }
                #endif

                apr_table_clear(tab);
                apr_hash_set(msr->tcache, key, klen, NULL);
            }

            if (msr->txcfg->debuglog_level >= 9) {
                msr_log(msr, 9, "Cleared transformation cache for phase %d", msr->phase);
            }
        }

        msr->tcache_items = 0;
        msr->tcache = apr_hash_make(msr->mp);
        if (msr->tcache == NULL) return -1;
    }

    switch(phase) {
        case 1 :
            return modsecurity_process_phase_request_headers(msr);
        case 2 :
            return modsecurity_process_phase_request_body(msr);
        case 3 :
            return modsecurity_process_phase_response_headers(msr);
        case 4 :
            return modsecurity_process_phase_response_body(msr);
        case 5 :
            return modsecurity_process_phase_logging(msr);
        default :
            msr_log(msr, 1, "Invalid processing phase: %d", msr->phase);
            break;
    }

    return -1;
}
