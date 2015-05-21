/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ap_config.h"
#include "ap_mmn.h"
#include "httpd.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_log.h"


#include "apr_hash.h"
#include "apr_errno.h"
#include "apr_xml.h"

#include "util_filter.h"

module AP_MODULE_DECLARE_DATA wurfl_module;

typedef struct {
	int state;
    apr_xml_doc *wurfl_db;
    apr_hash_t *device_hash;
    const char* mobile_env;
    const char* tablet_env;
} WurflConfig;

typedef struct {
	int is_mobile;
	int is_tablet;
} DeviceInfo;

static void *create_wurlf_server_config(apr_pool_t *p, server_rec *s)
{
    WurflConfig *sconf = apr_pcalloc(p, sizeof *sconf);

    sconf->state = 0;
    sconf->wurfl_db = NULL;
    sconf->device_hash = apr_hash_make(p);


    return (void *)sconf;
}

char *get_mobile_browser_value(apr_xml_elem *e) {
	apr_xml_attr *attr;

	attr = e->attr;
	while (attr) {
		if ( strcmp(attr->name, "value") == 0 ) {
			return (char *)attr->value;
		}
	attr = attr->next;
	}
	return NULL;
}

char *get_user_agent(apr_xml_elem *e) {
	apr_xml_attr *attr;

	attr = e->parent->parent->attr;
	while (attr) {
		if ( strcmp(attr->name, "user_agent") == 0 ) {
			return (char *)attr->value;
		}
	attr = attr->next;
	}
	return NULL;
}

int is_tablet(apr_xml_elem *e) {
	apr_xml_attr *attr;

	attr = e->attr;
	while (attr) {
		if ( strcmp(attr->name, "value") == 0 ) {
			if ( strcmp(attr->value, "false") ==0 ) {
				return FALSE;
			}
			if ( strcmp(attr->value, "true") ==0 ) {
				return TRUE;
			}
		}
	attr = attr->next;
	}
	return FALSE;
}

static void iterate_xml(apr_pool_t *p, apr_xml_elem *e, apr_hash_t *device_hash) {
	apr_xml_elem *child_element, *device;
	apr_xml_attr *attr, *attr2;
	DeviceInfo *device_info;
	int tablet;
	char *mobile_browser;
	char *user_agent = NULL;

	if ( e->first_child ) {
		child_element = e->first_child;

		while (child_element) {
			if ( strcmp(child_element->name, "capability") == 0 ) {
				if (child_element->attr) {
					attr = child_element->attr;
					device_info = apr_palloc(p, sizeof(device_info));
					device_info->is_mobile = FALSE;
					device_info->is_tablet = FALSE;
					while (attr) {
						if ( strcmp(attr->value, "mobile_browser") == 0 ) {
								mobile_browser = get_mobile_browser_value(child_element);
								user_agent = get_user_agent(child_element);
								device_info->is_mobile=TRUE;
						}
						if ( strcmp(attr->value, "is_tablet") == 0 ) {
							tablet = is_tablet(child_element);
							user_agent = get_user_agent(child_element);
							device_info->is_tablet=tablet;
							device_info->is_mobile=TRUE; // all tablets are also mobile
						}
						attr = attr->next;
					}
					if ( user_agent != NULL && ( strcmp(user_agent,"") != 0 )) {
						if ( device_info->is_mobile ) {
							apr_hash_set(device_hash, user_agent, APR_HASH_KEY_STRING, device_info);
							// ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL , "UA: %s, mobile_browser: %s, is_mobile: %d, is_tablet: %d", user_agent, mobile_browser, device_info->is_mobile, device_info->is_tablet );
						}
					}
				}
			}
			iterate_xml(p, child_element, device_hash);
			child_element = child_element->next;
		}
	}
}

static const char *cmd_wurfldb(cmd_parms *cmd, void *dconf, const char *arg1)
{
	WurflConfig *sconf;
	apr_file_t *xmlfile;
	apr_status_t fopen_status, xmlparse_status;
	apr_xml_parser *xmlparser;
	apr_xml_doc *xmldoc;
	apr_time_t start, end, diff;
	apr_xml_elem *child_element, *parent;
	int level = 0;

    if (cmd->path == NULL) {  /* is server command */


    	sconf = ap_get_module_config(cmd->server->module_config, &wurfl_module);

    	fopen_status = apr_file_open(&xmlfile, arg1, APR_READ, APR_OS_DEFAULT, cmd->pool);

		if( fopen_status != APR_SUCCESS )
		{
		  char errbuf[1024] = {0};
		  char *errstr;
		  errstr = apr_strerror( fopen_status, errbuf, sizeof(errbuf) );
		  ap_log_error(APLOG_MARK, APLOG_ERR, xmlparse_status, cmd->server , "Error opening WURFL xml file: %s", errstr);
		  return NULL;
		}

		xmlparser = apr_xml_parser_create(cmd->pool);

		start = apr_time_now();
		xmlparse_status = apr_xml_parse_file(cmd->pool, &xmlparser, &xmldoc, xmlfile, 2000);

		if( xmlparse_status != APR_SUCCESS )
		{
		  if ( xmlparser == NULL ) {
			  ap_log_error(APLOG_MARK, APLOG_ERR, xmlparse_status, cmd->server , "Error initializing xmlparser");
		  } else {
			  char errbuf[1024] = {0};
			  char *errstr;
			  errstr = apr_xml_parser_geterror( xmlparser, errbuf, sizeof(errbuf) );
			  ap_log_error(APLOG_MARK, APLOG_ERR, xmlparse_status, cmd->server , "Error parsing WURFL xml file: %s", errstr);
		  }
		  return NULL;
		}
		end = apr_time_now();
		diff = end - start;

		// ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL , "Parsing WURFL xml file took %d microseconds", diff);

		start = apr_time_now();
		if (xmldoc->root) {
	        iterate_xml(cmd->pool, xmldoc->root, sconf->device_hash);
		}
		end = apr_time_now();
		diff = end - start;

		unsigned int hash_count = apr_hash_count(sconf->device_hash);

		// ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL , "Intializing device_hash took %d microseconds and has %d entries", diff, hash_count);

		sconf->wurfl_db = xmldoc;
    }

    return NULL;
}


static const char *cmd_wurflmobileenv(cmd_parms *cmd, void *dconf, const char *arg1)
{
	WurflConfig *sconf;

    sconf = ap_get_module_config(cmd->server->module_config, &wurfl_module);

    if ( arg1 != NULL) {
    	sconf->mobile_env = arg1;
    } else {
    	sconf->mobile_env = "MOBILEHOST";
    }

    return NULL;
}

static const char *cmd_wurfltabletenv(cmd_parms *cmd, void *dconf, const char *arg1)
{
	WurflConfig *sconf;

    sconf = ap_get_module_config(cmd->server->module_config, &wurfl_module);

    if ( arg1 != NULL) {
    	sconf->tablet_env = arg1;
    } else {
    	sconf->tablet_env = "TABLETHOST";
    }

    return NULL;
}

static const char *cmd_wurflengine(cmd_parms *cmd,
                                     void *in_dconf, int flag)
{
	WurflConfig *sconf;

    sconf = ap_get_module_config(cmd->server->module_config, &wurfl_module);

    sconf->state = flag;

    // set default values for WurflMobileEnv and WurflTabletEnv
    cmd_wurflmobileenv(cmd, in_dconf, NULL);
    cmd_wurfltabletenv(cmd, in_dconf, NULL);

    return NULL;
}

static int wurfl_match_headers(request_rec *r)
{
    WurflConfig *sconf;
    const char *user_agent;
    DeviceInfo *device_info;

    sconf = ap_get_module_config(r->server->module_config, &wurfl_module);
    // WurflEnable is off
    if (!sconf->state) {
        return DECLINED;
    }
    user_agent = apr_table_get(r->headers_in, "User-Agent");
	// ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server , "User-Agent is %s", user_agent);
    if (user_agent!=NULL) {
        device_info = apr_hash_get(sconf->device_hash, user_agent, APR_HASH_KEY_STRING);
        if ( device_info != NULL) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server , "Found hash entry for %s MOBILE: %d TABLET: %d", user_agent, device_info->is_mobile, device_info->is_tablet);
            apr_table_setn(r->subprocess_env, sconf->mobile_env, "true");
  
            if ( device_info->is_tablet ) {
                apr_table_setn(r->subprocess_env, sconf->mobile_env, "true");
            }
        }
    } else {
    	// ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server , "No entry found for UA: %s", user_agent);
    }

    return DECLINED;
}


static const command_rec wurfl_cmds[] =
{
    AP_INIT_FLAG("WurflEnable", cmd_wurflengine, NULL, RSRC_CONF,
                 "On or off to enable the whole WURFL module"),
    AP_INIT_TAKE1("WurflDBFile", cmd_wurfldb, NULL, RSRC_CONF,
                 "the filename of the WURFL-DB xml file"),
    AP_INIT_TAKE1("WurflMobileEnv", cmd_wurflmobileenv, NULL, RSRC_CONF,
    			"ENV to set for mobile user agents"),
    AP_INIT_TAKE1("WurflTabletEnv", cmd_wurfltabletenv, NULL, RSRC_CONF,
    		   	 "ENV to set for tablet user agents"),

    { NULL }
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_header_parser(wurfl_match_headers, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA wurfl_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    create_wurlf_server_config,  /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    wurfl_cmds,                  /* command apr_table_t */
    register_hooks              /* register hooks */
};
