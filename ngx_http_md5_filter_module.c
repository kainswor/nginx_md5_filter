/* 
 * This module provides an MD5 "filter" which when enabled emits an MD5 digest,
 * and when disabled, bypasses at no added cost.
 *
 * Note: It only works on full requests, which nginx would've served with status == 200
 * 
 * Header Filter:
 *  Content-Length=32
 *  Content-Type="text/plain"
 *
 * Body Filter:
 *  Emits only 32byte hexdigest
 *
 * Keith Ainsworth, keith@hulu.com, 2013
 */

#include<ngx_config.h>
#include<ngx_core.h>
#include<ngx_http.h>
#include<ngx_md5.h>
//sprintf
#include<stdio.h>

static ngx_int_t ngx_http_md5_filter_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_md5_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_md5_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static void * ngx_http_md5_filter_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_md5_filter_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

// module conf type
typedef struct{
    ngx_flag_t enable;
} ngx_http_md5_filter_loc_conf_t;

// Module config-file language
// md5_filter on|off;
static ngx_command_t ngx_http_md5_filter_commands[] = {
    {
        ngx_string("md5_filter"),                           //name
        NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,                    //type (use in location, on/off)
        ngx_conf_set_flag_slot,                             //set method (set the flag)
        NGX_HTTP_LOC_CONF_OFFSET,                           //save in location conf
        offsetof(ngx_http_md5_filter_loc_conf_t, enable),   //where it goes
        NULL                                                //nginx magic var
    },
    ngx_null_command    //nginx magic var
};

//module context
static ngx_http_module_t ngx_http_md5_filter_module_ctx = {
    NULL,                           //preconf
    ngx_http_md5_filter_init,       //postconf
    
    NULL,       //create main conf
    NULL,       //init main conf

    NULL,       //create server conf
    NULL,       //merge server conf

    ngx_http_md5_filter_create_loc_conf,
    ngx_http_md5_filter_merge_loc_conf
};

// Methods to init the module
static ngx_int_t ngx_http_md5_filter_init(ngx_conf_t *cf) {
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_md5_body_filter;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_md5_header_filter;

    return NGX_OK;
}

// Initialize the config for handling
static void* ngx_http_md5_filter_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_md5_filter_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_md5_filter_loc_conf_t));
    if(conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->enable = NGX_CONF_UNSET;
    return conf;
}

// For merging the actual specified config
static char* ngx_http_md5_filter_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_md5_filter_loc_conf_t *prev = parent;
    ngx_http_md5_filter_loc_conf_t *conf = child;
    
    //Take the current locations value over the parent locations value, and unset if neither
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    if(conf->enable != 1 && conf->enable != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "MD5 Filter must be enabled or disabled");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

//nginx magic
ngx_module_t ngx_http_md5_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_md5_filter_module_ctx,
    ngx_http_md5_filter_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

// Simple header filter which sets the Content-Length to 32
// and the Content-Type to 'text/plain'
static ngx_int_t ngx_http_md5_header_filter(ngx_http_request_t *r)
{
    ngx_http_md5_filter_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_md5_filter_module);

    if((!conf->enable) ||
       (r->headers_out.status != NGX_HTTP_OK)) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Bypassed");
        return ngx_http_next_header_filter(r);
    }
    
    //X-Content-Length = original Content-Length
    ngx_table_elt_t *x_content_length = ngx_list_push(&r->headers_out.headers);
    x_content_length->hash = 1;
    x_content_length->key.len = sizeof("X-Content-Length") - 1;
    x_content_length->key.data = (u_char*) "X-Content-Length";
    x_content_length->value.data = ngx_pcalloc(r->pool, 32);
    x_content_length->value.len = snprintf((char*)x_content_length->value.data, 31, "%d", (int)r->headers_out.content_length_n);

    r->headers_out.content_length_n = 32;
    r->headers_out.content_type.data = (u_char*) "text/plain";
    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Adjusted the response headers");
    return ngx_http_next_header_filter(r);
}

// Body filter enabled emits only a 32 byte digest
static ngx_int_t ngx_http_md5_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{    
    ngx_http_md5_filter_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_md5_filter_module);
    if((!conf->enable) ||
       (r->headers_out.status != NGX_HTTP_OK)) {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_md5_t *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_md5_filter_module);
    if(ctx==NULL) {
        // No context implies first run
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_md5_t));
        if(ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_md5_filter_module);
        ngx_md5_init(ctx);
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "MD5 Filter: Initialized MD5 context");
    }

    ngx_chain_t *it;
    for(it = in; it; it = it->next) {
        if(it->buf->last == it->buf->pos) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "MD5 Filter: Skipping empty buffer");
        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "MD5 Filter: Updating %db\n", (int)(it->buf->last - it->buf->pos));
            ngx_md5_update(ctx, it->buf->pos, it->buf->last - it->buf->pos);
        }
        // mark as sent to client so nginx is happy 
        it->buf->pos = it->buf->last;
        
        if(it->buf->last_buf) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "MD5 Filter: Finalizing");
            it->buf->last_buf = 0;
            // Make a buffer with the digest
            ngx_chain_t *rc = ngx_alloc_chain_link(r->pool);
            if(rc == NULL ) {
                return NGX_ERROR;
            }
            rc->next = NULL;
            rc->buf = ngx_calloc_buf(r->pool);
            if(rc->buf == NULL) {
                return NGX_ERROR;
            }
            rc->buf->memory = 1;
            rc->buf->last_buf = 1;
            rc->buf->pos = (u_char*) ngx_pcalloc(r->pool, 32);
            if(rc->buf->pos == NULL) {
                return NGX_ERROR;
            }
            rc->buf->last = rc->buf->pos + 32;
            u_char tmpbuf[16];
            ngx_md5_final(tmpbuf, ctx);
            u_char* ptr = rc->buf->pos;
            int i;
            for(i = 0; i < 16; i++) {
                ptr += sprintf((char*)ptr, "%02x", tmpbuf[i]);
            }
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Hash digest: %s", rc->buf->pos);
            // Link into the buffer chain
            return ngx_http_next_body_filter(r, rc);
        }
    }
    return ngx_http_next_body_filter(r, NULL);
}
