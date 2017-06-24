
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static void ngx_http_read_client_request_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_do_read_client_request_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_write_request_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_read_discarded_request_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_discard_request_body_filter(ngx_http_request_t *r,
    ngx_buf_t *b);
static ngx_int_t ngx_http_test_expect(ngx_http_request_t *r);

static ngx_int_t ngx_http_request_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_request_body_length_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_request_body_chunked_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
//HTTP包体的长度有可能非常大，如果试图一次性调用并读取完所有的包体，那么多半会阻塞Nginx进程。HTTP框架提供了一种方法来异步地接收包体：
/*
ngx_http_read_client_request_body是一个异步方法，调用它只是说明要求Nginx开始接收请求的包体，并不表示是否已经接收完，当接收完所有的包体内容后，
post_handler指向的回调方法会被调用。因此，即使在调用了ngx_http_read_client_request_body方法后它已经返回，也无法确定这时是否已经调用过post_handler
指向的方法。换句话说，ngx_http_read_client_request_body返回时既有可能已经接收完请求中所有的包体（假如包体的长度很小），也有可能还没开始接收包体。
如果ngx_http_read_client_request_body是在ngx_http_mytest_handler处理方法中调用的，那么后者一般要返回NGX_DONE，因为下一步就是将它的返回值作为参数
传给ngx_http_finalize_request。 
*/

/*
        这里开辟真正的读取数据的空间后，buf的指针指向终端空间的头尾以及解析完的数据的位置，
                    buf1                       buf2                    buf3
        _________________________________________________________________________________
        |                          |                         |                           |
        |__________________________|_________________________|___________________________|
        
     1.第一次开辟好存储数据的空间ngx_create_temp_buf后，r->request_body->buf pos last start指向buf1的头部，end指向buf3尾部
     
     2.假设第一次读取完内核协议栈的数据后填充好了buf1,r->request_body->buf中的pos start指向buf1的头部，last指向buf1尾部(buf2头部)，end指向buf3尾部

     3.开始调用ngx_http_request_body_filter，在该函数里面会重新分配一个ngx_buf_t，把r->request_body->buf成员赋值给她。然后把这个新的ngx_buf_t
     添加到r->request_body->bufs链表中。赋值完后r->request_body->buf中的start指向buf1的头部，pos last指向buf1尾部(buf2头部)，end指向buf3尾部

     4.从复上面的2 3步骤

     5.当解析完buf3的内容后，发现r->request_body->buf从内核读取到buf空间中的网络数据包已经被三个新的ngx_buf_t指向，并且这三个ngx_buf_t
       通过r->request_body->bufs链表连接在了一起，这时候r->request_body->buf中的end = last,也就是所有ngx_create_temp_buf开辟的内存空间
       已经存满了(recv的数据存在该空间里面)，并且数据分成三个ngx_buf_t指向这些空间，然后连接到了转存到了r->request_body->bufs链表上。在

     6.ngx_http_request_body_save_filter中检测到rb->buf->last == rb->buf->end，上面的buf(buf1+buf2+buf3)已经填满，然后通过r->request_body->bufs
       把三个ngx_buf_t指向的内存空间一次性写入临时文件，写入临时文件后，r->request_body->buf中的pos last指针重新指向头部，又可以从新从
       内核协议栈读取数据存储在里面了，
       然后从复1-5的过程
*/

ngx_int_t
ngx_http_read_client_request_body(ngx_http_request_t *r,
    ngx_http_client_body_handler_pt post_handler)
{// post_handler 通常是ngx_http_read_client_request_body_handler
    size_t                     preread;
    ssize_t                    size;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t                out;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;
	/*
     首先把该请求对应的原始请求的引用计数加l。这同时是在要求每一个HTTP模块在传入的post_handler方法被回调时，务必调用类似
     ngx_http_finalize_request的方法去结束请求，否则引用计数会始终无法清零，从而导致请求无法释放。
     */
    r->main->count++;	//	引用计数+1
	//	子请求不需要自己去读取请求体
    if (r != r->main || r->request_body || r->discard_body) {
        r->request_body_no_buffering = 0;
        post_handler(r);
        return NGX_OK;
    }

#if (NGX_HTTP_V2)
    if (r->stream) {
        rc = ngx_http_v2_read_request_body(r, post_handler);
        goto done;
    }
#endif

    if (ngx_http_test_expect(r) != NGX_OK) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }
	//	为请求的http body申请内存
    rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (rb == NULL) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     rb->bufs = NULL;
     *     rb->buf = NULL;
     *     rb->free = NULL;
     *     rb->busy = NULL;
     *     rb->chunked = NULL;
     */

    rb->rest = -1;
    rb->post_handler = post_handler;

    r->request_body = rb;
	//	如果content length小于0 并且是chunk编码方式 则不需要接收body
    if (r->headers_in.content_length_n < 0 && !r->headers_in.chunked) {
        r->request_body_no_buffering = 0;
        post_handler(r);
        return NGX_OK;
    }
	/* 接收HTTP头部的流程中，是有可能接收到HTTP包体的。首先我们需要检查在header_in缓冲区中已经接收到的包体长度，确定其是否大于或者等于
content-length头部指定的长度，如果大干或等于则说明已经接收到完整的包体 */
    preread = r->header_in->last - r->header_in->pos;

    if (preread) {

        /* there is the pre-read part of the request body */

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http client request body preread %uz", preread);
		//	当前ngx_chain_t结构体out只有header_in这一个buf缓冲区
        out.buf = r->header_in;
        out.next = NULL;
		//把最新读取到的buf数据添加到r->request_body->bufs中，并且让free指向该bufs中所有数据中已经解析了的数据节点信息(重复利用ngx_buf_t)
        //busy链表中的ngx_buf_t节点指向bufs中所有数据中还没有解析完毕的数据
        rc = ngx_http_request_body_filter(r, &out);

        if (rc != NGX_OK) {
            goto done;
        }

        r->request_length += preread - (r->header_in->last - r->header_in->pos);

        if (!r->headers_in.chunked
            && rb->rest > 0	//	还需要接收body
            && rb->rest <= (off_t) (r->header_in->end - r->header_in->last))
        {
            /* the whole request body may be placed in r->header_in */
			//	r->header_in剩余空间可以完全存储剩余的body数据
            b = ngx_calloc_buf(r->pool);
            if (b == NULL) {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                goto done;
            }
			//	利用r->header_in中剩余的空间作为一个buf来接收剩下所有的body数据
            b->temporary = 1;
            b->start = r->header_in->pos;
            b->pos = r->header_in->pos;
            b->last = r->header_in->last;
            b->end = r->header_in->end;

            rb->buf = b;	//	rb->buf是当前正在接收body的缓冲区 buf是rb->bufs链表中的一个 

            r->read_event_handler = ngx_http_read_client_request_body_handler;
            r->write_event_handler = ngx_http_request_empty_handler;
			//	接收包体
            rc = ngx_http_do_read_client_request_body(r);
            goto done;
        }

    }
	else 
	{	//	header_in中没有body数据
        /* set rb->rest */

        if (ngx_http_request_body_filter(r, NULL) != NGX_OK) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto done;
        }
    }

    if (rb->rest == 0) {	//	没有需要接收的数据了
        /* the whole request body was pre-read */
        r->request_body_no_buffering = 0;
        post_handler(r);
        return NGX_OK;
    }

    if (rb->rest < 0) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "negative request body rest");
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    size = clcf->client_body_buffer_size;	//	提取出配置文件中client_body_buffer_size的大小
    size += size >> 2;

    /* TODO: honor r->request_body_in_single_buf */

    if (!r->headers_in.chunked && rb->rest < size) {
        size = (ssize_t) rb->rest;

        if (r->request_body_in_single_buf) {
            size += preread;
        }

    } else {
        size = clcf->client_body_buffer_size;
    }

    rb->buf = ngx_create_temp_buf(r->pool, size);	//	为request body申请buf缓冲区
    if (rb->buf == NULL) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    r->read_event_handler = ngx_http_read_client_request_body_handler;
    r->write_event_handler = ngx_http_request_empty_handler;

    rc = ngx_http_do_read_client_request_body(r);

done:

    if (r->request_body_no_buffering
        && (rc == NGX_OK || rc == NGX_AGAIN))
    {
        if (rc == NGX_OK) {
            r->request_body_no_buffering = 0;

        } else {
            /* rc == NGX_AGAIN */
            r->reading_body = 1;
        }

        r->read_event_handler = ngx_http_block_reading;	//	由于已经读完了body 不需要再读了 将读事件阻塞住 什么都不做
        post_handler(r);
    }

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        r->main->count--;
    }

    return rc;
}


ngx_int_t
ngx_http_read_unbuffered_request_body(ngx_http_request_t *r)
{
    ngx_int_t  rc;

#if (NGX_HTTP_V2)
    if (r->stream) {
        rc = ngx_http_v2_read_unbuffered_request_body(r);

        if (rc == NGX_OK) {
            r->reading_body = 0;
        }

        return rc;
    }
#endif

    if (r->connection->read->timedout) {
        r->connection->timedout = 1;
        return NGX_HTTP_REQUEST_TIME_OUT;
    }

    rc = ngx_http_do_read_client_request_body(r);

    if (rc == NGX_OK) {
        r->reading_body = 0;
    }

    return rc;
}


static void
ngx_http_read_client_request_body_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    if (r->connection->read->timedout) {
        r->connection->timedout = 1;
        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    rc = ngx_http_do_read_client_request_body(r);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_http_finalize_request(r, rc);
    }
}

/*
 * ngx_http_read_client_request_body_handler
 * 和
 * ngx_http_read_client_request_body
 * 的共同部分
*/
static ngx_int_t
ngx_http_do_read_client_request_body(ngx_http_request_t *r)
{
    off_t                      rest;
    size_t                     size;
    ssize_t                    n;
    ngx_int_t                  rc;
    ngx_chain_t                out;
    ngx_connection_t          *c;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;
    rb = r->request_body;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http read client request body");

    for ( ;; ) {
        for ( ;; ) {
            if (rb->buf->last == rb->buf->end) {

                if (rb->buf->pos != rb->buf->last) {

                    /* pass buffer to request body filter chain */

                    out.buf = rb->buf;
                    out.next = NULL;

                    rc = ngx_http_request_body_filter(r, &out);

                    if (rc != NGX_OK) {
                        return rc;
                    }

                } else {

                    /* update chains */

                    rc = ngx_http_request_body_filter(r, NULL);

                    if (rc != NGX_OK) {
                        return rc;
                    }
                }

                if (rb->busy != NULL) {
                    if (r->request_body_no_buffering) {
                        if (c->read->timer_set) {
                            ngx_del_timer(c->read);
                        }

                        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                            return NGX_HTTP_INTERNAL_SERVER_ERROR;
                        }

                        return NGX_AGAIN;
                    }

                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                rb->buf->pos = rb->buf->start;
                rb->buf->last = rb->buf->start;
            }

            size = rb->buf->end - rb->buf->last;
            rest = rb->rest - (rb->buf->last - rb->buf->pos);

            if ((off_t) size > rest) {
                size = (size_t) rest;
            }

            n = c->recv(c, rb->buf->last, size);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http client request body recv %z", n);

            if (n == NGX_AGAIN) {
                break;
            }

            if (n == 0) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client prematurely closed connection");
            }

            if (n == 0 || n == NGX_ERROR) {
                c->error = 1;
                return NGX_HTTP_BAD_REQUEST;
            }

            rb->buf->last += n;
            r->request_length += n;

            if (n == rest) {
                /* pass buffer to request body filter chain */

                out.buf = rb->buf;
                out.next = NULL;

                rc = ngx_http_request_body_filter(r, &out);

                if (rc != NGX_OK) {
                    return rc;
                }
            }

            if (rb->rest == 0) {
                break;
            }

            if (rb->buf->last < rb->buf->end) {
                break;
            }
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http client request body rest %O", rb->rest);

        if (rb->rest == 0) {
            break;
        }

        if (!c->read->ready) {

            if (r->request_body_no_buffering
                && rb->buf->pos != rb->buf->last)
            {
                /* pass buffer to request body filter chain */

                out.buf = rb->buf;
                out.next = NULL;

                rc = ngx_http_request_body_filter(r, &out);

                if (rc != NGX_OK) {
                    return rc;
                }
            }

            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_add_timer(c->read, clcf->client_body_timeout);

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            return NGX_AGAIN;
        }
    }

    if (c->read->timer_set) {	//	接收到了完整的包体 则不需要检查接收HTTP超时了
        ngx_del_timer(c->read);
    }

    if (!r->request_body_no_buffering) {
        r->read_event_handler = ngx_http_block_reading;
        rb->post_handler(r);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_write_request_body(ngx_http_request_t *r)
{
    ssize_t                    n;
    ngx_chain_t               *cl, *ln;
    ngx_temp_file_t           *tf;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    rb = r->request_body;	//	提取ngx_http_request_body_t结构

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http write client request body, bufs %p", rb->bufs);

    if (rb->temp_file == NULL) {	//	分配临时文件管理结构
        tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
        if (tf == NULL) {
            return NGX_ERROR;
        }

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        tf->file.fd = NGX_INVALID_FILE;
        tf->file.log = r->connection->log;
        tf->path = clcf->client_body_temp_path;	//	临时文件存储位置
        tf->pool = r->pool;
        tf->warn = "a client request body is buffered to a temporary file";
        tf->log_level = r->request_body_file_log_level;
        tf->persistent = r->request_body_in_persistent_file;
        tf->clean = r->request_body_in_clean_file;

        if (r->request_body_file_group_access) {
            tf->access = 0660;
        }

        rb->temp_file = tf;	//	ngx_http_request_body_t管理临时文件结构

        if (rb->bufs == NULL) {	//	如果缓冲区链表为空 仅仅创建临时文件即可 这种情况出现在request_body_in_file_only=1的情况
            /* empty body with r->request_body_in_file_only */

            if (ngx_create_temp_file(&tf->file, tf->path, tf->pool,
                                     tf->persistent, tf->clean, tf->access)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            return NGX_OK;
        }
    }

    if (rb->bufs == NULL) {	//	当前没有可缓存到文件的数据
        return NGX_OK;
    }

    n = ngx_write_chain_to_temp_file(rb->temp_file, rb->bufs);

    /* TODO: n == 0 or not complete and level event */

    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    rb->temp_file->offset += n;	//	调整temp file的偏移量offset

    /* mark all buffers as written */

    for (cl = rb->bufs; cl; /* void */) {	//把bufs中的ngx_chain_t节点全部取出来添加到r->pool->chain中

        cl->buf->pos = cl->buf->last;

        ln = cl;
        cl = cl->next;
        ngx_free_chain(r->pool, ln);	//
    }

    rb->bufs = NULL;	//	bufs中的数据已经全部缓存到临时文件中 将bufs置为空

    return NGX_OK;
}


ngx_int_t
ngx_http_discard_request_body(ngx_http_request_t *r)
{
    ssize_t       size;
    ngx_int_t     rc;
    ngx_event_t  *rev;

    if (r != r->main || r->discard_body || r->request_body) {
        return NGX_OK;
    }

#if (NGX_HTTP_V2)
    if (r->stream) {
        r->stream->skip_data = 1;
        return NGX_OK;
    }
#endif

    if (ngx_http_test_expect(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rev = r->connection->read;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "http set discard body");

    if (rev->timer_set) {	//	丢弃包体不用考虑超时问题
        ngx_del_timer(rev);
    }

    if (r->headers_in.content_length_n <= 0 && !r->headers_in.chunked) {
        return NGX_OK;
    }

    size = r->header_in->last - r->header_in->pos;

    if (size || r->headers_in.chunked) {
        rc = ngx_http_discard_request_body_filter(r, r->header_in);

        if (rc != NGX_OK) {
            return rc;
        }

        if (r->headers_in.content_length_n == 0) {
            return NGX_OK;
        }
    }

    rc = ngx_http_read_discarded_request_body(r);

    if (rc == NGX_OK) {
        r->lingering_close = 0;
        return NGX_OK;
    }

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    /* rc == NGX_AGAIN */

    r->read_event_handler = ngx_http_discarded_request_body_handler;

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->count++;
    r->discard_body = 1;

    return NGX_OK;
}


void
ngx_http_discarded_request_body_handler(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    ngx_msec_t                 timer;
    ngx_event_t               *rev;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;
    rev = c->read;

    if (rev->timedout) {
        c->timedout = 1;
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    if (r->lingering_time) {
        timer = (ngx_msec_t) r->lingering_time - (ngx_msec_t) ngx_time();

        if ((ngx_msec_int_t) timer <= 0) {
            r->discard_body = 0;
            r->lingering_close = 0;
            ngx_http_finalize_request(r, NGX_ERROR);
            return;
        }

    } else {
        timer = 0;
    }

    rc = ngx_http_read_discarded_request_body(r);

    if (rc == NGX_OK) {
        r->discard_body = 0;
        r->lingering_close = 0;
        ngx_http_finalize_request(r, NGX_DONE);
        return;
    }

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    /* rc == NGX_AGAIN */

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    if (timer) {

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        timer *= 1000;

        if (timer > clcf->lingering_timeout) {
            timer = clcf->lingering_timeout;
        }

        ngx_add_timer(rev, timer);
    }
}


static ngx_int_t
ngx_http_read_discarded_request_body(ngx_http_request_t *r)
{
    size_t     size;
    ssize_t    n;
    ngx_int_t  rc;
    ngx_buf_t  b;
    u_char     buffer[NGX_HTTP_DISCARD_BUFFER_SIZE];

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http read discarded body");

    ngx_memzero(&b, sizeof(ngx_buf_t));

    b.temporary = 1;

    for ( ;; ) {
        if (r->headers_in.content_length_n == 0) {
            r->read_event_handler = ngx_http_block_reading;
            return NGX_OK;
        }

        if (!r->connection->read->ready) {
            return NGX_AGAIN;
        }

        size = (size_t) ngx_min(r->headers_in.content_length_n,
                                NGX_HTTP_DISCARD_BUFFER_SIZE);

        n = r->connection->recv(r->connection, buffer, size);

        if (n == NGX_ERROR) {
            r->connection->error = 1;
            return NGX_OK;
        }

        if (n == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (n == 0) {
            return NGX_OK;
        }

        b.pos = buffer;
        b.last = buffer + n;

        rc = ngx_http_discard_request_body_filter(r, &b);

        if (rc != NGX_OK) {
            return rc;
        }
    }
}


static ngx_int_t
ngx_http_discard_request_body_filter(ngx_http_request_t *r, ngx_buf_t *b)
{
    size_t                    size;
    ngx_int_t                 rc;
    ngx_http_request_body_t  *rb;

    if (r->headers_in.chunked) {

        rb = r->request_body;

        if (rb == NULL) {

            rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
            if (rb == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            rb->chunked = ngx_pcalloc(r->pool, sizeof(ngx_http_chunked_t));
            if (rb->chunked == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            r->request_body = rb;
        }

        for ( ;; ) {

            rc = ngx_http_parse_chunked(r, b, rb->chunked);

            if (rc == NGX_OK) {

                /* a chunk has been parsed successfully */

                size = b->last - b->pos;

                if ((off_t) size > rb->chunked->size) {
                    b->pos += (size_t) rb->chunked->size;
                    rb->chunked->size = 0;

                } else {
                    rb->chunked->size -= size;
                    b->pos = b->last;
                }

                continue;
            }

            if (rc == NGX_DONE) {

                /* a whole response has been parsed successfully */

                r->headers_in.content_length_n = 0;
                break;
            }

            if (rc == NGX_AGAIN) {

                /* set amount of data we want to see next time */

                r->headers_in.content_length_n = rb->chunked->length;
                break;
            }

            /* invalid */

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "client sent invalid chunked body");

            return NGX_HTTP_BAD_REQUEST;
        }

    } else {
        size = b->last - b->pos;

        if ((off_t) size > r->headers_in.content_length_n) {
            b->pos += (size_t) r->headers_in.content_length_n;
            r->headers_in.content_length_n = 0;

        } else {
            b->pos = b->last;
            r->headers_in.content_length_n -= size;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_test_expect(ngx_http_request_t *r)
{
    ngx_int_t   n;
    ngx_str_t  *expect;

    if (r->expect_tested
        || r->headers_in.expect == NULL
        || r->http_version < NGX_HTTP_VERSION_11)
    {
        return NGX_OK;
    }

    r->expect_tested = 1;

    expect = &r->headers_in.expect->value;

    if (expect->len != sizeof("100-continue") - 1
        || ngx_strncasecmp(expect->data, (u_char *) "100-continue",
                           sizeof("100-continue") - 1)
           != 0)
    {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "send 100 Continue");

    n = r->connection->send(r->connection,
                            (u_char *) "HTTP/1.1 100 Continue" CRLF CRLF,
                            sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1);

    if (n == sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1) {
        return NGX_OK;
    }

    /* we assume that such small packet should be send successfully */

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_request_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    if (r->headers_in.chunked) {
        return ngx_http_request_body_chunked_filter(r, in);

    } else {
        return ngx_http_request_body_length_filter(r, in);
    }
}


static ngx_int_t
ngx_http_request_body_length_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    size_t                     size;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl, *tl, *out, **ll;
    ngx_http_request_body_t   *rb;

    rb = r->request_body;

    if (rb->rest == -1) {	//	第一次执行该函数  rest 设置为请求头的 content-length
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http request body content length filter");

        rb->rest = r->headers_in.content_length_n;	//	设置rest为content-length
    }

    out = NULL;
    ll = &out;
	//	遍历链表计算还需要接收多少数据 其实就是计算rest
    for (cl = in; cl; cl = cl->next) {

        if (rb->rest == 0) {	//	已经不需要接收body数据了
            break;
        }

        tl = ngx_chain_get_free_buf(r->pool, &rb->free);	//	构造一个ngx_chain_t结构体
        if (tl == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b = tl->buf;

        ngx_memzero(b, sizeof(ngx_buf_t));
		//b的相关成员指针指向in中的各个节点里面的对应成员，即新的b指向获取到的包体数据中的各个ngx_buf_t
        //b指向的数据和cl->buf指向的数据时一致的，最后实际读取到的数据的头尾用b指向
        b->temporary = 1;
        b->tag = (ngx_buf_tag_t) &ngx_http_read_client_request_body;
        b->start = cl->buf->pos;
        b->pos = cl->buf->pos;
        b->last = cl->buf->last;
        b->end = cl->buf->end;
        b->flush = r->request_body_no_buffering;

        size = cl->buf->last - cl->buf->pos;
		//	计算rest 也就是还需要接收多少字节的数据
		//	调整c1->buf->pos 最终cl->buf->pos<=cl->buf->last
        if ((off_t) size < rb->rest) {
            cl->buf->pos = cl->buf->last;	//	调整c1->buf的pos指针
            rb->rest -= size;//已经获取到size了，还差rb->rest才到content_length_n

        } else {	// 这种情况下 b会在ngx_chain_update_chains回收
            cl->buf->pos += (size_t) rb->rest;
            rb->rest = 0;
            b->last = cl->buf->pos;//实际读到的数据比我们期望的rest数据多，因此我们截取实际需要的数据即可
            b->last_buf = 1;//标记该buf是组成包体数据的buf数组中的最后一个ngx_buf_t
        }

        *ll = tl;
        ll = &tl->next;
    }

	/*****************************************************************************
	 * 
	 * 注: 当是r->header_in时，r->rb->bufs = NULL
	 * 所以当调用ngx_http_request_body_save_filter时 只是把out挂接在r->rb->bufs上
	 * 当调用ngx_chain_update_chains时 并不会处理r->header_in 只会处理out下的buf
	 * 
	 *****************************************************************************
	*/
	
	//把in表中的数据(通过从新创建ngx_buf_t指向in表中各个数据的成员)连接到r->request_body->bufs中，这样所有的out数据都会添加到r->request_body->bufs数组中
	//通过新创建的ngx_chain_t(之前out中的ngx_chain_t就通过下面的ngx_chain_update_chains进行回收)中的各个指针来执行新读取到的out数据，ngx_http_request_body_save_filter，通过该函数后所有的out数据都连接到rb->bufs中缓存了

	// 合并out到r->rb->bufs后面
	rc = ngx_http_top_request_body_filter(r, out);	//	ngx_http_request_body_save_filter
	
	//rb中的bufs链表中的成员中的各个指针指向读取到的原始数据位置(如pos指向读取到数据的头，last指向读取到数据的尾部)
    //rb->busy最初是直接从out中拷贝的，指向的数据空间最初与bufs是一样的，但是一旦http模块从网络读取到的数据中解析出一部分数据，那么free中成员的各个指针就会移动，例如pos会
    //向last方向移动，直到pos=last，这时候busy中的这个ngx_buf_t节点成员就可以从busy链表中取出，然后添加到free链表中

    ngx_chain_update_chains(r->pool, &rb->free, &rb->busy, &out,
                            (ngx_buf_tag_t) &ngx_http_read_client_request_body);

    return rc;
}


static ngx_int_t
ngx_http_request_body_chunked_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    size_t                     size;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl, *out, *tl, **ll;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    rb = r->request_body;

    if (rb->rest == -1) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http request body chunked filter");

        rb->chunked = ngx_pcalloc(r->pool, sizeof(ngx_http_chunked_t));
        if (rb->chunked == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->headers_in.content_length_n = 0;
        rb->rest = 3;
    }

    out = NULL;
    ll = &out;

    for (cl = in; cl; cl = cl->next) {

        for ( ;; ) {

            ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                           "http body chunked buf "
                           "t:%d f:%d %p, pos %p, size: %z file: %O, size: %O",
                           cl->buf->temporary, cl->buf->in_file,
                           cl->buf->start, cl->buf->pos,
                           cl->buf->last - cl->buf->pos,
                           cl->buf->file_pos,
                           cl->buf->file_last - cl->buf->file_pos);

            rc = ngx_http_parse_chunked(r, cl->buf, rb->chunked);

            if (rc == NGX_OK) {

                /* a chunk has been parsed successfully */

                clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

                if (clcf->client_max_body_size
                    && clcf->client_max_body_size
                       - r->headers_in.content_length_n < rb->chunked->size)
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "client intended to send too large chunked "
                                  "body: %O+%O bytes",
                                  r->headers_in.content_length_n,
                                  rb->chunked->size);

                    r->lingering_close = 1;

                    return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
                }

                tl = ngx_chain_get_free_buf(r->pool, &rb->free);
                if (tl == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                b = tl->buf;

                ngx_memzero(b, sizeof(ngx_buf_t));

                b->temporary = 1;
                b->tag = (ngx_buf_tag_t) &ngx_http_read_client_request_body;
                b->start = cl->buf->pos;
                b->pos = cl->buf->pos;
                b->last = cl->buf->last;
                b->end = cl->buf->end;
                b->flush = r->request_body_no_buffering;

                *ll = tl;
                ll = &tl->next;

                size = cl->buf->last - cl->buf->pos;

                if ((off_t) size > rb->chunked->size) {
                    cl->buf->pos += (size_t) rb->chunked->size;
                    r->headers_in.content_length_n += rb->chunked->size;
                    rb->chunked->size = 0;

                } else {
                    rb->chunked->size -= size;
                    r->headers_in.content_length_n += size;
                    cl->buf->pos = cl->buf->last;
                }

                b->last = cl->buf->pos;

                continue;
            }

            if (rc == NGX_DONE) {

                /* a whole response has been parsed successfully */

                rb->rest = 0;

                tl = ngx_chain_get_free_buf(r->pool, &rb->free);
                if (tl == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                b = tl->buf;

                ngx_memzero(b, sizeof(ngx_buf_t));

                b->last_buf = 1;

                *ll = tl;
                ll = &tl->next;

                break;
            }

            if (rc == NGX_AGAIN) {

                /* set rb->rest, amount of data we want to see next time */

                rb->rest = rb->chunked->length;

                break;
            }

            /* invalid */

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "client sent invalid chunked body");

            return NGX_HTTP_BAD_REQUEST;
        }
    }

    rc = ngx_http_top_request_body_filter(r, out);

    ngx_chain_update_chains(r->pool, &rb->free, &rb->busy, &out,
                            (ngx_buf_tag_t) &ngx_http_read_client_request_body);

    return rc;
}


ngx_int_t
ngx_http_request_body_save_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_buf_t                 *b;
    ngx_chain_t               *cl;
    ngx_http_request_body_t   *rb;

    rb = r->request_body;

#if (NGX_DEBUG)

    for (cl = rb->bufs; cl; cl = cl->next) {
        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "http body old buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    for (cl = in; cl; cl = cl->next) {
        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "http body new buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

#endif

    /* TODO: coalesce neighbouring buffers */
	//	合并ngx_chain_t结构体的缓冲区rb->bufs和in
    if (ngx_chain_add_copy(r->pool, &rb->bufs, in) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r->request_body_no_buffering) {	//	如果不缓存包体 则不能把数据存储到文件中
        return NGX_OK;
    }
	// 当一个rb->buf填满后就会通过ngx_http_write_request_body把bufs链表中的所有ngx_chain_t->ngx_buf_t中指向的数据
	// 写入到临时文件，并把ngx_buf_t结构加入r->pool->chain,通过r->pool统一释放他们
    if (rb->rest > 0) {
		//需要缓存数据，并且rb->buf数据已经解析完毕，并且buf已经满了，但是包体还没有读完，那么就可以把buf中的数据写入临时文件，
        //这样改buf指向的内存空间在该函数退出后可以继续用来读取数据
        if (rb->buf && rb->buf->last == rb->buf->end
            && ngx_http_write_request_body(r) != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        return NGX_OK;
    }

    /* rb->rest == 0 */
	/*已经接收完所有包体*/
    if (rb->temp_file || r->request_body_in_file_only) {

        if (ngx_http_write_request_body(r) != NGX_OK) {	//	写缓冲区数据到临时文件中
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (rb->temp_file->file.offset != 0) {	//	利用buf的file*成员管理临时文件 方便之后读取文件内容

            cl = ngx_chain_get_free_buf(r->pool, &rb->free);
            if (cl == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            b = cl->buf;

            ngx_memzero(b, sizeof(ngx_buf_t));

            b->in_file = 1;
            b->file_last = rb->temp_file->file.offset;
            b->file = &rb->temp_file->file;

            rb->bufs = cl;
        }
    }

    return NGX_OK;
}
