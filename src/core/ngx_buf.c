
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


ngx_buf_t *
ngx_create_temp_buf(ngx_pool_t *pool, size_t size)
{
    ngx_buf_t *b;

    b = ngx_calloc_buf(pool);
    if (b == NULL) {
        return NULL;
    }

    b->start = ngx_palloc(pool, size);
    if (b->start == NULL) {
        return NULL;
    }

    /*
     * set by ngx_calloc_buf():
     *
     *     b->file_pos = 0;
     *     b->file_last = 0;
     *     b->file = NULL;
     *     b->shadow = NULL;
     *     b->tag = 0;
     *     and flags
     */

    b->pos = b->start;
    b->last = b->start;
    b->end = b->last + size;
    b->temporary = 1;

    return b;
}


ngx_chain_t *
ngx_alloc_chain_link(ngx_pool_t *pool)
{
    ngx_chain_t  *cl;

    cl = pool->chain;

    if (cl) {
		// 如果存在返回第一个chain节点
        pool->chain = cl->next;
        return cl;
    }

    cl = ngx_palloc(pool, sizeof(ngx_chain_t));
    if (cl == NULL) {
        return NULL;
    }

    return cl;
}


ngx_chain_t *
ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs)
{
    u_char       *p;
    ngx_int_t     i;
    ngx_buf_t    *b;
    ngx_chain_t  *chain, *cl, **ll;

    p = ngx_palloc(pool, bufs->num * bufs->size);
    if (p == NULL) {
        return NULL;
    }

	// ll首先指向chain的地址(地址的地址)
    ll = &chain;

    for (i = 0; i < bufs->num; i++) {

        b = ngx_calloc_buf(pool);
        if (b == NULL) {
            return NULL;
        }

        /*
         * set by ngx_calloc_buf():
         *
         *     b->file_pos = 0;
         *     b->file_last = 0;
         *     b->file = NULL;
         *     b->shadow = NULL;
         *     b->tag = 0;
         *     and flags
         *
         */

        b->pos = p;
        b->last = p;
        b->temporary = 1;

        b->start = p;
        p += bufs->size;
        b->end = p;

		// 提取出挂在pool上的chain结构
		// 可能存在可能不存在
        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            return NULL;
        }

        cl->buf = b;
        *ll = cl;
        ll = &cl->next;
    }

    *ll = NULL;

    return chain;
}


ngx_int_t
ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain, ngx_chain_t *in)
{
    ngx_chain_t  *cl, **ll;

    ll = chain;

	//	遍历chain，查找到chain的最后结尾
    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }

	//	遍历in，并且创建分配chain的基本节点，并将其buf指向in的部分
    while (in) {
        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = in->buf;
        *ll = cl;
        ll = &cl->next;
        in = in->next;
    }

	// 最后将最后一个chain节点的next指向一个NULL指针
    *ll = NULL;

    return NGX_OK;
}


ngx_chain_t *
ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free)
{
    ngx_chain_t  *cl;

    if (*free) {
        cl = *free;
        *free = cl->next;
        cl->next = NULL;
        return cl;
    }

    cl = ngx_alloc_chain_link(p);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = ngx_calloc_buf(p);
    if (cl->buf == NULL) {
        return NULL;
    }

    cl->next = NULL;

    return cl;
}


void
ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free, ngx_chain_t **busy,
    ngx_chain_t **out, ngx_buf_tag_t tag)
{
    ngx_chain_t  *cl;

    if (*busy == NULL) {
		// 如果busy不存在
        *busy = *out;

    } else {
    	// 如果busy存在
    	// 找到busy的尾
        for (cl = *busy; cl->next; cl = cl->next) { /* void */ }

        cl->next = *out;
    }

    *out = NULL;

    while (*busy) {
        cl = *busy;

		// 如果存在需要处理的内存空间last-pos!=0,则停止处理
        if (ngx_buf_size(cl->buf) != 0) {
            break;
        }

        if (cl->buf->tag != tag) {
			// busy下一个节点
            *busy = cl->next;
			//	回收chain节点到pool中
            ngx_free_chain(p, cl);
            continue;
        }

		// 重置buf为空
        cl->buf->pos = cl->buf->start;
        cl->buf->last = cl->buf->start;

		// busy下一个节点
        *busy = cl->next;
        cl->next = *free;
        *free = cl;
    }
}


off_t
ngx_chain_coalesce_file(ngx_chain_t **in, off_t limit)
{
    off_t         total, size, aligned, fprev;
    ngx_fd_t      fd;
    ngx_chain_t  *cl;

    total = 0;

    cl = *in;
    fd = cl->buf->file->fd;

    do {
		// 当前buf的file大小
        size = cl->buf->file_last - cl->buf->file_pos;

		// 如果大于，则凑够一整页数据发送出去
        if (size > limit - total) {
            size = limit - total;

			// ngx_pagesize=4096
            aligned = (cl->buf->file_pos + size + ngx_pagesize - 1)
                       & ~((off_t) ngx_pagesize - 1);

            if (aligned <= cl->buf->file_last) {
                size = aligned - cl->buf->file_pos;
            }
        }

        total += size;
        fprev = cl->buf->file_pos + size;
		// 处理下一个buf
        cl = cl->next;

    } while (cl
             && cl->buf->in_file	// 这段缓冲区处理的是文件
             && total < limit
             && fd == cl->buf->file->fd	//	处理的是同一个文件描述符 ???
             && fprev == cl->buf->file_pos);

    *in = cl;

    return total;
}


/*
 * 当发送了sent字节之后需要对当前使用的缓冲区做处理，
 * 并返回当前仍未处理过的缓冲区指针。
**/
ngx_chain_t *
ngx_chain_update_sent(ngx_chain_t *in, off_t sent)
{
    off_t  size;

	// 遍历in链表
    for ( /* void */ ; in; in = in->next) {

        if (ngx_buf_special(in->buf)) {
            continue;
        }

        if (sent == 0) {
            break;
        }

		// 当前buf的大小
        size = ngx_buf_size(in->buf);

        if (sent >= size) {
            sent -= size;

			// 如果在内存中，调整pos
            if (ngx_buf_in_memory(in->buf)) {
                in->buf->pos = in->buf->last;
            }
			// 如果在文件中，调整file_pos
            if (in->buf->in_file) {
                in->buf->file_pos = in->buf->file_last;
            }

            continue;
        }

		// 如果到达这里说明 sent < size
		// 当前buf只剩下size-sent
        if (ngx_buf_in_memory(in->buf)) {
            in->buf->pos += (size_t) sent;
        }

        if (in->buf->in_file) {
            in->buf->file_pos += sent;
        }

        break;
    }

    return in;
}
