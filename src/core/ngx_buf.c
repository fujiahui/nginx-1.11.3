
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
		// ������ڷ��ص�һ��chain�ڵ�
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

	// ll����ָ��chain�ĵ�ַ(��ַ�ĵ�ַ)
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

		// ��ȡ������pool�ϵ�chain�ṹ
		// ���ܴ��ڿ��ܲ�����
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

	//	����chain�����ҵ�chain������β
    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }

	//	����in�����Ҵ�������chain�Ļ����ڵ㣬������bufָ��in�Ĳ���
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

	// ������һ��chain�ڵ��nextָ��һ��NULLָ��
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
		// ���busy������
        *busy = *out;

    } else {
    	// ���busy����
    	// �ҵ�busy��β
        for (cl = *busy; cl->next; cl = cl->next) { /* void */ }

        cl->next = *out;
    }

    *out = NULL;

    while (*busy) {
        cl = *busy;

		// ���������Ҫ������ڴ�ռ�last-pos!=0,��ֹͣ����
        if (ngx_buf_size(cl->buf) != 0) {
            break;
        }

        if (cl->buf->tag != tag) {
			// busy��һ���ڵ�
            *busy = cl->next;
			//	����chain�ڵ㵽pool��
            ngx_free_chain(p, cl);
            continue;
        }

		// ����bufΪ��
        cl->buf->pos = cl->buf->start;
        cl->buf->last = cl->buf->start;

		// busy��һ���ڵ�
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
		// ��ǰbuf��file��С
        size = cl->buf->file_last - cl->buf->file_pos;

		// ������ڣ���չ�һ��ҳ���ݷ��ͳ�ȥ
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
		// ������һ��buf
        cl = cl->next;

    } while (cl
             && cl->buf->in_file	// ��λ�������������ļ�
             && total < limit
             && fd == cl->buf->file->fd	//	�������ͬһ���ļ������� ???
             && fprev == cl->buf->file_pos);

    *in = cl;

    return total;
}


/*
 * ��������sent�ֽ�֮����Ҫ�Ե�ǰʹ�õĻ�����������
 * �����ص�ǰ��δ������Ļ�����ָ�롣
**/
ngx_chain_t *
ngx_chain_update_sent(ngx_chain_t *in, off_t sent)
{
    off_t  size;

	// ����in����
    for ( /* void */ ; in; in = in->next) {

        if (ngx_buf_special(in->buf)) {
            continue;
        }

        if (sent == 0) {
            break;
        }

		// ��ǰbuf�Ĵ�С
        size = ngx_buf_size(in->buf);

        if (sent >= size) {
            sent -= size;

			// ������ڴ��У�����pos
            if (ngx_buf_in_memory(in->buf)) {
                in->buf->pos = in->buf->last;
            }
			// ������ļ��У�����file_pos
            if (in->buf->in_file) {
                in->buf->file_pos = in->buf->file_last;
            }

            continue;
        }

		// �����������˵�� sent < size
		// ��ǰbufֻʣ��size-sent
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
