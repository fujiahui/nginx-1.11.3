
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SLAB_H_INCLUDED_
#define _NGX_SLAB_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_slab_page_s  ngx_slab_page_t;

/* slab的四种情况
 * 1. 存储为一些结构相连的pages的数目 (slab page管理结构)
 * 2. 存储为标记chunk使用情况的bitmap (size == exact_size)
 * 3. 存储为chunk的大小 (size < exact_size)
 * 4. 存储标记chunk的使用情况以及chunk的大小 (size > exact_size)
**/
struct ngx_slab_page_s {
    uintptr_t         slab;
    ngx_slab_page_t  *next;
    uintptr_t         prev;
};


typedef struct {
    ngx_shmtx_sh_t    lock;

    size_t            min_size;	// 最小分割成的chunk的大小
    size_t            min_shift;	// min_size对应的移位数

    ngx_slab_page_t  *pages;	// slab page管理结构开始位置
    ngx_slab_page_t  *last;	// 
    ngx_slab_page_t   free;	//	空闲slab page管理结构链表

    u_char           *start;	// pages数组的起始地址
    u_char           *end;	// 整个slab pool的结束位置

    ngx_shmtx_t       mutex;

    u_char           *log_ctx;
    u_char            zero;

    unsigned          log_nomem:1;

    void             *data;
    void             *addr;	// 整个slab pool的开始位置
} ngx_slab_pool_t;


void ngx_slab_init(ngx_slab_pool_t *pool);
void *ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size);
void *ngx_slab_alloc_locked(ngx_slab_pool_t *pool, size_t size);
void *ngx_slab_calloc(ngx_slab_pool_t *pool, size_t size);
void *ngx_slab_calloc_locked(ngx_slab_pool_t *pool, size_t size);
void ngx_slab_free(ngx_slab_pool_t *pool, void *p);
void ngx_slab_free_locked(ngx_slab_pool_t *pool, void *p);


#endif /* _NGX_SLAB_H_INCLUDED_ */
