
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SLAB_H_INCLUDED_
#define _NGX_SLAB_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_slab_page_s  ngx_slab_page_t;

/* slab���������
 * 1. �洢ΪһЩ�ṹ������pages����Ŀ (slab page����ṹ)
 * 2. �洢Ϊ���chunkʹ�������bitmap (size == exact_size)
 * 3. �洢Ϊchunk�Ĵ�С (size < exact_size)
 * 4. �洢���chunk��ʹ������Լ�chunk�Ĵ�С (size > exact_size)
**/
struct ngx_slab_page_s {
    uintptr_t         slab;
    ngx_slab_page_t  *next;
    uintptr_t         prev;
};


typedef struct {
    ngx_shmtx_sh_t    lock;

    size_t            min_size;	// ��С�ָ�ɵ�chunk�Ĵ�С
    size_t            min_shift;	// min_size��Ӧ����λ��

    ngx_slab_page_t  *pages;	// slab page����ṹ��ʼλ��
    ngx_slab_page_t  *last;	// 
    ngx_slab_page_t   free;	//	����slab page����ṹ����

    u_char           *start;	// pages�������ʼ��ַ
    u_char           *end;	// ����slab pool�Ľ���λ��

    ngx_shmtx_t       mutex;

    u_char           *log_ctx;
    u_char            zero;

    unsigned          log_nomem:1;

    void             *data;
    void             *addr;	// ����slab pool�Ŀ�ʼλ��
} ngx_slab_pool_t;


void ngx_slab_init(ngx_slab_pool_t *pool);
void *ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size);
void *ngx_slab_alloc_locked(ngx_slab_pool_t *pool, size_t size);
void *ngx_slab_calloc(ngx_slab_pool_t *pool, size_t size);
void *ngx_slab_calloc_locked(ngx_slab_pool_t *pool, size_t size);
void ngx_slab_free(ngx_slab_pool_t *pool, void *p);
void ngx_slab_free_locked(ngx_slab_pool_t *pool, void *p);


#endif /* _NGX_SLAB_H_INCLUDED_ */
