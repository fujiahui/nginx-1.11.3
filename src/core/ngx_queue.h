
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef _NGX_QUEUE_H_INCLUDED_
#define _NGX_QUEUE_H_INCLUDED_


typedef struct ngx_queue_s  ngx_queue_t;

struct ngx_queue_s {
    ngx_queue_t  *prev;
    ngx_queue_t  *next;
};

//	初始化队列
#define ngx_queue_init(q)                                                     \
    (q)->prev = q;                                                            \
    (q)->next = q

//	判断队列是否为空
#define ngx_queue_empty(h)                                                    \
    (h == (h)->prev)

//	在头节点之后插入新节点
#define ngx_queue_insert_head(h, x)                                           \
    (x)->next = (h)->next;                                                    \
    (x)->next->prev = x;                                                      \
    (x)->prev = h;                                                            \
    (h)->next = x


#define ngx_queue_insert_after   ngx_queue_insert_head

//	//在尾节点之后插入新节点 
#define ngx_queue_insert_tail(h, x)                                           \
    (x)->prev = (h)->prev;                                                    \
    (x)->prev->next = x;                                                      \
    (x)->next = h;                                                            \
    (h)->prev = x

//	获取第一个结点
#define ngx_queue_head(h)                                                     \
    (h)->next

//	获取最后一个结点
#define ngx_queue_last(h)                                                     \
    (h)->prev

//	获取哨兵结点（即参数h）
#define ngx_queue_sentinel(h)                                                 \
    (h)

//	获取下一个结点
#define ngx_queue_next(q)                                                     \
    (q)->next

//	获取上一个结点
#define ngx_queue_prev(q)                                                     \
    (q)->prev


#if (NGX_DEBUG)
//	删除节点x
#define ngx_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next;                                              \
    (x)->prev = NULL;                                                         \
    (x)->next = NULL

#else
//	删除节点x
#define ngx_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next

#endif

//	将h为哨兵结点的队列中q结点开始到队尾结点的整个链拆分、链接到空的n队列中，
//	h队列中的剩余结点组成新队列；
#define ngx_queue_split(h, q, n)                                              \
    (n)->prev = (h)->prev;                                                    \
    (n)->prev->next = n;                                                      \
    (n)->next = q;                                                            \
    (h)->prev = (q)->prev;                                                    \
    (h)->prev->next = h;                                                      \
    (q)->prev = n;

//	将n队列中的所有结点按顺序链接到h队列末尾，n队列清空
#define ngx_queue_add(h, n)                                                   \
    (h)->prev->next = (n)->next;                                              \
    (n)->next->prev = (h)->prev;                                              \
    (h)->prev = (n)->prev;                                                    \
    (h)->prev->next = h;


#define ngx_queue_data(q, type, link)                                         \
    (type *) ((u_char *) q - offsetof(type, link))

//	一个指针前进一次，一个指针前进两次
ngx_queue_t *ngx_queue_middle(ngx_queue_t *queue);
//	插入排序
void ngx_queue_sort(ngx_queue_t *queue,
    ngx_int_t (*cmp)(const ngx_queue_t *, const ngx_queue_t *));


#endif /* _NGX_QUEUE_H_INCLUDED_ */
