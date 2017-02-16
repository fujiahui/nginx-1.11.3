
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HASH_H_INCLUDED_
#define _NGX_HASH_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


//	散列表槽元素
//	hash元素结构
typedef struct {
    void             *value;	//	value，即某个key对应的值，即<key,value>中的value  
    u_short           len;	//	name长度
    u_char            name[1];	//	某个要hash的数据(在nginx中表现为字符串)，即<key,value>中的key
    //	ngx_hash_elt_t结构中的name字段就是ngx_hash_key_t结构中的key
} ngx_hash_elt_t;
// sizeof(ngx_hash_elt_t) = 8

//	hash结构
typedef struct {
	//	散列表的首地址，也就是第一个槽的地址
    ngx_hash_elt_t  **buckets;	//	hash桶(有size个桶)
    //	散列表中槽的总数
    ngx_uint_t        size;	//	hash桶个数
} ngx_hash_t;
//	sizeof(ngx_hash_t) = 8

typedef struct {
    ngx_hash_t        hash;	//	基本散列表
    //	当使用这个ngx_hash_wildcard_t通配符散列表作为某容器的元素时
    //	可以使用这个value指针指向用户数据
    void             *value;
} ngx_hash_wildcard_t;


//	预添加哈希散列元素结构
typedef struct {	
    ngx_str_t         key;	//	key，为nginx的字符串结构
    ngx_uint_t        key_hash;	//	由该key计算出的hash值(通过hash函数如ngx_hash_key_lc())
    void             *value;	//	该key对应的值，组成一个键-值对<key,value>
    //	一般在使用中，value指针可能指向静态数据区(例如全局数组、常量字符串)、堆区(例如动态分配的数据区用来保存value值)等
} ngx_hash_key_t;
//	sizeof(ngx_hash_key_t) = 16


typedef ngx_uint_t (*ngx_hash_key_pt) (u_char *data, size_t len);

// 支持通配符*的散列表
typedef struct {
    ngx_hash_t            hash;	//	用于精确匹配的基本散列表
    ngx_hash_wildcard_t  *wc_head;	//	用于查询前置通配符的散列表
    ngx_hash_wildcard_t  *wc_tail;	//	用于查询后置通配符的散列表
} ngx_hash_combined_t;


typedef struct {	//	hash初始化结构
	//	指向普通的完全匹配散列表
    ngx_hash_t       *hash;	//	指向待初始化的hash结构
    ngx_hash_key_pt   key;	//	hash函数指针

    ngx_uint_t        max_size;	//	bucket的最大个数
    ngx_uint_t        bucket_size;	//	每个bucket的空间, 不是sizeof(ngx_hash_elt_t)

    char             *name;	//	该hash结构的名字(仅在错误日志中使用) 
    //	分配散列表(最多三个)	
    //	它负责分配基本哈希列表、前置通配哈希列表、后置哈希列表中所有槽
    ngx_pool_t       *pool;	//	该hash结构从pool指向的内存池中分配
    ngx_pool_t       *temp_pool;	//	分配临时数据空间的内存池
} ngx_hash_init_t;


#define NGX_HASH_SMALL            1
#define NGX_HASH_LARGE            2

#define NGX_HASH_LARGE_ASIZE      16384
#define NGX_HASH_LARGE_HSIZE      10007

#define NGX_HASH_WILDCARD_KEY     1
#define NGX_HASH_READONLY_KEY     2


/*
 * 这里设计了3个简易的哈希列表( keys_hash、dns_wc_head_hash、dns_wc_tail_hash)，
 * 即采用分离链表法来解决冲突，这样做的好处是如果没有这三个用分离链表法来解决冲突的简易哈希列表，
 * 那么每添加一个关键字元素都要遍历数组（数组采用开放地址法解决冲突，冲突就必须遍历）
*/
typedef struct {
	//	指明了散列表的槽个数，简易散列表方法需要对hsize求余
    ngx_uint_t        hsize;

    ngx_pool_t       *pool;
    ngx_pool_t       *temp_pool;

	/*
	 *	*_hash变量都是简易散列表
	**/

	//	用动态数组以ngx_hash_key_t结构体保存着不含通配符关键字的元素
    ngx_array_t       keys;	//	ngx_hash_key_t
	/*
	 * 一个极其简单的散列表，以数组的形式保存着hsize个元素
	 * 每个元素都是ngx_array_t动态数组。在用户添加的元素过程中，
	 * 会根据关键码将用户的ngx_str_t类型的关键字添加到ngx_array_t动态数组中。
	 * 这里所有的用户元素的关键字都不可以带通配符，表示精确匹配
	**/
	/*
	 * 这是个二维数组，第一个维度代表的是bucket的编号，
	 * 那么keys_hash[i]中存放的是所有的key算出来的hash值对hsize取模以后的值为i的key。
	 * 假设有3个key,分别是key1,key2和key3假设hash值算出来以后对hsize取模的值都是i，
	 * 那么这三个key的值就顺序存放在keys_hash[i][0],keys_hash[i][1], keys_hash[i][2]。
	 * 该值在调用的过程中用来保存和检测是否有冲突的key值，也就是是否有重复。
	 */
    ngx_array_t      *keys_hash;	//	ngx_str_t

	//	用动态数组以ngx_hash_key_t结构体保存着前置通配符关键字的元素
	//	存放前向通配符key被处理完成以后的值。比如：“*.abc.com”被处理完成以后，变成“com.abc.”被存放在此数组中。
    ngx_array_t       dns_wc_head;	//	ngx_hash_key_t
	/*
	 * 一个极其简单的散列表，以数组的形式保存着hsize个元素
	 * 每个元素都是ngx_array_t动态数组。在用户添加的元素过程中，
	 * 会根据关键码将用户的ngx_str_t类型的关键字添加到ngx_array_t动态数组中。
	 * 这里所有的用户元素的关键字都带前置通配符
	**/
    ngx_array_t      *dns_wc_head_hash;	//	ngx_str_t

	//	用动态数组以ngx_hash_key_t结构体保存着后置通配符关键字的元素
	//	存放后向通配符key被处理完成以后的值。比如：“mail.xxx.*”被处理完成以后，变成“mail.xxx.”被存放在此数组中。
    ngx_array_t       dns_wc_tail;	//	ngx_hash_key_t
	/*
	 * 一个极其简单的散列表，以数组的形式保存着hsize个元素
	 * 每个元素都是ngx_array_t动态数组。在用户添加的元素过程中，
	 * 会根据关键码将用户的ngx_str_t类型的关键字添加到ngx_array_t动态数组中。
	 * 这里所有的用户元素的关键字都带后置通配符
	**/
    ngx_array_t      *dns_wc_tail_hash;	//	ngx_str_t
} ngx_hash_keys_arrays_t;


typedef struct {
    ngx_uint_t        hash;
    ngx_str_t         key;
    ngx_str_t         value;
    u_char           *lowcase_key;
} ngx_table_elt_t;


//	用于查询元素
/*
 * key: 根据散列方法算出来的散列关键字
 * name: 实际key的地址
 * len: 实际key的长度
*/
void *ngx_hash_find(ngx_hash_t *hash, ngx_uint_t key, u_char *name, size_t len);
//	用于查找前置通配符
void *ngx_hash_find_wc_head(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
//	用于查找后置通配符
void *ngx_hash_find_wc_tail(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
void *ngx_hash_find_combined(ngx_hash_combined_t *hash, ngx_uint_t key,
    u_char *name, size_t len);

ngx_int_t ngx_hash_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);
ngx_int_t ngx_hash_wildcard_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);

//	hash宏
#define ngx_hash(key, c)   ((ngx_uint_t) key * 31 + c)
ngx_uint_t ngx_hash_key(u_char *data, size_t len);
//	lc表示lower case，即字符串转换为小写后再计算hash值  
ngx_uint_t ngx_hash_key_lc(u_char *data, size_t len);
ngx_uint_t ngx_hash_strlow(u_char *dst, u_char *src, size_t n);

// 先构造好了ngx_hash_keys_arrays_t结构体，就可以很方便的
// ngx_hash_init或ngx_hash_wildcard_init方法创建支持通配符的散列表
ngx_int_t ngx_hash_keys_array_init(ngx_hash_keys_arrays_t *ha, ngx_uint_t type);
// 负责构造ngx_hash_key_t结构
ngx_int_t ngx_hash_add_key(ngx_hash_keys_arrays_t *ha, ngx_str_t *key,
    void *value, ngx_uint_t flags);


#endif /* _NGX_HASH_H_INCLUDED_ */
