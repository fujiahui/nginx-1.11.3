
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HASH_H_INCLUDED_
#define _NGX_HASH_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


//	ɢ�б��Ԫ��
//	hashԪ�ؽṹ
typedef struct {
    void             *value;	//	value����ĳ��key��Ӧ��ֵ����<key,value>�е�value  
    u_short           len;	//	name����
    u_char            name[1];	//	ĳ��Ҫhash������(��nginx�б���Ϊ�ַ���)����<key,value>�е�key
    //	ngx_hash_elt_t�ṹ�е�name�ֶξ���ngx_hash_key_t�ṹ�е�key
} ngx_hash_elt_t;
// sizeof(ngx_hash_elt_t) = 8

//	hash�ṹ
typedef struct {
	//	ɢ�б���׵�ַ��Ҳ���ǵ�һ���۵ĵ�ַ
    ngx_hash_elt_t  **buckets;	//	hashͰ(��size��Ͱ)
    //	ɢ�б��в۵�����
    ngx_uint_t        size;	//	hashͰ����
} ngx_hash_t;
//	sizeof(ngx_hash_t) = 8

typedef struct {
    ngx_hash_t        hash;	//	����ɢ�б�
    //	��ʹ�����ngx_hash_wildcard_tͨ���ɢ�б���Ϊĳ������Ԫ��ʱ
    //	����ʹ�����valueָ��ָ���û�����
    void             *value;
} ngx_hash_wildcard_t;


//	Ԥ��ӹ�ϣɢ��Ԫ�ؽṹ
typedef struct {	
    ngx_str_t         key;	//	key��Ϊnginx���ַ����ṹ
    ngx_uint_t        key_hash;	//	�ɸ�key�������hashֵ(ͨ��hash������ngx_hash_key_lc())
    void             *value;	//	��key��Ӧ��ֵ�����һ����-ֵ��<key,value>
    //	һ����ʹ���У�valueָ�����ָ��̬������(����ȫ�����顢�����ַ���)������(���綯̬�������������������valueֵ)��
} ngx_hash_key_t;
//	sizeof(ngx_hash_key_t) = 16


typedef ngx_uint_t (*ngx_hash_key_pt) (u_char *data, size_t len);

// ֧��ͨ���*��ɢ�б�
typedef struct {
    ngx_hash_t            hash;	//	���ھ�ȷƥ��Ļ���ɢ�б�
    ngx_hash_wildcard_t  *wc_head;	//	���ڲ�ѯǰ��ͨ�����ɢ�б�
    ngx_hash_wildcard_t  *wc_tail;	//	���ڲ�ѯ����ͨ�����ɢ�б�
} ngx_hash_combined_t;


typedef struct {	//	hash��ʼ���ṹ
	//	ָ����ͨ����ȫƥ��ɢ�б�
    ngx_hash_t       *hash;	//	ָ�����ʼ����hash�ṹ
    ngx_hash_key_pt   key;	//	hash����ָ��

    ngx_uint_t        max_size;	//	bucket��������
    ngx_uint_t        bucket_size;	//	ÿ��bucket�Ŀռ�, ����sizeof(ngx_hash_elt_t)

    char             *name;	//	��hash�ṹ������(���ڴ�����־��ʹ��) 
    //	����ɢ�б�(�������)	
    //	��������������ϣ�б�ǰ��ͨ���ϣ�б����ù�ϣ�б������в�
    ngx_pool_t       *pool;	//	��hash�ṹ��poolָ����ڴ���з���
    ngx_pool_t       *temp_pool;	//	������ʱ���ݿռ���ڴ��
} ngx_hash_init_t;


#define NGX_HASH_SMALL            1
#define NGX_HASH_LARGE            2

#define NGX_HASH_LARGE_ASIZE      16384
#define NGX_HASH_LARGE_HSIZE      10007

#define NGX_HASH_WILDCARD_KEY     1
#define NGX_HASH_READONLY_KEY     2


/*
 * ���������3�����׵Ĺ�ϣ�б�( keys_hash��dns_wc_head_hash��dns_wc_tail_hash)��
 * �����÷��������������ͻ���������ĺô������û���������÷��������������ͻ�ļ��׹�ϣ�б�
 * ��ôÿ���һ���ؼ���Ԫ�ض�Ҫ�������飨������ÿ��ŵ�ַ�������ͻ����ͻ�ͱ��������
*/
typedef struct {
	//	ָ����ɢ�б�Ĳ۸���������ɢ�б�����Ҫ��hsize����
    ngx_uint_t        hsize;

    ngx_pool_t       *pool;
    ngx_pool_t       *temp_pool;

	/*
	 *	*_hash�������Ǽ���ɢ�б�
	**/

	//	�ö�̬������ngx_hash_key_t�ṹ�屣���Ų���ͨ����ؼ��ֵ�Ԫ��
    ngx_array_t       keys;	//	ngx_hash_key_t
	/*
	 * һ������򵥵�ɢ�б����������ʽ������hsize��Ԫ��
	 * ÿ��Ԫ�ض���ngx_array_t��̬���顣���û���ӵ�Ԫ�ع����У�
	 * ����ݹؼ��뽫�û���ngx_str_t���͵Ĺؼ�����ӵ�ngx_array_t��̬�����С�
	 * �������е��û�Ԫ�صĹؼ��ֶ������Դ�ͨ�������ʾ��ȷƥ��
	**/
	/*
	 * ���Ǹ���ά���飬��һ��ά�ȴ������bucket�ı�ţ�
	 * ��ôkeys_hash[i]�д�ŵ������е�key�������hashֵ��hsizeȡģ�Ժ��ֵΪi��key��
	 * ������3��key,�ֱ���key1,key2��key3����hashֵ������Ժ��hsizeȡģ��ֵ����i��
	 * ��ô������key��ֵ��˳������keys_hash[i][0],keys_hash[i][1], keys_hash[i][2]��
	 * ��ֵ�ڵ��õĹ�������������ͼ���Ƿ��г�ͻ��keyֵ��Ҳ�����Ƿ����ظ���
	 */
    ngx_array_t      *keys_hash;	//	ngx_str_t

	//	�ö�̬������ngx_hash_key_t�ṹ�屣����ǰ��ͨ����ؼ��ֵ�Ԫ��
	//	���ǰ��ͨ���key����������Ժ��ֵ�����磺��*.abc.com������������Ժ󣬱�ɡ�com.abc.��������ڴ������С�
    ngx_array_t       dns_wc_head;	//	ngx_hash_key_t
	/*
	 * һ������򵥵�ɢ�б����������ʽ������hsize��Ԫ��
	 * ÿ��Ԫ�ض���ngx_array_t��̬���顣���û���ӵ�Ԫ�ع����У�
	 * ����ݹؼ��뽫�û���ngx_str_t���͵Ĺؼ�����ӵ�ngx_array_t��̬�����С�
	 * �������е��û�Ԫ�صĹؼ��ֶ���ǰ��ͨ���
	**/
    ngx_array_t      *dns_wc_head_hash;	//	ngx_str_t

	//	�ö�̬������ngx_hash_key_t�ṹ�屣���ź���ͨ����ؼ��ֵ�Ԫ��
	//	��ź���ͨ���key����������Ժ��ֵ�����磺��mail.xxx.*������������Ժ󣬱�ɡ�mail.xxx.��������ڴ������С�
    ngx_array_t       dns_wc_tail;	//	ngx_hash_key_t
	/*
	 * һ������򵥵�ɢ�б����������ʽ������hsize��Ԫ��
	 * ÿ��Ԫ�ض���ngx_array_t��̬���顣���û���ӵ�Ԫ�ع����У�
	 * ����ݹؼ��뽫�û���ngx_str_t���͵Ĺؼ�����ӵ�ngx_array_t��̬�����С�
	 * �������е��û�Ԫ�صĹؼ��ֶ�������ͨ���
	**/
    ngx_array_t      *dns_wc_tail_hash;	//	ngx_str_t
} ngx_hash_keys_arrays_t;


typedef struct {
    ngx_uint_t        hash;
    ngx_str_t         key;
    ngx_str_t         value;
    u_char           *lowcase_key;
} ngx_table_elt_t;


//	���ڲ�ѯԪ��
/*
 * key: ����ɢ�з����������ɢ�йؼ���
 * name: ʵ��key�ĵ�ַ
 * len: ʵ��key�ĳ���
*/
void *ngx_hash_find(ngx_hash_t *hash, ngx_uint_t key, u_char *name, size_t len);
//	���ڲ���ǰ��ͨ���
void *ngx_hash_find_wc_head(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
//	���ڲ��Һ���ͨ���
void *ngx_hash_find_wc_tail(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
void *ngx_hash_find_combined(ngx_hash_combined_t *hash, ngx_uint_t key,
    u_char *name, size_t len);

ngx_int_t ngx_hash_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);
ngx_int_t ngx_hash_wildcard_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);

//	hash��
#define ngx_hash(key, c)   ((ngx_uint_t) key * 31 + c)
ngx_uint_t ngx_hash_key(u_char *data, size_t len);
//	lc��ʾlower case�����ַ���ת��ΪСд���ټ���hashֵ  
ngx_uint_t ngx_hash_key_lc(u_char *data, size_t len);
ngx_uint_t ngx_hash_strlow(u_char *dst, u_char *src, size_t n);

// �ȹ������ngx_hash_keys_arrays_t�ṹ�壬�Ϳ��Ժܷ����
// ngx_hash_init��ngx_hash_wildcard_init��������֧��ͨ�����ɢ�б�
ngx_int_t ngx_hash_keys_array_init(ngx_hash_keys_arrays_t *ha, ngx_uint_t type);
// ������ngx_hash_key_t�ṹ
ngx_int_t ngx_hash_add_key(ngx_hash_keys_arrays_t *ha, ngx_str_t *key,
    void *value, ngx_uint_t flags);


#endif /* _NGX_HASH_H_INCLUDED_ */
