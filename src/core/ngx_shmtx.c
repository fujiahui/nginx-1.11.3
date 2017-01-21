
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_HAVE_ATOMIC_OPS)


static void ngx_shmtx_wakeup(ngx_shmtx_t *mtx);

/*
	�ź�����nginx����Ҫ��Ϊ�������ĸ���ʵ�֣�
	����Ҫ��Ҳ��Ψһ��������ǻ�������lock�Ĳ��֣�
	1. ����ʹ���ź�����Ҳ���ǹص�������ʱ�򣬽�������������
	2. ���û�йص�����lock��ʱ�򣬽���sem_wait�������ߣ������usleep�ó��������Ĳ��֡�
*/

ngx_int_t
ngx_shmtx_create(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr, u_char *name)
{
	// ָ�����ڴ��еĵ�ַ
    mtx->lock = &addr->lock;

	// ���ָ��Ϊ-1 ��ʾ�ر�������
    if (mtx->spin == (ngx_uint_t) -1) {
        return NGX_OK;
    }

    mtx->spin = 2048;	// Ĭ��Ϊ2048

#if (NGX_HAVE_POSIX_SEM)

    mtx->wait = &addr->wait;

	// shared���Ϊ0��ô��ʼ�����ź�������ͬһ�����̵ĸ����̼߳乲��ģ�
	// �������ڽ��̹���ģ�value�Ƿ�����ź����ĳ�ʼֵ
	// int sem_init(sem_t *sem, int shared, unsigned int value);
    if (sem_init(&mtx->sem, 1, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      "sem_init() failed");
    } else {
    	// ��mtx->semaphore��Ϊ1����ʾ�Ѿ��ɹ���ʼ���ź�����
        mtx->semaphore = 1;
    }

#endif

    return NGX_OK;
}


void
ngx_shmtx_destroy(ngx_shmtx_t *mtx)
{
#if (NGX_HAVE_POSIX_SEM)

    if (mtx->semaphore) {
		// ���������ź���
		// int sem_destroy(sem_t *sem);
        if (sem_destroy(&mtx->sem) == -1) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                          "sem_destroy() failed");
        }
    }

#endif
}


ngx_uint_t
ngx_shmtx_trylock(ngx_shmtx_t *mtx)
{
    return (*mtx->lock == 0 && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid));
}


void
ngx_shmtx_lock(ngx_shmtx_t *mtx)
{
    ngx_uint_t         i, n;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "shmtx lock");

    for ( ;; ) {

		// ����lock�е�ֵ�ǲ���0���ǵĻ���ngx_pidֵд�뵽lock��
		// ��x86��ngx_atomic_cmp_set����������Ȼ�����CAS�к���
        if (*mtx->lock == 0 && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid)) {
            return;
        }

        if (ngx_ncpu > 1) {

            for (n = 1; n < mtx->spin; n <<= 1) {

                for (i = 0; i < n; i++) {
                    ngx_cpu_pause();
                }

                if (*mtx->lock == 0
                    && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid))
                {
                    return;
                }
            }
        }

#if (NGX_HAVE_POSIX_SEM)
		// ��������˵����û���õ�mtx->lock��

		// ����ʹ���ź������ź���Ϊ���ѽ���ʼ���ɹ�����ʼ�����ɹ����߲������if
        if (mtx->semaphore) {
			// waitԭ�Ӽ�1�������Ǳ�ʾ���м��������ڴ�sem_t����sem_wait��
			// ���Ҫ�ͺ����wakeup������ϵ������⡣
            (void) ngx_atomic_fetch_add(mtx->wait, 1);

			// ����ȥ��ȡһ����������ɹ���waitԭ�Ӽ�1��
			// ��Ϊ����return���ˣ���û����sem_wait��wait����һ���ԭ�Ӽ�1�ͻع���
            if (*mtx->lock == 0 && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid)) {
                (void) ngx_atomic_fetch_add(mtx->wait, -1);
                return;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                           "shmtx wait %uA", *mtx->wait);

			// ���ڸ��ź�����1���������ź���С�ڵ���0��ʱ��������ֱ���ź�������0
			// int sem_wait(sem_t *sem);
			// sem_wait��1�����С��1���������ȴ���������ȥwake up
            while (sem_wait(&mtx->sem) == -1) {
                ngx_err_t  err;

                err = ngx_errno;

				// err==EINTR��ʾ�жϣ����Ǵ��󣬿��Լ���sem_wait�ȴ�
                if (err != NGX_EINTR) {
                    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, err,
                                  "sem_wait() failed while waiting on shmtx");
                    break;
                }
            }

            ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                           "shmtx awoke");

            continue;
        }

#endif

        ngx_sched_yield();
    }
}


void
ngx_shmtx_unlock(ngx_shmtx_t *mtx)
{
    if (mtx->spin != (ngx_uint_t) -1) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "shmtx unlock");
    }

	// ����lock�е�ֵ�ǲ���ngx_pid���ǵĻ���0ֵд�뵽lock��
	// ���ǵĻ�˵������������ռ�������ͷŲ�����Ȼʧ��
	// ��x86��ngx_atomic_cmp_set����������Ȼ�����CAS�к���

	// ��������lock��Ϊ0
    if (ngx_atomic_cmp_set(mtx->lock, ngx_pid, 0)) {
		// ����ɹ���wakeup�����Ľ���
        ngx_shmtx_wakeup(mtx);
    }
}


ngx_uint_t
ngx_shmtx_force_unlock(ngx_shmtx_t *mtx, ngx_pid_t pid)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "shmtx forced unlock");

    if (ngx_atomic_cmp_set(mtx->lock, pid, 0)) {
        ngx_shmtx_wakeup(mtx);
        return 1;
    }

    return 0;
}


static void
ngx_shmtx_wakeup(ngx_shmtx_t *mtx)
{
#if (NGX_HAVE_POSIX_SEM)
    ngx_atomic_uint_t  wait;

	// �ź�����ʼ������ֱ�ӷ��أ�˵������û�õ��ź���
    if (!mtx->semaphore) {
        return;
    }

    for ( ;; ) {

        wait = *mtx->wait;

		// ���û�н������ź�������wait����ֱ��return���������lock
        if ((ngx_atomic_int_t) wait <= 0) {
            return;
        }

		// ����г���������wait���ͼ�ȥһ��
        if (ngx_atomic_cmp_set(mtx->wait, wait, wait - 1)) {
            break;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "shmtx wake %uA", wait);

	// ���ڸ��ź�������1����
	// int sem_post(sem_t *sem);
	// ����ȥsem_postȥ֪ͨ��sem_wait�Ľ��̡�
    if (sem_post(&mtx->sem) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      "sem_post() failed while wake shmtx");
    }

#endif
}


#else


ngx_int_t
ngx_shmtx_create(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr, u_char *name)
{
    if (mtx->name) {

        if (ngx_strcmp(name, mtx->name) == 0) {
            mtx->name = name;
            return NGX_OK;
        }

        ngx_shmtx_destroy(mtx);
    }

    mtx->fd = ngx_open_file(name, NGX_FILE_RDWR, NGX_FILE_CREATE_OR_OPEN,
                            NGX_FILE_DEFAULT_ACCESS);

    if (mtx->fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", name);
        return NGX_ERROR;
    }

    if (ngx_delete_file(name) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      ngx_delete_file_n " \"%s\" failed", name);
    }

    mtx->name = name;

    return NGX_OK;
}


void
ngx_shmtx_destroy(ngx_shmtx_t *mtx)
{
    if (ngx_close_file(mtx->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", mtx->name);
    }
}


ngx_uint_t
ngx_shmtx_trylock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    err = ngx_trylock_fd(mtx->fd);

    if (err == 0) {
        return 1;
    }

    if (err == NGX_EAGAIN) {
        return 0;
    }

#if __osf__ /* Tru64 UNIX */

    if (err == NGX_EACCES) {
        return 0;
    }

#endif

    ngx_log_abort(err, ngx_trylock_fd_n " %s failed", mtx->name);

    return 0;
}


void
ngx_shmtx_lock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    err = ngx_lock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    ngx_log_abort(err, ngx_lock_fd_n " %s failed", mtx->name);
}


void
ngx_shmtx_unlock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    err = ngx_unlock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    ngx_log_abort(err, ngx_unlock_fd_n " %s failed", mtx->name);
}


ngx_uint_t
ngx_shmtx_force_unlock(ngx_shmtx_t *mtx, ngx_pid_t pid)
{
    return 0;
}

#endif
