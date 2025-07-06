/**
 * selector.c - un muliplexor de entrada salida
 */
#include <assert.h> // :)
#include <errno.h>	// :)
#include <pthread.h>
#include <stdio.h>	// perror
#include <stdlib.h> // malloc
#include <string.h> // memset

#include "../include/selector.h"
#include <fcntl.h>
#include <stdint.h> // SIZE_MAX
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define N(x) (sizeof(x) / sizeof((x)[0]))

#define ERROR_DEFAULT_MSG "something failed"

/** retorna una descripción humana del fallo */
const char *selector_error(const selector_status status) {
	const char *msg;
	switch (status) {
		case SELECTOR_SUCCESS:
			msg = "Success";
			break;
		case SELECTOR_ENOMEM:
			msg = "Not enough memory";
			break;
		case SELECTOR_MAXFD:
			msg = "Can't handle any more file descriptors";
			break;
		case SELECTOR_IARGS:
			msg = "Illegal argument";
			break;
		case SELECTOR_IO:
			msg = "I/O error";
			break;
		default:
			msg = ERROR_DEFAULT_MSG;
	}
	return msg;
}

static void wake_handler(const int signal) {
	(void) signal;
	// nada que hacer. está solo para interrumpir el select
}

// señal a usar para las notificaciones de resolución
struct selector_init conf;
static sigset_t emptyset, blockset;

selector_status selector_init(const struct selector_init *c) {
	memcpy(&conf, c, sizeof(conf));

	// inicializamos el sistema de comunicación entre threads y el selector
	// principal. La técnica se encuentra descripta en
	// "The new pselect() system call" <https://lwn.net/Articles/176911/>
	//  March 24, 2006
	selector_status ret = SELECTOR_SUCCESS;
	struct sigaction act = {
		.sa_handler = wake_handler,
	};

	// 0. calculamos mascara para evitar que se interrumpa antes de llegar al
	//    select
	sigemptyset(&blockset);
	sigaddset(&blockset, conf.signal);
	if (-1 == sigprocmask(SIG_BLOCK, &blockset, NULL)) {
		ret = SELECTOR_IO;
		goto finally;
	}

	// 1. Registramos una función que atenderá la señal de interrupción
	//    del selector.
	//    Esta interrupción es útil en entornos multi-hilos.

	if (sigaction(conf.signal, &act, 0)) {
		ret = SELECTOR_IO;
		goto finally;
	}
	sigemptyset(&emptyset);

finally:
	return ret;
}

selector_status selector_close(void) {
	// Nada para liberar.
	// TODO(juan): podriamos reestablecer el handler de la señal.
	return SELECTOR_SUCCESS;
}

// estructuras internas
struct item {
	int fd;
	fd_interest interest;
	const fd_handler *handler;
	void *data;
};

/* tarea bloqueante */
struct blocking_job {
	/** selector dueño de la resolucion */
	fd_selector s;
	/** file descriptor dueño de la resolucion */
	int fd;

	/** datos del trabajo provisto por el usuario */
	void *data;

	/** el siguiente en la lista */
	struct blocking_job *next;
};

/** marca para usar en item->fd para saber que no está en uso */
static const int FD_UNUSED = -1;

/** verifica si el item está usado */
#define ITEM_USED(i) ((FD_UNUSED != (i)->fd))

struct fdselector {
	// almacenamos en una jump table donde la entrada es el file descriptor.
	// Asumimos que el espacio de file descriptors no va a ser esparso; pero
	// esto podría mejorarse utilizando otra estructura de datos
	struct item *fds;
	size_t fd_size; // cantidad de elementos posibles de fds

	int epoll_fd;
	struct epoll_event *events;
	size_t max_events; // max number of events that can be handled at once

	/** timeout prototipico para usar en select() */
	struct timespec master_t;
	/** tambien select() puede cambiar el valor */
	struct timespec slave_t;

	// notificaciónes entre blocking jobs y el selector
	volatile pthread_t selector_thread;
	/** protege el acceso a resolutions jobs */
	pthread_mutex_t resolution_mutex;
	/**
	 * lista de trabajos blockeantes que finalizaron y que pueden ser
	 * notificados.
	 */
	struct blocking_job *resolution_jobs;
};

/** cantidad máxima de file descriptors que la plataforma puede manejar */
#define ITEMS_MAX_SIZE FD_SETSIZE

// en esta implementación el máximo está dado por el límite natural de select(2).

/**
 * determina el tamaño a crecer, generando algo de slack para no tener
 * que realocar constantemente.
 */
static size_t next_capacity(const size_t n) {
	unsigned bits = 0;
	size_t tmp = n;
	while (tmp != 0) {
		tmp >>= 1;
		bits++;
	}
	tmp = 1UL << bits;

	assert(tmp >= n);
	if (tmp > ITEMS_MAX_SIZE) {
		tmp = ITEMS_MAX_SIZE;
	}

	return tmp + 1;
}

static inline void item_init(struct item *item) {
	item->fd = FD_UNUSED;
}

/**
 * inicializa los nuevos items. `last' es el indice anterior.
 * asume que ya está blanqueada la memoria.
 */
static void items_init(fd_selector s, const size_t last) {
	assert(last <= s->fd_size);
	for (size_t i = last; i < s->fd_size; i++) {
		item_init(s->fds + i);
	}
}

/**
 * garantizar cierta cantidad de elemenos en `fds'.
 * Se asegura de que `n' sea un número que la plataforma donde corremos lo
 * soporta
 */
static selector_status ensure_capacity(fd_selector s, const size_t n) {
	selector_status ret = SELECTOR_SUCCESS;

	const size_t element_size = sizeof(*s->fds);
	if (n < s->fd_size) {
		// nada para hacer, entra...
		ret = SELECTOR_SUCCESS;
	} else if (n > ITEMS_MAX_SIZE) {
		// me estás pidiendo más de lo que se puede.
		ret = SELECTOR_MAXFD;
	} else if (NULL == s->fds) {
		// primera vez.. alocamos
		const size_t new_size = next_capacity(n);

		s->fds = calloc(new_size, element_size);
		if (NULL == s->fds) {
			ret = SELECTOR_ENOMEM;
		} else {
			s->fd_size = new_size;
			items_init(s, 0);
		}
	} else {
		// hay que agrandar...
		const size_t new_size = next_capacity(n);
		if (new_size > SIZE_MAX / element_size) { // ver MEM07-C
			ret = SELECTOR_ENOMEM;
		} else {
			struct item *tmp = realloc(s->fds, new_size * element_size);
			if (NULL == tmp) {
				ret = SELECTOR_ENOMEM;
			} else {
				s->fds = tmp;
				const size_t old_size = s->fd_size;
				s->fd_size = new_size;

				items_init(s, old_size);
			}
		}
	}

	return ret;
}

fd_selector selector_new(const size_t initial_elements) {
	size_t size = sizeof(struct fdselector);
	fd_selector ret = malloc(size);
	if (ret != NULL) {
		memset(ret, 0x00, size);
		ret->master_t.tv_sec = conf.select_timeout.tv_sec;
		ret->master_t.tv_nsec = conf.select_timeout.tv_nsec;
		ret->resolution_jobs = 0;
		pthread_mutex_init(&ret->resolution_mutex, 0);
		if (0 != ensure_capacity(ret, initial_elements)) {
			selector_destroy(ret);
			ret = NULL;
		} else {
			// max events that can be handled at once
			ret->max_events = initial_elements > 0 ? initial_elements : 1024;
			ret->events = calloc(ret->max_events, sizeof(struct epoll_event));
			if (!ret->events) {
				selector_destroy(ret);
				return NULL;
			}
			ret->epoll_fd = epoll_create1(0);
			if (ret->epoll_fd == -1) {
				perror("epoll_create1");
				selector_destroy(ret);
				return NULL;
			}
		}
	}
	return ret;
}

void selector_destroy(fd_selector s) {
	if (s != NULL) {
		if (s->fds != NULL) {
			for (size_t i = 0; i < s->fd_size; i++) {
				if (ITEM_USED(s->fds + i)) {
					selector_unregister_fd(s, i);
				}
			}
			pthread_mutex_destroy(&s->resolution_mutex);
			struct blocking_job *j = s->resolution_jobs;
			while (j != NULL) {
				struct blocking_job *aux = j;
				j = j->next;
				free(aux);
			}
			free(s->fds);
			s->fds = NULL;
			s->fd_size = 0;
		}
		// free all events in list
		if (s->events) {
			free(s->events);
			s->events = NULL;
		}
		if (s->epoll_fd != -1) {
			close(s->epoll_fd);
			s->epoll_fd = -1;
		}
		free(s);
	}
}

#define INVALID_FD(fd) ((fd) < 0 || (fd) >= ITEMS_MAX_SIZE)

static uint32_t interest_to_epoll_events(fd_interest interest) {
	uint32_t events = 0;
	if (interest & OP_READ)
		events |= EPOLLIN;
	if (interest & OP_WRITE)
		events |= EPOLLOUT;
	return events;
}

selector_status selector_register(fd_selector s, const int fd, const fd_handler *handler, const fd_interest interest,
								  void *data) {
	selector_status ret = SELECTOR_SUCCESS;
	if (s == NULL || INVALID_FD(fd) || handler == NULL) {
		ret = SELECTOR_IARGS;
		goto finally;
	}
	size_t ufd = (size_t) fd;
	if (ufd > s->fd_size) {
		ret = ensure_capacity(s, ufd);
		if (SELECTOR_SUCCESS != ret) {
			goto finally;
		}
	}
	struct item *item = s->fds + ufd;
	if (ITEM_USED(item)) {
		ret = SELECTOR_FDINUSE;
		goto finally;
	} else {
		item->fd = fd;
		item->handler = handler;
		item->interest = interest;
		item->data = data;
		struct epoll_event ev = {0};
		ev.events = interest_to_epoll_events(interest);
		ev.data.ptr = item;
		if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
			perror("epoll_ctl: add");
			memset(item, 0x00, sizeof(*item));
			item_init(item);
			ret = SELECTOR_IO;
			goto finally;
		}
	}
finally:
	return ret;
}

selector_status selector_unregister_fd(fd_selector s, const int fd) {
	selector_status ret = SELECTOR_SUCCESS;
	if (NULL == s || INVALID_FD(fd)) {
		ret = SELECTOR_IARGS;
		goto finally;
	}
	struct item *item = s->fds + fd;
	if (!ITEM_USED(item)) {
		ret = SELECTOR_IARGS;
		goto finally;
	}
	if (item->handler->handle_close != NULL) {
		struct selector_key key = {
			.s = s,
			.fd = item->fd,
			.data = item->data,
		};
		item->handler->handle_close(&key);
	}
	item->interest = OP_NOOP;
	epoll_ctl(s->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
	memset(item, 0x00, sizeof(*item));
	item_init(item);
finally:
	return ret;
}

selector_status selector_set_interest(fd_selector s, int fd, fd_interest i) {
	selector_status ret = SELECTOR_SUCCESS;
	if (NULL == s || INVALID_FD(fd)) {
		ret = SELECTOR_IARGS;
		goto finally;
	}
	struct item *item = s->fds + fd;
	if (!ITEM_USED(item)) {
		ret = SELECTOR_IARGS;
		goto finally;
	}
	item->interest = i;
	struct epoll_event ev = {0};
	ev.events = interest_to_epoll_events(i);
	ev.data.ptr = item;
	if (epoll_ctl(s->epoll_fd, EPOLL_CTL_MOD, fd, &ev) == -1) {
		perror("epoll_ctl: mod");
		ret = SELECTOR_IO;
	}
finally:
	return ret;
}

selector_status selector_set_interest_key(struct selector_key *key, fd_interest i) {
	selector_status ret;
	if (NULL == key || NULL == key->s || INVALID_FD(key->fd)) {
		ret = SELECTOR_IARGS;
	} else {
		ret = selector_set_interest(key->s, key->fd, i);
	}
	return ret;
}

/**
 * se encarga de manejar los resultados del select.
 * se encuentra separado para facilitar el testing
 */
static void handle_block_notifications(fd_selector s) {
	struct selector_key key = {
		.s = s,
	};
	pthread_mutex_lock(&s->resolution_mutex);
	struct blocking_job *j = s->resolution_jobs;
	while (j != NULL) {
		struct item *item = s->fds + j->fd;
		if (ITEM_USED(item)) {
			key.fd = item->fd;
			key.data = item->data;
			item->handler->handle_block(&key);
		}

		struct blocking_job *aux = j;
		j = j->next;
		free(aux);
	}
	s->resolution_jobs = 0;
	pthread_mutex_unlock(&s->resolution_mutex);
}

selector_status selector_notify_block(fd_selector s, const int fd) {
	selector_status ret = SELECTOR_SUCCESS;

	// TODO(juan): usar un pool
	struct blocking_job *job = malloc(sizeof(*job));
	if (job == NULL) {
		ret = SELECTOR_ENOMEM;
		goto finally;
	}
	job->s = s;
	job->fd = fd;

	// encolamos en el selector los resultados
	pthread_mutex_lock(&s->resolution_mutex);
	job->next = s->resolution_jobs;
	s->resolution_jobs = job;
	pthread_mutex_unlock(&s->resolution_mutex);

	// notificamos al hilo principal
	pthread_kill(s->selector_thread, conf.signal);

finally:
	return ret;
}

selector_status selector_select(fd_selector s) {
	selector_status ret = SELECTOR_SUCCESS;
	s->selector_thread = pthread_self();
	int timeout_ms = (int) (s->master_t.tv_sec * 1000 + s->master_t.tv_nsec / 1000000);
	int n = epoll_wait(s->epoll_fd, s->events, s->max_events, timeout_ms);
	if (n < 0) {
		if (errno == EINTR) {
			// interrupted by signal, ok
		} else {
			perror("epoll_wait");
			ret = SELECTOR_IO;
			goto finally;
		}
	}
	for (int i = 0; i < n; i++) {
		struct item *item = (struct item *) s->events[i].data.ptr;
		if (!item || !ITEM_USED(item) || !item->handler)
			continue;
		struct selector_key key = {
			.s = s,
			.fd = item->fd,
			.data = item->data,
		};
		uint32_t ev = s->events[i].events;
		if ((ev & EPOLLIN) && (item->interest & OP_READ) && item->handler->handle_read) {
			item->handler->handle_read(&key);
		}
		if ((ev & EPOLLOUT) && (item->interest & OP_WRITE) && item->handler->handle_write) {
			item->handler->handle_write(&key);
		}
		if ((ev & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) && item->handler->handle_close) {
			item->handler->handle_close(&key);
		}
	}
	handle_block_notifications(s);
finally:
	return ret;
}

int selector_fd_set_nio(const int fd) {
	int ret = 0;
	// TODO: Check! Changed this: int flags = fcntl(fd, F_GETFD, 0);
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		ret = -1;
	} else {
		if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
			ret = -1;
		}
	}
	return ret;
}

// selector_status selector_unregister_fd_noclose(fd_selector s, const int fd) {
// 	selector_status ret = SELECTOR_SUCCESS;

// 	if (NULL == s || INVALID_FD(fd)) {
// 		ret = SELECTOR_IARGS;
// 		goto finally;
// 	}

// 	struct item *item = s->fds + fd;
// 	if (!ITEM_USED(item)) {
// 		ret = SELECTOR_IARGS;
// 		goto finally;
// 	}

// 	item->interest = OP_NOOP;
// 	epoll_ctl(s->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
// 	memset(item, 0x00, sizeof(*item));
// 	item_init(item);

// finally:
// 	return ret;
// }