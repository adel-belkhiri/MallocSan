/* Exercise pthread_cond_* through MallocSan's wrappers: condvars on the stack,
   in static storage, and in TAINTED heap memory; wait/signal and wait/broadcast. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct box { pthread_mutex_t m; pthread_cond_t c; int ready; int done; };

static void init_box(struct box *b){
	pthread_mutex_init(&b->m, NULL); pthread_cond_init(&b->c, NULL);
	b->ready = 0; b->done = 0;
}
static void *waiter(void *arg){
	struct box *b = arg;
	pthread_mutex_lock(&b->m);
	while (!b->ready) pthread_cond_wait(&b->c, &b->m);
	b->done++;
	pthread_mutex_unlock(&b->m);
	return NULL;
}
/* returns 0 on success, 1 if the wakeup was lost (would hang without the alarm) */
static int run(struct box *b, int nthreads, int broadcast, const char *what){
	pthread_t t[8];
	init_box(b);
	printf("    [start %s]\n", what); for (int i = 0; i < nthreads; i++) pthread_create(&t[i], NULL, waiter, b);
	usleep(120000);
	pthread_mutex_lock(&b->m);
	b->ready = 1;
	if (broadcast) pthread_cond_broadcast(&b->c);
	else for (int i = 0; i < nthreads; i++) pthread_cond_signal(&b->c);
	pthread_mutex_unlock(&b->m);
	for (int i = 0; i < nthreads; i++) pthread_join(t[i], NULL);
	int ok = (b->done == nthreads);
	printf("  %-34s woke %d/%d  %s\n", what, b->done, nthreads, ok?"OK":"LOST WAKEUP"); fflush(stdout);
	return ok?0:1;
}
int main(void){
	setvbuf(stdout,NULL,_IONBF,0); alarm(40);                      /* a lost wakeup would hang forever */
	int bad = 0;
	struct box stackbox;
	bad += run(&stackbox, 4, 0, "stack condvar, cond_signal");
	bad += run(&stackbox, 4, 1, "stack condvar, cond_broadcast");
	static struct box staticbox;
	bad += run(&staticbox, 4, 0, "static condvar, cond_signal");
	struct box *heapbox = malloc(sizeof *heapbox);   /* TAINTED under MallocSan */
	bad += run(heapbox, 4, 0, "tainted-heap condvar, signal");
	bad += run(heapbox, 4, 1, "tainted-heap condvar, broadcast");
	free(heapbox);
	printf("failures=%d\n", bad);
	return bad?1:0;
}
