#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "tsc.h"
#define USE_PTHREAD
#undef USE_PTHREAD

// #define FLOOD_BY_GETPID
#define FLOOD_BY_WRITE

#define CPUBIND_OFFSET 0
#define NR_THREAD_PARAMS 64
#ifdef USE_PTHREAD
typedef struct thread_param_s {
  unsigned int threadid;
  int loop;
  pthread_barrier_t *barrier;
  pthread_mutex_t *print_lock;
  pthread_t thread;
} thread_param_t;

static thread_param_t thread_params[NR_THREAD_PARAMS];

static void *run(void *arg) {
  thread_param_t *param = (thread_param_t *)arg;
  int loop = param->loop;
  uint64_t ts;
  cpu_set_t cpuset;

  CPU_ZERO(&cpuset);
  CPU_SET(param->threadid, &cpuset);
  if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) < 0) {
    perror("cpu_setaffinity");
    return NULL;
  }
  // pthread_barrier_wait(param->barrier);

  ts = -nod_rdtsc();
  for (int i = 0; i < loop; i++) {
    (void volatile) getpid();
  }
  ts += nod_rdtsc();

  pthread_mutex_lock(param->print_lock);
  printf("getpid(tid=%d) called %d times, total ts: %lu\n", param->threadid,
         loop, ts);
  pthread_mutex_unlock(param->print_lock);
  return NULL;
}
#else
static int pids[NR_THREAD_PARAMS];
void run(int id, int loop) {
  int pid;
  uint64_t ts;
  cpu_set_t cpuset;

  CPU_ZERO(&cpuset);
  CPU_SET(CPUBIND_OFFSET + id, &cpuset);
  if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) < 0) {
    perror("cpu_setaffinity");
    goto out;
  }

  pid = getpid();

#if defined(FLOOD_BY_WRITE)
  char buf[2];
  int fd = open("/dev/null", O_WRONLY);
  if (fd < 0) {
    perror("open /dev/null");
    goto out;
  }
  snprintf(buf, sizeof(buf), "%d", id);
#endif

  ts = -nod_rdtsc();
  for (int i = 0; i < loop; i++) {
#if defined(FLOOD_BY_GETPID)
    (void volatile) getpid();
#elif defined(FLOOD_BY_WRITE)
    (void)!write(fd, buf, sizeof(buf));
#endif
  }
  ts += nod_rdtsc();

  printf("getpid(pid=%d) called %d times, total ticks: %lu\n", pid, loop, ts);
#if defined(FLOOD_BY_WRITE)
  close(fd);
#endif
out:
  exit(0);
}
#endif

int main(int argc, char *argv[]) {
  int loop, nthreads = 1;
  uint64_t ts;
  pthread_barrier_t barrier;
  pthread_mutex_t print_lock;

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <number of iterations> <#threads>\n", argv[0]);
    return -1;
  }

  loop = atoi(argv[1]);
  if (argc >= 3) {
    nthreads = atoi(argv[2]);
  }

  if (nthreads > NR_THREAD_PARAMS) {
    fprintf(stderr, "Maximum number of threads is %d\n", NR_THREAD_PARAMS);
    return -1;
  }

#ifdef USE_PTHREAD
  pthread_barrier_init(&barrier, NULL, nthreads);
  pthread_mutex_init(&print_lock, NULL);

  for (int i = 0; i < nthreads; i++) {
    thread_params[i].threadid = i;
    thread_params[i].loop = loop;
    thread_params[i].barrier = &barrier;
    thread_params[i].print_lock = &print_lock;
    pthread_create(&thread_params[i].thread, NULL, run, &thread_params[i]);
  }

  for (int i = 0; i < nthreads; i++) {
    pthread_join(thread_params[i].thread, NULL);
  }
#else
  for (int i = 0; i < nthreads; i++) {
    pids[i] = fork();
    if (pids[i] == 0) {
      run(i, loop);
    }
  }

  for (int i = 0; i < nthreads; i++) {
    waitpid(pids[i], NULL, 0);
  }
#endif

  return 0;
}
