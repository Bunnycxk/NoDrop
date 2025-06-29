#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "ioctl.h"

int main(int argc, char *argv[]) {
  int fd, ret;
  FILE *file;
  char *buf;
  uint64_t len;
  nod_ioctl_data_t data;

  if (argc < 2) {
    fprintf(stderr,
            "Usage: %s [clean|fetch|stat|clear-stat|start|stop|count|bufsize "
            "(size in KB)]\n",
            argv[0]);
    return 0;
  }

  fd = open(NOD_IOCTL_PATH, O_RDWR);
  if (fd < 0) {
    perror("Cannot open " NOD_IOCTL_PATH);
    return 127;
  }

  if (!strcmp(argv[1], "clean")) {
    if (!ioctl(fd, NOD_IOCTL_CLEAR_BUFFER, 0))
      fprintf(stderr, "Success\n");
  } else if (!strcmp(argv[1], "fetch")) {
    if ((ret = ioctl(fd, NOD_IOCTL_READ_BUFFER_COUNT_INFO, &data))) {
      fprintf(stderr, "Get Buffer Count Info failed, reason %d\n", ret);
      return -1;
    }

    len = data.buffer_count.unflushed_len;
    buf = malloc(len);
    if (!data.fetch_buffer.buf) {
      fprintf(stderr, "Allocate memory failed\n");
      return -1;
    }

    data.fetch_buffer.len = len;
    data.fetch_buffer.buf = buf;
    if ((ret = ioctl(fd, NOD_IOCTL_FETCH_BUFFER, &data))) {
      fprintf(stderr, "Fetch Buffer failed, reason %d\n", ret);
      return -1;
    }

    if (argc <= 2)
      file = stdout;
    else
      file = fopen(argv[2], "wb");
    if (!file) {
      fprintf(stderr, "Cannot open file\n");
      return -1;
    }

    if (fwrite(data.fetch_buffer.buf, data.fetch_buffer.len, 1, file) == 1) {
      fprintf(stderr, "Write %lu bytes to file %s\n", data.fetch_buffer.len,
              argc <= 2 ? "stdout" : argv[2]);
    } else {
      fprintf(stderr, "Write to file %s failed\n",
              argc <= 2 ? "stdout" : argv[2]);
    }

    if (file != stdout)
      fclose(file);

  } else if (!strcmp(argv[1], "count")) {
    if (!ioctl(fd, NOD_IOCTL_READ_BUFFER_COUNT_INFO, &data)) {
      printf("event_count=%lu,unflushed_count=%lu,unflushed_len=%lu\n",
             data.buffer_count.event_count, data.buffer_count.unflushed_count,
             data.buffer_count.unflushed_len);
    }
  } else if (!strcmp(argv[1], "stat")) {
    if (!ioctl(fd, NOD_IOCTL_READ_STATISTICS, &data)) {
      printf("n_evts\tdrop_evts\tdrop_unsolved\n%ld\t%ld\t%ld\n",
             data.event_stat.n_evts, data.event_stat.n_drop_evts,
             data.event_stat.n_drop_evts_unsolved);
    }
  } else if (!strcmp(argv[1], "clear-stat")) {
    if (!ioctl(fd, NOD_IOCTL_CLEAR_STATISTICS, 0)) {
      fprintf(stderr, "Statistics cleared\n");
    }
  } else if (!strcmp(argv[1], "stop")) {
    if (!ioctl(fd, NOD_IOCTL_STOP_RECORDING, 0))
      fprintf(stderr, "Stopped\n");

  } else if (!strcmp(argv[1], "start")) {
    if (!ioctl(fd, NOD_IOCTL_START_RECORDING, 0))
      fprintf(stderr, "Start\n");

  } else if (!strcmp(argv[1], "bufsize")) {
    if (argc >= 3) {
      data.buffer_size.bufsize = (unsigned long)atol(argv[2]) * 1024;
      if ((ret = ioctl(fd, NOD_IOCTL_SET_BUFFER_SIZE, &data))) {
        fprintf(stderr, "set buffer size failed: %d\n", ret);
        return -1;
      }
    }
    if ((ret = ioctl(fd, NOD_IOCTL_GET_BUFFER_SIZE, &data))) {
      fprintf(stderr, "get buffer size failed: %d\n", ret);
      return -1;
    }
    printf("buffer size: %lu\n", data.buffer_size.bufsize);
  } else if (!strcmp(argv[1], "comm")) {
    if (argc >= 3) {
      strncpy(data.target_comm.comm, argv[2], NOD_TARGET_COMM_MAX_LEN - 1);
      data.target_comm.comm[NOD_TARGET_COMM_MAX_LEN - 1] = '\0';
      if ((ret = ioctl(fd, NOD_IOCTL_SET_TARGET_COMM, &data))) {
        fprintf(stderr, "set target comm failed: %d\n", ret);
      }
    }
    if ((ret = ioctl(fd, NOD_IOCTL_GET_TARGET_COMM, &data))) {
      fprintf(stderr, "get target comm failed: %d\n", ret);
      return -1;
    }
    printf("target comm: \"%s\"\n", data.target_comm.comm);
  } else {
    fprintf(stderr, "Unknown cmd %s\n", argv[1]);
  }

  return 0;
}
