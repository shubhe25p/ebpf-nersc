#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

#define TRACEFS_PIPE	"/sys/kernel/tracing/trace_pipe"
#define DEBUGFS_PIPE "/sys/kernel/debug/tracing/trace_pipe"

int read_trace_pipe_iter(void (*cb)(const char *str, void *data), void *data, int iter)
{
	size_t buflen, n;
	char *buf = NULL;
	FILE *fp = NULL;

	if (access(TRACEFS_PIPE, F_OK) == 0)
		fp = fopen(TRACEFS_PIPE, "r");
	else
		fp = fopen(DEBUGFS_PIPE, "r");
	if (!fp)
		return -1;

	 /* We do not want to wait forever when iter is specified. */
	if (iter)
		fcntl(fileno(fp), F_SETFL, O_NONBLOCK);

	while ((n = getline(&buf, &buflen, fp) >= 0) || errno == EAGAIN) {
		if (n > 0)
			cb(buf, data);
		if (iter && !(--iter))
			break;
	}

	free(buf);
	if (fp)
		fclose(fp);
	return 0;
}

static void trace_pipe_cb(const char *str, void *data)
{
	printf("%s", str);
}

void read_trace_pipe(void)
{
	read_trace_pipe_iter(trace_pipe_cb, NULL, 0);
}

int main()
{
	read_trace_pipe();
	return 0;
}