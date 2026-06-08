/*
 * sandbox_run - запуск нового процесса в песочнице.
 *
 * Регистрирует собственный pid в /proc/sandbox/control, затем execvp() целевой
 * команды. pid при exec сохраняется, поэтому запускаемая программа сразу
 * оказывается под эмуляцией.
 *
 *   sudo sandbox_run <команда> [аргументы...]
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

int main(int argc, char **argv)
{
	char buf[64];
	int fd, n;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <command> [args...]\n", argv[0]);
		return 2;
	}

	fd = open("/proc/sandbox/control", O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "open /proc/sandbox/control: %s\n"
			"(модуль загружен? права root?)\n", strerror(errno));
		return 1;
	}

	n = snprintf(buf, sizeof(buf), "add %d\n", (int)getpid());
	if (write(fd, buf, n) != n) {
		fprintf(stderr, "write control: %s\n", strerror(errno));
		close(fd);
		return 1;
	}
	close(fd);

	/*
	 * Пометить окружение, чтобы было видно, что shell работает в песочнице.
	 * debian_chroot подхватывается стандартным .bashrc в Mint/Ubuntu и
	 * показывается в начале промпта как (sandbox).
	 */
	setenv("debian_chroot", "sandbox", 1);
	setenv("SANDBOX", "1", 1);

	execvp(argv[1], &argv[1]);
	fprintf(stderr, "execvp %s: %s\n", argv[1], strerror(errno));
	return 127;
}
