/*
 * Copyright (C) 2017 Nikos Mavrogiannopoulos
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <gnutls/gnutls.h>

/* Unit test for _cstp_recv_packet(). I checks whether
 * CSTP packets are received and decoded as expected.
 */
static unsigned int verbose;
#define UNDER_TEST
#define force_write write

#include "../src/tlslib.c"

int get_cert_names(worker_st *ws, const gnutls_datum_t *raw)
{
	return 0;
}

#define MAX_SIZE 256
#define ITERATIONS 1024

void writer(int fd)
{
	unsigned int size, i, j;
	unsigned char buf[MAX_SIZE + 8];

	memset(buf, 0, sizeof(buf));

	for (i = 0; i < ITERATIONS; i++) {
		assert(gnutls_rnd(GNUTLS_RND_NONCE, &size,
				  sizeof(unsigned int)) >= 0);

		size %= MAX_SIZE;
		size++; /* non-zero */

		buf[4] = (size >> 8) & 0xff;
		buf[5] = size & 0xff;

		size += 8;

		if (verbose)
			fprintf(stderr, "sending %d\n", size);
		for (j = 0; j < size; j++) { /* use multiple writes */
			assert(write(fd, buf + j, 1) == 1);
		}
	}
}

void receiver(int fd)
{
	worker_st ws = { 0 };
	unsigned char buf[MAX_SIZE * 3];
	int ret;
	unsigned int i;
	ws.conn_fd = fd;

	for (i = 0; i < ITERATIONS; i++) {
		ret = _cstp_recv_packet(&ws, buf, sizeof(buf));
		if (verbose)
			fprintf(stderr, "received %d\n", ret);
		assert(ret > 0);
	}
}

/* Writes a CSTP header announcing a BODY_SIZE-byte body, but only
 * BODY_SIZE/2 bytes of body, then closes the socket - simulating a
 * proxy connection dropped mid-packet. A correct _cstp_recv_packet()
 * must report this as an error, not as a successful, fully-populated
 * packet built from a truncated buffer. */
#define NEG_BODY_SIZE 64

void neg_writer(int fd)
{
	unsigned char buf[8 + NEG_BODY_SIZE] = { 0 };

	buf[4] = (NEG_BODY_SIZE >> 8) & 0xff;
	buf[5] = NEG_BODY_SIZE & 0xff;

	assert(write(fd, buf, 8 + NEG_BODY_SIZE / 2) == 8 + NEG_BODY_SIZE / 2);

	close(fd);
}

void neg_receiver(int fd)
{
	worker_st ws = { 0 };
	unsigned char buf[8 + NEG_BODY_SIZE];
	int ret;

	ws.conn_fd = fd;

	ret = _cstp_recv_packet(&ws, buf, sizeof(buf));
	if (verbose)
		fprintf(stderr, "negative test received %d\n", ret);

	if (ret > 0) {
		fprintf(stderr,
			"FAIL: expected error on truncated packet, got %d\n",
			ret);
		exit(1);
	}
}

void run_negative_test(void)
{
	int sockets[2];
	pid_t child;
	int status = 0;

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) >= 0);

	child = fork();
	assert(child >= 0);

	if (child) {
		close(sockets[1]);
		neg_receiver(sockets[0]);
		wait(&status);
		if (WEXITSTATUS(status) != 0) {
			fprintf(stderr, "negative test child failed %d!\n",
				(int)WEXITSTATUS(status));
			exit(1);
		}
	} else {
		close(sockets[0]);
		neg_writer(sockets[1]);
		exit(0);
	}
}

int main(int argc, char *argv[])
{
	int sockets[2];
	pid_t child;
	int status = 0;

	if (argc > 1)
		verbose = 1;

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) >= 0);

	child = fork();
	assert(child >= 0);

	if (child) {
		close(sockets[1]);
		receiver(sockets[0]);
		wait(&status);
		if (WEXITSTATUS(status) != 0) {
			fprintf(stderr, "child failed %d!\n",
				(int)WEXITSTATUS(status));
			exit(1);
		}
	} else {
		close(sockets[0]);
		writer(sockets[1]);
		return 0;
	}

	run_negative_test();

	return 0;
}
