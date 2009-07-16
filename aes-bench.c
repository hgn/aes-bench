/*
** Copyright (C) 2008 - Hagen Paul Pfeifer <hagen@jauu.net>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <inttypes.h>

#include <sys/time.h>
#include <time.h>

#include <pthread.h>

#define	SUCCESS  0
#define	FAILURE -1

#define	RANDPOOLSRC "/dev/urandom"

#define TIME_GT(x,y) (x->tv_sec > y->tv_sec || (x->tv_sec == y->tv_sec && x->tv_usec > y->tv_usec))
#define TIME_LT(x,y) (x->tv_sec < y->tv_sec || (x->tv_sec == y->tv_sec && x->tv_usec < y->tv_usec))

#define	BENCH_ROUNDS 1000

/* crypt routines */
#include <openssl/blowfish.h>
#include <openssl/evp.h>

#define	SLOT_SIZE_BYTE 20 // 20 Byte data blob
#define	SLOT_SIZE_HMAC 12 // 12 Byte HMAC (SHA1)
#define SLOTS_PER_FRAME 3

#define	BUFSIZE 2048
#define	BUFFERSIZE 4096

#define min(x,y) ({ \
        const typeof(x) _x = (x);       \
        const typeof(y) _y = (y);       \
        (void) (&_x == &_y);            \
        _x < _y ? _x : _y; })

enum cipher_list {
	AES_128 = 1,
	AES_192,
	AES_256,
	CAST5,
	BF
};

static const unsigned char key[] =
	{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
static const unsigned char iv[] =
	{1,2,3,4,5,6,7,8};

enum __CIPHER_MODE {
	CIPHER_MODE_CBC = 1,
	CIPHER_MODE_CFB
};

enum {
	KEY_LEN_128 = 1,
	KEY_LEN_192,
	KEY_LEN_256
};

static int cipher_mode = CIPHER_MODE_CBC; /* defaults to cbc */
static int key_len = KEY_LEN_128;
static int data_size = SLOT_SIZE_BYTE;

#define	CIPHER_MODE CBC // CBC or CFB
#define	CIPHER AES_128

EVP_CIPHER_CTX ctx_en;
EVP_CIPHER_CTX ctx_de;


static void
err_die(const char *msg)
{
	fprintf(stderr, "ERROR: %s\n", msg);
	exit(1);
}

static void
sys_die(const char *msg)
{
	fprintf(stderr, "ERROR: %s: %s\n", msg, strerror(errno));
	exit(1);
}

static const EVP_CIPHER *
get_cfb_ciper(void)
{
	switch (key_len) {
		case KEY_LEN_128:
			return EVP_aes_128_cfb();
			break;
		case KEY_LEN_192:
			return EVP_aes_192_cfb();
			break;
		case KEY_LEN_256:
			return EVP_aes_256_cfb();
			break;
		default:
			err_die("Programmed error in switch/case");
			break;
	}

	return NULL;
}

static const EVP_CIPHER *
get_cbc_ciper(void)
{
	switch (key_len) {
		case KEY_LEN_128:
			return EVP_aes_128_cbc();
			break;
		case KEY_LEN_192:
			return EVP_aes_192_cbc();
			break;
		case KEY_LEN_256:
			return EVP_aes_256_cbc();
			break;
		default:
			err_die("Programmed error in switch/case");
			break;
	}

	return NULL;
}

static const EVP_CIPHER *
get_ciper(void)
{
	switch (cipher_mode) {
		case CIPHER_MODE_CBC:
			return get_cbc_ciper();
			break;
		case CIPHER_MODE_CFB:
			return get_cfb_ciper();
			break;
		default:
			err_die("Programmed error in switch/case");
			break;
	}

	return NULL;
}

static void
build_io_data_blob(uint8_t **t_buf, uint32_t size)
{
	uint8_t cnt;
	uint8_t *newbuf;

	newbuf = malloc(BUFFERSIZE);
	if (!newbuf) {
		sys_die("malloc");
	}

	for (cnt = 0; cnt < size; cnt++) {
		long int randval;
		randval = random();
		newbuf[cnt] = (((int)randval) % (122 - 97 + 1)) + 97;
	}
	newbuf[size - 1] = '\0';

	*t_buf = newbuf;
}

int
init_cipher(void)
{
	EVP_CIPHER_CTX_init(&ctx_en);
	EVP_EncryptInit_ex(&ctx_en, get_ciper(), NULL, key, iv);

	EVP_CIPHER_CTX_init(&ctx_de);
	EVP_DecryptInit_ex(&ctx_de, get_ciper(), NULL, key, iv);

	return SUCCESS;
}


static int
encrypt_buf_io(unsigned char *io_buf, int in_size, int *out_len)
{

	int tmplen = 0;
	uint8_t in_data[BUFSIZE];

	memcpy(in_data, io_buf, in_size);

	if (!EVP_EncryptUpdate(&ctx_en, io_buf, out_len, in_data, in_size)) {
		return FAILURE;
	}

	if (!EVP_EncryptFinal_ex(&ctx_en, io_buf + *out_len, &tmplen)) {
		return FAILURE;
	}

	*out_len += tmplen;

	return SUCCESS;
}


static int
decrypt_buf_io(unsigned char *io_buf, int in_size, int *out_len)
{

	int tmplen = 0;
	uint8_t in_data[BUFSIZE];

	memcpy(in_data, io_buf, in_size);

	if (!EVP_DecryptUpdate(&ctx_de, in_data, out_len, io_buf, in_size)) {
		return FAILURE;
	}

	if (!EVP_DecryptFinal_ex(&ctx_de, in_data + *out_len, &tmplen)) {
		return FAILURE;
	}

	*out_len += tmplen;

	return SUCCESS;

}

static int
subtime(struct timeval *op1, struct timeval *op2, struct timeval *result)
{
        int borrow = 0, sign = 0;
        struct timeval *temp_time;

        if (TIME_LT(op1, op2)) {
                temp_time = op1;
                op1  = op2;
                op2  = temp_time;
                sign = 1;
        }
        if (op1->tv_usec >= op2->tv_usec) {
                result->tv_usec = op1->tv_usec-op2->tv_usec;
        }
        else {
                result->tv_usec = (op1->tv_usec + 1000000) - op2->tv_usec;
                borrow = 1;
        }
        result->tv_sec = (op1->tv_sec-op2->tv_sec) - borrow;

        return sign;
}

static void
crypt(void)
{
	int i;
	uint8_t clone_data[data_size + SLOT_SIZE_HMAC];
	uint32_t out_len;
	int ret;
	uint8_t *data_blob;
	struct timeval tv_b, tv_e;
	long retval;
	struct timeval tv_tmp;

	build_io_data_blob(&voip_data, data_size - 1);
	memcpy(clone_data, data_blob, data_size);

	ret = encrypt_buf_io(data_blob, data_size, (int *) &out_len);
	if (ret != SUCCESS)
		err_die("Can't encrypt io buf");


	gettimeofday(&tv_b, NULL);
	for (i = 0; i < BENCH_ROUNDS; i++) {

	ret = decrypt_buf_io(data_blob, out_len, (int *) &out_len);
	}
	gettimeofday(&tv_e, NULL);

	subtime(&tv_e, &tv_b, &tv_tmp);
	double total_real = tv_tmp.tv_sec * 1000000 + ((double) tv_tmp.tv_usec);

	total_real /= BENCH_ROUNDS;
	if (ret != SUCCESS)
		err_die("Can't decrypt io buf");

	if (!memcmp(&data_blob, &clone_data, out_len)) {
		fprintf(stderr, "ERROR: data corrupted\n");
		exit(1);
	} else {
		fprintf(stderr, "ENCRYPTION PASSED\n");

	}
}

static int
initiate_seed(void)
{
	ssize_t ret;
	int rand_fd;
	uint32_t randpool;

	/* set randon pool seed */
	rand_fd = open(RANDPOOLSRC, O_RDONLY);
	if (rand_fd == -1)
		sys_die("Open file");

	ret = read(rand_fd, &randpool, sizeof(uint32_t));
	if (ret != sizeof(uint32_t))
		err_die("Can't pad randpool\n");

	/* set global seed */
	srandom(randpool);

	return SUCCESS;
}


int main(int ac, char **av)
{
	int kl;

	if (ac < 4) {
		fprintf(stderr, "USAGE: me <128|192|256>  <cfb|cbc> <datasize>\n");
		exit(1);
	}

	kl = atoi(av[1]);
	switch (kl) {
		case 128:
			key_len = KEY_LEN_128;
			break;
		case 192:
			key_len = KEY_LEN_192;
			break;
		case 256:
			key_len = KEY_LEN_256;
			break;
		default:
			fprintf(stderr, "USAGE: %s <128|192|256>  <cfb|cbc> <datasize>\n",
					av[0]);
			exit(1);
			break;
	}

	if (!strcmp(av[2], "cfb")) {
		cipher_mode = CIPHER_MODE_CFB;
	} else if ((!strcmp(av[2], "cbc"))) {
		cipher_mode = CIPHER_MODE_CBC;
	} else {
		fprintf(stderr, "USAGE: %s <128|192|256>  <cfb|cbc> <datasize>\n",
				av[0]);
		exit(1);
	}

	data_size = atoi(av[3]);
	if (data_size <= 0 || data_size > BUFFERSIZE) {
		fprintf(stderr, "USAGE: %s <128|192|256>  <cfb|cbc> <datasize>\n",
				av[0]);
		exit(1);
	}


	initiate_seed();
	init_cipher();

	crypt();


	return 0;
}


/* vi: set tw=78 sw=4 ts=4 sts=4 ff=unix noet: */
