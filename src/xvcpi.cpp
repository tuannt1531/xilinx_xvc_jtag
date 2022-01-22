/*
 * Description :  Xilinx Virtual Cable Server for Raspberry Pi
 *
 * See Licensing information at End of File.
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <errno.h> 

#include <sys/mman.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <pthread.h>

#include "xvcpi.h"

#include <iostream>
#include <string>
#include <assert.h>
#include <sys/time.h>
#include <time.h>

#define MAP_SIZE 1024

#define ERROR_JTAG_INIT_FAILED -1
#define ERROR_OK 1

#define MAX_PORT 65535

static uint32_t xilinxgpio_xfer(int n, uint32_t tms, uint32_t tdi);
static int xilinxgpio_read(void);
static void xilinxgpio_write(int tck, int tms, int tdi);

static int xilinxgpio_init(void);
static int xilinxgpio_quit(void);

/* Transition delay coefficients */
static unsigned int jtag_delay = 0;

static int status = STOPPED;

int tms_tck_uio = 3;
int tdi_tdo_uio = 2;
int fd_uio_1 = 0;
int fd_uio_2 = 0;
volatile unsigned int *gpio_uio_1;
volatile unsigned int *gpio_uio_2;

int tck_gpio = 8;
int tms_gpio = 0;
int tdi_gpio = 0;
int tdo_gpio = 8;

int tck_last_value = -1;
int tms_last_value = -1;
int tdi_last_value = -1;
int tdo_last_value = -1;

static int verbose = 0;

uint64_t byte_recv_num = 0;
uint64_t s_time_checking = 0;

long s_trace_time = 0;
long e_trace_time = 0;
long trace_time = 0;



uint64_t getTimestamp(void)
{
	struct timeval tv;
	uint64_t get_time = 0;
	gettimeofday(&tv, NULL);

	get_time = tv.tv_sec;
	return get_time;
}

uint64_t getTimeUs(void)
{
	struct timeval tv;
	uint32_t get_time = 0;
	gettimeofday(&tv, NULL);

	get_time = tv.tv_usec;
	return get_time;
}

static int xilinxgpio_init(void)
{
	std::string name_uiod_1 = "/dev/uio" + std::to_string(tms_tck_uio);
	printf("open UIO device file: '%s' \n", name_uiod_1.c_str());
	fd_uio_1 = open(name_uiod_1.c_str(), O_RDWR);
	if (fd_uio_1 < 1)
	{
		printf("Invalid UIO device file: '%s' \n", name_uiod_1.c_str());
	}
	assert(tdi_tdo_uio != -1);

	std::string name_uiod_2 = "/dev/uio" + std::to_string(tdi_tdo_uio);
	printf("open UIO device file: '%s' \n", name_uiod_2.c_str());
	fd_uio_2 = open(name_uiod_2.c_str(), O_RDWR);
	if (fd_uio_2 < 1)
	{
		printf("Invalid UIO device file: '%s'n \n", name_uiod_2.c_str());
	}
	gpio_uio_1 = (volatile unsigned *)mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd_uio_1, 0);
	if (!gpio_uio_1)
	{
		printf("mmapn error \n");
	}
	gpio_uio_2 = (volatile unsigned *)mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd_uio_2, 0);
	if (!gpio_uio_2)
	{
		printf("mmapn error \n");
	}
	std::cout << fd_uio_1 << std::endl;
	std::cout << fd_uio_2 << std::endl;
	std::cout << *gpio_uio_1 << std::endl;
	std::cout << *gpio_uio_2 << std::endl;
	std::cout << "JTAG Port Initialized" << std::endl;
	return ERROR_OK;
}

static uint32_t xilinxgpio_xfer(int n, uint32_t tms, uint32_t tdi)
{
	uint32_t tdo = 0;
	for (int i = 0; i < n; i++) {
		xilinxgpio_write(0, tms & 1, tdi & 1);
		xilinxgpio_write(1, tms & 1, tdi & 1);
		tdo |= xilinxgpio_read() << i;
		tms >>= 1;
		tdi >>= 1;
	}
	return tdo;
}

static int xilinxgpio_read(void)
{
	unsigned char *ptr = (unsigned char *)gpio_uio_2;
    if (ptr[tdo_gpio])
    {
        return 1;
    }
    return 0;
}

static void xilinxgpio_write(int tck, int tms, int tdi)
{
	unsigned char *ptr1 = (unsigned char *)gpio_uio_1;
	unsigned char *ptr2 = (unsigned char *)gpio_uio_2;
	if(tdi != tdi_last_value){
		if (tdi)
		{
			ptr2[tdi_gpio] = 1;
		}
		else
		{
			ptr2[tdi_gpio] = 0;
		}
		tdi_last_value = tdi;
	}

	if(tms != tms_last_value){
		if (tms)
		{
			ptr1[tms_gpio] = 1;
		}
		else
		{
			ptr1[tms_gpio] = 0;
		}
		tms_last_value = tms;
	}

	if(tck != tck_last_value){
		if (tck)
		{
			ptr1[tck_gpio] = 1;
		}
		else
		{
			ptr1[tck_gpio] = 0;
		}
		tck_last_value =tck;
	}

	// for (unsigned int i = 0; i < jtag_delay; i++)
	// 	asm volatile("");
}




static int sread(int fd, void *target, int len) {
	unsigned char *t = (unsigned char *)target;
	while (len)
	{
		int r = read(fd, t, len);
		if (r <= 0)
			return r;
		t += r;
		len -= r;
		byte_recv_num += r;
   }
   return 1;
}

int handle_data(int fd) {
	const char xvcInfo[] = "xvcServer_v1.0:16384\n";

	do {
		if(getTimestamp() - s_time_checking >= 10){
			std::cout << "bitrate est = " << std::to_string(byte_recv_num / 10000) << "KB/s" << std::endl;
			std::cout << "processing time est = " << std::to_string(trace_time / 10.0) << "s" << std::endl;
			byte_recv_num = 0;
			s_time_checking = getTimestamp();
			trace_time = 0;
		}
		char cmd[16];
		unsigned char buffer[16384*2], result[16384];
		memset(cmd, 0, 16);

		if (sread(fd, cmd, 2) != 1)
			return 1;

		if (memcmp(cmd, "ge", 2) == 0) {
			if (sread(fd, cmd, 6) != 1)
				return 1;
			memcpy(result, xvcInfo, strlen(xvcInfo));
			if (write(fd, result, strlen(xvcInfo)) != strlen(xvcInfo)) {
				perror("write");
				return 1;
			}
			if (verbose) {
				printf("%u : Received command: 'getinfo'\n", (int)time(NULL));
				printf("\t Replied with %s\n", xvcInfo);
			}
			break;
		} else if (memcmp(cmd, "se", 2) == 0) {
			if (sread(fd, cmd, 9) != 1)
				return 1;
			memcpy(result, cmd + 5, 4);
			if (write(fd, result, 4) != 4) {
				perror("write");
				return 1;
			}
			if (verbose) {
				printf("%u : Received command: 'settck'\n", (int)time(NULL));
				printf("\t Replied with '%.*s'\n\n", 4, cmd + 5);
			}
			break;
		} else if (memcmp(cmd, "sh", 2) == 0) {
			if (sread(fd, cmd, 4) != 1)
				return 1;
			if (verbose) {
				printf("%u : Received command: 'shift'\n", (int)time(NULL));
			}
		} else {

			fprintf(stderr, "invalid cmd '%s'\n", cmd);
			return 1;
		}

		int len;
		if (sread(fd, &len, 4) != 1) {
			fprintf(stderr, "reading length failed\n");
			return 1;
		}

		int nr_bytes = (len + 7) / 8;
		if (nr_bytes * 2 > sizeof(buffer)) {
			fprintf(stderr, "buffer size exceeded\n");
			return 1;
		}

		if (sread(fd, buffer, nr_bytes * 2) != 1) {
			fprintf(stderr, "reading data failed\n");
			return 1;
		}
		memset(result, 0, nr_bytes);

		if (verbose) {
			printf("\tNumber of Bits  : %d\n", len);
			printf("\tNumber of Bytes : %d \n", nr_bytes);
			printf("\n");
		}

		xilinxgpio_write(0, 1, 1);

		int bytesLeft = nr_bytes;
		int bitsLeft = len;
		int byteIndex = 0;
		uint32_t tdi, tms, tdo;

		while (bytesLeft > 0) {
			tms = 0;
			tdi = 0;
			tdo = 0;
			if (bytesLeft >= 4) {
				memcpy(&tms, &buffer[byteIndex], 4);
				memcpy(&tdi, &buffer[byteIndex + nr_bytes], 4);

				tdo = xilinxgpio_xfer(32, tms, tdi);
				memcpy(&result[byteIndex], &tdo, 4);

				bytesLeft -= 4;
				bitsLeft -= 32;
				byteIndex += 4;

				if (verbose) {
					printf("LEN : 0x%08x\n", 32);
					printf("TMS : 0x%08x\n", tms);
					printf("TDI : 0x%08x\n", tdi);
					printf("TDO : 0x%08x\n", tdo);
				}

			} else {
				memcpy(&tms, &buffer[byteIndex], bytesLeft);
				memcpy(&tdi, &buffer[byteIndex + nr_bytes], bytesLeft);

				tdo = xilinxgpio_xfer(bitsLeft, tms, tdi);
				memcpy(&result[byteIndex], &tdo, bytesLeft);

				bytesLeft = 0;

				if (verbose) {
					printf("LEN : 0x%08x\n", bitsLeft);
					printf("TMS : 0x%08x\n", tms);
					printf("TDI : 0x%08x\n", tdi);
					printf("TDO : 0x%08x\n", tdo);
				}
				break;
			}
		}

		xilinxgpio_write(0, 1, 0);

		if (write(fd, result, nr_bytes) != nr_bytes) {
			perror("write");
			return 1;
		}

	} while (1);
	/* Note: Need to fix JTAG state updates, until then no exit is allowed */
	return 0;
}

int start(int port) {
   int i;
   int s;
   struct sockaddr_in address;

   if (xilinxgpio_init() < 1) {
      fprintf(stderr,"Failed in xilinxgpio_init()\n");
      return -1;
   }

   s = socket(AF_INET, SOCK_STREAM, 0);

   if (s < 0) {
      perror("socket");
      return 1;
   }

   i = 1;
   setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &i, sizeof i);

   address.sin_addr.s_addr = INADDR_ANY;
   address.sin_port = htons(port);
   address.sin_family = AF_INET;

   if (bind(s, (struct sockaddr*) &address, sizeof(address)) < 0) {
      perror("bind");
      return 1;
   }

   if (listen(s, 0) < 0) {
      perror("listen");
      return 1;
   }

   printf("Listening on port %d\n", port);

   fd_set conn;
   int maxfd = 0;

   FD_ZERO(&conn);
   FD_SET(s, &conn);

   maxfd = s;

   status = RUNNING;
   while (status == RUNNING) {
      fd_set read = conn, except = conn;
      int fd;

      if (select(maxfd + 1, &read, 0, &except, 0) < 0) {
         perror("select");
         break;
      }

      for (fd = 0; fd <= maxfd; ++fd) {
         if (FD_ISSET(fd, &read)) {
            if (fd == s) {
               int newfd;
               socklen_t nsize = sizeof(address);

               newfd = accept(s, (struct sockaddr*) &address, &nsize);

               if (verbose)
                  printf("connection accepted - fd %d\n", newfd);
               if (newfd < 0) {
                  perror("accept");
               } else {
            	  int flag = 1;
            	  int optResult = setsockopt(newfd,
            			  	  	  	  	  	 IPPROTO_TCP,
            			  	  	  	  	  	 TCP_NODELAY,
            			  	  	  	  	  	 (char *)&flag,
            			  	  	  	  	  	 sizeof(int));
            	  if (optResult < 0)
            		  perror("TCP_NODELAY error");
                  if (newfd > maxfd) {
                     maxfd = newfd;
                  }
                  FD_SET(newfd, &conn);
               }
            }
            else if (handle_data(fd)) {

               if (verbose)
                  printf("connection closed - fd %d\n", fd);
               close(fd);
               FD_CLR(fd, &conn);
            }
         }
         else if (FD_ISSET(fd, &except)) {
            if (verbose)
               printf("connection aborted - fd %d\n", fd);
            close(fd);
            FD_CLR(fd, &conn);
            if (fd == s)
               break;
         }
      }
   }
   status = STOPPED;
   return 0;
}

void stop() {
	status = STOP;
}

int main(int argc, char **argv) {

   int c;
   int port = 2542;

   opterr = 0;
   extern char *optarg;
   char *p;
   int num;
   errno = 0;
   long conv;

   while ((c = getopt(argc, argv, "vp:")) != -1)
      switch (c) {
      case 'v':
         verbose = 1;
         break;
			case 'p':
				conv = strtol(optarg, &p, 10);
				// Check for errors: e.g., the string does not represent an integer
				// or the integer is larger than int
				if (errno != 0 || *p != '\0' || conv > MAX_PORT || conv <= 0) {
					fprintf(stderr, "Invalid port (must be between 1 and 65535): %s\n", optarg);
					return 1;
				} else {
					port = (int)conv;
				}
				break;
      case '?':
         fprintf(stderr, "usage: %s [-v]\n", *argv);
         return 1;
      }

	int err;
	if(err = start(port))
		return err;
	return 0;
}

/*
 * This work, "xvcpi.c", is a derivative of "xvcServer.c" (https://github.com/Xilinx/XilinxVirtualCable)
 * by Avnet and is used by Xilinx for XAPP1251.
 *
 * "xvcServer.c" is licensed under CC0 1.0 Universal (http://creativecommons.org/publicdomain/zero/1.0/)
 * by Avnet and is used by Xilinx for XAPP1251.
 *
 * "xvcServer.c", is a derivative of "xvcd.c" (https://github.com/tmbinc/xvcd)
 * by tmbinc, used under CC0 1.0 Universal (http://creativecommons.org/publicdomain/zero/1.0/).
 *
 * Portions of "xvcpi.c" are derived from OpenOCD (http://openocd.org)
 *
 * "xvcpi.c" is licensed under CC0 1.0 Universal (http://creativecommons.org/publicdomain/zero/1.0/)
 * by Derek Mulcahy.*
 */