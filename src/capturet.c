#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/select.h>
#include <poll.h>

#include <pcap.h>

#define MAXIMUM_SNAPLEN		65535

static char *program_name;

static void usage(void) __attribute__((noreturn));
static void error(const char *, ...);
static void warning(const char *, ...);
static void dumpt(u_char *, const struct pcap_pkthdr *, const u_char *);

static pcap_t *pd;

extern int optind;
extern int opterr;
extern char *optarg;

int
main(int argc, char **argv)
{
  register int op;
  register char *cp, *cmdbuf, *device;
  char ebuf[PCAP_ERRBUF_SIZE];
  int status;
  int packet_count;
  
  device = NULL;
  if ((cp = strrchr(argv[0], '/')) != NULL)
    program_name = cp + 1;
  else
    program_name = argv[0];

  opterr = 0;
  while ((op = getopt(argc, argv, "i:")) != -1) {
    switch (op) {

    case 'i':
      device = optarg;
      break;

      /*case 's':
    case 'b':
    break;*/
      
    default:
      usage();
    }
  }

  if (device == NULL) {
    error("Need device %s", ebuf);
  }
  
  *ebuf = '\0';
  pd = pcap_create(device, ebuf);
  if (pd == NULL)
    error("%s", ebuf);

  // amount of frame buffer to read
  status = pcap_set_snaplen(pd, MAXIMUM_SNAPLEN);
  if (status != 0)
    error("%s: pcap_set_snaplen failed: %s",
	  device, pcap_statustostr(status));

  // if don't set immediate, need to set timeout
  status = pcap_set_immediate_mode(pd, 1);
  if (status != 0)
    error("%s: pcap_set_immediate_mode failed: %s",
	  device, pcap_statustostr(status));

  status = pcap_activate(pd);
  if (status < 0) {
    /*
     * pcap_activate() failed.
     */
    error("%s: %s\n(%s)", device,
	  pcap_statustostr(status), pcap_geterr(pd));
  } else if (status > 0) {
    /*
     * pcap_activate() succeeded, but it's warning us
     * of a problem it had.
     */
    warning("%s: %s\n(%s)", device,
	    pcap_statustostr(status), pcap_geterr(pd));
  }
  printf("pcap_activate success\n");

  //TODO set nonblock

  printf("Listening on %s\n", device);
  packet_count = 0;
  for (;;) {
    status = pcap_dispatch(pd, -1, dumpt,
			   (u_char *)&packet_count);
    if (status < 0)
      break;
    if(packet_count > 100)
      break;
  }
  
  if (status == -2) {
    /*
     * We got interrupted, so perhaps we didn't
     * manage to finish a line we were printing.
     * Print an extra newline, just in case.
     */
    putchar('\n');
  }
  (void)fflush(stdout);
  if (status == -1) {
    /*
     * Error.  Report it.
     */
    (void)fprintf(stderr, "%s: pcap_loop: %s\n",
		  program_name, pcap_geterr(pd));
  }
  pcap_close(pd);
  exit(status == -1 ? 1 : 0);
}

// pcap_handler
static void
dumpt(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
  int i = 0;
  int len = 20;
  int *counterp = (int *)user;
  
  printf("Packet number: %d\n", (*counterp));
  for(i = 0; i < len; i++)
  {
    printf("0x%X ", bytes[i]);
  }
  printf("\n");

  (*counterp)++;
}

static void
usage(void)
{
  (void)fprintf(stderr,
		"Usage: %s [ -i interface ]\n",
		//"Usage: %s [ -i interface ] [ -s snaplen ] [ -b bufsize ]\n",
		program_name);
  exit(1);
}

/* VARARGS */
static void
error(const char *fmt, ...)
{
	va_list ap;

	(void)fprintf(stderr, "%s: ", program_name);
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
	exit(1);
	/* NOTREACHED */
}

/* VARARGS */
static void
warning(const char *fmt, ...)
{
	va_list ap;

	(void)fprintf(stderr, "%s: WARNING: ", program_name);
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
}
