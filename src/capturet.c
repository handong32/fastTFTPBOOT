#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>

#include <sys/types.h>
#include <sys/select.h>
#include <sys/ioctl.h>    
#include <sys/socket.h>

#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

#include <net/if.h>
#include <netinet/ether.h>

#include <pcap.h>
#include "dhcp.h"

#define ETHER_TYPE	0x0800
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

unsigned char macaddr[ETHER_ADDR_LEN];

void getmacaddr(char *eth) {
  int s;
  struct ifreq buffer;
  
  s = socket(PF_INET, SOCK_DGRAM, 0);
  memset(&buffer, 0x00, sizeof(buffer));
  strcpy(buffer.ifr_name, eth);
  ioctl(s, SIOCGIFHWADDR, &buffer);
  close(s);

  for(s = 0; s < ETHER_ADDR_LEN; s++ )
  {
    macaddr[s] = (unsigned char)buffer.ifr_hwaddr.sa_data[s];
  }  
}

int
main(int argc, char **argv)
{
  register int op;
  register char *cp, *cmdbuf, *device;
  char ebuf[PCAP_ERRBUF_SIZE];
  struct ifreq if_ip;	/* get ip addr */
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

  getmacaddr(device);
  
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

  printf("Listening on %s, macaddr=%02X %02X %02X %02X %02X %02X\n", device, macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);
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
static void dumpt(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
  struct ifreq if_ip;	/* get ip addr */
	
  int *counterp = (int *)user;
  int len = h->caplen;
  
  /* Header structures */
  struct ether_header *eh = (struct ether_header *) bytes;
  struct iphdr *iph = (struct iphdr *) (bytes+ sizeof(struct ether_header));
  struct udphdr *udph = (struct udphdr *) (bytes + sizeof(struct iphdr) + sizeof(struct ether_header));
  struct dhcp_packet *dhcp = (struct dhcp_packet*)  (bytes + sizeof(struct iphdr) + sizeof(struct ether_header) + sizeof(struct udphdr));
  
  memset(&if_ip, 0, sizeof(struct ifreq));

  if(dhcp->op != BOOTREQUEST) {
    return;
  }

  printf("BOOTREQUEST from %02X %02X %02X %02X %02X %02X\n", dhcp->chaddr[0], dhcp->chaddr[1], dhcp->chaddr[2], dhcp->chaddr[3], dhcp->chaddr[4], dhcp->chaddr[5]); 
  printf("op -> 0x%X \nhtype -> 0x%X\n hlen -> 0x%X\n hops -> 0x%X\n xid -> 0x%X\n flags -> 0x%X\n", dhcp->op, dhcp->htype, dhcp->hlen, dhcp->hops, dhcp->xid, dhcp->flags);
  
  /*printf("Packet number: %d\n", (*counterp));
  for(i = 0; i < len; i++)
  {
    printf("0x%X ", bytes[i]);
  }
  printf("\n");
  */
  
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
