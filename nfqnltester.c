/* N F Q N L _ T E S T   */

/* System headers */

#define _GNU_SOURCE                /* To get memmem */

#include <poll.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter.h>       /* for NF_ACCEPT */
#include <libnetfilter_queue/pktbuff.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>

/* Macros */

#define NUM_TESTS 3
#define T2 0xfaceb00c

/* If bool is a macro, get rid of it */
#ifdef bool
#undef bool
#undef true
#undef false
#endif

/* Typedefs */

/* Enable gdb to show Booleans as "true" or "false" */
typedef enum bool
{
  false,
  true
} bool;

/* Static Variables */

static bool get_out;
static struct nlif_handle *ih;
static int if_fd;
static int id_acked;
static int b;                      /* Batch factor */
static bool tests[NUM_TESTS];

/* Static prototypes */

static void usage(void);

/* ******************************** print_pkt ******************************* */

static void
print_pkt(struct nfq_data *nfad, uint32_t id, struct nfqnl_msg_packet_hdr *ph,
  uint32_t mark)
{
  struct nfqnl_msg_packet_hw *hwph;
  uint32_t ifi, uid, gid, skbinfo;
  int ret;
  uint8_t *data, *secdata;
  struct timeval tv;
  char tbuf[128];

  printf("hw_protocol=0x%04x hook=%u id=%u ",
    ntohs(ph->hw_protocol), ph->hook, id);

  hwph = nfq_get_packet_hw(nfad);
  if (hwph)
  {
    int i, hlen = ntohs(hwph->hw_addrlen);

    printf("hw_src_addr=");
    for (i = 0; i < hlen - 1; i++)
      printf("%02x:", hwph->hw_addr[i]);
    printf("%02x ", hwph->hw_addr[hlen - 1]);
  }                                /* if (hwph) */

  if (mark)
    printf("mark=0x%x ", mark);

  skbinfo = nfq_get_skbinfo(nfad);
  if (skbinfo & NFQA_SKB_GSO)
    fputs("GSO ", stdout);
  if (skbinfo & NFQA_SKB_CSUMNOTREADY)
    fputs("checksum not ready ", stdout);
  if (skbinfo & NFQA_SKB_CSUM_NOTVERIFIED)
    fputs("checksum not verified ", stdout);

  ifi = nfq_get_indev(nfad);
  if (ifi)
  {
    printf("indev=%u", ifi);

/* Try to get indev name */
    ret = nfq_get_indev_name(ih, nfad, tbuf);
    if (ret == -1)
      putchar(' ');
    else
      printf("(%s) ", tbuf);
  }                                /* if (ifi) */

  ifi = nfq_get_outdev(nfad);
  if (ifi)
  {
    printf("outdev=%u", ifi);
    ret = nfq_get_outdev_name(ih, nfad, tbuf);
    if (ret == -1)
      putchar(' ');
    else
      printf("(%s) ", tbuf);
  }                                /* if (ifi) */
  ifi = nfq_get_physindev(nfad);
  if (ifi)
    printf("physindev=%u ", ifi);

  ifi = nfq_get_physoutdev(nfad);
  if (ifi)
    printf("physoutdev=%u ", ifi);

  if (nfq_get_uid(nfad, &uid))
    printf("uid=%u ", uid);

  if (nfq_get_gid(nfad, &gid))
    printf("gid=%u ", gid);

  ret = nfq_get_secctx(nfad, &secdata);
  if (ret > 0)
    printf("secctx=\"%.*s\" ", ret, secdata);

  ret = nfq_get_payload(nfad, &data);
  if (ret >= 0)
    printf("payload_len=%d ", ret);

  if (!nfq_get_timestamp(nfad, &tv) &&
    strftime(tbuf, sizeof tbuf, "%T", localtime(&tv.tv_sec)))
    printf("stamp=%s.%06ld ", tbuf, tv.tv_usec);

  fputc('\n', stdout);

}                                  /* print_pkt() */

/* *********************************** cb *********************************** */

#ifdef GIVE_UP
#undef GIVE_UP
#endif
#define GIVE_UP(x)\
do {fputs(x, stderr); goto send_verdict; } while (0)

static int
cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
  struct nfq_data *nfad, void *data)
{
  uint32_t id;
  struct nfqnl_msg_packet_hdr *ph;
  uint16_t plen;
  uint8_t *payload;
  uint8_t *udp_payload;
  uint32_t udp_payload_len;
  struct udphdr *udph;
  struct iphdr *ip4h;
  char pb[pktb_head_size()];
  struct pkt_buff *pktb;
  uint32_t verdict = NF_ACCEPT;
  uint8_t *buf = NULL;
  uint32_t data_len = 0;
  uint32_t mark;
  uint32_t newmark = 0;
  uint8_t *p;
  int ret;

  printf("entering callback\n");
  ph = nfq_get_msg_packet_hdr(nfad);
  id = ntohl(ph->packet_id);
  mark = nfq_get_nfmark(nfad);
  print_pkt(nfad, id, ph, mark);

  plen = nfq_get_payload(nfad, &payload);

/* Set up a packet buffer. Use extra room in the receive buffer. */
  pktb = pktb_setup_raw(pb, AF_INET, payload, plen, *(size_t *)data);
  if (!pktb)
  {
    perror("pktb_setup_raw");
    return MNL_CB_ERROR;
  }                                /* if (!pktb) */
  if (!(ip4h = nfq_ip_get_hdr(pktb)))
    GIVE_UP("Malformed IP\n");
  if (nfq_ip_set_transport_header(pktb, ip4h))
    GIVE_UP("No payload found\n");
  if (!(udph = nfq_udp_get_hdr(pktb)))
    GIVE_UP("Packet too short to get UDP header\n");
  if (!(udp_payload = nfq_udp_get_payload(udph, pktb)))
    GIVE_UP("Packet too short to get UDP payload\n");
  udp_payload_len = nfq_udp_get_payload_len(udph, pktb);

  if (tests[0] && udp_payload_len >= 2 && udp_payload[0] == 'q' &&
    isspace(udp_payload[1]))
  {
    verdict = NF_DROP;
    get_out = true;
  }                                /* if (tests[0] && ... */

  if (tests[1] && (p = memmem(udp_payload, udp_payload_len, "ZXC", 3)))
    nfq_udp_mangle_ipv4(pktb, p - udp_payload, 3, "VBN", 3);

  if (tests[2] && mark != T2)
  {
    verdict = NF_REPEAT;
    newmark = T2;
  }                                /* if (tests[2] && mark != T2) */

  if (pktb_mangled(pktb))
  {
    data_len = pktb_len(pktb);
    buf = pktb_data(pktb);
  }                                /* if (pktb_mangled(pktb)) */

send_verdict:

/* If batching and this packet is mangled, ack previous un_acked packets */
  if (b && data_len && id - id_acked > 1)
  {
    ret = nfq_set_verdict_batch(qh, id - 1, verdict);
    if (ret == -1)
      return ret;
  }                                /* if (b && data_len && id - id_acked > 1) */
  if (!b || data_len)
  {
    if (newmark)
      return nfq_set_verdict2(qh, id_acked =
        id, verdict, newmark, data_len, buf);
    else
      return nfq_set_verdict(qh, id_acked = id, verdict, data_len, buf);
  }                                /* if (!b || data_len) */
  if (!(id % b))
  {
    if (newmark)
      return nfq_set_verdict_batch2(qh, id_acked = id, verdict, newmark);
    else
      return nfq_set_verdict_batch(qh, id_acked = id, verdict);
  }                                /* if (!(id % b)) */
  return MNL_CB_OK;
}                                  /* cb() */

/* ********************************** main ********************************** */

int
main(int argc, char **argv)
{
  struct nfq_handle *h;
  struct nfq_q_handle *qh;
  int fd;
  int rv;
  uint32_t queue_num = 0;
  uint32_t ret;
  char buf[4096 + 0xffff] __attribute__((aligned));
  int i;
  size_t sperrume;                 /* Spare room */
  struct pollfd fds[2];

  while ((i = getopt(argc, argv, "b:ht:")) != -1)
  {
    switch (i)
    {
      case 'b':
        b = atoi(optarg);
        if (b <= 0)
        {
          fprintf(stderr, "Batch factor %d is out of range\n", b);
          exit(EXIT_FAILURE);
        }                          /* if (b <= 0) */
        break;

      case 'h':
        usage();
        return 0;

      case 't':
        ret = atoi(optarg);
        if (ret < 0 || ret >= NUM_TESTS)
        {
          fprintf(stderr, "Test %d is out of range\n", ret);
          exit(EXIT_FAILURE);
        }                          /* if (ret < 0 || ret >= NUM_TESTS) */
        tests[ret] = true;
        break;

      case '?':
        exit(EXIT_FAILURE);
    }                              /* switch (i) */
  }                        /* while ((i = getopt(argc, argv, "a:ht:")) != -1) */

  if (argc == optind)
  {
    fputs("Missing queue number\n", stderr);
    exit(EXIT_FAILURE);
  }                                /* if (argc == optind) */
  queue_num = atoi(argv[optind]);
  if (queue_num > 65535)
  {
    fprintf(stderr, "Usage: %s [<0-65535>]\n", argv[0]);
    exit(EXIT_FAILURE);
  }                                /* if (queue_num > 65535) */

  if (tests[2] && b)
  {
    fputs("Test 2 is incompatible with verdict batching\n", stderr);
    exit(EXIT_FAILURE);
  }                                /* if (tests[2] && b) */

  printf("opening library handle\n");
  h = nfq_open();
  if (!h)
  {
    fprintf(stderr, "error during nfq_open()\n");
    exit(1);
  }                                /* if (!h) */

  printf("opening nlif handle\n");
  ih = nlif_open();
  if (!ih)
    perror("nlif_open");
  if_fd = nlif_fd(ih);
  if (if_fd == -1)
    perror("nlif_fd");
  nlif_query(ih);

  printf("setting socket buffer size to 2MB\n");
  ret = nfnl_rcvbufsiz(nfq_nfnlh(h), 1024 * 1024);
  printf("Read buffer set to 0x%x bytes (%gMB)\n", ret, ret / 1024.0 / 1024);

  printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
  if (nfq_unbind_pf(h, AF_INET) < 0)
  {
    fprintf(stderr, "error during nfq_unbind_pf()\n");
    exit(1);
  }                                /* if (nfq_unbind_pf(h, AF_INET) < 0) */

  printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
  if (nfq_bind_pf(h, AF_INET) < 0)
  {
    fprintf(stderr, "error during nfq_bind_pf()\n");
    exit(1);
  }                                /* if (nfq_bind_pf(h, AF_INET) < 0) */

  printf("binding this socket to queue '%d'\n", queue_num);
  qh = nfq_create_queue(h, queue_num, &cb, &sperrume);
  if (!qh)
  {
    fprintf(stderr, "error during nfq_create_queue()\n");
    exit(1);
  }                                /* if (!qh) */

  printf("setting copy_packet mode\n");
  if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
  {
    fprintf(stderr, "can't set packet_copy mode\n");
    exit(1);
  }                   /* if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) */

  printf("setting flags to request UID and GID\n");
  if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID))
  {
    fprintf(stderr, "This kernel version does not allow to "
      "retrieve process UID/GID.\n");
  }   /* if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) */

  printf("setting flags to request security context\n");
  if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX))
  {
    fprintf(stderr, "This kernel version does not allow to "
      "retrieve security context.\n");
  }     /* if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) */

  printf("setting flags to request GSO\n");
  if (nfq_set_queue_flags(qh, NFQA_CFG_F_GSO, NFQA_CFG_F_GSO))
  {
    fprintf(stderr, "can't set GSO\n");
    exit(1);
  }           /* if (nfq_set_queue_flags(qh, NFQA_CFG_F_GSO, NFQA_CFG_F_GSO)) */

  printf("Waiting for packets...\n");

  fd = nfq_fd(h);

/* Set up for poll() */
  fds[0].fd = if_fd;
  fds[0].events = POLLIN;
  fds[1].fd = fd;
  fds[1].events = POLLIN;

  for (;;)
  {
    do
      rv = poll((struct pollfd *)&fds, 2, -1);
    while (rv == -1 && errno == EINTR);
    if (rv == -1)
    {
      perror("poll");
      exit(EXIT_FAILURE);
    }                              /* if (rv == -1) */

    if (fds[0].revents & POLLIN)
    {
      printf("RT pkt received\n");
      rv = nlif_catch(ih);
      if (rv < 0)
        perror("nlif_catch");
    }                              /* if (fds[0].revents & POLLIN) */

    if (fds[1].revents & POLLIN)
    {
      if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
      {
        printf("pkt received\n");
        sperrume = sizeof buf - rv;
        rv = nfq_handle_packet(h, buf, rv);
        if (rv == -1)
        {
          perror("nfq_handle_packet");
          break;
        }                          /* if (rv == -1) */
        if (get_out)
          break;
      }                     /* if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) */
      if (rv < 0)
      {
        if (errno == ENOBUFS)
        {
          printf("losing packets!\n");
          continue;
        }                          /* if (errno == ENOBUFS) */
        perror("recv");
        break;
      }                            /* if (rv < 0) */
    }                              /* if (fds[1].revents & POLLIN) */
  }                                /* for (;;) */

  printf("unbinding from queue %d\n", queue_num);
  nfq_destroy_queue(qh);

  printf("closing library handles\n");
  nfq_close(h);
  nlif_close(ih);

  exit(0);
}                                  /* main() */

/* ********************************** usage ********************************* */

static void
usage(void)
{
/* N.B. Trailing empty comments are there to stop gnu indent joining lines */
  puts("\nUsage: nfqnl_test [-b <batch factor>] [-t <test #>],... " /*  */
    "queue_number\n"               /*  */
    "       nfqnl_test -h\n"       /*  */
    "  -b <n>: send a batch verdict only when packet id is a " /*  */
    "multiple of <n>.\n"           /*  */
    "          If a packet is mangled, then ack any previous " /*  */
    "un-acked packets\n"           /*  */
    "          and send the mangled one.\n" /*  */
    "  -h: give this Help and exit\n" /*  */
    "  -t <n>: do Test <n>. Tests are:\n" /*  */
    "    0: Exit nfqnl_test if incoming packet starts \"q[[:space:]]\"\n" /*  */
    "    1: Replace 1st ZXC by VBN\n" /*  */
    "    2: If packet mark is not 0xfaceb00c, set it to 0xfaceb00c\n" /*  */
    "       and give verdict NF_REPEAT\n" /*  */
    "       If packet mark *is* 0xfaceb00c, accept the packet\n" /*  */
    );
}                                  /* usage() */
