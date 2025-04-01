/*
  SPDX-License-Identifier: BSD-3-Clause
  Copyright 2018 Jonathan Ribas, FraudBuster. All rights reserved.
*/

#include <errno.h>
#include <math.h>
#include <rte_interrupts.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <netinet/in.h>
#include <unistd.h>  

#include <rte_ethdev.h>

#include "main.h"

/* ADDITION */
#include <time.h>

#define TIME_TO_WAIT 1
#define LISTEN_PORT 9090
#define BUFFER_SIZE 2048


struct trace_entry {
  const char *flag;
  const char *filepath;
};

struct trace_entry trace_map[] = {{"--cp-dl-long", "/cp_dl_long_10mb.pcap"},
                                  {"--cp-dl-short", "/cp_dl_short_10mb.pcap"},
                                  {"--cp-ul-long", "/cp_ul_long_10mb.pcap"},
                                  {"--cp-ul-short", "/cp_ul_short_10mb.pcap"},
                                  {"--cp-type7", "/type7.pcap"},
                                  {"--cp-1gb-rand", "/c_plane_64_rand.pcap"},
                                  {"--up-dl-short", "/up_dl_short_10mb.pcap"},
                                  {"--up-ul-long", "/up_ul_long_10mb.pcap"},
                                  {"--up-ul-short", "/up_ul_short_10mb.pcap"},
                                  {"--debug", "/temp.pcap"},
                                  {NULL, NULL}};

struct trace_entry trace_map_range[] = {
    {"--cp-dl-long-r", "/cp_dl_long_1mb.pcap"},
    {"--cp-dl-short-r", "/cp_dl_short_1mb.pcap"},
    {"--cp-ul-long-r", "/cp_ul_long_1mb.pcap"},
    {"--cp-ul-short-r", "/cp_ul_short_1mb.pcap"},
    {"--up-dl-short-r", "/up_dl_short_1mb.pcap"},
    {"--up-ul-long-r", "/up_ul_long_1mb.pcap"},
    {"--up-ul-short-r", "/up_ul_short_1mb.pcap"},
    {NULL, NULL}};

void usage(void) {
  puts(
      "It is end user's responsibility to obey the applicable law.\n"
      "This tool is made for educational purposes and based on "
      "https://github.com/FraudBuster/dpdk-burst-replay\n\n"
      "cufh-attacker [TRAFFIC-TYPE] [OPTIONS] PORT1[,PORTX...]\n"
      "PORT1[,PORTX...] : specify the list of ports to be used (pci "
      "addresses).\n"
      "Traffic-type <MBPS>:\n"
      "--cp-dl-big: traffic type C-plane Downlink single repetitive packet "
      "1582 bytes each (10/100/1000 Mbps only)\n"
      "--cp-dl-small: traffic type C-plane Downlink single repetitive packet "
      "64 bytes each (10/100/1000 Mbps only)\n"
      "--cp-1gb-rand: traffic type C-plane Downlink single repetitive packet "
      "64 bytes each (10/100/1000 Mbps only) with preloaded randomized MAC\n"
      "--cp-ul-big: traffic type C-plane Uplink (10/100/1000 Mbps only) single "
      "repetitive packet 1582 bytes each (10/100/1000 Mbps only)\n"
      "--cp-ul-small: traffic type C-plane Uplink (10/100/1000 Mbps only) "
      "single repetitive packet 64 bytes each (10/100/1000 Mbps only)\n"
      "--up-dl: traffic type U-plane Downlink (10/100/1000 Mbps only)\n"
      "--up-ul: traffic type U-plane Uplink (10/100/1000 Mbps only)\n"
      "Traffic-type-r <START-SPEED, STOP-SPEED, INCREMENT>:\n"
      "The traffic type is same as above, with addition of '-r' such as "
      "'--cp-dl-small' it will run from START-SPEED to STOP-SPEED\n"
      "with increasing speed of INCREMENT value. (if 1,10,1 is set then it "
      "will run 1 Mbps, 2 Mbps, 3 Mbps, ..., 10 Mbps) \n"
      "Options:\n"
      "--c : send traffic continuously, not applicable to '-r'\n"
      "--numacore <NUMA-CORE> : use cores from the desired NUMA. Only\n"
      "  NICs on the selected numa core will be available (default is 0).\n"
      "--wait-enter: will wait until you press ENTER to start the replay "
      "(asked\n"
      "  once all the initialization are done).\n"
      "--dst <MAC-ADDRESS>: change to desired destination MAC-ADDRESS.\n"
      "--src <MAC-ADDRESS>: change to desired source MAC-ADDRESS.\n"
      "--vlan <VLAN>: change to desired VLAN.\n"
      "--rand : Randomize source MAC Address\n"
      "PCAP_FILE: if not stated, set the file to send through the DPDK ports "
      "by file name."
      /* TODO: */
      /* "[--maxbitrate bitrate]|[--normalspeed] : bitrate not to be exceeded
         (default: no limit) in ko/s.\n" */
      /* "  specify --normalspeed to replay the trace with the good timings." */
  );
  return;
}

#ifdef DEBUG
void print_opts(const struct cmd_opts *opts) {
  int i;

  if (!opts)
    return;
  puts("--");
  printf("numacore: %i\n", (int)(opts->numacore));
  printf("nb runs: %u\n", opts->nbruns);
  /* if (opts->maxbitrate) */
  /*     printf("MAX BITRATE: %u\n", opts->maxbitrate); */
  /* else */
  /*     puts("MAX BITRATE: FULL SPEED"); */
  printf("trace: %s\n", opts->trace);
  printf("pci nic ports:");
  for (i = 0; opts->pcicards[i]; i++)
    printf(" %s", opts->pcicards[i]);
  puts("\n--");
  return;
}
#endif /* DEBUG */

char **str_to_pcicards_list(struct cmd_opts *opts, char *pcis) {
  char **list = NULL;
  int i;

  if (!pcis || !opts)
    return (NULL);

  for (i = 1;; i++) {
    list = realloc(list, sizeof(*list) * (i + 1));
    if (!list)
      return (NULL);
    list[i - 1] = pcis;
    list[i] = NULL;
    while (*pcis != '\0' && *pcis != ',')
      pcis++;
    if (*pcis == '\0')
      break;
    else { /* , */
      *pcis = '\0';
      pcis++;
    }
  }
  opts->nb_pcicards = i;
  return (list);
}

// helper to get filepath
const char *get_filepath(const char *flag, struct trace_entry *map) {
  for (int i = 0; map[i].flag != NULL; i++) {
    if (strcmp(map[i].flag, flag) == 0) {
      return map[i].filepath;
    }
  }
  return NULL;
}

// vol_num is argv[i+1]
int file_helper(struct cmd_opts *opts, const char *filename,
                const char *vol_num, bool range) {

  if (!opts || !filename || !vol_num)
    return EINVAL;

  strcat(opts->trace, filename); // if no nb runs is specified

  if (!range) {
    if (!strcmp(vol_num, "10")) {
      opts->nbruns = (!strcmp(filename, "/c_plane_64_rand.pcap")) ? 100 : 1;
    } else if (!strcmp(vol_num, "100")) {
      opts->nbruns = 10;
    } else if (!strcmp(vol_num, "1000")) {
      opts->nbruns = (!strcmp(filename, "/c_plane_64_rand.pcap")) ? 1 : 100;
    } else {
      return EPROTO;
    }
  } else if (range) {
    opts->r_active = 1; // if no nb runs is specified

    char vol_copy[128];
    strncpy(vol_copy, vol_num, sizeof(vol_copy));
    vol_copy[sizeof(vol_copy) - 1] = '\0';

    char *token = strtok(vol_copy, ",");
    int j = 0;
    while (token != NULL && j < 3) {
      opts->range[j] = atoi(token);
      token = strtok(NULL, ",");
      j++;
    }
  }
  return 0;
}

int parse_options(const int argc, char **argv, struct cmd_opts *opts) {
  int i;
  unsigned int j;

  if (!argv || !opts)
    return (EINVAL);
  if (argc < 2)
    return (ENOENT); /* if no trace or no pcicard is specified */

  for (i = 1; i < argc - 1; i++) {

    /* --numacore numacore */
    if (!strcmp(argv[i], "--numacore")) {
      int nc;

      /* if no numa core is specified */
      if (i + 1 >= argc - 1)
        return (ENOENT);

      nc = atoi(argv[i + 1]);
      if (nc < 0 || nc > 2)
        return (ENOENT);
      opts->numacore = (char)nc;
      i++;
      continue;
    }

    /* ADDITION: change nbruns to volumetric tiers */

    if (strcmp(argv[i], "--pcap-path") == 0) {
      fprintf(stdout, "Got pcap filepath %s\n", argv[i + 1]);
      char *pcap_filepath = strdup(argv[++i]);
      opts->trace = pcap_filepath;
      i++;
      continue;
    }

    // call the helper function to get filepath
    const char *filepath = get_filepath(argv[i], trace_map);
    if (filepath) {
      if (i + 1 >= argc - 1)
        return (ENOENT);
      int err = file_helper(opts, filepath, argv[i + 1], false);
      if (err)
        return err;
      i++;
      continue;
    }
    if (filepath) {
      if (i + 1 >= argc - 1)
        return (ENOENT);
      int err = file_helper(opts, filepath, argv[i + 1], true);
      if (err)
        return err;
      i++;
      continue;
    }

    if (!strcmp(argv[i], "--c")) {
      opts->cont = 1;
      continue;
    }

    /* Edit fields */
    if (!strcmp(argv[i], "--dst")) {
      if (i + 1 >= argc - 1)
        return (ENOENT);
      opts->dst_mac = argv[i + 1];
      // printf(opts->dst_mac);
      i++;
      continue;
    }

    if (!strcmp(argv[i], "--src")) {
      if (i + 1 >= argc - 1)
        return (ENOENT);
      opts->src_mac = argv[i + 1];
      // printf(opts->src_mac);
      i++;
      continue;
    }

    if (!strcmp(argv[i], "--vlan")) {
      if (i + 1 >= argc - 1)
        return (ENOENT);
      opts->vlan = argv[i + 1];
      // printf(opts->vlan);
      i++;
      continue;
    }

    if (!strcmp(argv[i], "--rand")) {
      opts->random_mac = 1;
      continue;
    }

    if (!strcmp(argv[i], "--seq")) {
      opts->seq_active = 1;
      continue;
    }

    /* --wait-enter */
    if (!strcmp(argv[i], "--wait-enter")) {
      opts->wait = 1;
      continue;
    }

    break;
  }
  if (i + 1 > argc)
    return (EPROTO);

  // -- debug purposes -- to remove later --
  //   printf("\n Parsed Command Line Options:\n");
  //   printf("--------------------------------\n");
  //   printf("Trace path      : %s\n", opts->trace);
  //   printf("Number of runs  : %u\n", opts->nbruns);
  //   printf("Source MAC      : %s\n", opts->src_mac);
  //   printf("Destination MAC : %s\n", opts->dst_mac);
  //   printf("VLAN            : %s\n", opts->vlan);
  //   printf("NUMA Core       : %d\n", opts->numacore);
  //   printf("Continuous mode : %s\n", opts->cont ? "true" : "false");
  //   printf("Random MAC?     : %s\n", opts->random_mac ? "true" : "false");
  //   printf("Sequential?     : %s\n", opts->seq_active ? "true" : "false");
  //   printf("Range mode      : %s\n", opts->r_active ? "true" : "false");

  // if (opts->r_active) {
  //     printf("Range values    : %d to %d step %d\n", opts->range[0],
  //     opts->range[1], opts->range[2]);
  // }

  // printf("PCI devices     : ");
  // for (int j = 0; opts->pcicards && opts->pcicards[j]; j++) {
  //     printf("%s ", opts->pcicards[j]);
  // }
  // printf("\n--------------------------------\n\n");

  opts->pcicards = str_to_pcicards_list(opts, argv[i]);
  return (0);
}

int check_needed_memory(const struct cmd_opts *opts,
                        const struct pcap_ctx *pcap, struct dpdk_ctx *dpdk) {
  float needed_mem;
  char *hsize;

  if (!opts || !pcap || !dpdk)
    return (EINVAL);

  /* # CALCULATE THE NEEDED SIZE FOR MBUF STRUCTS */
  dpdk->mbuf_sz = sizeof(struct rte_mbuf) + pcap->max_pkt_sz;
  dpdk->mbuf_sz += (dpdk->mbuf_sz % (sizeof(int)));
#ifdef DEBUG
  puts("Needed paket allocation size = "
       "(size of MBUF) + (size of biggest pcap packet), "
       "rounded up to the next multiple of an integer.");
  printf("(%lu + %u) + ((%lu + %u) %% %lu) = %lu\n", sizeof(struct rte_mbuf),
         pcap->max_pkt_sz, sizeof(struct rte_mbuf), pcap->max_pkt_sz,
         sizeof(int), dpdk->mbuf_sz);
#endif /* DEBUG */
       // printf("-> Needed MBUF size: %lu\n", dpdk->mbuf_sz);

  /* # CALCULATE THE NEEDED NUMBER OF MBUFS */
#ifdef DPDK_RECOMMANDATIONS
  /* For number of pkts to be allocated on the mempool, DPDK says: */
  /* The optimum size (in terms of memory usage) for a mempool is when n is a
     power of two minus one: n = (2^q - 1).  */
#ifdef DEBUG
  puts("Needed number of MBUFS: next power of two minus one of "
       "(nb pkts * nb ports)");
#endif /* DEBUG */
  dpdk->nb_mbuf = get_next_power_of_2(pcap->nb_pkts * opts->nb_pcicards) - 1;
#else  /* !DPDK_RECOMMANDATIONS */
  /*
    Some tests shown that the perf are not so much impacted when allocating the
    exact number of wanted mbufs. I keep it simple for now to reduce the needed
    memory on large pcap.
  */
  dpdk->nb_mbuf = pcap->nb_pkts * opts->nb_pcicards;
#endif /* DPDK_RECOMMANDATIONS */
  /*
    If we have a pcap with very few packets, we need to allocate more mbufs
    than necessary to avoid rte_mempool_create failure.
  */
  if (dpdk->nb_mbuf < (MBUF_CACHE_SZ * 2))
    dpdk->nb_mbuf = MBUF_CACHE_SZ * 4;
  // printf("-> Needed number of MBUFS: %lu\n", dpdk->nb_mbuf);

  /* # CALCULATE THE TOTAL NEEDED MEMORY SIZE  */
  needed_mem = dpdk->mbuf_sz * dpdk->nb_mbuf;
#ifdef DEBUG
  puts("Needed memory = (needed mbuf size) * (number of needed mbuf).");
  printf("%lu * %lu = %.0f bytes\n", dpdk->mbuf_sz, dpdk->nb_mbuf, needed_mem);
#endif /* DEBUG */
  hsize = nb_oct_to_human_str(needed_mem);
  if (!hsize)
    return (-1);
  // printf("-> Needed Memory = %s\n", hsize);
  free(hsize);

  /* # CALCULATE THE NEEDED NUMBER OF GIGABYTE HUGEPAGES */
  if (fmod(needed_mem, ((double)(1024 * 1024 * 1024))))
    dpdk->pool_sz = needed_mem / (float)(1024 * 1024 * 1024) + 1;
  else
    dpdk->pool_sz = needed_mem / (1024 * 1024 * 1024);
  // printf("-> Needed Hugepages of 1 Go = %lu\n", dpdk->pool_sz);
  return (0);
}
int main(const int argc, char **argv) {

  struct cmd_opts opts;
  struct cpus_bindings cpus;
  struct dpdk_ctx dpdk;
  struct pcap_ctx pcap;
  int ret;
  /* ADDITION */
  unsigned int i, sent;

  /* set default opts */
  bzero(&cpus, sizeof(cpus));
  bzero(&opts, sizeof(opts));
  bzero(&dpdk, sizeof(dpdk));
  bzero(&pcap, sizeof(pcap));
  opts.nbruns = 1;
  /* ADDITION */
  opts.src_mac = "a";
  opts.dst_mac = "a";
  opts.vlan = "a";

  srand(time(NULL));

  struct timespec start, end;
  long long elapsed_ns;
  const long long one_sec_ns = 1000000000LL; // 1 second in nanoseconds

  time_t current_time;
  char *time_string;

  char *pcap_dir =
      getenv("PCAP_DIR"); // Access the environment variable directly
  if (pcap_dir == NULL) {
    fprintf(stderr, "PCAP_DIR not set\n");
    return EXIT_FAILURE;
  }
  size_t len = strlen(pcap_dir);
  if (pcap_dir[len - 1] == '\n') {
    pcap_dir[len - 1] = '\0';
  }

  opts.trace = pcap_dir;
  opts.nbruns = 100;

  ret = parse_options(argc, argv, &opts);
  if (ret) {
    usage();
    return EXIT_FAILURE;
  }
  if (strlen(opts.trace) <= 0) {
    printf("Error: pcap file not specified...\n");
    return EXIT_FAILURE;
  }
#ifdef DEBUG
  print_opts(&opts);
#endif /* DEBUG */

  /*
    pre parse the pcap file to get needed informations:
    . number of packets
    . biggest packet size
  */
  ret = preload_pcap(&opts, &pcap);
  if (ret)
    goto mainExit;

  /* calculate needed memory to allocate for mempool */
  ret = check_needed_memory(&opts, &pcap, &dpdk);
  if (ret)
    goto mainExit;

  /*
    check that we have enough cpus, find the ones to use and calculate
     corresponding coremask
  */
  ret = init_cpus(&opts, &cpus);
  if (ret)
    goto mainExit;

  /* init dpdk eal and mempool */
  ret = init_dpdk_eal_mempool(&opts, &cpus, &dpdk);
  if (ret)
    goto mainExit;

  /* cache pcap file into mempool */
  ret = load_pcap(&opts, &pcap, &cpus, &dpdk);
  if (ret)
    goto mainExit;

  /* init dpdk ports to send pkts */
  ret = init_dpdk_ports(&cpus);
  if (ret)
    goto mainExit;

  if (opts.cont) {
    if (opts.r_active) {
      return (ENOENT);
    }
    /* start tx threads and wait to start to send pkts */

    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    // Create UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        goto mainExit;
    }

    // Allow address reuse
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(sockfd);
        goto mainExit;
    }

    // Bind to port
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(LISTEN_PORT);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        goto mainExit;
    }

    printf("UDP Server listening on port %d...\n", LISTEN_PORT);

    // Receive data
    ssize_t bytes_received = recvfrom(sockfd, buffer, BUFFER_SIZE - 1, 0,
                                      (struct sockaddr *)&client_addr, &client_len);
    if (bytes_received < 0) {
        perror("recvfrom failed");
        close(sockfd);
        goto mainExit;
    }

    buffer[bytes_received] = '\0'; // Null-terminate the received data

    // printf("Received message: \"%s\" from %s:%d\n",
    //        buffer,
    //        inet_ntoa(client_addr.sin_addr),
    //        ntohs(client_addr.sin_port));

    close(sockfd);

    while (1) {
      clock_gettime(CLOCK_REALTIME, &start);

      current_time = time(NULL);
      time_string = ctime(&current_time);
      printf("The current time is: %s", time_string);

      ret = start_tx_threads(&opts, &cpus, &dpdk, &pcap);

      clock_gettime(CLOCK_REALTIME, &end);

      elapsed_ns = (end.tv_sec - start.tv_sec) * one_sec_ns +
                   (end.tv_nsec - start.tv_nsec);
      long long sleep_ns = one_sec_ns - elapsed_ns;

      if (sleep_ns > 0) {
        struct timespec sleep_time = {0, sleep_ns};
        nanosleep(&sleep_time, NULL);
      }
      if (ret)
        goto mainExit;
    }
  } else if (opts.r_active) {
    clock_t last = clock();
    for (i = opts.range[0]; i < (opts.range[1]) + 1; i += opts.range[2]) {
      opts.nbruns = i;
      sent = 0;
      while (1) {

        clock_gettime(CLOCK_REALTIME, &start);

        current_time = time(NULL);
        time_string = ctime(&current_time);
        // printf("------------------------------------- The current time is:
        // %s", time_string);

        ret = start_tx_threads(&opts, &cpus, &dpdk, &pcap);

        clock_gettime(CLOCK_REALTIME, &end);

        elapsed_ns = (end.tv_sec - start.tv_sec) * one_sec_ns +
                     (end.tv_nsec - start.tv_nsec);
        long long sleep_ns = one_sec_ns - elapsed_ns;

        if (sleep_ns > 0) {
          struct timespec sleep_time = {0, sleep_ns};
          nanosleep(&sleep_time, NULL);
        }

        if (!ret) {
          break;
        }
      }
    }
  } else {
    ret = start_tx_threads(&opts, &cpus, &dpdk, &pcap);
    if (ret)
      goto mainExit;
  }

mainExit:
  /* cleanup */
  clean_pcap_ctx(&pcap);
  dpdk_cleanup(&dpdk, &cpus);
  if (cpus.cpus_to_use)
    free(cpus.cpus_to_use);
  return (ret);
}
