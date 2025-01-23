/*
  SPDX-License-Identifier: BSD-3-Clause
  Copyright 2018 Jonathan Ribas, FraudBuster. All rights reserved.
*/

#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <math.h>

#include <rte_ethdev.h>

#include "main.h"

/* ADDITION */
#include <time.h>

#define TIME_TO_WAIT 1


void usage(void)
{
    puts(
         "It is end user's responsibility to obey the applicable law.\n"
         "This tool is made for educational purposes and based on https://github.com/FraudBuster/dpdk-burst-replay\n\n"
         "cufh-attacker [TRAFFIC-TYPE] [OPTIONS] PORT1[,PORTX...]\n"
         "PORT1[,PORTX...] : specify the list of ports to be used (pci addresses).\n"
         "Traffic-type <MBPS>:\n"
         "--cp-dl-big: traffic type C-plane Downlink single repetitive packet 1582 bytes each (10/100/1000 Mbps only)\n"
         "--cp-dl-small: traffic type C-plane Downlink single repetitive packet 64 bytes each (10/100/1000 Mbps only)\n"
         "--cp-1gb-rand: traffic type C-plane Downlink single repetitive packet 64 bytes each (10/100/1000 Mbps only) with preloaded randomized MAC\n"
        "--cp-ul-big: traffic type C-plane Uplink (10/100/1000 Mbps only) single repetitive packet 1582 bytes each (10/100/1000 Mbps only)\n"
        "--cp-ul-small: traffic type C-plane Uplink (10/100/1000 Mbps only) single repetitive packet 64 bytes each (10/100/1000 Mbps only)\n"
         "--up-dl: traffic type U-plane Downlink (10/100/1000 Mbps only)\n"
         "--up-ul: traffic type U-plane Uplink (10/100/1000 Mbps only)\n"      
         "Traffic-type-r <START-SPEED, STOP-SPEED, INCREMENT>:\n"
         "The traffic type is same as above, with addition of '-r' such as '--cp-dl-small' it will run from START-SPEED to STOP-SPEED\n" 
         "with increasing speed of INCREMENT value. (if 1,10,1 is set then it will run 1 Mbps, 2 Mbps, 3 Mbps, ..., 10 Mbps) \n"  
        "Options:\n"
         "--c : send traffic continuously, not applicable to '-r'\n"
         "--numacore <NUMA-CORE> : use cores from the desired NUMA. Only\n"
         "  NICs on the selected numa core will be available (default is 0).\n"
         "--wait-enter: will wait until you press ENTER to start the replay (asked\n"
         "  once all the initialization are done).\n"
         "--dst <MAC-ADDRESS>: change to desired destination MAC-ADDRESS.\n"
         "--src <MAC-ADDRESS>: change to desired source MAC-ADDRESS.\n"
         "--vlan <VLAN>: change to desired VLAN.\n"
         "--rand : Randomize source MAC Address\n"
         "PCAP_FILE: if not stated, set the file to send through the DPDK ports by file name."
         /* TODO: */
         /* "[--maxbitrate bitrate]|[--normalspeed] : bitrate not to be exceeded (default: no limit) in ko/s.\n" */
         /* "  specify --normalspeed to replay the trace with the good timings." */
        );
    return ;
}

#ifdef DEBUG
void print_opts(const struct cmd_opts* opts)
{
    int i;

    if (!opts)
        return ;
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
    return ;
}
#endif /* DEBUG */

char** str_to_pcicards_list(struct cmd_opts* opts, char* pcis)
{
    char** list = NULL;
    int i;

    if (!pcis || !opts)
        return (NULL);

    for (i = 1; ; i++) {
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

int parse_options(const int ac, char** av, struct cmd_opts* opts)
{
    int i;
    unsigned int j;
    
    // char* dir = getenv("PCAP_DIR");
    // if (dir == NULL) {
    //     printf("PCAP_DIR is not set\n");
    //     return 1;
    // }
    // printf(dir);
    // strcpy(opts->trace, dir);
    
    

    if (!av || !opts)
        return (EINVAL);

    /* if no trace or no pcicard is specified */
    if (ac < 2)
        // printf("this error");
        return (ENOENT);

    for (i = 1; i < ac - 1; i++) {
        
        /* --numacore numacore */
        if (!strcmp(av[i], "--numacore")) {
            int nc;

            /* if no numa core is specified */
            if (i + 1 >= ac - 1)
                return (ENOENT);

            nc = atoi(av[i + 1]);
            if (nc < 0 || nc > 2)
                return (ENOENT);
            opts->numacore = (char)nc;
            i++;
            continue;
        }

        /* ADDITION: change nbruns to volumetric tiers */

        if (!strcmp(av[i], "--cp-dl-long")) {
            strcat(opts->trace, "/cp_dl_long_10mb.pcap");
            // strcpy(opts->trace, "cp_dl_10mb_big.pcap");
            // opts->trace = "cp_dl_10mb_big.pcap";
            /* if no nb runs is specified */
            if (i + 1 >= ac - 1)
                return (ENOENT);
            /* for each choosen volume */
            if (!strcmp((av[i + 1]), "10")){
                opts->nbruns = 1;
            }
            else if (!strcmp((av[i + 1]), "100")){
                opts->nbruns = 10;
            }
            else if (!strcmp((av[i + 1]), "1000")){
                /* It will have packet drop */
                opts->nbruns = 100;
            }
            // Packet drop value = 105
            /* else the value is wrong */
            else{
                return (EPROTO);
            }
            i++;
            continue;
        }
        else if (!strcmp(av[i], "--cp-dl-short")) {
            strcat(opts->trace, "/cp_dl_short_10mb.pcap");
            // opts->trace = "cp_ul_10mb_small.pcap";
            /* if no nb runs is specified */
            if (i + 1 >= ac - 1)
                return (ENOENT);
            /* for each choosen volume */
            if (!strcmp((av[i + 1]), "10")){
                opts->nbruns = 1;
            }
            else if (!strcmp((av[i + 1]), "100")){
                opts->nbruns = 10;
            }
            else if (!strcmp((av[i + 1]), "1000")){
                opts->nbruns = 100;
            }
            /* else the value is wrong */
            else{
                return (EPROTO);
            }
            i++;
            continue;
        }
        else if (!strcmp(av[i], "--cp-type7")) {
            strcat(opts->trace, "/type7.pcap");
            // opts->trace = "cp_ul_10mb_small.pcap";
            /* if no nb runs is specified */
            if (i + 1 >= ac - 1)
                return (ENOENT);
            /* for each choosen volume */
            if (!strcmp((av[i + 1]), "10")){
                opts->nbruns = 1;
            }
            else if (!strcmp((av[i + 1]), "100")){
                opts->nbruns = 10;
            }
            else if (!strcmp((av[i + 1]), "1000")){
                opts->nbruns = 100;
            }
            /* else the value is wrong */
            else{
                return (EPROTO);
            }
            i++;
            continue;
        }
        else if (!strcmp(av[i], "--cp-1gb-rand")) {
            strcat(opts->trace, "/c_plane_64_rand.pcap");
            // opts->trace = "cp_ul_10mb_small.pcap";
            /* if no nb runs is specified */
            if (i + 1 >= ac - 1)
                return (ENOENT);
            /* for each choosen volume */
            if (!strcmp((av[i + 1]), "1000")){
                opts->nbruns = 1;
            }
            else if (!strcmp((av[i + 1]), "100")){
                opts->nbruns = 10;
            }
            else if (!strcmp((av[i + 1]), "10")){
                opts->nbruns = 100;
            }
            /* else the value is wrong */
            else{
                return (EPROTO);
            }
            i++;
            continue;
        }
        else if (!strcmp(av[i], "--cp-ul-long")) {
            strcat(opts->trace, "/cp_ul_long_10mb.pcap");
            // opts->trace = "cp_ul_10mb_big.pcap";
            /* if no nb runs is specified */
            if (i + 1 >= ac - 1)
                return (ENOENT);
            /* for each choosen volume */
            if (!strcmp((av[i + 1]), "10")){
                opts->nbruns = 1;
            }
            else if (!strcmp((av[i + 1]), "100")){
                opts->nbruns = 10;
            }
            else if (!strcmp((av[i + 1]), "1000")){
                opts->nbruns = 100;
            }
            /* else the value is wrong */
            else{
                return (EPROTO);
            }
            i++;
            continue;
        }
         else if (!strcmp(av[i], "--cp-ul-short")) {
            strcat(opts->trace, "/cp_ul_short_10mb.pcap");
            // opts->trace = "cp_ul_10mb_small.pcap";
            /* if no nb runs is specified */
            if (i + 1 >= ac - 1)
                return (ENOENT);
            /* for each choosen volume */
            if (!strcmp((av[i + 1]), "10")){
                opts->nbruns = 1;
            }
            else if (!strcmp((av[i + 1]), "100")){
                opts->nbruns = 10;
            }
            else if (!strcmp((av[i + 1]), "1000")){
                opts->nbruns = 100;
            }
            /* else the value is wrong */
            else{
                return (EPROTO);
            }
            i++;
            continue;
        }
        else if (!strcmp(av[i], "--up-dl-short")) {
            strcat(opts->trace, "/up_dl_short_10mb.pcap");
            // opts->trace = "up_dl_10mb.pcap";
            /* if no nb runs is specified */
            if (i + 1 >= ac - 1)
                return (ENOENT);
            /* for each choosen volume */
            if (!strcmp((av[i + 1]), "10")){
                opts->nbruns = 1;
            }
            else if (!strcmp((av[i + 1]), "100")){
                opts->nbruns = 10;
            }
            else if (!strcmp((av[i + 1]), "1000")){
                /* It will have packet drop */
                opts->nbruns = 100;
            }
            // Packet drop value = 110
            /* else the value is wrong */
            else{
                return (EPROTO);
            }
            i++;
            continue;
        } 
        else if (!strcmp(av[i], "--up-ul-long")) {
            strcat(opts->trace, "/up_ul_long_10mb.pcap");
            // opts->trace = "up_ul_10mb.pcap";
            /* if no nb runs is specified */
            if (i + 1 >= ac - 1)
                return (ENOENT);
            /* for each choosen volume */
            if (!strcmp((av[i + 1]), "10")){
                opts->nbruns = 1;
            }
            else if (!strcmp((av[i + 1]), "100")){
                opts->nbruns = 10;
            }
            else if (!strcmp((av[i + 1]), "1000")){
                opts->nbruns = 100;
            }
            // Packet drop value = 120
            /* else the value is wrong */
            else{
                return (EPROTO);
            }
            i++;
            continue;
        } 
        else if (!strcmp(av[i], "--up-ul-short")) {
            strcat(opts->trace, "/up_ul_short_10mb.pcap");
            // opts->trace = "up_ul_10mb.pcap";
            /* if no nb runs is specified */
            if (i + 1 >= ac - 1)
                return (ENOENT);
            /* for each choosen volume */
            if (!strcmp((av[i + 1]), "10")){
                opts->nbruns = 1;
            }
            else if (!strcmp((av[i + 1]), "100")){
                opts->nbruns = 10;
            }
            else if (!strcmp((av[i + 1]), "1000")){
                opts->nbruns = 100;
            }
            // Packet drop value = 120
            /* else the value is wrong */
            else{
                return (EPROTO);
            }
            i++;
            continue;
        } 
        else if (!strcmp(av[i], "--debug")) {
            strcat(opts->trace, "/temp.pcap");
            // opts->trace = "up_ul_10mb.pcap";
            /* if no nb runs is specified */
            if (i + 1 >= ac - 1)
                return (ENOENT);
            /* for each choosen volume */
            if (!strcmp((av[i + 1]), "10")){
                opts->nbruns = 1;
            }
            else if (!strcmp((av[i + 1]), "100")){
                opts->nbruns = 10;
            }
            else if (!strcmp((av[i + 1]), "1000")){
                opts->nbruns = 100;
            }
            // Packet drop value = 120
            /* else the value is wrong */
            else{
                return (EPROTO);
            }
            i++;
            continue;
        } 


        /* ADDITION: range-based */
        else if (!strcmp(av[i], "--cp-dl-long-r")) {
            strcat(opts->trace, "/cp_dl_long_1mb.pcap");
            // opts->trace = "cp_dl_1mb_big.pcap";
            opts->r_active = 1;
            /* if no nb runs is specified */
            if (i + 1 >= ac - 1)
                return (ENOENT);
            char* token = strtok((av[i + 1]), ",");
            int j = 0;
            while (token != NULL && j < 3) {
                opts->range[j] = atoi(token);
                token = strtok(NULL, ",");
                j++;
            }
            i++;
            continue;
        } 
        else if (!strcmp(av[i], "--cp-dl-short-r")) {
            strcat(opts->trace, "/cp_dl_short_1mb.pcap");
            // opts->trace = "cp_ul_1mb_small.pcap";
            opts->r_active = 1;
            /* if no nb runs is specified */
            if (i + 1 >= ac - 1)
                return (ENOENT);
            char* token = strtok((av[i + 1]), ",");
            int j = 0;
            while (token != NULL && j < 3) {
                opts->range[j] = atoi(token);
                token = strtok(NULL, ",");
                j++;
            }
            i++;
            continue;
        }
        else if (!strcmp(av[i], "--cp-ul-long-r")) {
            strcat(opts->trace, "/cp_ul_long_1mb.pcap");
            // opts->trace = "cp_ul_1mb_big.pcap";
            opts->r_active = 1;
            /* if no nb runs is specified */
            if (i + 1 >= ac - 1)
                return (ENOENT);
            char* token = strtok((av[i + 1]), ",");
            int j = 0;
            while (token != NULL && j < 3) {
                opts->range[j] = atoi(token);
                token = strtok(NULL, ",");
                j++;
            }
            i++;
            continue;
        }
         else if (!strcmp(av[i], "--cp-ul-short-r")) {
            strcat(opts->trace, "/cp_ul_short_1mb.pcap");
            // opts->trace = "cp_ul_1mb_small.pcap";
            opts->r_active = 1;
            /* if no nb runs is specified */
            if (i + 1 >= ac - 1)
                return (ENOENT);
            char* token = strtok((av[i + 1]), ",");
            int j = 0;
            while (token != NULL && j < 3) {
                opts->range[j] = atoi(token);
                token = strtok(NULL, ",");
                j++;
            }
            i++;
            continue;
        }
        else if (!strcmp(av[i], "--up-dl-short-r")) {
            strcat(opts->trace, "/up_dl_short_1mb.pcap");
            // opts->trace = "up_dl_1mb.pcap";
            opts->r_active = 1;
            /* if no nb runs is specified */
            if (i + 1 >= ac - 1)
                return (ENOENT);
            char* token = strtok((av[i + 1]), ",");
            int j = 0;
            while (token != NULL && j < 3) {
                opts->range[j] = atoi(token);
                token = strtok(NULL, ",");
                j++;
            }
            i++;
            continue;
        } 
        else if (!strcmp(av[i], "--up-ul-long-r")) {
            strcat(opts->trace, "/up_ul_long_1mb.pcap");
            // opts->trace = "up_ul_1mb.pcap";
            opts->r_active = 1;
            /* if no nb runs is specified */
            if (i + 1 >= ac - 1)
                return (ENOENT);
            char* token = strtok((av[i + 1]), ",");
            int j = 0;
            while (token != NULL && j < 3) {
                opts->range[j] = atoi(token);
                token = strtok(NULL, ",");
                j++;
            }
            i++;
            continue;
        } 
        else if (!strcmp(av[i], "--up-ul-short-r")) {
            strcat(opts->trace, "/up_ul_short_1mb.pcap");
            // opts->trace = "up_ul_1mb.pcap";
            opts->r_active = 1;
            /* if no nb runs is specified */
            if (i + 1 >= ac - 1)
                return (ENOENT);
            char* token = strtok((av[i + 1]), ",");
            int j = 0;
            while (token != NULL && j < 3) {
                opts->range[j] = atoi(token);
                token = strtok(NULL, ",");
                j++;
            }
            i++;
            continue;
        } 

        if (!strcmp(av[i], "--c")) {
            opts->cont = 1;
            continue;
        }        

        /* Edit fields */
        if (!strcmp(av[i], "--dst")) {
            if (i + 1 >= ac - 1)
                return (ENOENT);
            opts->dst_mac = av[i + 1];
            // printf(opts->dst_mac);
            i++;
            continue;
        }
        
        if (!strcmp(av[i], "--src")) {
            if (i + 1 >= ac - 1)
                return (ENOENT);
            opts->src_mac = av[i + 1];
            // printf(opts->src_mac);
            i++;
            continue;
        }
        
        if (!strcmp(av[i], "--vlan")) {
            if (i + 1 >= ac - 1)
                return (ENOENT);
            opts->vlan = av[i + 1];
            // printf(opts->vlan);
            i++;
            continue;
        }

        if (!strcmp(av[i], "--rand")) {
            opts->random_mac = 1;
            continue;
        }   

        if (!strcmp(av[i], "--seq")) {
            opts->seq_active = 1;
            continue;
        }   
        
        /* --wait-enter */
        if (!strcmp(av[i], "--wait-enter")) {
            opts->wait = 1;
            continue;
        }

        break;
    }
    if (i + 1 > ac)
        return (EPROTO);
    
    /* ADDITION: change file name parsing into data type to PCAP parsing */

    // if (!strcmp(av[i], "--cp-dl")) {
    //     opts->trace = "0919_attack3.pcap";
    // }
    // else if (!strcmp(av[i], "--cp-ul")) {
    //     opts->trace = "du_cp_ul.pcap";
    // }
    // else if (!strcmp(av[i], "--up-dl")) {
    //     opts->trace = "du_cp_ul.pcap";
    // }
    // /* or user can input their own PCAP */
    // else{
    //     opts->trace = av[i];
    // }

    // opts->trace = av[i];


    opts->pcicards = str_to_pcicards_list(opts, av[i]);
    return (0);
}

int check_needed_memory(const struct cmd_opts* opts, const struct pcap_ctx* pcap,
                        struct dpdk_ctx* dpdk)
{
    float           needed_mem;
    char*           hsize;

    if (!opts || !pcap || !dpdk)
        return (EINVAL);

    /* # CALCULATE THE NEEDED SIZE FOR MBUF STRUCTS */
    dpdk->mbuf_sz = sizeof(struct rte_mbuf) + pcap->max_pkt_sz;
    dpdk->mbuf_sz += (dpdk->mbuf_sz % (sizeof(int)));
#ifdef DEBUG
    puts("Needed paket allocation size = "
         "(size of MBUF) + (size of biggest pcap packet), "
         "rounded up to the next multiple of an integer.");
    printf("(%lu + %u) + ((%lu + %u) %% %lu) = %lu\n",
           sizeof(struct rte_mbuf), pcap->max_pkt_sz,
           sizeof(struct rte_mbuf), pcap->max_pkt_sz,
           sizeof(int), dpdk->mbuf_sz);
#endif /* DEBUG */
    //printf("-> Needed MBUF size: %lu\n", dpdk->mbuf_sz);

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
#else /* !DPDK_RECOMMANDATIONS */
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
    //printf("-> Needed number of MBUFS: %lu\n", dpdk->nb_mbuf);

    /* # CALCULATE THE TOTAL NEEDED MEMORY SIZE  */
    needed_mem = dpdk->mbuf_sz * dpdk->nb_mbuf;
#ifdef DEBUG
    puts("Needed memory = (needed mbuf size) * (number of needed mbuf).");
    printf("%lu * %lu = %.0f bytes\n", dpdk->mbuf_sz, dpdk->nb_mbuf, needed_mem);
#endif /* DEBUG */
    hsize = nb_oct_to_human_str(needed_mem);
    if (!hsize)
        return (-1);
    //printf("-> Needed Memory = %s\n", hsize);
    free(hsize);

    /* # CALCULATE THE NEEDED NUMBER OF GIGABYTE HUGEPAGES */
    if (fmod(needed_mem,((double)(1024*1024*1024))))
        dpdk->pool_sz = needed_mem / (float)(1024*1024*1024) + 1;
    else
        dpdk->pool_sz = needed_mem / (1024*1024*1024);
    //printf("-> Needed Hugepages of 1 Go = %lu\n", dpdk->pool_sz);
    return (0);
}

int main(const int ac, char** av)
{
    struct cmd_opts         opts;
    struct cpus_bindings    cpus;
    struct dpdk_ctx         dpdk;
    struct pcap_ctx         pcap;
    int                     ret;
    /* ADDITION */
    unsigned int i,sent;

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
    char* time_string;

    char* command = "echo $PCAP_DIR";
    char output[1024];

    FILE* fp = popen(command, "r");
    if (fp == NULL) {
        printf("PCAP_DIR not set\n");
        return 1;
    }
    fgets(output, 1024, fp);
    pclose(fp);

    // Remove trailing newline if present
    size_t len = strlen(output);
    if (output[len-1] == '\n') {
        output[len-1] = '\0';
    }

    opts.trace=output;

    ret = parse_options(ac, av, &opts);
    if (ret) {
        usage();
        return (1);
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

    if(opts.cont){
        if(opts.r_active){
            return (ENOENT);
        }
         /* start tx threads and wait to start to send pkts */
        
        while(1){
            clock_gettime(CLOCK_REALTIME, &start);

            current_time = time(NULL);
            time_string = ctime(&current_time);
            printf("The current time is: %s", time_string);

            ret = start_tx_threads(&opts, &cpus, &dpdk, &pcap);

            clock_gettime(CLOCK_REALTIME, &end);

            elapsed_ns = (end.tv_sec - start.tv_sec) * one_sec_ns + (end.tv_nsec - start.tv_nsec);
            long long sleep_ns = one_sec_ns - elapsed_ns;

            if (sleep_ns > 0) {
                struct timespec sleep_time = {0, sleep_ns};
                nanosleep(&sleep_time, NULL);
            }
            if (ret)
                goto mainExit;            
         }
    }
    else if(opts.r_active){
        clock_t last = clock();
        for (i = opts.range[0]; i < (opts.range[1]) + 1; i+=opts.range[2]){
            opts.nbruns = i;
            sent=0;
            while(1){

                clock_gettime(CLOCK_REALTIME, &start);

                current_time = time(NULL);
                time_string = ctime(&current_time);
                // printf("------------------------------------- The current time is: %s", time_string);

                ret = start_tx_threads(&opts, &cpus, &dpdk, &pcap);

                clock_gettime(CLOCK_REALTIME, &end);

                elapsed_ns = (end.tv_sec - start.tv_sec) * one_sec_ns + (end.tv_nsec - start.tv_nsec);
                long long sleep_ns = one_sec_ns - elapsed_ns;

                if (sleep_ns > 0) {
                    struct timespec sleep_time = {0, sleep_ns};
                    nanosleep(&sleep_time, NULL);
                }

                if(!ret){
                    break;
                }

            }
        }      
    }
    else{
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
