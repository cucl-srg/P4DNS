/*
 * Copyright (c) 2017, All rights reserved.
 * See LICENSE.txt for full details. 
 * 
 *  Created:   19 Jun 2017
 *  File name: exactio_file.c
 *  Description:
 *  <INSERT DESCRIPTION HERE> 
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <errno.h>

#include <linux/ethtool.h>
#ifndef ETHTOOL_GET_TS_INFO
#include "ethtool_ts_info.h"
#endif


#include "exactio_exanic.h"

#include "../utils.h"

typedef enum {
    EXACTIO_FILE_MOD_IGNORE = 0,
    EXACTIO_FILE_MOD_RESET  = 1,
    EXACTIO_FILE_MOD_TAIL   = 2,
} exactio_exa_mod_t;



static void exa_destroy(eio_stream_t* this)
{
    exa_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    if(priv->closed){
        return;
    }

    if(priv->rx){
        exanic_release_rx_buffer(priv->rx);
    }

    if(priv->tx){
        exanic_release_tx_buffer(priv->tx);
    }

    if(priv->rx_nic){
        exanic_release_handle(priv->rx_nic);
    }

    if(priv->tx_nic){
        exanic_release_handle(priv->tx_nic);
    }

    priv->closed = true;

}



//Write operations
static eio_error_t exa_write_acquire(eio_stream_t* this, char** buffer, int64_t* len, int64_t* ts)
{
    exa_priv_t* priv = IOSTREAM_GET_PRIVATE(this);

    ifassert(priv->tx_buffer){
        return EIO_ERELEASE;
    }

    ifassert(*len > (int64_t)priv->max_tx_mtu){
        return EIO_ETOOBIG;
    }

    iflikely(*len == 0){
        *len = priv->max_tx_mtu;
    }

    priv->tx_buffer_len = *len;
    priv->tx_buffer = exanic_begin_transmit_frame(priv->tx,(size_t)*len);

    (void)ts;
    //eio_nowns(ts);
    *buffer = priv->tx_buffer;

    return EIO_ENONE;
}

static eio_error_t exa_write_release(eio_stream_t* this, int64_t len, int64_t* ts)
{
    exa_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    ifassert(!priv->tx_buffer){
        return EIO_EACQUIRE;
    }

    ifassert(len > priv->tx_buffer_len){
        fprintf(stderr,"Error: length supplied is larger than length of buffer. Corruption likely. Aborting\n");
        exit(-1);
    }

    exanic_cycles32_t old_start = 0;
    exanic_cycles32_t start     = 0;
    ifunlikely(ts){
        old_start = exanic_get_tx_timestamp(priv->tx);
    }

    ifunlikely(len == 0){
        exanic_abort_transmit_frame(priv->tx);
        return EIO_ENONE;
    }

    ifunlikely(exanic_end_transmit_frame(priv->tx,len)){
        return EIO_EUNSPEC;
    }

    ifunlikely(ts){
        do{
            /* Wait for TX frame to leave the NIC */
        }
        while (old_start == start);

        //This is nasty because the last packet sent timestamp will not always
        //be timestamp of the packet sent
        *ts = exanic_expand_timestamp(priv->tx_nic, start);
    }


    priv->tx_buffer     = NULL;
    priv->tx_buffer_len = 0;
    return EIO_ENONE;
}



int ethtool_ioctl(int fd, char *ifname, void *data)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_data = data;

    return ioctl(fd, SIOCETHTOOL, &ifr);
}

static int ethtool_get_priv_flags(int fd, char *ifname, uint32_t *flags)
{
    struct ethtool_value val;
    int ret;

    memset(&val, 0, sizeof(val));
    val.cmd = ETHTOOL_GPFLAGS;
    ret = ethtool_ioctl(fd, ifname, &val);
    if (ret == 0)
        *flags = val.data;

    return ret;
}


static int ethtool_get_flag_names(int fd, char *ifname,
                                  char flag_names[32][ETH_GSTRING_LEN])
{
    struct ethtool_drvinfo drvinfo;
    struct ethtool_gstrings *strings;
    unsigned len;

    /* Get number of flags from driver info */
    memset(&drvinfo, 0, sizeof(drvinfo));
    drvinfo.cmd = ETHTOOL_GDRVINFO;
    if (ethtool_ioctl(fd, ifname, &drvinfo) == -1)
        return -1;

    len = drvinfo.n_priv_flags;
    if (len > 32)
        len = 32;

    /* Get flag names */
    strings = calloc(1, sizeof(struct ethtool_gstrings) + len * ETH_GSTRING_LEN);
    strings->cmd = ETHTOOL_GSTRINGS;
    strings->string_set = ETH_SS_PRIV_FLAGS;
    strings->len = len;
    if (ethtool_ioctl(fd, ifname, strings) == -1)
    {
        free(strings);
        return -1;
    }

    memset(flag_names, 0, 32 * ETH_GSTRING_LEN);
    memcpy(flag_names, strings->data, len * ETH_GSTRING_LEN);

    return 0;
}


static int ethtool_set_priv_flags(int fd, char *ifname, uint32_t flags)
{
    struct ethtool_value val;

    memset(&val, 0, sizeof(val));
    val.cmd = ETHTOOL_SPFLAGS;
    val.data = flags;

    return ethtool_ioctl(fd, ifname, &val);
}

static int set_exanic_params(exanic_t *exanic, char* device, int port_number,
                             bool promisc, bool kernel_bypass)
{
    struct ifreq ifr;
    int fd;

    if (exanic_get_interface_name(exanic, port_number, ifr.ifr_name, IFNAMSIZ) != 0)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number,
                exanic_get_last_error());
        exit(1);
    }


    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1 ||
            ioctl(fd, SIOCGIFFLAGS, &ifr) == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number, strerror(errno));
        exit(1);
    }

    if(promisc)
        ifr.ifr_flags |= IFF_PROMISC;

    ifr.ifr_flags |= IFF_UP;

    if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number, strerror(errno));
        exit(1);
    }


    if(!kernel_bypass)
        return 0;


    /* Get flag names and current setting */
    char flag_names[32][ETH_GSTRING_LEN];
    uint32_t flags = 0;
    if (ethtool_get_flag_names(fd, ifr.ifr_name, flag_names) == -1 ||
        ethtool_get_priv_flags(fd, ifr.ifr_name, &flags) == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number, strerror(errno));
        exit(1);
    }

    /* Look for flag name */
    int i = 0;
    for (i = 0; i < 32; i++)
        if (strcmp("bypass_only", flag_names[i]) == 0)
            break;
    if (i == 32)
    {
        fprintf(stderr, "%s:%d: could not find bypass-only flag \n",
                device, port_number);
        exit(1);
    }

    flags |= (1 << i);

    /* Set flags */
    if (ethtool_set_priv_flags(fd, ifr.ifr_name, flags) == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number,
                (errno == EINVAL) ? "Feature not supported on this port"
                                  : strerror(errno));
        exit(1);
    }

    return 0;
}



/*
 * Arguments
 * [0] filename
 * [1] read buffer size
 * [2] write buffer size
 * [3] reset on modify
 */
static eio_error_t exa_construct(eio_stream_t* this, exa_args_t* args)
{
    const char* interface_rx = args->interface_rx;
    const char* interface_tx = args->interface_tx;
    const bool promisc       = args->promisc;
    const bool kernel_bypass = args->kernel_bypass;

    exa_priv_t* priv = IOSTREAM_GET_PRIVATE(this);

    if(interface_rx){
        if(parse_device(interface_rx, priv->rx_dev, &priv->rx_dev_id, &priv->rx_port))
        {
            fprintf (stderr, "%s: no such interface or not an ExaNIC\n",
                     interface_rx);
            return 1;
        }

        priv->rx_nic = exanic_acquire_handle(priv->rx_dev);
        if (!priv->rx_nic){
            fprintf(stderr, "exanic_acquire_handle: %s\n", exanic_get_last_error());
            return 1;
        }

        priv->rx = exanic_acquire_rx_buffer(priv->rx_nic, priv->rx_port, 0);
        if (!priv->rx){
            fprintf(stderr, "exanic_acquire_rx_buffer: %s\n", exanic_get_last_error());
            return 1;
        }

        if(set_exanic_params(priv->rx_nic, priv->rx_dev, priv->rx_port,
                             promisc,kernel_bypass)){
            return 1;
        }

    }

    if(interface_tx){
        if(parse_device(interface_tx, priv->tx_dev, &priv->tx_dev_id, &priv->tx_port))
        {
            fprintf (stderr, "%s: no such interface or not an ExaNIC\n",
                     interface_tx);
            return 1;
        }


        priv->tx_nic = exanic_acquire_handle(priv->tx_dev);
        if (!priv->tx_nic){
            fprintf(stderr, "exanic_acquire_handle: %s\n", exanic_get_last_error());
            return 1;
        }

        priv->max_tx_mtu = exanic_get_tx_mtu(priv->tx);

        priv->tx = exanic_acquire_tx_buffer(priv->tx_nic, priv->tx_port, 0);
        if (!priv->tx){
            fprintf(stderr, "exanic_acquire_tx_buffer: %s\n", exanic_get_last_error());
            return 1;
        }
    }


    //priv->eof    = 0;
    priv->closed = false;

    return 0;

}

NEW_IOSTREAM_DEFINE(exa,exa_args_t, exa_priv_t)

