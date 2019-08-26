/*
 * exact-capture-listener.c
 *
 *  Created on: 4 Aug 2017
 *      Author: mattg
 */


#include "exact-capture-listener.h"
#include "data_structs/expcap.h"
#include "utils.h"

extern volatile bool lstop;
extern int64_t max_pkt_len;
extern int64_t min_pcap_rec;
extern int64_t max_pcap_rec;

static __thread int dev_id;
static __thread int port_id;
static __thread lstats_t* lstats;

/*Assumes there there never more than 64 listener threads!*/
extern lstats_t lstats_all[MAX_ITHREADS];


typedef struct
{
    eio_stream_t* ostream;
    bool pcap_hdr;
} ostream_state_t;


static inline void add_dummy_packet(char* obuff,
                                    char* dummy_data, int64_t dummy_rec_len,
                                    int64_t prev_pkt_hw_time)
{


    const int64_t dummy_payload_len = dummy_rec_len - sizeof(pcap_pkthdr_t) -
            sizeof(expcap_pktftr_t);

    ch_log_debug1("Adding dummy of pcap record of len=%li (payload=%li) to %p\n",
                  dummy_rec_len, dummy_payload_len, obuff);

    pcap_pkthdr_t* dummy_hdr = (pcap_pkthdr_t*) (obuff);
    obuff += sizeof(pcap_pkthdr_t);

    //Use the last ts value so the writer thread doesn't break
    dummy_hdr->ts.raw = prev_pkt_hw_time;
    dummy_hdr->caplen = dummy_rec_len - sizeof(pcap_pkthdr_t);
    dummy_hdr->len = 0; /*This is an invalid dummy packet, 0 wire length */

    memset(obuff, 0xFF, dummy_payload_len);
    //memcpy (obuff, dummy_data, dummy_payload_len);
    obuff += dummy_payload_len;

    memset(obuff, 0xFF, sizeof(expcap_pktftr_t));
    (void)dummy_data;
    return;
    expcap_pktftr_t* pkt_ftr = (expcap_pktftr_t*)(obuff);

    obuff += sizeof(expcap_pktftr_t);
    pkt_ftr->flags = 0;
    pkt_ftr->foot.extra.dropped = 0;

    ch_log_debug1("Updated obuff to %p.\n", obuff);

}


static inline void flush_buffer(eio_stream_t* ostream, int64_t bytes_added,
                  int64_t obuff_len, char* obuff, int64_t prev_pkt_hw_time,
                  char* dummy_data)
{

    //Nothing to do if nothing was added
    if(bytes_added == 0)
    {
        return;
    }

    ch_log_debug1("Flushing at offset %li, buffer_start=%p, buffer_fin=%p\n",
                  bytes_added,
                  obuff,
                  obuff+obuff_len-1);
    /* What is the minimum sized packet that we can squeeze in?
     * Just a header and a footer, no content */

    ch_log_debug1("max pcap record=%li min pcap record=%li\n", max_pcap_rec,
                  min_pcap_rec);

    /* Find the next disk block boundary with space for adding a minimum packet*/
    const int64_t block_bytes = round_up(bytes_added + min_pcap_rec, DISK_BLOCK);

    ch_log_debug1("Block bytes=%li\n", block_bytes);
    ifunlikely(block_bytes > obuff_len)
    {
        ch_log_fatal("Assumption violated %li > %li\n", block_bytes, obuff_len);
    }

    /* How many bytes do we need to write? */
    int64_t remain = block_bytes - bytes_added;

    ch_log_debug1("Remain bytes=%li\n", remain);

    /* Fill out the remaining space with packets no smaller than min_packet, and
     * no larger than max_packet. Assume that remain is at least as big as a
     * minimum sized packet (which is enforced above).
     */
    while(remain > 0)
    {
        ch_log_debug1("Remain:%li, added:%li max %li (problem=%i)\n",
                      remain, bytes_added, obuff_len, bytes_added > obuff_len);

        if(remain <= max_pcap_rec){
            add_dummy_packet(obuff + bytes_added, dummy_data, remain,
                             prev_pkt_hw_time);
            ch_log_debug1("Added dummy of size %li\n", remain);
            bytes_added += remain;
            remain -= remain;
            break;
        }
        else if(remain - max_pcap_rec < min_pcap_rec){
            add_dummy_packet(obuff + bytes_added, dummy_data, min_pcap_rec,
                             prev_pkt_hw_time);
            ch_log_debug1("Added dummy of size %li\n", min_pcap_rec);
            remain -= min_pcap_rec;
            bytes_added += min_pcap_rec;
        }
        else{
            add_dummy_packet(obuff + bytes_added, dummy_data, max_pcap_rec,
                             prev_pkt_hw_time);
            ch_log_debug1("Added dummy of size %li\n", max_pcap_rec);
            remain -= max_pcap_rec;
            bytes_added += max_pcap_rec;
        }
    }

    /* At this point, we've padded up to the disk block boundary.
     * Flush out to disk thread writer*/
    eio_wr_rel(ostream, bytes_added, NULL);

    ch_log_debug1("Done flushing at %li bytes added\n", bytes_added);
}

/* Finish off a packet in the obuff by adding a footer. Return the number of bytes added */
static inline int64_t fin_packet(pcap_pkthdr_t* hdr, char* obuff, uint8_t flags,
        int64_t* dropped, int dev_id, int port_id)
{

    expcap_pktftr_t* pkt_ftr = (expcap_pktftr_t*) (obuff);

    /* Are we sure? Doing this means that caplen > len, which is technically a
     * PCAP violation? But the bytes here didn't come off the wire? */
    hdr->caplen += sizeof(expcap_pktftr_t);
    pkt_ftr->flags = flags;
    pkt_ftr->foot.extra.dropped = *dropped;
    pkt_ftr->dev_id  = dev_id;
    pkt_ftr->port_id = port_id;
    *dropped = 0;


    return sizeof(expcap_pktftr_t);
}


/* Copy a packet fragment from ibuff to obuff. Return the number of bytes copied*/
static inline int64_t cpy_frag(pcap_pkthdr_t* hdr, char* const obuff,
                               char* ibuff, int64_t ibuff_len)
{
    int64_t added = 0;
    /* Only copy as much as the caplen */
    iflikely(hdr->len < max_pkt_len)
    {
        /*
         * Get the data out of the fragment, but don't copy more
         * than max_caplen
         */
        const int64_t copy_bytes = MIN(max_pkt_len - hdr->len, ibuff_len);
        memcpy (obuff, ibuff, copy_bytes);

        /* Do accounting and stats */
        hdr->caplen += copy_bytes;
        added = copy_bytes;
    }

    hdr->len += ibuff_len;
    lstats->bytes_rx += ibuff_len;

    return added;
}


static i64 rx_packets = 0;

/* This func tries to rx one packet and returns the number of bytes RX'd.
 * The return may be zero if no packet was RX'd, or if there was an error */
static inline int64_t rx_packet ( eio_stream_t* istream,  char* const obuff,
        char* obuff_end, exanic_cycles_t* rx_time, int64_t* dropped
)
{
#ifndef NOIFASSERT
    i64 rx_frags = 0;
#endif

    /* Set up a new pcap header */
    int64_t rx_b = 0;

    pcap_pkthdr_t* hdr = (pcap_pkthdr_t*) (obuff);
    rx_b += sizeof(pcap_pkthdr_t);
    ifassert(obuff + rx_b >= obuff_end)
        ch_log_fatal("Obuff %p + %li = %p will exceeded max %p\n", obuff, rx_b,
                     obuff + rx_b, obuff_end);


    /* Reset just the things that need to be incremented in the header */
    hdr->caplen  = 0;
    hdr->len     = 0;

    /* Try to RX the first fragment */
    eio_error_t err = EIO_ENONE;
    char* ibuff;
    int64_t ibuff_len;
    for (int64_t tryagains = 0; ; lstats->spins1_rx++, tryagains++)
    {
        err = eio_rd_acq (istream, &ibuff, &ibuff_len, rx_time);

        iflikely(err != EIO_ETRYAGAIN)
        {
            hdr->ts.raw = *rx_time;
            break;
        }

        /* Make sure we don't wait forever */
        ifunlikely(lstop || tryagains >= (1024 * 1024))
        {
            return 0;
        }

    }

    rx_packets++;
    /* Note, no use of lstop: don't stop in the middle of RX'ing a packet */
    for (;; err = eio_rd_acq (istream, &ibuff, &ibuff_len, NULL),
            lstats->spinsP_rx++)
    {
#ifndef NOIFASSERT
        rx_frags++;
#endif
        switch(err)
        {
            case EIO_ETRYAGAIN:
                /* Most of the time will be spent here (hopefully..) */
                continue;

            /* Got a fragment. There are some more fragments to come */
            case EIO_EFRAG_MOR:
                rx_b += cpy_frag(hdr,obuff + rx_b,ibuff,ibuff_len);
                break;

            /* Got a complete frame. There are no more fragments */
            case EIO_ENONE:
                rx_b += cpy_frag(hdr,obuff + rx_b,ibuff,ibuff_len);
                rx_b += fin_packet(hdr, obuff + rx_b, EXPCAP_FLAG_NONE, dropped,
                                   dev_id, port_id);
                break;

            /* Got a corrupt (CRC) frame. There are no more fragments */
            case EIO_EFRAG_CPT:
                lstats->errors++;
                rx_b += cpy_frag(hdr,obuff + rx_b,ibuff,ibuff_len);
                rx_b += fin_packet(hdr, obuff + rx_b, EXPCAP_FLAG_CRPT,dropped,
                                   dev_id, port_id);
                break;

            /* Got an aborted frame. There are no more fragments */
            case EIO_EFRAG_ABT:
                lstats->errors++;
                rx_b += cpy_frag(hdr,obuff + rx_b,ibuff,ibuff_len);
                rx_b += fin_packet(hdr, obuff + rx_b, EXPCAP_FLAG_ABRT,dropped,
                                   dev_id, port_id);
                break;

            /* **** UNRECOVERABLE ERRORS BELOW THIS LINE **** */
            /* Software overflow happened, we're dead. Exit the function */
            case EIO_ESWOVFL:
                lstats->swofl++;
                /* Forget what we were doing, just exit */
                eio_rd_rel(istream, NULL);

                /*Skip to a good place in the receive buffer*/
                err = eio_rd_acq(istream, NULL, NULL, NULL);
                eio_rd_rel(istream, NULL);
                return 0;

            /* Hardware overflow happened, we're dead. Exit the function */
            case EIO_EHWOVFL:
                lstats->hwofl++;
                /* Forget what we were doing, just exit */
                eio_rd_rel(istream, NULL);

                /*Skip to a good place in the receive buffer*/
                err = eio_rd_acq(istream, NULL, NULL, NULL);
                eio_rd_rel(istream, NULL);
                return 0;

            default:
                ch_log_fatal("Unexpected error code %i\n", err);
        }

        /* When we get here, we have fragment(s), so we need to release the read
         * pointer, but this may fail. In which case we drop everything */
        if(eio_rd_rel(istream, NULL)){
            return 0;
        }

#ifndef NOIFASSERT
        ifassert(obuff + rx_b >= obuff_end)
            ch_log_fatal("Obuff %p + %li = %p exceeds max %p\n",
                     obuff, rx_b, obuff + rx_b, obuff_end);
#endif


        /* If there are no more frags to come, then we're done! */
        if(err != EIO_EFRAG_MOR){
            lstats->packets_rx++;
            return rx_b;
        }

        /* There are more frags, go again!*/
    }



    /* Unreachable */
    ch_log_fatal("Error: Reached unreachable code!\n");
    return -1;
}

/*
 * Look for a new output stream and output the buffer from that stream
 */
static inline int get_obuff(int64_t curr_ostream, int64_t num_ostreams,
                            ostream_state_t* ostreams,
        char** obuff, int64_t* obuff_len )
{
    ch_log_debug2("Looking for new ostream %li..\n", num_ostreams);
    /* Look at each ostream just once */
    for (int i = 0; i < num_ostreams; i++, curr_ostream++)
    {
        curr_ostream = curr_ostream >= num_ostreams ? 0 : curr_ostream;
        eio_stream_t* ostream = ostreams[curr_ostream].ostream;
        eio_error_t err = eio_wr_acq (ostream, obuff, obuff_len, NULL);
        iflikely(err == EIO_ENONE)
        {
            ch_log_debug1("Got ostream at index %li..\n", curr_ostream);
            return curr_ostream;
        }
        iflikely(err == EIO_ETRYAGAIN)
        {
            continue; //Look at the next ring
        }

        ch_log_error("Could not get bring with unexpected error %i\n", err);
        return -1;
    }

    ch_log_debug2("Could not find an ostream!\n");
    return curr_ostream;

}


/*
 * This is the main listener thread. It's job is is to a single ExaNIC buffer
 * (2MB) and copy fragments of packets in 120B chunks into a slot in a larger
 * ring buffer. The larger ring buffer is the connection to a writer thread that
 * syncs data to disk. The listener thread puts places holders for PCAP header
 * in the ring and minimal info in the headers. Final preparation of these
 * headers is left to the writer thread. This thread has very tight timing
 * requirements. It only has about 60ns to handle each fragment and maintain
 * line rate. The writer requires that all data is 4K aligned. To solve this the
 * listener inserts "dummy" packets to pad out to 4K whenever it syncs to the
 * writer.
 */

void* listener_thread (void* params)
{
    listener_params_t* lparams = params;
    ch_log_debug1("Creating exanic listener thread id=%li on interface=%s\n",
                    lparams->ltid, lparams->interface);

    /*
     * Set up a dummy packet to pad out extra space when needed
     * dummy packet areas are per thread to avoid falsely sharing memory
     */
    char dummy_data[DISK_BLOCK * 2];
    init_dummy_data(dummy_data, DISK_BLOCK *2);

    const CH_VECTOR(cstr)* dests = lparams->dests;
    const int64_t num_ostreams = dests->count;
    char* iface = lparams->interface;
    const int64_t ltid = lparams->ltid; /* Listener thread id */

    /* Thread local storage parameters */
    dev_id  = lparams->exanic_dev_num;
    port_id = lparams->exanic_port;
    lstats  = &lstats_all[ltid];

    eio_stream_t* istream = NULL;
    eio_args_t inargs;
    bzero(&inargs,sizeof(inargs));
    inargs.type                     = EIO_EXA;
    inargs.args.exa.interface_rx    = iface;
    inargs.args.exa.interface_tx    = NULL;
    inargs.args.exa.kernel_bypass   = lparams->kernel_bypass;
    inargs.args.exa.promisc         = lparams->promisc;
    int err = eio_new (&inargs, &istream);
    if (err)
    {
        ch_log_fatal("Could not create listener input stream %s\n");
        return NULL;
    }

    if (lparams->dummy_istream)
    {
        /* Replace the input stream with a dummy stream */
        ch_log_debug1("Creating null output stream in place of exanic name: %s\n",
                    iface);
        inargs.type = EIO_DUMMY;
        inargs.args.dummy.read_buff_size = 64;
        inargs.args.dummy.rd_mode = DUMMY_MODE_EXANIC;
        inargs.args.dummy.exanic_pkt_bytes = inargs.args.dummy.read_buff_size;
        inargs.args.dummy.write_buff_size = 0;   /* We don't write to this stream */
        err = eio_new (&inargs, &istream);
        if (err)
        {
            ch_log_error("Could not create listener input stream %s\n");
            return NULL;
        }
    }
    ch_log_debug1("Done. Setting up exanic listener for interface %s\n", iface);

    if (dests->count > MAX_OTHREADS)
    {
        ch_log_fatal("Too many destinations\n");
    }
    ch_log_debug1("Setting up %li listener bring streams for interface %s\n",
                  num_ostreams, lparams->interface);
    char bring_name[BRING_NAME_LEN + 1] = {0}; /* +1 = space for null terminator */

    ostream_state_t ostreams[num_ostreams];
    for (int ostr_idx = 0; ostr_idx < num_ostreams; ostr_idx++)
    {
        const char* dest = dests->first[ostr_idx];

        /* Turn the interface string into a unique shared memory name */
        bzero (bring_name, BRING_NAME_LEN);
        ch_word bring_name_chars = sprintf(bring_name,"EXCAP_%04X", getpid());
        for (size_t i = 0;
                i < strlen (iface) && bring_name_chars < BRING_NAME_LEN; i++)
        {
            if (isalnum(iface[i]))
            {
                bring_name[bring_name_chars] = iface[i];
                bring_name_chars++;
            }
        }

        bring_name[bring_name_chars] = '_';
        bring_name_chars++;

        for (size_t i = 0;
                i < strlen (dest) && bring_name_chars < BRING_NAME_LEN; i++)
        {
            if (isalnum(dest[i]))
            {
                bring_name[bring_name_chars] = dest[i];
                bring_name_chars++;
            }
            else{
                bring_name[bring_name_chars] = '_';
                bring_name_chars++;

            }
        }

        /* This must be a multiple of the disk block size (assume 4kB)*/

        ch_log_debug1("Creating bring output stream with name: %s\n", bring_name);
        eio_stream_t* ostream = NULL;
        eio_args_t outargs;
        bzero(&outargs, sizeof(outargs));
        outargs.type = EIO_BRING;
        outargs.args.bring.filename = bring_name;
        outargs.args.bring.isserver = 1;
        outargs.args.bring.slot_size  = BRING_SLOT_SIZE;
        outargs.args.bring.slot_count = BRING_SLOT_COUNT;
        ch_log_debug1("slots=%li, slot_count=%li\n", outargs.args.bring.slot_size,
                      outargs.args.bring.slot_count);
        if (eio_new (&outargs, &ostream))
        {
            ch_log_error(
                    "Could not create listener output stream with name %s\n",
                    bring_name);
            return NULL;
        }

        if (lparams->dummy_ostream)
        {
            ch_log_debug1(
                    "Creating null output stream in place of bring name: %s\n",
                    bring_name);
            outargs.type = EIO_DUMMY;
            outargs.args.dummy.read_buff_size = 0; /*We don't read form this stream */
            outargs.args.dummy.write_buff_size = BRING_SLOT_SIZE;
            if (eio_new (&outargs, &ostream))
            {
                ch_log_error(
                        "Could not create listener output stream with name %s\n",
                        bring_name);
                return NULL;
            }
            ch_log_debug1(
                    "Done creating null output stream at index %li with name: %s\n",
                    ostr_idx, bring_name);
        }

        ch_log_debug1("Assigning ostream at index %li\n", ostr_idx);
        ostreams[ostr_idx].ostream = ostream;
        ostreams[ostr_idx].pcap_hdr = false;
    }
    ch_log_debug1(
            "Done setting up exanic listener bring streams for interface %s\n",
            iface);

    //**************************************************************************
    //Listener - Real work begins here!
    //**************************************************************************
    char* obuff = NULL;
    int64_t obuff_len = 0;

    /* May want to change this depending on scheduling goals */
    int64_t curr_ostream = ltid;
    int64_t bytes_added = 0;


    int64_t now;
    const int64_t maxwaitns = 1000 * 1000 * 100;
    eio_nowns (&now);
    int64_t timeout = now + maxwaitns; //100ms timeout
    exanic_cycles_t prev_pkt_hw_time = 0;

    int64_t dropped = 0;

    const int64_t expcap_foot_size = (int64_t)sizeof(expcap_pktftr_t);
    const int64_t pcap_head_size = (int64_t)sizeof(pcap_pkthdr_t);
    const int64_t max_pcap_rec = max_pkt_len + pcap_head_size
                                        + expcap_foot_size;


    while (!lstop)
    {
        /*
         * The following code will flush the output buffer and send it across to
         * the writer thread and then obtain a new output buffer. It does so in
         * one of 2 circumstances:
         *
         * 1) There is less than 1 full packet plus a pcap_pkt_hdr_t left worth
         * of space in the output buffer. The pcap_pkthdr_t is required to ensure
         * there is enough space for a dummy packet to pad out the rest of this
         * buffer to be block aligned size for high speed writes to disk.
         *
         * 2) There has been a timeout and there are packets waiting (not just a
         * pre-prepared pcap header. We do this so that packets don't wait too
         * long before timestamp conversions and things happen.
         */

        const bool buff_full = obuff_len - bytes_added <  max_pcap_rec * 2;
        const bool timed_out = now >= timeout && bytes_added > pcap_head_size;
        ifunlikely( obuff && (buff_full || timed_out))
        {
            ch_log_debug1( "Buffer flush: buff_full=%i, timed_out =%i, obuff_len (%li) - bytes_added (%li) = %li < full_packet_size x 2 (%li) = (%li)\n",
                    buff_full, timed_out, obuff_len, bytes_added, obuff_len - bytes_added, max_pcap_rec * 2);

            flush_buffer(ostreams[curr_ostream].ostream, bytes_added,
                    obuff_len, obuff, prev_pkt_hw_time,
                    dummy_data);

            /* Reset the timer and the buffer */
            eio_nowns(&now);
            timeout = now + maxwaitns;
            obuff = NULL;
            obuff_len = 0;
            bytes_added = 0;
        }

        while(!obuff && !lstop)
        {
            /* We don't have an output buffer to work with, so try to grab one*/
            curr_ostream = get_obuff(curr_ostream,num_ostreams,ostreams,
                    &obuff,&obuff_len);

            if(curr_ostream < 0){
                goto finished;
            }

            /*
             * We looked at all the ostreams, there was nowhere to put a frame.
             * If there is a new frame, then skip it, otherwise try again to
             * find a place to put it. We don't want this to happen, but we do
             * want it to be fast when it does hence "likely".
             */
            iflikely(!obuff)
            {
                ch_log_debug2("No buffer, dropping packet..\n");
                eio_error_t err = EIO_ENONE;
                err = eio_rd_acq(istream, NULL, NULL, NULL);
                iflikely(err == EIO_ENONE)
                {
                    lstats->dropped++;
                    dropped++;
                }
                ifunlikely(err == EIO_ESWOVFL)
                {
                    lstats->swofl++;
                }
                err = eio_rd_rel(istream, NULL);
                if(err == EIO_ESWOVFL )
                {
                    lstats->swofl++;
                }
            }
        }

        if(lstop){
            goto finished;
        }

        /* This func tries to rx one packet it returns the number of bytes RX'd
         * this may be zero if no packet was RX'd, or if there was an error */
        const int64_t rx_bytes = rx_packet(istream, obuff + bytes_added, obuff +
                                           obuff_len, &prev_pkt_hw_time, &dropped);

        ifunlikely(rx_bytes == 0)
        {
            /*Do this here so we don't do it too often. Only when we're
             * waiting around with nothing to do */
            eio_nowns(&now);
        }
        ifassert(rx_bytes > max_pcap_rec)
        {
            ch_log_fatal("RX %liB > full packet size %li\n",
                         rx_bytes, max_pcap_rec);

        }

        bytes_added += rx_bytes;

        ifassert(bytes_added > obuff_len)
        {
            ch_log_fatal("Wrote beyond end of buffer %li > %li\n",
                         rx_bytes, obuff_len);
        }




    }

finished:
    ch_log_debug1("Listener thread %i for %s exiting\n", lparams->ltid,
                lparams->interface);


    //Remove any last headers that are waiting
    if(bytes_added == sizeof(pcap_pkthdr_t))
    {
        bytes_added = 0;
    }

    if(obuff){
        flush_buffer(ostreams[curr_ostream].ostream, bytes_added, obuff_len,
                obuff, prev_pkt_hw_time, dummy_data);
    }

    ch_log_debug1("Listener thread %i for %s done.\n", lparams->ltid,
                lparams->interface);

    //free(params); ??
    return NULL;
}
