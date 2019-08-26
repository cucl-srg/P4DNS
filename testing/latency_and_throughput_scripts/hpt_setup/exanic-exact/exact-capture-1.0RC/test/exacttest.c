#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>


#include <chaste/utils/util.h>
#include "exactio/exactio_file.h"

#define ts_to_ns(ts) ( ts.tv_sec * 1000 * 1000 * 1000 + ts.tv_nsec)

int writer()
{

    char test_data[1500];

    eio_stream_t* testc  = NULL;
    const char* argsc[5] = { "blah", "1500", "4096", "1", "0"};
    int err = eio_new(EIO_BRING, &testc, 5, argsc);
    //const char* argsc[3] = { "blah", "64", "64"};
    //int err = eio_new(EIO_NULL, &testc, 3, argsc);
    if(err){
        ERR("Could not construct stream err=%li\n", err);
        return err;
    }

    char* wr_buffer = NULL;
    int64_t wr_len = 64;

    struct timespec now = {0};
    clock_gettime(CLOCK_REALTIME,&now);
    uint64_t stop_ns        = 0;
    uint64_t total_bytes    = 0;
    uint64_t sample_bytes   = 0;
    uint64_t total_packets  = 0;
    uint64_t sample_packets = 0;
    uint64_t start_ns       = ts_to_ns(now);
    uint64_t total_start_ns = ts_to_ns(now);

    uint64_t blocking_start_ns = 0;
    uint64_t blocking_stop_ns = 0;
    uint64_t blocking_time_ns = 0;

    uint64_t min_tx_ns = UINT64_MAX;
    uint64_t max_tx_ns = 0;
    uint64_t acq_ns = 0;
    uint64_t rel_ns = 0;


    for(uint64_t i=0;i < 1000* 1000 * 1000;i++){
        wr_len = 64;
        clock_gettime(CLOCK_REALTIME,&now);
        acq_ns = ts_to_ns(now);
        eio_error_t err = eio_wr_acq(testc, &wr_buffer, &wr_len);
        switch(err){
            case EIO_ETRYAGAIN: {

                if(blocking_start_ns){
                    clock_gettime(CLOCK_REALTIME,&now);
                    blocking_stop_ns = ts_to_ns(now);
                }
                else{

                    blocking_start_ns = acq_ns;
                }
                i--;
                continue;
            }
            case EIO_ENONE:     break;
            default: fprintf(stderr,"Error %i\n", err); return -1;
        }
        //printf("%i Got %li bytes to write\n", i, wr_len);
        //(*(uint64_t*)(wr_buffer)) = i;

        wr_len = i%(1500-64);
        memcpy(wr_buffer,test_data,wr_len);
        eio_wr_rel(testc,wr_len);
        clock_gettime(CLOCK_REALTIME,&now);
        rel_ns = ts_to_ns(now);


        if(blocking_stop_ns){
            blocking_time_ns += blocking_stop_ns - blocking_start_ns;
            blocking_start_ns = 0;
            blocking_stop_ns  = 0;
        }

        sample_bytes += wr_len;
        total_bytes  += wr_len;
        sample_packets++;
        total_packets++;

        const uint64_t tx_ns = rel_ns - acq_ns;
        min_tx_ns = tx_ns < min_tx_ns ? tx_ns : min_tx_ns;
        max_tx_ns = tx_ns > max_tx_ns ? tx_ns : max_tx_ns;

        stop_ns = rel_ns;
        const uint64_t delta_ns = stop_ns - start_ns;
        if(delta_ns >= 1000 * 1000 * 1000){
            const uint64_t total_delta_ns = stop_ns - total_start_ns;
            const double total_gbs  = total_bytes * 8 / (double)total_delta_ns;
            const double sample_gbs = sample_bytes * 8 / (double)delta_ns;
            const double blocking_prec = (double)blocking_time_ns / delta_ns * 100.0;
            const double sample_mpps = (double)sample_packets / delta_ns *1000;
            const double total_mpps  = (double)total_packets / total_delta_ns * 1000;

            printf("min_tx=%lins last_tx=%lins max_tx=%lins - total rate=%.3fGbs sample rate=%.3fGbs (%luns) blocking_time=%li (%.2f%%) %0.2fMPPS (%.2fMPPs)\n",
                    min_tx_ns,
                    tx_ns,
                    max_tx_ns,
                    total_gbs,
                    sample_gbs,
                    delta_ns,
                    blocking_time_ns,
                    blocking_prec,
                    total_mpps,
                    sample_mpps);
            //Reset all counters for sample period
            start_ns         = stop_ns;
            sample_bytes     = 0;
            blocking_time_ns = 0;
            sample_packets   = 0;
        }

    }



    return 0;
}



int reader()
{
    eio_stream_t* tests;
    const char* argss[5] = { "blah", "64", "512", "0", "0"};
    int err = eio_new(EIO_BRING, &tests, 5, argss);
    //const char* argss[3] = { "blah", "4000", "4000"};
    //int err = eio_new(EIO_NULL, &tests, 3, argss);

    if(err){
        ERR("Could not construct stream err=%li\n", err);
        return err;
    }

    char* rd_buffer = NULL;
    int64_t rd_len = 64;

    //Stats keeping
    struct timespec now = {0};
    clock_gettime(CLOCK_REALTIME,&now);
    uint64_t stop_ns        = 0;
    uint64_t total_bytes    = 0;
    uint64_t sample_bytes   = 0;
    uint64_t total_packets  = 0;
    uint64_t sample_packets = 0;
    uint64_t start_ns       = ts_to_ns(now);
    uint64_t total_start_ns = ts_to_ns(now);

    uint64_t blocking_start_ns = 0;
    uint64_t blocking_stop_ns = 0;
    uint64_t blocking_time_ns = 0;

    uint64_t min_rx_ns = UINT64_MAX;
    uint64_t max_rx_ns = 0;
    uint64_t acq_ns = 0;
    uint64_t rel_ns = 0;

    for(int i=0;;i++){
        clock_gettime(CLOCK_REALTIME,&now);
        acq_ns = ts_to_ns(now);
        eio_error_t err = eio_rd_acq(tests, &rd_buffer, &rd_len);
        switch(err){
            case EIO_EEOF:      continue;
            case EIO_ETRYAGAIN:{
                if(blocking_start_ns){
                    clock_gettime(CLOCK_REALTIME,&now);
                    blocking_stop_ns = ts_to_ns(now);
                }
                else{
                    blocking_start_ns = acq_ns;
                }
                i--;
                continue;

            }
            case EIO_ENONE:     break;
            default: fprintf(stderr,"Error %i\n", err);  return -1;
        }

        eio_rd_rel(tests);
        clock_gettime(CLOCK_REALTIME,&now);
        rel_ns = ts_to_ns(now);


        if(blocking_stop_ns){
            blocking_time_ns += blocking_stop_ns - blocking_start_ns;
            blocking_start_ns = 0;
            blocking_stop_ns  = 0;
        }

        sample_bytes += rd_len;
        total_bytes  += rd_len;
        sample_packets++;
        total_packets++;

        const uint64_t rx_ns = rel_ns - acq_ns;
        min_rx_ns = rx_ns < min_rx_ns ? rx_ns : min_rx_ns;
        max_rx_ns = rx_ns > max_rx_ns ? rx_ns : max_rx_ns;

        stop_ns = rel_ns;
        const uint64_t delta_ns = stop_ns - start_ns;
        if(delta_ns >= 1000 * 1000 * 1000){
            const uint64_t total_delta_ns = stop_ns - total_start_ns;
            const double total_gbs  = total_bytes * 8 / (double)total_delta_ns;
            const double sample_gbs = sample_bytes * 8 / (double)delta_ns;
            const double blocking_prec = (double)blocking_time_ns / delta_ns * 100.0;
            const double sample_mpps = (double)sample_packets / delta_ns *1000;
            const double total_mpps  = (double)total_packets / total_delta_ns * 1000;
            printf("min_rx=%lins last_rx=%lins max_rx=%lins - total rate=%.3fGbs sample rate=%.3fGbs (%luns) blocking_time=%li (%.2f%%) %0.2fMPPS (%.2fMPPs)\n",
                    min_rx_ns,
                    rx_ns,
                    max_rx_ns,
                    total_gbs,
                    sample_gbs,
                    delta_ns,
                    blocking_time_ns,
                    blocking_prec,
                    total_mpps,
                    sample_mpps);            //Reset all counters for sample period
            start_ns         = stop_ns;
            sample_bytes     = 0;
            blocking_time_ns = 0;
            sample_packets   = 0;
        }


    }

    return -1;

}


int main(int argc, const char** argv)
{

    (void)argv;

    if(argc == 2){
        reader();
    }
    else{
        writer();
    }


    return 0;
}

