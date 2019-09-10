/* Trivial libtrace program that counts the number of HTTP packets in a trace.
 * Designed to demonstrate the use of trace_get_tcp()
 */
#include "libtrace.h"
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <getopt.h>

int i = 0;
int range = 65536;
uint64_t tcpsyncount[65536];
uint64_t tcpackcount[65536];
uint64_t tcpnoackcount[65536];

static void per_packet(libtrace_packet_t *packet)
{
	libtrace_tcp_t *tcp;

	/* Get the TCP header using trace_get_tcp() */
	tcp = trace_get_tcp(packet);
	
	/* If the packet does not have a TCP header, skip it */
	if (tcp == NULL)
		return;

	/* Scan all ports to count the number of TCP SYNs and the number of SYN ACKs*/
	for(i = 1; i <= range; i++){

		if ((ntohs(tcp->dest) == i) && (ntohs(tcp->syn)))
			tcpsyncount[i] +=1;
		if ((ntohs(tcp->source) ==i) && (ntohs(tcp->syn)) && (ntohs(tcp->ack)))
			tcpackcount[i] +=1;
		if (tcpsyncount[i] >= tcpackcount[i])
			tcpnoackcount[i] = tcpsyncount[i] - tcpackcount[i];
	}
}

static void libtrace_cleanup(libtrace_t *trace, libtrace_packet_t *packet) {

        /* It's very important to ensure that we aren't trying to destroy
         * a NULL structure, so each of the destroy calls will only occur
         * if the structure exists */
        if (trace)
                trace_destroy(trace);

        if (packet)
                trace_destroy_packet(packet);
}

int main(int argc, char *argv[])
{
        /* This is essentially the same main function from readdemo.c */

        libtrace_t *trace = NULL;
        libtrace_packet_t *packet = NULL;

	/* Initialize the counter */
	for (i = 1; i <= range; i = i + 1 ){
		tcpsyncount[i] = 0;
		tcpackcount[i] = 0;
		tcpnoackcount[i] = 0;
	}
        /* Ensure we have at least one argument after the program name */
        if (argc < 2) {
                fprintf(stderr, "Usage: %s inputURI\n", argv[0]);
                return 1;
        }

	packet = trace_create_packet();

        if (packet == NULL) {
                perror("Creating libtrace packet");
                libtrace_cleanup(trace, packet);
                return 1;
        }

        trace = trace_create(argv[1]);

        if (trace_is_err(trace)) {
                trace_perror(trace,"Opening trace file");
                libtrace_cleanup(trace, packet);
                return 1;
        }

        if (trace_start(trace) == -1) {
                trace_perror(trace,"Starting trace");
                libtrace_cleanup(trace, packet);
                return 1;
        }


        while (trace_read_packet(trace,packet)>0) {
                per_packet(packet);
        }

        if (trace_is_err(trace)) {
                trace_perror(trace,"Reading packets");
                libtrace_cleanup(trace, packet);
                return 1;
        }

	/* Display Scanning Result */

	printf("Port No		SYNs		Unanswered SYNs" "\n");
	for(i = 1; i <= range; i++){
		if (tcpsyncount[i] >= 100){
			printf("%" PRIu16 "		", i);
			printf("%" PRIu64 "		", tcpsyncount[i]);
			printf("%" PRIu64 "\n", tcpnoackcount[i]);
		}
	}
        libtrace_cleanup(trace, packet);
        return 0;
}

