/* Count the number of GRE packets and the byte size during each minute*/

#include "libtrace.h"
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <getopt.h>

uint64_t count_packets = 0;		/* The number of packets */
uint64_t size_bytes = 0;		/* The bytes size of the packtes during interval */
uint32_t next_report = 0;
uint32_t interval = 60;		/* Reporting interval defaults to 60 seconds. */

static void per_packet(libtrace_packet_t *packet)
{
	libtrace_gre_t *gre;
	struct timeval ts;
	void *transport = NULL;
	uint8_t proto;
	uint32_t rem;

	transport = trace_get_transport(packet, &proto, &rem);

	/* If there was no transport header, it can't be a GRE packet */
	if (transport == NULL)
		return;

	/* Check if the protocol is GRE, the protocal value can be found from libtrace.h 
	TRACE_IPPROTO_GRE = 47 */
	if (proto != 47)
		return;

	/* Get the Packet header*/
	gre = (libtrace_gre_t *)transport;

	/* Get the timestamp for the current packet */
	ts = trace_get_timeval(packet);
	
	/* If the packet does not have a GRE header, skip it */
	if (!gre)
		return;

	/* If next_report is zero, then this is the first packet from the
	 * trace so we need to determine the time at which the first report
	 * must occur */
	if (next_report == 0) {
		next_report = ts.tv_sec + interval;

		/* This is also a good opportunity to print column headings */
		printf("TIME\t\tGRE PACKETS\tBYTES\n");
	}

	while ((uint32_t)ts.tv_sec > next_report) {	
		
		/* Print a timestamp for the report and the packet count */
		printf("%u \t%" PRIu64 "\t\t%" PRIu64 "\n", next_report, count_packets, size_bytes);
		
		/* Reset the counter */
		count_packets = 0;
		size_bytes = 0;

		/* Determine when the next report is due */
		next_report += interval;
	}

	/* Count the number of packets */	
	count_packets += 1;
	/* Count the byte size of all packets during the interval*/
	size_bytes += trace_get_wire_length(packet);
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

	printf("%u \t%" PRIu64 "\t\t%" PRIu64 "\n", next_report, count_packets, size_bytes);

        libtrace_cleanup(trace, packet);
        return 0;
}

