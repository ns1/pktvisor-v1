/*
 * Copyright 2015 NSONE, Inc.
 */

#include <sys/time.h>
#include <time.h>
#include <curses.h>
#include <stdio.h>
#include <signal.h>
#include <arpa/inet.h>

#include "pktvisorui.h"

#define START_COL 0
#define START_ROW 5
#define FULL 0

WINDOW *w;
int redraw_interval;
bool do_redraw = true;
struct itimerval redraw_itv;
enum redraw_target {
    SOURCE_TABLE,
    DEST_TABLE,
    MALFORMED_TABLE,
    SRC_PORT_TABLE,
    QUERY2_TABLE,
    QUERY3_TABLE,
    NXDOMAIN_TABLE,
    REFUSED_TABLE,
    GEO_LOC_TABLE,
    GEO_ASN_TABLE,
    SUMMARY_TABLE,
    QTYPE_TABLE,
    HELP
};
int cur_target = SUMMARY_TABLE;

// rate computations
uint64_t last_incoming, last_outgoing, last_query, last_reply;
struct timeval last_rate_ts;

void gotsignalrm(int sig) {
    do_redraw = 1;
    signal(sig, gotsignalrm);
}

void redraw_table_int(struct int32_entry *table, char *txt_hdr, int row, int col, int max) {
    struct int32_entry *entry, *tmp_entry, *sorted_table;
    unsigned int i = 0;

    mvprintw(row, col, "%s", txt_hdr);

    if (!table) {
        mvprintw(++row, col, "(no data)");
        return;
    }

    if (max <= 0)
        max = getmaxy(w) - 10;

    // copy the table so we can sort it non destructively
    sorted_table = NULL;
    HASH_ITER(hh, table, entry, tmp_entry) {
        HASH_ADD(hh_srt, sorted_table, key, sizeof(uint32_t), entry);
    }

    HASH_SRT(hh_srt, sorted_table, sort_int_by_count);
    HASH_ITER(hh_srt, sorted_table, entry, tmp_entry) {
        mvprintw(++row, col, "%6u %lu", entry->key, entry->count);
        if (++i >= max)
            break;
    }
    HASH_CLEAR(hh_srt, sorted_table);

}

void redraw_table_ip(struct int32_entry *table, char *txt_hdr, int row, int col, int max) {
    struct int32_entry *entry, *tmp_entry, *sorted_table;
    char ip[INET_ADDRSTRLEN];
    unsigned int i = 0;

    mvprintw(row, col, "%s", txt_hdr);

    if (!table) {
        mvprintw(++row, col, "(no data)");
        return;
    }

    if (max <= 0)
        max = getmaxy(w) - 10;

    // copy the table so we can sort it non destructively
    sorted_table = NULL;
    HASH_ITER(hh, table, entry, tmp_entry) {
        HASH_ADD(hh_srt, sorted_table, key, sizeof(uint32_t), entry);
    }


    HASH_SRT(hh_srt, sorted_table, sort_int_by_count);
    HASH_ITER(hh_srt, sorted_table, entry, tmp_entry) {
        inet_ntop(AF_INET, &entry->key, ip, sizeof(ip));
        mvprintw(++row, col, "%16s %lu", ip, entry->count);
        if (++i >= max)
            break;
    }
    HASH_CLEAR(hh_srt, sorted_table);

}

void redraw_table_str(struct str_entry *table, char *txt_hdr, int row, int col, int max) {
    struct str_entry *entry, *tmp_entry, *sorted_table;
    unsigned int i = 0;
    int max_len = 0;

    mvprintw(row, col, "%s", txt_hdr);
    if (!table) {
        mvprintw(++row, col, "(no data)");
        return;
    }

    if (max <= 0)
        max = getmaxy(w) - 10;

    // copy the table so we can sort it non destructively
    sorted_table = NULL;
    HASH_ITER(hh, table, entry, tmp_entry) {
        HASH_ADD(hh_srt, sorted_table, key, MAX_DNAME_LEN, entry);
    }

    HASH_SRT(hh_srt, sorted_table, sort_str_by_count);
    HASH_ITER(hh_srt, sorted_table, entry, tmp_entry) {
        if (strlen(entry->key) > max_len)
            max_len = strlen(entry->key);
        if (++i >= max)
            break;
    }
    i = 0;
    HASH_ITER(hh_srt, sorted_table, entry, tmp_entry) {
        mvprintw(++row, col, "%-*s %lu", max_len, strlen(entry->key) ? entry->key : "[empty]", entry->count);
        if (++i >= max)
            break;
    }
    HASH_CLEAR(hh_srt, sorted_table);

}

void pktvisor_ui_init(int interval) {
    w = initscr();
    cbreak();
    noecho();
    nodelay(w, 1);
    redraw_interval = interval;

    last_incoming = last_query = last_reply = 0;
    last_rate_ts.tv_sec = 0;
    last_rate_ts.tv_usec = 0;

    cur_target = SUMMARY_TABLE;
    signal(SIGALRM, gotsignalrm);
    redraw_itv.it_interval.tv_sec = redraw_interval;
    redraw_itv.it_interval.tv_usec = 0;
    redraw_itv.it_value.tv_sec = redraw_interval;
    redraw_itv.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &redraw_itv, NULL);
}

void redraw_header(struct dnsctxt *dns_ctxt) {

    double outgoing = (double)dns_ctxt->seen - (double)dns_ctxt->incoming;

    // rates
    uint64_t incoming_pps = 0, outgoing_pps = 0, query_pps = 0, reply_pps = 0;
    struct timeval time_now;
    double t_delta = 0;

    // see HEADER_SIZE def
    mvprintw(0, 0, "total  : %6lu, incming: %6lu, outgoing: %6lu, malformed: %6lu (%0.2f%%) | ?=help", //, EDNS: %6lu (%0.2f%%)",
             dns_ctxt->seen,
             dns_ctxt->incoming,
             (long)outgoing,
             dns_ctxt->cnt_malformed,
             ((double)dns_ctxt->cnt_malformed / (double)dns_ctxt->seen)*100,
             dns_ctxt->cnt_edns
             //,((double)dns_ctxt->cnt_edns / (double)dns_ctxt->seen)*100
             );

    mvprintw(1, 0, "Query  : %6lu, Reply  : %6lu | 1=q2, 2=q3, 3=src, 4=dst, 5=mal, 6=nx, 7=ref, 8=ports, 9=geo, 0=asn",
             dns_ctxt->cnt_query,
             dns_ctxt->cnt_reply);

    mvprintw(2, 0, "NOERROR: %6lu (%0.2f%%), SRVFAIL: %6lu (%0.2f%%), NXDOMAIN: %6lu (%0.2f%%), REFUSED: %6lu (%0.2f%%)",
             dns_ctxt->cnt_status_noerror,
             ((double)dns_ctxt->cnt_status_noerror / outgoing)*100,
             dns_ctxt->cnt_status_srvfail,
             ((double)dns_ctxt->cnt_status_srvfail / outgoing)*100,
             dns_ctxt->cnt_status_nxdomain,
             ((double)dns_ctxt->cnt_status_nxdomain / outgoing)*100,
             dns_ctxt->cnt_status_refused,
             ((double)dns_ctxt->cnt_status_refused / outgoing)*100);

    // calculate rates
    gettimeofday(&time_now, NULL);
    if (last_incoming > 0 && last_rate_ts.tv_sec > 0) {
        t_delta = ((double)time_now.tv_sec+(double)time_now.tv_usec/1000000) -
                         ((double)last_rate_ts.tv_sec+(double)last_rate_ts.tv_usec/1000000);
        incoming_pps = (uint64_t)((double)(dns_ctxt->incoming - last_incoming) / t_delta);
        outgoing_pps = (uint64_t)((double)(outgoing - last_outgoing) / t_delta);
        query_pps = (uint64_t)((double)(dns_ctxt->cnt_query - last_query) / t_delta);
        reply_pps = (uint64_t)((double)(dns_ctxt->cnt_reply - last_reply) / t_delta);
    }
    last_rate_ts.tv_sec = time_now.tv_sec;
    last_rate_ts.tv_usec = time_now.tv_usec;
    last_incoming = dns_ctxt->incoming;
    last_outgoing = outgoing;
    last_query = dns_ctxt->cnt_query;
    last_reply = dns_ctxt->cnt_reply;

    mvprintw(3, 0, "RATES  : incoming %lu | outgoing %lu | query %lu | reply %lu | pkts per %0.2fs",
             incoming_pps,
             outgoing_pps,
             query_pps,
             reply_pps,
             t_delta);

}

void redraw_summary(struct dnsctxt *dns_ctxt) {

    redraw_table_ip(dns_ctxt->source_table, "Top Source IPs", START_ROW, START_COL, 5);
    redraw_table_str(dns_ctxt->nxdomain_table, "NXDOMAIN Names", START_ROW, START_COL+27, 5);
    redraw_table_str(dns_ctxt->refused_table, "Refused Names", START_ROW, START_COL+65, 5);

    redraw_table_int(dns_ctxt->src_port_table, "Top Source Ports", START_ROW+7, START_COL, 5);
    redraw_table_str(dns_ctxt->query_name2_table, "Top Queries (2)", START_ROW+7, START_COL+27, 5);
    redraw_table_str(dns_ctxt->query_name3_table, "Top Queries (3)", START_ROW+7, START_COL+65, 5);

    redraw_table_str(dns_ctxt->geo_loc_table, "By GeoLocation", START_ROW+14, START_COL, 5);
    redraw_table_str(dns_ctxt->qtype_table, "By QType", START_ROW+14, START_COL+27, 5);
    redraw_table_str(dns_ctxt->geo_asn_table, "By ASN", START_ROW+14, START_COL+50, 5);

}

void redraw_help() {

    printw("\n\n");
    printw(" ? \t\tShow help\n");
    printw(" s \t\tShow summary screen\n");
    printw(" q \t\tShow top query types\n");
    printw(" 0 \t\tShow top ASNs\n");
    printw(" 1 \t\tShow top query domains (2 levels)\n");
    printw(" 2 \t\tShow top query domains (3 levels)\n");
    printw(" 3 \t\tShow top source IPs (from incoming pkts)\n");
    printw(" 4 \t\tShow top destination IPs (in outgoing pkts)\n");
    printw(" 5 \t\tShow top source IPs for malformed queries\n");
    printw(" 6 \t\tShow top NXDOMAINs\n");
    printw(" 7 \t\tShow top REFUSED\n");
    printw(" 8 \t\tShow top source ports\n");
    printw(" 9 \t\tShow top GeoIP\n");
}

void redraw(struct dnsctxt *dns_ctxt) {

    erase();

    redraw_header(dns_ctxt);

    switch (cur_target) {
    case SUMMARY_TABLE:
        redraw_summary(dns_ctxt);
        break;
    case QTYPE_TABLE:
        redraw_table_str(dns_ctxt->qtype_table, "Top Query Types", START_ROW, START_COL, FULL);
        break;
    case SOURCE_TABLE:
        redraw_table_ip(dns_ctxt->source_table, "Top Source IPs (Incoming)", START_ROW, START_COL, FULL);
        break;
    case DEST_TABLE:
        redraw_table_ip(dns_ctxt->dest_table, "Top Destination IPs (Outgoing)", START_ROW, START_COL, FULL);
        break;
    case MALFORMED_TABLE:
        redraw_table_ip(dns_ctxt->malformed_table, "Malformed Query Source IPs", START_ROW, START_COL, FULL);
        break;
    case NXDOMAIN_TABLE:
        redraw_table_str(dns_ctxt->nxdomain_table, "NXDOMAIN Names", START_ROW, START_COL, FULL);
        break;
    case REFUSED_TABLE:
        redraw_table_str(dns_ctxt->refused_table, "Refused Names", START_ROW, START_COL, FULL);
        break;
    case SRC_PORT_TABLE:
        redraw_table_int(dns_ctxt->src_port_table, "Top Source Ports", START_ROW, START_COL, FULL);
        break;
    case GEO_LOC_TABLE:
        redraw_table_str(dns_ctxt->geo_loc_table, "By Incoming GeoLocation", START_ROW, START_COL, FULL);
        break;
    case GEO_ASN_TABLE:
        redraw_table_str(dns_ctxt->geo_asn_table, "By Incoming ASN", START_ROW, START_COL, FULL);
        break;
    case QUERY2_TABLE:
        redraw_table_str(dns_ctxt->query_name2_table, "Top Queries (2)", START_ROW, START_COL, FULL);
        break;
    case HELP:
        redraw_help();
        break;
    case QUERY3_TABLE:
    default:
        redraw_table_str(dns_ctxt->query_name3_table, "Top Queries (3)", START_ROW, START_COL, FULL);
        break;
    }

    refresh();
    do_redraw = false;
}


int keyboard(struct dnsctxt *dns_ctxt) {

    int ch;
    bool no_key = false;

    ch = getch() & 0xff;
    if (ch == ERR) {
        return ERR;
    }
    if (ch >= 'A' && ch <= 'Z')
        ch += 'a' - 'A';
    switch (ch) {
    case '?':
        cur_target = HELP;
        break;
    case 's':
        cur_target = SUMMARY_TABLE;
        break;
    case 'q':
        cur_target = QTYPE_TABLE;
        break;
    case '1':
        cur_target = QUERY2_TABLE;
        break;
    case '2':
        cur_target = QUERY3_TABLE;
        break;
    case '3':
        cur_target = SOURCE_TABLE;
        break;
    case '4':
        cur_target = DEST_TABLE;
        break;
    case '5':
        cur_target = MALFORMED_TABLE;
        break;
    case '6':
        cur_target = NXDOMAIN_TABLE;
        break;
    case '7':
        cur_target = REFUSED_TABLE;
        break;
    case '9':
        cur_target = GEO_LOC_TABLE;
        break;
    case '0':
        cur_target = GEO_ASN_TABLE;
        break;
    case '8':
        cur_target = SRC_PORT_TABLE;
        break;
    default:
        no_key = true;
    }

    if (!no_key) {
        do_redraw = true;
        redraw(dns_ctxt);
    }

    return ch;

}

void pktvisor_ui(struct dnsctxt *dns_ctxt) {

    if (do_redraw || 0 == redraw_interval)
        redraw(dns_ctxt);

    keyboard(dns_ctxt);

}

void pktvisor_ui_waitforkey(struct dnsctxt *dns_ctxt) {
    redraw(dns_ctxt);
    mvprintw(getmaxy(w)-2, 0, "<hit q to continue>");
    refresh();
    while (keyboard(dns_ctxt) != 'q');
}

void pktvisor_ui_shutdown() {
    endwin();
}
