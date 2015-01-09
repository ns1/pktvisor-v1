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
    REFUSED_TABLE
};
int cur_target = QUERY3_TABLE;

void gotsignalrm(int sig) {
    do_redraw = 1;
    signal(sig, gotsignalrm);
}

void redraw_table_int(struct int32_entry *table, char *txt_hdr) {
    struct int32_entry *entry, *tmp_entry, *sorted_table;
    unsigned int i = 0;

    mvprintw(4, 0, "%s\n\n", txt_hdr);

    if (!table) {
        printw("(no data)");
        return;
    }

    // copy the table so we can sort it non destructively
    sorted_table = NULL;
    HASH_ITER(hh, table, entry, tmp_entry) {
        HASH_ADD(hh_srt, sorted_table, key, sizeof(uint32_t), entry);
    }

    HASH_SRT(hh_srt, sorted_table, sort_int_by_count);
    HASH_ITER(hh_srt, sorted_table, entry, tmp_entry) {
        printw("%6u %lu\n", entry->key, entry->count);
        if (++i > getmaxy(w) - 10)
            break;
    }
    HASH_CLEAR(hh_srt, sorted_table);

}

void redraw_table_ip(struct int32_entry *table, char *txt_hdr) {
    struct int32_entry *entry, *tmp_entry, *sorted_table;
    char ip[INET_ADDRSTRLEN];
    unsigned int i = 0;

    mvprintw(4, 0, "%s\n\n", txt_hdr);

    if (!table) {
        printw("(no data)");
        return;
    }

    // copy the table so we can sort it non destructively
    sorted_table = NULL;
    HASH_ITER(hh, table, entry, tmp_entry) {
        HASH_ADD(hh_srt, sorted_table, key, sizeof(uint32_t), entry);
    }

    HASH_SRT(hh_srt, sorted_table, sort_int_by_count);
    HASH_ITER(hh_srt, sorted_table, entry, tmp_entry) {
        inet_ntop(AF_INET, &entry->key, ip, sizeof(ip));
        printw("%16s %lu\n", ip, entry->count);
        if (++i > getmaxy(w) - 10)
            break;
    }
    HASH_CLEAR(hh_srt, sorted_table);

}

void redraw_table_str(struct str_entry *table, char *txt_hdr) {
    struct str_entry *entry, *tmp_entry, *sorted_table;
    unsigned int i = 0;
    int max_len = 0;

    mvprintw(4, 0, "%s\n\n", txt_hdr);
    if (!table) {
        printw("(no data)");
        return;
    }

    // copy the table so we can sort it non destructively
    sorted_table = NULL;
    HASH_ITER(hh, table, entry, tmp_entry) {
        if (strlen(entry->key) > max_len)
            max_len = strlen(entry->key);
        HASH_ADD(hh_srt, sorted_table, key, MAX_DNAME_LEN, entry);
    }

    HASH_SRT(hh_srt, sorted_table, sort_str_by_count);
    HASH_ITER(hh_srt, sorted_table, entry, tmp_entry) {
        printw("%-*s %lu\n", max_len, strlen(entry->key) ? entry->key : ".", entry->count);
        if (++i > getmaxy(w) - 10)
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

    cur_target = QUERY3_TABLE;
    signal(SIGALRM, gotsignalrm);
    redraw_itv.it_interval.tv_sec = redraw_interval;
    redraw_itv.it_interval.tv_usec = 0;
    redraw_itv.it_value.tv_sec = redraw_interval;
    redraw_itv.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &redraw_itv, NULL);
}

void redraw_header(struct dnsctxt *dns_ctxt) {

    // see HEADER_SIZE def
    mvprintw(0, 0, "total  : %6lu, incming: %6lu, outgoing: %6lu, malformed: %6lu (%0.2f%%), EDNS: %6lu (%0.2f%%)",
             dns_ctxt->seen,
             dns_ctxt->incoming,
             dns_ctxt->seen - dns_ctxt->incoming,
             dns_ctxt->cnt_malformed,
             ((double)dns_ctxt->cnt_malformed / (double)dns_ctxt->seen)*100,
             dns_ctxt->cnt_edns,
             ((double)dns_ctxt->cnt_edns / (double)dns_ctxt->seen)*100);

    mvprintw(1, 0, "Query  : %6lu, Reply  : %6lu | 1=query2, 2=query3, 3=src, 4=dest, 5=mal, 6=nx, 7=refused, 8=ports",
             dns_ctxt->cnt_query,
             dns_ctxt->cnt_reply);

    mvprintw(2, 0, "NOERROR: %6lu (%0.2f%%), SRVFAIL: %6lu (%0.2f%%), NXDOMAIN: %6lu (%0.2f%%), REFUSED: %6lu (%0.2f%%)",
             dns_ctxt->cnt_status_noerror,
             ((double)dns_ctxt->cnt_status_noerror / (double)dns_ctxt->seen)*100,
             dns_ctxt->cnt_status_srvfail,
             ((double)dns_ctxt->cnt_status_srvfail / (double)dns_ctxt->seen)*100,
             dns_ctxt->cnt_status_nxdomain,
             ((double)dns_ctxt->cnt_status_nxdomain / (double)dns_ctxt->seen)*100,
             dns_ctxt->cnt_status_refused,
             ((double)dns_ctxt->cnt_status_refused / (double)dns_ctxt->seen)*100);

}

void redraw(struct dnsctxt *dns_ctxt) {

    clear();

    redraw_header(dns_ctxt);

    switch (cur_target) {
    case SOURCE_TABLE:
        redraw_table_ip(dns_ctxt->source_table, "Top Source IPs");
        break;
    case DEST_TABLE:
        redraw_table_ip(dns_ctxt->dest_table, "Top Destination IPs");
        break;
    case MALFORMED_TABLE:
        redraw_table_ip(dns_ctxt->malformed_table, "Malformed Query Source IPs");
        break;
    case NXDOMAIN_TABLE:
        redraw_table_str(dns_ctxt->nxdomain_table, "NXDOMAIN Names");
        break;
    case REFUSED_TABLE:
        redraw_table_str(dns_ctxt->refused_table, "Refused Names");
        break;
    case SRC_PORT_TABLE:
        redraw_table_int(dns_ctxt->src_port_table, "Top Source Ports");
        break;
    case QUERY2_TABLE:
        redraw_table_str(dns_ctxt->query_name2_table, "Top Queries (2)");
        break;
    case QUERY3_TABLE:
    default:
        redraw_table_str(dns_ctxt->query_name3_table, "Top Queries (3)");
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
    case '1':
    case 'q':
        cur_target = QUERY2_TABLE;
        break;
    case '2':
    case 's':
        cur_target = QUERY3_TABLE;
        break;
    case '3':
    case 'd':
        cur_target = SOURCE_TABLE;
        break;
    case '4':
    case 'm':
        cur_target = DEST_TABLE;
        break;
    case '5':
    case 'w':
        cur_target = MALFORMED_TABLE;
        break;
    case '6':
    case 'n':
        cur_target = NXDOMAIN_TABLE;
        break;
    case '7':
    case 'r':
        cur_target = REFUSED_TABLE;
        break;
    case '8':
    case 'p':
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
    mvprintw(getmaxy(w)-2, 0, "<hit Q to continue>");
    redraw(dns_ctxt);
    while (keyboard(dns_ctxt) != 'q');
}

void pktvisor_ui_shutdown() {
    endwin();
}
