/*
 * Copyright 2015 NSONE, Inc.
 */

#include <sys/time.h>
#include <time.h>
#include <curses.h>
#include <stdio.h>
#include <signal.h>

#include "dnstopui.h"

WINDOW *w;
int redraw_interval;
bool do_redraw = true;
struct itimerval redraw_itv;

void gotsignalrm(int sig) {
    do_redraw = 1;
    signal(sig, gotsignalrm);
}

void dnstop_ui_init(int interval) {
    w = initscr();
    cbreak();
    noecho();
    nodelay(w, 1);
    redraw_interval = interval;

    signal(SIGALRM, gotsignalrm);
    redraw_itv.it_interval.tv_sec = redraw_interval;
    redraw_itv.it_interval.tv_usec = 0;
    redraw_itv.it_value.tv_sec = redraw_interval;
    redraw_itv.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &redraw_itv, NULL);
}

void redraw_header(struct dnsctxt *dns_ctxt) {

    mvprintw(0, 0, "total  : %6lu, incming: %6lu, outgoing: %6lu, malformed: %6lu (%0.2f%%), EDNS: %6lu (%0.2f%%)",
             dns_ctxt->seen,
             dns_ctxt->incoming,
             dns_ctxt->seen - dns_ctxt->incoming,
             dns_ctxt->cnt_malformed,
             ((double)dns_ctxt->cnt_malformed / (double)dns_ctxt->seen)*100,
             dns_ctxt->cnt_edns,
             ((double)dns_ctxt->cnt_edns / (double)dns_ctxt->seen)*100);

    mvprintw(1, 0, "Query  : %6lu, Reply  : %6lu",
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
    redraw_header(dns_ctxt);
    refresh();
    do_redraw = false;
}

void keyboard() {

}

void dnstop_ui(struct dnsctxt *dns_ctxt) {

    if (do_redraw || 0 == redraw_interval)
        redraw(dns_ctxt);

    keyboard();

}

void dnstop_ui_shutdown() {
    endwin();
}

//int do_redraw = 1;

//int interactive = 1;

//#ifdef HAVE_STRUCT_BPF_TIMEVAL
//struct bpf_timeval last_ts;
//#else
//struct timeval last_ts;
//#endif
//time_t report_interval = 1;

//void
//cron_pre(void) {
//    (void)0;
//}

//void
//cron_post(void) {
//    query_count_intvl = 0;
//    reply_count_intvl = 0;
//}

//void
//redraw() {
//    cron_pre();
//    report();
//    cron_post();
//    do_redraw = 0;
//}

//void
//keyboard(void) {
//    int ch;
//    int old_do_redraw = do_redraw;
//    do_redraw = 1;
//    ch = getch() & 0xff;
//    if (ch >= 'A' && ch <= 'Z')
//        ch += 'a' - 'A';
//    switch (ch) {
//    case 's':
//        SubReport = Sources_report;
//        break;
//    case 'd':
//        SubReport = Destinatioreport;
//        break;
//    case '1':
//    case '2':
//    case '3':
//    case '4':
//    case '5':
//    case '6':
//    case '7':
//    case '8':
//    case '9':
//        SubReport = Domain_report;
//        cur_level = ch - '0';
//        break;
//    case '!':
//        SubReport = DomSrc_report;
//        cur_level = 1;
//        break;
//    case 'c':
//    case '@':
//        SubReport = DomSrc_report;
//        cur_level = 2;
//        break;
//    case '#':
//        SubReport = DomSrc_report;
//        cur_level = 3;
//        break;
//    case '$':
//        SubReport = DomSrc_report;
//        cur_level = 4;
//        break;
//    case '%':
//        SubReport = DomSrc_report;
//        cur_level = 5;
//        break;
//    case '^':
//        SubReport = DomSrc_report;
//        cur_level = 6;
//        break;
//    case '&':
//        SubReport = DomSrc_report;
//        cur_level = 7;
//        break;
//    case '*':
//        SubReport = DomSrc_report;
//        cur_level = 8;
//        break;
//    case '(':
//        SubReport = DomSrc_report;
//        cur_level = 9;
//        break;
//    case 't':
//        SubReport = Qtypes_report;
//        break;
//    case 'o':
//        SubReport = Opcodes_report;
//        break;
//    case 'r':
//        SubReport = Rcodes_report;
//        break;
//    case 030:
//        Quit = 1;
//        break;
//    case 022:
//        ResetCounters();
//        break;
//    case '?':
//        SubReport = Help_report;
//        break;
//    case ' ':
//        /* noop - just redraw the screen */
//        break;
//    default:
//        do_redraw = old_do_redraw;
//        break;
//    }
//}

//void
//gotsigalrm(int sig) {
//    do_redraw = 1;
//    signal(sig, gotsigalrm);
//}

//void
//Help_report(void) {
//    print_func(" s - Sources list\n");
//    print_func(" d - Destinations list\n");
//    print_func(" t - Query types\n");
//    print_func(" o - Opcodes\n");
//    print_func(" r - Rcodes\n");
//    print_func(" 1 - 1st level Query Names"
//               "\t! - with Sources\n");
//    print_func(" 2 - 2nd level Query Names"
//               "\t@ - with Sources\n");
//    print_func(" 3 - 3rd level Query Names"
//               "\t# - with Sources\n");
//    print_func(" 4 - 4th level Query Names"
//               "\t$ - with Sources\n");
//    print_func(" 5 - 5th level Query Names"
//               "\t%% - with Sources\n");
//    print_func(" 6 - 6th level Query Names"
//               "\t^ - with Sources\n");
//    print_func(" 7 - 7th level Query Names"
//               "\t& - with Sources\n");
//    print_func(" 8 - 8th level Query Names"
//               "\t* - with Sources\n");
//    print_func(" 9 - 9th level Query Names"
//               "\t( - with Sources\n");
//    print_func("^R - Reset counters\n");
//    print_func("^X - Exit\n");
//    print_func("\n");
//    print_func(" ? - this\n");
//}


//char *
//rcode_str(unsigned int r) {
//    static char buf[30];
//    switch (r) {
//    case 0:
//        return "Noerror";
//        break;
//    case 1:
//        return "Formerr";
//        break;
//    case 2:
//        return "Servfail";
//        break;
//    case 3:
//        return "Nxdomain";
//        break;
//    case 4:
//        return "Notimpl";
//        break;
//    case 5:
//        return "Refused";
//        break;
//    case 6:
//        return "Yxdomain";
//        break;
//    case 7:
//        return "Yxrrset";
//        break;
//    case 8:
//        return "Nxrrset";
//        break;
//    case 9:
//        return "Notauth";
//        break;
//    case 10:
//        return "Notzone";
//        break;
//    default:
//        if (rcodes_buf[r])
//            return rcodes_buf[r];
//        snprintf(buf, 30, "Rcode%d", r);
//        return rcodes_buf[r] = strdup(buf);
//    }
//}

//int
//get_nlines(void) {
//    if (interactive)
//        return getmaxy(w) - 6;
//    else
//        return 50;
//}

//int
//get_ncols(void) {
//    if (interactive)
//        return getmaxx(w);
//    else
//        return 80;
//}

//const char *
//StringCounter_col_fmt(const SortItem * si) {
//    StringCounter *sc = si->ptr;
//    return sc->s;
//}

//const char *
//dashes(int n) {
//    static char *buf = "-----------------------------------------------"
//                       "-----------------------------------------------------------------"
//                       "-----------------------------------------------------------------"
//                       "-----------------------------------------------------------------"
//                       "-----------------------------------------------------------------"
//                       "-----------------------------------------------------------------";
//    return &buf[strlen(buf) - n];
//}

//void
//Table_report(SortItem * sorted, int rows, const char *col1, const char *col2, col_fmt F1, col_fmt F2, unsigned int base) {
//    int W1 = strlen(col1);
//    int W2 = col2 ? strlen(col2) : 0;
//    int WC = 9;			/* width of "Count" column */
//    int WP = 6;			/* width of "Percent" column */
//    int i;
//    int nlines = get_nlines();
//    int ncols = get_ncols();
//    char fmt1[64];
//    char fmt2[64];
//    unsigned int sum = 0;

//    if (nlines > rows)
//        nlines = rows;

//    for (i = 0; i < nlines; i++) {
//        const char *t = F1(sorted + i);
//        if (W1 < strlen(t))
//            W1 = strlen(t);
//    }
//    if (W1 + 1 + WC + 1 + WP + 1 + WP + 1 > ncols)
//        W1 = ncols - 1 - WC - 1 - WP - 1 - WP - 1;

//    if (NULL == col2 || NULL == F2) {
//        snprintf(fmt1, 64, "%%-%d.%ds %%%ds %%%ds %%%ds\n", W1, W1, WC, WP, WP);
//        snprintf(fmt2, 64, "%%-%d.%ds %%%dd %%%d.1f %%%d.1f\n", W1, W1, WC, WP, WP);
//        print_func(fmt1, col1, "Count", "%", "cum%");
//        print_func(fmt1, dashes(W1), dashes(WC), dashes(WP), dashes(WP));
//        for (i = 0; i < nlines; i++) {
//            sum += (sorted + i)->cnt;
//            const char *t = F1(sorted + i);
//            print_func(fmt2,
//                       t,
//                       (sorted + i)->cnt,
//                       100.0 * (sorted + i)->cnt / base,
//                       100.0 * sum / base);
//        }
//    } else {
//        for (i = 0; i < nlines; i++) {
//            const char *t = F2(sorted + i);
//            if (W2 < strlen(t))
//                W2 = strlen(t);
//        }
//        if (W2 + 1 + W1 + 1 + WC + 1 + WP + 1 + WP + 1 > ncols)
//            W2 = ncols - 1 - W1 - 1 - WC - 1 - WP - 1 - WP - 1;
//        snprintf(fmt1, 64, "%%-%d.%ds %%-%d.%ds %%%ds %%%ds %%%ds\n", W1, W1, W2, W2, WC, WP, WP);
//        snprintf(fmt2, 64, "%%-%d.%ds %%-%d.%ds %%%dd %%%d.1f %%%d.1f\n", W1, W1, W2, W2, WC, WP, WP);
//        print_func(fmt1, col1, col2, "Count", "%", "cum%");
//        print_func(fmt1, dashes(W1), dashes(W2), dashes(WC), dashes(WP), dashes(WP));
//        for (i = 0; i < nlines; i++) {
//            const char *t = F1(sorted + i);
//            const char *q = F2(sorted + i);
//            sum += (sorted + i)->cnt;
//            print_func(fmt2,
//                       t,
//                       q,
//                       (sorted + i)->cnt,
//                       100.0 * (sorted + i)->cnt / base,
//                       100.0 * sum / base);
//        }
//    }
//}

//void
//StringCounter_report(hashtbl * tbl, char *what) {
//    unsigned int sum = 0;
//    int sortsize = hash_count(tbl);
//    SortItem *sortme = calloc(sortsize, sizeof(SortItem));
//    StringCounter *sc;
//    hash_iter_init(tbl);
//    sortsize = 0;
//    while ((sc = hash_iterate(tbl))) {
//        sum += sc->count;
//        sortme[sortsize].cnt = sc->count;
//        sortme[sortsize].ptr = sc;
//        sortsize++;
//    }
//    qsort(sortme, sortsize, sizeof(SortItem), SortItem_cmp);
//    Table_report(sortme, sortsize,
//                 what, NULL,
//                 StringCounter_col_fmt, NULL,
//                 sum);
//    free(sortme);
//}

//void
//StringAddrCounter_free(void *p) {
//    StringAddrCounter *ssc = p;
//    free(ssc->straddr.str);
//}

//void
//Domain_report(void) {
//    if (cur_level > max_level) {
//        print_func("\tYou must start %s with -l %d\n", progname, cur_level);
//        print_func("\tto collect this level of domain stats.\n", progname);
//        return;
//    }
//    StringCounter_report(Domains[cur_level], "Query Name");
//}

//const char *
//Qtype_col_fmt(const SortItem * si) {
//    return si->ptr;
//}

//void
//Simple_report(unsigned int a[], unsigned int max, const char *name, strify * to_str) {
//    unsigned int i;
//    unsigned int sum = 0;
//    unsigned int sortsize = 0;
//    SortItem *sortme = calloc(max, sizeof(SortItem));
//    for (i = 0; i < max; i++) {
//        if (0 == a[i])
//            continue;
//        sum += a[i];
//        sortme[sortsize].cnt = a[i];
//        sortme[sortsize].ptr = to_str(i);
//        sortsize++;
//    }
//    qsort(sortme, sortsize, sizeof(SortItem), SortItem_cmp);
//    Table_report(sortme, sortsize,
//                 name, NULL,
//                 Qtype_col_fmt, NULL,
//                 sum);
//    free(sortme);
//}

//void
//Qtypes_report(void) {
//    Simple_report(qtype_counts, T_MAX, "Query Type", qtype_str);
//}

//void
//Opcodes_report(void) {
//    Simple_report(opcode_counts, OP_MAX, "Opcode", opcode_str);
//}

//void
//Rcodes_report(void) {
//    Simple_report(rcode_counts, RC_MAX, "Rcode", rcode_str);
//}

//const char *
//AgentAddr_col_fmt(const SortItem * si) {
//    AgentAddr *a = si->ptr;
//    return anon_inet_ntoa(&a->src);
//}

//void
//AgentAddr_report(hashtbl * tbl, const char *what) {
//    unsigned int sum = 0;
//    int sortsize = hash_count(tbl);
//    SortItem *sortme = calloc(sortsize, sizeof(SortItem));
//    AgentAddr *a;
//    hash_iter_init(tbl);
//    sortsize = 0;
//    while ((a = hash_iterate(tbl))) {
//        sum += a->count;
//        sortme[sortsize].cnt = a->count;
//        sortme[sortsize].ptr = a;
//        sortsize++;
//    }
//    qsort(sortme, sortsize, sizeof(SortItem), SortItem_cmp);
//    Table_report(sortme, sortsize,
//                 what, NULL,
//                 AgentAddr_col_fmt, NULL,
//                 sum);
//    free(sortme);
//}

//const char *
//StringAddr_col1_fmt(const SortItem * si) {
//    StringAddrCounter *ssc = si->ptr;
//    return anon_inet_ntoa(&ssc->straddr.addr);
//}

//const char *
//StringAddr_col2_fmt(const SortItem * si) {
//    StringAddrCounter *ssc = si->ptr;
//    return ssc->straddr.str;
//}



//void
//StringAddrCounter_report(hashtbl * tbl, char *what1, char *what2) {
//    unsigned int sum = 0;
//    int sortsize = hash_count(tbl);
//    SortItem *sortme = calloc(sortsize, sizeof(SortItem));
//    StringAddrCounter *ssc;
//    hash_iter_init(tbl);
//    sortsize = 0;
//    while ((ssc = hash_iterate(tbl))) {
//        sum += ssc->count;
//        sortme[sortsize].cnt = ssc->count;
//        sortme[sortsize].ptr = ssc;
//        sortsize++;
//    }
//    qsort(sortme, sortsize, sizeof(SortItem), SortItem_cmp);
//    Table_report(sortme, sortsize,
//                 what1, what2,
//                 StringAddr_col1_fmt, StringAddr_col2_fmt,
//                 sum);
//    free(sortme);
//}

//void
//DomSrc_report(void) {
//    if (0 == opt_count_domsrc) {
//        print_func("\tReport disabled\n");
//        return;
//    }
//    if (cur_level > max_level) {
//        print_func("\tYou must start %s with -l %d\n", progname, cur_level);
//        print_func("\tto collect this level of domain stats.\n", progname);
//        return;
//    }
//    StringAddrCounter_report(DomSrcs[cur_level], "Source", "Query Name");
//}


//void
//Sources_report(void) {
//    AgentAddr_report(Sources, "Sources");
//}

//void
//Destinatioreport(void) {
//    AgentAddr_report(Destinations, "Destinations");
//}

//void
//report(void) {
//    int Y = 0;
//    time_t t;
//    move(Y, 0);
//    if (opt_count_queries) {
//        print_func("Queries: %u new, %u total",
//                   query_count_intvl, query_count_total);
//        if (Got_EOF)
//            print_func(", EOF");
//        clrtoeol();
//        Y++;
//    }
//    if (opt_count_replies) {
//        move(Y, 0);
//        print_func("Replies: %u new, %u total",
//                   reply_count_intvl, reply_count_total);
//        if (Got_EOF)
//            print_func(", EOF");
//        clrtoeol();
//        Y++;
//    }
//    t = time(NULL);
//    move(0, get_ncols() - 25);
//    print_func("%s", ctime(&t));
//    move(Y + 1, 0);
//    clrtobot();
//    if (SubReport)
//        SubReport();
//    refresh();
//}


//void
//init_curses(void) {
//    w = initscr();
//    cbreak();
//    noecho();
//    nodelay(w, 1);
//}

//void
//ResetCounters(void) {
//    int lvl;
//    if (NULL == Sources)
//        Sources = hash_create(hash_buckets, my_inXaddr_hash, my_inXaddr_cmp);
//    if (NULL == Destinations)
//        Destinations = hash_create(hash_buckets, my_inXaddr_hash, my_inXaddr_cmp);
//    for (lvl = 1; lvl <= max_level; lvl++) {
//        if (NULL != Domains[lvl])
//            continue;
//        Domains[lvl] = hash_create(hash_buckets, string_hash, string_cmp);
//        if (opt_count_domsrc)
//            DomSrcs[lvl] = hash_create(hash_buckets, stringaddr_hash, stringaddr_cmp);
//    }
//    query_count_intvl = 0;
//    query_count_total = 0;
//    reply_count_intvl = 0;
//    reply_count_total = 0;
//    memset(qtype_counts, 0, sizeof(qtype_counts));
//    memset(qclass_counts, 0, sizeof(qclass_counts));
//    memset(opcode_counts, 0, sizeof(opcode_counts));
//    memset(rcode_counts, 0, sizeof(rcode_counts));
//    hash_free(Sources, free);
//    hash_free(Destinations, free);
//    for (lvl = 1; lvl <= max_level; lvl++) {
//        hash_free(Domains[lvl], free);
//        if (opt_count_domsrc)
//            hash_free(DomSrcs[lvl], StringAddrCounter_free);
//    }
//    memset(&last_ts, '\0', sizeof(last_ts));
//}


//struct timeval start = {0, 0};
//struct timeval now = {0, 0};
//struct timeval last_progress = {0, 0};

//void
//progress(pcap_t * p) {
//    unsigned int msgs = query_count_total + reply_count_total;
//    gettimeofday(&now, NULL);
//    if (now.tv_sec == last_progress.tv_sec)
//        return;
//    time_t wall_elapsed = now.tv_sec - start.tv_sec;
//    if (0 == wall_elapsed)
//        return;
//    double rate = (double)msgs / wall_elapsed;
//    fprintf(stderr, "%u %7.1f m/s\n", msgs, rate);
//    last_progress = now;
//}

//int
//ui_main(int argc, char *argv[]) {
//    int redraw_interval = 1;
//    struct itimerval redraw_itv;

//    SubReport = Sources_report;
//    progname = strdup(strrchr(argv[0], '/') ? strchr(argv[0], '/') + 1 : argv[0]);
//    srandom(time(NULL));

//    ResetCounters();
//    gettimeofday(&start, NULL);

//    if (interactive) {
//        init_curses();
//        redraw();

//        if (redraw_interval) {
//            signal(SIGALRM, gotsigalrm);
//            redraw_itv.it_interval.tv_sec = redraw_interval;
//            redraw_itv.it_interval.tv_usec = 0;
//            redraw_itv.it_value.tv_sec = redraw_interval;
//            redraw_itv.it_value.tv_usec = 0;
//            setitimer(ITIMER_REAL, &redraw_itv, NULL);
//        }
//        while (0 == Quit) {
//            if (0 == x && 1 == readfile_state) {
//                /* block on keyboard until user quits */
//                readfile_state++;
//                nodelay(w, 0);
//                do_redraw = 1;
//                Got_EOF = 1;
//            }
//            if (do_redraw || 0 == redraw_interval)
//                redraw();
//            keyboard();
//        }
//        endwin();		/* klin, Thu Nov 28 08:56:51 2002 */
//    }

//    return 0;
//}
