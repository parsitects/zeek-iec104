module iec104;

type APDU_Counters: record {
    v_s: count &default=0;
    v_r: count &default=0;
    ack: count &default=0;
};

redef record connection += {
    orig_counters: APDU_Counters &default=APDU_Counters();
    resp_counters: APDU_Counters &default=APDU_Counters();
};

function update_counters(send: APDU_Counters, recv: APDU_Counters, ssn: count, rsn: count)
{
    if (send$v_s != ssn || send$v_r != rsn) {
        print fmt("  WEIRD: Sequence number mismatch: expected (Tx:%d, Rx:%d), got (Tx:%d, Rx:%d).  Adjusting.",
                  send$v_s, send$v_r, ssn, rsn);
        send$v_r = rsn;
        send$v_s = ssn;
    }

    send$v_s += 1;
    recv$v_r += 1;
    recv$ack = rsn;
}

function check_rsn(cs: APDU_Counters, cr: APDU_Counters, rsn: count)
{
    if (rsn < cs$v_r) {
        print fmt("  WEIRD: S-Format packet with Rx counter %d, %d already seen.",
                  rsn, cs$v_r);
    }

    # XXX: Any other sanity checks?
    cr$ack = rsn;
}

event iec104::s(c: connection, is_orig: bool, rsn: count) &priority=-10
{
    print "  SEQ: ORIG", c$orig_counters, "RESP", c$resp_counters;
    if (is_orig) {
        check_rsn(c$orig_counters, c$resp_counters, rsn);
    } else {
        check_rsn(c$resp_counters, c$orig_counters, rsn);
    }
}

event iec104::i(c: connection, is_orig: bool, ssn: count, rsn: count)
{
    if (is_orig) {
        update_counters(c$orig_counters, c$resp_counters, ssn, rsn);
    } else {
        update_counters(c$resp_counters, c$orig_counters, ssn, rsn);
    }
}
