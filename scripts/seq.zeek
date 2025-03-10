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
        if (send$v_s != 0 || send$v_r != 0) {
            print fmt("  WEIRD: Sequence number mismatch: expected (Tx:%d, Rx:%d), got (Tx:%d, Rx:%d).  Adjusting.",
                      send$v_s, send$v_r, ssn, rsn);
        }
        send$v_r = rsn;
        send$v_s = ssn;

        if (recv$v_s == 0 && recv$v_r == 0) {
            # Freshly instantiated counters for an already-established
            # connection.
            recv$v_s = rsn;
            recv$v_r = ssn;
        }
    }

    send$v_s = (send$v_s + 1) % 0x8000;
    recv$v_r = (recv$v_r + 1) % 0x8000;
    recv$ack = rsn;
}

function check_rsn(cs: APDU_Counters, cr: APDU_Counters, rsn: count)
{
    if (rsn != cs$v_r) {
        print fmt("  WEIRD: S-Format packet with Rx counter %d, expected %d.",
                  rsn, cs$v_r);
        cs$v_r = rsn;
    }

    # XXX: Any other sanity checks?
    cr$ack = rsn;
}

event iec104::s
    (c: connection, is_orig: bool, rsn: count)
    &priority=-15
{
    if (is_orig) {
        check_rsn(c$orig_counters, c$resp_counters, rsn);
    } else {
        check_rsn(c$resp_counters, c$orig_counters, rsn);
    }
}

event iec104::i
    (c: connection, is_orig: bool, ssn: count, rsn: count)
    &priority=-15
{
    if (is_orig) {
        update_counters(c$orig_counters, c$resp_counters, ssn, rsn);
    } else {
        update_counters(c$resp_counters, c$orig_counters, ssn, rsn);
    }
}
