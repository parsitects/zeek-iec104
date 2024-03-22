module iec104;

global type_i_counter = 0;
global type_s_counter = 0;
global type_u_counter = 0;
global apdu_len = 0;
global apci_type = "";
# global apci_tx: count &log;
# global apci_rx: count &log;
global begin_time: time;
global total_time: interval;

export {
    ## Log stream identifier.
    redef enum Log::ID += {
        LOG_ASDU_IDENT,
        LOG_M_SP_NA_1,
        LOG_M_SP_TA_1,
        LOG_M_DP_NA_1,
        LOG_M_DP_TA_1,
        LOG_M_ST_NA_1,
        LOG_M_ST_TA_1,
        LOG_M_BO_NA_1,
        LOG_M_BO_TA_1,
        LOG_M_ME_NA_1,
        LOG_M_ME_TA_1,
        LOG_M_ME_NB_1,
        LOG_M_ME_TB_1,
        LOG_M_ME_NC_1,
        LOG_M_ME_TC_1,
        LOG_M_SP_TB_1,
        LOG_M_DP_TB_1,
        LOG_M_ST_TB_1,
        LOG_M_BO_TB_1,
        LOG_M_ME_TD_1,
        LOG_M_ME_TE_1,
        LOG_M_ME_TF_1,
        LOG_C_SC_NA_1,
        LOG_C_DC_NA_1,
        LOG_C_RC_NA_1,
        LOG_C_SE_NA_1,
        LOG_C_SE_NB_1,
        LOG_C_SE_NC_1,
        LOG_C_BO_NA_1,
        LOG_C_SC_TA_1,
        LOG_C_DC_TA_1,
        LOG_C_RC_TA_1,
        LOG_C_SE_TA_1,
        LOG_C_SE_TC_1,
        LOG_C_BO_TA_1,
        LOG_M_EI_NA_1,
        LOG_C_IC_NA_1,
        LOG_C_RD_NA_1,
        LOG_C_RP_NA_1,
        LOG_APCI_U,
        LOG_APCI_S,
        LOG_SVA_QOS,
        LOG_DIQ_CP56Time2a,
        LOG_DIQ_CP24Time2a,
        LOG_UNK,
    };

    type SIQ: record {
        spi: bool &log;
        bl: bool &log;
        sb: bool &log;
        nt: bool &log;
        iv: bool &log;
    };

    type DIQ: record {
        dpi: count &log;
        bl: bool &log;
        sb: bool &log;
        nt: bool &log;
        iv: bool &log;
    };

    type M_SP_NA_1_io: record {
        obj_addr: count &log;
        siq: SIQ &log;
    };

    type M_SP_NA_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: M_SP_NA_1_io &log;
    };

    type CP24Time2a: record {
        ms: count &log;
        minute: count &log;
    };

    type M_SP_TA_1_io: record {
        obj_addr: count &log;
        siq: SIQ &log;
        tt: CP24Time2a &log;
    };

    type M_SP_TA_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: M_SP_TA_1_io &log;
    };

    type M_DP_NA_1_io: record {
        obj_addr: count &log;
        diq: DIQ &log;
    };

    type M_DP_NA_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: M_DP_NA_1_io &log;
    };

    type M_DP_TA_1_io: record {
        obj_addr: count &log;
        diq: DIQ &log;
        tt: CP24Time2a &log;
    };

    type M_DP_TA_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: M_DP_TA_1_io &log;
    };

    type QDS: record {
        ov: bool &log;
        bl: bool &log;
        sb: bool &log;
        nt: bool &log;
        iv: bool &log;
    };

    type M_ST_NA_1_io: record {
        obj_addr: count &log;
        vti: count &log;
        qds: QDS &log;
    };

    type M_ST_NA_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: M_ST_NA_1_io &log;
    };

    type M_ST_TA_1_io: record {
        obj_addr: count &log;
        vti: count &log;
        qds: QDS &log;
        tt: CP24Time2a &log;
    };

    type M_ST_TA_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: M_ST_TA_1_io &log;
    };

    type M_BO_NA_1_io: record {
        obj_addr: count &log;
        bsi: count &log;
        qds: QDS &log;
    };

    type M_BO_NA_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: M_BO_NA_1_io &log;
    };

    type M_BO_TA_1_io: record {
        obj_addr: count &log;
        bsi: count &log;
        qds: QDS &log;
        tt: CP24Time2a;
    };

    type M_BO_TA_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: M_BO_TA_1_io &log;
    };

    type M_ME_NA_1_io: record {
        obj_addr: count &log;
        nva: count &log;
        qds: QDS &log;
    };

    type M_ME_NA_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: M_ME_NA_1_io &log;
    };

    type M_ME_TA_1_io: record {
        obj_addr: count &log;
        nva: count &log;
        qds: QDS &log;
        tt: CP24Time2a &log;
    };

    type M_ME_TA_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: M_ME_TA_1_io &log;
    };

    type M_ME_NB_1_io: record {
        obj_addr: count &log;
        sva: count &log;
        qds: QDS &log;
    };

    type M_ME_NB_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: M_ME_NB_1_io &log;
    };

    type M_ME_TB_1_io: record {
        obj_addr: count &log;
        sva: count &log;
        qds: QDS &log;
        tt: CP24Time2a;
    };

    type M_ME_TB_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: M_ME_TB_1_io &log;
    };

    type M_ME_NC_1_io: record {
        obj_addr: count &log;
        r32: double &log;
        qds: QDS &log;
    };

    type M_ME_NC_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: M_ME_NC_1_io &log;
    };

    type M_ME_TC_1_io: record {
        obj_addr: count &log;
        r32: double &log;
        qds: QDS &log;
        tt: CP24Time2a;
    };

    type M_ME_TC_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: M_ME_TC_1_io &log;
    };

    type CP56Time2a: record {
        ms: count &log;
        minute: count &log;
        iv: bool &log;
        hour: count &log;
        su: bool &log;
        day: count &log;
        dow: count &log;
        month: count &log;
        year: count &log;
    };

    type M_SP_TB_1_io: record {
        obj_addr: count &log;
        siq: SIQ &log;
        tt: CP56Time2a &log;
    };

    type M_SP_TB_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: M_SP_TB_1_io &log;
    };

    type M_DP_TB_1_io: record {
        obj_addr: count &log;
        diq: DIQ &log;
        tt: CP56Time2a &log;
    };

    type M_DP_TB_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: M_DP_TB_1_io &log;
    };

    type M_ST_TB_1_io: record {
        obj_addr: count &log;
        vti: count &log;
        qds: QDS &log;
        tt: CP56Time2a &log;
    };

    type M_ST_TB_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: M_ST_TB_1_io &log;
    };

    type M_BO_TB_1_io: record {
        obj_addr: count &log;
        bsi: count &log;
        qds: QDS &log;
        tt: CP56Time2a;
    };

    type M_BO_TB_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: M_BO_TB_1_io &log;
    };

    type M_ME_TD_1_io: record {
        obj_addr: count &log;
        nva: count &log;
        qds: QDS &log;
        tt: CP56Time2a &log;
    };

    type M_ME_TD_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: M_ME_TD_1_io &log;
    };

    type M_ME_TE_1_io: record {
        obj_addr: count &log;
        sva: count &log;
        qds: QDS &log;
        tt: CP56Time2a &log;
    };

    type M_ME_TE_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: M_ME_TE_1_io &log;
    };

    type M_ME_TF_1_io: record {
        obj_addr: count &log;
        r32: double &log;
        qds: QDS &log;
        tt: CP56Time2a &log;
    };

    type M_ME_TF_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: M_ME_TF_1_io &log;
    };

    type SCO: record {
        scs: bool &log;
        qu: count &log;
        se: bool &log;
    };

    type C_SC_NA_1_io: record {
        obj_addr: count &log;
        sco: SCO &log;
    };

    type C_SC_NA_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: C_SC_NA_1_io &log;
    };

    type DCO: record {
        dcs: count &log;
        qu: count &log;
        se: bool &log;
    };

    type C_DC_NA_1_io: record {
        obj_addr: count &log;
        sco: DCO &log;
    };

    type C_DC_NA_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: C_DC_NA_1_io &log;
    };

    type RCO: record {
        rcs: count &log;
        qu: count &log;
        se: bool &log;
    };

    type C_RC_NA_1_io: record {
        obj_addr: count &log;
        sco: RCO &log;
    };

    type C_RC_NA_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: C_RC_NA_1_io &log;
    };

    type QOS: record {
        ql: count &log;
        se: bool &log;
    };

    type C_SE_NA_1_io: record {
        obj_addr: count &log;
        nva: count &log;
        qos: QOS &log;
    };

    type C_SE_NA_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: C_SE_NA_1_io &log;
    };

    type C_SE_NB_1_io: record {
        obj_addr: count &log;
        sva: count &log;
        qos: QOS &log;
    };

    type C_SE_NB_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: C_SE_NB_1_io &log;
    };

    type C_SE_NC_1_io: record {
        obj_addr: count &log;
        r32: double &log;
        qos: QOS &log;
    };

    type C_SE_NC_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: C_SE_NC_1_io &log;
    };

    type C_BO_NA_1_io: record {
        obj_addr: count &log;
        bsi: count &log;
    };

    type C_BO_NA_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: C_BO_NA_1_io &log;
    };

    type C_SC_TA_1_io: record {
        obj_addr: count &log;
        sco: SCO &log;
        tt: CP56Time2a &log;
    };

    type C_SC_TA_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: C_SC_TA_1_io &log;
    };

    type C_DC_TA_1_io: record {
        obj_addr: count &log;
        sco: DCO &log;
        tt: CP56Time2a &log;
    };

    type C_DC_TA_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: C_DC_TA_1_io &log;
    };

    type C_RC_TA_1_io: record {
        obj_addr: count &log;
        rco: RCO &log;
        tt: CP56Time2a &log;
    };

    type C_RC_TA_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: C_RC_TA_1_io &log;
    };

    type C_SE_TA_1_io: record {
        obj_addr: count &log;
        nva: count &log;
        qos: QOS &log;
        tt: CP56Time2a &log;
    };

    type C_SE_TA_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: C_SE_TA_1_io &log;
    };

    type C_SE_TC_1_io: record {
        obj_addr: count &log;
        r32: double &log;
        qos: QOS &log;
        tt: CP56Time2a &log;
    };

    type C_SE_TC_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: C_SE_TC_1_io &log;
    };

    type C_BO_TA_1_io: record {
        obj_addr: count &log;
        bsi: count &log;
        tt: CP56Time2a &log;
    };

    type C_BO_TA_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: C_BO_TA_1_io &log;
    };

    type M_EI_NA_1_io: record {
        obj_addr: count &log;
        coi: count &log;
        lpc: bool &log;
    };

    type M_EI_NA_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: M_EI_NA_1_io &log;
    };

    type C_IC_NA_1_io: record {
        obj_addr: count &log;
        qoi: count &log;
    };

    type C_IC_NA_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: C_IC_NA_1_io &log;
    };

    type C_RD_NA_1_io: record {
        obj_addr: count &log;
    };

    type C_RD_NA_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: C_RD_NA_1_io &log;
    };

    type C_RP_NA_1_io: record {
        obj_addr: count &log;
        qrp: count &log;
    };

    type C_RP_NA_1_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        io: C_RP_NA_1_io &log;
    };

    type AsduIdent: record {
        type_id: TypeID &log;
        nobj: count &log;
        sq: bool &log;
        cot: COT &log;
        pn: bool &log;
        test: bool &log;
        originator_address: count &log;
        common_address: count &log;
    };

    type AsduIdent_log: record {
        ts: time &log;
        uid: string &log;
        is_orig: bool &log;
        ident: AsduIdent &log;
    };

    type APCI_S: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        is_orig: bool &log;
        rsn: count &log;
    };

    type APCI_U: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        is_orig: bool &log;
        startdt: count &log;
        stopdt: count &log;
        testfr: count &log;
    };

    type UNK: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        is_orig: bool &log;
        type_id: TypeID &log;
        data: string &log;
    };
}

const ports = {
    2404/tcp
};

redef likely_server_ports += { ports };

event zeek_init() &priority=5
{
    Log::create_stream(iec104::LOG_ASDU_IDENT, [$columns=AsduIdent_log, $path="iec104-asdu-ident"]);
    Log::create_stream(iec104::LOG_M_SP_NA_1, [$columns=M_SP_NA_1_log, $path="iec104-M_SP_NA_1"]);
    Log::create_stream(iec104::LOG_M_SP_TA_1, [$columns=M_SP_TA_1_log, $path="iec104-M_SP_TA_1"]);
    Log::create_stream(iec104::LOG_M_DP_NA_1, [$columns=M_DP_NA_1_log, $path="iec104-M_DP_NA_1"]);
    Log::create_stream(iec104::LOG_M_DP_TA_1, [$columns=M_DP_TA_1_log, $path="iec104-M_DP_TA_1"]);
    Log::create_stream(iec104::LOG_M_ST_NA_1, [$columns=M_ST_NA_1_log, $path="iec104-M_ST_NA_1"]);
    Log::create_stream(iec104::LOG_M_ST_TA_1, [$columns=M_ST_TA_1_log, $path="iec104-M_ST_TA_1"]);
    Log::create_stream(iec104::LOG_M_BO_NA_1, [$columns=M_BO_NA_1_log, $path="iec104-M_BO_NA_1"]);
    Log::create_stream(iec104::LOG_M_BO_TA_1, [$columns=M_BO_TA_1_log, $path="iec104-M_BO_TA_1"]);
    Log::create_stream(iec104::LOG_M_ME_NA_1, [$columns=M_ME_NA_1_log, $path="iec104-M_ME_NA_1"]);
    Log::create_stream(iec104::LOG_M_ME_TA_1, [$columns=M_ME_TA_1_log, $path="iec104-M_ME_TA_1"]);
    Log::create_stream(iec104::LOG_M_ME_NB_1, [$columns=M_ME_NB_1_log, $path="iec104-M_ME_NB_1"]);
    Log::create_stream(iec104::LOG_M_ME_TB_1, [$columns=M_ME_TB_1_log, $path="iec104-M_ME_TB_1"]);
    Log::create_stream(iec104::LOG_M_ME_NC_1, [$columns=M_ME_NC_1_log, $path="iec104-M_ME_NC_1"]);
    Log::create_stream(iec104::LOG_M_ME_TC_1, [$columns=M_ME_TC_1_log, $path="iec104-M_ME_TC_1"]);
    Log::create_stream(iec104::LOG_M_SP_TB_1, [$columns=M_SP_TB_1_log, $path="iec104-M_SP_TB_1"]);
    Log::create_stream(iec104::LOG_M_DP_TB_1, [$columns=M_DP_TB_1_log, $path="iec104-M_DP_TB_1"]);
    Log::create_stream(iec104::LOG_M_ST_TB_1, [$columns=M_ST_TB_1_log, $path="iec104-M_ST_TB_1"]);
    Log::create_stream(iec104::LOG_M_BO_TB_1, [$columns=M_BO_TB_1_log, $path="iec104-M_BO_TB_1"]);
    Log::create_stream(iec104::LOG_M_ME_TD_1, [$columns=M_ME_TD_1_log, $path="iec104-M_ME_TD_1"]);
    Log::create_stream(iec104::LOG_M_ME_TE_1, [$columns=M_ME_TE_1_log, $path="iec104-M_ME_TE_1"]);
    Log::create_stream(iec104::LOG_M_ME_TF_1, [$columns=M_ME_TF_1_log, $path="iec104-M_ME_TF_1"]);
    Log::create_stream(iec104::LOG_C_SC_NA_1, [$columns=C_SC_NA_1_log, $path="iec104-C_SC_NA_1"]);
    Log::create_stream(iec104::LOG_C_DC_NA_1, [$columns=C_DC_NA_1_log, $path="iec104-C_DC_NA_1"]);
    Log::create_stream(iec104::LOG_C_RC_NA_1, [$columns=C_RC_NA_1_log, $path="iec104-C_RC_NA_1"]);
    Log::create_stream(iec104::LOG_C_SE_NA_1, [$columns=C_SE_NA_1_log, $path="iec104-C_SE_NA_1"]);
    Log::create_stream(iec104::LOG_C_SE_NB_1, [$columns=C_SE_NB_1_log, $path="iec104-C_SE_NB_1"]);
    Log::create_stream(iec104::LOG_C_SE_NC_1, [$columns=C_SE_NC_1_log, $path="iec104-C_SE_NC_1"]);
    Log::create_stream(iec104::LOG_C_BO_NA_1, [$columns=C_BO_NA_1_log, $path="iec104-C_BO_NA_1"]);
    Log::create_stream(iec104::LOG_C_SC_TA_1, [$columns=C_SC_TA_1_log, $path="iec104-C_SC_TA_1"]);
    Log::create_stream(iec104::LOG_C_DC_TA_1, [$columns=C_DC_TA_1_log, $path="iec104-C_DC_TA_1"]);
    Log::create_stream(iec104::LOG_C_RC_TA_1, [$columns=C_RC_TA_1_log, $path="iec104-C_RC_TA_1"]);
    Log::create_stream(iec104::LOG_C_SE_TA_1, [$columns=C_SE_TA_1_log, $path="iec104-C_SE_TA_1"]);
    Log::create_stream(iec104::LOG_C_SE_TC_1, [$columns=C_SE_TC_1_log, $path="iec104-C_SE_TC_1"]);
    Log::create_stream(iec104::LOG_C_BO_TA_1, [$columns=C_BO_TA_1_log, $path="iec104-C_BO_TA_1"]);
    Log::create_stream(iec104::LOG_M_EI_NA_1, [$columns=M_EI_NA_1_log, $path="iec104-M_EI_NA_1"]);
    Log::create_stream(iec104::LOG_C_IC_NA_1, [$columns=C_IC_NA_1_log, $path="iec104-C_IC_NA_1"]);
    Log::create_stream(iec104::LOG_C_RD_NA_1, [$columns=C_RD_NA_1_log, $path="iec104-C_RD_NA_1"]);
    Log::create_stream(iec104::LOG_C_RP_NA_1, [$columns=C_RP_NA_1_log, $path="iec104-C_RP_NA_1"]);
    Log::create_stream(iec104::LOG_APCI_U, [$columns=APCI_U, $path="iec104-apci_u"]);
    Log::create_stream(iec104::LOG_APCI_S, [$columns=APCI_S, $path="iec104-apci_s"]);
    Log::create_stream(iec104::LOG_UNK, [$columns=UNK, $path="iec104-unk"]);
}

event iec104::s(c: connection, is_orig: bool, rsn: count)
{
    local rec = APCI_S($ts=current_event_time(),
                       $uid=c$uid,
                       $id=c$id,
                       $is_orig=is_orig,
                       $rsn=rsn);
    Log::write(iec104::LOG_APCI_S, rec);
}

event iec104::u(c: connection, is_orig: bool, startdt: count, stopdt: count, testfr: count)
{
    local rec = APCI_U($ts=current_event_time(),
                       $uid=c$uid,
                       $id=c$id,
                       $is_orig=is_orig,
                       $startdt=startdt,
                       $stopdt=stopdt,
                       $testfr=testfr);
    Log::write(iec104::LOG_APCI_U, rec);
}

event iec104::asdu(c: connection, is_orig: bool, ident: AsduIdent)
{
    local rec = AsduIdent_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $ident=ident);
    Log::write(iec104::LOG_ASDU_IDENT, rec);
}

event iec104::M_SP_NA_1(c: connection, is_orig: bool, io: M_SP_NA_1_io)
{
    local rec = M_SP_NA_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_M_SP_NA_1, rec);
}

event iec104::M_SP_TA_1(c: connection, is_orig: bool, io: M_SP_TA_1_io)
{
    local rec = M_SP_TA_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_M_SP_TA_1, rec);
}

event iec104::M_DP_NA_1(c: connection, is_orig: bool, io: M_DP_NA_1_io)
{
    local rec = M_DP_NA_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_M_DP_NA_1, rec);
}

event iec104::M_DP_TA_1(c: connection, is_orig: bool, io: M_DP_TA_1_io)
{
    local rec = M_DP_TA_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_M_DP_TA_1, rec);
}

event iec104::M_ST_NA_1(c: connection, is_orig: bool, io: M_ST_NA_1_io)
{
    local rec = M_ST_NA_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_M_ST_NA_1, rec);
}

event iec104::M_ST_TA_1(c: connection, is_orig: bool, io: M_ST_TA_1_io)
{
    local rec = M_ST_TA_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_M_ST_TA_1, rec);
}

event iec104::M_BO_NA_1(c: connection, is_orig: bool, io: M_BO_NA_1_io)
{
    local rec = M_BO_NA_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_M_BO_NA_1, rec);
}

event iec104::M_BO_TA_1(c: connection, is_orig: bool, io: M_BO_TA_1_io)
{
    local rec = M_BO_TA_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_M_BO_TA_1, rec);
}

event iec104::M_ME_NA_1(c: connection, is_orig: bool, io: M_ME_NA_1_io)
{
    local rec = M_ME_NA_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_M_ME_NA_1, rec);
}

event iec104::M_ME_TA_1(c: connection, is_orig: bool, io: M_ME_TA_1_io)
{
    local rec = M_ME_TA_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_M_ME_TA_1, rec);
}

event iec104::M_ME_NB_1(c: connection, is_orig: bool, io: M_ME_NB_1_io)
{
    local rec = M_ME_NB_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_M_ME_NB_1, rec);
}

event iec104::M_ME_TB_1(c: connection, is_orig: bool, io: M_ME_TB_1_io)
{
    local rec = M_ME_TB_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_M_ME_TB_1, rec);
}

event iec104::M_ME_NC_1(c: connection, is_orig: bool, io: M_ME_NC_1_io)
{
    local rec = M_ME_NC_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_M_ME_NC_1, rec);
}

event iec104::M_ME_TC_1(c: connection, is_orig: bool, io: M_ME_TC_1_io)
{
    local rec = M_ME_TC_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_M_ME_TC_1, rec);
}

event iec104::M_SP_TB_1(c: connection, is_orig: bool, io: M_SP_TB_1_io)
{
    local rec = M_SP_TB_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_M_SP_TB_1, rec);
}

event iec104::M_DP_TB_1(c: connection, is_orig: bool, io: M_DP_TB_1_io)
{
    local rec = M_DP_TB_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_M_DP_TB_1, rec);
}

event iec104::M_ST_TB_1(c: connection, is_orig: bool, io: M_ST_TB_1_io)
{
    local rec = M_ST_TB_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_M_ST_TB_1, rec);
}

event iec104::M_BO_TB_1(c: connection, is_orig: bool, io: M_BO_TB_1_io)
{
    local rec = M_BO_TB_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_M_BO_TB_1, rec);
}

event iec104::M_ME_TD_1(c: connection, is_orig: bool, io: M_ME_TD_1_io)
{
    local rec = M_ME_TD_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_M_ME_TD_1, rec);
}

event iec104::M_ME_TE_1(c: connection, is_orig: bool, io: M_ME_TE_1_io)
{
    local rec = M_ME_TE_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_M_ME_TE_1, rec);
}

event iec104::M_ME_TF_1(c: connection, is_orig: bool, io: M_ME_TF_1_io)
{
    local rec = M_ME_TF_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_M_ME_TF_1, rec);
}

event iec104::C_SC_NA_1(c: connection, is_orig: bool, io: C_SC_NA_1_io)
{
    local rec = C_SC_NA_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_C_SC_NA_1, rec);
}

event iec104::C_DC_NA_1(c: connection, is_orig: bool, io: C_DC_NA_1_io)
{
    local rec = C_DC_NA_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_C_DC_NA_1, rec);
}

event iec104::C_RC_NA_1(c: connection, is_orig: bool, io: C_RC_NA_1_io)
{
    local rec = C_DC_NA_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_C_RC_NA_1, rec);
}

event iec104::C_SE_NA_1(c: connection, is_orig: bool, io: C_SE_NA_1_io)
{
    local rec = C_SE_NA_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_C_SE_NA_1, rec);
}

event iec104::C_SE_NB_1(c: connection, is_orig: bool, io: C_SE_NB_1_io)
{
    local rec = C_SE_NB_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_C_SE_NB_1, rec);
}

event iec104::C_SE_NC_1(c: connection, is_orig: bool, io: C_SE_NC_1_io)
{
    local rec = C_SE_NC_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_C_SE_NC_1, rec);
}

event iec104::C_BO_NA_1(c: connection, is_orig: bool, io: C_BO_NA_1_io)
{
    local rec = C_BO_NA_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_C_BO_NA_1, rec);
}

event iec104::C_SC_TA_1(c: connection, is_orig: bool, io: C_SC_TA_1_io)
{
    local rec = C_SC_TA_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_C_SC_TA_1, rec);
}

event iec104::C_DC_TA_1(c: connection, is_orig: bool, io: C_DC_TA_1_io)
{
    local rec = C_DC_TA_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_C_DC_TA_1, rec);
}

event iec104::C_RC_TA_1(c: connection, is_orig: bool, io: C_RC_TA_1_io)
{
    local rec = C_RC_TA_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_C_RC_TA_1, rec);
}

event iec104::C_SE_TA_1(c: connection, is_orig: bool, io: C_SE_TA_1_io)
{
    local rec = C_SE_TA_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_C_SE_TA_1, rec);
}

event iec104::C_SE_TC_1(c: connection, is_orig: bool, io: C_SE_TC_1_io)
{
    local rec = C_SE_TC_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_C_SE_TC_1, rec);
}

event iec104::C_BO_TA_1(c: connection, is_orig: bool, io: C_BO_TA_1_io)
{
    local rec = C_BO_TA_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_C_BO_TA_1, rec);
}

event iec104::M_EI_NA_1(c: connection, is_orig: bool, io: M_EI_NA_1_io)
{
    local rec = M_EI_NA_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_M_EI_NA_1, rec);
}

event iec104::C_IC_NA_1(c: connection, is_orig: bool, io: C_IC_NA_1_io)
{
    local rec = C_IC_NA_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_C_IC_NA_1, rec);
}

event iec104::C_RD_NA_1(c: connection, is_orig: bool, io: C_RD_NA_1_io)
{
    local rec = C_RD_NA_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_C_RD_NA_1, rec);
}

event iec104::C_RP_NA_1(c: connection, is_orig: bool, io: C_RP_NA_1_io)
{
    local rec = C_RP_NA_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_C_RP_NA_1, rec);
}

event iec104::Unknown_ASDU(c: connection, is_orig: bool, type_id: iec104::TypeID, hex: string)
{
    local rec = UNK($ts=current_event_time(),
                    $uid=c$uid,
                    $id=c$id,
                    $is_orig=is_orig,
                    $type_id=type_id,
                    $data=hex);
    Log::write(iec104::LOG_UNK, rec);

}
