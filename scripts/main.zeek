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
        LOG,
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
        LOG_M_SP_TB_1,
        LOG_M_DP_TB_1,
        LOG_M_ST_TB_1,
        LOG_M_BO_TB_1,
        LOG_M_ME_TD_1,
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
        LOG_APCI_U,
        LOG_APCI_S,
        LOG_SVA_QOS,
        LOG_DIQ_CP56Time2a,
        LOG_DIQ_CP24Time2a,
        LOG_SVA_QDS_CP56Time2a,
        LOG_IEEE_754_QDS_CP56Time2a,
        LOG_IEEE_754_QDS_CP24Time2a,
        LOG_Read_Command,
        LOG_QRP,
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

    type QOS_field: record {
        ql: count &log &optional;
        se: count &log &optional;
    };

    type SVA_QOS: record {
        Asdu_num: count &log;
        info_obj_addr: count &log &optional;
        SVA: count &log &optional;
        qos: QOS_field &log &optional;
    };

    type QDS_field: record {
        ov: count &log;
        bl: count &log;
        sb: count &log;
        nt: count &log;
        iv: count &log;
    };

    type minutes: record {
        mins: count &log &optional;
        iv: count &log &optional;
    };

    type hours: record {
        hours: count &log &optional;
        su: count &log &optional;
    };

    type day_dows: record {
        day: count &log &optional;
        day_of_week: count &log &optional;
    };

    type CP24TIME2A: record {
        milli: count &log &optional;
        minute: minutes &log &optional;
    };

    type CP56TIME2A: record {
        milli: count &log &optional;
        minute: minutes &log &optional;
        hour: hours &log &optional;
        day_dow: day_dows &log &optional;
        mon: count &log &optional;
        year: count &log &optional;
    };

    type DIQ_field: record {
        dpi: count &log &optional;
        bl: count &log &optional;
        sb: count &log &optional;
        nt: count &log &optional;
        iv: count &log &optional;
    };

    type DIQ_CP56Time2a: record {
        Asdu_num: count &log;
        info_obj_type: count &log &optional;
        info_obj_addr: count &log &optional;
        diq: DIQ_field &log &optional;
        CP56Time2a: CP56TIME2A &log &optional;
    };

    type DIQ_CP24Time2a: record {
        Asdu_num: count &log;
        info_obj_addr: count &log &optional;
        diq: DIQ_field &log &optional;
        CP24Time2a: CP24TIME2A &log &optional;
    };

    type SVA_QDS_CP56Time2a: record {
        Asdu_num: count &log;
        info_obj_addr: count &log &optional;
        SVA: count &log &optional;
        qds: QDS_field &log &optional;
        CP56Time2a: CP56TIME2A &log &optional;
    };

    type L_IEEE_754_QDS_CP56Time2a: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        is_orig: bool &log;
        info_obj_addr: count &log;
        # FIXME: Value is actually a short float.
        value: count &log;
        qds: QDS_field &log;
        btt: CP56TIME2A &log;
    };

    type IEEE_754_QDS_CP24Time2a: record {
        Asdu_num: count &log;
        info_obj_addr: count &log &optional;
        value: count &log &optional;
        qds: QDS_field &log &optional;
        CP24Time2a: CP24TIME2A &log &optional;
    };

    type Read_Command: record {
        Asdu_num: count &log;
        info_obj_addr: count &log &optional;
    };

    type QRP: record {
        Asdu_num: count &log;
        info_obj_addr: count &log &optional;
        raw_data: string &log &optional;
    };

    type Asdu: record {
        type_id: TypeID &log &optional;
        seq: count &log &optional;
        num_ix: count &log &optional;
        # cause_tx: count &log &optional;
        cause: COT &log &optional;
        negative: count &log &optional;
        test: count &log &optional;
        originator_address: count &log &optional;
        common_address: count &log &optional;

        # interrogation_command: QOI &log &optional;
        interrogation_command: vector of count &log &optional;

        # single_point_information: SIQ &log &optional;
        single_point_information: vector of count &log &optional;

        single_command: vector of count &log &optional;

        double_command: vector of count &log &optional;

        regulating_step_command: vector of count &log &optional;
        bit_string_32_bit: vector of count &log &optional;
        setpoint_command_scaled_value: vector of count &log &optional;
        measured_value_scaled_value: vector of count &log &optional;

        step_position_information: vector of count &log &optional;

        single_point_information_CP56Time2a: vector of count &log &optional;
        single_point_information_CP24Time2a: vector of count &log &optional;
        # double_point_information_CP56Time2a: DIQ_CP56Time2a &log &optional;
        double_point_information_CP56Time2a: vector of count &log &optional;
        double_point_information_CP24Time2a: vector of count &log &optional;

        step_position_information_CP56Time2a: vector of count &log &optional;
        step_position_information_CP24Time2a: vector of count &log &optional;
        bit_string_32_bit_CP56Time2a: vector of count &log &optional;
        bit_string_32_bit_CP24Time2a: vector of count &log &optional;
        end_of_initialization: vector of count &log &optional;
        measured_value_normalized_CP56Time2a: vector of count &log &optional;
        measured_value_normalized_CP24Time2a: vector of count &log &optional;
        measured_value_scaled_CP24Time2a: vector of count &log &optional;
        measured_value_scaled_CP56Time2a: vector of count &log &optional;
        measured_value_short_floating_point_CP56Time2a: vector of count &log &optional;
        measured_value_short_floating_point_CP24Time2a: vector of count &log &optional;
        read_Command: vector of count &log &optional;
        qrp: vector of count &log &optional;

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

    ## Record type containing the column fields of the iec104 log.
    type Info: record {
        ## Timestamp for when the activity happened.
        ts: time &log;
        ## Unique ID for the connection.
        uid: string &log;
        ## The connection's 4-tuple of endpoint addresses/ports.
        id: conn_id &log;

        # TODO: Adapt subsequent fields as needed.

        apdu_len: count &log &optional;
        # apdu_len : count &optional;

        # apci_type : count &log;
        # apci_type : count &optional;
        apci_type: string &log &optional;

        apci_tx: count &log &optional;
        apci_rx: count &log &optional;

        # TODO: Should that be an array of ASDUs?
        asdu: Asdu &log &optional;
        # asdu: count &log &optional;

        asdu_uid: string &log &optional;

        # Counters can be for statistics but also serve good indicator for correct parsing.
        # type_i_counter: count &log;
        type_i_counter: count &optional;
        # type_s_counter: count &log;
        type_s_counter: count &optional;
        # type_u_counter: count &log;
        type_u_counter: count &optional;

        ## Request-side payload.
        request: string &optional &log;
        ## Response-side payload.
        reply: string &optional &log;
    };

    ## Default hook into iec104 logging.
    global log_iec104: event(rec: Info);
}

global SVA_QOS_vec: vector of count;
global SVA_QOS_temp: vector of count;

global DIQ_CP56Time2a_vec: vector of count;
global DIQ_CP56Time2a_temp: vector of count;
global DIQ_CP24Time2a_vec: vector of count;
global DIQ_CP24Time2a_temp: vector of count;
global SVA_QDS_CP56Time2a_vec: vector of count;
global SVA_QDS_CP56Time2a_temp: vector of count;
global IEEE_754_QDS_CP56Time2a_vec: vector of count;
global IEEE_754_QDS_CP56Time2a_temp: vector of count;
global IEEE_754_QDS_CP24Time2a_vec: vector of count;
global IEEE_754_QDS_CP24Time2a_temp: vector of count;
global Read_Command_vec: vector of count;
global Read_Command_temp: vector of count;
global QRP_vec: vector of count;
global QRP_temp: vector of count;

redef record connection += {
    iec104: Info &optional;
};

const ports = {
    # TODO: Replace with actual port(s).
    2404/tcp # adapt port number in iec104.evt accordingly
};

redef likely_server_ports += { ports };

event zeek_init() &priority=5
{
    Log::create_stream(iec104::LOG, [$columns=Info, $ev=log_iec104, $path="iec104"]);
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
    Log::create_stream(iec104::LOG_M_SP_TB_1, [$columns=M_SP_TB_1_log, $path="iec104-M_SP_TB_1"]);
    Log::create_stream(iec104::LOG_M_DP_TB_1, [$columns=M_DP_TB_1_log, $path="iec104-M_DP_TB_1"]);
    Log::create_stream(iec104::LOG_M_ST_TB_1, [$columns=M_ST_TB_1_log, $path="iec104-M_ST_TB_1"]);
    Log::create_stream(iec104::LOG_M_BO_TB_1, [$columns=M_BO_TB_1_log, $path="iec104-M_BO_TB_1"]);
    Log::create_stream(iec104::LOG_M_ME_TD_1, [$columns=M_ME_TD_1_log, $path="iec104-M_ME_TD_1"]);
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
    Log::create_stream(iec104::LOG_APCI_U, [$columns=APCI_U, $path="iec104-apci_u"]);
    Log::create_stream(iec104::LOG_APCI_S, [$columns=APCI_S, $path="iec104-apci_s"]);
    Log::create_stream(iec104::LOG_SVA_QDS_CP56Time2a, [$columns=SVA_QDS_CP56Time2a, $path="iec104-M_ME_TE_1"]);
    Log::create_stream(iec104::LOG_IEEE_754_QDS_CP56Time2a,
                       [$columns=L_IEEE_754_QDS_CP56Time2a,
                        $path="iec104-M_ME_TF_1"]);
    Log::create_stream(iec104::LOG_IEEE_754_QDS_CP24Time2a, [$columns=IEEE_754_QDS_CP24Time2a, $path="iec104-M_ME_TC_1"]);
    Log::create_stream(iec104::LOG_Read_Command, [$columns=Read_Command, $path="iec104-C_RD_NA_1"]);
    Log::create_stream(iec104::LOG_QRP, [$columns=QRP, $path="iec104-C_RP_NA_1"]);
    Log::create_stream(iec104::LOG_UNK, [$columns=UNK, $path="iec104-unk"]);
}

# Initialize logging state.
hook set_session(c: connection)
{
    if ( c?$iec104 ) {
        c$iec104$ts = current_event_time();
        return;
    }

    c$iec104 = Info($ts = current_event_time(),
                    $uid = c$uid,
                    $id = c$id,
                    $apdu_len = apdu_len,
                    $apci_type = apci_type);
    c$iec104$asdu = Asdu();
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

event iec104::asdu(c: connection, type_id: TypeID, seq: count, num_ix: count, cause: COT,
                   negative: count, test: count, originator_address: count, common_address: count
                  ) &priority=3
{
    hook set_session(c);

    local info = c$iec104;
    info$asdu$type_id = type_id;
    info$asdu$seq = seq;
    info$asdu$num_ix = num_ix;

    info$asdu$cause = cause;
    info$asdu$negative = negative;
    info$asdu$test = test;

    info$asdu$originator_address = originator_address;
    info$asdu$common_address = common_address;
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

event iec104::C_IC_NA_1(c: connection, is_orig: bool, io: C_IC_NA_1_io)
{
    local rec = C_IC_NA_1_log(
        $ts=current_event_time(),
        $uid=c$uid,
        $is_orig=is_orig,
        $io=io);
    Log::write(iec104::LOG_C_IC_NA_1, rec);
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

event iec104::SVA_QDS_CP56Time2a_evt(c: connection, sva_QDS_CP56Time2a: SVA_QDS_CP56Time2a)
{
    hook set_session(c);

    local info = c$iec104;

    local next_num: count;
    next_num = |SVA_QDS_CP56Time2a_vec| + 1;

    SVA_QDS_CP56Time2a_temp += next_num;
    SVA_QDS_CP56Time2a_vec += next_num;

    local new_SVA_QDS_CP56Time2a = SVA_QDS_CP56Time2a($Asdu_num=next_num);
    new_SVA_QDS_CP56Time2a$info_obj_addr = sva_QDS_CP56Time2a$info_obj_addr;
    new_SVA_QDS_CP56Time2a$SVA = sva_QDS_CP56Time2a$SVA;
    new_SVA_QDS_CP56Time2a$qds = sva_QDS_CP56Time2a$qds;
    new_SVA_QDS_CP56Time2a$CP56Time2a = sva_QDS_CP56Time2a$CP56Time2a;

    Log::write(iec104::LOG_SVA_QDS_CP56Time2a, new_SVA_QDS_CP56Time2a);
}

event iec104::IEEE_754_QDS_CP56Time2a_evt(c: connection,
                                          is_orig: bool,
                                          info_obj_addr: count,
                                          value: count,
                                          qds: QDS_field,
                                          btt: CP56TIME2A)
{
    local rec = L_IEEE_754_QDS_CP56Time2a($ts=current_event_time(),
                                          $uid=c$uid,
                                          $id=c$id,
                                          $is_orig=is_orig,
                                          $info_obj_addr=info_obj_addr,
                                          $value=value,
                                          $qds=qds,
                                          $btt=btt);

    Log::write(iec104::LOG_IEEE_754_QDS_CP56Time2a, rec);
}

event iec104::IEEE_754_QDS_CP24Time2a_evt(c: connection, ieee_754_QDS_CP24Time2a: IEEE_754_QDS_CP24Time2a)
{
    hook set_session(c);

    local info = c$iec104;

    local next_num: count;
    next_num = |IEEE_754_QDS_CP24Time2a_vec| + 1;

    IEEE_754_QDS_CP24Time2a_temp += next_num;
    IEEE_754_QDS_CP24Time2a_vec += next_num;

    local new_IEEE_754_QDS_CP24Time2a = IEEE_754_QDS_CP24Time2a($Asdu_num=next_num);
    new_IEEE_754_QDS_CP24Time2a$info_obj_addr = ieee_754_QDS_CP24Time2a$info_obj_addr;
    new_IEEE_754_QDS_CP24Time2a$value = ieee_754_QDS_CP24Time2a$value;
    new_IEEE_754_QDS_CP24Time2a$qds = ieee_754_QDS_CP24Time2a$qds;
    new_IEEE_754_QDS_CP24Time2a$CP24Time2a = ieee_754_QDS_CP24Time2a$CP24Time2a;

    Log::write(iec104::LOG_IEEE_754_QDS_CP24Time2a, new_IEEE_754_QDS_CP24Time2a);
}

event iec104::Read_Command_evt(c: connection, read_Command: Read_Command)
{
    hook set_session(c);

    local info = c$iec104;

    local next_num: count;
    next_num = |Read_Command_vec| + 1;

    Read_Command_temp += next_num;
    Read_Command_vec += next_num;

    local rec = Read_Command($Asdu_num=next_num);
    rec$info_obj_addr = read_Command$info_obj_addr;

    Log::write(iec104::LOG_Read_Command, rec);
}

event iec104::QRP_evt(c: connection, qrp: QRP)
{
    hook set_session(c);

    local info = c$iec104;

    local next_num: count;
    next_num = |QRP_vec| + 1;

    QRP_temp += next_num;
    QRP_vec += next_num;

    local rec = QRP($Asdu_num=next_num);
    rec$info_obj_addr = qrp$info_obj_addr;
    rec$raw_data = qrp$raw_data;

    Log::write(iec104::LOG_QRP, rec);
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
