struct STATISTIC_PACKET_LENGTH {
    u32 n;
    u32 dev;
    s32 m1;
    u32 m2;
    u32 sum;
    u32 max;
};

struct STATISTIC_FWD_PACKET_LENGTH {
    u32 n;
    u32 dev;
    s32 m1;
    u32 m2;
    u32 min;
};

struct STATISTIC_BACK_PACKET_LENGTH {
    u32 n;
    u32 dev;
    s32 m1;
    u32 m2;
    u32 sum;
};

struct STATISTIC_FLOW_IAT {
    u32 n;
    u32 sum;
};

struct STATISTIC_FWD_IAT {
    u32 n;
    u32 dev;
    s32 m1;
    u32 m2;
};

struct STATISTIC_BACK_IAT {
    u32 n;
    u32 sum;
    u32 max;
};


struct STATISTIC_ACTIVE {
    u32 n;
    u32 max;
};


struct STATISTIC_IDLE {
    u32 n;
    u32 max;
};


struct FLOW_KEY {
    u8 protocol;
    u32 src;
    u32 dest;
    u32 src_port;
    u32 dest_port;
};

struct FLOW_FEATURE_NODE {
    u8 fwd_fin;
    u8 back_fin;
//    u8 rst;

    u16 fwd_win;
    u16 back_win;
    u32 src;

    u32 flow_start_time;
    u32 flow_end_time;
    u32 active_start_time;
    u32 active_end_time;
    u32 fwd_flow_end_time;
    u32 back_flow_end_time;

    struct STATISTIC_PACKET_LENGTH packet_length;
    struct STATISTIC_FWD_PACKET_LENGTH fwd_packet_length;
    struct STATISTIC_BACK_PACKET_LENGTH back_packet_length;
    struct STATISTIC_ACTIVE active;
    struct STATISTIC_IDLE idle;
    struct STATISTIC_FLOW_IAT iat;
    struct STATISTIC_FWD_IAT fwd_iat;
    struct STATISTIC_BACK_IAT back_iat;
};

struct PACKET_INFO {
    struct FLOW_KEY *flow_key;
    u8 fin, rst, syn;
    u16 win;
    u32 current_time;
    u32 payload;
};

