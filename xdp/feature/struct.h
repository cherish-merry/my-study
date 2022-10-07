struct STATISTIC_32 {
    u32 n;
    u32 dev;
    s32 m1;
    u32 m2;
    u32 sum;
    u32 min;
    u32 max;
};

struct STATISTIC_SUM_32 {
    u32 n;
    u32 sum;
};

struct STATISTIC_MIN_32 {
    u32 n;
    u32 min;
};

struct STATISTIC_MAX_32 {
    u32 n;
    u32 max;
};

struct STATISTIC_STD_32 {
    u32 n;
    u32 dev;
    s32 m1;
    u32 m2;
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
    u8 syn;

    u16 fwd_win;
    u16 back_win;
    u32 src;

    u32 flow_start_time;
    u32 flow_end_time;
    u32 active_start_time;
    u32 active_end_time;
    u32 fwd_flow_end_time;
    u32 back_flow_end_time;

    struct STATISTIC_32 packet_len;
    struct STATISTIC_32 fwd_packet_length;
    struct STATISTIC_32 back_packet_length;
    struct STATISTIC_MAX_32 active;
//    struct STATISTIC_MAX_32 idle;
    struct STATISTIC_32 iat;
//    struct STATISTIC_32 fwd_iat;
    struct STATISTIC_SUM_32 back_iat;
};

struct PACKET_INFO {
    struct FLOW_KEY *flow_key;
    u8 fin, rst, syn;
    u16 win;
    u32 current_time;
    u32 payload;
};

