'''
    idx = 0;
    actual_val = feature_vec.lookup(&idx);
    bpf_trace_printk("Protocol:%llu", flow->protocol);
    if (actual_val != NULL) *actual_val = flow->protocol;

'''

if __name__ == '__main__':
    for i in range(0, 64):
        print("idx = {};".format(i))
        print("actual_val = feature_vec.lookup(&idx);")
        print('bpf_trace_printk("Protocol:%llu", flow->protocol);')
        print("if (actual_val != NULL) *actual_val = flow->protocol;")
