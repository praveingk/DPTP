import socket

hostname = socket.gethostname()


def setup_tofino1 ():
    pass


def setup_virt_tofino2 ():
    dptpIngress = bfrt.dptp_v16.pipe.DptpIngress
    dptpEgress  = bfrt.dptp_v16.pipe.DptpEgress

    dptpIngress.acl.add_with__drop(ingress_port=176, dstaddr=0xa0000010000a, ethertype=0x800)
    dptpIngress.acl.add_with__drop(ingress_port=160, dstaddr=0x100000000001, ethertype=0x800)

    dptpIngress.classify_logical_switch.add_with_classify_switch(dstaddr=0xa0000010000a, switch_id=0)
    dptpIngress.classify_logical_switch.add_with_classify_switch(dstaddr=0x100000000001, switch_id=1)

    dptpIngress.classify_src_logical_switch.add_with_classify_src_switch(srcaddr=0xa0000010000a, switch_id=0)
    dptpIngress.classify_src_logical_switch.add_with_classify_src_switch(srcaddr=0x100000000001, switch_id=1)

    pass

def setup_tofino2 ():
    # pd mac_forward add_entry set_egr ethernet_dstAddr 0x3cfdfead84a4 action_egress_spec 130
    # pd mac_forward add_entry set_egr ethernet_dstAddr 0x3cfdfead84a5 action_egress_spec 131
    # pd mac_forward add_entry set_egr ethernet_dstAddr 0x6cb3115309b2 action_egress_spec 147
    # pd mac_forward add_entry set_egr ethernet_dstAddr 0xa0000010000a action_egress_spec 160
    # pd mac_forward add_entry set_egr ethernet_dstAddr 0x100000000001 action_egress_spec 176
    dptpIngress = bfrt.dptp_v16.pipe.DptpIngress
    dptpEgress  = bfrt.dptp_v16.pipe.DptpEgress

    # Ingress Tables
    dptpIngress.timesyncs2s_store_igTs_hi.set_default_with_timesyncs2s_capture_igTs_hi(switch_id=19)

    dptpIngress.timesyncs2s_store_igTs_hi.add_with_timesyncs2s_capture_igTs_hi(mdata_command=0x13, mdata_switch_id=0x1, switch_id=0x1)

    dptpIngress.dptp_now.dptp_handle_overflow.add_with_nop(dptp_compare_residue=0)

    dptpIngress.mac_forward.add_with_set_egr(dstaddr=0x3cfdfead84a4, egress_spec=130)
    dptpIngress.mac_forward.add_with_set_egr(dstaddr=0x3cfdfead84a5, egress_spec=131)
    dptpIngress.mac_forward.add_with_set_egr(dstaddr=0x6cb3115309b2, egress_spec=147)
    dptpIngress.mac_forward.add_with_set_egr(dstaddr=0xa0000010000a, egress_spec=160)
    dptpIngress.mac_forward.add_with_set_egr(dstaddr=0x100000000001, egress_spec=176)

    dptpIngress.timesync_inform_cp.add_with_timesync_flag_cp_learn(command=0x2)
    dptpIngress.timesync_inform_cp.add_with_timesync_flag_cp_learn(command=0x12)

    dptpIngress.copy_dptp_packet.add_with_dptp_packet(command=0x2)
    dptpIngress.copy_dptp_packet.add_with_dptp_packet(command=0x12)

    dptpIngress.flip_address.add_with_reverse_packet(command=0x2)
    dptpIngress.flip_address.add_with_reverse_packet(command=0x12)

    dptpIngress.qos.add_with_do_qos(command=0x2)
    dptpIngress.qos.add_with_do_qos(command=0x6)
    dptpIngress.qos.add_with_do_qos(command=0x12)


    # Egress Tables
    dptpEgress.calc_current_utilization.add_with_do_calc_current_utilization(ingress_port=0x80, link=0x80)
    dptpEgress.calc_current_utilization.add_with_do_calc_current_utilization(ingress_port=0x81, link=0x81)
    dptpEgress.calc_current_utilization.add_with_do_calc_current_utilization(ingress_port=0x82, link=0x82)
    dptpEgress.calc_current_utilization.add_with_do_calc_current_utilization(ingress_port=0x83, link=0x83)

    dptpEgress.dptp_capture_tx.add_with_do_dptp_capture_tx(command=0x12)
    dptpEgress.dptp_capture_tx.add_with_do_dptp_capture_tx(command=0x11)
    dptpEgress.dptp_capture_tx.add_with_do_dptp_capture_tx(command=0x2)
    pass


if hostname == 'tofino1':
    setup_tofino1()
elif hostname == 'tofino2':
    setup_tofino2()
    setup_virt_tofino2()
