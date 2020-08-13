import socket

hostname = socket.gethostname()


def setup_tofino1 ():
    pass


def setup_virt_tofino2 ():
    virtSwitch = bfrt.dptp_simple_switch.pipe.SwitchIngress.virt_switch

    virtSwitch.acl.add_with__drop(ingress_port=176, ethernet_dstaddr=0xa0000010000a, ethernet_ethertype=0x800)
    virtSwitch.acl.add_with__drop(ingress_port=160, ethernet_dstaddr=0x100000000001, ethernet_ethertype=0x800)

    virtSwitch.classify_logical_switch.add_with_classify_switch(ethernet_dstaddr=0xa0000010000a, switch_id=0)
    virtSwitch.classify_logical_switch.add_with_classify_switch(ethernet_dstaddr=0xa0000020000a, switch_id=0)

    virtSwitch.classify_logical_switch.add_with_classify_switch(ethernet_dstaddr=0x100000000001, switch_id=1)

    virtSwitch.classify_src_logical_switch.add_with_classify_src_switch(ethernet_srcaddr=0xa0000010000a, switch_id=0)
    virtSwitch.classify_src_logical_switch.add_with_classify_src_switch(ethernet_srcaddr=0x100000000001, switch_id=1)

    pass

def setup_tofino2 ():
    dptpSwitchIngress = bfrt.dptp_simple_switch.pipe.SwitchIngress

    #dptpSwitchIngress.dptp_now.dptp_handle_overflow.add_with_nop(dptp_compare_residue=0)

    # Tina
    dptpSwitchIngress.mac_forward.add_with_set_egr(dstaddr=0x6cb3115309b0, egress_spec=128)
    dptpSwitchIngress.mac_forward.add_with_set_egr(dstaddr=0x6cb3115309b2, egress_spec=129)

    # Loopback Switch1-Master
    dptpSwitchIngress.mac_forward.add_with_set_egr(dstaddr=0xa0000010000a, egress_spec=160)
    dptpSwitchIngress.mac_forward.add_with_set_egr(dstaddr=0x100000000001, egress_spec=176)

    pass


if hostname == 'tofino1':
    setup_tofino1()
elif hostname == 'tofino2':
    setup_tofino2()
    setup_virt_tofino2()
