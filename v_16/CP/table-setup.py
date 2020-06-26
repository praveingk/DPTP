import socket

hostname = socket.gethostname()


def setup_tofino1 ():
    pass


def setup_virt_tofino2 ():
    virtSwitch = bfrt.dptp.pipe.DptpSwitchIngress.virt_switch

    virtSwitch.acl.add_with__drop(ingress_port=176, dstaddr=0xa0000010000a, ethertype=0x800)
    virtSwitch.acl.add_with__drop(ingress_port=160, dstaddr=0x100000000001, ethertype=0x800)

    virtSwitch.classify_logical_switch.add_with_classify_switch(dstaddr=0xa0000010000a, switch_id=0)
    virtSwitch.classify_logical_switch.add_with_classify_switch(dstaddr=0x100000000001, switch_id=1)

    virtSwitch.classify_src_logical_switch.add_with_classify_src_switch(srcaddr=0xa0000010000a, switch_id=0)
    virtSwitch.classify_src_logical_switch.add_with_classify_src_switch(srcaddr=0x100000000001, switch_id=1)

    pass

def setup_tofino2 ():
    dptpSwitchIngress = bfrt.dptp.pipe.DptpSwitchIngress

    dptpSwitchIngress.dptp_now.dptp_handle_overflow.add_with_nop(dptp_compare_residue=0)

    dptpSwitchIngress.dptp_ingress.mac_forward.add_with_set_egr(dstaddr=0x3cfdfead84a4, egress_spec=130)
    dptpSwitchIngress.dptp_ingress.mac_forward.add_with_set_egr(dstaddr=0x3cfdfead84a5, egress_spec=131)
    dptpSwitchIngress.dptp_ingress.mac_forward.add_with_set_egr(dstaddr=0x6cb3115309b2, egress_spec=147)
    dptpSwitchIngress.dptp_ingress.mac_forward.add_with_set_egr(dstaddr=0xa0000010000a, egress_spec=160)
    dptpSwitchIngress.dptp_ingress.mac_forward.add_with_set_egr(dstaddr=0x100000000001, egress_spec=176)

    pass


if hostname == 'tofino1':
    setup_tofino1()
elif hostname == 'tofino2':
    setup_tofino2()
    setup_virt_tofino2()
