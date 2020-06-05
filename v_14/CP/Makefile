#
# PROGNAME : Things to be changed according to program.
# ARCH: vther it is tofinobm or tofino or bmv2.
#
PROGNAME := dptp_topo
ARCH := tofino
SOURCES := dptp_topo_cp.c
TOFINO_BUILD_DIR = /root/bf-sde-9.1.1/install
TOFINO_SDE_INCLUDE := -I$(TOFINO_BUILD_DIR)/include
TOFINO_LIBS := /usr/lib/x86_64-linux-gnu/libpthread.so \
/usr/lib/x86_64-linux-gnu/libpcap.so\
/usr/lib/libpiall.so\
/usr/lib/libpifeproto.so\
$(TOFINO_BUILD_DIR)/lib/libbfsys.so \
$(TOFINO_BUILD_DIR)/lib/libbf_switchd_lib.so \
$(TOFINO_BUILD_DIR)/lib/libbfutils.so \
$(TOFINO_BUILD_DIR)/lib/libtofinopdfixed_thrift.so \
$(TOFINO_BUILD_DIR)/lib/$(ARCH)pd/$(PROGNAME)/libpd.so \
$(TOFINO_BUILD_DIR)/lib/$(ARCH)pd/$(PROGNAME)/libpdthrift.so \
$(TOFINO_BUILD_DIR)/lib/libpython3.4m.so \
$(TOFINO_BUILD_DIR)/lib/libavago.so \
$(TOFINO_BUILD_DIR)/lib/libdriver.so \


all: $(PROGNAME)_cp

$(PROGNAME)_cp:
	@echo 'gcc $(TOFINO_SDE_INCLUDE) $(SOURCES) -o $(PROGNAME)_cp $(TOFINO_LIBS)'
	@gcc  $(TOFINO_SDE_INCLUDE) $(SOURCES) -o $(PROGNAME)_cp $(TOFINO_LIBS)

	@echo ' Finished successfully building.'

clean:
	@rm $(PROGNAME)_cp
