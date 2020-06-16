#
# PROGNAME : Things to be changed according to program.
# ARCH: vther it is tofinobm or tofino or bmv2.
#
PROGNAME := dptp_main
ARCH := tofino
SOURCES := src/dptp.cpp src/dptp_main.cpp
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
$(TOFINO_BUILD_DIR)/lib/libpython3.4m.so \
$(TOFINO_BUILD_DIR)/lib/libavago.so \
$(TOFINO_BUILD_DIR)/lib/libdriver.so

all: $(PROGNAME)

$(PROGNAME):
	@echo 'g++ -g -std=c++11 $(TOFINO_SDE_INCLUDE) $(SOURCES) -o $(PROGNAME) $(TOFINO_LIBS)'
	@g++ -g -std=c++11 $(TOFINO_SDE_INCLUDE) $(SOURCES) -o $(PROGNAME) $(TOFINO_LIBS)

	@echo ' Finished successfully building.'

clean:
	@rm $(PROGNAME)
