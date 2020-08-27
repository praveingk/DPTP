ifndef SDE_INSTALL
$(error SDE_INSTALL is not set)
endif

P4_PROG = dptp_simple_switch
ARCH = tofino
PROFILE := test
DEBUGLEVEL = 1
ifeq ($(profile), debug)
  CXXFLAGS += -DDEBUGLEVEL=$(DEBUGLEVEL)
endif

SOURCES = src/dptp.cpp src/dptp_simple_switch.cpp

CC = gcc

CFLAGS  = -DSDE_INSTALL=\"$(SDE_INSTALL)\"              \
          -I$(SDE_INSTALL)/include                      \
          -I$(SDE_INSTALL)/include/$(ARCH)/pdfixed

BF_LIBS  = -lbf_switchd_lib        \
           -lpi                    \
           -lpi_dummy              \
           -lpifeproto             \
           -ltofinopdfixed_thrift  \
           -lavago                 \
           -ldriver                \
           -lbfutils               \
           -lbfsys                 \
           -lpython3.4m

LDFLAGS  = -Wl,-rpath,$(SDE_INSTALL)/lib
LDLIBS   = -L$(SDE_INSTALL)/lib -L$(SDE_INSTALL)/lib/$(ARCH)pd/$(P4_PROG)
LDLIBS  += -Wl,--start-group $(BF_LIBS) -Wl,--end-group
LDLIBS  += -lm -pthread -lpcap -lstdc++ -ldl -levent -lthrift


all: $(P4_PROG)


$(P4_PROG): 
	$(CC) $(CFLAGS) $(SOURCES) -o $(P4_PROG) $(LDLIBS) $(LDFLAGS)
	@echo ' Finished successfully building.'

clean:
	rm $(P4_PROG) *.log zlog-cfg-cur
