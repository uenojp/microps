APPS = 

DRIVERS = driver/dummy.o \
		  driver/loopback.o \

OBJS = util.o \
	   net.o \
	   ip.o \
	   icmp.o \
	   ether.o \
	   arp.o \
	   udp.o \
	   tcp.o \

TESTS = test/step0.exe \
		test/step1.exe \
		test/step2.exe \
		test/step3.exe \
		test/step4.exe \
		test/step5.exe \
		test/step6.exe \
		test/step7.exe \
		test/step8.exe \
		test/step9.exe \
		test/step10.exe \
		test/step11.exe \
		test/step12.exe \
		test/step13.exe \
		test/step14.exe \
		test/step15.exe \
		test/step16.exe \
		test/step17.exe \
		test/step18.exe \
		test/step19.exe \
		test/step20-1.exe \
		test/step20-2.exe \
		test/step21.exe \
		test/step22.exe \
		test/step23.exe \
		test/step24.exe \
		test/step25.exe \
		test/step27.exe \
		test/step28.exe \

CFLAGS := $(CFLAGS) -g -W -Wall -Wno-unused-parameter -iquote .

ifeq ($(shell uname),Linux)
  # Linux specific settings
  BASE = platform/linux
  CFLAGS := $(CFLAGS) -pthread -iquote $(BASE)
  LDFLAGS := $(LDFLAGS) -lrt
  DRIVERS := $(DRIVERS) $(BASE)/driver/ether_tap.o
  OBJS := $(OBJS) $(BASE)/intr.o $(BASE)/sched.o
endif

ifeq ($(shell uname),Darwin)
  # macOS specific settings
endif

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all clean

all: $(APPS) $(TESTS)

$(APPS): %.exe : %.o $(OBJS) $(DRIVERS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TESTS): %.exe : %.o $(OBJS) $(DRIVERS) test/test.h
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(APPS) $(APPS:.exe=.o) $(OBJS) $(DRIVERS) $(TESTS) $(TESTS:.exe=.o)
