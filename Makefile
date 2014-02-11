#
#Makefile for dns_parse
#

CC      = gcc 
CFLAGS  += -Wall -g
#CFLAGS  += -DPERF_DEBUG
INCLUDEFLAGS = 
LDFLAGS = 
OBJS    = dns_parse.o
TARGETS = dns_parse 

all : $(TARGETS)

dns_parse:dns_parse.o $(OBJS)
	    $(CC) -o $@ $^ $(LDFLAGS)

%.o:%.c
	    $(CC) -o $@ -c $< $(CFLAGS) $(INCLUDEFLAGS)

%.d:%.c
	    @set -e; rm -f $@; $(CC) -MM $< $(INCLUDEFLAGS) > $@.$$$$; \
			    sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
				    rm -f $@.$$$$

-include $(OBJS:.o=.d)

clean:
	rm -f $(TARGETS) *.o *.d *.d.*
