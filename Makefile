# Generated automatically from Makefile.in by configure.
OBJ=ndpmon.o  alarm.o monitoring.o monitoring_ra.o monitoring_na.o monitoring_ns.o  monitoring_rd.o print_packet_info.o  routers.o neighbors.o parser.o 
FLAGS=-Wall -pedantic -O2 -I/usr/include -I/usr/include -I/usr/include  -D_LINUX_
#LIB=-lpcap -lxml2
CC=gcc
LIB= -L/usr/lib -lxml2 -L/usr/lib -lpcap -L/usr/lib -lcrypto
MAKE=make -C ./plugins/mac_resolv
MAKE_COUNTERMEASURES=make -C ./plugins/countermeasures
all: ndpmon

prefix=/usr/local
exec_prefix=${prefix}
datadir=${prefix}/share
confdir=${prefix}/etc
datadir=${prefix}/share
localstatedir=${prefix}/var

INSTALL_DIR=${prefix}/ndpmon
MAN_DIR=/usr/local/share/man/man8
BINARY_DIR=${exec_prefix}/sbin
confprefix=/usr/local/etc
CONF_DIR=$(confprefix)/ndpmon
# By default, ndpmon is installed in /usr/local
# variable data thus go to /var/local and not /usr/local/share
#DATA_DIR=${datadir}/ndpmon
dataprefix=/var/local
DATA_DIR=$(dataprefix)/ndpmon

install: ndpmon
	# Copy the source and objects to the INSTALL_DIR
	mkdir -p $(INSTALL_DIR)
	cp *.[hco] $(INSTALL_DIR)
	cp demopipeprogram.pl.sample $(INSTALL_DIR)
	cp create_html_table.py $(INSTALL_DIR)
	cp -r plugins $(INSTALL_DIR)

	# Copy the XML and DTD of the configuration to the CONF_DIR
	mkdir -p $(CONF_DIR)
	cp config_ndpmon.xml $(CONF_DIR)
	cp config_ndpmon.dtd $(CONF_DIR)

	# Copy the XML and DTD of the neighbor cache to the DATA_DIR
	mkdir -p $(DATA_DIR)
	cp neighbor_list.xml $(DATA_DIR)
	cp neighbor_list.dtd $(DATA_DIR)
	cp alerts.xml $(DATA_DIR)
	
	# Copy the manpage to the MAN_DIR
	mkdir -p $(MAN_DIR)
	mkdir -p $(MAN_DIR)
	cp ndpmon.8 $(MAN_DIR)

	# Copy the binary to BINARY_DIR
	mkdir -p $(BINARY_DIR)
	mkdir -p $(BINARY_DIR)
	cp ndpmon $(BINARY_DIR)

	# Linux Specific
	cp ndpmon.sh /etc/init.d/ndpmon
	chmod +x /etc/init.d/ndpmon

uninstall:
	-rm -rf $(INSTALL_DIR)
	-rm $(MAN_DIR)/ndpmon.8
	-rm $(BINARY_DIR)/ndpmon
	echo "Keeping the configuration files in $(CONF_DIR) and the data files in $(DATA_DIR). Use \"make purge\" to remove them."
	rm /etc/init.d/ndpmon

purge: uninstall
	-rm -rf $(CONF_DIR)
	-rm -rf $(DATA_DIR)

clean: 
	-rm -rf *~ *.o ndpmon plugins/mac_resolv/mac_resolv.o plugins/countermeasures/*.o

ndpmon: $(OBJ)
	$(CC) $(FLAGS) $(OBJ) -o ndpmon $(LIB) 

monitoring.o: monitoring.c monitoring.h
	$(CC) $(FLAGS) -c `xml2-config  --cflags` monitoring.c 

monitoring_ra.o: monitoring_ra.c monitoring_ra.h
	$(CC) $(FLAGS) -c `xml2-config  --cflags` monitoring_ra.c 

monitoring_na.o: monitoring_na.c monitoring_na.h
	$(CC) $(FLAGS) -c `xml2-config  --cflags` monitoring_na.c 

monitoring_ns.o: monitoring_ns.c monitoring_ns.h
	$(CC) $(FLAGS) -c `xml2-config  --cflags` monitoring_ns.c 

monitoring_rd.o: monitoring_rd.c monitoring_rd.h
	$(CC) $(FLAGS) -c `xml2-config  --cflags` monitoring_rd.c 

alarm.o: alarm.c alarm.h
	$(CC) $(FLAGS) -c `xml2-config  --cflags` alarm.c 

print_packet_info.o: print_packet_info.c print_packet_info.h
	$(CC) $(FLAGS) -c `xml2-config  --cflags` print_packet_info.c 

ndpmon.o: ndpmon.c ndpmon.h
	$(CC) $(FLAGS) -c `xml2-config  --cflags` ndpmon.c 

routers.o: routers.c routers.h
	$(CC) $(FLAGS) -c `xml2-config  --cflags` routers.c 

neighbors.o: neighbors.c neighbors.h
	$(CC) $(FLAGS) -c `xml2-config  --cflags` neighbors.c 

parser.o: parser.c
	$(CC) $(FLAGS) -c `xml2-config  --cflags` parser.c 

plugins/mac_resolv/mac_resolv.o: plugins/mac_resolv/mac_resolv.c
	$(MAKE)

plugins/countermeasures/countermeasures.o: plugins/countermeasures/countermeasures.c
	$(MAKE_COUNTERMEASURES)
