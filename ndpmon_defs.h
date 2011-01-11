#ifndef _NDPMON_DEFS_
#define _NDPMON_DEFS_ 1

#include "neighbors.h"
#include "routers.h"
#include "utils.h"

#ifdef _MACRESOLUTION_
#include "./plugins/mac_resolv/mac_resolv.h"
#endif

#define _CONFIG_PATH_ "/usr/local/etc/ndpmon/config_ndpmon.xml"
#define _CONFIG_DTD_PATH_ "/usr/local/etc/ndpmon/config_ndpmon.dtd"
#define _CACHE_PATH_ "/var/local/ndpmon/neighbor_list.xml"
#define _CACHE_DTD_PATH_ "/var/local/ndpmon/neighbor_list.dtd"
#define _DISCOVERY_HISTORY_PATH_ "/var/local/ndpmon/discovery_history.dat"
#define _MANUF_PATH_ "/usr/local/ndpmon/plugins/mac_resolv/manuf"

extern int DEBUG;
extern int learning;

extern struct neighbor_list *neighbors;
extern struct router_list *routers;

extern char admin_mail[128];
extern char syslog_facility[16];
extern int ignor_autoconf;

extern char config_path[128];
extern char cache_path[128];
extern char dtd_path[128];
extern char dtd_config_path[128];
extern char discovery_history_path[128];

extern int use_reverse_hostlookups;
struct action_selector {int sendmail; int syslog; char* exec_pipe_program;};
extern struct action_selector action_low_pri, action_high_pri;
  
    
#ifdef _MACRESOLUTION_
extern manufacturer_t *manuf;
#endif

#endif
