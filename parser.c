#include "parser.h"
#include "membounds.h"
#ifdef _COUNTERMEASURES_
#include "./plugins/countermeasures/countermeasures.h"
#endif
#include <assert.h>

static xmlParserCtxtPtr ctxt; /* the parser context */
static xmlDocPtr doc; /* the resulting document tree */
static xmlXPathContextPtr xpctxt;/* the xpath context of main config file*/


/*Clear xml structures in memory*/
void free_xml()
{
	xmlXPathFreeContext (xpctxt);
	xmlFreeDoc(doc);
	xmlFreeParserCtxt(ctxt);
}

/* Write value to proc entry
 * Return: 0 is ok
 */
static int write_proc(const char *file, const char *value)
{
	int fd;
	ssize_t ret;

	if (file == NULL || value == NULL) return -1;

	fd = open(file,O_WRONLY);
	if (fd < 0) return -1;

	ret = write(fd,value,strlen(value)); 
	if (ret < 0) {
		char error[100];
		snprintf(error, sizeof(error)-1, "Error while trying to set proc entry %s to %s", file, value);
		perror(error);
		close(fd);
		exit(1);
	}

	close(fd);

	return 0;
}


/* If the tag ignor_autoconf if set, disable this feature by
 * setting the variables 
 * /proc/sys/net/ipv6/conf/all/autoconf
 * /proc/sys/net/ipv6/conf/all/accept_ra
 * /proc/sys/net/ipv6/conf/all/accept_ra_defrtr
 * /proc/sys/net/ipv6/conf/all/accept_ra_pinfo
 * /proc/sys/net/ipv6/conf/all/accept_redirects
 * to 0 to avoid the monitoring host to be attacked
 */
void autoconf()
{
	char *request ="/config_ndpmon/ignor_autoconf/text()";
	char  *flag;

	xmlXPathObjectPtr xmlobject = xmlXPathEval ((xmlChar*)request, xpctxt);
	
	if( xmlobject != NULL)
	{	
	    flag = (char *)xmlobject->nodesetval->nodeTab[0]->content;
	    ignor_autoconf = atoi(flag);

        /* Not working for BSD */
#ifdef _LINUX_
		/** note: it may be a good option to save values, and restore
		 * them when exiting
		 */
		write_proc("/proc/sys/net/ipv6/conf/all/autoconf",flag);
		write_proc("/proc/sys/net/ipv6/conf/all/accept_ra",flag);
		write_proc("/proc/sys/net/ipv6/conf/all/accept_ra_defrtr",flag);
		write_proc("/proc/sys/net/ipv6/conf/all/accept_ra_pinfo",flag);
		write_proc("/proc/sys/net/ipv6/conf/all/accept_redirects",flag);
	}
#endif
	xmlXPathFreeObject (xmlobject);
	return;
}

/* Parse settings for what to perform on what action */
void parse_actions()
{
	char* request;
	xmlXPathObjectPtr xmlobject;

	request ="/config_ndpmon/actions_low_pri/sendmail/text()";
	xmlobject = xmlXPathEval ((xmlChar*)request, xpctxt);
	if ((xmlobject->nodesetval==NULL) || (strcmp("1", (char*)xmlobject->nodesetval->nodeTab[0]->content)!=0)) action_low_pri.sendmail=0;
	else action_low_pri.sendmail=1; 
	xmlXPathFreeObject (xmlobject);

	request ="/config_ndpmon/actions_low_pri/syslog/text()";
	xmlobject = xmlXPathEval ((xmlChar*)request, xpctxt);
	if ((xmlobject->nodesetval==NULL) || (strcmp("1", (char*)xmlobject->nodesetval->nodeTab[0]->content)!=0)) action_low_pri.syslog=0;
	else action_low_pri.syslog=1; 
	xmlXPathFreeObject (xmlobject);
	
	request ="/config_ndpmon/actions_low_pri/exec_pipe_program/text()";
	xmlobject = xmlXPathEval ((xmlChar*)request, xpctxt);
	if (xmlobject->nodesetval==NULL) action_low_pri.exec_pipe_program="";
	else action_low_pri.exec_pipe_program=strdup((char*)xmlobject->nodesetval->nodeTab[0]->content);
	xmlXPathFreeObject (xmlobject);


	request ="/config_ndpmon/actions_high_pri/sendmail/text()";
	xmlobject = xmlXPathEval ((xmlChar*)request, xpctxt);
	if ((xmlobject->nodesetval==NULL) || (strcmp("1", (char*)xmlobject->nodesetval->nodeTab[0]->content)!=0)) action_high_pri.sendmail=0;
	else action_high_pri.sendmail=1; 
	xmlXPathFreeObject (xmlobject);

	request ="/config_ndpmon/actions_high_pri/syslog/text()";
	xmlobject = xmlXPathEval ((xmlChar*)request, xpctxt);
	if ((xmlobject->nodesetval==NULL) || (strcmp("1", (char*)xmlobject->nodesetval->nodeTab[0]->content)!=0)) action_high_pri.syslog=0;
	else action_high_pri.syslog=1; 
	xmlXPathFreeObject (xmlobject);
	
	request ="/config_ndpmon/actions_high_pri/exec_pipe_program/text()";
	xmlobject = xmlXPathEval ((xmlChar*)request, xpctxt);
	if (xmlobject->nodesetval==NULL) action_high_pri.exec_pipe_program=NULL;
	else action_high_pri.exec_pipe_program=strdup((char*)xmlobject->nodesetval->nodeTab[0]->content);
	xmlXPathFreeObject (xmlobject);

	return;
}

/* Should we do reverse DNS lookups on an action that is logged? */
void get_use_reverse_hostlookups()
{
	char* request ="/config_ndpmon/use_reverse_hostlookups/text()";

	xmlXPathObjectPtr xmlobject = xmlXPathEval ((xmlChar*)request, xpctxt);
	if ((xmlobject->nodesetval==NULL) || (strcmp("1", (char*)xmlobject->nodesetval->nodeTab[0]->content)!=0)) use_reverse_hostlookups=0;
	else use_reverse_hostlookups=1;

	xmlXPathFreeObject (xmlobject);
	return;
}

/*Admin mail from the config file to send warnings
*/
void get_mail()
{
	char* request ="/config_ndpmon/admin_mail/text()";

	xmlXPathObjectPtr xmlobject = xmlXPathEval ((xmlChar*)request, xpctxt);
	strncpy(admin_mail,(char*)xmlobject->nodesetval->nodeTab[0]->content, ADMIN_MAIL_SIZE);

	xmlXPathFreeObject (xmlobject);
	return;
}

/* Initialize the syslogging */
void init_syslog()
{
	char *request ="/config_ndpmon/syslog_facility/text()";
	char  *value;
	int facility = -1;

	xmlXPathObjectPtr xmlobject = xmlXPathEval ((xmlChar*)request, xpctxt);
	value = (char *)xmlobject->nodesetval->nodeTab[0]->content;
	strncpy(syslog_facility,(char *)xmlobject->nodesetval->nodeTab[0]->content, SYSLOG_FACILITY_SIZE);
	if( !STRCMP(value,"LOG_LOCAL0") )
	{
		facility = LOG_LOCAL0;
	}
	else if( !STRCMP(value,"LOG_LOCAL0") )
	{
		facility = LOG_LOCAL0;
	}
	else if( !STRCMP(value,"LOG_LOCAL1") )
	{
		facility = LOG_LOCAL1;
	}
	else if( !STRCMP(value,"LOG_LOCAL2") )
	{
		facility = LOG_LOCAL2;
	}
	else if( !STRCMP(value,"LOG_LOCAL3") )
	{
		facility = LOG_LOCAL3;
	}
	else if( !STRCMP(value,"LOG_LOCAL4") )
	{
		facility = LOG_LOCAL4;
	}
	else if( !STRCMP(value,"LOG_LOCAL5") )
	{
		facility = LOG_LOCAL5;
	}
	else if( !STRCMP(value,"LOG_LOCAL6") )
	{
		facility = LOG_LOCAL6;
	}
	else if( !STRCMP(value,"LOG_LOCAL7") )
	{
		facility = LOG_LOCAL7;
	}
	else if( !STRCMP(value,"LOG_USER") )
	{
		facility = LOG_USER;
	}
	else if( !STRCMP(value,"LOG_MAIL") )
	{
		facility = LOG_MAIL;
	}
	else if( !STRCMP(value,"LOG_DAEMON") )
	{
		facility = LOG_DAEMON;
	}
	else if( !STRCMP(value,"LOG_AUTH") )
	{
		facility = LOG_AUTH;
	}
	else if( !STRCMP(value,"LOG_SYSLOG") )
	{
		facility = LOG_SYSLOG;
	}
	else if( !STRCMP(value,"LOG_LPR") )
	{
		facility = LOG_LPR;
	}
	else if( !STRCMP(value,"LOG_NEWS") )
	{
		facility = LOG_NEWS;
	}
	else if( !STRCMP(value,"LOG_UUCP") )
	{
		facility = LOG_UUCP;
	}
	else if( !STRCMP(value,"LOG_CRON") )
	{
		facility = LOG_CRON;
	}
	else if( !STRCMP(value,"LOG_AUTHPRIV") )
	{
		facility = LOG_AUTHPRIV;
	}
	else if( !STRCMP(value,"LOG_FTP") )
	{
		facility = LOG_FTP;
	}

	if (facility == -1)
		return;

	openlog ("NDPMon", LOG_NDELAY|LOG_CONS|LOG_PID, facility);
	syslog (LOG_NOTICE, "Program started by User %d", getuid ());

	xmlXPathFreeObject (xmlobject);
	return;
}

/*
 * Routers
 * */
void parse_routers()
{
	xmlXPathObjectPtr xmlobject;
	xmlNode *router;
        char *text, *request="/config_ndpmon/routers";

	xmlobject = xmlXPathEval ((xmlChar*)request, xpctxt);
	if (xmlobject->nodesetval==NULL) {
		xmlXPathFreeObject (xmlobject);
		return;
        }
	router = xmlobject->nodesetval->nodeTab[0]->children;

	while(router != NULL) {
		if (router->type == XML_ELEMENT_NODE && STRCMP(router->name,"router")==0) {
			struct ether_addr mac;
			struct in6_addr lla;
			uint8_t  param_curhoplimit=0;
			uint8_t  param_flags_reserved=0;
			uint16_t param_router_lifetime=0;
			uint32_t param_reachable_timer=0;
			uint32_t param_retrans_timer=0;
			uint32_t param_mtu=0;
			int params_volatile=1;
			prefix_t* tmp_prefix = NULL;
			address_t* tmp_address = NULL;
			xmlNode *param = router->children;
			int vlan_id = 4095;
			while(param != NULL) {
				if (param->type != XML_ELEMENT_NODE) {
					param = param->next;
					continue;
				}
                                /* We have an XML Element: */
				if( !STRCMP(param->name,"mac") ) {
					memcpy(&mac,ether_aton((char *)XML_GET_CONTENT(param->children)),sizeof(struct ether_addr));
				}
				else if( !STRCMP(param->name,"vlan_id") ) {
					text = (char*)XML_GET_CONTENT(param->children);
					vlan_id = atoi(text!=NULL?text:"4095");
				}
				else if( !STRCMP(param->name,"lla") ) {
					inet_pton(AF_INET6,(char *)XML_GET_CONTENT(param->children), &lla);
				}
				else if( !STRCMP(param->name,"param_curhoplimit") ) {
					text = (char*)XML_GET_CONTENT(param->children);
					param_curhoplimit = atoi(text!=NULL?text:"0");
					}
				else if( !STRCMP(param->name,"param_flags_reserved") ) {
					text = (char*)XML_GET_CONTENT(param->children);
					param_flags_reserved = atoi(text!=NULL?text:"0");
					}
				else if( !STRCMP(param->name,"param_router_lifetime") ) {
					text = (char*)XML_GET_CONTENT(param->children);
					param_router_lifetime = atoi(text!=NULL?text:"0");
				}
				else if( !STRCMP(param->name,"param_reachable_timer") ) {
					text = (char*)XML_GET_CONTENT(param->children);
					param_reachable_timer = strtoul(text!=NULL?text:"0", NULL, 10);
				}
				else if( !STRCMP(param->name,"param_retrans_timer") ) {
					text = (char*)XML_GET_CONTENT(param->children);
					param_retrans_timer = strtoul(text!=NULL?text:"0", NULL, 10);
				}
				else if( !STRCMP(param->name,"param_mtu") ) {
					text = (char*)XML_GET_CONTENT(param->children);
					param_mtu = strtoul(text!=NULL?text:"0", NULL, 10);
				}
				else if( !STRCMP(param->name,"params_volatile") ) {
					text = (char*)XML_GET_CONTENT(param->children);
					params_volatile = atoi(text!=NULL?text:"1");
				}
				else if( !STRCMP(param->name,"addresses") ) {
					xmlNode *address = param->children;
					while(address != NULL) {
						if (address->type == XML_ELEMENT_NODE &&  STRCMP(address->name,"address")==0 ) {
							/* Read address: */
							address_t* new_address = malloc(sizeof(address_t));
							if (new_address==NULL) {
								fprintf(stderr, "malloc failed.");
							}
							inet_pton(AF_INET6,(char *)XML_GET_CONTENT(address->children), &new_address->address);
							/* Add address to tmp address list: */
							new_address->next = tmp_address;
							tmp_address = new_address;
						}
						/* Fetch next address node: */
						address = address->next;
					}
				} /* end addresses */
				else if( !STRCMP(param->name,"prefixes") ) {
					xmlNode *prefix = param->children;
					while(prefix != NULL) {
						if (prefix->type == XML_ELEMENT_NODE && STRCMP(prefix->name,"prefix")==0) {
							/* Read prefix params: */
							xmlNode *prefix_param = prefix->children;
							prefix_t* new_prefix = malloc(sizeof(prefix_t));
							char buffer[INET6_ADDRSTRLEN];
							if (new_prefix==NULL) {
								fprintf(stderr, "malloc failed.");
							}
							memset(&new_prefix->prefix, 0, sizeof(struct in6_addr));
							new_prefix->mask = 0;
							new_prefix->param_valid_time = 0;
							new_prefix->param_preferred_time = 0;
							while(prefix_param != NULL) {
								if (prefix_param->type != XML_ELEMENT_NODE) {
									prefix_param = prefix_param->next;
									continue;
								}
				                                /* We have an XML Element: */
								if (STRCMP(prefix_param->name,"address")==0) {
									text=(char *)XML_GET_CONTENT(prefix_param->children);
									strncpy(buffer,text, INET6_ADDRSTRLEN);
									inet_pton(AF_INET6,buffer, &new_prefix->prefix);
								}
								else if (STRCMP(prefix_param->name,"mask")==0) {
									text=(char *)XML_GET_CONTENT(prefix_param->children);
									new_prefix->mask = atoi(text!=NULL?text:0);
								}
								else if (STRCMP(prefix_param->name,"param_flags_reserved")==0) {
									text=(char *)XML_GET_CONTENT(prefix_param->children);
									new_prefix->param_flags_reserved = atoi(text!=NULL?text:0);
								}
								else if (STRCMP(prefix_param->name,"param_valid_time")==0) {
									text=(char *)XML_GET_CONTENT(prefix_param->children);
									new_prefix->param_valid_time = strtoul(text!=NULL?text:"0", NULL, 10);
								}
								else if (STRCMP(prefix_param->name,"param_preferred_time")==0) {
									text=(char *)XML_GET_CONTENT(prefix_param->children);
									new_prefix->param_preferred_time = strtoul(text!=NULL?text:"0", NULL, 10);
								}
								prefix_param = prefix_param->next;
							}
							/* Add prefix to tmp list:*/
							new_prefix->next = tmp_prefix;
							tmp_prefix = new_prefix;
						}
						/* Fetch next prefix node: */
						prefix = prefix->next;
					}
				} /* end prefixes */
				/* Fetch next router param: */
				param = param->next;
			} /* end router params */
			/* Add router to the router list: */
			router_add(
				&routers, vlan_id, &mac, &lla,
				param_curhoplimit,
				param_flags_reserved,
				param_router_lifetime,
				param_reachable_timer,
				param_retrans_timer,
				param_mtu,
				params_volatile
			);
			while (tmp_prefix!=NULL) {
				prefix_t* current=tmp_prefix;
				router_add_prefix(
					routers, vlan_id, lla, mac,
					current->prefix,
					current->mask,
					current->param_flags_reserved,
					current->param_valid_time,
					current->param_preferred_time
				);
				tmp_prefix = current->next;
				free(current);
			}
			while (tmp_address!=NULL) {
				address_t* current=tmp_address;
				router_add_address(routers, vlan_id, mac, current->address);
				tmp_address = current->next;
				free(current);
			}
		} /* end is XML element and router */
		/* Fetch next router node: */
		router = router->next;
	}
	xmlXPathFreeObject (xmlobject);
}

#if 0
void parse_routers()
{
        xmlDoc *doc = NULL;
        xmlNode *root_element = NULL;
        xmlNode *current = NULL;
        char* c;

	/*parse the file and get the DOM */
        doc = xmlReadFile(config_path, NULL, 0);	

	/*Get the root element node */
        root_element = xmlDocGetRootElement(doc);
        current = root_element->children;

	request ="/config_ndpmon/actions_low_pri/sendmail/text()";
	xmlobject = xmlXPathEval ((xmlChar*)request, xpctxt);
	if ((xmlobject->nodesetval!=NULL) || (strcmp("1", (char*)xmlobject->nodesetval->nodeTab[0]->content)!=0)) action_low_pri.sendmail=0;
	else action_low_pri.sendmail=1; 
	xmlXPathFreeObject (xmlobject);


	while(current != NULL)
	{
		if (current->type == XML_ELEMENT_NODE)
		{
			if( !STRCMP(current->name,"routers") )
			{
				xmlNode *router = current->children;
				while(router != NULL)
				{
					if (router->type == XML_ELEMENT_NODE)
					{
						if( !STRCMP(router->name,"router") )
						{
							struct ether_addr mac;
							struct in6_addr lla;
							uint8_t  param_curhoplimit=0;
							uint8_t  param_flags_reserved=0;
							uint16_t param_router_lifetime=0;
							uint32_t param_reachable_timer=0;
							uint32_t param_retrans_timer=0;
							xmlNode *param = router->children;
							while(param != NULL)
							{
								if (param->type == XML_ELEMENT_NODE)
								{
									if( !STRCMP(param->name,"mac") )
									{
										memcpy(&mac,ether_aton((char *)XML_GET_CONTENT(param->children)),sizeof(struct ether_addr));
									}
									else if( !STRCMP(param->name,"lla") )
									{
										inet_pton(AF_INET6,(char *)XML_GET_CONTENT(param->children), &lla);
									}
									else if( !STRCMP(param->name,"param_curhoplimit") )
									{
										char* text = (char*)XML_GET_CONTENT(param->children);
										param_curhoplimit = atoi(text!=NULL?text:"0");
									}
									else if( !STRCMP(param->name,"param_flags_reserved") )
									{
										char* text = (char*)XML_GET_CONTENT(param->children);
										param_flags_reserved = atoi(text!=NULL?text:"0");
									}
									else if( !STRCMP(param->name,"param_router_lifetime") )
									{
										char* text = (char*)XML_GET_CONTENT(param->children);
										param_router_lifetime = atoi(text!=NULL?text:"0");
									}
									else if( !STRCMP(param->name,"param_reachable_timer") )
									{
										char* text = (char*)XML_GET_CONTENT(param->children);
										param_reachable_timer = atoi(text!=NULL?text:"0");
									}
									else if( !STRCMP(param->name,"param_retrans_timer") )
									{
										char* text = (char*)XML_GET_CONTENT(param->children);
										param_retrans_timer = atoi(text!=NULL?text:"0");
										add_router(&routers, &mac, &lla, param_curhoplimit, param_flags_reserved, param_router_lifetime, param_reachable_timer, param_retrans_timer);
									}
									else if( !STRCMP(param->name,"addresses") )
									{
										xmlNode *address = param->children;
										while(address != NULL)
										{
											if (address->type == XML_ELEMENT_NODE)
											{
												if( !STRCMP(address->name,"address") )
												{
													struct in6_addr addr;
													inet_pton(AF_INET6,(char *)XML_GET_CONTENT(address->children), &addr);
													add_router_address(&routers, mac, addr);
												}
											}
											address = address->next;
										}
									}
									else if( !STRCMP(param->name,"prefixes") )
									{
										xmlNode *prefix = param->children;
										while(prefix != NULL)
										{
											if (prefix->type == XML_ELEMENT_NODE)
											{
												if( !STRCMP(prefix->name,"prefix") )
												{
													struct in6_addr addr;
													int mask=0;
													char buffer[INET6_ADDRSTRLEN];
													struct _xmlAttr *attr = prefix->properties;

													while(attr != NULL)
													{
														if (attr->type == XML_ATTRIBUTE_NODE)
														{
															if( !STRCMP(attr->name,"mask") )
															{
																c=(char *)XML_GET_CONTENT(attr->children);
																mask = atoi(c);
/*																mask = atoi((char *)XML_GET_CONTENT(attr->children));  */
															}
														}
														attr = attr->next;
													}

													c=(char *)XML_GET_CONTENT(prefix->children);
													strncpy(buffer,c, INET6_ADDRSTRLEN);
/*													strcpy(buffer,(char *)XML_GET_CONTENT(prefix->children));	*/
													inet_pton(AF_INET6,buffer, &addr);

													add_prefix(&routers, lla, mac, addr,mask);
												}
											}
											prefix = prefix->next;
										}
									}
								}
								param = param->next;
							}
						}
					}
					router = router->next;
				}
			}
		}
		current = current->next;
	}

	xmlFreeDoc(doc);
	return;
}
#endif

#ifdef _COUNTERMEASURES_
/** Parse counter measures configuration. */
void parse_countermeasures() {
    char
        *config_kill_illegitimate_router=NULL,
        *config_kill_wrong_prefix=NULL,
        *config_propagate_router_params=NULL,
        *config_indicate_ndpmon_presence=NULL,
        *request;
    xmlXPathObjectPtr xmlobject;

    request ="/config_ndpmon/countermeasures/kill_illegitimate_router/text()";
    xmlobject = xmlXPathEval ((xmlChar*)request, xpctxt);
    if (xmlobject->nodesetval!=NULL) {
        config_kill_illegitimate_router = (char*)xmlobject->nodesetval->nodeTab[0]->content;
    }
    xmlXPathFreeObject (xmlobject);

    request ="/config_ndpmon/countermeasures/kill_wrong_prefix/text()";
    xmlobject = xmlXPathEval ((xmlChar*)request, xpctxt);
    if (xmlobject->nodesetval!=NULL) {
        config_kill_wrong_prefix = (char*)xmlobject->nodesetval->nodeTab[0]->content;
    }
    xmlXPathFreeObject (xmlobject);

    request ="/config_ndpmon/countermeasures/propagate_router_params/text()";
    xmlobject = xmlXPathEval ((xmlChar*)request, xpctxt);
    if (xmlobject->nodesetval!=NULL) {
        config_propagate_router_params = (char*)xmlobject->nodesetval->nodeTab[0]->content;
    }
    xmlXPathFreeObject (xmlobject);

    request ="/config_ndpmon/countermeasures/indicate_ndpmon_presence/text()";
    xmlobject = xmlXPathEval ((xmlChar*)request, xpctxt);
    if (xmlobject->nodesetval!=NULL) {
        config_indicate_ndpmon_presence = (char*)xmlobject->nodesetval->nodeTab[0]->content;
    }
    xmlXPathFreeObject (xmlobject);

    cm_guard_init_all(
        config_kill_illegitimate_router,
        config_kill_wrong_prefix,
        config_propagate_router_params,
        config_indicate_ndpmon_presence
    );

}
#endif


void parse_config()
{
	FILE *f = NULL;

	fprintf(stderr,"Reading configuration file: \"%s\" ...\n",config_path);
	
	if( (f=fopen (config_path, "r")) == NULL )
	{
		perror("fopen");
		exit(1);
	}

	LIBXML_TEST_VERSION;

	/* create a parser context */
	ctxt = xmlNewParserCtxt();
	if (ctxt == NULL)
	{
		fprintf(stderr, "Failed to allocate parser context\n");
		fclose(f);
		return;
	}
	/* parse the file, activating the DTD validation option */
	doc = xmlCtxtReadFile(ctxt, config_path, NULL, XML_PARSE_DTDVALID);
	/* check if parsing suceeded */
	if (doc == NULL)
	{
		fprintf(stderr, "Failed to parse %s\n", config_path);
	}
	else
	{
		/* check if validation suceeded */
		if (ctxt->valid == 0)
			fprintf(stderr, "Failed to validate %s\n", config_path);
		/* free up the resulting document */
		else
		{
			xmlXPathInit();
			xpctxt= xmlXPathNewContext(doc);
		}
	}

	autoconf();
	get_mail();
	init_syslog();
	parse_routers();
	parse_actions();
#ifdef _COUNTERMEASURES_
        parse_countermeasures();
#endif
	free_xml();
	fclose(f);
	fprintf(stderr,"    Done.\n");
}

void parse_cache(char *filename)
{
	xmlDoc *doc = NULL;
	xmlNode *root_element = NULL;
	xmlNode *neighbor = NULL;
	char *c;

	LIBXML_TEST_VERSION;

	/*parse the file and get the DOM */
	doc = xmlReadFile(cache_path, NULL, 0);	

	/*Get the root element node */
	root_element = xmlDocGetRootElement(doc);
	neighbor = root_element->children;

	while(neighbor != NULL)
	{
		if( !STRCMP(neighbor->name,"neighbor") )
		{
			struct in6_addr lla;
			struct ether_addr mac, eth;
			xmlNode *param = neighbor->children;
			uint16_t vlan_id = 4095;

			while(param != NULL)
			{
				if (param->type == XML_ELEMENT_NODE)
				{
					if( !STRCMP(param->name,"mac") )
					{
						c=(char *)XML_GET_CONTENT(param->children);
						memcpy(&mac,ether_aton(c),sizeof(struct ether_addr));
/*						memcpy(&mac,ether_aton((char *)XML_GET_CONTENT(param->children)),sizeof(struct ether_addr));	*/
						add_neighbor(&neighbors, vlan_id, mac);
					}
					else if( !STRCMP(param->name,"vlan_id") ) {
						char *text = (char*)XML_GET_CONTENT(param->children);
						vlan_id = atoi(text!=NULL?text:"4095");
					}
					else if( !STRCMP(param->name,"time") )
					{
						c=(char *)XML_GET_CONTENT(param->children);
						set_neighbor_timer(&neighbors, vlan_id, mac,atoi(c));
/*						set_neighbor_timer(&neighbors, mac,atoi((char *)XML_GET_CONTENT(param->children)));		*/
					}
					else if( !STRCMP(param->name,"lla") )
					{
						if(param->children != NULL)
						{
							inet_pton(AF_INET6,(char *)XML_GET_CONTENT(param->children), &lla);
							set_neighbor_lla(&neighbors, vlan_id, mac, lla);
						}
					}
					else if( !STRCMP(param->name,"addresses") )
					{
						xmlNode *address = param->children;
						while(address != NULL)
						{
							if (address->type == XML_ELEMENT_NODE)
							{
								if( !STRCMP(address->name,"address") )
								{
									struct in6_addr addr;
									struct _xmlAttr *attr = address->properties;
									inet_pton(AF_INET6,(char *)XML_GET_CONTENT(address->children), &addr);
									add_neighbor_ip(&neighbors, vlan_id, mac, addr);

									while(attr != NULL)
									{
										if (attr->type == XML_ATTRIBUTE_NODE)
										{
											if( !STRCMP(attr->name,"lastseen") )
											{
												set_neighbor_address_timer(&neighbors, vlan_id, mac, addr, (time_t) atoi((const char *)(attr->children->content)));
											}
											else if ( !STRCMP(attr->name,"firstseen") )
											{
												set_neighbor_first_address_timer(&neighbors, vlan_id, mac, addr, (time_t) atoi((const char *)(attr->children->content)));
											}
										}
										attr = attr->next;
									}

								}
							}
							address = address->next;
						}
					}
					else if( !STRCMP(param->name,"old_mac") )
					{
						xmlNode *old = param->children;
						while(old != NULL)
						{
							if (old->type == XML_ELEMENT_NODE)
							{
								if( !STRCMP(old->name,"mac") )
								{
									struct _xmlAttr *attr = old->properties;
									
									memcpy(&eth,ether_aton((char *)XML_GET_CONTENT(old->children)),sizeof(struct ether_addr));
									add_neighbor_old_mac(&neighbors, vlan_id, lla, eth);
									
									while(attr != NULL)
									{
										if (attr->type == XML_ATTRIBUTE_NODE)
										{
											if( !STRCMP(attr->name,"last") )
											{
												neighbor_set_last_mac(&neighbors, vlan_id, lla, eth);
											}
										}
										attr = attr->next;
									}

								}
							}
							old = old->next;
						}
					}
								
				}
				param = param->next;
			}
		}
		neighbor = neighbor->next;
	}

	xmlFreeDoc(doc);
	return;
}

void write_config()
{
	const char *uri=config_path;
	int rc;
	char str_ip[IP6_STR_SIZE];
	xmlTextWriterPtr writer;
	router_list_t *tmp = routers;
#ifdef _COUNTERMEASURES_
	char config_kill_illegitimate_router[CM_GUARD_REPRESENTATION_SIZE];
	char config_kill_wrong_prefix[CM_GUARD_REPRESENTATION_SIZE];
	char config_propagate_router_params[CM_GUARD_REPRESENTATION_SIZE];
	char config_indicate_ndpmon_presence[CM_GUARD_REPRESENTATION_SIZE];
#endif

	printf("Writing config...\n");
	print_routers(routers);

	/* Create a new XmlWriter for uri, with no compression. */
	writer = xmlNewTextWriterFilename(uri, 0);
	if (writer == NULL)
	{
		printf("testXmlwriterFilename: Error creating the xml writer\n");
		return;
	}

	xmlTextWriterSetIndent(writer, 1);

	/* Start the document with the xml default for the version,
	 * encoding ISO 8859-1 and the default for the standalone
	 * declaration. */
	rc = xmlTextWriterStartDocument(writer, NULL, MY_ENCODING, NULL);
	if (rc < 0)
	{
		printf("testXmlwriterFilename: Error at xmlTextWriterStartDocument\n");
		return;
	}

	xmlTextWriterStartDTD	(writer, (xmlChar*)"config_ndpmon", NULL, (xmlChar*)dtd_config_path);
	xmlTextWriterEndDTD (writer);

	/* Give the stylesheet for display in the web interface */
	xmlTextWriterWriteRaw(writer, (xmlChar*)"<?xml-stylesheet type=\"text/xsl\" href=\"config.xsl\" ?>\n");

	/* Start an element named "config_ndpmon". Since this is the first
	 * element, this will be the root element of the document. */
	rc = xmlTextWriterStartElement(writer, BAD_CAST "config_ndpmon");
	if (rc < 0)
	{
		printf("testXmlwriterFilename: Error at xmlTextWriterStartElement\n");
		return;
	}

	/* Attribute ignor_autoconf */
	rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "ignor_autoconf", "%d", ignor_autoconf);
	if (rc < 0)
	{
		printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
		return;
	}
	
	/* Attribute syslog_facility */
	rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "syslog_facility", "%s", syslog_facility);
	if (rc < 0)
	{
		printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
		return;
	}

	/* Attribute admin_mail */
	rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "admin_mail", "%s", admin_mail);
	if (rc < 0)
	{
		printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
		return;
	}


	/* Elements of actions_low_pri */
	rc =  xmlTextWriterStartElement(writer, BAD_CAST "actions_low_pri");
	if (rc < 0)
	{
		printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
		return;
	}

	/* Attribute sendmail */
	rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "sendmail", "%d", action_low_pri.sendmail);
	if (rc < 0)
	{
		printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
		return;
	}

	/* Attribute syslog */
	rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "syslog", "%d", action_low_pri.syslog);
	if (rc < 0)
	{
		printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
		return;
	}

	
	/* Attribute exec_pipe_program */
	rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "exec_pipe_program", "%s", action_low_pri.exec_pipe_program);
	if (rc < 0)
	{
		printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
		return;
	}


	/* Close  actions_low_pri  */
	rc = xmlTextWriterEndElement(writer);
	if (rc < 0)
	{
		printf("testXmlwriterFilename: Error at xmlTextWriterEndElement\n");
		return;
	}


	/* Elements of actions_high_pri */
	rc =  xmlTextWriterStartElement(writer, BAD_CAST "actions_high_pri");
	if (rc < 0)
	{
		printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
		return;
	}

	/* Attribute sendmail */
	rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "sendmail", "%d", action_high_pri.sendmail);
	if (rc < 0)
	{
		printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
		return;
	}

	/* Attribute syslog */
	rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "syslog", "%d", action_high_pri.syslog);
	if (rc < 0)
	{
		printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
		return;
	}

	
	/* Attribute exec_pipe_program */
	rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "exec_pipe_program", "%s", action_high_pri.exec_pipe_program);
	if (rc < 0)
	{
		printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
		return;
	}


	/* Close  actions_high_pri  */
	rc = xmlTextWriterEndElement(writer);
	if (rc < 0)
	{
		printf("testXmlwriterFilename: Error at xmlTextWriterEndElement\n");
		return;
	}


	/* Attribute use_reverse_hostlookups */
	rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "use_reverse_hostlookups", "%d", use_reverse_hostlookups);
	if (rc < 0)
	{
		printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
		return;
	}

	

	/* Start an element named routers containing the routers' definition */
	rc = xmlTextWriterStartElement(writer, BAD_CAST "routers");
	if (rc < 0)
	{
		printf("testXmlwriterFilename: Error at xmlTextWriterStartElement\n");
		return;
	}


	/*for each router a new neighbor with its attributes is created in the file */
	while(tmp != NULL)
	{
		address_t *tmp_address = tmp->addresses;
		prefix_t *tmp_prefix   = tmp->prefixes;
		ipv6_ntoa(str_ip, tmp->lla);

		/* Start an element named "router" as child of routers. */
		rc = xmlTextWriterStartElement(writer, BAD_CAST "router");
		if (rc < 0) goto start_element_error;
		/* Element mac */
		rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "mac", "%s", ether_ntoa(&(tmp->mac)));
		if (rc < 0) goto format_element_error;
		/* Element lla */
		rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "lla", "%s", str_ip);
		if (rc < 0) goto format_element_error;
		/* Elements for Router Advertisement Parameters: */
		rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "param_curhoplimit", "%u", tmp->param_curhoplimit);
		if (rc < 0) goto format_element_error;
		rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "param_flags_reserved", "%u", tmp->param_flags_reserved);
		if (rc < 0) goto format_element_error;
		rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "param_router_lifetime", "%u", tmp->param_router_lifetime);
		if (rc < 0) goto format_element_error;
		rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "param_reachable_timer", "%u", tmp->param_reachable_timer);
		if (rc < 0) goto format_element_error;
		rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "param_retrans_timer", "%u", tmp->param_retrans_timer);
		if (rc < 0) goto format_element_error;
		rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "param_mtu", "%u", tmp->param_mtu);
		if (rc < 0) goto format_element_error;
		rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "params_volatile", "%i", tmp->params_volatile);
		if (rc < 0) goto format_element_error;

		/* Start an element named prefixes */
		rc = xmlTextWriterStartElement(writer, BAD_CAST "prefixes");
		if (rc < 0) goto start_element_error;
		while(tmp_prefix != NULL)
		{
			ipv6_ntoa(str_ip, tmp_prefix->prefix);
			rc = xmlTextWriterStartElement(writer, BAD_CAST "prefix");
			if (rc < 0) goto start_element_error;
			/* Elements for prefix address and mask:*/
			rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "address", "%s", str_ip);
			if (rc < 0) goto format_element_error;		
			rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "mask", "%i", tmp_prefix->mask);
			if (rc < 0) goto format_element_error;		
                        /* Elements for prefix parameters:*/
			rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "param_flags_reserved", "%u", tmp_prefix->param_flags_reserved);
			if (rc < 0) goto format_element_error;		
			rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "param_valid_time", "%u", tmp_prefix->param_valid_time);
			if (rc < 0) goto format_element_error;		
			rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "param_preferred_time", "%u", tmp_prefix->param_preferred_time);
			if (rc < 0) goto format_element_error;
			rc = xmlTextWriterEndElement(writer);
			if (rc < 0) goto end_element_error;
                        /* Fetch next prefix:*/
			tmp_prefix = tmp_prefix->next;
		}   

		rc = xmlTextWriterEndElement(writer);
		if (rc < 0) goto end_element_error;

		/* Addresses */
		rc = xmlTextWriterStartElement(writer, BAD_CAST "addresses");
		if (rc < 0) goto start_element_error;

		while(tmp_address != NULL)
		{
			ipv6_ntoa(str_ip, tmp_address->address);
			/*Element for address.*/
			rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "address", "%s", str_ip);
			if (rc < 0) goto format_element_error;
			tmp_address = tmp_address->next;
		}    

		/* close addresses */
		rc = xmlTextWriterEndElement(writer);
		if (rc < 0)
		{
			printf("testXmlwriterFilename: Error at xmlTextWriterEndElement\n");
			return;
		}

		/* close router */
		rc = xmlTextWriterEndElement(writer);
		if (rc < 0)
		{
			printf("testXmlwriterFilename: Error at xmlTextWriterEndElement\n");
			return;
		}

		tmp = tmp->next;
	}

	/* Close routers  */
	rc = xmlTextWriterEndElement(writer);
	if (rc < 0)
	{
		printf("testXmlwriterFilename: Error at xmlTextWriterEndElement\n");
		return;
	}

#ifdef _COUNTERMEASURES_
	cm_guard_all_to_representation(
		config_kill_illegitimate_router,
		config_kill_wrong_prefix,
		config_propagate_router_params,
		config_indicate_ndpmon_presence
	);

	/* Start an element named countermeasures containing the counter measures configuration. */
	rc = xmlTextWriterStartElement(writer, BAD_CAST "countermeasures");
	if (rc < 0) goto start_element_error;

	/* Write guard configurations. */
	rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "kill_illegitimate_router", "%s", config_kill_illegitimate_router);
	if (rc < 0) goto format_element_error;
	rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "kill_wrong_prefix", "%s", config_kill_wrong_prefix);
	if (rc < 0) goto format_element_error;
	rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "propagate_router_params", "%s", config_propagate_router_params);
	if (rc < 0) goto format_element_error;
	rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "indicate_ndpmon_presence", "%s", config_indicate_ndpmon_presence);
	if (rc < 0) goto format_element_error;

	/* Close countermeasures  */
	rc = xmlTextWriterEndElement(writer);
	if (rc < 0) goto end_element_error;
#endif

	/* Close config_ndpmon */
	rc = xmlTextWriterEndElement(writer);
	if (rc < 0)
	{
		printf("testXmlwriterFilename: Error at xmlTextWriterEndElement\n");
		return;
	}

	xmlFreeTextWriter(writer);
	return;

	format_element_error:
	printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
	xmlFreeTextWriter(writer);
	return;
        start_element_error:
	printf("testXmlwriterFilename: Error at xmlTextWriterStartElement\n");
	xmlFreeTextWriter(writer);
	return;
        end_element_error:
	printf("testXmlwriterFilename: Error at xmlTextWriterEndElement\n");
	xmlFreeTextWriter(writer);
	return;
}


void write_cache()
{
	const char *uri=cache_path;
	int rc;
	char str_ip[IP6_STR_SIZE];
	xmlTextWriterPtr writer;
	neighbor_list_t *tmp = neighbors;
	FILE *dat = NULL;

	printf("Writing cache...\n");

	/* Create a new XmlWriter for uri, with no compression. */
	writer = xmlNewTextWriterFilename(uri, 0);
	if (writer == NULL)
	{
		printf("testXmlwriterFilename: Error creating the xml writer\n");
		return;
	}

	xmlTextWriterSetIndent(writer, 1);

	/* Start the document with the xml default for the version,
	 * encoding ISO 8859-1 and the default for the standalone
	 * declaration. */
	rc = xmlTextWriterStartDocument(writer, NULL, MY_ENCODING, NULL);
	if (rc < 0)
	{
		printf("testXmlwriterFilename: Error at xmlTextWriterStartDocument\n");
		return;
	}

	xmlTextWriterStartDTD	(writer, (xmlChar*)"neighbor_list", NULL, (xmlChar*)dtd_path);
	xmlTextWriterEndDTD (writer);	

	/* Give the stylesheet for display in the web interface */
	xmlTextWriterWriteRaw(writer, (xmlChar*)"<?xml-stylesheet type=\"text/xsl\" href=\"neighbor.xsl\" ?>\n");

	/* Start an element named "neighbor_list". Since this is the first
	 * element, this will be the root element of the document. */
	rc = xmlTextWriterStartElement(writer, BAD_CAST "neighbor_list");
	if (rc < 0)
	{
		printf("testXmlwriterFilename: Error at xmlTextWriterStartElement\n");
		return;
	}

	/*for each neighbor in the cache a new neighbor element with its 
	 *attributes is created in the file */
	while(tmp != NULL)
	{
		address_t *atmp = tmp->addresses;
		ethernet_t *etmp = tmp->old_mac;
		/* to format the time */
		time_t timep;
		char time_str[27];
		char vlan_str[10];

		/* Start an element named "neighbor" as child of neighbor_list. */
		rc = xmlTextWriterStartElement(writer, BAD_CAST "neighbor");
		if (rc < 0)
		{
			printf("testXmlwriterFilename: Error at xmlTextWriterStartElement\n");
			return;
		}
		/* Attribute vlan_id */

		snprintf(vlan_str,9,"%d",(int) tmp->vlan_id);
		rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "vlan_id", "%s", vlan_str);
		if (rc < 0)
		{
			printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
			return;
		}

		/* Attribute mac */
		rc = xmlTextWriterStartElement(writer, BAD_CAST "mac");
		if (rc < 0)
		{
			printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
			return;
		}
#ifdef _MACRESOLUTION_
		rc = xmlTextWriterWriteFormatAttribute(writer, BAD_CAST "vendor", "%s", tmp->vendor);
		if (rc < 0)
		{
			printf("testXmlwriterFilename: Error at xmlTextWriterWriteAttribute %d\n",rc);
		}
#endif
		rc = xmlTextWriterWriteRaw(writer, BAD_CAST ether_ntoa(&(tmp->mac)));
		if (rc < 0)
		{
			printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
			return;
		}

		rc = xmlTextWriterEndElement(writer);
		if (rc < 0)
		{
			printf("testXmlwriterFilename: Error at xmlTextWriterEndElement\n");
			return;
		}
		/*
		rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "mac", "%s", ether_ntoa(&(tmp->mac)));
		if (rc < 0)
		{
			printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
			return;
		}
		*/

		/* Attribute lla */
		ipv6_ntoa(str_ip, tmp->lla);
		rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "lla", "%s", str_ip);
		if (rc < 0)
		{
			printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
			return;
		}

		/* element time */
		rc = xmlTextWriterStartElement(writer, BAD_CAST "time");
		if (rc < 0)
		{
			printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
			return;
		}

#if 0
		rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "time", "%d",tmp->timer);
		if (rc < 0)
		{
			printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
			return;
		}
#endif

		/* convert to str representation in order to display it in the web interface */
		timep = tmp->timer;
		strcpy(time_str, ctime(&timep));
		rc = xmlTextWriterWriteFormatAttribute(writer, BAD_CAST "timestr", "%s", time_str);
		if (rc < 0)
		{
			printf("testXmlwriterFilename: Error at xmlTextWriterWriteAttribute %d\n",rc);
		}

		/* the content */
		snprintf(time_str,27,"%d",(int) tmp->timer);
		rc = xmlTextWriterWriteRaw(writer, BAD_CAST time_str);
		if (rc < 0)
		{
			printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
			return;
		}

		rc = xmlTextWriterEndElement(writer);
		if (rc < 0)
		{
			printf("testXmlwriterFilename: Error at xmlTextWriterEndElement\n");
			return;
		}

		/* Addresses */
		/* rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "adresses", NULL, NULL); */
		rc = xmlTextWriterStartElement(writer, BAD_CAST "addresses");
		if (rc < 0)
		{
			printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
			return;
		}

		while(atmp != NULL)
		{
			/* to store a char * version of the int + \O */
			ipv6_ntoa(str_ip, atmp->address);

			/* the address element */
			rc = xmlTextWriterStartElement(writer, BAD_CAST "address");
			if (rc < 0)
			{
				printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
				return;
			}

			/* lastseen timer */
			rc = xmlTextWriterWriteFormatAttribute(writer, BAD_CAST "lastseen", "%d", (int)atmp->lastseen);
			if (rc < 0)
			{
				printf("testXmlwriterFilename: Error at xmlTextWriterWriteAttribute %d\n",rc);
			}

			/* convert to str representation in order to display it in the web interface */
			timep = atmp->lastseen;
			strcpy(time_str, ctime(&timep));
			rc = xmlTextWriterWriteFormatAttribute(writer, BAD_CAST "lastseenstr", "%s", time_str);
			if (rc < 0)
			{
				printf("testXmlwriterFilename: Error at xmlTextWriterWriteAttribute %d\n",rc);
			}

			/* firstseen timer */
			rc = xmlTextWriterWriteFormatAttribute(writer, BAD_CAST "firstseen", "%d", (int)atmp->firstseen);
			if (rc < 0)
			{
				printf("testXmlwriterFilename: Error at xmlTextWriterWriteAttribute %d\n",rc);
			}

			/* convert to str representation in order to display it in the web interface */
			timep = atmp->firstseen;
			strcpy(time_str, ctime(&timep));
			rc = xmlTextWriterWriteFormatAttribute(writer, BAD_CAST "firstseenstr", "%s", time_str);
			if (rc < 0)
			{
				printf("testXmlwriterFilename: Error at xmlTextWriterWriteAttribute %d\n",rc);
			}

			/* the content */
			rc = xmlTextWriterWriteRaw(writer, BAD_CAST str_ip);
			if (rc < 0)
			{
				printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
				return;
			}
	
			rc = xmlTextWriterEndElement(writer);
			if (rc < 0)
			{
				printf("testXmlwriterFilename: Error at xmlTextWriterEndElement\n");
				return;
			}

			atmp = atmp->next;
		}    

		rc = xmlTextWriterEndElement(writer);
		if (rc < 0)
		{
			printf("testXmlwriterFilename: Error at xmlTextWriterEndElement\n");
			return;
		}


		/* Old Mac */
		rc = xmlTextWriterStartElement(writer, BAD_CAST "old_mac");
		if (rc < 0)
		{
			printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
			return;
		}

		while(etmp != NULL)
		{
			rc = xmlTextWriterStartElement(writer, BAD_CAST "mac");
			if (rc < 0)
			{
				printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
				return;
			}
			if(!MEMCMP(&(etmp->mac),&(tmp->previous_mac), sizeof(struct ether_addr)))
			{
				rc = xmlTextWriterWriteFormatAttribute(writer, BAD_CAST "last", "%s", "true");
				if (rc < 0)
				{
					printf("testXmlwriterFilename: Error at xmlTextWriterWriteAttribute %d\n",rc);
				}
			}
#ifdef _MACRESOLUTION_
			rc = xmlTextWriterWriteFormatAttribute(writer, BAD_CAST "vendor", "%s", etmp->vendor);
			if (rc < 0)
			{
				printf("testXmlwriterFilename: Error at xmlTextWriterWriteAttribute %d\n",rc);
			}
#endif
			rc = xmlTextWriterWriteRaw(writer, BAD_CAST ether_ntoa(&(etmp->mac)));
			if (rc < 0)
			{
				printf("testXmlwriterFilename: Error at xmlTextWriterWriteFormatElement\n");
				return;
			}

			rc = xmlTextWriterEndElement(writer);
			if (rc < 0)
			{
				printf("testXmlwriterFilename: Error at xmlTextWriterEndElement\n");
				return;
			}

			etmp = etmp->next;
		}    

		rc = xmlTextWriterEndElement(writer);
		if (rc < 0)
		{
			printf("testXmlwriterFilename: Error at xmlTextWriterEndElement\n");
			return;
		}

		/* Close neighbor */
		rc = xmlTextWriterEndElement(writer);
		if (rc < 0)
		{
			printf("testXmlwriterFilename: Error at xmlTextWriterEndElement\n");
			return;
		}
		tmp = tmp->next;
	}

	/* Close neighbor_list */
	rc = xmlTextWriterEndElement(writer);
	if (rc < 0)
	{
		printf("testXmlwriterFilename: Error at xmlTextWriterEndElement\n");
		return;
	}

	xmlFreeTextWriter(writer);

	/* Write in discovery_history.dat the number of neighbors in the cache for statistics */
	if( (dat = fopen(discovery_history_path,"a")) != NULL)
	{
		fprintf(dat,"%d %d\n", (int)time(NULL), nb_neighbor(neighbors) );
		fclose(dat);
	}

}
