/********************************************************************************
NDPMon - Neighbor Discovery Protocol Monitor
Copyright (C) 2006 MADYNES Project, LORIA - INRIA Lorraine (France)

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

Author Info:
  Name: Thibault Cholez
  Mail: thibault.cholez@esial.uhp-nancy.fr

Maintainer:
  Name: Frederic Beck
  Mail: frederic.beck@loria.fr

MADYNES Project, LORIA-INRIA Lorraine, hereby disclaims all copyright interest in
the tool 'NDPMon' (Neighbor Discovery Protocol Monitor) written by Thibault Cholez.

Olivier Festor, Scientific Leader of the MADYNEs Project, 20 August 2006
***********************************************************************************/


#include "alarm.h"
#include "membounds.h"

static int watch;


/*Define if warnings must be reported*/
void set_alarm(int b)
{
	watch = b;
}

/*Resolve IPv6 to Hostname*/
void gethostfromipv6(char* ipv6adr,char* hostname) 
{
	struct in6_addr addrbuf;
	struct hostent *h;

	if (0 == inet_pton(AF_INET6, ipv6adr, &addrbuf)) { 
		snprintf(hostname, HOST_NAME_SIZE, "<%s>",hstrerror(h_errno));
		if (DEBUG) fprintf(stderr,"Problem (inet_pton) looking up \"%." HOST_NAME_LEN_FSTR "s\": %." HOST_NAME_LEN_FSTR "s\n", ipv6adr, hstrerror(h_errno)); 
		return;
	}
	h=gethostbyaddr(&addrbuf,sizeof(addrbuf),AF_INET6);
	if (h) { 
		snprintf(hostname, HOST_NAME_SIZE, "%s", h->h_name);
	} else { 
		snprintf(hostname, HOST_NAME_SIZE, "<%s>",hstrerror(h_errno));
		if (DEBUG) fprintf(stderr, "Problem (gethostbyaddr) looking up \"%." HOST_NAME_LEN_FSTR "s\": %." HOST_NAME_LEN_FSTR "s\n", ipv6adr, hstrerror(h_errno)); 
	}
	return;
}                                   

/*Notify the waning message from buffer
 *according to the severity
 */
void notify(int result, char* buffer, char* reason, struct ether_addr* mac_addr, char* ipv6, struct ether_addr* mac_addr2)
{
	char hostname[HOST_NAME_SIZE];
	if(watch)
	{
		char mailmessage[MAIL_MESSAGE_SIZE];
		/* Build mailmessage to send or to pipe to external program */
		snprintf(mailmessage, MAIL_MESSAGE_SIZE, "%-9s%s\n","Reason:",reason);
		if (mac_addr != NULL) {
			snprintf(mailmessage, MAIL_MESSAGE_SIZE, "%s%-9s%s\n",mailmessage,"MAC:",ether_ntoa(mac_addr));
#ifdef _MACRESOLUTION_
       			snprintf(mailmessage,MAIL_MESSAGE_SIZE, "%s%-9s%s\n",mailmessage,"Vendor:",get_manufacturer(manuf, *mac_addr));
#endif
		}
		if (mac_addr2 != NULL) {
			snprintf(mailmessage, MAIL_MESSAGE_SIZE, "%s%-9s%s\n",mailmessage,"MAC:",ether_ntoa(mac_addr2));
#ifdef _MACRESOLUTION_
       			snprintf(mailmessage, MAIL_MESSAGE_SIZE, "%s%-9s%s\n",mailmessage,"Vendor:",get_manufacturer(manuf, *mac_addr2));
#endif
		}
		if (strlen(ipv6)>0) {
                        snprintf(mailmessage, MAIL_MESSAGE_SIZE, "%s%-9s%s\n",mailmessage,"IPv6:",ipv6);
                        if (use_reverse_hostlookups==1) {
	                        gethostfromipv6(ipv6,hostname);
	                        if (DEBUG) fprintf(stderr,"DNS Resolution result for %s: %s\n",ipv6,hostname);
        	                snprintf(mailmessage, MAIL_MESSAGE_SIZE, "%s%-9s%s\n",mailmessage,"DNS:",hostname);
                        }
                }


		switch (result) 
		{
			case 0:
				printf("No problem \n");
				break;
			case 1:
				printf("Warning: %s \n", buffer);
				if(!already_sent(buffer))
				{
					if (action_low_pri.sendmail==1) { 
						mail(mailmessage,buffer); 
					}
					if (action_low_pri.syslog==1) 
						syslog(LOG_INFO, " %s ", buffer);
					if (action_low_pri.exec_pipe_program!=NULL) 
						do_exec_pipe_program(action_low_pri.exec_pipe_program, mailmessage);
				}
				break;
			case 2:
				printf("Warning: %s \n", buffer);
				if(!already_sent(buffer))
				{
					if (action_high_pri.sendmail==1) { 
						mail(mailmessage,buffer); 
					}
					if (action_high_pri.syslog==1) 
						syslog(LOG_INFO, " %s ", buffer);
					if (action_high_pri.exec_pipe_program!=NULL) 
						do_exec_pipe_program(action_high_pri.exec_pipe_program, mailmessage);
				}
				break;
			default:
				printf ("No problem \n");
				break;
		}
	}
}

/*Execute external program and send some pipedata to its stdin*/
void do_exec_pipe_program(char* program, char* pipedata)
{
	FILE *pipeprocess;

	pipeprocess = popen (program, "w");
	fprintf (pipeprocess, "%s\n", pipedata);
	fflush(pipeprocess);
	fclose (pipeprocess);
}

/*Send a mail to the admin containing the message*/
void mail(char* message, char* subjectappend)
{
	FILE *pp;
	static int init=0;
	static char args[MAIL_ARGS_SIZE];/*shoule be sufficient*/

	if(!init)
	{
		snprintf(args, MAIL_ARGS_SIZE, "mail -s \"NDPMon_Security_Alert: %s\" %s", subjectappend, admin_mail);
	}  

	printf("Sending mail alert ...\n");
	pp = popen(args, "w");
	if (pp == NULL) 
	{ 
		perror("popen error: unable to send mail"); 
		return;
	}

	
	fprintf(pp,"%s",message); 
#ifdef _LINUX_
	/* For the Cc: */
	fprintf(pp,"\n");
#endif

	fflush(pp);

	pclose(pp);
}


/*Test if the message has been recently send to avoid
 *multiple warnings for the same problem
 */
int already_sent(char* message)
{
	static char old_messages[HISTORY_LENGTH][NOTIFY_BUFFER_SIZE];
	static int index=0;
	int i;

	for (i=0; i<HISTORY_LENGTH; i++)
	{
		if (!strcmp(message, old_messages[i]))
			return 1;
	}

	strncpy(old_messages[index], message, NOTIFY_BUFFER_SIZE);

	if(index==HISTORY_LENGTH-1)
		index=0;
	else
		index++;

	return 0;
}
