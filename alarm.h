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

#ifndef _ALARM_
#define _ALARM_ 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <syslog.h>

#include "ndpmon_defs.h"

#define HISTORY_LENGTH 20

/* Execute external program and send data to its stdin */
void do_exec_pipe_program(char* program, char* pipedata);

/*Define if warnings must be reported*/
void set_alarm(int a);

/*Notify the waning message from buffer
 *according to the severity
 */
void notify(int result, char* buffer, char* reason, struct ether_addr* mac_addr, char* ipv6, struct ether_addr* mac_addr2);

/*Send a mail to the admin containing the message*/
void mail(char* message, char* subjectappend);

/*Test if the message has been recently send to avoid
 *multiple warnings for the same problem
 */
int already_sent(char* message);

#endif
