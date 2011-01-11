#include <stdlib.h>

#include "membounds.h"
#include "mac_resolv.h"

/* gcc -Wall -O2 -g mac_resolv.c -o mac_resolv */

int is_manufacturer(manufacturer_t *list, char *code, char *name)
{
	manufacturer_t *tmp = list;

	while(tmp != NULL)
	{
		if( !strcmp(tmp->code,code) && !strcmp(tmp->name,name) )
			return 1;

		tmp = tmp->next;
	}

	return 0;
}

int add_manufacturer(manufacturer_t **list, char *code, char *name)
{
        manufacturer_t *tmp = *list,*new=NULL;

        if(is_manufacturer(*list,code,name))
        {
                /* fprintf(stderr,"Manufacturer already in list\n"); */
                return 0;
        }

        if( (new=/*(manufacturer_t *)*/malloc(sizeof(manufacturer_t))) == NULL)
        {
                perror("malloc");
                return 0;
        }

        strncpy(new->code,code, MANUFACTURER_CODE_SIZE);
        strncpy(new->name,name, MANUFACTURER_NAME_SIZE);
        new->next = NULL;

        if(*list != NULL)
        {
                while(tmp->next != NULL)
                        tmp=tmp->next;
                tmp->next=new;
        }
        else
                 *list = new;

        return 1;
}

char * get_manufacturer(manufacturer_t *list, struct ether_addr eth)
{
	manufacturer_t *tmp = list;

	while(tmp != NULL)
	{
		unsigned int first, second, third;
	
		sscanf(tmp->code,"%x:%x:%x",&first, &second, &third);
#ifdef _FREEBSD_
		if( (first == eth.octet[0]) && (second == eth.octet[1]) && (third == eth.octet[2]) )
#else
		if( (first == eth.ether_addr_octet[0]) && (second == eth.ether_addr_octet[1]) && (third == eth.ether_addr_octet[2]) )
#endif
			return tmp->name;

		tmp = tmp->next;
	}

	return "unknown";
}

int clean_manufacturer(manufacturer_t **list)
{
	manufacturer_t *tmp = *list, *todel = NULL;

	while(tmp != NULL)
	{
		todel = tmp;
		tmp = tmp->next;
		free(todel);
	}

	return 1;
}

void print_manufacturer(manufacturer_t *list)
{
	manufacturer_t *tmp = list;

	while(tmp != NULL)
	{
		fprintf(stderr,"Manufacturer %s \tCode %s\n",tmp->name,tmp->code);
		tmp = tmp->next;
	}

	return ;
}


int read_manuf_file(char *filename, manufacturer_t **list)
{
	FILE *f;
	char buffer[BUFFER_SIZE];

	if( (f=fopen(filename,"r")) == NULL)
	{
		perror("fopen");
		return -1;
	}

	while( fgets(buffer, BUFFER_SIZE, f) != NULL)
	{
		unsigned int first, second, third;
		char manuf_name[MANUFACTURER_NAME_SIZE];

		memset(manuf_name,0,MANUFACTURER_NAME_SIZE);

		if( (buffer[0] == '#') || (buffer[0] == '\n') )
		{
			/* Comments... Nothing to do... */
		}
		else if( sscanf(buffer, "%2x:%2x:%2x %" MANUFACTURER_NAME_LEN_FSTR "s",&first, &second, &third, manuf_name) != EOF)
		{
			char code[MANUFACTURER_CODE_SIZE]; 

			sprintf(code,"%.2x:%.2x:%.2x", first,second,third);
			add_manufacturer(list,code,manuf_name);
		}
		else
			fprintf(stderr,"----------- UNKNOWN ------------------\n");

	}

	fclose(f);
	return 0;
}

#if 0
int main(int argc, char **argv)
{
	struct ether_addr eth;

	manufacturer_t *manuf = NULL;

	read_manuf_file("manuf",&manuf);

	/* print_manufacturer(manuf); */

	memcpy(&eth,ether_aton("00:13:72:14:C4:58"),sizeof(struct ether_addr));
	fprintf(stderr,"00:13:72:14:C4:58 is from vendor %s\n", get_manufacturer(manuf,eth) );

	fprintf(stderr,"\n");
	memcpy(&eth,ether_aton("0:c:6e:d7:a3:2b"),sizeof(struct ether_addr));
	fprintf(stderr,"0:c:6e:d7:a3:2b is from vendor %s\n", get_manufacturer(manuf,eth) );

	fprintf(stderr,"\n");
	memcpy(&eth,ether_aton("0:11:24:89:41:56"),sizeof(struct ether_addr));
	fprintf(stderr,"0:11:24:89:41:56 is from vendor %s\n", get_manufacturer(manuf,eth) );

	fprintf(stderr,"\n");
	memcpy(&eth,ether_aton("0:30:b6:51:d4:1c"),sizeof(struct ether_addr));
	fprintf(stderr,"0:30:b6:51:d4:1c is from vendor %s\n", get_manufacturer(manuf,eth) );

	fprintf(stderr,"\n");
	memcpy(&eth,ether_aton("00:08:02:65:d3:ea"),sizeof(struct ether_addr));
	fprintf(stderr,"00:08:02:65:d3:ea is from vendor %s\n", get_manufacturer(manuf,eth) );

	fprintf(stderr,"\n");
	memcpy(&eth,ether_aton("00:0d:bc:e0:61:22"),sizeof(struct ether_addr));
	fprintf(stderr,"00:0d:bc:e0:61:22 is from vendor %s\n", get_manufacturer(manuf,eth) );

	fprintf(stderr,"\n");
	memcpy(&eth,ether_aton("aa:dd:bc:e0:61:22"),sizeof(struct ether_addr));
	fprintf(stderr,"aa:dd:bc:e0:61:22 is from vendor %s\n", get_manufacturer(manuf,eth) );

	clean_manufacturer(&manuf);
	return 0;
}
#endif

