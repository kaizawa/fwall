/**********************************************************
 * fwalladm.c
 * �ʰץѥ��åȥե��륿���Ǥ��� fwall �⥸�塼��δ�����
 * ���ޥ�ɡ��롼����ɲá��ѹ���Ԥ���
 *
 *   Usage: fwalladm
 *
 *   ����̵��
 *
 *   �ץ��ץȤΥ��ޥ��
 *
 *     insert rule <rule number> <protocol> <src port> <dest port> <src address> <destion address> <action>
 *     add rule <protocol> <src port> <dest port> <src address> <dest address> <action>
 *     delete rule <rule number>
 *     list rule
 *     add interface <interface>
 *     delete interface <interface>
 *     list interface
 *
 *           insert rule      : �������롼������Υ롼���ֹ���ɲ�
 *           add rule         : �������롼���Ǹ�Υ롼��Ȥ����ɲ�
 *           delete rule      : ���ꤵ�줿��¸�Υ롼�����
 *           list rule        : �������ꤵ��Ƥ���롼���ɽ��
 *           add interface    : �ѥ��åȤ�Ĵ����Ԥ����󥿡��ե��������ɲ�
 *           delete interface : �ѥ��åȤ�Ĵ����Ԥ����󥿡��ե���������
 *           list interface   : �����оݤȤʤäƤ��륤�󥿡��ե����������
 *
 *  �ѹ�����
 *   2005/03/04
 *    o �ץ��ץȤˤ� CTL+D �ˤ� fwalladm ���ޥ�ɤ�λ�Ǥ���褦�ˤ����� 
 *
 ***********************************************************/

#include  <fcntl.h>
#include  <stropts.h>
#include  <stdio.h>
#include  <sys/stream.h>
#include  <string.h>
#include  <errno.h>
#include  <netdb.h>
#include <stdlib.h>


/* local include file */
#include "fwall.h"

#define BUFSIZE 10

#define PRINTADDR(addr) if( addr.s_addr == 0) printf("%15s","*"); else  printf("%15s",inet_ntoa(addr));
#define PRINTPORT(port) if( port == 0)  printf("(*)"); else  printf("(%u)",port);


struct in_addr *getaddr(char *);
void print_usage(char **);
void print_command_usage();
int  strioctl(int , int , int, int, char *);
void parse_command(int, char *, char *, char *);


main(int argc, char *argv[])
{
    int  fd, args;
    char buf[BUFSIZE * 10];
    char command[BUFSIZE];
    char type[BUFSIZE];
    char parameter[BUFSIZE * 8];


    /* fwall �⥸�塼��� PUSH ���뤿��� ip �ǥХ����� open   */
    /* ���Υץ���फ�������� IOCTL message ��ȿ������     */
    /* �Τ� fwall �⥸�塼������ʤΤǡ�open ����ǥХ����ϡ�  */
    /* �֤ä��㤱 STREAM �ǥХ����Ǥ���С�/dev/le �Ǥ�        */
    /* /dev/tcp �Ǥ�ʤ�Ǥ�褤                               */
    fd = open("/dev/ip",O_RDONLY,0666);
    if ( fd < 0)
        perror("open /dev/ip ");

    /* open ���� STREAM �� fwall �⥸�塼�������(PUSH)        */
    if( ioctl(fd,I_PUSH,"fwall") < 0){
        perror("I_PUSH");
        exit(0);
    }

    /* �ץ��ץȤ��饳�ޥ�ɤ�����դ��� */
    for(;;) {

        bzero(command, sizeof(command));
        bzero(type, sizeof(type));
        bzero(parameter, sizeof(parameter));
        
        printf( "> " );
        if(gets(buf) == NULL)
            exit(0);
        
        args = sscanf( buf, "%s %s %[.0-9a-zA-Z *]",command, type, parameter);

        switch(args) {
            case EOF:
            case 0:
                break;
            default:
                parse_command(fd, command, type, parameter);
        }
    }
}

/*****************************************************************************
 * strioctl()
 * STREAM �ǥХ����� ioctl()
 *
 *  ������
 *           fd: STERAM �ǥХ����� File Descriptor
 *          cmd: IOCTL ���ޥ��
 *       timout: �����ॢ������
 *          len: M_IOCTL ��å������Ȥ���STREAM ����������ǡ���
 *           dp: �ǡ���Ĺ
 * ����͡�
 *          ������ STREAM ������������ǡ����Υǡ���Ĺ
 *          ���ԡ� �ޥ��ʥ���
 *
 *****************************************************************************/
int
strioctl(fd, cmd, timout, len, dp)
int     fd;
int     cmd;
int     timout;
int     len;
char    *dp;
{
    struct  strioctl        sioc;
    int     rc;

    sioc.ic_cmd = cmd;
    sioc.ic_timout = timout;
    sioc.ic_len = len;
    sioc.ic_dp = dp;
    rc = ioctl(fd, I_STR, &sioc);

    if (rc < 0)
        return (rc);
    else
        return (sioc.ic_len);
}
    
/*****************************************************************************
 * getaddr()
 * �桼������Ϳ����줿�ۥ���̾�ʤޤ���IP���ɥ쥹�ˤ��� in_addr ��¤�Τ�����
 *
 *  ������
 *           name : �ۥ���̾���ޤ��� IP ���ɥ쥹
 *
 * ����͡�
 *          ������ in_addr ��¤�ΤΥݥ���
 *          ���ԡ� NULL
 *****************************************************************************/
struct in_addr
*getaddr(char *name) {
    struct hostent *hp;

    hp = gethostbyname(name);
    if(!hp) {
        fprintf(stderr, "Unknown host %s\n", name);
        return(NULL);
    }
    return ((struct in_addr *)hp->h_addr);
}

/************************************************************
 * print_usage()
 * Usage ��ɽ��
 ************************************************************/
void
print_usage(char **argv)
{
    printf ("Usage: %s\n",argv[0]);
    exit(0);
}
/************************************************************
 * print_command_usage()
 * prompt �� usage ��ɽ��
 ************************************************************/
void
print_command_usage()
{
    printf ("Command usage: \n");
    printf ("\tadd rule <protocol> <src port> <dest port> <src address> <dest address> <action>\n");
    printf ("\tinsert rule <rule number> <protocol> <src port> <dest port> <src address> <dest address> <action>\n");
    printf ("\tdelete rule <rule number>\n");
    printf ("\tlist rule\n");
    printf ("\tadd interface <interface>\n");
    printf ("\tdelete interface <interface>\n");
    printf ("\tlist interface\n");
    
    return;
}

/************************************************************
 * parse_command()
 * �ץ��ץȤ���Υ��ޥ�ɤβ���
 * fwall �⥸�塼��ؤ� IOCTL ��å�����������
 *
 *  ������
 *           fd        : STERAM �ǥХ���(/dev/ip) �� File Descriptor
 *           command   : ���ޥ��(add, insert, delete, list)
 *           type      : ���ޥ�ɤμ¹��о�(rule, interface)
 *           parameter : ���ޥ�ɤΥѥ�᡼��(IP ���ɥ쥹�����ġ��Ե�����)
 *
 * ����͡�
 *          ̵��
 ************************************************************/
void
parse_command(int fd, char *command, char *type, char *parameter)
{
    int             c, n, params;
    fwall_rule_t    rule;
    char src_addr[BUFSIZE *2], dst_addr[BUFSIZE *2];
    char src_port[BUFSIZE], dst_port[BUFSIZE];
    char proto[BUFSIZE];
    char number[BUFSIZE];
    char action[BUFSIZE];
    char interface[BUFSIZE];
    char strings[BUFSIZE *2];

    /* ����Υ롼���ֹ�ˡ����롼�������*/
    if(strcmp(command, "insert") == 0){
        if(strcmp(type, "rule") == 0){
            params = sscanf( parameter, "%s %s %s %s %s %s %s",
                             number , proto, src_port, dst_port, src_addr, dst_addr, action);
            switch(params) {
                case 7:
                    rule.number = atoi(number);

                    if(strcasecmp(proto, "TCP") == 0)
                        rule.proto = IPPROTO_TCP;
                    else if(strcasecmp(proto, "UDP") == 0)
                        rule.proto = IPPROTO_UDP;
                    else if(strcasecmp(proto, "ICMP") == 0)
                        rule.proto = IPPROTO_ICMP;
                    else if(strcasecmp(proto, "*") == 0)
                        rule.proto = IPPROTO_IP;
                    else {
                        fprintf(stderr,"Unknown Protocol\n");
                        goto err;
                    }
                    
                    /* �ݡ��ȤȤ��ƥ磻��ɥ����ɤ����ꤵ�줿�� 0 �Ȥߤʤ�*/
                    if(strcmp(src_port, "*") == 0)
                        sprintf(src_port,"0");
                    if(strcmp(dst_port, "*") == 0)
                        sprintf(dst_port,"0");
                    rule.src_port = atoi(src_port);
                    rule.dst_port = atoi(dst_port);

                    /* ���ɥ쥹�Ȥ��ƥ磻��ɥ����ɤ����ꤵ�줿�� 0.0.0.0 �Ȥߤʤ�*/
                    if(strcmp(src_addr, "*") == 0)
                        sprintf(src_addr,"0");
                    if(strcmp(dst_addr, "*") == 0)
                        sprintf(dst_addr,"0");
                    rule.src_addr = *getaddr(src_addr);
                    rule.dst_addr = *getaddr(dst_addr);

                    if(strcasecmp(action, "ALLOW") == 0)
                        rule.action = ALLOW;
                    else if(strcasecmp(action, "DENY") == 0)
                        rule.action = DENY;
                    else if(strcasecmp(action, "REJECT") == 0)
                        rule.action = REJECT;
                    else {
                        fprintf(stderr,"Unknown action\n");
                        goto err;
                    }
                    
                    if (strioctl(fd, INSERTRULE, -1, sizeof(fwall_rule_t),(char *)&rule) < 0) {
                        if(errno == EINVAL){
                            fprintf(stderr,"Can't add rule %u\n", n);
                            return;
                        }
                        perror("strioctl :INSERTRULE");
                        exit(0);
                    }
                    return;
                default:
                    break;
            }/* switch() �ν����*/
            goto err;
        } /* if type == rule  */
        goto err;
    } /* if command == insert */

    /* ���롼�����ֺǸ�Υ롼��Ȥ����ɲ�*/
    if(strcmp(command, "add") == 0){
        if(strcmp(type, "rule") == 0){
            params = sscanf( parameter, "%s %s %s %s %s %s",
                             proto, src_port, dst_port, src_addr, dst_addr, action);
            switch(params) {
                case 6:

                    if(strcasecmp(proto, "TCP") == 0)
                        rule.proto = IPPROTO_TCP;
                    else if(strcasecmp(proto, "UDP") == 0)
                        rule.proto = IPPROTO_UDP;
                    else if(strcasecmp(proto, "ICMP") == 0)
                        rule.proto = IPPROTO_ICMP;
                    else if(strcasecmp(proto, "*") == 0)
                        rule.proto = IPPROTO_IP;
                    else {
                        fprintf(stderr,"Unknown Protocol\n");                        
                        goto err;
                    }

                    /* �ݡ��ȤȤ��Ƥƥ磻��ɥ����ɤ����ꤵ�줿�� 0 �Ȥߤʤ�*/
                    if(strcmp(src_port, "*") == 0)
                        sprintf(src_port,"0");                        
                    if(strcmp(dst_port, "*") == 0)
                        sprintf(dst_port,"0");                                                
                    rule.src_port = atoi(src_port);                        
                    rule.dst_port = atoi(dst_port);

                    /* ���ɥ쥹�Ȥ��ƥ磻��ɥ����ɤ����ꤵ�줿�� 0.0.0.0 �Ȥߤʤ�*/
                    if(strcmp(src_addr, "*") == 0)
                        sprintf(src_addr,"0");
                    if(strcmp(dst_addr, "*") == 0)
                        sprintf(dst_addr,"0");                    
                    rule.src_addr = *getaddr(src_addr);
                    rule.dst_addr = *getaddr(dst_addr);
                    
                    if(strcasecmp(action, "ALLOW") == 0)
                        rule.action = ALLOW;
                    else if(strcasecmp(action, "DENY") == 0)
                        rule.action = DENY;
                    else if(strcasecmp(action, "REJECT") == 0)
                        rule.action = REJECT;
                    else {
                        fprintf(stderr,"Unknown action\n");
                        goto err;
                    }
                    
                    if (strioctl(fd, ADDRULE, -1, sizeof(fwall_rule_t),(char *)&rule) < 0) {
                        if(errno == EINVAL){
                            fprintf(stderr,"Can't add rule %u\n", n);
                            return;
                        }
                        perror("strioctl :ADDRULE");
                        exit(0);
                    }
                    return;
                default:
                    break;
            }/* switch() �ν����*/
            goto err;            
        } /* if type == rule  */
        
        if(strcmp(type, "interface") == 0){
            params = sscanf( parameter, "%s", interface);
            switch(params) {
                case 1:            
                    sprintf(strings, "/usr/sbin/ifconfig %s modinsert fwall@2", interface);
                    break;
                default:
                    goto err;
            }
            system(strings);
            return;
        }/* if type == interface */
        goto err;
    } /* if command == add */    

    /* �������ꤵ��Ƥ���롼���ɽ��*/
    if(strcmp(command, "list") == 0){
        if(strcmp(type, "rule") == 0){
            for(n = 0 ;; n++){
                bzero(&rule, sizeof(fwall_rule_t));
                rule.number = n;
                if (strioctl(fd, GETRULE, -1, sizeof(fwall_rule_t), (char *)&rule) < 0) {
                    if(errno == EINVAL)
                        /* EINVAL ���֤ä��Ȥ������ȤϤ⤦����ʾ�Υ롼���̵��*/
                        break;
                    else
                        perror("strioctl : GETRULE");                    
                    exit(0);
                }
                
                printf("Rule %u:\t",n);
                PRINTADDR(rule.src_addr);
                PRINTPORT(rule.src_port);
                printf("\t->\t");
                PRINTADDR(rule.dst_addr);                
                PRINTPORT(rule.dst_port);
                printf("\t");
                
                switch(rule.proto){
                    case IPPROTO_TCP:
                        printf("TCP\t");
                        break;
                    case IPPROTO_UDP:
                        printf("UDP\t");
                        break;
                    case IPPROTO_ICMP:
                        printf("ICMP\t");
                        break;                        
                    case IPPROTO_IP:
                        printf("*\t");
                        break;
                    default:
                        printf("?\t");
                }
                
                switch(rule.action){
                    case ALLOW:
                        printf("ALLOW\n");
                        break;
                    case REJECT:
                        printf("REJECT\n");
                        break;
                    case DENY:
                        printf("DENY\n");
                        break;
                    default:
                        printf("Unknown action(%d)\n",rule.action);
                        break;
                }
            }/* for �롼�� */
            return;
        }/* if type == rule */
        
        if(strcmp(type, "interface") == 0){
            sprintf(strings,"ifconfig -au modlist 2>/dev/null|nawk -v RS=0,FS=\" \" \'/fwall/{print $NF}\'");
            system(strings);
            return;
        }/* if type = interface */                
        goto err;
    }/* if command == list*/

    /* ����Υ롼���ֹ�Υ롼�����*/
    if(strcmp(command, "delete") == 0){
        if(strcmp(type, "rule") == 0){
            params = sscanf( parameter, "%s", number);
            n = atoi(number);
            if (strioctl(fd, DELRULE, -1, sizeof(uint32_t),(char *)&n) < 0) {
                if(errno == EINVAL){
                    fprintf(stderr,"Rule %u doesn't exist.\n",n);
                    return;
                } else
                    perror("strioctl :DELRULE");
                exit(0);
            }
            return;
        }/* if type == rule */
        
        if(strcmp(type, "interface") == 0){
            params = sscanf( parameter, "%s", interface);
            switch(params) {
                case 1:            
                    sprintf(strings, "/usr/sbin/ifconfig %s modremove fwall@2", interface);                    
                    break;
                default:
                    goto err;
            }            
            system(strings);
            return;
        }/* if type = interface */        
    }

    /* �ץ��ץȾ�ǡ�quit��exit ������դ�����ץ���ཪλ*/
    if(strcmp(command, "quit") == 0 || strcmp(command, "exit") == 0 )
        exit(0);
  err:
    print_command_usage();
    return;    
}
