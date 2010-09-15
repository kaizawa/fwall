/**********************************************************
 * fwalladm.c
 * 簡易パケットフィルターである fwall モジュールの管理用
 * コマンド。ルールの追加、変更を行う。
 *
 *   Usage: fwalladm
 *
 *   引数無し
 *
 *   プロンプトのコマンド
 *
 *     insert rule <rule number> <protocol> <src port> <dest port> <src address> <destion address> <action>
 *     add rule <protocol> <src port> <dest port> <src address> <dest address> <action>
 *     delete rule <rule number>
 *     list rule
 *     add interface <interface>
 *     delete interface <interface>
 *     list interface
 *
 *           insert rule      : 新しいルールを指定のルール番号で追加
 *           add rule         : 新しいルールを最後のルールとして追加
 *           delete rule      : 指定された既存のルールを削除
 *           list rule        : 現在設定されているルールを表示
 *           add interface    : パケットの調査を行うインターフェースを追加
 *           delete interface : パケットの調査を行うインターフェースを削除
 *           list interface   : 現在対象となっているインターフェースを報告
 *
 *  変更履歴
 *   2005/03/04
 *    o プロンプトにて CTL+D にて fwalladm コマンドを終了できるようにした。 
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


    /* fwall モジュールを PUSH するために ip デバイスを open   */
    /* このプログラムから送られる IOCTL message に反応する     */
    /* のは fwall モジュールだけなので、open するデバイスは、  */
    /* ぶっちゃけ STREAM デバイスであれば、/dev/le でも        */
    /* /dev/tcp でもなんでもよい                               */
    fd = open("/dev/ip",O_RDONLY,0666);
    if ( fd < 0)
        perror("open /dev/ip ");

    /* open した STREAM に fwall モジュールを挿入(PUSH)        */
    if( ioctl(fd,I_PUSH,"fwall") < 0){
        perror("I_PUSH");
        exit(0);
    }

    /* プロンプトからコマンドを受け付ける */
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
 * STREAM デバイス用 ioctl()
 *
 *  引数：
 *           fd: STERAM デバイスの File Descriptor
 *          cmd: IOCTL コマンド
 *       timout: タイムアウト値
 *          len: M_IOCTL メッセージとしてSTREAM に送信するデータ
 *           dp: データ長
 * 戻り値：
 *          成功： STREAM から受信したデータのデータ長
 *          失敗： マイナス値
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
 * ユーザから与えられたホスト名（またはIPアドレス）から in_addr 構造体を得る
 *
 *  引数：
 *           name : ホスト名、または IP アドレス
 *
 * 戻り値：
 *          成功： in_addr 構造体のポインタ
 *          失敗： NULL
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
 * Usage の表示
 ************************************************************/
void
print_usage(char **argv)
{
    printf ("Usage: %s\n",argv[0]);
    exit(0);
}
/************************************************************
 * print_command_usage()
 * prompt の usage の表示
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
 * プロンプトからのコマンドの解析
 * fwall モジュールへの IOCTL メッセージの送信
 *
 *  引数：
 *           fd        : STERAM デバイス(/dev/ip) の File Descriptor
 *           command   : コマンド(add, insert, delete, list)
 *           type      : コマンドの実行対象(rule, interface)
 *           parameter : コマンドのパラメータ(IP アドレス、許可・不許可等)
 *
 * 戻り値：
 *          無し
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

    /* 指定のルール番号に、新ルールを挿入*/
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
                    
                    /* ポートとしてワイルドカードが指定されたら 0 とみなす*/
                    if(strcmp(src_port, "*") == 0)
                        sprintf(src_port,"0");
                    if(strcmp(dst_port, "*") == 0)
                        sprintf(dst_port,"0");
                    rule.src_port = atoi(src_port);
                    rule.dst_port = atoi(dst_port);

                    /* アドレスとしてワイルドカードが指定されたら 0.0.0.0 とみなす*/
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
            }/* switch() の終わり*/
            goto err;
        } /* if type == rule  */
        goto err;
    } /* if command == insert */

    /* 新ルールを一番最後のルールとして追加*/
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

                    /* ポートとしててワイルドカードが指定されたら 0 とみなす*/
                    if(strcmp(src_port, "*") == 0)
                        sprintf(src_port,"0");                        
                    if(strcmp(dst_port, "*") == 0)
                        sprintf(dst_port,"0");                                                
                    rule.src_port = atoi(src_port);                        
                    rule.dst_port = atoi(dst_port);

                    /* アドレスとしてワイルドカードが指定されたら 0.0.0.0 とみなす*/
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
            }/* switch() の終わり*/
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

    /* 現在設定されているルールを表示*/
    if(strcmp(command, "list") == 0){
        if(strcmp(type, "rule") == 0){
            for(n = 0 ;; n++){
                bzero(&rule, sizeof(fwall_rule_t));
                rule.number = n;
                if (strioctl(fd, GETRULE, -1, sizeof(fwall_rule_t), (char *)&rule) < 0) {
                    if(errno == EINVAL)
                        /* EINVAL が返ったということはもうこれ以上のルールは無い*/
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
            }/* for ループ */
            return;
        }/* if type == rule */
        
        if(strcmp(type, "interface") == 0){
            sprintf(strings,"ifconfig -au modlist 2>/dev/null|nawk -v RS=0,FS=\" \" \'/fwall/{print $NF}\'");
            system(strings);
            return;
        }/* if type = interface */                
        goto err;
    }/* if command == list*/

    /* 指定のルール番号のルールを削除*/
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

    /* プロンプト上で、quit、exit を受け付けたらプログラム終了*/
    if(strcmp(command, "quit") == 0 || strcmp(command, "exit") == 0 )
        exit(0);
  err:
    print_command_usage();
    return;    
}
