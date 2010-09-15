/*************************************************************
 * �ʰ� packet �ե��륿���Υ롼��⥸�塼��
 * 
 * /usr/local/bin/gcc -D_KERNEL fwall_rule.c -c
 *
 * �ѹ�����
 *   2005/03/09
 *     o �롼��˴�Ϣ����ե��󥯥�������Ω������
 *   2005/03/11
 *     o �ѥ��åȵ��ݻ��˥롼���ֹ�ȡ�IP ���ɥ쥹�� syslog ��ɽ������褦�ˤ�����
 *     o �롼����ɲû��˥ݡ����ֹ�ȡ��ץ�ȥ���� syslog ��ɽ������褦�ˤ�����
 *     o IP �إå��β��ϻ��� IP �إå��ؤΥ��ɥ쥹�� 4 �Х��ȶ������̵�������
 *        PANIC ��ȯ��(memory address not aligned)��������������뤿�ᡢ
 *       �ǡ���������٥��ԡ����Ƥ��顢���ԡ���Υǡ�����Ĵ������褦�ˤ�����
 *
 **************************************************************/

/* STREAM �ѥإå� */
#include <sys/modctl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

/* TCP/IP ��Ϣ�إå� */
#include  <netinet/in.h>
#include  <sys/types.h>
#include  <sys/socket.h>
#include  <sys/dlpi.h>
#include  <fcntl.h>
#include  <sys/signal.h>
#include  <net/if.h>
#include  <netinet/if_ether.h>
#include  <netinet/in_systm.h>
#include  <netinet/tcp.h>
#include  <netinet/udp.h>
#include  <netinet/ip.h>

/* fwall �⥸�塼���ѥإå� */
#include "fwall.h"

/* count �˸��ߤ���롼��������� */
#define RULES(count)  \
          for( rulep = rules_head, count = 0 ; rulep ; ++count, rulep = rulep->next_rule)
/* rulep �˸��ߤλ���Υ롼���ֹ�Υ롼��Υݥ��󥿤����� */
#define WALKRULE(rulep, number) \
          for( rulep = rules_head ; rulep && number ; --number, rulep = rulep->next_rule)
#define COMPARE_ADDR(address_1, address_2)  \
          (bcmp( address_1, address_2, sizeof(struct in_addr)) == 0)

#define IS_ALIGN(ip) (((ulong_t)ip % 4) == 0)


char *action_string[] = { "ALLOW", "REJECT", "DENY" };

/*
 * �⥸�塼��Υ����Х�ǡ��� �ǽ�Υ롼��ؤΥݥ��󥿤��Ǽ
 * ���Υǡ����ν񤭹��ߤ���¾Ū�˹Ԥ��ʤ���Фʤ�ʤ�
 */
fwall_rule_t *rules_head = NULL;

void  fwall_insert_rule (queue_t*, mblk_t*);
void  fwall_delete_rule (queue_t*, mblk_t*);
void  fwall_get_rule (queue_t*, mblk_t*);
void  fwall_check_rule(queue_t*, mblk_t*);
int   fwall_check_rule_ip(struct ip *, int);
void  fwall_print_rule(fwall_rule_t *);
extern void  debug_print(int , char *, ...);

/*****************************************************************************
 * fwall_insert_rule()
 * �롼����ɲä��롣�⥸�塼��Υ����Х�ǡ������ѹ����뤳�Ȥˤʤ롣
 * �����Х�ǡ������ѹ����뤿��ˤϡ���¾�⡼�ɤǤʤ��Ƥ� �ʤ�ʤ��Τǡ�
 * ���Υ롼�����ɬ�� qwriter() ����ƤФ�롣
 *
 *  ������
 *           q:  queue ��¤�ΤΥݥ���
 *          mp:  message block �Υݥ���
 * ����͡�
 *           �ʤ���
 *****************************************************************************/
void 
fwall_insert_rule(queue_t *q, mblk_t *mp)
{
    fwall_rule_t   *new;          /* ������ allocate ����롼��   */
    fwall_rule_t   *user_rule;    /* fwalladm �����Ϥ����롼��    */
    fwall_rule_t   *rulep;        /* �����ѤΥݥ���             */
    uint32_t       rule_number;   /* �׵ᤵ�줿�ɲä���롼���ֹ� */
    uint32_t       total_rules;   /* ���ߤ���롼���             */
    struct iocblk *iocp;
    
    /* b_cont �� fwalladm �����Ϥ����롼���ޤ� M_DATA message �ؤΥݥ��󥿤ΤϤ�*/
    user_rule = (fwall_rule_t *)mp->b_cont->b_rptr;

    /* total_rules �˸��ߤ���롼��������� */
    RULES(total_rules);    

    /* IOCTL ���ޥ�ɤ� ADDRULE(�ɲáˤʤ���ֺǸ�ˡ�INSERTRULE��������*/
    /* �ʤ����Υ롼���ֹ�˥롼����ɲ�                               */
    iocp = (struct iocblk *)mp->b_rptr;
    switch (iocp->ioc_cmd) {
        case ADDRULE:
            rule_number = total_rules;
            break;
        case INSERTRULE:
            rule_number = user_rule->number;
            break;
    }
            
    /*---------------------------------------------*/
    /* �⤷���ʲ��ξ��ˤ��ä��饨�顼            */
    /* 1. �롼��κ������ۤ��Ƥ���               */
    /* 2. ���ߤΥ롼�������礭���롼���ֹ����� */
    /*---------------------------------------------*/ 
    if( total_rules >= MAXRULES || rule_number > total_rules ){
        mp->b_datap->db_type = M_IOCNAK;
        qreply(q, mp);
        DEBUG_PRINT0(CE_CONT, "fwall_insert_rule: Couldn't insert new rule.\n");                    
        return;                        
    }
    DEBUG_PRINT1(CE_CONT, "fwall_insert_rule: Number of rules = %u",total_rules);
    
    /* fwalladm �����Ϥ����롼��(user_rule)�򿷤��� allocate �����롼��(new)�˥��ԡ� */
    new = kmem_zalloc(sizeof(fwall_rule_t), KM_SLEEP);
    bcopy( user_rule, new , sizeof(fwall_rule_t));
    
    if(rules_head == NULL){
        /* �롼�뤬�ޤ����ꤵ��Ƥ��ʤ��������� �롼��� rule_head �Ȥ������ꤹ�� */
        /* �ǽ�Υ롼��ʤΤǡ�fwalladm ���餭���롼���ֹ��̵�뤷�ƣ��֥롼��Ȥ���*/
        new->next_rule = NULL;        
        rules_head = new;
    } else if ( rule_number == 0){
        /* rule_head �Ȥ��ƴ�¸�Υ롼�룰�����˥롼����ɲ� */
        new->next_rule = rules_head;
        rules_head = new;
    } else {
        /* �롼�뤬���Ǥ�¸�ߤ��롣���ꤵ�줿�롼���ֹ�ˡ��������롼����ɲä��� */
        rulep = rules_head;

        /* ���ꤵ�줿�롼���ֹ�ΰ�����Υ롼���õ��*/
        WALKRULE(rulep, rule_number -1);
        
        /* rule_number ���ܤΥ롼��Ȥ��ƥ�󥯥ꥹ�Ȥ�����ɲ� */
        new->next_rule = rulep->next_rule;
        rulep->next_rule = new;
    }
    mp->b_datap->db_type = M_IOCACK;

    fwall_print_rule(new);

    qreply(q, mp);
    return;
}

/******************************************************************************
 * fwall_delete_rule()
 * fwalladm ���ޥ�ɤ���Υ롼��κ���׵���������
 *
 *  ������
 *          q :  queue ��¤�ΤΥݥ���
 *          mp:  message block �Υݥ���
 *
 * ����͡�
 *           �ʤ���
 *****************************************************************************/ 
void
fwall_delete_rule(queue_t *q, mblk_t *mp)
{
    fwall_rule_t *rulep;         /* �����ѤΥݥ���             */
    fwall_rule_t *delp;          /* �������롼��               */
    uint32_t      rule_number;   /* �׵ᤵ�줿�������롼���ֹ� */
    uint32_t      total_rules;   /* ���ߤ���롼���             */    

    /* b_cont �ǥݥ���Ȥ���Ƥ��� message �� read �ݥ��󥿡��Ϻ������롼���ֹ�ΤϤ� */
    rule_number = *(uint32_t *)mp->b_cont->b_rptr;
    
    /* total_rules �˸��ߤ���롼��������� */
    RULES(total_rules);
    
    /*----------------------------------------------------------*/    
    /* �⤷���ʲ��ξ��˥ޥå������饨�顼                     */
    /* 1.�롼��κ������ۤ��Ƥ���                             */
    /* 2.���ߤΥ롼��� -1 ����礭���롼���ֹ椬���ꤵ��Ƥ��� */
    /* 3.���ߥ롼�뤬��Ĥ����ꤵ��Ƥ��ʤ�                     */
    /*----------------------------------------------------------*/    
    if( total_rules >= MAXRULES || total_rules == 0 || rule_number > total_rules -1 ){
        mp->b_datap->db_type = M_IOCNAK;
        qreply(q, mp);
        DEBUG_PRINT1(CE_CONT, "fwall_delete_rule: Couldn't remove rule number %u.\n", rule_number);
        return;                        
    }
    
    if( rule_number == 0){
        /* �ǽ�Υ롼��(=rules_head)�κ���׵�                        */
        /* ��󥯥ꥹ�ȤΥ�󥯤�ĥ��ʤ��������θ�롼��� free ���� */        
        rulep = rules_head;
        rules_head = rules_head->next_rule;
        kmem_free(rulep, sizeof(fwall_rule_t));
        mp->b_datap->db_type = M_IOCACK;
        qreply(q, mp);
        cmn_err(CE_CONT, "Rule %u removed",*(uint32_t *)mp->b_cont->b_rptr);        
        return;
    } else if( rule_number > 0){
        rulep = rules_head;
        /* ������������Υ롼���õ��*/
        WALKRULE(rulep, rule_number -1);

        /* ���λ����� rulep �Ϻ�����������Υ롼��ΤϤ�*/
        if (rulep->next_rule == NULL){
            /* ���Ϥ��줿�롼���ֹ��̵��             */
            /* M_IOCNAK(=�������) ���֤������顼ɽ�� */            
            mp->b_datap->db_type = M_IOCNAK;
            qreply(q, mp);
            cmn_err(CE_CONT, "Invalid rule number");                        
            return;
        }
        /* ��󥯥ꥹ�ȤΥ�󥯤�ĥ��ʤ��������θ�롼��� free ���� */
        delp = rulep->next_rule;
        rulep->next_rule = delp->next_rule;
        kmem_free(delp,sizeof(fwall_rule_t));
        mp->b_datap->db_type = M_IOCACK;
        qreply(q, mp);            
        cmn_err(CE_CONT, "Rule %u removed", *(uint32_t *)mp->b_cont->b_rptr);        
        return;
        
    } else {
        /* ���Ϥ��줿�롼���ֹ��̵��             */
        /* M_IOCNAK(=�������) ���֤������顼ɽ�� */        
        mp->b_datap->db_type = M_IOCNAK;
        qreply(q, mp);
        cmn_err(CE_CONT, "Invalid rule number");                                    
        return;
    }
}

/******************************************************************************
 * fwall_get_rule()
 * ���ꤵ�줿�ֹ�Υ롼���õ������������
 *
 *  ������
 *          q :  queue ��¤�ΤΥݥ���
 *          mp:  message block �Υݥ���
 *
 * ����͡�
 *           �ʤ���
 *******************************************************************************/
void
fwall_get_rule(queue_t *q, mblk_t *mp)
{
    fwall_rule_t  *user_rule;    /* fwalladm �����Ϥ����롼��*/
    fwall_rule_t  *rulep;        /* �����ѤΥݥ���         */
    uint32_t      rule_number;   /* �롼���ֹ�               */

    user_rule = (fwall_rule_t *)mp->b_cont->b_rptr;
    rule_number = user_rule->number;
    if(rules_head == NULL){
        /* �롼��Ϥޤ���Ĥ����ꤵ��Ƥ��ʤ�!!
         * M_IOCNAK(=�������) ���֤�*/
        mp->b_datap->db_type = M_IOCNAK;
        qreply(q, mp);
        return;
    }    
    rulep = rules_head;
    while(rule_number){
        /* rule_number ���ܤΥ롼���õ��*/
        if(rulep->next_rule == NULL){
            /* ���Ϥ��줿�롼���ֹ��̵��
             * M_IOCNAK(=�������) ���֤� */
            mp->b_datap->db_type = M_IOCNAK;
            qreply(q, mp);
            return;                
        } 
        rulep = rulep->next_rule;
        rule_number--;            
    }
    /* ���λ����� rulep �� n ���ܤΥ롼�뤬���롣
     * ����� user_rule���Ĥޤ� M_IOCTL message
     * �� b_cont �ǷҤ��ä� M_DATA message �˥��ԡ�
     * ����fwalladm ���ޥ�ɤ��ֿ����Ƥ��*/
    bcopy(rulep, user_rule, sizeof(fwall_rule_t));
    mp->b_datap->db_type = M_IOCACK;
    qreply(q, mp);    
    return;
}

/******************************************************************************
 * fwall_check_rule_ip
 * 
 * �����Ȥ����Ϥ��줿 IP �إå��ؤΥݥ��󥿤��롼��˥ޥå����뤫������å�
 *
 *  ������
 *          ip :  ip �إå��ؤΥݥ���
 *
 * ����͡�
 *          ž�����Ĥξ��   : 0
 *          ž���Ե��Ĥξ�� : -1
 *******************************************************************************/
int
fwall_check_rule_ip(struct ip *orgip, int len)
{
    struct tcphdr *tcphdr;             /* TCP �إå���¤��         */
    struct udphdr *udphdr;             /* UDP �إå���¤��         */
    fwall_rule_t  *rulep;              /* �����ѤΥ롼��Υݥ��� */
    uint16_t      src_port, dst_port;  /* ��������������ݡ���     */
    uint8_t       proto;
    struct ip     *ip;
    uint32_t      rule_number;   /* �롼���ֹ� */

    /*
     * ���饤����Ȥ����꤬����Τǡ�Ĵ���Ѥ� buffer ���Ѱդ��ơ�������� IP �Υǡ���
     * �򥳥ԡ����Ƥ���Ĵ����Ԥ����Ȥˤ��롣
     */
    ip = (struct ip *)kmem_zalloc(len , KM_NOSLEEP);
    if ( ip == NULL){
        DEBUG_PRINT0(CE_CONT, "fwall_check_rule_ip: cannot allocate memory\n");
        return(DENY);
    }
    bcopy(orgip, ip, len);

#ifdef ALIGN_CHECK
    if( !IS_ALIGN(ip)){
        cmn_err(CE_CONT, "fwall_check_rule_ip: memory is not align\n");
        kmem_free(ip, len);        
        return(DENY);
    }
#endif

    /*
     * ip_p �ˤ� protocol ��Ƚ�ꤷ��TCP, UDP �Υݡ��Ȥ�Ĵ�٤롣
     * TCP,UDP �ɤ���Ǥ�ʤ����� 0 ������Ƥ���
     */
    proto = ip->ip_p;
    switch(proto){
        case IPPROTO_TCP:
            tcphdr = (struct tcphdr *)((char *)ip + ((ip->ip_hl)<<2));
            dst_port = tcphdr->th_dport;
            src_port = tcphdr->th_sport;
            break;
        case IPPROTO_UDP:
            udphdr = (struct udphdr *)((char *)ip + ((ip->ip_hl)<<2));
            dst_port = udphdr->uh_dport;
            src_port = udphdr->uh_sport;            
            break;
        default:
            dst_port = 0;
            src_port = 0;
    }
    
    for (rulep = rules_head, rule_number = 0 ; rulep != NULL ; rulep = rulep->next_rule, rule_number++){
        switch(rulep->action){
            case ALLOW:
                /* ��������ȯ�������ɥ쥹�� ACCEPT �롼��Υ��ɥ쥹�˥ޥå����뤫��� */
                if(
                    (ip->ip_src.s_addr == rulep->src_addr.s_addr || rulep->src_addr.s_addr == INADDR_ANY)&&
                    (ip->ip_dst.s_addr == rulep->dst_addr.s_addr || rulep->dst_addr.s_addr == INADDR_ANY)&&
                    ( proto == rulep->proto || rulep->proto == IPPROTO_IP)&&
                    (dst_port == rulep->dst_port || rulep->dst_port == 0)&&
                    (src_port == rulep->src_port || rulep->src_port == 0)
                    )
                    {
                        /* �ޥå������� 0 ��꥿����putnext() ����ΤϸƤӽФ����ؿ�����Ǥ */
                        kmem_free(ip, len);                                
                        return(ALLOW);                    
                    }                
            case REJECT:
                /* ̤������DENY �������ˤ��롣*/
            case DENY:
                /* ��������ȯ�������ɥ쥹�� DENY �롼��Υ��ɥ쥹�˥ޥå����뤫��� */
                if(
                    (ip->ip_src.s_addr == rulep->src_addr.s_addr || rulep->src_addr.s_addr == INADDR_ANY)&&
                    (ip->ip_dst.s_addr == rulep->dst_addr.s_addr || rulep->dst_addr.s_addr == INADDR_ANY)&&
                    (proto == rulep->proto || rulep->proto == IPPROTO_IP)&&
                    (dst_port == rulep->dst_port || rulep->dst_port == 0)&&
                    (src_port == rulep->src_port || rulep->src_port == 0)
                    )
                    {
                        /* �ޥå������� DENY(0x2) ��꥿����freemsg() ����ΤϸƤӽФ����ؿ�����Ǥ */
                        cmn_err(CE_CONT,"Packet denied by rule %d: %d.%d.%d.%d -> %d.%d.%d.%d (ipid =%u)",
                                rule_number,
                                ip->ip_src.s_net, ip->ip_src.s_host, ip->ip_src.s_lh, ip->ip_src.s_impno,
                                ip->ip_dst.s_net, ip->ip_dst.s_host, ip->ip_dst.s_lh, ip->ip_dst.s_impno,
                                ip->ip_id
                                );
                        kmem_free(ip, len);
                        return(DENY);
                    }
                break;                                
            default:
                break;
        }
    }/* for ��λ */

    /*
     * �ɤΥ롼��ˤ�ޥå����ʤ��ä��Τ� ALLOW ��꥿����
     */
    kmem_free(ip, len);                            
    return(ALLOW);
}

/******************************************************************************
 * fwall_print_rule
 * 
 * �����Ȥ����Ϥ��줿 �롼��� syslog �˽��Ϥ���
 * ���ɲû����ѡ����ˤ��Ƥ��ޤä����ײ�����
 *
 *  ������
 *          rule :  �롼��ؤΥݥ���
 *
 * ����͡�
 *          �ʤ�
 *          
 *******************************************************************************/
void
fwall_print_rule(fwall_rule_t *rule)
{
    char *proto;

    switch(rule->proto){
        case IPPROTO_TCP:
            proto = "TCP";
            break;
        case IPPROTO_UDP:
            proto = "UDP";
            break;
        case IPPROTO_ICMP:
            proto = "ICMP";
            break;
        default:
            proto = "*";
    }
    
    cmn_err(CE_CONT, "Rule Added. Proto: %s : %d.%d.%d.%d(%d) -> %d.%d.%d.%d(%d) %s\n",
            proto,
            rule->src_addr.s_net, rule->src_addr.s_host, rule->src_addr.s_lh, rule->src_addr.s_impno,
            rule->src_port,
            rule->dst_addr.s_net, rule->dst_addr.s_host, rule->dst_addr.s_lh, rule->dst_addr.s_impno,
            rule->dst_port,
            action_string[rule->action]
            );
}

