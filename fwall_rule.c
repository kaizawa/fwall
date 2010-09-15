/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1986, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copright (c) 2005-2010  Kazuyoshi Aizawa <admin2@whiteboard.ne.jp>
 * All rights reserved.
 */
/*************************************************************
 * 簡易 packet フィルターのルールモジュール
 * 
 * /usr/local/bin/gcc -D_KERNEL fwall_rule.c -c
 *
 * 変更履歴
 *   2005/03/09
 *     o ルールに関連するファンクションを独立させた
 *   2005/03/11
 *     o パケット拒否時にルール番号と、IP アドレスを syslog に表示するようにした。
 *     o ルールの追加時にポート番号と、プロトコルも syslog に表示するようにした。
 *     o IP ヘッダの解析時に IP ヘッダへのアドレスが 4 バイト境界上に無いために
 *        PANIC が発生(memory address not aligned)する問題を修正するため、
 *       データ部を一度コピーしてから、コピー後のデータを調査するようにした。
 *
 **************************************************************/

/* STREAM 用ヘッダ */
#include <sys/modctl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

/* TCP/IP 関連ヘッダ */
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

/* fwall モジュール用ヘッダ */
#include "fwall.h"

/* count に現在の総ルール数が入る */
#define RULES(count)  \
          for( rulep = rules_head, count = 0 ; rulep ; ++count, rulep = rulep->next_rule)
/* rulep に現在の指定のルール番号のルールのポインタが入る */
#define WALKRULE(rulep, number) \
          for( rulep = rules_head ; rulep && number ; --number, rulep = rulep->next_rule)
#define COMPARE_ADDR(address_1, address_2)  \
          (bcmp( address_1, address_2, sizeof(struct in_addr)) == 0)

#define IS_ALIGN(ip) (((ulong_t)ip % 4) == 0)


char *action_string[] = { "ALLOW", "REJECT", "DENY" };

/*
 * モジュールのグローバルデータ 最初のルールへのポインタを格納
 * このデータの書き込みは排他的に行われなければならない
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
 * ルールを追加する。モジュールのグローバルデータを変更することになる。
 * グローバルデータを変更するためには、排他モードでなくては ならないので、
 * このルーチンは必ず qwriter() から呼ばれる。
 *
 *  引数：
 *           q:  queue 構造体のポインタ
 *          mp:  message block のポインタ
 * 戻り値：
 *           なし。
 *****************************************************************************/
void 
fwall_insert_rule(queue_t *q, mblk_t *mp)
{
    fwall_rule_t   *new;          /* 新規に allocate するルール   */
    fwall_rule_t   *user_rule;    /* fwalladm から届いたルール    */
    fwall_rule_t   *rulep;        /* 処理用のポインタ             */
    uint32_t       rule_number;   /* 要求された追加するルール番号 */
    uint32_t       total_rules;   /* 現在の総ルール数             */
    struct iocblk *iocp;
    
    /* b_cont は fwalladm から届いたルールを含む M_DATA message へのポインタのはず*/
    user_rule = (fwall_rule_t *)mp->b_cont->b_rptr;

    /* total_rules に現在の総ルール数が入る */
    RULES(total_rules);    

    /* IOCTL コマンドが ADDRULE(追加）なら一番最後に、INSERTRULE（挿入）*/
    /* なら指定のルール番号にルールを追加                               */
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
    /* もし、以下の条件にあったらエラー            */
    /* 1. ルールの最大数を越えている               */
    /* 2. 現在のルール数より大きいルール番号を指定 */
    /*---------------------------------------------*/ 
    if( total_rules >= MAXRULES || rule_number > total_rules ){
        mp->b_datap->db_type = M_IOCNAK;
        qreply(q, mp);
        DEBUG_PRINT0(CE_CONT, "fwall_insert_rule: Couldn't insert new rule.\n");                    
        return;                        
    }
    DEBUG_PRINT1(CE_CONT, "fwall_insert_rule: Number of rules = %u",total_rules);
    
    /* fwalladm から届いたルール(user_rule)を新しく allocate したルール(new)にコピー */
    new = kmem_zalloc(sizeof(fwall_rule_t), KM_SLEEP);
    bcopy( user_rule, new , sizeof(fwall_rule_t));
    
    if(rules_head == NULL){
        /* ルールがまだ設定されていない。新しい ルールを rule_head として設定する */
        /* 最初のルールなので、fwalladm からきたルール番号は無視して０番ルールとする*/
        new->next_rule = NULL;        
        rules_head = new;
    } else if ( rule_number == 0){
        /* rule_head として既存のルール０の前にルールを追加 */
        new->next_rule = rules_head;
        rules_head = new;
    } else {
        /* ルールがすでに存在する。指定されたルール番号に、新しいルールを追加する */
        rulep = rules_head;

        /* 指定されたルール番号の一つ前のルールを探す*/
        WALKRULE(rulep, rule_number -1);
        
        /* rule_number 番目のルールとしてリンクリストの中に追加 */
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
 * fwalladm コマンドからのルールの削除要求を処理する
 *
 *  引数：
 *          q :  queue 構造体のポインタ
 *          mp:  message block のポインタ
 *
 * 戻り値：
 *           なし。
 *****************************************************************************/ 
void
fwall_delete_rule(queue_t *q, mblk_t *mp)
{
    fwall_rule_t *rulep;         /* 処理用のポインタ             */
    fwall_rule_t *delp;          /* 削除するルール               */
    uint32_t      rule_number;   /* 要求された削除するルール番号 */
    uint32_t      total_rules;   /* 現在の総ルール数             */    

    /* b_cont でポイントされている message の read ポインターは削除するルール番号のはず */
    rule_number = *(uint32_t *)mp->b_cont->b_rptr;
    
    /* total_rules に現在の総ルール数が入る */
    RULES(total_rules);
    
    /*----------------------------------------------------------*/    
    /* もし、以下の条件にマッチしたらエラー                     */
    /* 1.ルールの最大数を越えている                             */
    /* 2.現在のルール数 -1 より大きいルール番号が指定されている */
    /* 3.現在ルールが一つも設定されていない                     */
    /*----------------------------------------------------------*/    
    if( total_rules >= MAXRULES || total_rules == 0 || rule_number > total_rules -1 ){
        mp->b_datap->db_type = M_IOCNAK;
        qreply(q, mp);
        DEBUG_PRINT1(CE_CONT, "fwall_delete_rule: Couldn't remove rule number %u.\n", rule_number);
        return;                        
    }
    
    if( rule_number == 0){
        /* 最初のルール(=rules_head)の削除要求                        */
        /* リンクリストのリンクを張りなおし、その後ルールを free する */        
        rulep = rules_head;
        rules_head = rules_head->next_rule;
        kmem_free(rulep, sizeof(fwall_rule_t));
        mp->b_datap->db_type = M_IOCACK;
        qreply(q, mp);
        cmn_err(CE_CONT, "Rule %u removed",*(uint32_t *)mp->b_cont->b_rptr);        
        return;
    } else if( rule_number > 0){
        rulep = rules_head;
        /* 削除する一つ前のルールを探す*/
        WALKRULE(rulep, rule_number -1);

        /* この時点で rulep は削除する一つ前のルールのはず*/
        if (rulep->next_rule == NULL){
            /* 入力されたルール番号は無い             */
            /* M_IOCNAK(=否定応答) を返し、エラー表示 */            
            mp->b_datap->db_type = M_IOCNAK;
            qreply(q, mp);
            cmn_err(CE_CONT, "Invalid rule number");                        
            return;
        }
        /* リンクリストのリンクを張りなおし、その後ルールを free する */
        delp = rulep->next_rule;
        rulep->next_rule = delp->next_rule;
        kmem_free(delp,sizeof(fwall_rule_t));
        mp->b_datap->db_type = M_IOCACK;
        qreply(q, mp);            
        cmn_err(CE_CONT, "Rule %u removed", *(uint32_t *)mp->b_cont->b_rptr);        
        return;
        
    } else {
        /* 入力されたルール番号は無い             */
        /* M_IOCNAK(=否定応答) を返し、エラー表示 */        
        mp->b_datap->db_type = M_IOCNAK;
        qreply(q, mp);
        cmn_err(CE_CONT, "Invalid rule number");                                    
        return;
    }
}

/******************************************************************************
 * fwall_get_rule()
 * 指定された番号のルールを探し、返答する
 *
 *  引数：
 *          q :  queue 構造体のポインタ
 *          mp:  message block のポインタ
 *
 * 戻り値：
 *           なし。
 *******************************************************************************/
void
fwall_get_rule(queue_t *q, mblk_t *mp)
{
    fwall_rule_t  *user_rule;    /* fwalladm から届いたルール*/
    fwall_rule_t  *rulep;        /* 処理用のポインタ         */
    uint32_t      rule_number;   /* ルール番号               */

    user_rule = (fwall_rule_t *)mp->b_cont->b_rptr;
    rule_number = user_rule->number;
    if(rules_head == NULL){
        /* ルールはまだ一つも設定されていない!!
         * M_IOCNAK(=否定応答) を返す*/
        mp->b_datap->db_type = M_IOCNAK;
        qreply(q, mp);
        return;
    }    
    rulep = rules_head;
    while(rule_number){
        /* rule_number 番目のルールを探す*/
        if(rulep->next_rule == NULL){
            /* 入力されたルール番号は無い
             * M_IOCNAK(=否定応答) を返す */
            mp->b_datap->db_type = M_IOCNAK;
            qreply(q, mp);
            return;                
        } 
        rulep = rulep->next_rule;
        rule_number--;            
    }
    /* この時点で rulep に n 番目のルールが入る。
     * それを user_rule、つまり M_IOCTL message
     * の b_cont で繋がった M_DATA message にコピー
     * してfwalladm コマンドに返信してやる*/
    bcopy(rulep, user_rule, sizeof(fwall_rule_t));
    mp->b_datap->db_type = M_IOCACK;
    qreply(q, mp);    
    return;
}

/******************************************************************************
 * fwall_check_rule_ip
 * 
 * 引数として渡された IP ヘッダへのポインタがルールにマッチするかをチェック
 *
 *  引数：
 *          ip :  ip ヘッダへのポインタ
 *
 * 戻り値：
 *          転送許可の場合   : 0
 *          転送不許可の場合 : -1
 *******************************************************************************/
int
fwall_check_rule_ip(struct ip *orgip, int len)
{
    struct tcphdr *tcphdr;             /* TCP ヘッダ構造体         */
    struct udphdr *udphdr;             /* UDP ヘッダ構造体         */
    fwall_rule_t  *rulep;              /* 処理用のルールのポインタ */
    uint16_t      src_port, dst_port;  /* 送信元、あて先ポート     */
    uint8_t       proto;
    struct ip     *ip;
    uint32_t      rule_number;   /* ルール番号 */

    /*
     * アラインメントの問題があるので、調査用の buffer を用意して、そちらに IP のデータ
     * をコピーしてから調査を行うことにする。
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
     * ip_p にて protocol を判定し、TCP, UDP のポートを調べる。
     * TCP,UDP どちらでもない場合は 0 を入れておく
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
                /* 送信元、発信元アドレスが ACCEPT ルールのアドレスにマッチするか比較 */
                if(
                    (ip->ip_src.s_addr == rulep->src_addr.s_addr || rulep->src_addr.s_addr == INADDR_ANY)&&
                    (ip->ip_dst.s_addr == rulep->dst_addr.s_addr || rulep->dst_addr.s_addr == INADDR_ANY)&&
                    ( proto == rulep->proto || rulep->proto == IPPROTO_IP)&&
                    (dst_port == rulep->dst_port || rulep->dst_port == 0)&&
                    (src_port == rulep->src_port || rulep->src_port == 0)
                    )
                    {
                        /* マッチしたら 0 をリターン。putnext() するのは呼び出した関数の責任 */
                        kmem_free(ip, len);                                
                        return(ALLOW);                    
                    }                
            case REJECT:
                /* 未実装。DENY と等価にする。*/
            case DENY:
                /* 送信元、発信元アドレスが DENY ルールのアドレスにマッチするか比較 */
                if(
                    (ip->ip_src.s_addr == rulep->src_addr.s_addr || rulep->src_addr.s_addr == INADDR_ANY)&&
                    (ip->ip_dst.s_addr == rulep->dst_addr.s_addr || rulep->dst_addr.s_addr == INADDR_ANY)&&
                    (proto == rulep->proto || rulep->proto == IPPROTO_IP)&&
                    (dst_port == rulep->dst_port || rulep->dst_port == 0)&&
                    (src_port == rulep->src_port || rulep->src_port == 0)
                    )
                    {
                        /* マッチしたら DENY(0x2) をリターン。freemsg() するのは呼び出した関数の責任 */
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
    }/* for 終了 */

    /*
     * どのルールにもマッチしなかったので ALLOW をリターン。
     */
    kmem_free(ip, len);                            
    return(ALLOW);
}

/******************************************************************************
 * fwall_print_rule
 * 
 * 引数として渡された ルールを syslog に出力する
 * （追加時専用・・にしてしまった。要改善）
 *
 *  引数：
 *          rule :  ルールへのポインタ
 *
 * 戻り値：
 *          なし
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

