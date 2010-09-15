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
 * 簡易 packet フィルター
 * 
 * /usr/local/bin/gcc -D_KERNEL fwall.c -c
 * ld -dn -r fwall.o fwall_check_rule.o -o fwall
 *
 * 変更履歴
 *   2005/03/04
 *     o オープンしていない UDP ポートにパケットを受けた場合に
 *       PANIC してしまう問題を修正。
 *     o 送信 message が複数の mblk から成る場合でも、ルールの
 *       チェックができるようにした。
 *     o REJECT ルールを DENY ルールと等価にした。
 *   2005/03/09
 *     o ルールに関連するファンクションを独立させた
 *     o モジュールの open 毎に確保される fwall 構造体に stream のアドレスを
 *       格納するようにし、同一 stream に２つの fwall モジュールが挿入される
 *       ことが無いようにした。
 *     o Debug 出力用の関数を追加した。
 *   2005/03/10
 *     o ダウンストリーム、アップストリームともに、M_DATA メッセージだけでなく
 *       M_PROTO に含まれるデータ(DL_UNITDATA_REQ, DL_UNITDATA_IND) もチェック
 *       できるようにした。(M_DATA で NIC ドライバとのデータのやりとりをする
 *       のは Sun の NIC ドライバだけのよう。)
 *     o 受信したメッセージ(mblk) を毎回 pullupmsg(9F)によって、データ部をまとめ、
 *       複数の mblk が連なっている場合でも全データを確認できるようにした。
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

/*
 * モジュールのグローバルデータ 最初のルールへのポインタを格納
 * このデータの書き込みは排他的に行われなければならない
 */
fwall_t *fwall_head = NULL;
                                   
static int   fwall_open (queue_t*, dev_t*, int, int, cred_t*);
static int   fwall_close (queue_t*, int, int, cred_t*);
static int   fwall_rput (queue_t*, mblk_t*);
static int   fwall_wput (queue_t*, mblk_t*);
static int   fwall_data_rput(queue_t *, mblk_t *);
static int   fwall_data_wput(queue_t *, mblk_t *);
static int   fwall_proto_wput(queue_t *, mblk_t *);
static int   fwall_proto_rput(queue_t *, mblk_t *);
static int   fwall_add_to_list(fwall_t *);
static int   fwall_delete_from_list(fwall_t *);

void debug_print(int , char *, ...);
extern void  fwall_insert_rule (queue_t*, mblk_t*);
extern void  fwall_delete_rule (queue_t*, mblk_t*);
extern void  fwall_get_rule (queue_t*, mblk_t*);
extern int   fwall_check_rule_ip(struct ip *, int);

static struct module_info minfo =
{ 0xdefe, "fwall", 1, INFPSZ, 512, 128 };

static struct qinit rinit = {
  fwall_rput, NULL, fwall_open, fwall_close, NULL, &minfo, NULL};

static struct qinit winit = {
  fwall_wput, NULL, NULL, NULL, NULL, &minfo, NULL};
   
struct streamtab fwmdinfo={ 
  &rinit, &winit, NULL, NULL};

static struct fmodsw fw_fmodsw ={
  "fwall", &fwmdinfo, (D_NEW|D_MP|D_MTQPAIR|D_MTOUTPERIM|D_MTOCEXCL)
};

struct modlstrmod modlstrmod ={  
  &mod_strmodops, "simple firewall module", &fw_fmodsw };

static struct modlinkage modlinkage ={ 
  MODREV_1, (void *)&modlstrmod, NULL };


int
_init()
{
	return (mod_install(&modlinkage));
}

int
_info(modinfop)
	struct modinfo *modinfop;
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

/*
 * モジュールのオープンルーチン
 */
static int
fwall_open (queue_t* q, dev_t *dev, int oflag, int sflag, cred_t *cred)
{
    fwall_t *fwall, *fwp;
    struct stdata *stream; /* この queue の stream のポインタ */

    if (sflag != MODOPEN){
        return EINVAL;
    }
    
    stream = q->q_stream;

    /*
     * fwall 構造体のリストの中から、同じアドレスの stream を持っている
     * ものが無いかどうかをチェックする。もしあれば、それは２つめの fwall
     * モジュールが STREAM に挿入されようとしていることを意味するので、エラー
     * を返す。
     * fwall モジュールは D_MTOCEXCL フラグをたてているので、この open(9E)
     * ルーチンは排他的に(PERMOD)にアクセスされる。そのため、以下の処理では
     * ロックは取得しない。
     */
    for( fwp = fwall_head ; fwp != NULL ; fwp = fwp->next){
        if (fwp->stream == stream){
            DEBUG_PRINT0(CE_CONT, "fwall module alreay exists on this stream");
            return EINVAL;
        }
    }

    fwall = kmem_zalloc(sizeof(struct fwall), KM_SLEEP);

    if(fwall == NULL){
        return EAGAIN;
    }

    if(fwall_add_to_list(fwall) < 0){
        kmem_free(fwall, sizeof(struct fwall));        
        return EINVAL;
    }

    fwall->stream = stream;
    
    q->q_ptr = WR(q)->q_ptr = fwall;
    qprocson(q);
    return (0);
}

/*
 * モジュールのクローズルーチン
 */
static int
fwall_close (queue_t *q, int flag, int sflag, cred_t *cred)
{
    fwall_t *fwall = q->q_ptr;

    qprocsoff(q);
    q->q_ptr = WR(q)->q_ptr = NULL;

    /*
     * fwall 構造体のリストの中から、この stream のエントリを
     * 削除する。オープンの場合と同様に、この処理のためにロック
     * を取得する必要は無い。
     */
    if(fwall_delete_from_list(fwall) < 0){
        kmem_free(fwall,sizeof(struct fwall));
        return(DDI_FAILURE);        
    }
    
    kmem_free(fwall,sizeof(struct fwall));
    return(0);
}

/*************************************************************************
 * fwall_wput()
 * fwall モジュールの write put 手続き
 * 
 * STREAM の上方ら到着した message の処理を行う
 * これは ip モジュールの putnext() から呼ばれる。
 *************************************************************************/
static int
fwall_wput(queue_t *q, mblk_t *mp)
{
    mblk_t *mp2;
    struct iocblk *iocp;
    
    switch(mp->b_datap->db_type){
        case M_DATA:
            /* 通常のデータメッセージ。ルールをチェックする */
            fwall_data_wput(q, mp);
            return(0);
        case M_PROTO:            
        case M_PCPROTO:
            /* プロトコルメッセージ。DL_UNITDATA_REQ の可能性もある */            
            fwall_proto_wput(q, mp);
            return(0);
        case M_IOCTL:
            /*
             * IOCTL の message。fwalladm からのルールの設定コマンドが
             * 入っているかもしれない。もし違ったら次のドライバへ put
             */
            iocp = (struct iocblk *)mp->b_rptr;
            switch (iocp->ioc_cmd) {
                case ADDRULE:
                case INSERTRULE:
                    /* b_cont に入っているのはコマンド引数が入ったデータ message のはず*/
                    mp2 = mp->b_cont;
                    if(!mp2 || mp2->b_datap->db_type != M_DATA){
                        /*
                         * b_cont に M_DATA message が含まれていない！
                         * M_IOCNAK(=否定応答) を返し、エラー表示 
                         */
                        mp->b_datap->db_type = M_IOCNAK;
                        qreply(q, mp);
                        DEBUG_PRINT0(CE_CONT, "IOCTL message doesn't have M_DATA message");
                        return(0);
                    }
                    /* グローバルデータを変更するので、排他モードにアップグレード */
                    qwriter(q, mp, fwall_insert_rule, PERIM_OUTER);
                    return(0);
                case DELRULE:
                    /* b_cont に入っているのはコマンド引数が入ったデータ message のはず */
                    mp2 = mp->b_cont;
                    if(!mp2 || mp2->b_datap->db_type != M_DATA){
                        /*
                         * b_cont に M_DATA message が含まれていない！
                         * M_IOCNAK(=否定応答) を返し、エラー表示
                         */                             
                        mp->b_datap->db_type = M_IOCNAK;
                        qreply(q, mp);
                        DEBUG_PRINT0(CE_CONT, "IOCTL message doesn't have M_DATA message");
                        return(0);
                    }
                    /* グローバルデータを変更するので、排他モードにアップグレード */
                    qwriter(q, mp, fwall_delete_rule, PERIM_OUTER);
                    return(0);                    
                case GETRULE:
                    fwall_get_rule(q, mp);
                    return(0);
                    
                default:
                    /* fwall モジュールの IOCTL コマンドではない */
                    break;
            }
            break;
                    
        default:
            /*
             * M_DATA でも M_IOCTL でも無い message。
             * そのまま次のモジュール（ドライバ）へ put
             */
            break;
    }
    putnext(q, mp);
    return(0);
}

/**********************************************************************
 * fwall_rput()
 * fwall モジュールの read put 手続き
 * 
 * STREAM の下方から到着した message の処理を行う
 * これはインターフェースドライバの putnext() より呼ばれる。
 ***********************************************************************/
static int
fwall_rput(queue_t *q, mblk_t *mp)
{

    switch(mp->b_datap->db_type){
        case M_PROTO:            
        case M_PCPROTO:
            /* プロトコル message。DL_UNITDATA_IND の可能性もある */
            fwall_proto_rput(q, mp);
            return(0);        
        case M_DATA:
            /* 通常のデータ message */
            fwall_data_rput(q, mp);
            return(0);
        default:
            /* データ message でない。次のモジュール（IP) へ put */
            break;
    }

    putnext(q, mp);
    return(0);
}

/*****************************************************************************
 * fwall_add_to_list
 * 
 * fwall 構造体のリンクリストに新しい fwall 構造体を追加する。
 * グローバルデータを変更するためには、排他モードでなくてはならないのが、
 * このルーチンは必ず fwall_open() からしか呼ばれないので、気にしなくていい。
 *
 *  引数：
 *           fwall:  リストに追加する fwall 構造体
 *
 * 戻り値：
 *           常に 0
 *****************************************************************************/
static int
fwall_add_to_list(fwall_t *fwall)
{
    fwall_t *fwp;

    if ((fwp = fwall_head) == NULL){
        /* 一番最初のモジュールのオープンだ */
        fwall_head = fwall;
        fwall->next = NULL;
        return(0);
    }
    
    while(fwp){
        if(fwp->next == NULL){
            break;
        } else {
            fwp = fwp->next;
        }
    }

    fwp->next = fwall;
    fwall->next = NULL;
    return(0);
}
/*****************************************************************************
 * fwall_delete_from_list
 * 
 * fwall 構造体のリンクリストから fwall 構造体をはずず。
 * グローバルデータを変更するためには、排他モードでなくてはならないのが、
 * このルーチンは必ず fwall_close() からしか呼ばれないので、気にしなくていい。
 *
 *  引数：
 *           fwall: リストからはずす fwall 構造体
 *           
 * 戻り値：
 *           成功時   : 0
 *           エラー時 : -1
 *****************************************************************************/
static int
fwall_delete_from_list(fwall_t *fwall)
{
    fwall_t *fwp, *fwprevp;

    if ((fwp = fwall_head) == NULL){
        /*
         * fwall_close が呼ばれているのに fwall_head が NULL だ。
         * あり得ない（はずの）状況。
         */
        cmn_err(CE_CONT, "fwall_delete_from_list: fwall_head is NULL\n");
        return(-1);
    }

    fwprevp = (fwall_t *)NULL;
    do{
        if (fwp == fwall){
            if (fwprevp == NULL)
                fwall_head = (fwall_t *)NULL;
            else
                fwprevp->next = fwp->next;
            return(0);
        }
        fwprevp = fwp;
        fwp = fwp->next;
    } while(fwp);        

    cmn_err(CE_CONT, "fwall_delete_from_list: can't find fwall_t within link list\n");    
    return(-1);    
}

/*****************************************************************************
 * bebug_print()
 *
 * デバッグ出力用関数
 *
 *  引数：
 *           level  :  エラーの深刻度。cmn_err(9F) の第一引数に相当
 *           format :  メッセージの出力フォーマットcmn_err(9F) の第二引数に相当
 * 戻り値：
 *           なし。
 *****************************************************************************/
void
debug_print(int level, char *format, ...)
{ 
    va_list     ap;
    char        buf[MAX_MSG];

    va_start(ap, format);
    vsprintf(buf, format, ap);    
    va_end(ap);
    cmn_err(level, "%s", buf);
}    

/*****************************************************************************
 * fwall_data_wput()
 * 
 * M_DATA メッセージ用の write サイド put(9E) ルーチン。
 *
 *  引数：
 *           q : write サイドの queue のポインタ
 *           mp: 受信したメッセージブロックのポインタ
 * 
 * 戻り値：
 *          常に 0 
 *****************************************************************************/
static int
fwall_data_wput(queue_t *q, mblk_t *mp)
{
    struct ip     *ip = NULL;          /* IP ヘッダ構造体          */
    mblk_t        *newmp = NULL;       /* 複数の mblk に分かれた message をひとつにまとめたもの */
    int           len;

    /* 連なった複数の mblk を 1 つの message にコピーする */
    newmp = msgpullup(mp, -1);

    if (newmp == NULL){
        /* msgpullup() が失敗した。memory 不足？ */
        DEBUG_PRINT0(CE_CONT, "fwall_data_wput: msgpullup failed\n");
        freemsg(mp);
        return(0);
    }

    len = msgdsize(newmp);

    /*
     * コピーした mblk の b_rptr は Ethernet ヘッダなので、14 byte ずらして
     * IP のポインタを得る。
     */    
    ip = (struct ip *)(newmp->b_rptr + 14);
    
    if (fwall_check_rule_ip(ip, len) == ALLOW){
        /* 許可された。次のモジュールへ */        
        putnext(q, mp);        
    } else {
        /* 許可されなかった。メッセージを Free する */        
        freemsg(mp);
    }

    /* msgpullup() でコピーしたメッセージももう要らない */    
    freemsg(newmp);
    return(0);
}

/*****************************************************************************
 * fwall_proto_wput()
 * 
 * M_PCPROTO および M_PROTO メッセージ用の write サイド put ルーチン。
 * IP からのデータは DL_UNITDATA_REQ プリミティブとしてくる可能性もあるため、
 * その場合は続きの M_DATA メッセージのに含まれる IP データをチェックする。
 *
 *  引数：
 *           q : write サイドの queue のポインタ
 *           mp: 受信したメッセージブロックのポインタ
 * 戻り値：
 *          常に 0 
 *****************************************************************************/
static int
fwall_proto_wput(queue_t *q, mblk_t *mp)
{
    struct ip   *ip = NULL;          /* IP ヘッダ構造体   */
    mblk_t      *newmp = NULL;       /* 調査用の一時 mblk */
    t_uscalar_t *dl_primitive;
    int         len;

    dl_primitive = (t_uscalar_t *)mp->b_rptr;

    /*
     * もし DL_UNITDATA_REQ プリミティブでなければ、ルールの
     * チェックは必要ないので次のモジュール（ドライバ）へ渡す
     */
    if(*dl_primitive != DL_UNITDATA_REQ){
        putnext(q, mp);
        return(0);
    }
    
    DEBUG_PRINT0(CE_CONT,"fwall_proto_wput: get DL_UNITDATA_REQ");

    /*
     * この M_PROTO の続き(b_cont)の message は IP データを含む M_DATA
     * メッセージのはず。連なった複数の mblk を 1 つの message にコピーする 
     */
    newmp = msgpullup(mp->b_cont, -1);

    if (newmp == NULL){
        /* msgpullup() が失敗した。memory 不足？ */
        DEBUG_PRINT0(CE_CONT, "fwall_proto_wput: msgpullup failed\n");
        freemsg(mp);
        return(0);
    }

    len = msgdsize(newmp);
    
    /*
     * コピーした mblk の b_rptr は IP ヘッダ。
     */
    ip = (struct ip *)newmp->b_rptr;

    if (fwall_check_rule_ip(ip, len) == ALLOW){
        /* 許可された。次のモジュールへ */
        putnext(q, mp);        
    } else {
        /* 許可されなかった。メッセージを Free する */
        freemsg(mp);
    }

    /* msgpullup() でコピーしたメッセージももう要らない */
    freemsg(newmp);
    return(0);
}

/*****************************************************************************
 * fwall_data_rput()
 * 
 * M_DATA メッセージ用の read サイド put(9E) ルーチン。
 *
 *  引数：
 *           q : read サイドの queue のポインタ
 *           mp: 受信したメッセージブロックのポインタ
 * 
 * 戻り値：
 *          常に 0 
 *****************************************************************************/
static int
fwall_data_rput(queue_t *q, mblk_t *mp)
{
    struct ip     *ip = NULL;          /* IP ヘッダ構造体          */    
    mblk_t        *newmp = NULL;
    int           len;

    /* 連なった複数の mblk を 1 つの message にコピーする */
    newmp = msgpullup(mp, -1);

    if (newmp == NULL){
        /* msgpullup() が失敗した。memory 不足？ */
        DEBUG_PRINT0(CE_CONT, "fwall_data_rput: msgpullup failed\n");
        freemsg(mp);
        return(0);
    }

    len = msgdsize(newmp);

    /*
     * コピーした mblk の b_rptr は IP ヘッダ。
     */
    ip = (struct ip *)newmp->b_rptr;

    if (fwall_check_rule_ip(ip, len) == ALLOW){
        /* 許可された。次のモジュールへ */        
        putnext(q, mp);        
    } else {
        /* 許可されなかった。メッセージを Free する */        
        freemsg(mp);
    }

    /* msgpullup() でコピーしたメッセージももう要らない */    
    freemsg(newmp);
    return(0);
}

/*****************************************************************************
 * fwall_proto_rput()
 * 
 * M_PCPROTO および M_PROTO メッセージ用の read サイド put ルーチン。
 * ドライバからのパケットデータが DL_UNITDATA_IND プリミティブとしてくる
 * 可能性もあるため、その場合は続きの M_DATA メッセージのに含まれる IP
 * データをチェックする。
 *
 *  引数：
 *           q : read サイドの queue のポインタ
 *           mp: 受信したメッセージブロックのポインタ
 * 戻り値：
 *          常に 0 
 *****************************************************************************/
static int
fwall_proto_rput(queue_t *q, mblk_t *mp)
{
    struct ip     *ip = NULL;          /* IP ヘッダ構造体 */    
    mblk_t        *newmp = NULL;                
    t_uscalar_t   *dl_primitive;
    int           len;

    dl_primitive = (t_uscalar_t *)mp->b_rptr;

    /*
     * もし DL_UNITDATA_IND プリミティブでなければ、ルールの
     * チェックは必要ないので次のモジュール（IP）へ渡す
     */
    if(*dl_primitive != DL_UNITDATA_IND){
        putnext(q, mp);
        return(0);
    }
    
    DEBUG_PRINT0(CE_CONT,"fwall_proto_rput: get DL_UNITDATA_IND\n");

    /*
     * この M_PROTO の続き(b_cont)の mblk は IP データを含む M_DATA
     * メッセージのはず。連なった複数の mblk を 1 つの message にコピーする 
     */
    newmp = msgpullup(mp->b_cont, -1);
    if (newmp == NULL){
        /* msgpullup() が失敗した。memory 不足？ */
        DEBUG_PRINT0(CE_CONT, "fwall_proto_rput: msgpullup failed\n");
        freemsg(mp);
        return(0);
    }

    len = msgdsize(newmp);
    
    /*
     * コピーした mblk の b_rptr は IP ヘッダ。
     */
    ip = (struct ip *)newmp->b_rptr;

    if (fwall_check_rule_ip(ip, len) == ALLOW){
        /* 許可された。次のモジュールへ */        
        putnext(q, mp);        
    } else {
        /* 許可されなかった。メッセージを Free する */        
        freemsg(mp);
    }
    
    /* msgpullup() でコピーしたメッセージももう要らない */
    freemsg(newmp);
    return(0);
}
