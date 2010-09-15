 /************************************************************* 
 * �ʰ� packet �ե��륿��
 * 
 * /usr/local/bin/gcc -D_KERNEL fwall.c -c
 * ld -dn -r fwall.o fwall_check_rule.o -o fwall
 *
 * �ѹ�����
 *   2005/03/04
 *     o �����ץ󤷤Ƥ��ʤ� UDP �ݡ��Ȥ˥ѥ��åȤ����������
 *       PANIC ���Ƥ��ޤ����������
 *     o ���� message ��ʣ���� mblk ����������Ǥ⡢�롼���
 *       �����å����Ǥ���褦�ˤ�����
 *     o REJECT �롼��� DENY �롼��������ˤ�����
 *   2005/03/09
 *     o �롼��˴�Ϣ����ե��󥯥�������Ω������
 *     o �⥸�塼��� open ��˳��ݤ���� fwall ��¤�Τ� stream �Υ��ɥ쥹��
 *       ��Ǽ����褦�ˤ���Ʊ�� stream �ˣ��Ĥ� fwall �⥸�塼�뤬���������
 *       ���Ȥ�̵���褦�ˤ�����
 *     o Debug �����Ѥδؿ����ɲä�����
 *   2005/03/10
 *     o �����󥹥ȥ꡼�ࡢ���åץ��ȥ꡼��Ȥ�ˡ�M_DATA ��å����������Ǥʤ�
 *       M_PROTO �˴ޤޤ��ǡ���(DL_UNITDATA_REQ, DL_UNITDATA_IND) ������å�
 *       �Ǥ���褦�ˤ�����(M_DATA �� NIC �ɥ饤�ФȤΥǡ����Τ��Ȥ�򤹤�
 *       �Τ� Sun �� NIC �ɥ饤�Ф����Τ褦��)
 *     o ����������å�����(mblk) ����� pullupmsg(9F)�ˤ�äơ��ǡ�������ޤȤᡢ
 *       ʣ���� mblk ��Ϣ�ʤäƤ�����Ǥ����ǡ������ǧ�Ǥ���褦�ˤ�����
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

/*
 * �⥸�塼��Υ����Х�ǡ��� �ǽ�Υ롼��ؤΥݥ��󥿤��Ǽ
 * ���Υǡ����ν񤭹��ߤ���¾Ū�˹Ԥ��ʤ���Фʤ�ʤ�
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
 * �⥸�塼��Υ����ץ�롼����
 */
static int
fwall_open (queue_t* q, dev_t *dev, int oflag, int sflag, cred_t *cred)
{
    fwall_t *fwall, *fwp;
    struct stdata *stream; /* ���� queue �� stream �Υݥ��� */

    if (sflag != MODOPEN){
        return EINVAL;
    }
    
    stream = q->q_stream;

    /*
     * fwall ��¤�ΤΥꥹ�Ȥ��椫�顢Ʊ�����ɥ쥹�� stream ����äƤ���
     * ��Τ�̵�����ɤ���������å����롣�⤷����С�����ϣ��Ĥ�� fwall
     * �⥸�塼�뤬 STREAM ����������褦�Ȥ��Ƥ��뤳�Ȥ��̣����Τǡ����顼
     * ���֤���
     * fwall �⥸�塼��� D_MTOCEXCL �ե饰�򤿤ƤƤ���Τǡ����� open(9E)
     * �롼�������¾Ū��(PERMOD)�˥�����������롣���Τ��ᡢ�ʲ��ν����Ǥ�
     * ��å��ϼ������ʤ���
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
 * �⥸�塼��Υ������롼����
 */
static int
fwall_close (queue_t *q, int flag, int sflag, cred_t *cred)
{
    fwall_t *fwall = q->q_ptr;

    qprocsoff(q);
    q->q_ptr = WR(q)->q_ptr = NULL;

    /*
     * fwall ��¤�ΤΥꥹ�Ȥ��椫�顢���� stream �Υ���ȥ��
     * ������롣�����ץ�ξ���Ʊ�ͤˡ����ν����Τ���˥�å�
     * ���������ɬ�פ�̵����
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
 * fwall �⥸�塼��� write put ��³��
 * 
 * STREAM �ξ��������夷�� message �ν�����Ԥ�
 * ����� ip �⥸�塼��� putnext() ����ƤФ�롣
 *************************************************************************/
static int
fwall_wput(queue_t *q, mblk_t *mp)
{
    mblk_t *mp2;
    struct iocblk *iocp;
    
    switch(mp->b_datap->db_type){
        case M_DATA:
            /* �̾�Υǡ�����å��������롼�������å����� */
            fwall_data_wput(q, mp);
            return(0);
        case M_PROTO:            
        case M_PCPROTO:
            /* �ץ�ȥ����å�������DL_UNITDATA_REQ �β�ǽ���⤢�� */            
            fwall_proto_wput(q, mp);
            return(0);
        case M_IOCTL:
            /*
             * IOCTL �� message��fwalladm ����Υ롼������ꥳ�ޥ�ɤ�
             * ���äƤ��뤫�⤷��ʤ����⤷��ä��鼡�Υɥ饤�Ф� put
             */
            iocp = (struct iocblk *)mp->b_rptr;
            switch (iocp->ioc_cmd) {
                case ADDRULE:
                case INSERTRULE:
                    /* b_cont �����äƤ���Τϥ��ޥ�ɰ��������ä��ǡ��� message �ΤϤ�*/
                    mp2 = mp->b_cont;
                    if(!mp2 || mp2->b_datap->db_type != M_DATA){
                        /*
                         * b_cont �� M_DATA message ���ޤޤ�Ƥ��ʤ���
                         * M_IOCNAK(=�������) ���֤������顼ɽ�� 
                         */
                        mp->b_datap->db_type = M_IOCNAK;
                        qreply(q, mp);
                        DEBUG_PRINT0(CE_CONT, "IOCTL message doesn't have M_DATA message");
                        return(0);
                    }
                    /* �����Х�ǡ������ѹ�����Τǡ���¾�⡼�ɤ˥��åץ��졼�� */
                    qwriter(q, mp, fwall_insert_rule, PERIM_OUTER);
                    return(0);
                case DELRULE:
                    /* b_cont �����äƤ���Τϥ��ޥ�ɰ��������ä��ǡ��� message �ΤϤ� */
                    mp2 = mp->b_cont;
                    if(!mp2 || mp2->b_datap->db_type != M_DATA){
                        /*
                         * b_cont �� M_DATA message ���ޤޤ�Ƥ��ʤ���
                         * M_IOCNAK(=�������) ���֤������顼ɽ��
                         */                             
                        mp->b_datap->db_type = M_IOCNAK;
                        qreply(q, mp);
                        DEBUG_PRINT0(CE_CONT, "IOCTL message doesn't have M_DATA message");
                        return(0);
                    }
                    /* �����Х�ǡ������ѹ�����Τǡ���¾�⡼�ɤ˥��åץ��졼�� */
                    qwriter(q, mp, fwall_delete_rule, PERIM_OUTER);
                    return(0);                    
                case GETRULE:
                    fwall_get_rule(q, mp);
                    return(0);
                    
                default:
                    /* fwall �⥸�塼��� IOCTL ���ޥ�ɤǤϤʤ� */
                    break;
            }
            break;
                    
        default:
            /*
             * M_DATA �Ǥ� M_IOCTL �Ǥ�̵�� message��
             * ���Τޤ޼��Υ⥸�塼��ʥɥ饤�Сˤ� put
             */
            break;
    }
    putnext(q, mp);
    return(0);
}

/**********************************************************************
 * fwall_rput()
 * fwall �⥸�塼��� read put ��³��
 * 
 * STREAM �β����������夷�� message �ν�����Ԥ�
 * ����ϥ��󥿡��ե������ɥ饤�Ф� putnext() ���ƤФ�롣
 ***********************************************************************/
static int
fwall_rput(queue_t *q, mblk_t *mp)
{

    switch(mp->b_datap->db_type){
        case M_PROTO:            
        case M_PCPROTO:
            /* �ץ�ȥ��� message��DL_UNITDATA_IND �β�ǽ���⤢�� */
            fwall_proto_rput(q, mp);
            return(0);        
        case M_DATA:
            /* �̾�Υǡ��� message */
            fwall_data_rput(q, mp);
            return(0);
        default:
            /* �ǡ��� message �Ǥʤ������Υ⥸�塼���IP) �� put */
            break;
    }

    putnext(q, mp);
    return(0);
}

/*****************************************************************************
 * fwall_add_to_list
 * 
 * fwall ��¤�ΤΥ�󥯥ꥹ�Ȥ˿����� fwall ��¤�Τ��ɲä��롣
 * �����Х�ǡ������ѹ����뤿��ˤϡ���¾�⡼�ɤǤʤ��ƤϤʤ�ʤ��Τ���
 * ���Υ롼�����ɬ�� fwall_open() ���餷���ƤФ�ʤ��Τǡ����ˤ��ʤ��Ƥ�����
 *
 *  ������
 *           fwall:  �ꥹ�Ȥ��ɲä��� fwall ��¤��
 *
 * ����͡�
 *           ��� 0
 *****************************************************************************/
static int
fwall_add_to_list(fwall_t *fwall)
{
    fwall_t *fwp;

    if ((fwp = fwall_head) == NULL){
        /* ���ֺǽ�Υ⥸�塼��Υ����ץ�� */
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
 * fwall ��¤�ΤΥ�󥯥ꥹ�Ȥ��� fwall ��¤�Τ�Ϥ�����
 * �����Х�ǡ������ѹ����뤿��ˤϡ���¾�⡼�ɤǤʤ��ƤϤʤ�ʤ��Τ���
 * ���Υ롼�����ɬ�� fwall_close() ���餷���ƤФ�ʤ��Τǡ����ˤ��ʤ��Ƥ�����
 *
 *  ������
 *           fwall: �ꥹ�Ȥ���Ϥ��� fwall ��¤��
 *           
 * ����͡�
 *           ������   : 0
 *           ���顼�� : -1
 *****************************************************************************/
static int
fwall_delete_from_list(fwall_t *fwall)
{
    fwall_t *fwp, *fwprevp;

    if ((fwp = fwall_head) == NULL){
        /*
         * fwall_close ���ƤФ�Ƥ���Τ� fwall_head �� NULL ����
         * �������ʤ��ʤϤ��Ρ˾�����
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
 * �ǥХå������Ѵؿ�
 *
 *  ������
 *           level  :  ���顼�ο����١�cmn_err(9F) ��������������
 *           format :  ��å������ν��ϥե����ޥå�cmn_err(9F) ���������������
 * ����͡�
 *           �ʤ���
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
 * M_DATA ��å������Ѥ� write ������ put(9E) �롼����
 *
 *  ������
 *           q : write �����ɤ� queue �Υݥ���
 *           mp: ����������å������֥�å��Υݥ���
 * 
 * ����͡�
 *          ��� 0 
 *****************************************************************************/
static int
fwall_data_wput(queue_t *q, mblk_t *mp)
{
    struct ip     *ip = NULL;          /* IP �إå���¤��          */
    mblk_t        *newmp = NULL;       /* ʣ���� mblk ��ʬ���줿 message ��ҤȤĤˤޤȤ᤿��� */
    int           len;

    /* Ϣ�ʤä�ʣ���� mblk �� 1 �Ĥ� message �˥��ԡ����� */
    newmp = msgpullup(mp, -1);

    if (newmp == NULL){
        /* msgpullup() �����Ԥ�����memory ��­�� */
        DEBUG_PRINT0(CE_CONT, "fwall_data_wput: msgpullup failed\n");
        freemsg(mp);
        return(0);
    }

    len = msgdsize(newmp);

    /*
     * ���ԡ����� mblk �� b_rptr �� Ethernet �إå��ʤΤǡ�14 byte ���餷��
     * IP �Υݥ��󥿤����롣
     */    
    ip = (struct ip *)(newmp->b_rptr + 14);
    
    if (fwall_check_rule_ip(ip, len) == ALLOW){
        /* ���Ĥ��줿�����Υ⥸�塼��� */        
        putnext(q, mp);        
    } else {
        /* ���Ĥ���ʤ��ä�����å������� Free ���� */        
        freemsg(mp);
    }

    /* msgpullup() �ǥ��ԡ�������å�������⤦�פ�ʤ� */    
    freemsg(newmp);
    return(0);
}

/*****************************************************************************
 * fwall_proto_wput()
 * 
 * M_PCPROTO ����� M_PROTO ��å������Ѥ� write ������ put �롼����
 * IP ����Υǡ����� DL_UNITDATA_REQ �ץ�ߥƥ��֤Ȥ��Ƥ����ǽ���⤢�뤿�ᡢ
 * ���ξ���³���� M_DATA ��å������Τ˴ޤޤ�� IP �ǡ���������å����롣
 *
 *  ������
 *           q : write �����ɤ� queue �Υݥ���
 *           mp: ����������å������֥�å��Υݥ���
 * ����͡�
 *          ��� 0 
 *****************************************************************************/
static int
fwall_proto_wput(queue_t *q, mblk_t *mp)
{
    struct ip   *ip = NULL;          /* IP �إå���¤��   */
    mblk_t      *newmp = NULL;       /* Ĵ���Ѥΰ�� mblk */
    t_uscalar_t *dl_primitive;
    int         len;

    dl_primitive = (t_uscalar_t *)mp->b_rptr;

    /*
     * �⤷ DL_UNITDATA_REQ �ץ�ߥƥ��֤Ǥʤ���С��롼���
     * �����å���ɬ�פʤ��ΤǼ��Υ⥸�塼��ʥɥ饤�Сˤ��Ϥ�
     */
    if(*dl_primitive != DL_UNITDATA_REQ){
        putnext(q, mp);
        return(0);
    }
    
    DEBUG_PRINT0(CE_CONT,"fwall_proto_wput: get DL_UNITDATA_REQ");

    /*
     * ���� M_PROTO ��³��(b_cont)�� message �� IP �ǡ�����ޤ� M_DATA
     * ��å������ΤϤ���Ϣ�ʤä�ʣ���� mblk �� 1 �Ĥ� message �˥��ԡ����� 
     */
    newmp = msgpullup(mp->b_cont, -1);

    if (newmp == NULL){
        /* msgpullup() �����Ԥ�����memory ��­�� */
        DEBUG_PRINT0(CE_CONT, "fwall_proto_wput: msgpullup failed\n");
        freemsg(mp);
        return(0);
    }

    len = msgdsize(newmp);
    
    /*
     * ���ԡ����� mblk �� b_rptr �� IP �إå���
     */
    ip = (struct ip *)newmp->b_rptr;

    if (fwall_check_rule_ip(ip, len) == ALLOW){
        /* ���Ĥ��줿�����Υ⥸�塼��� */
        putnext(q, mp);        
    } else {
        /* ���Ĥ���ʤ��ä�����å������� Free ���� */
        freemsg(mp);
    }

    /* msgpullup() �ǥ��ԡ�������å�������⤦�פ�ʤ� */
    freemsg(newmp);
    return(0);
}

/*****************************************************************************
 * fwall_data_rput()
 * 
 * M_DATA ��å������Ѥ� read ������ put(9E) �롼����
 *
 *  ������
 *           q : read �����ɤ� queue �Υݥ���
 *           mp: ����������å������֥�å��Υݥ���
 * 
 * ����͡�
 *          ��� 0 
 *****************************************************************************/
static int
fwall_data_rput(queue_t *q, mblk_t *mp)
{
    struct ip     *ip = NULL;          /* IP �إå���¤��          */    
    mblk_t        *newmp = NULL;
    int           len;

    /* Ϣ�ʤä�ʣ���� mblk �� 1 �Ĥ� message �˥��ԡ����� */
    newmp = msgpullup(mp, -1);

    if (newmp == NULL){
        /* msgpullup() �����Ԥ�����memory ��­�� */
        DEBUG_PRINT0(CE_CONT, "fwall_data_rput: msgpullup failed\n");
        freemsg(mp);
        return(0);
    }

    len = msgdsize(newmp);

    /*
     * ���ԡ����� mblk �� b_rptr �� IP �إå���
     */
    ip = (struct ip *)newmp->b_rptr;

    if (fwall_check_rule_ip(ip, len) == ALLOW){
        /* ���Ĥ��줿�����Υ⥸�塼��� */        
        putnext(q, mp);        
    } else {
        /* ���Ĥ���ʤ��ä�����å������� Free ���� */        
        freemsg(mp);
    }

    /* msgpullup() �ǥ��ԡ�������å�������⤦�פ�ʤ� */    
    freemsg(newmp);
    return(0);
}

/*****************************************************************************
 * fwall_proto_rput()
 * 
 * M_PCPROTO ����� M_PROTO ��å������Ѥ� read ������ put �롼����
 * �ɥ饤�Ф���Υѥ��åȥǡ����� DL_UNITDATA_IND �ץ�ߥƥ��֤Ȥ��Ƥ���
 * ��ǽ���⤢�뤿�ᡢ���ξ���³���� M_DATA ��å������Τ˴ޤޤ�� IP
 * �ǡ���������å����롣
 *
 *  ������
 *           q : read �����ɤ� queue �Υݥ���
 *           mp: ����������å������֥�å��Υݥ���
 * ����͡�
 *          ��� 0 
 *****************************************************************************/
static int
fwall_proto_rput(queue_t *q, mblk_t *mp)
{
    struct ip     *ip = NULL;          /* IP �إå���¤�� */    
    mblk_t        *newmp = NULL;                
    t_uscalar_t   *dl_primitive;
    int           len;

    dl_primitive = (t_uscalar_t *)mp->b_rptr;

    /*
     * �⤷ DL_UNITDATA_IND �ץ�ߥƥ��֤Ǥʤ���С��롼���
     * �����å���ɬ�פʤ��ΤǼ��Υ⥸�塼���IP�ˤ��Ϥ�
     */
    if(*dl_primitive != DL_UNITDATA_IND){
        putnext(q, mp);
        return(0);
    }
    
    DEBUG_PRINT0(CE_CONT,"fwall_proto_rput: get DL_UNITDATA_IND\n");

    /*
     * ���� M_PROTO ��³��(b_cont)�� mblk �� IP �ǡ�����ޤ� M_DATA
     * ��å������ΤϤ���Ϣ�ʤä�ʣ���� mblk �� 1 �Ĥ� message �˥��ԡ����� 
     */
    newmp = msgpullup(mp->b_cont, -1);
    if (newmp == NULL){
        /* msgpullup() �����Ԥ�����memory ��­�� */
        DEBUG_PRINT0(CE_CONT, "fwall_proto_rput: msgpullup failed\n");
        freemsg(mp);
        return(0);
    }

    len = msgdsize(newmp);
    
    /*
     * ���ԡ����� mblk �� b_rptr �� IP �إå���
     */
    ip = (struct ip *)newmp->b_rptr;

    if (fwall_check_rule_ip(ip, len) == ALLOW){
        /* ���Ĥ��줿�����Υ⥸�塼��� */        
        putnext(q, mp);        
    } else {
        /* ���Ĥ���ʤ��ä�����å������� Free ���� */        
        freemsg(mp);
    }
    
    /* msgpullup() �ǥ��ԡ�������å�������⤦�פ�ʤ� */
    freemsg(newmp);
    return(0);
}
