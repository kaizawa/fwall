/*
 * fwall �⥸�塼��ȡ�fwalladm ���ޥ���Ѥζ���
 * �إå��ե�����
 *
 */

#ifndef __FWALL_H
#define __FWALL__H

/* fwall �⥸�塼���Ѥ� STREAM ioctl ���ޥ��*/
#define ADDRULE     0xabc001    /* �롼����ɲ� */
#define DELRULE     0xabc002    /* �롼��κ�� */
#define GETRULE     0xabc003    /* �롼��μ��� */
#define INSERTRULE  0xabc004    /* �롼������� */

/* �롼��Υ�������� */
#define ALLOW  0x00  /* �̲���� */
#define REJECT 0x01  /* ���� */
#define DENY   0x02  /* ̵�� */

/* �롼��Υ����� */
#define PORTFILETER 0x01 /* �̾�Ρ����ɥ쥹���ݡ��ȥե��륿���Υ롼�� */
#define EXPRESSION  0x02 /* Ǥ�դΥե��륿���μ�����ꤷ���롼�� */

/* ����롼��� */
#define MAXRULES  255

/* �ġ��Υ롼������Ѥι�¤��*/
typedef struct fwall_rule {
    uint8_t            rule_type;   /* �롼��Υ����� */    
    struct in_addr     src_addr;    /* ���������ɥ쥹��PORTFILTER �ǻ���*/
    struct in_addr     dst_addr;    /* �����襢�ɥ쥹��PORTFILTER �ǻ��� */
    uint16_t           src_port;    /* �������ݡ��ȡ�PORTFILTER �ǻ��� */
    uint16_t           dst_port;    /* ������ݡ��ȡ�PORTFILTER �ǻ��� */
    uint8_t            proto;       /* �ץ�ȥ��롣PORTFILTER �ǻ��� */
    uint32_t           offset;      /* �ե��륿�����ϰ��֡� EXPRESSION �ǻ���*/
    uint32_t           length;      /* �ե������Ĺ��EXPRESSION �ǻ��� */
    uint32_t           value;       /* ��Ӥ����͡� EXPRESSION �ǻ��� */
    uint8_t            action;      /* �̲ᡢ���ݡ�̵�롣 */
    uint8_t            number;      /* �롼���ֹ档fwalladm ���ޥ�ɤ�����*/
    struct fwall_rule  *next_rule ; /* ���Υ롼��Υݥ��󥿡�fwall �⥸�塼�뤬���� */
    
}fwall_rule_t;

/*
 * �⥸�塼����Υץ饤�١��ȥǡ�����¤��
 * �ƥ⥸�塼�륤�󥹥��󥹤������˻��ĥץ饤�١��ȥǡ������Ǽ��
 */ 
typedef struct fwall
{
    struct in_addr *addr;   /* Not used now ... */
    struct stdata  *stream; /* stream �Υݥ��� */
    struct fwall *next;     /* ���� fwall ��¤�ΤؤΥݥ��� */
} fwall_t;

#ifdef _KERNEL
#define MAX_MSG 256  /* SYSLOG �˽��Ϥ����å������κ���ʸ���� */
/*
 * DEBUG �� define ����ȡ�DEBUG �⡼�� ON �ˤʤ� 
#define DEBUG
 */
/*
 * DEBUG �Ѥν��ϥ롼����
 * cmn_err(9F) �ˤ� syslog ��å���������Ϥ��롣
 * DEBUG �� on �ˤ���ȡ����ʤ�ΥǥХå���å���������Ͽ����롣
 */
#ifdef DEBUG
#define  DEBUG_PRINT0(level, format) debug_print(level, format)
#define  DEBUG_PRINT1(level, format, va1) debug_print(level, format, va1)
#define  DEBUG_PRINT2(level, format, va1, va2) debug_print(level, format, va1, va2)
#else
#define  DEBUG_PRINT0
#define  DEBUG_PRINT1
#define  DEBUG_PRINT2
#endif
#endif /* ifdef _KERNEL */

#endif /* #ifndef __FWALL_H */
