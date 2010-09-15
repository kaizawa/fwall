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
/*
 * fwall モジュールと、fwalladm コマンド用の共通
 * ヘッダファイル
 *
 */

#ifndef __FWALL_H
#define __FWALL__H

/* fwall モジュール用の STREAM ioctl コマンド*/
#define ADDRULE     0xabc001    /* ルールの追加 */
#define DELRULE     0xabc002    /* ルールの削除 */
#define GETRULE     0xabc003    /* ルールの取得 */
#define INSERTRULE  0xabc004    /* ルールの挿入 */

/* ルールのアクション */
#define ALLOW  0x00  /* 通過許可 */
#define REJECT 0x01  /* 拒否 */
#define DENY   0x02  /* 無視 */

/* ルールのタイプ */
#define PORTFILETER 0x01 /* 通常の、アドレス・ポートフィルターのルール */
#define EXPRESSION  0x02 /* 任意のフィルターの式を指定したルール */

/* 最大ルール数 */
#define MAXRULES  255

/* 個々のルール定義用の構造体*/
typedef struct fwall_rule {
    uint8_t            rule_type;   /* ルールのタイプ */    
    struct in_addr     src_addr;    /* 送信元アドレス。PORTFILTER で使用*/
    struct in_addr     dst_addr;    /* あて先アドレス。PORTFILTER で使用 */
    uint16_t           src_port;    /* 送信元ポート。PORTFILTER で使用 */
    uint16_t           dst_port;    /* あて先ポート。PORTFILTER で使用 */
    uint8_t            proto;       /* プロトコル。PORTFILTER で使用 */
    uint32_t           offset;      /* フィルター開始位置。 EXPRESSION で使用*/
    uint32_t           length;      /* フィールド長。EXPRESSION で使用 */
    uint32_t           value;       /* 比較する値。 EXPRESSION で使用 */
    uint8_t            action;      /* 通過、拒否、無視。 */
    uint8_t            number;      /* ルール番号。fwalladm コマンドが使用*/
    struct fwall_rule  *next_rule ; /* 次のルールのポインタ。fwall モジュールが使用 */
    
}fwall_rule_t;

/*
 * モジュール毎のプライベートデータ構造体
 * 各モジュールインスタンスがここに持つプライベートデータを格納。
 */ 
typedef struct fwall
{
    struct in_addr *addr;   /* Not used now ... */
    struct stdata  *stream; /* stream のポインタ */
    struct fwall *next;     /* 次の fwall 構造体へのポインタ */
} fwall_t;

#ifdef _KERNEL
#define MAX_MSG 256  /* SYSLOG に出力するメッセージの最大文字数 */
/*
 * DEBUG を define すると、DEBUG モード ON になる 
#define DEBUG
 */
/*
 * DEBUG 用の出力ルーチン
 * cmn_err(9F) にて syslog メッセージを出力する。
 * DEBUG を on にすると、かなりのデバッグメッセージが記録される。
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
