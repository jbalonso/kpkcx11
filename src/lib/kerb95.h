/* kerberos.h - The public definitions for Kerberos.
 *
 *              Allan Bjorklund
 *              September 12, 1995.
 *
 * Copyright (c) 1995,2000 Regents of The University of Michigan.
 * All Rights Reserved.
 * 
 *     Permission to use, copy, modify, and distribute this software and
 *     its documentation for any purpose and without fee is hereby granted,
 *     provided that the above copyright notice appears in all copies and
 *     that both that copyright notice and this permission notice appear
 *     in supporting documentation, and that the name of The University
 *     of Michigan not be used in advertising or publicity pertaining to
 *     distribution of the software without specific, written prior
 *     permission. This software is supplied as is without expressed or
 *     implied warranties of any kind.
 * 
 * Research Systems Unix Group
 * The University of Michigan
 * c/o Allan Bjorklund
 * 535 W. William Street
 * Ann Arbor, Michigan
 * kerb95@umich.edu
 */
#if defined(__cplusplus)
extern "C" {
#endif


//#ifndef _KERBEROS_H
//#define _KERBEROS_H

#define KRB_PRINCIPAL_SZ	40
#define KRB_SERVICE_SZ		40
#define KRB_INSTANCE_SZ		40
#define KRB_REALM_SZ		40
#define KRB_SERVER_SZ		80
#define KRB_CANON_INST		0x00000001
#define KRB_MUTUAL_AUTH		0x00000002
#define	KRB_CANON_LONG_INST	0x00000004

typedef struct _ktkt {
                      BYTE   kversion;
                      CHAR   principal[KRB_PRINCIPAL_SZ];
                      CHAR   principal_instance[KRB_INSTANCE_SZ];
                      CHAR   service[KRB_SERVICE_SZ];
                      CHAR   service_instance[KRB_INSTANCE_SZ];
                      CHAR   realm[KRB_REALM_SZ];
                      BYTE   session_key[8];
                      BYTE   skvno;
                      WORD   str_to_key;
                      LONG   issue_time;
                      LONG   expiration_time;
                      BYTE   ticket_sz;
                      BYTE   ticket[256];
                     } KTKT;

typedef KTKT FAR *LPKTKT;


typedef struct _clienta {
                         CHAR      principal[KRB_PRINCIPAL_SZ];
                         CHAR      pinstance[KRB_INSTANCE_SZ];
                         CHAR      realm    [KRB_REALM_SZ];
                         CHAR      service[KRB_SERVICE_SZ];
                         CHAR      sinstance[KRB_INSTANCE_SZ];
                         BYTE      session_key[8];
                         LONG      ipaddr;
                         LONG      issuetime;
                         LONG      expiretime;
                         DWORD     checksum;
                        } CLIENTSTRUCTA;

typedef CLIENTSTRUCTA FAR *LPCLIENTSTRUCTA;

typedef struct _clientw {
                         WCHAR     principal[KRB_PRINCIPAL_SZ];
                         WCHAR     pinstance[KRB_INSTANCE_SZ];
                         WCHAR     realm[KRB_REALM_SZ];
                         WCHAR     service[KRB_SERVICE_SZ];
                         WCHAR     sinstance[KRB_INSTANCE_SZ];
                         BYTE      session_key[8];
                         LONG      ipaddr;
                         LONG      issuetime;
                         LONG      expiretime;
                         DWORD     checksum;
                        } CLIENTSTRUCTW;

typedef CLIENTSTRUCTW FAR *LPCLIENTSTRUCTW;

/* ANSI/UNICODE ambivalent */

BOOL    WINAPI KrbCreateCache(DWORD, LPHANDLE);
BOOL    WINAPI KrbReleaseCache(LPHANDLE);
BOOL    WINAPI KrbStoreTkt(LPKTKT);
BOOL    WINAPI KrbDoesTktCacheExist(void);
LONG    WINAPI KrbGetCacheTimeStamp(void);
LPKTKT  WINAPI KrbWalkCache(BOOL);
DWORD   WINAPI KrbGetErrcode(BOOL);
void    WINAPI KrbDisplayErrorText(DWORD, HWND);
BOOL    WINAPI KrbReadPrivateMsg(LPBYTE *, LPBYTE, LPBYTE, LPDWORD, SOCKET,
                                 WORD);
BOOL    WINAPI KrbMakePrivateMsg(LPBYTE *, LPBYTE, LPBYTE, LPDWORD, SOCKET,
                                 WORD);
BOOL    WINAPI KrbReadSafeMsg(LPBYTE *, LPBYTE, LPDWORD, LPBYTE, SOCKET, WORD);
BOOL    WINAPI KrbMakeSafeMsg(LPBYTE *, LPBYTE, LPDWORD, LPBYTE, SOCKET, WORD);
BOOL    WINAPI KrbViewSettings(HWND);

/* ANSI Defnitions */

BOOL    WINAPI KrbSetCurrIdentityA(LPSTR, LPSTR, LPSTR);
BOOL    WINAPI KrbGetCurrIdentityA(LPSTR, LPSTR, LPSTR);
LPBYTE  WINAPI KrbGetSessionKeyA(LPSTR, LPSTR, LPSTR, WORD);
BOOL    WINAPI KrbRetrieveTktA(LPSTR, LPSTR, LPSTR, LPSTR, LPSTR, LPVOID,
                               WORD);

BOOL    WINAPI KrbRequestTGTA(LPSTR, LPSTR, LPSTR, LPSTR, WORD);
BOOL    WINAPI KrbRequestTGTDlgA(LPSTR, LPSTR, LPSTR, HWND, WORD);
void    WINAPI KrbParseIdentityA(LPSTR, LPSTR, LPSTR, LPSTR);
BOOL    WINAPI KrbDeleteTicketA(LPSTR, LPSTR, LPSTR, LPSTR, LPSTR, WORD);
BOOL    WINAPI KrbApplRequestA(LPSTR, LPSTR, LPSTR, HWND, DWORD, WORD);
BOOL    WINAPI KrbChangePasswordDlgA(LPSTR, LPSTR, LPSTR, HWND, WORD);
BOOL	WINAPI KrbSendAuthorizationA(SOCKET, LPSTR, LPSTR, LPSTR, LPSTR,
                                     DWORD, DWORD, WORD);
BOOL    WINAPI KrbBuildAuthorizationA(LPSTR, LPSTR, LPSTR, DWORD, DWORD,
                                      LPDWORD, LPBYTE, WORD);
BOOL    WINAPI KrbReceiveAuthorizationA(LPSTR, LPSTR, LPSTR, LPCLIENTSTRUCTA,
                                        SOCKET, DWORD, WORD);
BOOL    WINAPI KrbVerifyAuthorizationA(LPBYTE, LPBYTE FAR *, LPSTR, LPSTR, 
                                       LPCLIENTSTRUCTA, SOCKET, LPDWORD, LPDWORD,
                                       WORD);

/* UNICODE Definitions */

BOOL    WINAPI KrbSetCurrIdentityW(LPWSTR, LPWSTR, LPWSTR);
BOOL    WINAPI KrbGetCurrIdentityW(LPWSTR, LPWSTR, LPWSTR);
LPBYTE  WINAPI KrbGetSessionKeyW(LPWSTR, LPWSTR, LPWSTR, WORD);
BOOL    WINAPI KrbRetrieveTktW(LPWSTR, LPWSTR, LPWSTR, LPWSTR, LPWSTR, LPVOID,
                               WORD);
BOOL    WINAPI KrbRequestTGTW(LPWSTR, LPWSTR, LPWSTR, LPWSTR, WORD);
BOOL    WINAPI KrbRequestTGTDlgW(LPWSTR, LPWSTR, LPWSTR, HWND, WORD);
void    WINAPI KrbParseIdentityW(LPWSTR, LPWSTR, LPWSTR, LPWSTR);
BOOL    WINAPI KrbDeleteTicketW(LPWSTR, LPWSTR, LPWSTR, LPWSTR, LPWSTR, WORD);
BOOL    WINAPI KrbApplRequestW(LPWSTR, LPWSTR, LPWSTR, HWND, DWORD, WORD);
BOOL    WINAPI KrbChangePasswordDlgW(LPWSTR, LPWSTR, LPWSTR, HWND, WORD);
BOOL	WINAPI KrbSendAuthorizationW(SOCKET, LPWSTR, LPWSTR, LPWSTR, LPWSTR,
                                     DWORD, DWORD, WORD);
BOOL    WINAPI KrbBuildAuthorizationW(LPWSTR, LPWSTR, LPWSTR, DWORD, DWORD,
                                      LPDWORD, LPBYTE, WORD);
BOOL    WINAPI KrbReceiveAuthorizationW(LPWSTR, LPWSTR, LPWSTR, LPCLIENTSTRUCTW,
                                        SOCKET, DWORD, WORD);
BOOL    WINAPI KrbVerifyAuthorizationW(LPBYTE, LPBYTE FAR *, LPWSTR, LPWSTR, 
                                       LPCLIENTSTRUCTW, SOCKET, LPDWORD, LPDWORD,
                                       WORD);

#ifdef UNICODE
#define CLIENTSTRUCT		CLIENTSTRUCTW
#define LPCLIENTSTRUCT          LPCLIENTSTRUCTW

#define KrbSetCurrIdentity	KrbSetCurrIdentityW
#define KrbGetCurrIdentity	KrbGetCurrIdentityW
#define KrbGetSessionKey	KrbGetSessionKeyW
#define KrbRetrieveTkt		KrbRetrieveTktW
#define KrbRequestTGT		KrbRequestTGTW
#define KrbRequestTGTDlg	KrbRequestTGTDlgW
#define KrbParseIdentity	KrbParseIdentityW
#define KrbDeleteTicket		KrbDeleteTicketW
#define KrbApplRequest		KrbApplRequestW
#define KrbChangePasswordDlg	KrbChangePasswordDlgW
#define KrbSendAuthorization	KrbSendAuthorizationW
#define KrbBuildAuthorization	KrbBuildAuthorizationW
#define KrbReceiveAuthorization	KrbReceiveAuthorizationW
#define KrbVerifyAuthorization	KrbVerifyAuthorizationW
#else
#define CLIENTSTRUCT		CLIENTSTRUCTA
#define LPCLIENTSTRUCT          LPCLIENTSTRUCTA

#define KrbSetCurrIdentity	KrbSetCurrIdentityA
#define KrbGetCurrIdentity	KrbGetCurrIdentityA
#define KrbGetSessionKey	KrbGetSessionKeyA
#define KrbRetrieveTkt		KrbRetrieveTktA
#define KrbRequestTGT		KrbRequestTGTA
#define KrbRequestTGTDlg	KrbRequestTGTDlgA
#define KrbParseIdentity	KrbParseIdentityA
#define KrbDeleteTicket		KrbDeleteTicketA
#define KrbApplRequest		KrbApplRequestA
#define KrbChangePasswordDlg	KrbChangePasswordDlgA
#define KrbSendAuthorization	KrbSendAuthorizationA
#define KrbBuildAuthorization	KrbBuildAuthorizationA
#define KrbReceiveAuthorization	KrbReceiveAuthorizationA
#define KrbVerifyAuthorization	KrbVerifyAuthorizationA
#endif

#define KRB_ERR_NONE		0
#define KRB_ERR_MEM		1
#define KRB_ERR_BAD_PW		2
#define KRB_ERR_DLG		3
#define KRB_ERR_CACHE_HANDLE	4
#define KRB_ERR_CACHE_MAPPING	5
#define KRB_ERR_CACHE_RELEASE	6
#define KRB_ERR_CACHE_FULL	7
#define KRB_ERR_NO_TKT		8
#define KRB_ERR_VERSION		9
#define KRB_ERR_UNKNOWN_ID	10
#define KRB_ERR_REPLY		11
#define KRB_ERR_APPL_REPLY	12
#define KRB_ERR_DIE		13
#define KRB_ERR_NO_SERV_INF	14
#define KRB_ERR_NO_SOCKET	15
#define KRB_ERR_SOCKET_BIND	16
#define KRB_ERR_SERV_RES	17
#define KRB_ERR_CONNECT		18
#define KRB_ERR_TIMEOUT_W	19
#define KRB_ERR_WRITE_FAIL	20
#define KRB_ERR_READ_FAIL	21
#define KRB_ERR_MUT_AUTH	22
#define KRB_ERR_MUT_RECOG	23
#define KRB_ERR_BUF_OVER	24
#define KRB_ERR_GPEER		25
#define KRB_ERR_GSOCK		26
#define KRB_ERR_CLOCK_SKEW	27
#define KRB_ERR_WRONG_ORIGIN	28
#define KRB_ERR_MSG_TYPE	29
#define KRB_ERR_CHECK_SUM	30
#define KRB_ERR_PW_NEED_TGT	31
#define KRB_ERR_CHP_FAIL	32
#define KRB_ERR_UNKNOWN_STK	33
#define KRB_ERR_PWS_DONT_MATCH	34
#define KRB_ERR_PWREAD_FAIL	35
#define KRB_ERR_PW_INSECURE	36
#define KRB_ERR_NOADMIN		37
#define KRB_ERR_NOPUBLIC	38
#define KRB_ERR_UNSUPPORTED_VER	39

#define KRB_MAX_ERR_CODE	39

//#endif /* _KERBEROS_H */

#if defined(__cplusplus)
}
#endif
