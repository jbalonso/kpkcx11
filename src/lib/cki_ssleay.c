/*
 * Copyright (c) 1999
 * The Trustees of Columbia University in the City of New York.
 * All rights reserved.
 * 
 * Permission is granted to you to use, copy, create derivative works,
 * and redistribute this software and such derivative works for any
 * purpose, so long as the name of Columbia University is not used in any
 * advertising, publicity, or for any other purpose pertaining to the use
 * or distribution of this software, other than for including the
 * copyright notice set forth herein, without specific, written prior
 * authorization.  Columbia University reserves the rights to use, copy,
 * and distribute any such derivative works for any purposes.  The above
 * copyright notice must be included in any copy of any portion of this
 * software and the disclaimer below must also be included.
 * 
 *   THIS SOFTWARE IS PROVIDED AS IS, WITHOUT REPRESENTATION FROM THE
 *   TRUSTEES OF COLUMBIA UNIVERSITY IN THE CITY OF NEW YORK AS TO ITS
 *   FITNESS FOR ANY PURPOSE, AND WITHOUT WARRANTY BY THE TRUSTEES OF
 *   COLUMBIA UNIVERSITY IN THE CITY OF NEW YORK OF ANY KIND, EITHER
 *   EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION THE IMPLIED
 *   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *   THE TRUSTEES OF COLUMBIA UNIVERSITY IN THE CITY OF NEW YORK SHALL
 *   NOT BE LIABLE FOR ANY DAMAGES, INCLUDING SPECIAL, INDIRECT,
 *   INCIDENTAL, OR CONSEQUENTIAL DAMAGES, WITH RESPECT TO ANY CLAIM
 *   ARISING OUT OR IN CONNECTION WITH THE USE OF THE SOFTWARE, EVEN IF
 *   IT HAS BEEN OR IS HEREAFTER ADVISED OF THE POSSIBILITY OF SUCH
 *   DAMAGES.  YOU SHALL INDEMNIFY AND HOLD HARMLESS THE TRUSTEES OF
 *   COLUMBIA UNIVERSITY IN THE CITY OF NEW YORK, ITS EMPLOYEES AND
 *   AGENTS FROM AND AGAINST ANY AND ALL CLAIMS, DEMANDS, LOSS, DAMAGE OR
 *   EXPENSE (INCLUDING ATTORNEYS' FEES) ARISING OUT OF YOUR USE OF THIS
 *   SOFTWARE. 
 * 
 * The Trustees of Columbia University in the City of New York reserves
 * the right to revoke this permission if any of the terms of use set
 * forth above are breached.
 */ 

/*
 * Copyright  ©  2000
 * The Regents of the University of Michigan
 * ALL RIGHTS RESERVED
 *
 * permission is granted to use, copy, create derivative works 
 * and redistribute this software and such derivative works 
 * for any purpose, so long as the name of the university of 
 * michigan is not used in any advertising or publicity 
 * pertaining to the use or distribution of this software 
 * without specific, written prior authorization.  if the 
 * above copyright notice or any other identification of the 
 * university of michigan is included in any copy of any 
 * portion of this software, then the disclaimer below must 
 * also be included.
 *
 * this software is provided as is, without representation 
 * from the university of michigan as to its fitness for any 
 * purpose, and without warranty by the university of 
 * michigan of any kind, either express or implied, including 
 * without limitation the implied warranties of 
 * merchantability and fitness for a particular purpose. the 
 * regents of the university of michigan shall not be liable 
 * for any damages, including special, indirect, incidental, or 
 * consequential damages, with respect to any claim arising 
 * out of or in connection with the use of the software, even 
 * if it has been or is hereafter advised of the possibility of 
 * such damages.
 */

/* functions that use SSLeay routines */
#include <stdlib.h>
#include <string.h>

#include "cki_types.h"
#include "pkcs11_types.h"
#include "cki_funcs.h"
#include "pkcs11_funcs.h"
#include "cki_globals.h"
#include "pkcs11_globals.h"
#include "cki_new_free.h"
#include "pkcs11_new_free.h"
#include "cki_dup.h"
#include "debug.h"

static CK_KEY_TYPE keyType=CKK_RSA; 				/* XXX KWC Made static */
static CK_BBOOL True=TRUE;					/* XXX KWC Made static */
static CK_BBOOL False=FALSE;					/* XXX KWC Made static */
static CK_DATE date;						/* XXX KWC Made static */
static CK_RV res;						/* XXX KWC Made static */
static CK_BYTE empty='\0';					/* XXX KWC Made static */
static CK_ULONG mod_length; 					/* KWC */
static CK_CERTIFICATE_TYPE certType=CKC_X_509;			/* KWC */

CK_RV PKCS11_RSA_to_RsaPrivateKey(CK_SESSION_HANDLE hSession, RSA *rsa, 
								  char *username, char *subject, int subject_len) {
	CK_ATTRIBUTE_PTR pTemplate;
	CK_OBJECT_CLASS *pObjectClass;				/* XXX KWC Made static */
	int i=0;
	CK_CHAR_PTR label,id;
	unsigned char *n,*e,*d,*p,*q,*dmp1,*dmq1,*iqmp;
	CK_OBJECT_HANDLE_PTR pObject; /* we don't use this after it gets filled, oh well. */
	
	
	log_printf("entering PKCS11_RSA_to_RsaPrivateKey\n");
	CKI_Date_Init(&date);
	
	pObject=(CK_OBJECT_HANDLE *)malloc(sizeof(CK_OBJECT_HANDLE));
	if (!pObject) return(CKR_HOST_MEMORY);
	
	pTemplate=(CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE)*29);
	if (!pTemplate) return(CKR_HOST_MEMORY);
	
	for (i=0; i<29; i++) {
		pTemplate[i].ulValueLen=-1L;
		pTemplate[i].value=NULL_PTR;
	}
	i=0;
	
	pObjectClass=(CK_OBJECT_CLASS *)malloc(sizeof(CK_OBJECT_CLASS));
	if (!pObjectClass) return(CKR_HOST_MEMORY);
	*pObjectClass = CKO_PRIVATE_KEY;
	
	pTemplate[i].type=CKA_CLASS;
	pTemplate[i].ulValueLen=sizeof(CK_OBJECT_CLASS);
	res=CKI_SetAttrValue(&(pTemplate[i]), pObjectClass);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_TOKEN;
	pTemplate[i].ulValueLen=sizeof(CK_BBOOL);
	res=CKI_SetAttrValue(&(pTemplate[i]),&True);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_PRIVATE;
	pTemplate[i].ulValueLen=sizeof(CK_BBOOL);
	res=CKI_SetAttrValue(&(pTemplate[i]),&True);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_MODIFIABLE;
	pTemplate[i].ulValueLen=sizeof(CK_BBOOL);
	res=CKI_SetAttrValue(&(pTemplate[i]),&False);
	if (res!=CKR_OK) return(res);
	i++;
	
	label=(CK_CHAR_PTR)malloc(strlen(username)+strlen("'s private key")+2);
	if (!label) return(CKR_HOST_MEMORY); 
	sprintf((char *)label,"%s's private key",username);
	pTemplate[i].type=CKA_LABEL;
	pTemplate[i].ulValueLen=strlen((char *)label);
	pTemplate[i].value=label;
	i++;
	
	pTemplate[i].type=CKA_KEY_TYPE;
	pTemplate[i].ulValueLen=sizeof(CK_KEY_TYPE);
	res=CKI_SetAttrValue(&(pTemplate[i]),&keyType);
	if (res!=CKR_OK) return(res);
	i++;
	
	id=(CK_CHAR_PTR)malloc(strlen(username)+strlen(" wdauth")+2);
	if (!id) return(CKR_HOST_MEMORY); 
	sprintf((char *)id,"%s wdauth",username);
	pTemplate[i].type=CKA_ID;
	pTemplate[i].ulValueLen=strlen((char *)id);
	pTemplate[i].value=id;
	i++;
	
	pTemplate[i].type=CKA_START_DATE;
	pTemplate[i].ulValueLen=sizeof(CK_DATE);
	res=CKI_SetAttrValue(&(pTemplate[i]),&date);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_END_DATE;
	pTemplate[i].ulValueLen=sizeof(CK_DATE);
	res=CKI_SetAttrValue(&(pTemplate[i]),&date);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_DERIVE;
	pTemplate[i].ulValueLen=sizeof(CK_BBOOL);
	res=CKI_SetAttrValue(&(pTemplate[i]),&False);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_LOCAL;
	pTemplate[i].ulValueLen=sizeof(CK_BBOOL);
	res=CKI_SetAttrValue(&(pTemplate[i]),&True);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_SUBJECT;
	if (subject) {
		pTemplate[i].ulValueLen=subject_len;
		res=CKI_SetAttrValue(&(pTemplate[i]),subject);
	}
	else {
		pTemplate[i].ulValueLen=1L;
		res=CKI_SetAttrValue(&(pTemplate[i]),&empty);
	}
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_SENSITIVE;
	pTemplate[i].ulValueLen=sizeof(CK_BBOOL);
	res=CKI_SetAttrValue(&(pTemplate[i]),&True);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_DECRYPT;
	pTemplate[i].ulValueLen=sizeof(CK_BBOOL);
	res=CKI_SetAttrValue(&(pTemplate[i]),&False);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_SIGN;
	pTemplate[i].ulValueLen=sizeof(CK_BBOOL);
	res=CKI_SetAttrValue(&(pTemplate[i]),&True);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_SIGN_RECOVER;
	pTemplate[i].ulValueLen=sizeof(CK_BBOOL);
	res=CKI_SetAttrValue(&(pTemplate[i]),&False);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_UNWRAP;
	pTemplate[i].ulValueLen=sizeof(CK_BBOOL);
	res=CKI_SetAttrValue(&(pTemplate[i]),&False);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_EXTRACTABLE;
	pTemplate[i].ulValueLen=sizeof(CK_BBOOL);
	res=CKI_SetAttrValue(&(pTemplate[i]),&False);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_ALWAYS_SENSITIVE;
	pTemplate[i].ulValueLen=sizeof(CK_BBOOL);
	res=CKI_SetAttrValue(&(pTemplate[i]),&True);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_NEVER_EXTRACTABLE;
	pTemplate[i].ulValueLen=sizeof(CK_BBOOL);
	res=CKI_SetAttrValue(&(pTemplate[i]),&True);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_MODULUS;
	pTemplate[i].ulValueLen=BN_num_bytes(rsa->n);
	n=(unsigned char *)malloc(pTemplate[i].ulValueLen);
	BN_bn2bin(rsa->n,n);
	res=CKI_SetAttrValue(&(pTemplate[i]),n);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_PUBLIC_EXPONENT;
	pTemplate[i].ulValueLen=BN_num_bytes(rsa->e);
	e=(unsigned char *)malloc(pTemplate[i].ulValueLen);
	BN_bn2bin(rsa->e,e);
	res=CKI_SetAttrValue(&(pTemplate[i]),e);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_PRIVATE_EXPONENT;
	pTemplate[i].ulValueLen=BN_num_bytes(rsa->d);
	d=(unsigned char *)malloc(pTemplate[i].ulValueLen);
	BN_bn2bin(rsa->d,d);
	res=CKI_SetAttrValue(&(pTemplate[i]),d);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_PRIME_1;
	pTemplate[i].ulValueLen=BN_num_bytes(rsa->p);
	p=(unsigned char *)malloc(pTemplate[i].ulValueLen);
	BN_bn2bin(rsa->p,p);
	res=CKI_SetAttrValue(&(pTemplate[i]),p);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_PRIME_2;
	pTemplate[i].ulValueLen=BN_num_bytes(rsa->q);
	q=(unsigned char *)malloc(pTemplate[i].ulValueLen);
	BN_bn2bin(rsa->q,q);
	res=CKI_SetAttrValue(&(pTemplate[i]),q);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_EXPONENT_1;
	pTemplate[i].ulValueLen=BN_num_bytes(rsa->dmp1);
	dmp1=(unsigned char *)malloc(pTemplate[i].ulValueLen);
	BN_bn2bin(rsa->dmp1,dmp1);
	res=CKI_SetAttrValue(&(pTemplate[i]),dmp1);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_EXPONENT_2;
	pTemplate[i].ulValueLen=BN_num_bytes(rsa->dmq1);
	dmq1=(unsigned char *)malloc(pTemplate[i].ulValueLen);
	BN_bn2bin(rsa->dmq1,dmq1);
	res=CKI_SetAttrValue(&(pTemplate[i]),dmq1);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_COEFFICIENT;
	pTemplate[i].ulValueLen=BN_num_bytes(rsa->iqmp);
	iqmp=(unsigned char *)malloc(pTemplate[i].ulValueLen);
	BN_bn2bin(rsa->iqmp,iqmp);
	res=CKI_SetAttrValue(&(pTemplate[i]),iqmp);
	if (res!=CKR_OK) return(res);
	i++;
	
	/* pObject is an object handle or something. do we do anything with it? */
	res=C_CreateObject(hSession,pTemplate,1L,pObject);
	if (res!=CKR_OK) return(res);
	return(CKR_OK);
}


CK_RV PKCS11_RSA_to_RsaPublicKey(CK_SESSION_HANDLE hSession, RSA *rsa, 
								 char *username, char *subject, int subject_len) {
	CK_ATTRIBUTE_PTR pTemplate;
	CK_OBJECT_CLASS *pObjectClass;				/* KWC */
	int i=0;
	CK_CHAR_PTR label,id;
	CK_RV res;
	unsigned char *n, *e;
	CK_OBJECT_HANDLE_PTR pObject; /* we don't use this after it gets filled,
	oh well. */
	
	
	log_printf("entering PKCS11_RSA_to_RsaPublicKey\n");
	CKI_Date_Init(&date);
	
	pObject=(CK_OBJECT_HANDLE *)malloc(sizeof(CK_OBJECT_HANDLE));
	if (!pObject) return(CKR_HOST_MEMORY);
	
	pTemplate=(CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE)*29);
	if (!pTemplate) return(CKR_OK);
	
	for (i=0; i<29; i++) {
		pTemplate[i].ulValueLen=-1L;
		pTemplate[i].value=NULL_PTR;
	}
	i=0;
	
	pObjectClass=(CK_OBJECT_CLASS *)malloc(sizeof(CK_OBJECT_CLASS));
	if (!pObjectClass) return(CKR_HOST_MEMORY);
	*pObjectClass = CKO_PUBLIC_KEY;
	
	pTemplate[i].type=CKA_CLASS;
	pTemplate[i].ulValueLen=sizeof(CK_OBJECT_CLASS);
	res=CKI_SetAttrValue(&(pTemplate[i]),pObjectClass);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_TOKEN;
	pTemplate[i].ulValueLen=sizeof(CK_BBOOL);
	res=CKI_SetAttrValue(&(pTemplate[i]),&True);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_PRIVATE;
	pTemplate[i].ulValueLen=sizeof(CK_BBOOL);
	res=CKI_SetAttrValue(&(pTemplate[i]),&True);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_MODIFIABLE;
	pTemplate[i].ulValueLen=sizeof(CK_BBOOL);
	res=CKI_SetAttrValue(&(pTemplate[i]),&False);
	if (res!=CKR_OK) return(res);
	i++;
	
	label=(CK_CHAR_PTR)malloc(strlen(username)+strlen("'s public key")+2);
	if (!label) return(CKR_HOST_MEMORY); 
	sprintf((char *)label,"%s's public key",username);
	pTemplate[i].type=CKA_LABEL;
	pTemplate[i].ulValueLen=strlen((char *)label);
	pTemplate[i].value=label;
	i++;
	
	pTemplate[i].type=CKA_KEY_TYPE;
	pTemplate[i].ulValueLen=sizeof(CK_KEY_TYPE);
	res=CKI_SetAttrValue(&(pTemplate[i]),&keyType);
	if (res!=CKR_OK) return(res);
	i++;
	
	id=(CK_CHAR_PTR)malloc(strlen(username)+strlen(" wdauth")+2);
	if (!id) return(CKR_HOST_MEMORY); 
	sprintf((char *)id,"%s wdauth",username);
	pTemplate[i].type=CKA_ID;
	pTemplate[i].ulValueLen=strlen((char *)id);
	pTemplate[i].value=id;
	i++;
	
	pTemplate[i].type=CKA_START_DATE;
	pTemplate[i].ulValueLen=sizeof(CK_DATE);
	res=CKI_SetAttrValue(&(pTemplate[i]),&date);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_END_DATE;
	pTemplate[i].ulValueLen=sizeof(CK_DATE);
	res=CKI_SetAttrValue(&(pTemplate[i]),&date);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_DERIVE;
	pTemplate[i].ulValueLen=sizeof(CK_BBOOL);
	res=CKI_SetAttrValue(&(pTemplate[i]),&False);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_LOCAL;
	pTemplate[i].ulValueLen=sizeof(CK_BBOOL);
	res=CKI_SetAttrValue(&(pTemplate[i]),&True);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_SUBJECT;
	if (subject) {
		pTemplate[i].ulValueLen=subject_len;
		res=CKI_SetAttrValue(&(pTemplate[i]),subject);
	}
	else {
		pTemplate[i].ulValueLen=1L;
		res=CKI_SetAttrValue(&(pTemplate[i]),&empty);
	}
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_ENCRYPT;
	pTemplate[i].ulValueLen=sizeof(CK_BBOOL);
	res=CKI_SetAttrValue(&(pTemplate[i]),&False);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_VERIFY;
	pTemplate[i].ulValueLen=sizeof(CK_BBOOL);
	res=CKI_SetAttrValue(&(pTemplate[i]),&False);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_VERIFY_RECOVER;
	pTemplate[i].ulValueLen=sizeof(CK_BBOOL);
	res=CKI_SetAttrValue(&(pTemplate[i]),&False);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_WRAP;
	pTemplate[i].ulValueLen=sizeof(CK_BBOOL);
	res=CKI_SetAttrValue(&(pTemplate[i]),&False);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_MODULUS;
	pTemplate[i].ulValueLen=BN_num_bytes(rsa->n);
	n=(unsigned char *)malloc(pTemplate[i].ulValueLen);
	BN_bn2bin(rsa->n,n);
	res=CKI_SetAttrValue(&(pTemplate[i]),n);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_MODULUS_BITS; 
	pTemplate[i].ulValueLen=sizeof(CK_ULONG);
	mod_length=BN_num_bits(rsa->n);
	res=CKI_SetAttrValue(&(pTemplate[i]),&mod_length);
	if (res!=CKR_OK) return(res);
	i++;
	
	pTemplate[i].type=CKA_PUBLIC_EXPONENT;
	pTemplate[i].ulValueLen=BN_num_bytes(rsa->e);
	e=(unsigned char *)malloc(pTemplate[i].ulValueLen);
	BN_bn2bin(rsa->e,e);
	res=CKI_SetAttrValue(&(pTemplate[i]),e);
	if (res!=CKR_OK) return(res);
	i++;
	
	/* pObject is an object handle or something. do we do anything with it? */
	res=C_CreateObject(hSession,pTemplate,1L,pObject);
	if (res!=CKR_OK) return(res);
	return(CKR_OK);
}


CK_RV PKCS11_X509_to_X509Certificate(CK_SESSION_HANDLE hSession, 
									 X509 *x, char *username) {
	CK_ATTRIBUTE_PTR pTemplate;
	CK_OBJECT_CLASS *pObjectClass;				/* KWC */
	int i=0;
	CK_CHAR_PTR label,id;
	
	char *cert_der;
	char *serial_der, *subject_der, *issuer_der;
	int cert_len;
	int serial_len, subject_len, issuer_len;
	X509_NAME *issuer, *subject;
	ASN1_INTEGER *serial;
	CK_RV res;
	char *ptr;
	CK_OBJECT_HANDLE_PTR pObject; /* we don't use this after it gets filled,
	oh well. */
	
	log_printf("entering PKCS11_X509_to_X509Certificate\n");
	pObject=(CK_OBJECT_HANDLE *)malloc(sizeof(CK_OBJECT_HANDLE));
	if (!pObject)
	{
		log_printf("PKCS11_X509_to_X509Certificate: could not malloc object handle\n");
		return(CKR_HOST_MEMORY);
	}
	
	pTemplate=(CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE)*12);
	if (!pTemplate)
	{
		log_printf("PKCS11_X509_to_X509Certificate: could not malloc attribute space\n");
		return(CKR_HOST_MEMORY);
	}

	for (i=0; i<12; i++) {
		pTemplate[i].ulValueLen=-1L;
		pTemplate[i].value=NULL_PTR;
	}
	i=0;
	
	pObjectClass=(CK_OBJECT_CLASS *)malloc(sizeof(CK_OBJECT_CLASS));
	if (!pObjectClass)
	{
		log_printf("PKCS11_X509_to_X509Certificate: could not malloc object class space\n");
		return(CKR_HOST_MEMORY);
	}
	*pObjectClass = CKO_CERTIFICATE;
	
	
	pTemplate[i].type=CKA_CLASS;
	pTemplate[i].ulValueLen=sizeof(CK_OBJECT_CLASS);

	res=CKI_SetAttrValue(&(pTemplate[i]), pObjectClass);

	log_printf("PKCS11_X509_to_X509Certificate: pTemplate[%d].value is %ld\n",
		i, *(CK_ULONG *)pTemplate[i].value);

	if (res!=CKR_OK)
	{
		log_printf("PKCS11_X509_to_X509Certificate: error setting CKA_CLASS (0x%08x)\n", res);
		return(res);
	}
	i++;
	
	pTemplate[i].type=CKA_TOKEN;
	pTemplate[i].ulValueLen=sizeof(CK_BBOOL);
	res=CKI_SetAttrValue(&(pTemplate[i]),&True);
	if (res!=CKR_OK)
	{
		log_printf("PKCS11_X509_to_X509Certificate: error setting CKA_TOKEN (0x%08x)\n", res);
		return(res);
	}
	i++;
	
	pTemplate[i].type=CKA_PRIVATE;
	pTemplate[i].ulValueLen=sizeof(CK_BBOOL);
	res=CKI_SetAttrValue(&(pTemplate[i]),&True);
	if (res!=CKR_OK)
	{
		log_printf("PKCS11_X509_to_X509Certificate: error setting CKA_PRIVATE (0x%08x)\n", res);
		return(res);
	}
	i++;
	
	pTemplate[i].type=CKA_MODIFIABLE;
	pTemplate[i].ulValueLen=sizeof(CK_BBOOL);
	res=CKI_SetAttrValue(&(pTemplate[i]),&False);
	if (res!=CKR_OK)
	{
		log_printf("PKCS11_X509_to_X509Certificate: error setting CKA_MODIFIABLE (0x%08x)\n", res);
		return(res);
	}
	i++;
	
	label=(CK_CHAR_PTR)malloc(strlen(username)+strlen("'s certificate")+2);
	if (!label)
	{
		log_printf("PKCS11_X509_to_X509Certificate: error allocating space for label\n");
		return(CKR_HOST_MEMORY); 
	}
	sprintf((char *)label,"%s's certificate",username);
	pTemplate[i].type=CKA_LABEL;
	pTemplate[i].ulValueLen=strlen((char *)label);
	pTemplate[i].value=label;
	i++;
	
	pTemplate[i].type=CKA_CERTIFICATE_TYPE;
	pTemplate[i].ulValueLen=sizeof(CK_CERTIFICATE_TYPE);
	res=CKI_SetAttrValue(&(pTemplate[i]),&certType);
	if (res!=CKR_OK)
	{
		log_printf("PKCS11_X509_to_X509Certificate: error setting CKA_CERTIFICATE_TYPE (0x%08x)\n", res);
		return(res);
	}
	i++;
	
	id=(CK_CHAR_PTR)malloc(strlen(username)+strlen(" wdauth")+2);
	if (!id)
	{
		log_printf("PKCS11_X509_to_X509Certificate: error allocating space for id\n");
		return(CKR_HOST_MEMORY);
	}
	sprintf((char *)id,"%s wdauth",username);
	pTemplate[i].type=CKA_ID;
	pTemplate[i].ulValueLen=strlen((char *)id);
	pTemplate[i].value=id;
	i++;
	
	cert_len=i2d_X509(x,NULL);
	cert_der=(char *)malloc(cert_len);
	if (!cert_der)
	{
		log_printf("PKCS11_X509_to_X509Certificate: error allocating space for cert_der\n");
		return(CKR_HOST_MEMORY);
	}
	ptr=cert_der;
	i2d_X509(x,(unsigned char **)&ptr);
	
	issuer=X509_get_issuer_name(x);
	issuer_len=i2d_X509_NAME(issuer,NULL);
	issuer_der=(char *)malloc(issuer_len);
	if (!issuer_der)
	{
		log_printf("PKCS11_X509_to_X509Certificate: error allocating space for issuer_der\n");
		return(CKR_HOST_MEMORY);
	}
	ptr=issuer_der;
	i2d_X509_NAME(issuer,(unsigned char **)&ptr);
	
	subject=X509_get_subject_name(x);
	subject_len=i2d_X509_NAME(subject,NULL);
	subject_der=(char *)malloc(subject_len);
	if (!subject_der)
	{
		log_printf("PKCS11_X509_to_X509Certificate: error allocating space for subject_der\n");
		return(CKR_HOST_MEMORY);
	}
	ptr=subject_der;
	i2d_X509_NAME(subject,(unsigned char **)&ptr);
	
	serial=X509_get_serialNumber(x);
	if (serial==NULL) {
		log_printf("PKCS11_X509_to_X509Certificate: couldn't get serial number from cert\n");	
		return(CKR_FUNCTION_FAILED);	
	}
	serial_len=i2d_ASN1_INTEGER(serial,NULL);
	serial_der=(char *)malloc(serial_len);
	if (!serial_der)
	{
		log_printf("PKCS11_X509_to_X509Certificate: error allocating space for serial_der\n");
		return(CKR_HOST_MEMORY);
	}
	ptr=serial_der;

	log_printf("PKCS11_X509_to_X509Certificate: serial_len is %d\n",serial_len);
	i2d_ASN1_INTEGER(serial,(unsigned char **)&ptr);
	
	pTemplate[i].type=CKA_SUBJECT;
	pTemplate[i].ulValueLen=subject_len;
	res=CKI_SetAttrValue(&(pTemplate[i]),subject_der);
	if (res!=CKR_OK)
	{
		log_printf("PKCS11_X509_to_X509Certificate: error setting CKA_SUBJECT (0x%08x)\n", res);
		return(res);
	}
	i++;
	
	pTemplate[i].type=CKA_ISSUER;
	pTemplate[i].ulValueLen=issuer_len;
	res=CKI_SetAttrValue(&(pTemplate[i]),issuer_der);
	if (res!=CKR_OK)
	{
		log_printf("PKCS11_X509_to_X509Certificate: error setting CKA_ISSUER (0x%08x)\n", res);
		return(res);
	}
	i++;
	
	pTemplate[i].type=CKA_SERIAL_NUMBER;
	pTemplate[i].ulValueLen=serial_len;
	res=CKI_SetAttrValue(&(pTemplate[i]),serial_der);
	if (res!=CKR_OK)
	{
		log_printf("PKCS11_X509_to_X509Certificate: error setting CKA_SERIAL_NUMBER (0x%08x)\n", res);
		return(res);
	}
	i++;
	
	pTemplate[i].type=CKA_VALUE;
	pTemplate[i].ulValueLen=cert_len;
	res=CKI_SetAttrValue(&(pTemplate[i]),cert_der);
	if (res!=CKR_OK)
	{
		log_printf("PKCS11_X509_to_X509Certificate: error setting CKA_VALUE (0x%08x)\n", res);
		return(res);
	}
	i++;
	
	
	/* pObject is an object handle or something. do we do anything with it? */
	res=C_CreateObject(hSession,pTemplate,1L,pObject);
	if (res!=CKR_OK)
	{
		log_printf("PKCS11_X509_to_X509Certificate: error creating pObject (0x%08x)\n", res);
		return(res);
	}

	log_printf("PKCS11_X509_to_X509Certificate: returning CKR_OK\n", res);
	return(CKR_OK);
}


RSA *PKCS11_RsaPrivateKey_to_RSA(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) { 
	
	RSA *rsa;
	int i=0;
	int ctr;
	PKCS11_SESSION *pSession;
	CK_ATTRIBUTE_PTR pAttributes, attr; 
	
	log_printf("entering PKCS11_RsaPrivateKey_to_RSA\n");
	rsa=RSA_new();

        if ((pSession=PKCS11_FindSession(hSession))==NULL)
	        return(NULL);
	if (!pSession->ppSessionObject)
		return(NULL);
			
	ctr=0;
	while (pSession->ppSessionObject[ctr]) {
		if (pSession->ppSessionObject[ctr]->ulObjectHandle==hKey) {
			pAttributes=pSession->ppSessionObject[ctr]->pAttribute;
			attr=PKCS11_FindAttribute_p(pAttributes,CKA_MODULUS);
			if (!attr)
			{
				log_printf("PKCS11_RsaPrivateKey_to_RSA: could not find CKA_MODULUS\n");
				return(NULL);
			}
			
			rsa->n=BN_bin2bn(attr->value,attr->ulValueLen,rsa->n);
			attr=PKCS11_FindAttribute_p(pAttributes,CKA_PUBLIC_EXPONENT);
			if (!attr)
			{
				log_printf("PKCS11_RsaPrivateKey_to_RSA: could not find CKA_PUBLIC_EXPONENT\n");
				return(NULL);
			}
				rsa->e=BN_bin2bn(attr->value,attr->ulValueLen,rsa->e);
			attr=PKCS11_FindAttribute_p(pAttributes,CKA_PRIVATE_EXPONENT);
			if (!attr)
			{
				log_printf("PKCS11_RsaPrivateKey_to_RSA: could not find CKA_PRIVATE_EXPONENT\n");
				return(NULL);
			}
			rsa->d=BN_bin2bn(attr->value,attr->ulValueLen,rsa->d);
			attr=PKCS11_FindAttribute_p(pAttributes,CKA_PRIME_1);
			if (!attr)
			{
				log_printf("PKCS11_RsaPrivateKey_to_RSA: could not find CKA_PRIME_1\n");
				return(NULL);
			}

			rsa->p=BN_bin2bn(attr->value,attr->ulValueLen,rsa->p);
			attr=PKCS11_FindAttribute_p(pAttributes,CKA_PRIME_2);
			if (!attr)
			{
				log_printf("PKCS11_RsaPrivateKey_to_RSA: could not find CKA_PRIME_2\n");
				return(NULL);
			}
			rsa->q=BN_bin2bn(attr->value,attr->ulValueLen,rsa->q);
			attr=PKCS11_FindAttribute_p(pAttributes,CKA_EXPONENT_1);
			if (!attr)
			{
				log_printf("PKCS11_RsaPrivateKey_to_RSA: could not find CKA_EXPONENT_1\n");
				return(NULL);
			}
			rsa->dmp1=BN_bin2bn(attr->value,attr->ulValueLen,rsa->dmp1);
			attr=PKCS11_FindAttribute_p(pAttributes,CKA_EXPONENT_2);
			if (!attr)
			{
				log_printf("PKCS11_RsaPrivateKey_to_RSA: could not find CKA_EXPONENT_2\n");
				return(NULL);
			}
			rsa->dmq1=BN_bin2bn(attr->value,attr->ulValueLen,rsa->dmq1);
			attr=PKCS11_FindAttribute_p(pAttributes,CKA_COEFFICIENT);
			if (!attr)
			{
				log_printf("PKCS11_RsaPrivateKey_to_RSA: could not find CKA_COEFFICIENT\n");
				return(NULL);
			}
			rsa->iqmp=BN_bin2bn(attr->value,attr->ulValueLen,rsa->iqmp);
			return(rsa);
		}
		ctr++;
	}
	return(NULL);
}


