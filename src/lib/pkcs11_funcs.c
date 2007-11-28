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
 * Copyright  ©  2000,2002
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

#include <string.h>
#include <stdlib.h>

#include "cki_types.h"
#include "pkcs11_types.h"
#include "cki_funcs.h"
#include "pkcs11_funcs.h"
#include "cki_globals.h"
#include "pkcs11_globals.h"
#include "cki_new_free.h"
#include "pkcs11_new_free.h"
#include "doauth.h"
#include <openssl/err.h>
#include "debug.h"

#define MANUFID "Kerberized Certificate Factory"
#define LIBDESCR "Kerberos derived X509"

#define TLABEL "Kerberized X509"
#define TMODEL "Size XXXL"

CK_RV PKCS11_Init_Module(PKCS11_MODULE **ppModule) {
	CK_SLOT_ID slotID;
	CK_FLAGS slotFlags;
	PKCS11_SLOT *pSlot=NULL;
	CK_RV res;
	PKCS11_MODULE * pModule;
	CK_MECHANISM_TYPE pMechanismType[2];
	
	log_printf("entering PKCS11_Init_Module\n");
	if (!PKCS11_ModuleInitDone) {
		PKCS11_ModuleInitDone++;
		*ppModule=PKCS11_Module_New();
		if (*ppModule==NULL) {
			return(CKR_HOST_MEMORY);
		}
		pModule=*ppModule;
		res=PKCS11_Init_Info(pModule->pInfo);
		if (res!=CKR_OK) return(res);
		
		/*	  res=PKCS11_Init_Function_List(pModule->pFunctionList);
		if (res!=CKR_OK) return(res); */
		
		pSlot=PKCS11_Slot_New();
		if (pSlot==NULL) {
			return(CKR_HOST_MEMORY);
		}
		slotID=1L;
		slotFlags=CKF_TOKEN_PRESENT|CKF_REMOVABLE_DEVICE;
		res=PKCS11_Init_Slot(pSlot,slotID,slotFlags);
		if (res!=CKR_OK) return(res);
		pMechanismType[0]=CKM_RSA_PKCS;
		pMechanismType[1]=0;
		res=PKCS11_Init_Token(pSlot->pToken,
#if defined(USE_KRB5)
				      (unsigned char *)"KRB5",
#else
				      (unsigned char *)"KRB4",
#endif
				      pMechanismType);	  
		if (res!=CKR_OK) return(res);
		pModule->ppSlot=(PKCS11_SLOT **)malloc(sizeof(PKCS11_SLOT *)*2);
		if (pModule->ppSlot==NULL) {
			return(CKR_HOST_MEMORY);
		}
		pModule->ppSlot[0]=pSlot;
		pModule->ppSlot[1]=NULL;
	}
	return(CKR_OK);
}

CK_RV PKCS11_Init_Info(CK_INFO_PTR pInfo) {
	log_printf("entering PKCS11_Init_Info\n");
	pInfo->cryptokiVersion.major=2;
	pInfo->cryptokiVersion.minor=0;
	memcpy(pInfo->manufacturerID,MANUFID,strlen(MANUFID));
	pInfo->flags=0L;
	memcpy(pInfo->libraryDescription,LIBDESCR,strlen(LIBDESCR));
	pInfo->libraryVersion.major=0;
	pInfo->libraryVersion.minor=1;
	return(CKR_OK);
}

CK_RV PKCS11_Init_Function_List(CK_FUNCTION_LIST_PTR pFunctionList) {
	log_printf("entering PKCS11_Init_Function_List\n");
	pFunctionList->version.major=0;
	pFunctionList->version.minor=1;
	pFunctionList->C_Initialize=C_Initialize;
	pFunctionList->C_Finalize=C_Finalize;
	pFunctionList->C_GetInfo=C_GetInfo;
	pFunctionList->C_GetFunctionList=C_GetFunctionList;
	
	pFunctionList->C_GetSlotList=(CK_RV (*)())C_GetSlotList;
	pFunctionList->C_GetSlotInfo=C_GetSlotInfo;
	pFunctionList->C_GetTokenInfo=C_GetTokenInfo;
	pFunctionList->C_GetMechanismList=C_GetMechanismList;
	
	pFunctionList->C_GetMechanismInfo=(CK_RV (*)())C_GetMechanismInfo;
	pFunctionList->C_InitToken=C_InitToken;
	pFunctionList->C_InitPIN=C_InitPIN;
	pFunctionList->C_SetPIN=C_SetPIN;
	pFunctionList->C_OpenSession=C_OpenSession;
	pFunctionList->C_CloseSession=C_CloseSession;
	pFunctionList->C_CloseAllSessions=C_CloseAllSessions;
	pFunctionList->C_GetSessionInfo=C_GetSessionInfo;
	pFunctionList->C_GetOperationState=C_GetOperationState;
	pFunctionList->C_SetOperationState=C_SetOperationState;
	pFunctionList->C_Login=C_Login;
	pFunctionList->C_Logout=C_Logout;
	pFunctionList->C_CreateObject=C_CreateObject;
	pFunctionList->C_CopyObject=C_CopyObject;
	pFunctionList->C_DestroyObject=C_DestroyObject;
	pFunctionList->C_GetObjectSize=C_GetObjectSize;
	pFunctionList->C_GetAttributeValue=C_GetAttributeValue;
	pFunctionList->C_SetAttributeValue=C_SetAttributeValue;
	pFunctionList->C_FindObjectsInit=C_FindObjectsInit;
	pFunctionList->C_FindObjects=C_FindObjects;
	pFunctionList->C_FindObjectsFinal=C_FindObjectsFinal;
	pFunctionList->C_EncryptInit=C_EncryptInit;
	pFunctionList->C_Encrypt=C_Encrypt;
	pFunctionList->C_EncryptUpdate=C_EncryptUpdate;
	pFunctionList->C_EncryptFinal=C_EncryptFinal;
	pFunctionList->C_DecryptInit=C_DecryptInit;
	pFunctionList->C_Decrypt=C_Decrypt;
	pFunctionList->C_DecryptUpdate=C_DecryptUpdate;
	pFunctionList->C_DecryptFinal=C_DecryptFinal;
	pFunctionList->C_DigestInit=C_DigestInit;
	pFunctionList->C_Digest=C_Digest;
	pFunctionList->C_DigestUpdate=C_DigestUpdate;
	pFunctionList->C_DigestKey=C_DigestKey;
	pFunctionList->C_DigestFinal=C_DigestFinal;
	pFunctionList->C_SignInit=C_SignInit;
	pFunctionList->C_Sign=C_Sign;
	pFunctionList->C_SignUpdate=C_SignUpdate;
	pFunctionList->C_SignFinal=C_SignFinal;
	pFunctionList->C_SignRecoverInit=C_SignRecoverInit;
	pFunctionList->C_SignRecover=C_SignRecover;
	pFunctionList->C_VerifyInit=C_VerifyInit;
	pFunctionList->C_Verify=C_Verify;
	pFunctionList->C_VerifyUpdate=C_VerifyUpdate;
	pFunctionList->C_VerifyFinal=C_VerifyFinal;
	pFunctionList->C_VerifyRecoverInit=C_VerifyRecoverInit;
	pFunctionList->C_VerifyRecover=C_VerifyRecover;
	pFunctionList->C_DigestEncryptUpdate=C_DigestEncryptUpdate;
	pFunctionList->C_DecryptDigestUpdate=C_DecryptDigestUpdate;
	pFunctionList->C_SignEncryptUpdate=C_SignEncryptUpdate;
	pFunctionList->C_DecryptVerifyUpdate=C_DecryptVerifyUpdate;
	pFunctionList->C_GenerateKey=C_GenerateKey;
	pFunctionList->C_GenerateKeyPair=C_GenerateKeyPair;
	pFunctionList->C_WrapKey=C_WrapKey;
	pFunctionList->C_UnwrapKey=C_UnwrapKey;
	pFunctionList->C_DeriveKey=C_DeriveKey;
	pFunctionList->C_SeedRandom=C_SeedRandom;
	pFunctionList->C_GenerateRandom=C_GenerateRandom;
	pFunctionList->C_GetFunctionStatus=C_GetFunctionStatus;
	pFunctionList->C_CancelFunction=C_CancelFunction;
	return(CKR_OK);
}

#define SLOTDESC TLABEL
CK_RV PKCS11_Init_Slot(PKCS11_SLOT *pSlot, CK_SLOT_ID slotID, CK_FLAGS slotFlags) {
	
	log_printf("entering PKCS11_Init_Slot\n");
	pSlot->slotID=slotID;
	memcpy(pSlot->pInfo->slotDescription,SLOTDESC,strlen(SLOTDESC));
	pSlot->pInfo->flags=slotFlags;
	pSlot->pInfo->hardwareVersion.major=0;
	pSlot->pInfo->hardwareVersion.minor=1;
	pSlot->pInfo->firmwareVersion.major=0;
	pSlot->pInfo->firmwareVersion.minor=1;
	return(CKR_OK);
}

/* this should take a string of mech types so we can do this up right. later */
CK_RV PKCS11_Init_Token(PKCS11_TOKEN *pToken, CK_CHAR_PTR serialNumber, CK_MECHANISM_TYPE_PTR pMechanismType) {
	CK_CHAR_PTR pPin;
	PKCS11_MECHANISM *pMechanism;
	CK_TOKEN_INFO_PTR pInfo;
	CK_RV res;
	int i;
	
	log_printf("entering PKCS11_Init_Token\n");
	if (pToken->pInfo==NULL) {
		log_printf("in PKCS11_Init_Token, pToken->pInfo is NULL\n");
		return(CKR_FUNCTION_FAILED);
	}
	pInfo=pToken->pInfo;
	
	memcpy(pInfo->label,TLABEL,strlen(TLABEL));
	memcpy(pInfo->manufacturerID,MANUFID,strlen(MANUFID));
	memcpy(pInfo->model,TMODEL,strlen(TMODEL));
	memcpy(pInfo->serialNumber,serialNumber,strlen((const char *)serialNumber));
#if 1
	pInfo->flags=CKF_WRITE_PROTECTED|CKF_USER_PIN_INITIALIZED|CKF_EXCLUSIVE_EXISTS; 
#else
	pInfo->flags=CKF_WRITE_PROTECTED|CKF_LOGIN_REQUIRED|CKF_USER_PIN_INITIALIZED|CKF_EXCLUSIVE_EXISTS; 
#endif
	pInfo->ulMaxSessionCount=1L;
	pInfo->ulSessionCount=0L;
	pInfo->ulMaxRwSessionCount=0L;
	pInfo->ulRwSessionCount=0L;
	pInfo->ulMaxPinLen=64L;
	pInfo->ulMinPinLen=1L;
	pInfo->ulTotalPublicMemory=131072L;
	pInfo->ulFreePublicMemory=131072L;
	pInfo->ulTotalPrivateMemory=131072L;
	pInfo->ulFreePrivateMemory=131072L;
	pInfo->hardwareVersion.major=0;
	pInfo->hardwareVersion.minor=1;
	pInfo->firmwareVersion.major=0;
	pInfo->firmwareVersion.minor=1;
	
	/* mechanism */
	i=0;
	while (pMechanismType[i]!=0) {
		pMechanism=PKCS11_Mechanism_New();
		if (pMechanism==NULL) {
			return(CKR_HOST_MEMORY);
		}
		res=PKCS11_Init_Mechanism(pMechanism,pMechanismType[0]);
		if (res!=CKR_OK) return(res);
		
		pToken->ppMechanism=(PKCS11_MECHANISM **)malloc(sizeof(PKCS11_MECHANISM *)*2);
		if (pToken->ppMechanism==NULL){
			return(CKR_HOST_MEMORY);
		}	
		pToken->ppMechanism[i]=pMechanism;
		i++;
	}
	pToken->ppMechanism[i]=NULL;
	
	/* PIN */
	pPin=(CK_CHAR_PTR)malloc(sizeof(CK_CHAR)*(pInfo->ulMaxPinLen));
	if (pPin==NULL) {
		return(CKR_HOST_MEMORY);
	}
	memset(pPin,' ',pInfo->ulMaxPinLen);
	memcpy(pPin,"abcdefg",strlen("abcdefg")); /* bogus, will be fixed later */
	pToken->pPin=pPin;
	pToken->ulPinLen=strlen("abcdefg");
	return(CKR_OK);
}

CK_RV PKCS11_Init_Mechanism(PKCS11_MECHANISM *pMechanism,CK_MECHANISM_TYPE mechanismType) {
	log_printf("entering PKCS11_Init_Mechanism\n");
	switch (mechanismType) {
	case CKM_RSA_PKCS:
		pMechanism->pMechanism->mechanism=mechanismType;
		pMechanism->pMechanism->pParameter=NULL;
		pMechanism->pMechanism->ulParameterLen=0L;
		pMechanism->pInfo->ulMinKeySize=512L;
		pMechanism->pInfo->ulMaxKeySize=4096L;
		pMechanism->pInfo->flags=CKF_SIGN;
		break;
	default:
		return(CKR_FUNCTION_FAILED);
	}
	return(CKR_OK);
}

CK_RV PKCS11_Init_Session(
						  CK_SESSION_HANDLE ulSessionHandle,
						  CK_STATE state,
						  CK_FLAGS flags,
						  PKCS11_SESSION *pSession
						  )
{
	log_printf("PKCS11_Init_Session: entered\n");
	if (pSession==NULL)
		return(CKR_FUNCTION_FAILED);
	
	pSession->ulSessionHandle=ulSessionHandle;	
	pSession->pInfo->state=state; /* should I check this to be sure it makes sense? */
	pSession->pInfo->flags=flags; /* how about this? */
	
	/* set the state... */
	if (state==CKS_RO_PUBLIC_SESSION)
		pSession->pInfo->state=CKS_RO_USER_FUNCTIONS; 
	else 
		pSession->pInfo->state=CKS_RW_USER_FUNCTIONS; 
	
	log_printf("PKCS11_Init_Session: returning with successful login\n");
	return(CKR_OK);
}


CK_RV PKCS11_Init2_Session(
						   CK_SESSION_HANDLE ulSessionHandle,
						   CK_STATE state,
						   CK_FLAGS flags,
						   PKCS11_SESSION *pSession
						   )
{
	int res;
	char *user;
	struct a_t **attrl;
	struct a_t **tattrl;
	char *cert_der;
	char *key_der;
	char *cert_enc;
	char *key_enc;
	int cert_len;
	int key_len;
	RSA *rsa;
	X509 *x;
	char *subject_der;
	X509_NAME *subject;
	int subject_len;
	char *ptr;
	
	
	log_printf("PKCS11_Init2_Session: entered\n");
	if (pSession==NULL)
		return(CKR_FUNCTION_FAILED);
	
	b64_init();
	ERR_load_crypto_strings();
	
	res=doauth(&attrl,&tattrl);
	if (res)
	{
		log_printf("PKCS11_Init2_Session: doauth failed.  no ticket file?\n");
		return(CKR_TOKEN_NOT_PRESENT); /* fixme, need better error check */
	}
	
	/* create cert and key objects... */
	user=getelt(tattrl,"user");
	if (!user) {
		freeelts(attrl);
		freeelts(tattrl);
		return(CKR_FUNCTION_FAILED);
	}
	cert_enc=getelt(attrl,"cert");
	if (!cert_enc) {
		freeelts(attrl);
		freeelts(tattrl);
		return(CKR_FUNCTION_FAILED);
	}
	cert_der=(char *) malloc(strlen(cert_enc)*2);
	if (!cert_der) {
		freeelts(attrl);
		freeelts(tattrl);
		return(CKR_HOST_MEMORY);
	}
	log_printf("PKCS11_Init2_Session: cert '%s'\n",cert_enc);
	cert_len=b64_decode(cert_enc,strlen(cert_enc),cert_der);
	log_printf("PKCS11_Init2_Session: cert_len %d\n",cert_len);
	key_enc=getelt(attrl,"key");
	if (!key_enc) {
		free(cert_der);
		freeelts(attrl);
		freeelts(tattrl);
		return(CKR_FUNCTION_FAILED);
	}
	key_der=(char *) malloc(strlen(key_enc)*2);
	if (!key_der) {
		free(cert_der);
		free(key_der);
		freeelts(attrl);
		freeelts(tattrl);
		return(CKR_HOST_MEMORY);
	}
	key_len=b64_decode(key_enc,strlen(key_enc),key_der);
	log_printf("PKCS11_Init2_Session: key_len %d\n",key_len);
	
	ptr=cert_der;
	x=NULL;
	d2i_X509(&x,(unsigned char **)&ptr, cert_len);
	if (x==NULL)
	{
		free(cert_der);
		free(key_der);
		freeelts(attrl);
		freeelts(tattrl);
		log_printf("PKCS11_Init2_Session: Login here with null x\n");
		return(CKR_FUNCTION_FAILED);
	}
	res=PKCS11_X509_to_X509Certificate(ulSessionHandle,x,user);
	
	subject=X509_get_subject_name(x);
	subject_len=i2d_X509_NAME(subject,NULL);
	subject_der=(char *)malloc(subject_len);
	if (!subject_der) {
		X509_free(x);
		free(cert_der);
		free(key_der);
		freeelts(attrl);
		freeelts(tattrl);
		return(CKR_HOST_MEMORY);
	}
	ptr=subject_der;
	i2d_X509_NAME(subject,(unsigned char **)&ptr);
	
	ptr=key_der;
	rsa=NULL;
	d2i_RSAPrivateKey(&rsa,(unsigned char **)&ptr,key_len);   
	res=PKCS11_RSA_to_RsaPrivateKey(ulSessionHandle,rsa,user,subject_der,subject_len);
	res=PKCS11_RSA_to_RsaPublicKey(ulSessionHandle,rsa,user,subject_der,subject_len);

	X509_free(x);
	RSA_free(rsa);
	free(cert_der);
	free(key_der);
	free(subject_der);
	freeelts(attrl);
	freeelts(tattrl);
	log_printf("PKCS11_Init2_Session: returning with successful login\n");
	return(CKR_OK);
}

void PKCS11_CheckTokenPresent(PKCS11_SLOT *pSlot) {
	int validity;
	CK_MECHANISM_TYPE pMechanismType[2];
	
	log_printf("entering PKCS11_CheckTokenPresent\n");
	
	validity=checkTokenValidity();
	
	log_printf("PKCS11_CheckTokenPresent found %d\n", validity);
	if (validity == 0) {
		if (pSlot->pToken) {
			PKCS11_Token_Free(pSlot->pToken);
			pSlot->pToken=NULL;
		}
 	} else if (validity<0) {
		if (pSlot->pToken) {
			if (pSlot->pToken->ppSession && pSlot->pToken->ppSession[0]) {
				/* Close all of the active sessions. This is a dodgy
			  	   copy of the code in C_CloseAllSessions */
				PKCS11_Session_Free(pSlot->pToken->ppSession[0]);
				free(pSlot->pToken->ppSession);
				pSlot->pToken->ppSession = NULL_PTR;
			}
		} else {
			/* Build a new token description */
			pSlot->pToken=PKCS11_Token_New();
			pMechanismType[0]=CKM_RSA_PKCS;
			pMechanismType[1]=0;
			PKCS11_Init_Token(pSlot->pToken,
#if defined(USE_KRB5)
					  (unsigned char *)"KRB5",
#else
					  (unsigned char *)"KRB4",
#endif
					  pMechanismType);
		}
	}
}
		
PKCS11_SESSION *PKCS11_FindSession(CK_SESSION_HANDLE hSession) {
	unsigned int i = 0;
	
	while (PKCS11_ModulePtr->ppSlot[i]) {
		PKCS11_CheckTokenPresent(PKCS11_ModulePtr->ppSlot[i]);
		if (PKCS11_ModulePtr->ppSlot[i]->pToken &&
		    PKCS11_ModulePtr->ppSlot[i]->pToken->ppSession &&
		    PKCS11_ModulePtr->ppSlot[i]->pToken->ppSession[0]->ulSessionHandle == hSession) {
 			return (PKCS11_ModulePtr->ppSlot[i]->pToken->ppSession[0]);
		}
		i++;
	}

	log_printf("Session handle %d is invalid\n", hSession);

	return(NULL);
}
	
PKCS11_SLOT *PKCS11_FindSlot(CK_SLOT_ID slotID) {
	unsigned int i = 0;
	
	log_printf("entering PKCS11_FindSlot\n");
	
	while(PKCS11_ModulePtr->ppSlot[i]) {
		if (slotID == PKCS11_ModulePtr->ppSlot[i]->slotID) {
			PKCS11_CheckTokenPresent(PKCS11_ModulePtr->ppSlot[i]);
			return PKCS11_ModulePtr->ppSlot[i];
		}
		i++;
	}
	
	log_printf("Slot id %d is invalid\n", slotID);
	
	return(NULL);
}
