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

#include "config.h"
#include <stdio.h>
#include <stdlib.h>

#ifndef WIN32
#  include <unistd.h>
#else
#  define  _WIN32_WINNT	0x0400	// Now needed to get WinCrypt.h ... ?!?!!
#  include <windows.h>
#endif /* !WIN32 */

#ifndef macintosh
#  include <sys/types.h>
#endif /* !macintosh */

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#ifdef macintosh
#define USE_KRB5
#endif /* macintosh */

#ifndef WIN32
#  if defined(USE_KRB5)
#    include "krb5.h"
#  else /* !USE_KRB5 */
#    include <openssl/des.h>
#    if !defined(linux) && !defined(HPUX)	/* Actually KRB5 1.1 */
#      define DES_DEFS
#    endif /* !linux */
#    ifdef macintosh
#      include <KClient.h>
#    else /* !macintosh */
#      include "des-openssl-hack.h"
#      include <krb.h>
#    endif /* macintosh */
#  endif /* !USE_KRB5 */
#endif /* WIN32 */

#include <openssl/evp.h>
#include <openssl/buffer.h>


#include "doauth.h"
#include "debug.h"

#ifndef WIN32
#  include "store_tkt.h"
#  include <sys/stat.h>
#else
#  include "blob_to_rsa.h"
#endif

#ifdef macintosh
#  define KSUCCESS 0
#  define KFAILURE 255
#  define TKT_FILE "tktfile"
#  define R_TKT_FIL 0
#  define W_TKT_FIL 1
#  define MAX_K_NAME_SZ (ANAME_SZ + INST_SZ + REALM_SZ + 2)
#endif /* macintosh */

/* from b64.c */
int b64_encode(char *string,int len,char *out);

/* Forward reference prototypes */
int checkTokenValidity_W32();
int checkTokenValidity_KRB4();
int checkTokenValidity_KRB5();

char *getelt(struct a_t **alist, char *name) {
  int i;

  if (!alist) return(NULL);
  i=0;
  while (alist[i]) {
   if (!strcmp(alist[i]->name,name)) return(alist[i]->value);
   i++;
  }
  return(NULL);
}


#if defined(WIN32)

/*----------------------------------------------------------------------*/
/* Define global context pointer.  We continually check to see if this  */
/* certificate is still the current one.  If not, we free it up and get */
/* the context for the new one.                                         */

PCCERT_CONTEXT		gpCertContext = NULL;

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

#define HandleError(x) \
{\
    log_printf("============  An error occurred ============\n"); \
    log_printf(x); \
    log_printf("Error number %x.\n", GetLastError()); \
    return(0); \
}

/*----------------------------------------------------------------------*/
/* Microsoft reserves this property id value, but it doesn't specify	*/
/* it.   We'll have to specify it ourself...				*/
/*									*/
#define UM_DESIRED_CERT_PROP_ID		32

/*----------------------------------------------------------------------*/
/* This structure is also not defined (or at least published).		*/
/* The second DWORD could also be a flag, but they all seem to		*/
/* be one in the stuff we've gotten back...				*/
/*									*/
typedef struct _property_header
{
	DWORD	propid;		/* Property ID (as defined in wincrypt.h) */
	DWORD	version;	/* This could also be a flag?		  */
	DWORD	length;		/* Length of the property data that	  */
				/*    follows this structure		  */
} UM_PROPERTY_HEADER;

/*----------------------------------------------------------------------*/
/* This routine takes a pointer to the serialized output of		*/
/* a certificate storage and finds the Property that we are		*/
/* interested in (the subject's certificate itself)			*/
/* The serialized output area is not documented, but we			*/
/* can see the structure...						*/
/*----------------------------------------------------------------------*/

int locateCertPropertyFromSerializedOutput(void *pSerializedData, int totlen, char **ppCert, int *pLen)
{
	UM_PROPERTY_HEADER *pH;

	if (!ppCert)
		return(-2);
	if (!pLen)
		return(-2);

	pH = (UM_PROPERTY_HEADER *)pSerializedData;
	/* Keep looking until we've found the one we're looking		*/
	/* for, or we've gone past the end of the serialized data	*/
	while ( (char *)pH < ((char *)pSerializedData + totlen) )
	{
		if (pH->propid == UM_DESIRED_CERT_PROP_ID && pH->version == 1)
		{
			*pLen = pH->length;
			*ppCert = ((char *)pH + sizeof(UM_PROPERTY_HEADER));
			return 0;
		}
		else
		{
			pH = (UM_PROPERTY_HEADER*) ((char *)pH + pH->length + sizeof(UM_PROPERTY_HEADER));
		}
	}
	return(-1);
}

/*----------------------------------------------------------------------*/
/* This routine gets the Common Name attribute from a CERT_INFO		*/
/* structure.  It returns TRUE if successful, or FALSE otherwise.	*/
/*----------------------------------------------------------------------*/

BOOL getCommonNameFromCertContext(PCCERT_CONTEXT pCertContext, char **ppName, int*pNamelen)
{
	DWORD cbDecoded;		/* Length of decoded output */
	BYTE *pbDecoded = NULL;		/* Decoded output of subject name */
	PCERT_NAME_INFO pNameInfo;	/* Ptr to NAME_INFO structure */
	DWORD i;
	BOOL retval = FALSE;		/* Be a pessimist */
	
	if (pCertContext == NULL || ppName == NULL || pNamelen == NULL)
	{
		log_printf("getCommonNameFromCertContext: missing param (0x%08x 0x%08x 0x%08x)\n",
			pCertContext, ppName, pNamelen);
		return retval;
	}
	
	/* First get the length needed for the decoded output */
	if (!CryptDecodeObject(
		MY_ENCODING_TYPE,	/* Encoding type */
		((LPCSTR) 7),		/* (X509_NAME) this definition from */
					/* wincrypt.h conflicts with a */
					/* definition in OpenSSL ... */
		pCertContext->pCertInfo->Subject.pbData,	/* The thing to be decoded */
		pCertContext->pCertInfo->Subject.cbData,	/* Length of thing to be decoded */
		0,			    /* Flags */
		NULL,			/* Just getting req'd length */
		&cbDecoded))		/* where to return the length */
	{
		log_printf("getCommonNameFromCertContext: error (0x%08x) "
			"getting length of decoded subject name\n", GetLastError());
		return retval;
	}
	
	/* Allocate the space for the decoded Subject data */
	if ( (pbDecoded = (BYTE*)malloc(cbDecoded)) == NULL )
	{
		log_printf("getCommonNameFromCertContext: Could not obtain %d bytes "
			"for decoded subject.\n", cbDecoded);
		return retval;
	}
	
	/* Now, get the decoded subject output */
	if (!CryptDecodeObject(
		MY_ENCODING_TYPE,	/* Encoding type */
		((LPCSTR) 7),		/* (X509_NAME) this definition from */
					/* wincrypt.h conflicts with a */
					/* definition in OpenSSL ... */
		pCertContext->pCertInfo->Subject.pbData,	/* The thing to be decoded */
		pCertContext->pCertInfo->Subject.cbData,	/* Length of thing to be decoded */
		0,			/* Flags */
		pbDecoded,		/* Return the decoded subject info */
		&cbDecoded))		/* and it's length */
	{
		log_printf("getCommonNameFromCertContext: error (0x%08x) decoding subject name\n",
			GetLastError());
		free(pbDecoded);
		return retval;
	}
	
	pNameInfo = (PCERT_NAME_INFO)pbDecoded;
	
	/* Loop through all the RDN elements, looking for the Common Name */
	for (i = 0; i < pNameInfo->cRDN; i++)
	{
		log_printf("getCommonNameFromCertContext: RDN %d\tOID '%s'\tString '%s'\n",
			i, pNameInfo->rgRDN[i].rgRDNAttr->pszObjId,
			pNameInfo->rgRDN[i].rgRDNAttr->Value.pbData);
		if (!strcmp(pNameInfo->rgRDN[i].rgRDNAttr->pszObjId, szOID_COMMON_NAME))
		{
			log_printf("getCommonNameFromCertContext: Found Common Name at index %d\n",
				i);
			break;
		}
	}
	
	/* If we found the right RDN, get it's value into a string */
	if (i < pNameInfo->cRDN)
	{
		if (CertRDNValueToStr(
			CERT_RDN_PRINTABLE_STRING,
			&pNameInfo->rgRDN[i].rgRDNAttr->Value,
			*ppName,
			*pNamelen) != 0)
		{
			log_printf("getCommonNameFromCertContext: Certificate for %s has "
				"been retrieved.\n", *ppName);
			retval = TRUE;	/* SUCCESS! */
		}
		else
		{
			log_printf("getCommonNameFromCertContext: CertNameToStr failed "
				"(error 0x%08x).\n", GetLastError());
		}
	}
	else
	{
		log_printf("getCommonNameFromCertContext: Could not locate Common Name RDN value!\n");
	}
	
	if (pbDecoded)
		free(pbDecoded);
	
	return retval;
}

/*----------------------------------------------------------------------*/
/* Retrieve the certificate from the user's Root store that		*/
/* contains the KCA_AUTHREALM extension.				*/
/*----------------------------------------------------------------------*/

# define			OID_KCA_AUTHREALM	"1.3.6.1.4.1.250.42.1"

PCCERT_CONTEXT getKCACertificate()
{
	HCERTSTORE		hSystemStore;
	PCCERT_CONTEXT		pCertContext = NULL;
	PCCERT_CONTEXT		pPrevCertContext = NULL;
	CERT_INFO		*pCertInfo = NULL;
	DWORD			dwCertEncodingType = MY_ENCODING_TYPE;
	DWORD			dwFindFlags = 0;
	DWORD			dwFindType = CERT_FIND_ANY;
	PCERT_EXTENSION		pCertExt = NULL;
	CRYPT_OBJID_BLOB	*p = NULL;
	int			i = 0;
	BOOL			bFound = FALSE;
	char			tmpRealm[250];

	/*--------------------------------------------------------------*/
	/* Open system certificate store.				*/
	
	if(hSystemStore = CertOpenSystemStore(
		0,
		"MY"))
	{
		log_printf("getKCACertificate: MY system store is open. Continue.\n");
	}
	else
	{
		HandleError("getKCACertificate: The first system store did not open.");
	}
	

	while ( (pCertContext = CertFindCertificateInStore(
		hSystemStore,			/* Handle to the certificate store	*/
		dwCertEncodingType, 		/* Encoding type			*/
		dwFindFlags,			/* Flags				*/
		dwFindType, 			/* Says what the parameter must match	*/
		NULL,				/* in				 	*/
		pPrevCertContext)) != NULL) 	/* First time is null, after that it	*/
						/* should be the one we previously got	*/
	{
		log_printf("getKCACertificate: A certificate was found. Continue.\n");

		bFound = FALSE;
		if (!(pCertInfo = pCertContext->pCertInfo))
			goto NEXT;

		for (i = pCertInfo->cExtension; i; i--)
		{
			pCertExt = &pCertInfo->rgExtension[i-1];
			if (!strcmp(pCertExt->pszObjId, OID_KCA_AUTHREALM))
			{
				log_printf("getKCACertificate: Found KCA_AUTHREALM Extension\n");
				p = &pCertExt->Value;
				memcpy(tmpRealm, &p->pbData[2], p->cbData-2);
				tmpRealm[p->cbData-2] ='\0';
				log_printf("getKCACertificate:   value is: '%s'\n", tmpRealm);

				bFound = TRUE;
				break;
			}
		}

		if (bFound)
			break;

	NEXT:
		/*----------------------------------------------------------------------*/
		/* Set previous context to the current one so we don't loop forever	*/
		pPrevCertContext = pCertContext;
	}

	/*------------------------------------------------------------------------------*/
	/* Close the system certificate store, we're done with it...			*/
	CertCloseStore(hSystemStore, 0);

	return pCertContext;
}

/********************************************************************************
 *
 * os_getCertAndKey for WIN32
 *
 * On WIN32, cert and key are accessed via CryptoAPI
 *                    not from KerberosIV Ticket File
 *                    nor from KerberosV  Cred Cache
 ********************************************************************************/

int os_getCertAndKey(
	char			**cert_der,
	int			*cert_len,
	char			**key_der,
	int			*key_len,
	char			*name,
	int			namelen
)

{
	CERT_INFO		*pCertInfo = NULL;
	BYTE*			pbElement;
	DWORD			cbElement;
	
	HCRYPTPROV		hCryptProvider;
	DWORD			whichKey;
	HCRYPTKEY		hXchgKey;
	DWORD			dwBlobLen;
	BYTE			*pbKeyBlob = NULL;	/* Pointer to a simple key blob */
	char			*pChar;
	RSA 			*pRSA = NULL;
	

	if (name == NULL)
	{
		log_printf("os_getCertAndKey: name pointer is NULL\n");
		return(0);
	}
	strncpy(name, "fudge", namelen);

	/*----------------------------------------------------------------------*/
	/* Get the KCA-issued certificate, if any.				*/

	if ( (gpCertContext = getKCACertificate()) == NULL)
	{
		HandleError("os_getCertAndKey: Could not find KCA-issued certificate!");
	}


	/*----------------------------------------------------------------------*/
	/* Obtain the common name from the certificate				*/

	if (getCommonNameFromCertContext(gpCertContext, &name, &namelen))
	{
		log_printf("os_getCertAndKey: Certificate for %s has been retrieved.\n", name);
	}
	else
	{
		log_printf("os_getCertAndKey: getCommonNameFromCertContext failed. \n");
	}

	/*----------------------------------------------------------------------*/
	/* Find out how much memory to allocate for the serialized element.	*/
	
	if(CertSerializeCertificateStoreElement(
		gpCertContext,		/* The existing certificate.		*/
		0,			/* Accept default for dwFlags, 		*/
		NULL,			/* NULL for the first function call.	*/
		&cbElement))		/* Address where the length of the 	*/
					/* serialized element will be placed.	*/
	{
		log_printf("os_getCertAndKey: The length of the serialized string is %d.\n",cbElement);
	}
	else
	{
		HandleError("Finding the length of the serialized element failed.");
	}
	/*----------------------------------------------------------------------*/
	/* Allocate memory for the serialized element.				*/
	
	if(pbElement = (BYTE*)malloc(cbElement))
	{
		log_printf("os_getCertAndKey: Memory has been allocated. Continue.\n");
	}
	else
	{
		HandleError("The allocation of memory failed.");
	}
	/*----------------------------------------------------------------------*/
	/* Create the serialized element from a certificate context.		*/
	
	if(CertSerializeCertificateStoreElement(
		gpCertContext,		/* The certificate context source for	*/
					/*    the serialized element.		*/
		0,			/* dwFlags. Accept the default.		*/
		pbElement,		/* A pointer to where the new element	*/
					/*    will be stored.			*/
		&cbElement))		/* The length of the serialized element,*/
	{
		log_printf("os_getCertAndKey: The encoded element has been serialized. \n");
	}
	else
	{
		HandleError("The element could not be serialized.");
	}

	/* retrieve the DER encoded certificate part */
	if (locateCertPropertyFromSerializedOutput(pbElement, cbElement,
							cert_der, cert_len))
	{
		log_printf("os_getCertAndKey: could not find proper property in serialized certificate data\n");
		HandleError("could not find proper property in serialized certificate data\n");
	}

	log_printf("os_getCertAndKey: cert_len=%0d\n", *cert_len);
	
	/*----------------------------------------------------------------------*/
	/* OK, now obtain the private key associated with the certificate       */
	/*----------------------------------------------------------------------*/
	
	
	/*----------------------------------------------------------------------*/
	/* First get the handle to the provider for the key associated		*/
	/* with the certificate							*/
	whichKey = AT_KEYEXCHANGE;
	
	/*----------------------------------------------------------------------*/
	/* Acquire a handle to the Cryptographic Service Provider		*/
	if(!CryptAcquireContext(
		&hCryptProvider,		/* Handle to the CSP		*/
		NULL,				/* ContainerName		*/
		MS_DEF_PROV,			/* Provider name		*/
		PROV_RSA_FULL,			/* Provider type		*/
		0))				/* Flag values			*/
	{
		log_printf("os_getCertAndKey: initial CryptAcquireContext returned 0x%8X\n", GetLastError());

		/*--------------------------------------------------------------*/
		/* User's container should have been created in kx509!		*/
		HandleError("Unable to get CSP handle -- kx509 not run?\n");
	}

	
	/*----------------------------------------------------------------------*/
	/* Now get a HANDLE to the key itself					*/
	if(CryptGetUserKey(
		hCryptProvider,
		AT_KEYEXCHANGE,
		&hXchgKey))
	{
		log_printf("os_getCertAndKey: The key exchange key has been acquired. \n");
	}
	else
	{
		HandleError("Error during CryptGetUserKey exchange key.");
	}
	
	
	/*----------------------------------------------------------------------*/
	/* Now try to export the key...						*/
	/* Determine the size of the key blob and allocate memory.		*/
	
	if(CryptExportKey(
		hXchgKey,		/* Handle of the key we want to export 	*/
		(HCRYPTKEY)NULL,	/* Session key used to encrypt the blob	*/
					/* We don't want it encrypted...	*/
		PRIVATEKEYBLOB, 	/* We want the whole thing		*/
					/*   (public/private key pair)		*/
		0,			/* Flags				*/
		NULL,			/* We're just getting the length	*/
					/*    right now				*/
		&dwBlobLen))		/* The returned length			*/
	{
		log_printf("os_getCertAndKey: Size of the blob for the session key determined. \n");
	}
	else
	{
		HandleError("Error computing blob length.");
	}
	
	if(pbKeyBlob = (BYTE*)malloc(dwBlobLen)) 
	{
		log_printf("os_getCertAndKey: Memory has been allocated for the blob. \n");
	}
	else
	{
		HandleError("Out of memory. \n");
	}
	
	/*----------------------------------------------------------------------*/
	/* Export the key into a Private Key Blob.				*/
	
	if(CryptExportKey(
		hXchgKey,		/* Handle of the key we want to export	*/
		(HCRYPTKEY)NULL,	/* Session key used to encrypt the blob	*/
					/* We don't want it encrypted... 	*/
		PRIVATEKEYBLOB, 	/* We want the whole thing		*/
					/*    (public/private key pair)		*/
		0,			/* Flags				*/
		pbKeyBlob,		/* Where to return the key blob 	*/
		&dwBlobLen))		/* The returned length			*/
	{
		log_printf("os_getCertAndKey: Contents have been written to the blob. \n");
	}
	else
	{
		HandleError("Error during CryptExportKey.");
	}
		
	
	
	
	log_printf("os_getCertAndKey: We now have the serialized certificate and the Private Key Blob\n");
	
	/*------------------------------------------------------------------------------*/
	/* Convert the blob returned into an RSA structure				*/
	if (privkeyblob_to_rsa(pbKeyBlob, &pRSA))
	{
		HandleError("Failed converting keyblob into an RSA structure\n");
	}
	
	/* now convert key from RSA structure to DER to nice b64 format */
	
	*key_len = i2d_RSAPrivateKey(pRSA, NULL);
	if (!*key_len)
	{
		log_printf("os_getCertAndKey: error determining length for private key to DER conversion\n");
		HandleError("error determining length for private key to DER conversion\n");
	}
	
	*key_der = (char *) malloc(sizeof(char) * *key_len);
	if (!*key_der)
	{
		log_printf("os_getCertAndKey: error allocating storage for private key to DER conversion\n");
		HandleError("error allocating storage for private key to DER conversion\n");
	}
	
	pChar = *key_der;
	if (i2d_RSAPrivateKey(pRSA, &pChar) == 0)
	{
		log_printf("os_getCertAndKey: error converting private key to DER format\n");
		HandleError("error converting private key to DER format\n");
	}
	
	log_printf("os_getCertAndKey: key_len=%0d\n", *key_len);
	return 1;
}

#else	/* WIN32 */

#if defined(USE_KRB5) && !defined(WIN32)

/********************************************************************************
 *
 * os_getCertAndKey for KRB5 (Unix and/or Macintosh)
 *
 ********************************************************************************/

#define KX509_CC_PRINCIPAL  "kx509"
#define KX509_CC_INSTANCE   "certificate"

int os_getCertAndKey(
	char			**cert_der,
	int			*cert_len,
	char			**key_der,
	int			*key_len,
	char			*name,
	int			namelen
)

{
	krb5_context	k5_context;
	krb5_ccache	cc;
	krb5_error_code	k5_rc = 0;
	krb5_creds	match_creds;
	krb5_creds	creds;
	int		retrieve_flags = (KRB5_TC_MATCH_SRV_NAMEONLY);

	X509		*x509 = NULL;
	unsigned char	*data;
	char		subject[BUFSIZ];
	char		*cn;
	struct stat	statbuf;

	memset(&match_creds, '\0', sizeof(match_creds));

	log_printf("Trying to init_context\n");
	
	if ((k5_rc = krb5_init_context(&k5_context)))
	{
		log_printf("os_getCertAndKey: %s initializing K5 context, "
			"check configuration.\n", error_message(k5_rc));
		return 0;
	}

	log_printf("Trying to find default CC\n");
	
	if ((k5_rc = krb5_cc_default(k5_context, &cc)))
	{
		log_printf("os_getCertAndKey: %s resolving default credentials cache.\n",
			error_message(k5_rc));
		return 0;
	}

	log_printf("Trying to get credentials\n");
	
	if ((k5_rc = krb5_cc_get_principal(k5_context, cc, &match_creds.client)))
	{
		log_printf("os_getCertAndKey: %s retreiving primary principal from "
			"credentials cache.\n", error_message(k5_rc));
		return 0;
	}

	if ((k5_rc = krb5_sname_to_principal(k5_context, KX509_CC_INSTANCE,
						KX509_CC_PRINCIPAL, KRB5_NT_UNKNOWN,
						&match_creds.server)))
	{
		log_printf("os_getCertAndKey: %s creating principal structure for "
				"server principal\n", error_message(k5_rc));
		return 0;
	}

	if ((k5_rc = krb5_cc_retrieve_cred(k5_context, cc, retrieve_flags, &match_creds, &creds)))
	{
		log_printf("os_getCertAndKey: %s finding the credentials containing the "
			"private key and certificate in the credentials cache.\n",
			error_message(k5_rc));
		return 0;
	}

	/*
	 * Note, that while 'creds' is local stack storage, the things that it
	 * now points to are not.  So passing these addresses back is not a
	 * problem as long as we don't free that data before returning...
	 */
	strncpy(name, krb5_princ_name(k5_context, creds.client)->data, namelen);

	log_printf("os_getCertAndKey: K5 name has been assigned with '%s'\n", name);
	*key_der = creds.ticket.data;
	*key_len = creds.ticket.length;
	*cert_der = creds.second_ticket.data;
	*cert_len = creds.second_ticket.length;


	/* 
	 * Attempt to get the Common Name from the certificate.
	 * First we try to obtain an X509 structure from the
	 * DER format certificate that we have.
	 * Then we get the Subject Name from the X509 and
	 * parse that to get the Common Name.
	 *
	 * Note that 'name' has already been filled in above
	 * with the uniqname; so if we fail, the uniqname
	 * is returned...
	 */

	data = (unsigned char *)creds.second_ticket.data;

	x509 = d2i_X509(NULL, &data, creds.second_ticket.length);
	if (x509 != NULL)
	{
		X509_NAME_oneline(X509_get_subject_name(x509), subject, BUFSIZ);
		log_printf("os_getCertAndKey: The certificate subject name is '%s' (0x%08x)\n",
	          subject, &subject);
		cn = strtok(subject, "/");
		while (cn && strncmp(cn, "CN=", 3))
		{
			log_printf("os_getCertAndKey: Checking token '%s' (0x%08x)\n", cn, cn);
			cn = strtok(NULL, "/");
		}
		if (cn)
		{
			log_printf("os_getCertAndKey: Found Common Name '%s'\n", cn+3);
			strncpy(name, cn+3, namelen);
		}
		else
		{
			log_printf("os_getCertAndKey: Unable to parse common name from subject name\n");
		}
	}
	else
	{
		log_printf("os_getCertAndKey: d2i_X509 failed!\n");
	}
	X509_free(x509);

	return 1;
}
#endif

#if defined(USE_KRB4) && defined(macintosh) /* K4 macintosh client */

/********************************************************************************
 *
 * os_getCertAndKey for KRB4 Macintosh
 *
 ********************************************************************************/

int os_getCertAndKey(
	char			**cert_der,
	int			*cert_len,
	char			**key_der,
	int			*key_len,
	char			*name,
	int			namelen
)

{
	static CREDENTIALS	cred;
	MOCK_KTEXT_ST	*mtkt;
	OSErr		err;
	char		inst[INST_SZ];
	char		dummy[MAX_K_NAME_SZ+1];
	char		realm[REALM_SZ+1];
	X509		*x509 = NULL;
	unsigned char	*data = (unsigned char *)&mtkt->data[*key_len];
	char		subject[BUFSIZ];
	char		*cn;
	
	if ((err = tf_init(TKT_FILE, R_TKT_FIL)) != KSUCCESS)
	{
		log_printf("os_getCertAndKey: tf_init failed, returned %d\n", err);
		return 0;
	}
	
	if ((err = tf_get_pname(name)) != KSUCCESS)
	{
		log_printf("os_getCertAndKey: tf_get_pinst failed, returned %d\n", err);
		tf_close();
		return 0;
	}
	
	if ((err = tf_get_pinst(inst)) != KSUCCESS)
	{
		log_printf("os_getCertAndKey: tf_get_pinst failed, returned %d\n", err);
		tf_close();
		return 0;
	}

	if ((err = tf_get_cred(&cred)) != KSUCCESS)
	{
		log_printf("os_getCertAndKey: tf_get_cred failed, returned %d\n", err);
		tf_close();
		return 0;
	}
	
	tf_close();

	mtkt=(MOCK_KTEXT_ST *)&cred.ticket_st;
	*key_len=mtkt->key_length;
	*cert_len=mtkt->cert_length;
	*key_der=(char *)&mtkt->data[0];
	*cert_der=(char *)&mtkt->data[*key_len];
	
	/* 
	 * Attempt to get the Common Name from the certificate.
	 * First we try to obtain an X509 structure from the
	 * DER format certificate that we have.
	 * Then we get the Subject Name from the X509 and
	 * parse that to get the Common Name.
	 *
	 * Note that 'name' has already been filled in above
	 * with the uniqname; so if we fail, the uniqname
	 * is returned...
	 */

	data = (unsigned char *)&mtkt->data[*key_len];

	x509 = d2i_X509(NULL, &data, mtkt->cert_length);
	if (x509 != NULL) {
		X509_NAME_oneline(X509_get_subject_name(x509), subject, BUFSIZ);
		log_printf("os_getCertAndKey: The certificate subject name is '%s' (0x%08x)\n",
				subject, &subject);
		cn = strtok(subject, "/");
		while (cn && strncmp(cn, "CN=", 3)) {
			log_printf("os_getCertAndKey: Checking token '%s' (0x%08x)\n", cn, cn);
			cn = strtok(NULL, "/");
		}
		if (cn) {
			log_printf("os_getCertAndKey: Found Common Name '%s'\n", cn+3);
			strcpy(name, cn+3);
		} else {
			log_printf("os_getCertAndKey: Unable to parse common name from subject name\n");
		}
	} else {
		log_printf("os_getCertAndKey: d2i_X509 failed!\n");
	}
	X509_free(x509);
	
	return 1;
}
#endif

#if defined(USE_KRB4) && !defined(macintosh) /* K4 un*x clients */

/********************************************************************************
 *
 * os_getCertAndKey for KRB4 Unix
 *
 ********************************************************************************/
int os_getCertAndKey(
	char			**cert_der,
	int			*cert_len,
	char			**key_der,
	int			*key_len,
	char			*name,
	int			namelen
)

{
	CREDENTIALS   cred;
	MOCK_KTEXT_ST *mtkt;
	char		dummy[MAX_K_NAME_SZ+1];
	char		realm[REALM_SZ+1];
	int		res;
	X509		*x509 = NULL;
	unsigned char	*data = (unsigned char *)&mtkt->data[*key_len];
	char		subject[BUFSIZ];
	char		*cn;


	*name = '\0';
	res = tf_init(TKT_FILE, W_TKT_FIL);
	if (res != KSUCCESS)
	{
		log_printf("os_getCertAndKey: tf_init failed, returned %0d\n", res);
		return 0;
	}

	if (krb_get_tf_fullname(tkt_string(), name, dummy, realm))
	{
		log_printf("os_getCertAndKey: krb_get_tf_fullname failed\n");
		return 0;
	}
	log_printf("os_getCertAndKey: attempting krb_get_cred for realm='%s'\n", realm);
	res=krb_get_cred( KX509_PRINC, KX509_INST, realm, &cred);

	if (KSUCCESS != res) {
		log_printf("os_getCertAndKey: krb_get_cred failed to get mock ticket: %0d\n", res);
		return 0;
	}
	mtkt=(MOCK_KTEXT_ST *)&cred.ticket_st;
	*key_len=mtkt->key_length;
	*cert_len=mtkt->cert_length;
	*key_der=(char *)&mtkt->data[0];
	*cert_der=(char *)&mtkt->data[*key_len];

	/* 
	 * Attempt to get the Common Name from the certificate.
	 * First we try to obtain an X509 structure from the
	 * DER format certificate that we have.
	 * Then we get the Subject Name from the X509 and
	 * parse that to get the Common Name.
	 *
	 * Note that 'name' has already been filled in above
	 * with the uniqname; so if we fail, the uniqname
	 * is returned...
	 */

	data = (unsigned char *)&mtkt->data[*key_len];

	x509 = d2i_X509(NULL, &data, mtkt->cert_length);
	if (x509 != NULL)
	{
		X509_NAME_oneline(X509_get_subject_name(x509), subject, BUFSIZ);
		log_printf("os_getCertAndKey: The certificate subject name is '%s' (0x%08x)\n",
			subject, &subject);
		cn = strtok(subject, "/");
		while (cn && strncmp(cn, "CN=", 3))
		{
			log_printf("os_getCertAndKey: Checking token '%s' (0x%08x)\n", cn, cn);
			cn = strtok(NULL, "/");
		}
		if (cn)
		{
			log_printf("os_getCertAndKey: Found Common Name '%s'\n", cn+3);
			strcpy(name, cn+3);
		}
		else
		{
			log_printf("os_getCertAndKey: Unable to parse common name from subject name\n");
		}
	}
	else
	{
		log_printf("os_getCertAndKey: d2i_X509 failed!\n");
	}
	X509_free(x509);

	return 1;
}

#endif /* macintosh */
#endif /* WIN32 */


struct a_t **getCertAndKey(struct a_t **tattrl, char *name, int namelen)
{
	struct a_t	**attrl=NULL;

	int		cert_length;
	char		*cert_der;
	char		*cert_enc;
	int		key_length;
	char		*key_der;
	char		*key_enc;

	log_printf("getCertAndKey: entered\n");

	if (!os_getCertAndKey(&cert_der, 	&cert_length,
			&key_der, 	&key_length,
			name,		namelen))
	{
		log_printf("getCertAndKey: os_getCertAndKey failed\n"); 
		return(NULL);
	}

	cert_enc=(char *)malloc(sizeof(char)*(cert_length+1)*2);
	if (!cert_enc) { 
		log_printf("getCertAndKey: out of memory\n"); 
		free(cert_der);
		free(key_der);
		return(NULL);
	}     
	b64_encode(cert_der,cert_length,cert_enc);

	log_printf("getCertAndKey: cert_length=%0d\n", cert_length);
	log_printf("getCertAndKey: cert_enc='%s'\n", cert_enc);

	/* now convert key from internal format to DER to nice b64 format */

	log_printf("getCertAndKey: 4\n");
	key_enc=(char *)malloc(sizeof(char)*(key_length+1)*2);
	if (!key_enc) {
		log_printf("getCertAndKey: out of memory\n");
		free(cert_der);
		free(key_der);
		free(cert_enc);
		return(NULL);
	}     
	b64_encode(key_der,key_length,key_enc);

	log_printf("getCertAndKey: key_length=%0d\n", key_length);
	log_printf("getCertAndKey: key_enc='%s'\n", key_enc);

	log_printf("getCertAndKey: 5\n");

	/* make an attr list */
	attrl=(struct a_t **)malloc(sizeof(struct a_t *)*3);
   
	log_printf("getCertAndKey: 6\n");
	if (!attrl) {
		free(cert_der);
		free(key_der);
		free(cert_enc);
		free(key_enc);
		return(NULL);
	}
	(attrl)[0]=(struct a_t *)malloc(sizeof(struct a_t));
	log_printf("getCertAndKey: 7\n");
	if (! (attrl)[0]) {
		free(cert_der);
		free(key_der);
		free(cert_enc);
		free(key_enc);
		free(attrl);
		return(NULL);
	}
	(attrl)[1]=(struct a_t *)malloc(sizeof(struct a_t));
	log_printf("getCertAndKey: 8\n");
	if (! (attrl)[1]) {
		free(cert_der);
		free(key_der);
		free(cert_enc);
		free(key_enc);
		free((attrl)[0]);
		free(attrl);
		return(NULL);
	}
	log_printf("getCertAndKey: 9\n");
	(attrl)[2]=NULL;
	(attrl)[0]->name=strdup("cert");
	(attrl)[0]->value=strdup(cert_enc);
	(attrl)[1]->name=strdup("key");
	(attrl)[1]->value=strdup(key_enc);


	/* Don't need these any more... */
	log_printf("getCertAndKey: 12\n");
	free(cert_enc);
	log_printf("getCertAndKey: 13\n");
	free(key_enc);

	log_printf("getCertAndKey: leaving\n");
	return(attrl);
}


int doauth(attrl,tattrl)
struct a_t ***attrl, ***tattrl;
{
	char user[MAXSTRLEN];

	log_printf("doauth: entered\n");

	*attrl=NULL;
	*tattrl=NULL;

	*tattrl=(struct a_t **)malloc(sizeof(struct a_t *)*3);
	if (!*tattrl) return(-1);

	*attrl=getCertAndKey(*tattrl, user, sizeof(user)); 
	if (!*attrl) {
		log_printf("doauth: doauth 9, couldn't do cert/key\n");
		return(-1);
	}

	log_printf("doauth: user name is '%s'\n", user);

	(*tattrl)[0]=(struct a_t *)malloc(sizeof(struct a_t));
	if (! (*tattrl)[0]) return(-1); /* fixme, mem leak */
	(*tattrl)[1]=(struct a_t *)malloc(sizeof(struct a_t));
	if (! (*tattrl)[1]) return(-1); /* fixme, mem leak */
	(*tattrl)[2]=NULL;
	(*tattrl)[0]->name=strdup("user");
	(*tattrl)[0]->value=strdup(user);
	(*tattrl)[1]->name=strdup("password");
	(*tattrl)[1]->value=strdup("");

	log_printf("doauth: success\n");
	
	return(0);	/* success */
}

/*
 * checkTokenValidity
 *    return codes:
 *      0  there are no kx509 credentials available
 *     -1  creds are available, but have changed
 *      1  there are creds available
 *
 * Call the correct routine for our situation...
 *
 * Thanks to Simon Wilkinson <simon@sxw.org.uk>
 * for the original version of this code to better
 * handle re-acquiring certificates after one has
 * expired.
 */

int checkTokenValidity()
{
#if defined(WIN32)
	return checkTokenValidity_W32();
#endif
#if defined(USE_KRB5)
	return checkTokenValidity_KRB5();
#endif
#if defined(USE_KRB4)
	return checkTokenValidity_KRB4();
#endif
}

#if defined(WIN32)

int checkTokenValidity_W32()
{
	/*
	 *  1) Get the certificate out of the store (Make it a subroutine???)
	 *  2) Check if it is the same one (if we already have one)
	 */
	PCCERT_CONTEXT		pCertContext = NULL;
	static CERT_INFO	info;
	static int		last_result = 0;
	int			retval = 1;

	/*----------------------------------------------------------------------*/
	/* Get the KCA-issued certificate					*/

	if ( (pCertContext = getKCACertificate()) == NULL)
	{
		log_printf("checkTokenValidity_W32: Could not find KCA-issued certificate!");
		return (last_result = 0);
	}

	//--------------------------------------------------------------------
	// Compare the pCertInfo members of this certificate with the
	// global version to determine whether they are identical.

	if( gpCertContext && 
	    CertCompareCertificate(
				MY_ENCODING_TYPE,
				pCertContext->pCertInfo,
				gpCertContext->pCertInfo))
	{
	     log_printf("checkTokenValidity_32: The two certificates are identical. \n");
	     retval = last_result = 1;
	}
	else
	{
	     log_printf("checkTokenValidity_32: The two certificates are not identical. \n");
	     last_result = 1;
	     retval = -1;
	}
	/* Free up the CertContext storage */
	CertFreeCertificateContext(pCertContext);

	return retval;
}

#endif

#if defined(USE_KRB5)

int checkTokenValidity_KRB5()
{
	struct stat	statbuf;
	krb5_context	k5_context;
	krb5_ccache	cc;
	krb5_creds	match_creds, creds;
	krb5_error_code	k5_rc;

	static int	last_result = 0;
	static time_t	cc_modtime;
	static char	*cc_name = NULL;

	log_printf("entering checkTokenValidity_KRB5\n");
	memset(&match_creds, '\0', sizeof(match_creds));

#ifndef DARWIN
	/* KfM doesn't use a file.  drh 20021024 */
	/* If we don't already know the Credentials Cache name, determine it now */
	if (cc_name == NULL) {
		krb5_init_context(&k5_context);
		krb5_cc_default(k5_context, &cc);
		cc_name = (char *)krb5_cc_get_name(k5_context, cc);
		log_printf("checkTokenValidity_KRB5: cc_name is %s\n",cc_name);

		krb5_free_context(k5_context);
	
		if (cc_name == NULL) {
			log_printf("checkTokenValidity_KRB5: krb5_cc_get_name failed\n");
			return 0;
		}
	}
	
	/* Is the Credentials Cache there? */
	log_printf("checkTokenValidity_KRB5: trying stat\n");
	if (stat(cc_name, &statbuf)) {
		log_printf("checkTokenValidity_KRB5: Stat of %s failed\n",cc_name);
		return(last_result = 0);
	}

	/*
	 * Has it been altered since last we checked? If not, we say whatever we
	 * said last time.
	 */
    
	log_printf("File time is %d our time is %d\n", statbuf.st_mtime, cc_modtime);
   
	if (statbuf.st_mtime == cc_modtime) {
		log_printf("checkTokenValidity_KRB5: Nothing's changed since last time\n");
		return(last_result);
	}

	cc_modtime = statbuf.st_mtime;

#endif /* DARWIN */

	/*
	 * The ccache is present, and has been updated since we last
	 * looked. Check to see if there's a kx509 principal in it
	 * (Not much error reporting here - see the doauth code for
	 * some, if you _really_ want)
	 */

	if ((k5_rc = krb5_init_context(&k5_context))) {
		log_printf("checkTokenValidity_KRB5: %s getting krb5_init_context\n",
			error_message(k5_rc));
		return(last_result = 0);
	}

	if ((k5_rc = krb5_cc_default(k5_context, &cc))) {
		log_printf("checkTokenValidity_KRB5: %s getting krb5_cc_default\n",
			error_message(k5_rc));
		return(last_result = 0);
	}

	if ((k5_rc = krb5_cc_get_principal(k5_context, cc, &match_creds.client))) {
		log_printf("checkTokenValidity_KRB5: %s from krb5_cc_get_principal\n",
			error_message(k5_rc));  
		return(last_result = 0);
	}
       
	if ((k5_rc = krb5_sname_to_principal(k5_context, KX509_CC_INSTANCE,
  					 KX509_CC_PRINCIPAL, KRB5_NT_UNKNOWN,
  					 &match_creds.server))) {
		log_printf("checkTokenValidity_KRB5: %s from krb5_sname_to_principal\n",
			error_message(k5_rc));
		return(last_result = 0);
	}

	if ((k5_rc = krb5_cc_retrieve_cred(k5_context, cc, KRB5_TC_MATCH_SRV_NAMEONLY, 
  				    &match_creds, &creds))) {
		/* Not there _sniff_ */
		krb5_free_cred_contents(k5_context, &match_creds);
		log_printf("checkTokenValidity_KRB5: %s from krb5_cc_retrieve_cred\n",
			error_message(k5_rc));
		return(last_result = 0);
	}

#ifdef DARWIN
	/* However, this should work for all platforms. drh 20021024 */

	/*
	 * Has it been altered since last we checked? If not, we say whatever we
	 * said last time.
	 */
    
	log_printf("Creds endtime is %d our time is %d\n", creds.times.endtime, cc_modtime);
   
	if (creds.times.endtime == cc_modtime) {
		log_printf("checkTokenValidity_KRB5: Nothing's changed since last time\n");
		krb5_free_cred_contents(k5_context, &match_creds);
		krb5_free_cred_contents(k5_context, &creds);
		return(last_result);
	}

	cc_modtime = creds.times.endtime;

#endif /* DARWIN */

	krb5_free_cred_contents(k5_context, &match_creds);
	krb5_free_cred_contents(k5_context, &creds);

	/*
	 * This sucks, because the doauth code will just do all the
	 * above again when the session is opened. Ho hum
	 */

	/*
	 * We tell them that the creds are there, but that they have
	 * changed (future calls will just get that they are there
	 */

	last_result = 1;
	log_printf("checkTokenValidity_KRB5: Drop through reached, creds changed\n");
	return -1;
}

#endif

#if defined(USE_KRB4)

int checkTokenValidity_KRB4()
{
	CREDENTIALS	cred;
	MOCK_KTEXT_ST	*mtkt;
	char		name[MAX_K_NAME_SZ+1];
	char		dummy[MAX_K_NAME_SZ+1];
	char		realm[REALM_SZ+1];
	int		res;
	struct stat	statbuf;

	static int	last_result = 0;
	static time_t	cc_modtime;

	/* Stat the ticket file to see if it has changed since we last checked */

#if defined(macintosh)
#error	Can the Mac do a stat??? KWC 20020115
#else
	log_printf("checkTokenValidity_KRB4: trying stat\n");
	if (stat(TKT_FILE, &statbuf)) {
		log_printf("checkTokenValidity_KRB4: Stat of ticket file '%s' failed\n", TKT_FILE);
		return(last_result = 0);
	}
#endif

	/*
	 * Has it been altered since last we checked? If not, we say whatever we
	 * said last time.
	 */
    
	log_printf("File time is %d, our saved time is %d\n", statbuf.st_mtime, cc_modtime);
   
	if (statbuf.st_mtime == cc_modtime) {
		log_printf("checkTokenValidity_KRB4: Nothing's changed since last time\n");
		return(last_result);
	}

	cc_modtime = statbuf.st_mtime;

	/*
	 * The ccache is present, and has been updated since we last
	 * looked. Check to see if there's a kx509 principal in it
	 */

	res = tf_init(TKT_FILE, W_TKT_FIL);
	if (res != KSUCCESS)
	{
		log_printf("checkTokenValidity_KRB4: %s from tf_init\n", error_message(res));
		return (last_result = 0);
	}

	/* Get the realm name for the ticket file */
	res = krb_get_tf_fullname(tkt_string(), name, dummy, realm);
	if (res != KSUCCESS)
	{
		log_printf("checkTokenValidity_KRB4: %s from krb_get_tf_fullname ?\n", error_message(res));
		tf_close();
		return (last_result = 0);
	}
	log_printf("checkTokenValidity_KRB4: attempting krb_get_cred for realm='%s'\n", realm);

	res=krb_get_cred( KX509_PRINC, KX509_INST, realm, &cred);
	if (KSUCCESS != res) {
		log_printf("checkTokenValidity_KRB4: krb_get_cred failed to find certificate -- %s\n", error_message(res));
		log_printf("checkTokenValidity_KRB4: updated ticket file, but no certificate?\n");
		tf_close();
		/* Tell them that things have changed, and there is no cert! */
		last_result = 0;
		return (-1);
	}

	tf_close();

	/*
	 * We tell them that the creds are there, but that they have
	 * changed (future calls will just get that they are there
	 */

	last_result = 1;
	log_printf("checkTokenValidity_KRB4: Drop through reached, creds changed\n");
	return -1;
}

#endif

