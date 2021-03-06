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
 * Copyright  �  2000
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include "debug.h"

EVP_CIPHER_CTX *PKCS11_EvpCipherCtx_New() {
  EVP_CIPHER_CTX *pEvpCipherCtx;
  log_printf("entering PKCS11_EvpCipherCtx_New\n");
  pEvpCipherCtx=(EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX));
  if (pEvpCipherCtx==NULL) {
    return(NULL);
  }
  pEvpCipherCtx->cipher=NULL;
  pEvpCipherCtx->encrypt=0;
  pEvpCipherCtx->buf_len=0;
  memset(pEvpCipherCtx->buf,' ',sizeof(pEvpCipherCtx->buf));
  pEvpCipherCtx->app_data=NULL;
  return(pEvpCipherCtx);
}

EVP_MD_CTX *PKCS11_EvpMdCtx_New() {
  EVP_MD_CTX *pEvpMdCtx;

  log_printf("entering PKCS11_EvpMdCtx_New\n");
  pEvpMdCtx=(EVP_MD_CTX *)malloc(sizeof(EVP_MD_CTX));
  if (pEvpMdCtx==NULL) {
    return(NULL);
  }
  pEvpMdCtx->digest=NULL;
  return(pEvpMdCtx);
}

/* check later for mem leaks; how are subfields assigned? */
void PKCS11_EvpCipherCtx_Free(EVP_CIPHER_CTX *pEvpCipherCtx) {

  log_printf("entering PKCS11_EvpCipherCtx_Free\n");
  if (pEvpCipherCtx==NULL) return;
  free(pEvpCipherCtx); /* fixme! */
}

void PKCS11_EvpMdCtx_Free(EVP_MD_CTX *pEvpMdCtx) {
  log_printf("entering PKCS11_EvpMdCtx_Free\n");
  if (pEvpMdCtx==NULL) return;
  free(pEvpMdCtx); /* fixme */
}
