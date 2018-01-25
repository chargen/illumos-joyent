/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2018, Joyent, Inc.
 */

#include <strings.h>
#include <stdio.h>
#ifdef	PKCS11
#include <security/cryptoki.h>
#endif
#include "cryptotest.h"
#include "aes_ccm.h"

#ifdef PKCS11
#define	CCM_PARAMS CK_CCM_PARAMS
#define	INIT_CCM(_dataLen, _nonce, _nonceLen, _aad, _aadLen, _macLen) { \
	.ulDataLen = _dataLen,		\
	.pNonce = _nonce,		\
	.ulNonceLen = _nonceLen,	\
	.pAAD = _aad,			\
	.ulAADLen = _aadLen,		\
	.ulMACLen = _macLen		\
}
#else
#define	CCM_PARAMS CK_AES_CCM_PARAMS
#define	INIT_CCM(_dataLen, _nonce, _nonceLen, _aad, _aadLen, _macLen) { \
	.ulDataSize = _dataLen,		\
	.nonce = _nonce,		\
	.ulNonceSize = _nonceLen,	\
	.authData = _aad,		\
	.ulAuthDataSize = _aadLen,	\
	.ulMACSize = _macLen,		\
}
#endif

int
main(void)
{
	int errs = 0;
	int i;
	uint8_t N[1024];
	CCM_PARAMS param;

	cryptotest_t args;

	bzero(&param, sizeof (param));

	args.out = N;

	args.outlen = sizeof (N);

	args.mechname = SUN_CKM_AES_CCM;
	args.updatelen = 1;

	args.key = CCM_KEY1;
	args.keylen = sizeof (CCM_KEY1);
	for (i = 0; i < 12; i++) {
		CCM_PARAMS param = INIT_CCM(DATALEN[i] - AUTHLEN[i], NONCE[i],
		    NONCELEN[i], CCM_DATA1, AUTHLEN[i], MACLEN[i]);

		args.param = &param;
		args.plen = sizeof (param);

		args.in = CCM_DATA1 + AUTHLEN[i];
		args.inlen = DATALEN[i] - AUTHLEN[i];

		errs += run_test(&args, RES[i] + AUTHLEN[i],
		    RESLEN[i] - AUTHLEN[i], ENCR_FG);
		(void) fprintf(stderr, "----------\n");
	}

	args.key = CCM_KEY2;
	args.keylen = sizeof (CCM_KEY2);
	for (i = 12; i < 24; i++) {
		CCM_PARAMS param = INIT_CCM(DATALEN[i] - AUTHLEN[i], NONCE[i],
		    NONCELEN[i], DATA_2[i-12], AUTHLEN[i], MACLEN[i]);

		args.param = &param;
		args.plen = sizeof (param);

		args.in = DATA_2[i-12] + AUTHLEN[i];
		args.inlen = DATALEN[i] - AUTHLEN[i];

		errs += run_test(&args, RES[i] + AUTHLEN[i],
		    RESLEN[i] - AUTHLEN[i], ENCR_FG);
		(void) fprintf(stderr, "----------\n");
	}

	(void) fprintf(stderr, "\t\t\t=== decrypt ===\n----------\n\n");

	args.key = CCM_KEY1;
	args.keylen = sizeof (CCM_KEY1);
	for (i = 0; i < 12; i++) {
		CCM_PARAMS param = INIT_CCM(RESLEN[i] - AUTHLEN[i], NONCE[i],
		    NONCELEN[i], CCM_DATA1, AUTHLEN[i], MACLEN[i]);

		args.param = &param;
		args.plen = sizeof (param);

		args.in = RES[i] + AUTHLEN[i];
		args.inlen = RESLEN[i] - AUTHLEN[i];

		errs += run_test(&args, CCM_DATA1 + AUTHLEN[i],
		    DATALEN[i] - AUTHLEN[i], DECR_FG);
		(void) fprintf(stderr, "----------\n");
	}

	args.key = CCM_KEY2;
	args.keylen = sizeof (CCM_KEY2);
	for (i = 12; i < 24; i++) {
		CCM_PARAMS param = INIT_CCM(RESLEN[i] - AUTHLEN[i], NONCE[i],
		    NONCELEN[i], DATA_2[i-12], AUTHLEN[i], MACLEN[i]);

		args.param = &param;
		args.plen = sizeof (param);

		args.in = RES[i] + AUTHLEN[i];
		args.inlen = RESLEN[i] - AUTHLEN[i];

		errs += run_test(&args, DATA_2[i-12] + AUTHLEN[i],
		    DATALEN[i] - AUTHLEN[i], ENCR_FG);
		(void) fprintf(stderr, "----------\n");
	}

	if (errs != 0)
		(void) fprintf(stderr, "%d tests failed\n", errs);

	return (errs);
}
