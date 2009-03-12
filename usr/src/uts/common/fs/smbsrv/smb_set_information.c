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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * SMB: set_information
 *
 * This message is sent to change the information about a file.
 *
 * Client Request                     Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 8
 * USHORT FileAttributes;             Attributes of the file
 * UTIME LastWriteTime;               Time of last write
 * USHORT Reserved [5];               Reserved (must be 0)
 * USHORT ByteCount;                  Count of data bytes;    min = 2
 * UCHAR BufferFormat;                0x04
 * STRING FileName[];                 File name
 *
 * FileName is the fully qualified name of the file relative to the Tid.
 *
 * Support of all parameters is optional.  A server which does not
 * implement one of the parameters will ignore that field.  If the
 * LastWriteTime field contain zero then the file's time is not changed.
 *
 * Server Response                    Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 0
 * USHORT ByteCount;                  Count of data bytes = 0
 *
 */

#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>

smb_sdrc_t
smb_pre_set_information(smb_request_t *sr)
{
	DTRACE_SMB_1(op__SetInformation__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_set_information(smb_request_t *sr)
{
	DTRACE_SMB_1(op__SetInformation__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_set_information(smb_request_t *sr)
{
	int			rc;
	unsigned short		dattr;
	timestruc_t		utime;
	char			*path;
	struct smb_node		*dir_node;
	smb_attr_t		attr;
	struct smb_node		*node;
	char			*name;
	uint32_t		last_wtime;

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		(void) smbsr_encode_empty_result(sr);
		return (SDRC_SUCCESS);
	}

	name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	if (smbsr_decode_vwv(sr, "wl10.", &dattr, &last_wtime) != 0) {
		kmem_free(name, MAXNAMELEN);
		return (SDRC_ERROR);
	}

	if (smbsr_decode_data(sr, "%S", sr, &path) != 0) {
		kmem_free(name, MAXNAMELEN);
		return (SDRC_ERROR);
	}

	rc = smb_pathname_reduce(sr, sr->user_cr, path,
	    sr->tid_tree->t_snode, sr->tid_tree->t_snode, &dir_node, name);
	if (rc != 0) {
		kmem_free(name, MAXNAMELEN);
		smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	rc = smb_fsop_lookup(sr, sr->user_cr, SMB_FOLLOW_LINKS,
	    sr->tid_tree->t_snode, dir_node, name, &node, &attr, 0, 0);
	if (rc != 0) {
		smb_node_release(dir_node);
		kmem_free(name, MAXNAMELEN);
		smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	smb_node_release(dir_node);

	/*
	 * It is not valid to set FILE_ATTRIBUTE_DIRECTORY if the
	 * target is not a directory.
	 */
	if ((dattr & FILE_ATTRIBUTE_DIRECTORY) &&
	    (node->attr.sa_vattr.va_type != VDIR)) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER,
		    ERRDOS, ERROR_INVALID_PARAMETER);
		return (SDRC_ERROR);
	}

	if (smb_oplock_conflict(node, sr->session, NULL)) {
		/*
		 * for the benefit of attribute setting later on
		 */
		(void) smb_oplock_break(node, sr->session, B_FALSE);
	}

	/*
	 * For compatibility with Windows Servers, if the specified
	 * attributes have ONLY FILE_ATTRIBUTE_NORMAL set do NOT change
	 * the file's attributes.
	 * Note - this is different from TRANS2_SET_PATH/FILE_INFORMATION
	 */
	if (dattr != FILE_ATTRIBUTE_NORMAL)
		smb_node_set_dosattr(node, dattr);

	/*
	 * The behaviour when the time field is set to -1
	 * is not documented but is generally treated like 0,
	 * meaning that that server file system assigned value
	 * need not be changed.
	 */
	if (last_wtime != 0 && last_wtime != 0xFFFFFFFF) {
		utime.tv_sec = smb_local2gmt(sr, last_wtime);
		utime.tv_nsec = 0;
		smb_node_set_time(node, 0, &utime, 0, 0, SMB_AT_MTIME);
	}

	rc = smb_sync_fsattr(sr, sr->user_cr, node);
	smb_node_release(node);
	kmem_free(name, MAXNAMELEN);

	if (rc) {
		smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	rc = smbsr_encode_empty_result(sr);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}
