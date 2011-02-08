#!/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
# Copyright 2010, 2011 Joyent, Inc.  All rights reserved.
# Use is subject to license terms.
#

unset LD_LIBRARY_PATH
PATH=/usr/bin:/usr/sbin
export PATH

# state
# ZONE_STATE_CONFIGURED		0 (script will never see this)
# ZONE_STATE_INCOMPLETE		1 (script will never see this)
# ZONE_STATE_INSTALLED		2
# ZONE_STATE_READY		3
# ZONE_STATE_RUNNING		4
# ZONE_STATE_SHUTTING_DOWN	5
# ZONE_STATE_DOWN		6
# ZONE_STATE_MOUNTED		7

# cmd
#
# ready				0
# boot				1
# halt				4

ZONENAME=$1
ZONEPATH=$2
state=$3
cmd=$4
ALTROOT=$5

# If we're readying the zone, then make sure the per-zone writable
# directories exist so that we can lofs mount them.  We do this here,
# instead of in the install script, since this list has evolved and there
# are already zones out there in the installed state.
if [ $cmd -eq 0 ]; then
	[ ! -d $ZONEPATH/site ] && mkdir -m755 $ZONEPATH/site
	[ ! -d $ZONEPATH/local ] && mkdir -m755 $ZONEPATH/local
	[ ! -d $ZONEPATH/root/checkpoints ] && \
	    mkdir -m755 $ZONEPATH/root/checkpoints

	# Force zone snapshots to get mounted
	ls $ZONEPATH/.zfs/snapshot/* >/dev/null 2>&1
fi

exit 0
