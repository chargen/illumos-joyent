/*
* CDDL HEADER START
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License, v.1,  (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://opensource.org/licenses/CDDL-1.0.
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
* Copyright 2014-2017 Cavium, Inc. 
* The contents of this file are subject to the terms of the Common Development 
* and Distribution License, v.1,  (the "License").

* You may not use this file except in compliance with the License.

* You can obtain a copy of the License at available 
* at http://opensource.org/licenses/CDDL-1.0

* See the License for the specific language governing permissions and 
* limitations under the License.
*/

/****************************************************************************
 * Name:        nvm_map.h
 *
 * Description: Everest NVRAM map
 *
 ****************************************************************************/

#ifndef NVM_MAP_H
#define NVM_MAP_H

#define CRC_MAGIC_VALUE                     0xDEBB20E3
#define CRC32_POLYNOMIAL                    0xEDB88320
#define NVM_CRC_SIZE				(sizeof(u32))
enum nvm_sw_arbitrator {
	NVM_SW_ARB_HOST,
	NVM_SW_ARB_MCP,
	NVM_SW_ARB_UART,
	NVM_SW_ARB_RESERVED
};

/****************************************************************************
 * Boot Strap Region                                                        *
 ****************************************************************************/
struct legacy_bootstrap_region {
	u32 magic_value;	/* a pattern not likely to occur randomly */
#define NVM_MAGIC_VALUE          0x669955aa
	u32 sram_start_addr;	/* where to locate LIM code (byte addr) */
	u32 code_len;		/* boot code length (in dwords) */
	u32 code_start_addr;	/* location of code on media (media byte addr) */
	u32 crc;		/* 32-bit CRC */
};

/****************************************************************************
 * Directories Region                                                       *
 ****************************************************************************/
struct nvm_code_entry {
	u32 image_type;		/* Image type */
	u32 nvm_start_addr;	/* NVM address of the image */
	u32 len;		/* Include CRC */
	u32 sram_start_addr;	/* Where to load the image on the scratchpad */
	u32 sram_run_addr;	/* Relevant in case of MIM only */
};

enum nvm_image_type {
	NVM_TYPE_TIM1       = 0x01,
	NVM_TYPE_TIM2       = 0x02,
	NVM_TYPE_MIM1       = 0x03,
	NVM_TYPE_MIM2       = 0x04,
	NVM_TYPE_MBA        = 0x05,
	NVM_TYPE_MODULES_PN = 0x06,
	NVM_TYPE_VPD        = 0x07,
	NVM_TYPE_MFW_TRACE1 = 0x08,
	NVM_TYPE_MFW_TRACE2 = 0x09,
	NVM_TYPE_NVM_CFG1   = 0x0a,
	NVM_TYPE_L2B        = 0x0b,
	NVM_TYPE_DIR1       = 0x0c,
	NVM_TYPE_EAGLE_FW1  = 0x0d,
	NVM_TYPE_FALCON_FW1 = 0x0e,
	NVM_TYPE_PCIE_FW1   = 0x0f,
	NVM_TYPE_HW_SET     = 0x10,
	NVM_TYPE_LIM        = 0x11,
	NVM_TYPE_AVS_FW1    = 0x12,
	NVM_TYPE_DIR2       = 0x13,
	NVM_TYPE_CCM        = 0x14,
	NVM_TYPE_EAGLE_FW2  = 0x15,
	NVM_TYPE_FALCON_FW2 = 0x16,
	NVM_TYPE_PCIE_FW2   = 0x17,
	NVM_TYPE_AVS_FW2    = 0x18,
	NVM_TYPE_INIT_HW    = 0x19,
	NVM_TYPE_DEFAULT_CFG= 0x1a,
	NVM_TYPE_MDUMP	    = 0x1b,
	NVM_TYPE_NVM_META   = 0x1c,
	NVM_TYPE_ISCSI_CFG  = 0x1d,
	NVM_TYPE_FCOE_CFG   = 0x1f,
	NVM_TYPE_ETH_PHY_FW1 = 0x20,
	NVM_TYPE_ETH_PHY_FW2 = 0x21,
	NVM_TYPE_BDN        = 0x22,
	NVM_TYPE_8485X_PHY_FW = 0x23,
	NVM_TYPE_PUB_KEY    = 0x24,
	NVM_TYPE_RECOVERY   = 0x25,
	NVM_TYPE_MAX,
};

#ifdef DEFINE_IMAGE_TABLE
struct image_map {
	char name[32];
	char option[32];
	u32 image_type;
};

struct image_map g_image_table[] = {
	{"TIM1",        "-tim1",    NVM_TYPE_TIM1},
	{"TIM2",        "-tim2",    NVM_TYPE_TIM2},
	{"MIM1",        "-mim1",    NVM_TYPE_MIM1},
	{"MIM2",        "-mim2",    NVM_TYPE_MIM2},
	{"MBA",         "-mba",     NVM_TYPE_MBA},
	{"OPT_MODULES", "-optm",    NVM_TYPE_MODULES_PN},
	{"VPD",         "-vpd",     NVM_TYPE_VPD},
	{"MFW_TRACE1",  "-mfwt1",   NVM_TYPE_MFW_TRACE1},
	{"MFW_TRACE2",  "-mfwt2",   NVM_TYPE_MFW_TRACE2},
	{"NVM_CFG1",    "-cfg",     NVM_TYPE_NVM_CFG1},
	{"L2B",         "-l2b",     NVM_TYPE_L2B},
	{"DIR1",        "-dir1",    NVM_TYPE_DIR1},
	{"EAGLE_FW1",   "-eagle1",  NVM_TYPE_EAGLE_FW1},
	{"FALCON_FW1",  "-falcon1", NVM_TYPE_FALCON_FW1},
	{"PCIE_FW1",    "-pcie1",   NVM_TYPE_PCIE_FW1},
	{"HW_SET",      "-hw_set",  NVM_TYPE_HW_SET},
	{"LIM",         "-lim",     NVM_TYPE_LIM},
	{"AVS_FW1",     "-avs1",    NVM_TYPE_AVS_FW1},
	{"DIR2",        "-dir2",    NVM_TYPE_DIR2},
	{"CCM",         "-ccm",     NVM_TYPE_CCM},
	{"EAGLE_FW2",   "-eagle2",  NVM_TYPE_EAGLE_FW2},
	{"FALCON_FW2",  "-falcon2", NVM_TYPE_FALCON_FW2},
	{"PCIE_FW2",    "-pcie2",   NVM_TYPE_PCIE_FW2},
	{"AVS_FW2",     "-avs2",    NVM_TYPE_AVS_FW2},
	{"INIT_HW",     "-init_hw", NVM_TYPE_INIT_HW},
	{"DEFAULT_CFG", "-def_cfg", NVM_TYPE_DEFAULT_CFG},
	{"CRASH_DUMP",  "-mdump",   NVM_TYPE_MDUMP},
	{"META",	    "-meta",    NVM_TYPE_NVM_META},
	{"ISCSI_CFG",   "-iscsi_cfg", NVM_TYPE_ISCSI_CFG},
	{"FCOE_CFG",    "-fcoe_cfg",NVM_TYPE_FCOE_CFG},
	{"ETH_PHY_FW1", "-ethphy1", NVM_TYPE_ETH_PHY_FW1},
	{"ETH_PHY_FW2", "-ethphy2", NVM_TYPE_ETH_PHY_FW2},
	{"BDN",         "-bdn",     NVM_TYPE_BDN},
	{"PK",          "-pk",      NVM_TYPE_PUB_KEY},
	{"RECOVERY",    "-recovery",NVM_TYPE_RECOVERY}
};

#define IMAGE_TABLE_SIZE (sizeof(g_image_table) / sizeof(struct image_map))

#endif	/* #ifdef DEFINE_IMAGE_TABLE */
#define MAX_NVM_DIR_ENTRIES 150
/* Note: The has given 150 possible entries since anyway each file captures at least one page. */

struct nvm_dir { 
	s32 seq; /* This dword is used to indicate whether this dir is valid, and whether it is more updated than the other dir */
#define NVM_DIR_NEXT_MFW_MASK	0x00000001
#define NVM_DIR_SEQ_MASK	0xfffffffe
#define NVM_DIR_NEXT_MFW(seq) ((seq) & NVM_DIR_NEXT_MFW_MASK)
#define NVM_DIR_UPDATE_SEQ(_seq, swap_mfw) \
	do { \
		_seq = (((_seq + 2) & NVM_DIR_SEQ_MASK) | (NVM_DIR_NEXT_MFW(_seq ^ swap_mfw))); \
	} while (0)
#define IS_DIR_SEQ_VALID(seq) ((seq & NVM_DIR_SEQ_MASK) != NVM_DIR_SEQ_MASK)

	u32 num_images;
	u32 rsrv;
	struct nvm_code_entry code[1];	/* Up to MAX_NVM_DIR_ENTRIES */
};
#define NVM_DIR_SIZE(_num_images) (sizeof(struct nvm_dir) + (_num_images - 1) * sizeof(struct nvm_code_entry) + NVM_CRC_SIZE)

struct nvm_vpd_image {
	u32 format_revision;
#define VPD_IMAGE_VERSION        1

	/* This array length depends on the number of VPD fields */
	u8 vpd_data[1];
};

/****************************************************************************
 * NVRAM FULL MAP                                                           *
 ****************************************************************************/
#define DIR_ID_1    (0)
#define DIR_ID_2    (1)
#define MAX_DIR_IDS (2)

#define MFW_BUNDLE_1    (0)
#define MFW_BUNDLE_2    (1)
#define MAX_MFW_BUNDLES (2)

#define FLASH_PAGE_SIZE 0x1000
#define NVM_DIR_MAX_SIZE    (FLASH_PAGE_SIZE) 		/* 4Kb */
#define ASIC_MIM_MAX_SIZE   (300*FLASH_PAGE_SIZE)	/* 1.2Mb */
#define FPGA_MIM_MAX_SIZE   (62*FLASH_PAGE_SIZE)	/* 250Kb */

/* Each image must start on its own page. Bootstrap and LIM are bound together, so they can share the same page.
 * The LIM itself should be very small, so limit it to 8Kb, but in order to open a new page, we decrement the bootstrap size out of it.
 */
#define LIM_MAX_SIZE	    ((2*FLASH_PAGE_SIZE) - sizeof(struct legacy_bootstrap_region) - NVM_RSV_SIZE)
#define LIM_OFFSET          (NVM_OFFSET(lim_image))
#define NVM_RSV_SIZE		(44)
#define MIM_MAX_SIZE(is_asic) ((is_asic) ? ASIC_MIM_MAX_SIZE : FPGA_MIM_MAX_SIZE )
#define MIM_OFFSET(idx, is_asic) (NVM_OFFSET(dir[MAX_MFW_BUNDLES]) + ((idx == NVM_TYPE_MIM2) ? MIM_MAX_SIZE(is_asic) : 0))
#define NVM_FIXED_AREA_SIZE(is_asic) (sizeof(struct nvm_image) + MIM_MAX_SIZE(is_asic)*2)

union nvm_dir_union {
	struct nvm_dir dir;
	u8 page[FLASH_PAGE_SIZE];
};

/*                        Address
 *  +-------------------+ 0x000000
 *  |    Bootstrap:     |
 *  | magic_number      |
 *  | sram_start_addr   |
 *  | code_len  	|
 *  | code_start_addr   |
 *  | crc               |
 *  +-------------------+ 0x000014
 *  | rsrv              |
 *  +-------------------+ 0x000040
 *  | LIM               |
 *  +-------------------+ 0x002000
 *  | Dir1              |
 *  +-------------------+ 0x003000
 *  | Dir2              |
 *  +-------------------+ 0x004000
 *  | MIM1              |
 *  +-------------------+ 0x130000
 *  | MIM2              |
 *  +-------------------+ 0x25C000
 *  | Rest Images:      |
 *  | TIM1/2    	|
 *  | MFW_TRACE1/2      |
 *  | Eagle/Falcon FW   |
 *  | PCIE/AVS FW       |
 *  | MBA/CCM/L2B       |
 *  | VPD       	|
 *  | optic_modules     |
 *  |  ...              |
 *  +-------------------+ 0x400000
*/
struct nvm_image {
/*********** !!!  FIXED SECTIONS  !!! DO NOT MODIFY !!! **********************/
						/* NVM Offset  (size) */
	struct legacy_bootstrap_region bootstrap;	/* 0x000000 (0x000014) */
	u8 rsrv[NVM_RSV_SIZE];			/* 0x000014 (0x00002c) */
	u8 lim_image[LIM_MAX_SIZE];		/* 0x000040 (0x001fc0) */
	union nvm_dir_union dir[MAX_MFW_BUNDLES];	/* 0x002000 (0x001000)x2 */
	/* MIM1_IMAGE        	                   0x004000 (0x12c000) */
	/* MIM2_IMAGE                              0x130000 (0x12c000) */
/*********** !!!  FIXED SECTIONS  !!! DO NOT MODIFY !!! **********************/
};				/* 0x134 */

#define NVM_OFFSET(f)       ((u32_t)((int_ptr_t)(&(((struct nvm_image*)0)->f))))

struct hw_set_info {
	u32 reg_type;
#define GRC_REG_TYPE 1
#define PHY_REG_TYPE 2
#define PCI_REG_TYPE 4

	u32 bank_num;
	u32 pf_num;
	u32 operation;
#define READ_OP     1
#define WRITE_OP    2
#define RMW_SET_OP  3
#define RMW_CLR_OP  4

	u32 reg_addr;
	u32 reg_data;

	u32 reset_type;
#define POR_RESET_TYPE  (1 << 0)
#define HARD_RESET_TYPE (1 << 1)
#define CORE_RESET_TYPE (1 << 2)
#define MCP_RESET_TYPE  (1 << 3)
#define PERSET_ASSERT   (1 << 4)
#define PERSET_DEASSERT (1 << 5)

};

struct hw_set_image {
	u32 format_version;
#define HW_SET_IMAGE_VERSION        1
	u32 no_hw_sets;
	/* This array length depends on the no_hw_sets */
	struct hw_set_info hw_sets[1];
};

#endif				//NVM_MAP_H
