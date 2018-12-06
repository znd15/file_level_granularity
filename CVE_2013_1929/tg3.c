

/*
 * tg3.c: Broadcom Tigon3 ethernet driver.
 *
 * Copyright (C) 2001, 2002, 2003, 2004 David S. Miller (davem@redhat.com)
 * Copyright (C) 2001, 2002, 2003 Jeff Garzik (jgarzik@pobox.com)
 * Copyright (C) 2004 Sun Microsystems Inc.
 * Copyright (C) 2005-2013 Broadcom Corporation.
 *
 * Firmware is:
 * Derived from proprietary unpublished source code,
 * Copyright (C) 2000-2003 Broadcom Corporation.
 *
 * Permission is hereby granted for the distribution of this firmware
 * data in hexadecimal or equivalent format, provided this copyright
 * notice is accompanying it.
 */


#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/stringify.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/in.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/ioport.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ethtool.h>
#include <linux/mdio.h>
#include <linux/mii.h>
#include <linux/phy.h>
#include <linux/brcmphy.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/workqueue.h>
#include <linux/prefetch.h>
#include <linux/dma-mapping.h>
#include <linux/firmware.h>
#include <linux/ssb/ssb_driver_gige.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>

#include <net/checksum.h>
#include <net/ip.h>

#include <linux/io.h>
#include <asm/byteorder.h>
#include <linux/uaccess.h>

#include <uapi/linux/net_tstamp.h>
#include <linux/ptp_clock_kernel.h>

#ifdef CONFIG_SPARC
#include <asm/idprom.h>
#include <asm/prom.h>
#endif

#define BAR_0 0
#define BAR_2 2

#include "tg3.h"

/* Functions & macros to verify TG3_FLAGS types */

static inline int _tg3_flag(enum TG3_FLAGS flag, unsigned long *bits)
{
	return test_bit(flag, bits);
}

static inline void _tg3_flag_set(enum TG3_FLAGS flag, unsigned long *bits)
{
	set_bit(flag, bits);
}

static inline void _tg3_flag_clear(enum TG3_FLAGS flag, unsigned long *bits)
{
	clear_bit(flag, bits);
}

#define tg3_flag(tp, flag) \
 _tg3_flag(TG3_FLAG_##flag, (tp)->tg3_flags)
#define tg3_flag_set(tp, flag) \
 _tg3_flag_set(TG3_FLAG_##flag, (tp)->tg3_flags)
#define tg3_flag_clear(tp, flag) \
 _tg3_flag_clear(TG3_FLAG_##flag, (tp)->tg3_flags)

#define DRV_MODULE_NAME		"tg3"
#define TG3_MAJ_NUM 3
#define TG3_MIN_NUM 130
#define DRV_MODULE_VERSION \
 __stringify(TG3_MAJ_NUM) "." __stringify(TG3_MIN_NUM)
#define DRV_MODULE_RELDATE	"February 14, 2013"

#define RESET_KIND_SHUTDOWN 0
#define RESET_KIND_INIT 1
#define RESET_KIND_SUSPEND 2

#define TG3_DEF_RX_MODE 0
#define TG3_DEF_TX_MODE 0
#define TG3_DEF_MSG_ENABLE \
 (NETIF_MSG_DRV | \
 NETIF_MSG_PROBE | \
 NETIF_MSG_LINK | \
 NETIF_MSG_TIMER | \
 NETIF_MSG_IFDOWN | \
 NETIF_MSG_IFUP | \
 NETIF_MSG_RX_ERR | \
 NETIF_MSG_TX_ERR)

#define TG3_GRC_LCLCTL_PWRSW_DELAY 100

/* length of time before we decide the hardware is borked,
 * and dev->tx_timeout() should be called to fix the problem
 */

#define TG3_TX_TIMEOUT (5 * HZ)

/* hardware minimum and maximum for a single frame's data payload */
#define TG3_MIN_MTU 60
#define TG3_MAX_MTU(tp) \
 (tg3_flag(tp, JUMBO_CAPABLE) ? 9000 : 1500)

/* These numbers seem to be hard coded in the NIC firmware somehow.
 * You can't change the ring sizes, but you can change where you place
 * them in the NIC onboard memory.
 */
#define TG3_RX_STD_RING_SIZE(tp) \
 (tg3_flag(tp, LRG_PROD_RING_CAP) ? \
 TG3_RX_STD_MAX_SIZE_5717 : TG3_RX_STD_MAX_SIZE_5700)
#define TG3_DEF_RX_RING_PENDING 200
#define TG3_RX_JMB_RING_SIZE(tp) \
 (tg3_flag(tp, LRG_PROD_RING_CAP) ? \
 TG3_RX_JMB_MAX_SIZE_5717 : TG3_RX_JMB_MAX_SIZE_5700)
#define TG3_DEF_RX_JUMBO_RING_PENDING 100

/* Do not place this n-ring entries value into the tp struct itself,
 * we really want to expose these constants to GCC so that modulo et
 * al. operations are done with shifts and masks instead of with
 * hw multiply/modulo instructions. Another solution would be to
 * replace things like '% foo' with '& (foo - 1)'.
 */

#define TG3_TX_RING_SIZE 512
#define TG3_DEF_TX_RING_PENDING (TG3_TX_RING_SIZE - 1)

#define TG3_RX_STD_RING_BYTES(tp) \
 (sizeof(struct tg3_rx_buffer_desc) * TG3_RX_STD_RING_SIZE(tp))
#define TG3_RX_JMB_RING_BYTES(tp) \
 (sizeof(struct tg3_ext_rx_buffer_desc) * TG3_RX_JMB_RING_SIZE(tp))
#define TG3_RX_RCB_RING_BYTES(tp) \
 (sizeof(struct tg3_rx_buffer_desc) * (tp->rx_ret_ring_mask + 1))
#define TG3_TX_RING_BYTES (sizeof(struct tg3_tx_buffer_desc) * \
 TG3_TX_RING_SIZE)
#define NEXT_TX(N) (((N) + 1) & (TG3_TX_RING_SIZE - 1))

#define TG3_DMA_BYTE_ENAB 64

#define TG3_RX_STD_DMA_SZ 1536
#define TG3_RX_JMB_DMA_SZ 9046

#define TG3_RX_DMA_TO_MAP_SZ(x) ((x) + TG3_DMA_BYTE_ENAB)

#define TG3_RX_STD_MAP_SZ TG3_RX_DMA_TO_MAP_SZ(TG3_RX_STD_DMA_SZ)
#define TG3_RX_JMB_MAP_SZ TG3_RX_DMA_TO_MAP_SZ(TG3_RX_JMB_DMA_SZ)

#define TG3_RX_STD_BUFF_RING_SIZE(tp) \
 (sizeof(struct ring_info) * TG3_RX_STD_RING_SIZE(tp))

#define TG3_RX_JMB_BUFF_RING_SIZE(tp) \
 (sizeof(struct ring_info) * TG3_RX_JMB_RING_SIZE(tp))

/* Due to a hardware bug, the 5701 can only DMA to memory addresses
 * that are at least dword aligned when used in PCIX mode. The driver
 * works around this bug by double copying the packet. This workaround
 * is built into the normal double copy length check for efficiency.
 *
 * However, the double copy is only necessary on those architectures
 * where unaligned memory accesses are inefficient. For those architectures
 * where unaligned memory accesses incur little penalty, we can reintegrate
 * the 5701 in the normal rx path. Doing so saves a device structure
 * dereference by hardcoding the double copy threshold in place.
 */
#define TG3_RX_COPY_THRESHOLD 256
#if NET_IP_ALIGN == 0 || defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	#define TG3_RX_COPY_THRESH(tp) TG3_RX_COPY_THRESHOLD
#else
	#define TG3_RX_COPY_THRESH(tp) ((tp)->rx_copy_thresh)
#endif

#if (NET_IP_ALIGN != 0)
#define TG3_RX_OFFSET(tp) ((tp)->rx_offset)
#else
#define TG3_RX_OFFSET(tp) (NET_SKB_PAD)
#endif

/* minimum number of free TX descriptors required to wake up TX process */
#define TG3_TX_WAKEUP_THRESH(tnapi) ((tnapi)->tx_pending / 4)
#define TG3_TX_BD_DMA_MAX_2K 2048
#define TG3_TX_BD_DMA_MAX_4K 4096

#define TG3_RAW_IP_ALIGN 2

#define TG3_FW_UPDATE_TIMEOUT_SEC 5
#define TG3_FW_UPDATE_FREQ_SEC (TG3_FW_UPDATE_TIMEOUT_SEC / 2)

#define FIRMWARE_TG3		"tigon/tg3.bin"
#define FIRMWARE_TG3TSO		"tigon/tg3_tso.bin"
#define FIRMWARE_TG3TSO5	"tigon/tg3_tso5.bin"

static char version[] =
	DRV_MODULE_NAME ".c:v" DRV_MODULE_VERSION " (" DRV_MODULE_RELDATE ")";

MODULE_AUTHOR("David S. Miller (davem@redhat.com) and Jeff Garzik (jgarzik@pobox.com)");
MODULE_DESCRIPTION("Broadcom Tigon3 ethernet driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_MODULE_VERSION);
MODULE_FIRMWARE(FIRMWARE_TG3);
MODULE_FIRMWARE(FIRMWARE_TG3TSO);
MODULE_FIRMWARE(FIRMWARE_TG3TSO5);

static int tg3_debug = -1;	/* -1 == use TG3_DEF_MSG_ENABLE as value */
module_param(tg3_debug, int, 0);
MODULE_PARM_DESC(tg3_debug, "Tigon3 bitmapped debugging message enable value");

#define TG3_DRV_DATA_FLAG_10_100_ONLY 0x0001
#define TG3_DRV_DATA_FLAG_5705_10_100 0x0002

static DEFINE_PCI_DEVICE_TABLE(tg3_pci_tbl) = {
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5700)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5701)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5702)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5703)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5704)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5702FE)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5705)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5705_2)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5705M)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5705M_2)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5702X)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5703X)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5704S)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5702A3)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5703A3)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5782)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5788)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5789)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5901),
	 .driver_data = TG3_DRV_DATA_FLAG_10_100_ONLY |
			TG3_DRV_DATA_FLAG_5705_10_100},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5901_2),
	 .driver_data = TG3_DRV_DATA_FLAG_10_100_ONLY |
			TG3_DRV_DATA_FLAG_5705_10_100},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5704S_2)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5705F),
	 .driver_data = TG3_DRV_DATA_FLAG_10_100_ONLY |
			TG3_DRV_DATA_FLAG_5705_10_100},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5721)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5722)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5750)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5751)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5751M)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5751F),
	 .driver_data = TG3_DRV_DATA_FLAG_10_100_ONLY},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5752)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5752M)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5753)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5753M)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5753F),
	 .driver_data = TG3_DRV_DATA_FLAG_10_100_ONLY},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5754)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5754M)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5755)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5755M)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5756)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5786)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5787)},
	{PCI_DEVICE_SUB(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_5787M,
			PCI_VENDOR_ID_LENOVO,
			TG3PCI_SUBDEVICE_ID_LENOVO_5787M),
	 .driver_data = TG3_DRV_DATA_FLAG_10_100_ONLY},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5787M)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5787F),
	 .driver_data = TG3_DRV_DATA_FLAG_10_100_ONLY},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5714)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5714S)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5715)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5715S)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5780)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5780S)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5781)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5906)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5906M)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5784)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5764)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5723)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5761)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5761E)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_5761S)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_5761SE)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_5785_G)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_5785_F)},
	{PCI_DEVICE_SUB(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_57780,
			PCI_VENDOR_ID_AI, TG3PCI_SUBDEVICE_ID_ACER_57780_A),
	 .driver_data = TG3_DRV_DATA_FLAG_10_100_ONLY},
	{PCI_DEVICE_SUB(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_57780,
			PCI_VENDOR_ID_AI, TG3PCI_SUBDEVICE_ID_ACER_57780_B),
	 .driver_data = TG3_DRV_DATA_FLAG_10_100_ONLY},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_57780)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_57760)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_57790),
	 .driver_data = TG3_DRV_DATA_FLAG_10_100_ONLY},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_57788)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_5717)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_5717_C)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_5718)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_57781)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_57785)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_57761)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_57765)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_57791),
	 .driver_data = TG3_DRV_DATA_FLAG_10_100_ONLY},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_57795),
	 .driver_data = TG3_DRV_DATA_FLAG_10_100_ONLY},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_5719)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_5720)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_57762)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_57766)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_5762)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_5725)},
	{PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, TG3PCI_DEVICE_TIGON3_5727)},
	{PCI_DEVICE(PCI_VENDOR_ID_SYSKONNECT, PCI_DEVICE_ID_SYSKONNECT_9DXX)},
	{PCI_DEVICE(PCI_VENDOR_ID_SYSKONNECT, PCI_DEVICE_ID_SYSKONNECT_9MXX)},
	{PCI_DEVICE(PCI_VENDOR_ID_ALTIMA, PCI_DEVICE_ID_ALTIMA_AC1000)},
	{PCI_DEVICE(PCI_VENDOR_ID_ALTIMA, PCI_DEVICE_ID_ALTIMA_AC1001)},
	{PCI_DEVICE(PCI_VENDOR_ID_ALTIMA, PCI_DEVICE_ID_ALTIMA_AC1003)},
	{PCI_DEVICE(PCI_VENDOR_ID_ALTIMA, PCI_DEVICE_ID_ALTIMA_AC9100)},
	{PCI_DEVICE(PCI_VENDOR_ID_APPLE, PCI_DEVICE_ID_APPLE_TIGON3)},
	{PCI_DEVICE(0x10cf, 0x11a2)}, /* Fujitsu 1000base-SX with BCM5703SKHB */
	{}
};

MODULE_DEVICE_TABLE(pci, tg3_pci_tbl);

static const struct {
	const char string[ETH_GSTRING_LEN];
} ethtool_stats_keys[] = {
	{ "rx_octets" },
	{ "rx_fragments" },
	{ "rx_ucast_packets" },
	{ "rx_mcast_packets" },
	{ "rx_bcast_packets" },
	{ "rx_fcs_errors" },
	{ "rx_align_errors" },
	{ "rx_xon_pause_rcvd" },
	{ "rx_xoff_pause_rcvd" },
	{ "rx_mac_ctrl_rcvd" },
	{ "rx_xoff_entered" },
	{ "rx_frame_too_long_errors" },
	{ "rx_jabbers" },
	{ "rx_undersize_packets" },
	{ "rx_in_length_errors" },
	{ "rx_out_length_errors" },
	{ "rx_64_or_less_octet_packets" },
	{ "rx_65_to_127_octet_packets" },
	{ "rx_128_to_255_octet_packets" },
	{ "rx_256_to_511_octet_packets" },
	{ "rx_512_to_1023_octet_packets" },
	{ "rx_1024_to_1522_octet_packets" },
	{ "rx_1523_to_2047_octet_packets" },
	{ "rx_2048_to_4095_octet_packets" },
	{ "rx_4096_to_8191_octet_packets" },
	{ "rx_8192_to_9022_octet_packets" },

	{ "tx_octets" },
	{ "tx_collisions" },

	{ "tx_xon_sent" },
	{ "tx_xoff_sent" },
	{ "tx_flow_control" },
	{ "tx_mac_errors" },
	{ "tx_single_collisions" },
	{ "tx_mult_collisions" },
	{ "tx_deferred" },
	{ "tx_excessive_collisions" },
	{ "tx_late_collisions" },
	{ "tx_collide_2times" },
	{ "tx_collide_3times" },
	{ "tx_collide_4times" },
	{ "tx_collide_5times" },
	{ "tx_collide_6times" },
	{ "tx_collide_7times" },
	{ "tx_collide_8times" },
	{ "tx_collide_9times" },
	{ "tx_collide_10times" },
	{ "tx_collide_11times" },
	{ "tx_collide_12times" },
	{ "tx_collide_13times" },
	{ "tx_collide_14times" },
	{ "tx_collide_15times" },
	{ "tx_ucast_packets" },
	{ "tx_mcast_packets" },
	{ "tx_bcast_packets" },
	{ "tx_carrier_sense_errors" },
	{ "tx_discards" },
	{ "tx_errors" },

	{ "dma_writeq_full" },
	{ "dma_write_prioq_full" },
	{ "rxbds_empty" },
	{ "rx_discards" },
	{ "rx_errors" },
	{ "rx_threshold_hit" },

	{ "dma_readq_full" },
	{ "dma_read_prioq_full" },
	{ "tx_comp_queue_full" },

	{ "ring_set_send_prod_index" },
	{ "ring_status_update" },
	{ "nic_irqs" },
	{ "nic_avoided_irqs" },
	{ "nic_tx_threshold_hit" },

	{ "mbuf_lwm_thresh_hit" },
};

#define TG3_NUM_STATS ARRAY_SIZE(ethtool_stats_keys)
#define TG3_NVRAM_TEST 0
#define TG3_LINK_TEST 1
#define TG3_REGISTER_TEST 2
#define TG3_MEMORY_TEST 3
#define TG3_MAC_LOOPB_TEST 4
#define TG3_PHY_LOOPB_TEST 5
#define TG3_EXT_LOOPB_TEST 6
#define TG3_INTERRUPT_TEST 7


static const struct {
	const char string[ETH_GSTRING_LEN];
} ethtool_test_keys[] = {
	[TG3_NVRAM_TEST] = { "nvram test (online) " },
	[TG3_LINK_TEST] = { "link test (online) " },
	[TG3_REGISTER_TEST] = { "register test (offline)" },
	[TG3_MEMORY_TEST] = { "memory test (offline)" },
	[TG3_MAC_LOOPB_TEST] = { "mac loopback test (offline)" },
	[TG3_PHY_LOOPB_TEST] = { "phy loopback test (offline)" },
	[TG3_EXT_LOOPB_TEST] = { "ext loopback test (offline)" },
	[TG3_INTERRUPT_TEST] = { "interrupt test (offline)" },
};

#define TG3_NUM_TEST ARRAY_SIZE(ethtool_test_keys)


static void tg3_write32(struct tg3 *tp, u32 off, u32 val)
{
	writel(val, tp->regs + off);
}

static u32 tg3_read32(struct tg3 *tp, u32 off)
{
	return readl(tp->regs + off);
}

static void tg3_ape_write32(struct tg3 *tp, u32 off, u32 val)
{
	writel(val, tp->aperegs + off);
}

static u32 tg3_ape_read32(struct tg3 *tp, u32 off)
{
	return readl(tp->aperegs + off);
}

static void tg3_write_indirect_reg32(struct tg3 *tp, u32 off, u32 val)
{
	unsigned long flags;

	spin_lock_irqsave(&tp->indirect_lock, flags);
	pci_write_config_dword(tp->pdev, TG3PCI_REG_BASE_ADDR, off);
	pci_write_config_dword(tp->pdev, TG3PCI_REG_DATA, val);
	spin_unlock_irqrestore(&tp->indirect_lock, flags);
}

static void tg3_write_flush_reg32(struct tg3 *tp, u32 off, u32 val)
{
	writel(val, tp->regs + off);
	readl(tp->regs + off);
}

static u32 tg3_read_indirect_reg32(struct tg3 *tp, u32 off)
{
	unsigned long flags;
	u32 val;

	spin_lock_irqsave(&tp->indirect_lock, flags);
	pci_write_config_dword(tp->pdev, TG3PCI_REG_BASE_ADDR, off);
	pci_read_config_dword(tp->pdev, TG3PCI_REG_DATA, &val);
	spin_unlock_irqrestore(&tp->indirect_lock, flags);
	return val;
}

static void tg3_write_indirect_mbox(struct tg3 *tp, u32 off, u32 val)
{
	unsigned long flags;

	if (off == (MAILBOX_RCVRET_CON_IDX_0 + TG3_64BIT_REG_LOW)) {
		pci_write_config_dword(tp->pdev, TG3PCI_RCV_RET_RING_CON_IDX +
				       TG3_64BIT_REG_LOW, val);
		return;
	}
	if (off == TG3_RX_STD_PROD_IDX_REG) {
		pci_write_config_dword(tp->pdev, TG3PCI_STD_RING_PROD_IDX +
				       TG3_64BIT_REG_LOW, val);
		return;
	}

	spin_lock_irqsave(&tp->indirect_lock, flags);
	pci_write_config_dword(tp->pdev, TG3PCI_REG_BASE_ADDR, off + 0x5600);
	pci_write_config_dword(tp->pdev, TG3PCI_REG_DATA, val);
	spin_unlock_irqrestore(&tp->indirect_lock, flags);

	/* In indirect mode when disabling interrupts, we also need
 * to clear the interrupt bit in the GRC local ctrl register.
 */
	if ((off == (MAILBOX_INTERRUPT_0 + TG3_64BIT_REG_LOW)) &&
	    (val == 0x1)) {
		pci_write_config_dword(tp->pdev, TG3PCI_MISC_LOCAL_CTRL,
				       tp->grc_local_ctrl|GRC_LCLCTRL_CLEARINT);
	}
}

static u32 tg3_read_indirect_mbox(struct tg3 *tp, u32 off)
{
	unsigned long flags;
	u32 val;

	spin_lock_irqsave(&tp->indirect_lock, flags);
	pci_write_config_dword(tp->pdev, TG3PCI_REG_BASE_ADDR, off + 0x5600);
	pci_read_config_dword(tp->pdev, TG3PCI_REG_DATA, &val);
	spin_unlock_irqrestore(&tp->indirect_lock, flags);
	return val;
}

/* usec_wait specifies the wait time in usec when writing to certain registers
 * where it is unsafe to read back the register without some delay.
 * GRC_LOCAL_CTRL is one example if the GPIOs are toggled to switch power.
 * TG3PCI_CLOCK_CTRL is another example if the clock frequencies are changed.
 */
static void _tw32_flush(struct tg3 *tp, u32 off, u32 val, u32 usec_wait)
{
	if (tg3_flag(tp, PCIX_TARGET_HWBUG) || tg3_flag(tp, ICH_WORKAROUND))
		/* Non-posted methods */
		tp->write32(tp, off, val);
	else {
		/* Posted method */
		tg3_write32(tp, off, val);
		if (usec_wait)
			udelay(usec_wait);
		tp->read32(tp, off);
	}
	/* Wait again after the read for the posted method to guarantee that
 * the wait time is met.
 */
	if (usec_wait)
		udelay(usec_wait);
}

static inline void tw32_mailbox_flush(struct tg3 *tp, u32 off, u32 val)
{
	tp->write32_mbox(tp, off, val);
	if (tg3_flag(tp, FLUSH_POSTED_WRITES) ||
	    (!tg3_flag(tp, MBOX_WRITE_REORDER) &&
	     !tg3_flag(tp, ICH_WORKAROUND)))
		tp->read32_mbox(tp, off);
}

static void tg3_write32_tx_mbox(struct tg3 *tp, u32 off, u32 val)
{
	void __iomem *mbox = tp->regs + off;
	writel(val, mbox);
	if (tg3_flag(tp, TXD_MBOX_HWBUG))
		writel(val, mbox);
	if (tg3_flag(tp, MBOX_WRITE_REORDER) ||
	    tg3_flag(tp, FLUSH_POSTED_WRITES))
		readl(mbox);
}

static u32 tg3_read32_mbox_5906(struct tg3 *tp, u32 off)
{
	return readl(tp->regs + off + GRCMBOX_BASE);
}

static void tg3_write32_mbox_5906(struct tg3 *tp, u32 off, u32 val)
{
	writel(val, tp->regs + off + GRCMBOX_BASE);
}

#define tw32_mailbox(reg, val) tp->write32_mbox(tp, reg, val)
#define tw32_mailbox_f(reg, val) tw32_mailbox_flush(tp, (reg), (val))
#define tw32_rx_mbox(reg, val) tp->write32_rx_mbox(tp, reg, val)
#define tw32_tx_mbox(reg, val) tp->write32_tx_mbox(tp, reg, val)
#define tr32_mailbox(reg) tp->read32_mbox(tp, reg)

#define tw32(reg, val) tp->write32(tp, reg, val)
#define tw32_f(reg, val) _tw32_flush(tp, (reg), (val), 0)
#define tw32_wait_f(reg, val, us) _tw32_flush(tp, (reg), (val), (us))
#define tr32(reg) tp->read32(tp, reg)

static void tg3_write_mem(struct tg3 *tp, u32 off, u32 val)
{
	unsigned long flags;

	if (tg3_asic_rev(tp) == ASIC_REV_5906 &&
	    (off >= NIC_SRAM_STATS_BLK) && (off < NIC_SRAM_TX_BUFFER_DESC))
		return;

	spin_lock_irqsave(&tp->indirect_lock, flags);
	if (tg3_flag(tp, SRAM_USE_CONFIG)) {
		pci_write_config_dword(tp->pdev, TG3PCI_MEM_WIN_BASE_ADDR, off);
		pci_write_config_dword(tp->pdev, TG3PCI_MEM_WIN_DATA, val);

		/* Always leave this as zero. */
		pci_write_config_dword(tp->pdev, TG3PCI_MEM_WIN_BASE_ADDR, 0);
	} else {
		tw32_f(TG3PCI_MEM_WIN_BASE_ADDR, off);
		tw32_f(TG3PCI_MEM_WIN_DATA, val);

		/* Always leave this as zero. */
		tw32_f(TG3PCI_MEM_WIN_BASE_ADDR, 0);
	}
	spin_unlock_irqrestore(&tp->indirect_lock, flags);
}

static void tg3_read_mem(struct tg3 *tp, u32 off, u32 *val)
{
	unsigned long flags;

	if (tg3_asic_rev(tp) == ASIC_REV_5906 &&
	    (off >= NIC_SRAM_STATS_BLK) && (off < NIC_SRAM_TX_BUFFER_DESC)) {
		*val = 0;
		return;
	}

	spin_lock_irqsave(&tp->indirect_lock, flags);
	if (tg3_flag(tp, SRAM_USE_CONFIG)) {
		pci_write_config_dword(tp->pdev, TG3PCI_MEM_WIN_BASE_ADDR, off);
		pci_read_config_dword(tp->pdev, TG3PCI_MEM_WIN_DATA, val);

		/* Always leave this as zero. */
		pci_write_config_dword(tp->pdev, TG3PCI_MEM_WIN_BASE_ADDR, 0);
	} else {
		tw32_f(TG3PCI_MEM_WIN_BASE_ADDR, off);
		*val = tr32(TG3PCI_MEM_WIN_DATA);

		/* Always leave this as zero. */
		tw32_f(TG3PCI_MEM_WIN_BASE_ADDR, 0);
	}
	spin_unlock_irqrestore(&tp->indirect_lock, flags);
}

static void tg3_ape_lock_init(struct tg3 *tp)
{
	int i;
	u32 regbase, bit;

	if (tg3_asic_rev(tp) == ASIC_REV_5761)
		regbase = TG3_APE_LOCK_GRANT;
	else
		regbase = TG3_APE_PER_LOCK_GRANT;

	/* Make sure the driver hasn't any stale locks. */
	for (i = TG3_APE_LOCK_PHY0; i <= TG3_APE_LOCK_GPIO; i++) {
		switch (i) {
		case TG3_APE_LOCK_PHY0:
		case TG3_APE_LOCK_PHY1:
		case TG3_APE_LOCK_PHY2:
		case TG3_APE_LOCK_PHY3:
			bit = APE_LOCK_GRANT_DRIVER;
			break;
		default:
			if (!tp->pci_fn)
				bit = APE_LOCK_GRANT_DRIVER;
			else
				bit = 1 << tp->pci_fn;
		}
		tg3_ape_write32(tp, regbase + 4 * i, bit);
	}

}

static int tg3_ape_lock(struct tg3 *tp, int locknum)
{
	int i, off;
	int ret = 0;
	u32 status, req, gnt, bit;

	if (!tg3_flag(tp, ENABLE_APE))
		return 0;

	switch (locknum) {
	case TG3_APE_LOCK_GPIO:
		if (tg3_asic_rev(tp) == ASIC_REV_5761)
			return 0;
	case TG3_APE_LOCK_GRC:
	case TG3_APE_LOCK_MEM:
		if (!tp->pci_fn)
			bit = APE_LOCK_REQ_DRIVER;
		else
			bit = 1 << tp->pci_fn;
		break;
	case TG3_APE_LOCK_PHY0:
	case TG3_APE_LOCK_PHY1:
	case TG3_APE_LOCK_PHY2:
	case TG3_APE_LOCK_PHY3:
		bit = APE_LOCK_REQ_DRIVER;
		break;
	default:
		return -EINVAL;
	}

	if (tg3_asic_rev(tp) == ASIC_REV_5761) {
		req = TG3_APE_LOCK_REQ;
		gnt = TG3_APE_LOCK_GRANT;
	} else {
		req = TG3_APE_PER_LOCK_REQ;
		gnt = TG3_APE_PER_LOCK_GRANT;
	}

	off = 4 * locknum;

	tg3_ape_write32(tp, req + off, bit);

	/* Wait for up to 1 millisecond to acquire lock. */
	for (i = 0; i < 100; i++) {
		status = tg3_ape_read32(tp, gnt + off);
		if (status == bit)
			break;
		udelay(10);
	}

	if (status != bit) {
		/* Revoke the lock request. */
		tg3_ape_write32(tp, gnt + off, bit);
		ret = -EBUSY;
	}

	return ret;
}

static void tg3_ape_unlock(struct tg3 *tp, int locknum)
{
	u32 gnt, bit;

	if (!tg3_flag(tp, ENABLE_APE))
		return;

	switch (locknum) {
	case TG3_APE_LOCK_GPIO:
		if (tg3_asic_rev(tp) == ASIC_REV_5761)
			return;
	case TG3_APE_LOCK_GRC:
	case TG3_APE_LOCK_MEM:
		if (!tp->pci_fn)
			bit = APE_LOCK_GRANT_DRIVER;
		else
			bit = 1 << tp->pci_fn;
		break;
	case TG3_APE_LOCK_PHY0:
	case TG3_APE_LOCK_PHY1:
	case TG3_APE_LOCK_PHY2:
	case TG3_APE_LOCK_PHY3:
		bit = APE_LOCK_GRANT_DRIVER;
		break;
	default:
		return;
	}

	if (tg3_asic_rev(tp) == ASIC_REV_5761)
		gnt = TG3_APE_LOCK_GRANT;
	else
		gnt = TG3_APE_PER_LOCK_GRANT;

	tg3_ape_write32(tp, gnt + 4 * locknum, bit);
}

static int tg3_ape_event_lock(struct tg3 *tp, u32 timeout_us)
{
	u32 apedata;

	while (timeout_us) {
		if (tg3_ape_lock(tp, TG3_APE_LOCK_MEM))
			return -EBUSY;

		apedata = tg3_ape_read32(tp, TG3_APE_EVENT_STATUS);
		if (!(apedata & APE_EVENT_STATUS_EVENT_PENDING))
			break;

		tg3_ape_unlock(tp, TG3_APE_LOCK_MEM);

		udelay(10);
		timeout_us -= (timeout_us > 10) ? 10 : timeout_us;
	}

	return timeout_us ? 0 : -EBUSY;
}

static int tg3_ape_wait_for_event(struct tg3 *tp, u32 timeout_us)
{
	u32 i, apedata;

	for (i = 0; i < timeout_us / 10; i++) {
		apedata = tg3_ape_read32(tp, TG3_APE_EVENT_STATUS);

		if (!(apedata & APE_EVENT_STATUS_EVENT_PENDING))
			break;

		udelay(10);
	}

	return i == timeout_us / 10;
}

static int tg3_ape_scratchpad_read(struct tg3 *tp, u32 *data, u32 base_off,
				   u32 len)
{
	int err;
	u32 i, bufoff, msgoff, maxlen, apedata;

	if (!tg3_flag(tp, APE_HAS_NCSI))
		return 0;

	apedata = tg3_ape_read32(tp, TG3_APE_SEG_SIG);
	if (apedata != APE_SEG_SIG_MAGIC)
		return -ENODEV;

	apedata = tg3_ape_read32(tp, TG3_APE_FW_STATUS);
	if (!(apedata & APE_FW_STATUS_READY))
		return -EAGAIN;

	bufoff = tg3_ape_read32(tp, TG3_APE_SEG_MSG_BUF_OFF) +
		 TG3_APE_SHMEM_BASE;
	msgoff = bufoff + 2 * sizeof(u32);
	maxlen = tg3_ape_read32(tp, TG3_APE_SEG_MSG_BUF_LEN);

	while (len) {
		u32 length;

		/* Cap xfer sizes to scratchpad limits. */
		length = (len > maxlen) ? maxlen : len;
		len -= length;

		apedata = tg3_ape_read32(tp, TG3_APE_FW_STATUS);
		if (!(apedata & APE_FW_STATUS_READY))
			return -EAGAIN;

		/* Wait for up to 1 msec for APE to service previous event. */
		err = tg3_ape_event_lock(tp, 1000);
		if (err)
			return err;

		apedata = APE_EVENT_STATUS_DRIVER_EVNT |
			  APE_EVENT_STATUS_SCRTCHPD_READ |
			  APE_EVENT_STATUS_EVENT_PENDING;
		tg3_ape_write32(tp, TG3_APE_EVENT_STATUS, apedata);

		tg3_ape_write32(tp, bufoff, base_off);
		tg3_ape_write32(tp, bufoff + sizeof(u32), length);

		tg3_ape_unlock(tp, TG3_APE_LOCK_MEM);
		tg3_ape_write32(tp, TG3_APE_EVENT, APE_EVENT_1);

		base_off += length;

		if (tg3_ape_wait_for_event(tp, 30000))
			return -EAGAIN;

		for (i = 0; length; i += 4, length -= 4) {
			u32 val = tg3_ape_read32(tp, msgoff + i);
			memcpy(data, &val, sizeof(u32));
			data++;
		}
	}

	return 0;
}

static int tg3_ape_send_event(struct tg3 *tp, u32 event)
{
	int err;
	u32 apedata;

	apedata = tg3_ape_read32(tp, TG3_APE_SEG_SIG);
	if (apedata != APE_SEG_SIG_MAGIC)
		return -EAGAIN;

	apedata = tg3_ape_read32(tp, TG3_APE_FW_STATUS);
	if (!(apedata & APE_FW_STATUS_READY))
		return -EAGAIN;

	/* Wait for up to 1 millisecond for APE to service previous event. */
	err = tg3_ape_event_lock(tp, 1000);
	if (err)
		return err;

	tg3_ape_write32(tp, TG3_APE_EVENT_STATUS,
			event | APE_EVENT_STATUS_EVENT_PENDING);

	tg3_ape_unlock(tp, TG3_APE_LOCK_MEM);
	tg3_ape_write32(tp, TG3_APE_EVENT, APE_EVENT_1);

	return 0;
}

static void tg3_ape_driver_state_change(struct tg3 *tp, int kind)
{
	u32 event;
	u32 apedata;

	if (!tg3_flag(tp, ENABLE_APE))
		return;

	switch (kind) {
	case RESET_KIND_INIT:
		tg3_ape_write32(tp, TG3_APE_HOST_SEG_SIG,
				APE_HOST_SEG_SIG_MAGIC);
		tg3_ape_write32(tp, TG3_APE_HOST_SEG_LEN,
				APE_HOST_SEG_LEN_MAGIC);
		apedata = tg3_ape_read32(tp, TG3_APE_HOST_INIT_COUNT);
		tg3_ape_write32(tp, TG3_APE_HOST_INIT_COUNT, ++apedata);
		tg3_ape_write32(tp, TG3_APE_HOST_DRIVER_ID,
			APE_HOST_DRIVER_ID_MAGIC(TG3_MAJ_NUM, TG3_MIN_NUM));
		tg3_ape_write32(tp, TG3_APE_HOST_BEHAVIOR,
				APE_HOST_BEHAV_NO_PHYLOCK);
		tg3_ape_write32(tp, TG3_APE_HOST_DRVR_STATE,
				    TG3_APE_HOST_DRVR_STATE_START);

		event = APE_EVENT_STATUS_STATE_START;
		break;
	case RESET_KIND_SHUTDOWN:
		/* With the interface we are currently using,
 * APE does not track driver state. Wiping
 * out the HOST SEGMENT SIGNATURE forces
 * the APE to assume OS absent status.
 */
		tg3_ape_write32(tp, TG3_APE_HOST_SEG_SIG, 0x0);

		if (device_may_wakeup(&tp->pdev->dev) &&
		    tg3_flag(tp, WOL_ENABLE)) {
			tg3_ape_write32(tp, TG3_APE_HOST_WOL_SPEED,
					    TG3_APE_HOST_WOL_SPEED_AUTO);
			apedata = TG3_APE_HOST_DRVR_STATE_WOL;
		} else
			apedata = TG3_APE_HOST_DRVR_STATE_UNLOAD;

		tg3_ape_write32(tp, TG3_APE_HOST_DRVR_STATE, apedata);

		event = APE_EVENT_STATUS_STATE_UNLOAD;
		break;
	case RESET_KIND_SUSPEND:
		event = APE_EVENT_STATUS_STATE_SUSPEND;
		break;
	default:
		return;
	}

	event |= APE_EVENT_STATUS_DRIVER_EVNT | APE_EVENT_STATUS_STATE_CHNGE;

	tg3_ape_send_event(tp, event);
}

static void tg3_disable_ints(struct tg3 *tp)
{
	int i;

	tw32(TG3PCI_MISC_HOST_CTRL,
	     (tp->misc_host_ctrl | MISC_HOST_CTRL_MASK_PCI_INT));
	for (i = 0; i < tp->irq_max; i++)
		tw32_mailbox_f(tp->napi[i].int_mbox, 0x00000001);
}

static void tg3_enable_ints(struct tg3 *tp)
{
	int i;

	tp->irq_sync = 0;
	wmb();

	tw32(TG3PCI_MISC_HOST_CTRL,
	     (tp->misc_host_ctrl & ~MISC_HOST_CTRL_MASK_PCI_INT));

	tp->coal_now = tp->coalesce_mode | HOSTCC_MODE_ENABLE;
	for (i = 0; i < tp->irq_cnt; i++) {
		struct tg3_napi *tnapi = &tp->napi[i];

		tw32_mailbox_f(tnapi->int_mbox, tnapi->last_tag << 24);
		if (tg3_flag(tp, 1SHOT_MSI))
			tw32_mailbox_f(tnapi->int_mbox, tnapi->last_tag << 24);

		tp->coal_now |= tnapi->coal_now;
	}

	/* Force an initial interrupt */
	if (!tg3_flag(tp, TAGGED_STATUS) &&
	    (tp->napi[0].hw_status->status & SD_STATUS_UPDATED))
		tw32(GRC_LOCAL_CTRL, tp->grc_local_ctrl | GRC_LCLCTRL_SETINT);
	else
		tw32(HOSTCC_MODE, tp->coal_now);

	tp->coal_now &= ~(tp->napi[0].coal_now | tp->napi[1].coal_now);
}

static inline unsigned int tg3_has_work(struct tg3_napi *tnapi)
{
	struct tg3 *tp = tnapi->tp;
	struct tg3_hw_status *sblk = tnapi->hw_status;
	unsigned int work_exists = 0;

	/* check for phy events */
	if (!(tg3_flag(tp, USE_LINKCHG_REG) || tg3_flag(tp, POLL_SERDES))) {
		if (sblk->status & SD_STATUS_LINK_CHG)
			work_exists = 1;
	}

	/* check for TX work to do */
	if (sblk->idx[0].tx_consumer != tnapi->tx_cons)
		work_exists = 1;

	/* check for RX work to do */
	if (tnapi->rx_rcb_prod_idx &&
	    *(tnapi->rx_rcb_prod_idx) != tnapi->rx_rcb_ptr)
		work_exists = 1;

	return work_exists;
}

/* tg3_int_reenable
 * similar to tg3_enable_ints, but it accurately determines whether there
 * is new work pending and can return without flushing the PIO write
 * which reenables interrupts
 */
static void tg3_int_reenable(struct tg3_napi *tnapi)
{
	struct tg3 *tp = tnapi->tp;

	tw32_mailbox(tnapi->int_mbox, tnapi->last_tag << 24);
	mmiowb();

	/* When doing tagged status, this work check is unnecessary.
 * The last_tag we write above tells the chip which piece of
 * work we've completed.
 */
	if (!tg3_flag(tp, TAGGED_STATUS) && tg3_has_work(tnapi))
		tw32(HOSTCC_MODE, tp->coalesce_mode |
		     HOSTCC_MODE_ENABLE | tnapi->coal_now);
}

static void tg3_switch_clocks(struct tg3 *tp)
{
	u32 clock_ctrl;
	u32 orig_clock_ctrl;

	if (tg3_flag(tp, CPMU_PRESENT) || tg3_flag(tp, 5780_CLASS))
		return;

	clock_ctrl = tr32(TG3PCI_CLOCK_CTRL);

	orig_clock_ctrl = clock_ctrl;
	clock_ctrl &= (CLOCK_CTRL_FORCE_CLKRUN |
		       CLOCK_CTRL_CLKRUN_OENABLE |
		       0x1f);
	tp->pci_clock_ctrl = clock_ctrl;

	if (tg3_flag(tp, 5705_PLUS)) {
		if (orig_clock_ctrl & CLOCK_CTRL_625_CORE) {
			tw32_wait_f(TG3PCI_CLOCK_CTRL,
				    clock_ctrl | CLOCK_CTRL_625_CORE, 40);
		}
	} else if ((orig_clock_ctrl & CLOCK_CTRL_44MHZ_CORE) != 0) {
		tw32_wait_f(TG3PCI_CLOCK_CTRL,
			    clock_ctrl |
			    (CLOCK_CTRL_44MHZ_CORE | CLOCK_CTRL_ALTCLK),
			    40);
		tw32_wait_f(TG3PCI_CLOCK_CTRL,
			    clock_ctrl | (CLOCK_CTRL_ALTCLK),
			    40);
	}
	tw32_wait_f(TG3PCI_CLOCK_CTRL, clock_ctrl, 40);
}

#define PHY_BUSY_LOOPS 5000

static int __tg3_readphy(struct tg3 *tp, unsigned int phy_addr, int reg,
			 u32 *val)
{
	u32 frame_val;
	unsigned int loops;
	int ret;

	if ((tp->mi_mode & MAC_MI_MODE_AUTO_POLL) != 0) {
		tw32_f(MAC_MI_MODE,
		     (tp->mi_mode & ~MAC_MI_MODE_AUTO_POLL));
		udelay(80);
	}

	tg3_ape_lock(tp, tp->phy_ape_lock);

	*val = 0x0;

	frame_val  = ((phy_addr << MI_COM_PHY_ADDR_SHIFT) &
		      MI_COM_PHY_ADDR_MASK);
	frame_val |= ((reg << MI_COM_REG_ADDR_SHIFT) &
		      MI_COM_REG_ADDR_MASK);
	frame_val |= (MI_COM_CMD_READ | MI_COM_START);

	tw32_f(MAC_MI_COM, frame_val);

	loops = PHY_BUSY_LOOPS;
	while (loops != 0) {
		udelay(10);
		frame_val = tr32(MAC_MI_COM);

		if ((frame_val & MI_COM_BUSY) == 0) {
			udelay(5);
			frame_val = tr32(MAC_MI_COM);
			break;
		}
		loops -= 1;
	}

	ret = -EBUSY;
	if (loops != 0) {
		*val = frame_val & MI_COM_DATA_MASK;
		ret = 0;
	}

	if ((tp->mi_mode & MAC_MI_MODE_AUTO_POLL) != 0) {
		tw32_f(MAC_MI_MODE, tp->mi_mode);
		udelay(80);
	}

	tg3_ape_unlock(tp, tp->phy_ape_lock);

	return ret;
}

static int tg3_readphy(struct tg3 *tp, int reg, u32 *val)
{
	return __tg3_readphy(tp, tp->phy_addr, reg, val);
}

static int __tg3_writephy(struct tg3 *tp, unsigned int phy_addr, int reg,
			  u32 val)
{
	u32 frame_val;
	unsigned int loops;
	int ret;

	if ((tp->phy_flags & TG3_PHYFLG_IS_FET) &&
	    (reg == MII_CTRL1000 || reg == MII_TG3_AUX_CTRL))
		return 0;

	if ((tp->mi_mode & MAC_MI_MODE_AUTO_POLL) != 0) {
		tw32_f(MAC_MI_MODE,
		     (tp->mi_mode & ~MAC_MI_MODE_AUTO_POLL));
		udelay(80);
	}

	tg3_ape_lock(tp, tp->phy_ape_lock);

	frame_val  = ((phy_addr << MI_COM_PHY_ADDR_SHIFT) &
		      MI_COM_PHY_ADDR_MASK);
	frame_val |= ((reg << MI_COM_REG_ADDR_SHIFT) &
		      MI_COM_REG_ADDR_MASK);
	frame_val |= (val & MI_COM_DATA_MASK);
	frame_val |= (MI_COM_CMD_WRITE | MI_COM_START);

	tw32_f(MAC_MI_COM, frame_val);

	loops = PHY_BUSY_LOOPS;
	while (loops != 0) {
		udelay(10);
		frame_val = tr32(MAC_MI_COM);
		if ((frame_val & MI_COM_BUSY) == 0) {
			udelay(5);
			frame_val = tr32(MAC_MI_COM);
			break;
		}
		loops -= 1;
	}

	ret = -EBUSY;
	if (loops != 0)
		ret = 0;

	if ((tp->mi_mode & MAC_MI_MODE_AUTO_POLL) != 0) {
		tw32_f(MAC_MI_MODE, tp->mi_mode);
		udelay(80);
	}

	tg3_ape_unlock(tp, tp->phy_ape_lock);

	return ret;
}

static int tg3_writephy(struct tg3 *tp, int reg, u32 val)
{
	return __tg3_writephy(tp, tp->phy_addr, reg, val);
}

static int tg3_phy_cl45_write(struct tg3 *tp, u32 devad, u32 addr, u32 val)
{
	int err;

	err = tg3_writephy(tp, MII_TG3_MMD_CTRL, devad);
	if (err)
		goto done;

	err = tg3_writephy(tp, MII_TG3_MMD_ADDRESS, addr);
	if (err)
		goto done;

	err = tg3_writephy(tp, MII_TG3_MMD_CTRL,
			   MII_TG3_MMD_CTRL_DATA_NOINC | devad);
	if (err)
		goto done;

	err = tg3_writephy(tp, MII_TG3_MMD_ADDRESS, val);

done:
	return err;
}

static int tg3_phy_cl45_read(struct tg3 *tp, u32 devad, u32 addr, u32 *val)
{
	int err;

	err = tg3_writephy(tp, MII_TG3_MMD_CTRL, devad);
	if (err)
		goto done;

	err = tg3_writephy(tp, MII_TG3_MMD_ADDRESS, addr);
	if (err)
		goto done;

	err = tg3_writephy(tp, MII_TG3_MMD_CTRL,
			   MII_TG3_MMD_CTRL_DATA_NOINC | devad);
	if (err)
		goto done;

	err = tg3_readphy(tp, MII_TG3_MMD_ADDRESS, val);

done:
	return err;
}

static int tg3_phydsp_read(struct tg3 *tp, u32 reg, u32 *val)
{
	int err;

	err = tg3_writephy(tp, MII_TG3_DSP_ADDRESS, reg);
	if (!err)
		err = tg3_readphy(tp, MII_TG3_DSP_RW_PORT, val);

	return err;
}

static int tg3_phydsp_write(struct tg3 *tp, u32 reg, u32 val)
{
	int err;

	err = tg3_writephy(tp, MII_TG3_DSP_ADDRESS, reg);
	if (!err)
		err = tg3_writephy(tp, MII_TG3_DSP_RW_PORT, val);

	return err;
}

static int tg3_phy_auxctl_read(struct tg3 *tp, int reg, u32 *val)
{
	int err;

	err = tg3_writephy(tp, MII_TG3_AUX_CTRL,
			   (reg << MII_TG3_AUXCTL_MISC_RDSEL_SHIFT) |
			   MII_TG3_AUXCTL_SHDWSEL_MISC);
	if (!err)
		err = tg3_readphy(tp, MII_TG3_AUX_CTRL, val);

	return err;
}

static int tg3_phy_auxctl_write(struct tg3 *tp, int reg, u32 set)
{
	if (reg == MII_TG3_AUXCTL_SHDWSEL_MISC)
		set |= MII_TG3_AUXCTL_MISC_WREN;

	return tg3_writephy(tp, MII_TG3_AUX_CTRL, set | reg);
}

static int tg3_phy_toggle_auxctl_smdsp(struct tg3 *tp, bool enable)
{
	u32 val;
	int err;

	err = tg3_phy_auxctl_read(tp, MII_TG3_AUXCTL_SHDWSEL_AUXCTL, &val);

	if (err)
		return err;
	if (enable)

		val |= MII_TG3_AUXCTL_ACTL_SMDSP_ENA;
	else
		val &= ~MII_TG3_AUXCTL_ACTL_SMDSP_ENA;

	err = tg3_phy_auxctl_write((tp), MII_TG3_AUXCTL_SHDWSEL_AUXCTL,
				   val | MII_TG3_AUXCTL_ACTL_TX_6DB);

	return err;
}

static int tg3_bmcr_reset(struct tg3 *tp)
{
	u32 phy_control;
	int limit, err;

	/* OK, reset it, and poll the BMCR_RESET bit until it
 * clears or we time out.
 */
	phy_control = BMCR_RESET;
	err = tg3_writephy(tp, MII_BMCR, phy_control);
	if (err != 0)
		return -EBUSY;

	limit = 5000;
	while (limit--) {
		err = tg3_readphy(tp, MII_BMCR, &phy_control);
		if (err != 0)
			return -EBUSY;

		if ((phy_control & BMCR_RESET) == 0) {
			udelay(40);
			break;
		}
		udelay(10);
	}
	if (limit < 0)
		return -EBUSY;

	return 0;
}

static int tg3_mdio_read(struct mii_bus *bp, int mii_id, int reg)
{
	struct tg3 *tp = bp->priv;
	u32 val;

	spin_lock_bh(&tp->lock);

	if (tg3_readphy(tp, reg, &val))
		val = -EIO;

	spin_unlock_bh(&tp->lock);

	return val;
}

static int tg3_mdio_write(struct mii_bus *bp, int mii_id, int reg, u16 val)
{
	struct tg3 *tp = bp->priv;
	u32 ret = 0;

	spin_lock_bh(&tp->lock);

	if (tg3_writephy(tp, reg, val))
		ret = -EIO;

	spin_unlock_bh(&tp->lock);

	return ret;
}

static int tg3_mdio_reset(struct mii_bus *bp)
{
	return 0;
}

static void tg3_mdio_config_5785(struct tg3 *tp)
{
	u32 val;
	struct phy_device *phydev;

	phydev = tp->mdio_bus->phy_map[TG3_PHY_MII_ADDR];
	switch (phydev->drv->phy_id & phydev->drv->phy_id_mask) {
	case PHY_ID_BCM50610:
	case PHY_ID_BCM50610M:
		val = MAC_PHYCFG2_50610_LED_MODES;
		break;
	case PHY_ID_BCMAC131:
		val = MAC_PHYCFG2_AC131_LED_MODES;
		break;
	case PHY_ID_RTL8211C:
		val = MAC_PHYCFG2_RTL8211C_LED_MODES;
		break;
	case PHY_ID_RTL8201E:
		val = MAC_PHYCFG2_RTL8201E_LED_MODES;
		break;
	default:
		return;
	}

	if (phydev->interface != PHY_INTERFACE_MODE_RGMII) {
		tw32(MAC_PHYCFG2, val);

		val = tr32(MAC_PHYCFG1);
		val &= ~(MAC_PHYCFG1_RGMII_INT |
			 MAC_PHYCFG1_RXCLK_TO_MASK | MAC_PHYCFG1_TXCLK_TO_MASK);
		val |= MAC_PHYCFG1_RXCLK_TIMEOUT | MAC_PHYCFG1_TXCLK_TIMEOUT;
		tw32(MAC_PHYCFG1, val);

		return;
	}

	if (!tg3_flag(tp, RGMII_INBAND_DISABLE))
		val |= MAC_PHYCFG2_EMODE_MASK_MASK |
		       MAC_PHYCFG2_FMODE_MASK_MASK |
		       MAC_PHYCFG2_GMODE_MASK_MASK |
		       MAC_PHYCFG2_ACT_MASK_MASK   |
		       MAC_PHYCFG2_QUAL_MASK_MASK |
		       MAC_PHYCFG2_INBAND_ENABLE;

	tw32(MAC_PHYCFG2, val);

	val = tr32(MAC_PHYCFG1);
	val &= ~(MAC_PHYCFG1_RXCLK_TO_MASK | MAC_PHYCFG1_TXCLK_TO_MASK |
		 MAC_PHYCFG1_RGMII_EXT_RX_DEC | MAC_PHYCFG1_RGMII_SND_STAT_EN);
	if (!tg3_flag(tp, RGMII_INBAND_DISABLE)) {
		if (tg3_flag(tp, RGMII_EXT_IBND_RX_EN))
			val |= MAC_PHYCFG1_RGMII_EXT_RX_DEC;
		if (tg3_flag(tp, RGMII_EXT_IBND_TX_EN))
			val |= MAC_PHYCFG1_RGMII_SND_STAT_EN;
	}
	val |= MAC_PHYCFG1_RXCLK_TIMEOUT | MAC_PHYCFG1_TXCLK_TIMEOUT |
	       MAC_PHYCFG1_RGMII_INT | MAC_PHYCFG1_TXC_DRV;
	tw32(MAC_PHYCFG1, val);

	val = tr32(MAC_EXT_RGMII_MODE);
	val &= ~(MAC_RGMII_MODE_RX_INT_B |
		 MAC_RGMII_MODE_RX_QUALITY |
		 MAC_RGMII_MODE_RX_ACTIVITY |
		 MAC_RGMII_MODE_RX_ENG_DET |
		 MAC_RGMII_MODE_TX_ENABLE |
		 MAC_RGMII_MODE_TX_LOWPWR |
		 MAC_RGMII_MODE_TX_RESET);
	if (!tg3_flag(tp, RGMII_INBAND_DISABLE)) {
		if (tg3_flag(tp, RGMII_EXT_IBND_RX_EN))
			val |= MAC_RGMII_MODE_RX_INT_B |
			       MAC_RGMII_MODE_RX_QUALITY |
			       MAC_RGMII_MODE_RX_ACTIVITY |
			       MAC_RGMII_MODE_RX_ENG_DET;
		if (tg3_flag(tp, RGMII_EXT_IBND_TX_EN))
			val |= MAC_RGMII_MODE_TX_ENABLE |
			       MAC_RGMII_MODE_TX_LOWPWR |
			       MAC_RGMII_MODE_TX_RESET;
	}
	tw32(MAC_EXT_RGMII_MODE, val);
}

static void tg3_mdio_start(struct tg3 *tp)
{
	tp->mi_mode &= ~MAC_MI_MODE_AUTO_POLL;
	tw32_f(MAC_MI_MODE, tp->mi_mode);
	udelay(80);

	if (tg3_flag(tp, MDIOBUS_INITED) &&
	    tg3_asic_rev(tp) == ASIC_REV_5785)
		tg3_mdio_config_5785(tp);
}

static int tg3_mdio_init(struct tg3 *tp)
{
	int i;
	u32 reg;
	struct phy_device *phydev;

	if (tg3_flag(tp, 5717_PLUS)) {
		u32 is_serdes;

		tp->phy_addr = tp->pci_fn + 1;

		if (tg3_chip_rev_id(tp) != CHIPREV_ID_5717_A0)
			is_serdes = tr32(SG_DIG_STATUS) & SG_DIG_IS_SERDES;
		else
			is_serdes = tr32(TG3_CPMU_PHY_STRAP) &
				    TG3_CPMU_PHY_STRAP_IS_SERDES;
		if (is_serdes)
			tp->phy_addr += 7;
	} else
		tp->phy_addr = TG3_PHY_MII_ADDR;

	tg3_mdio_start(tp);

	if (!tg3_flag(tp, USE_PHYLIB) || tg3_flag(tp, MDIOBUS_INITED))
		return 0;

	tp->mdio_bus = mdiobus_alloc();
	if (tp->mdio_bus == NULL)
		return -ENOMEM;

	tp->mdio_bus->name     = "tg3 mdio bus";
	snprintf(tp->mdio_bus->id, MII_BUS_ID_SIZE, "%x",
		 (tp->pdev->bus->number << 8) | tp->pdev->devfn);
	tp->mdio_bus->priv     = tp;
	tp->mdio_bus->parent   = &tp->pdev->dev;
	tp->mdio_bus->read     = &tg3_mdio_read;
	tp->mdio_bus->write    = &tg3_mdio_write;
	tp->mdio_bus->reset    = &tg3_mdio_reset;
	tp->mdio_bus->phy_mask = ~(1 << TG3_PHY_MII_ADDR);
	tp->mdio_bus->irq      = &tp->mdio_irq[0];

	for (i = 0; i < PHY_MAX_ADDR; i++)
		tp->mdio_bus->irq[i] = PHY_POLL;

	/* The bus registration will look for all the PHYs on the mdio bus.
 * Unfortunately, it does not ensure the PHY is powered up before
 * accessing the PHY ID registers. A chip reset is the
 * quickest way to bring the device back to an operational state..
 */
	if (tg3_readphy(tp, MII_BMCR, &reg) || (reg & BMCR_PDOWN))
		tg3_bmcr_reset(tp);

	i = mdiobus_register(tp->mdio_bus);
	if (i) {
		dev_warn(&tp->pdev->dev, "mdiobus_reg failed (0x%x)\n", i);
		mdiobus_free(tp->mdio_bus);
		return i;
	}

	phydev = tp->mdio_bus->phy_map[TG3_PHY_MII_ADDR];

	if (!phydev || !phydev->drv) {
		dev_warn(&tp->pdev->dev, "No PHY devices\n");
		mdiobus_unregister(tp->mdio_bus);
		mdiobus_free(tp->mdio_bus);
		return -ENODEV;
	}

	switch (phydev->drv->phy_id & phydev->drv->phy_id_mask) {
	case PHY_ID_BCM57780:
		phydev->interface = PHY_INTERFACE_MODE_GMII;
		phydev->dev_flags |= PHY_BRCM_AUTO_PWRDWN_ENABLE;
		break;
	case PHY_ID_BCM50610:
	case PHY_ID_BCM50610M:
		phydev->dev_flags |= PHY_BRCM_CLEAR_RGMII_MODE |
				     PHY_BRCM_RX_REFCLK_UNUSED |
				     PHY_BRCM_DIS_TXCRXC_NOENRGY |
				     PHY_BRCM_AUTO_PWRDWN_ENABLE;
		if (tg3_flag(tp, RGMII_INBAND_DISABLE))
			phydev->dev_flags |= PHY_BRCM_STD_IBND_DISABLE;
		if (tg3_flag(tp, RGMII_EXT_IBND_RX_EN))
			phydev->dev_flags |= PHY_BRCM_EXT_IBND_RX_ENABLE;
		if (tg3_flag(tp, RGMII_EXT_IBND_TX_EN))
			phydev->dev_flags |= PHY_BRCM_EXT_IBND_TX_ENABLE;
		/* fallthru */
	case PHY_ID_RTL8211C:
		phydev->interface = PHY_INTERFACE_MODE_RGMII;
		break;
	case PHY_ID_RTL8201E:
	case PHY_ID_BCMAC131:
		phydev->interface = PHY_INTERFACE_MODE_MII;
		phydev->dev_flags |= PHY_BRCM_AUTO_PWRDWN_ENABLE;
		tp->phy_flags |= TG3_PHYFLG_IS_FET;
		break;
	}

	tg3_flag_set(tp, MDIOBUS_INITED);

	if (tg3_asic_rev(tp) == ASIC_REV_5785)
		tg3_mdio_config_5785(tp);

	return 0;
}

static void tg3_mdio_fini(struct tg3 *tp)
{
	if (tg3_flag(tp, MDIOBUS_INITED)) {
		tg3_flag_clear(tp, MDIOBUS_INITED);
		mdiobus_unregister(tp->mdio_bus);
		mdiobus_free(tp->mdio_bus);
	}
}

/* tp->lock is held. */
static inline void tg3_generate_fw_event(struct tg3 *tp)
{
	u32 val;

	val = tr32(GRC_RX_CPU_EVENT);
	val |= GRC_RX_CPU_DRIVER_EVENT;
	tw32_f(GRC_RX_CPU_EVENT, val);

	tp->last_event_jiffies = jiffies;
}

#define TG3_FW_EVENT_TIMEOUT_USEC 2500

/* tp->lock is held. */
static void tg3_wait_for_event_ack(struct tg3 *tp)
{
	int i;
	unsigned int delay_cnt;
	long time_remain;

	/* If enough time has passed, no wait is necessary. */
	time_remain = (long)(tp->last_event_jiffies + 1 +
		      usecs_to_jiffies(TG3_FW_EVENT_TIMEOUT_USEC)) -
		      (long)jiffies;
	if (time_remain < 0)
		return;

	/* Check if we can shorten the wait time. */
	delay_cnt = jiffies_to_usecs(time_remain);
	if (delay_cnt > TG3_FW_EVENT_TIMEOUT_USEC)
		delay_cnt = TG3_FW_EVENT_TIMEOUT_USEC;
	delay_cnt = (delay_cnt >> 3) + 1;

	for (i = 0; i < delay_cnt; i++) {
		if (!(tr32(GRC_RX_CPU_EVENT) & GRC_RX_CPU_DRIVER_EVENT))
			break;
		udelay(8);
	}
}

/* tp->lock is held. */
static void tg3_phy_gather_ump_data(struct tg3 *tp, u32 *data)
{
	u32 reg, val;

	val = 0;
	if (!tg3_readphy(tp, MII_BMCR, &reg))
		val = reg << 16;
	if (!tg3_readphy(tp, MII_BMSR, &reg))
		val |= (reg & 0xffff);
	*data++ = val;

	val = 0;
	if (!tg3_readphy(tp, MII_ADVERTISE, &reg))
		val = reg << 16;
	if (!tg3_readphy(tp, MII_LPA, &reg))
		val |= (reg & 0xffff);
	*data++ = val;

	val = 0;
	if (!(tp->phy_flags & TG3_PHYFLG_MII_SERDES)) {
		if (!tg3_readphy(tp, MII_CTRL1000, &reg))
			val = reg << 16;
		if (!tg3_readphy(tp, MII_STAT1000, &reg))
			val |= (reg & 0xffff);
	}
	*data++ = val;

	if (!tg3_readphy(tp, MII_PHYADDR, &reg))
		val = reg << 16;
	else
		val = 0;
	*data++ = val;
}

/* tp->lock is held. */
static void tg3_ump_link_report(struct tg3 *tp)
{
	u32 data[4];

	if (!tg3_flag(tp, 5780_CLASS) || !tg3_flag(tp, ENABLE_ASF))
		return;

	tg3_phy_gather_ump_data(tp, data);

	tg3_wait_for_event_ack(tp);

	tg3_write_mem(tp, NIC_SRAM_FW_CMD_MBOX, FWCMD_NICDRV_LINK_UPDATE);
	tg3_write_mem(tp, NIC_SRAM_FW_CMD_LEN_MBOX, 14);
	tg3_write_mem(tp, NIC_SRAM_FW_CMD_DATA_MBOX + 0x0, data[0]);
	tg3_write_mem(tp, NIC_SRAM_FW_CMD_DATA_MBOX + 0x4, data[1]);
	tg3_write_mem(tp, NIC_SRAM_FW_CMD_DATA_MBOX + 0x8, data[2]);
	tg3_write_mem(tp, NIC_SRAM_FW_CMD_DATA_MBOX + 0xc, data[3]);

	tg3_generate_fw_event(tp);
}

/* tp->lock is held. */
static void tg3_stop_fw(struct tg3 *tp)
{
	if (tg3_flag(tp, ENABLE_ASF) && !tg3_flag(tp, ENABLE_APE)) {
		/* Wait for RX cpu to ACK the previous event. */
		tg3_wait_for_event_ack(tp);

		tg3_write_mem(tp, NIC_SRAM_FW_CMD_MBOX, FWCMD_NICDRV_PAUSE_FW);

		tg3_generate_fw_event(tp);

		/* Wait for RX cpu to ACK this event. */
		tg3_wait_for_event_ack(tp);
	}
}

/* tp->lock is held. */
static void tg3_write_sig_pre_reset(struct tg3 *tp, int kind)
{
	tg3_write_mem(tp, NIC_SRAM_FIRMWARE_MBOX,
		      NIC_SRAM_FIRMWARE_MBOX_MAGIC1);

	if (tg3_flag(tp, ASF_NEW_HANDSHAKE)) {
		switch (kind) {
		case RESET_KIND_INIT:
			tg3_write_mem(tp, NIC_SRAM_FW_DRV_STATE_MBOX,
				      DRV_STATE_START);
			break;

		case RESET_KIND_SHUTDOWN:
			tg3_write_mem(tp, NIC_SRAM_FW_DRV_STATE_MBOX,
				      DRV_STATE_UNLOAD);
			break;

		case RESET_KIND_SUSPEND:
			tg3_write_mem(tp, NIC_SRAM_FW_DRV_STATE_MBOX,
				      DRV_STATE_SUSPEND);
			break;

		default:
			break;
		}
	}

	if (kind == RESET_KIND_INIT ||
	    kind == RESET_KIND_SUSPEND)
		tg3_ape_driver_state_change(tp, kind);
}

/* tp->lock is held. */
static void tg3_write_sig_post_reset(struct tg3 *tp, int kind)
{
	if (tg3_flag(tp, ASF_NEW_HANDSHAKE)) {
		switch (kind) {
		case RESET_KIND_INIT:
			tg3_write_mem(tp, NIC_SRAM_FW_DRV_STATE_MBOX,
				      DRV_STATE_START_DONE);
			break;

		case RESET_KIND_SHUTDOWN:
			tg3_write_mem(tp, NIC_SRAM_FW_DRV_STATE_MBOX,
				      DRV_STATE_UNLOAD_DONE);
			break;

		default:
			break;
		}
	}

	if (kind == RESET_KIND_SHUTDOWN)
		tg3_ape_driver_state_change(tp, kind);
}

/* tp->lock is held. */
static void tg3_write_sig_legacy(struct tg3 *tp, int kind)
{
	if (tg3_flag(tp, ENABLE_ASF)) {
		switch (kind) {
		case RESET_KIND_INIT:
			tg3_write_mem(tp, NIC_SRAM_FW_DRV_STATE_MBOX,
				      DRV_STATE_START);
			break;

		case RESET_KIND_SHUTDOWN:
			tg3_write_mem(tp, NIC_SRAM_FW_DRV_STATE_MBOX,
				      DRV_STATE_UNLOAD);
			break;

		case RESET_KIND_SUSPEND:
			tg3_write_mem(tp, NIC_SRAM_FW_DRV_STATE_MBOX,
				      DRV_STATE_SUSPEND);
			break;

		default:
			break;
		}
	}
}

static int tg3_poll_fw(struct tg3 *tp)
{
	int i;
	u32 val;

	if (tg3_flag(tp, IS_SSB_CORE)) {
		/* We don't use firmware. */
		return 0;
	}

	if (tg3_asic_rev(tp) == ASIC_REV_5906) {
		/* Wait up to 20ms for init done. */
		for (i = 0; i < 200; i++) {
			if (tr32(VCPU_STATUS) & VCPU_STATUS_INIT_DONE)
				return 0;
			udelay(100);
		}
		return -ENODEV;
	}

	/* Wait for firmware initialization to complete. */
	for (i = 0; i < 100000; i++) {
		tg3_read_mem(tp, NIC_SRAM_FIRMWARE_MBOX, &val);
		if (val == ~NIC_SRAM_FIRMWARE_MBOX_MAGIC1)
			break;
		udelay(10);
	}

	/* Chip might not be fitted with firmware. Some Sun onboard
 * parts are configured like that. So don't signal the timeout
 * of the above loop as an error, but do report the lack of
 * running firmware once.
 */
	if (i >= 100000 && !tg3_flag(tp, NO_FWARE_REPORTED)) {
		tg3_flag_set(tp, NO_FWARE_REPORTED);

		netdev_info(tp->dev, "No firmware running\n");
	}

	if (tg3_chip_rev_id(tp) == CHIPREV_ID_57765_A0) {
		/* The 57765 A0 needs a little more
 * time to do some important work.
 */
		mdelay(10);
	}

	return 0;
}

static void tg3_link_report(struct tg3 *tp)
{
	if (!netif_carrier_ok(tp->dev)) {
		netif_info(tp, link, tp->dev, "Link is down\n");
		tg3_ump_link_report(tp);
	} else if (netif_msg_link(tp)) {
		netdev_info(tp->dev, "Link is up at %d Mbps, %s duplex\n",
			    (tp->link_config.active_speed == SPEED_1000 ?
			     1000 :
			     (tp->link_config.active_speed == SPEED_100 ?
			      100 : 10)),
			    (tp->link_config.active_duplex == DUPLEX_FULL ?
			     "full" : "half"));

		netdev_info(tp->dev, "Flow control is %s for TX and %s for RX\n",
			    (tp->link_config.active_flowctrl & FLOW_CTRL_TX) ?
			    "on" : "off",
			    (tp->link_config.active_flowctrl & FLOW_CTRL_RX) ?
			    "on" : "off");

		if (tp->phy_flags & TG3_PHYFLG_EEE_CAP)
			netdev_info(tp->dev, "EEE is %s\n",
				    tp->setlpicnt ? "enabled" : "disabled");

		tg3_ump_link_report(tp);
	}

	tp->link_up = netif_carrier_ok(tp->dev);
}

static u16 tg3_advert_flowctrl_1000X(u8 flow_ctrl)
{
	u16 miireg;

	if ((flow_ctrl & FLOW_CTRL_TX) && (flow_ctrl & FLOW_CTRL_RX))
		miireg = ADVERTISE_1000XPAUSE;
	else if (flow_ctrl & FLOW_CTRL_TX)
		miireg = ADVERTISE_1000XPSE_ASYM;
	else if (flow_ctrl & FLOW_CTRL_RX)
		miireg = ADVERTISE_1000XPAUSE | ADVERTISE_1000XPSE_ASYM;
	else
		miireg = 0;

	return miireg;
}

static u8 tg3_resolve_flowctrl_1000X(u16 lcladv, u16 rmtadv)
{
	u8 cap = 0;

	if (lcladv & rmtadv & ADVERTISE_1000XPAUSE) {
		cap = FLOW_CTRL_TX | FLOW_CTRL_RX;
	} else if (lcladv & rmtadv & ADVERTISE_1000XPSE_ASYM) {
		if (lcladv & ADVERTISE_1000XPAUSE)
			cap = FLOW_CTRL_RX;
		if (rmtadv & ADVERTISE_1000XPAUSE)
			cap = FLOW_CTRL_TX;
	}

	return cap;
}

static void tg3_setup_flow_control(struct tg3 *tp, u32 lcladv, u32 rmtadv)
{
	u8 autoneg;
	u8 flowctrl = 0;
	u32 old_rx_mode = tp->rx_mode;
	u32 old_tx_mode = tp->tx_mode;

	if (tg3_flag(tp, USE_PHYLIB))
		autoneg = tp->mdio_bus->phy_map[TG3_PHY_MII_ADDR]->autoneg;
	else
		autoneg = tp->link_config.autoneg;

	if (autoneg == AUTONEG_ENABLE && tg3_flag(tp, PAUSE_AUTONEG)) {
		if (tp->phy_flags & TG3_PHYFLG_ANY_SERDES)
			flowctrl = tg3_resolve_flowctrl_1000X(lcladv, rmtadv);
		else
			flowctrl = mii_resolve_flowctrl_fdx(lcladv, rmtadv);
	} else
		flowctrl = tp->link_config.flowctrl;

	tp->link_config.active_flowctrl = flowctrl;

	if (flowctrl & FLOW_CTRL_RX)
		tp->rx_mode |= RX_MODE_FLOW_CTRL_ENABLE;
	else
		tp->rx_mode &= ~RX_MODE_FLOW_CTRL_ENABLE;

	if (old_rx_mode != tp->rx_mode)
		tw32_f(MAC_RX_MODE, tp->rx_mode);

	if (flowctrl & FLOW_CTRL_TX)
		tp->tx_mode |= TX_MODE_FLOW_CTRL_ENABLE;
	else
		tp->tx_mode &= ~TX_MODE_FLOW_CTRL_ENABLE;

	if (old_tx_mode != tp->tx_mode)
		tw32_f(MAC_TX_MODE, tp->tx_mode);
}

static void tg3_adjust_link(struct net_device *dev)
{
	u8 oldflowctrl, linkmesg = 0;
	u32 mac_mode, lcl_adv, rmt_adv;
	struct tg3 *tp = netdev_priv(dev);
	struct phy_device *phydev = tp->mdio_bus->phy_map[TG3_PHY_MII_ADDR];

	spin_lock_bh(&tp->lock);

	mac_mode = tp->mac_mode & ~(MAC_MODE_PORT_MODE_MASK |
				    MAC_MODE_HALF_DUPLEX);

	oldflowctrl = tp->link_config.active_flowctrl;

	if (phydev->link) {
		lcl_adv = 0;
		rmt_adv = 0;

		if (phydev->speed == SPEED_100 || phydev->speed == SPEED_10)
			mac_mode |= MAC_MODE_PORT_MODE_MII;
		else if (phydev->speed == SPEED_1000 ||
			 tg3_asic_rev(tp) != ASIC_REV_5785)
			mac_mode |= MAC_MODE_PORT_MODE_GMII;
		else
			mac_mode |= MAC_MODE_PORT_MODE_MII;

		if (phydev->duplex == DUPLEX_HALF)
			mac_mode |= MAC_MODE_HALF_DUPLEX;
		else {
			lcl_adv = mii_advertise_flowctrl(
				  tp->link_config.flowctrl);

			if (phydev->pause)
				rmt_adv = LPA_PAUSE_CAP;
			if (phydev->asym_pause)
				rmt_adv |= LPA_PAUSE_ASYM;
		}

		tg3_setup_flow_control(tp, lcl_adv, rmt_adv);
	} else
		mac_mode |= MAC_MODE_PORT_MODE_GMII;

	if (mac_mode != tp->mac_mode) {
		tp->mac_mode = mac_mode;
		tw32_f(MAC_MODE, tp->mac_mode);
		udelay(40);
	}

	if (tg3_asic_rev(tp) == ASIC_REV_5785) {
		if (phydev->speed == SPEED_10)
			tw32(MAC_MI_STAT,
			     MAC_MI_STAT_10MBPS_MODE |
			     MAC_MI_STAT_LNKSTAT_ATTN_ENAB);
		else
			tw32(MAC_MI_STAT, MAC_MI_STAT_LNKSTAT_ATTN_ENAB);
	}

	if (phydev->speed == SPEED_1000 && phydev->duplex == DUPLEX_HALF)
		tw32(MAC_TX_LENGTHS,
		     ((2 << TX_LENGTHS_IPG_CRS_SHIFT) |
		      (6 << TX_LENGTHS_IPG_SHIFT) |
		      (0xff << TX_LENGTHS_SLOT_TIME_SHIFT)));
	else
		tw32(MAC_TX_LENGTHS,
		     ((2 << TX_LENGTHS_IPG_CRS_SHIFT) |
		      (6 << TX_LENGTHS_IPG_SHIFT) |
		      (32 << TX_LENGTHS_SLOT_TIME_SHIFT)));

	if (phydev->link != tp->old_link ||
	    phydev->speed != tp->link_config.active_speed ||
	    phydev->duplex != tp->link_config.active_duplex ||
	    oldflowctrl != tp->link_config.active_flowctrl)
		linkmesg = 1;

	tp->old_link = phydev->link;
	tp->link_config.active_speed = phydev->speed;
	tp->link_config.active_duplex = phydev->duplex;

	spin_unlock_bh(&tp->lock);

	if (linkmesg)
		tg3_link_report(tp);
}

static int tg3_phy_init(struct tg3 *tp)
{
	struct phy_device *phydev;

	if (tp->phy_flags & TG3_PHYFLG_IS_CONNECTED)
		return 0;

	/* Bring the PHY back to a known state. */
	tg3_bmcr_reset(tp);

	phydev = tp->mdio_bus->phy_map[TG3_PHY_MII_ADDR];

	/* Attach the MAC to the PHY. */
	phydev = phy_connect(tp->dev, dev_name(&phydev->dev),
			     tg3_adjust_link, phydev->interface);
	if (IS_ERR(phydev)) {
		dev_err(&tp->pdev->dev, "Could not attach to PHY\n");
		return PTR_ERR(phydev);
	}

	/* Mask with MAC supported features. */
	switch (phydev->interface) {
	case PHY_INTERFACE_MODE_GMII:
	case PHY_INTERFACE_MODE_RGMII:
		if (!(tp->phy_flags & TG3_PHYFLG_10_100_ONLY)) {
			phydev->supported &= (PHY_GBIT_FEATURES |
					      SUPPORTED_Pause |
					      SUPPORTED_Asym_Pause);
			break;
		}
		/* fallthru */
	case PHY_INTERFACE_MODE_MII:
		phydev->supported &= (PHY_BASIC_FEATURES |
				      SUPPORTED_Pause |
				      SUPPORTED_Asym_Pause);
		break;
	default:
		phy_disconnect(tp->mdio_bus->phy_map[TG3_PHY_MII_ADDR]);
		return -EINVAL;
	}

	tp->phy_flags |= TG3_PHYFLG_IS_CONNECTED;

	phydev->advertising = phydev->supported;

	return 0;
}

static void tg3_phy_start(struct tg3 *tp)
{
	struct phy_device *phydev;

	if (!(tp->phy_flags & TG3_PHYFLG_IS_CONNECTED))
		return;

	phydev = tp->mdio_bus->phy_map[TG3_PHY_MII_ADDR];

	if (tp->phy_flags & TG3_PHYFLG_IS_LOW_POWER) {
		tp->phy_flags &= ~TG3_PHYFLG_IS_LOW_POWER;
		phydev->speed = tp->link_config.speed;
		phydev->duplex = tp->link_config.duplex;
		phydev->autoneg = tp->link_config.autoneg;
		phydev->advertising = tp->link_config.advertising;
	}

	phy_start(phydev);

	phy_start_aneg(phydev);
}

static void tg3_phy_stop(struct tg3 *tp)
{
	if (!(tp->phy_flags & TG3_PHYFLG_IS_CONNECTED))
		return;

	phy_stop(tp->mdio_bus->phy_map[TG3_PHY_MII_ADDR]);
}

static void tg3_phy_fini(struct tg3 *tp)
{
	if (tp->phy_flags & TG3_PHYFLG_IS_CONNECTED) {
		phy_disconnect(tp->mdio_bus->phy_map[TG3_PHY_MII_ADDR]);
		tp->phy_flags &= ~TG3_PHYFLG_IS_CONNECTED;
	}
}

static int tg3_phy_set_extloopbk(struct tg3 *tp)
{
	int err;
	u32 val;

	if (tp->phy_flags & TG3_PHYFLG_IS_FET)
		return 0;

	if ((tp->phy_id & TG3_PHY_ID_MASK) == TG3_PHY_ID_BCM5401) {
		/* Cannot do read-modify-write on 5401 */
		err = tg3_phy_auxctl_write(tp,
					   MII_TG3_AUXCTL_SHDWSEL_AUXCTL,
					   MII_TG3_AUXCTL_ACTL_EXTLOOPBK |
					   0x4c20);
		goto done;
	}

	err = tg3_phy_auxctl_read(tp,
				  MII_TG3_AUXCTL_SHDWSEL_AUXCTL, &val);
	if (err)
		return err;

	val |= MII_TG3_AUXCTL_ACTL_EXTLOOPBK;
	err = tg3_phy_auxctl_write(tp,
				   MII_TG3_AUXCTL_SHDWSEL_AUXCTL, val);

done:
	return err;
}

static void tg3_phy_fet_toggle_apd(struct tg3 *tp, bool enable)
{
	u32 phytest;

	if (!tg3_readphy(tp, MII_TG3_FET_TEST, &phytest)) {
		u32 phy;

		tg3_writephy(tp, MII_TG3_FET_TEST,
			     phytest | MII_TG3_FET_SHADOW_EN);
		if (!tg3_readphy(tp, MII_TG3_FET_SHDW_AUXSTAT2, &phy)) {
			if (enable)
				phy |= MII_TG3_FET_SHDW_AUXSTAT2_APD;
			else
				phy &= ~MII_TG3_FET_SHDW_AUXSTAT2_APD;
			tg3_writephy(tp, MII_TG3_FET_SHDW_AUXSTAT2, phy);
		}
		tg3_writephy(tp, MII_TG3_FET_TEST, phytest);
	}
}

static void tg3_phy_toggle_apd(struct tg3 *tp, bool enable)
{
	u32 reg;

	if (!tg3_flag(tp, 5705_PLUS) ||
	    (tg3_flag(tp, 5717_PLUS) &&
	     (tp->phy_flags & TG3_PHYFLG_MII_SERDES)))
		return;

	if (tp->phy_flags & TG3_PHYFLG_IS_FET) {
		tg3_phy_fet_toggle_apd(tp, enable);
		return;
	}

	reg = MII_TG3_MISC_SHDW_WREN |
	      MII_TG3_MISC_SHDW_SCR5_SEL |
	      MII_TG3_MISC_SHDW_SCR5_LPED |
	      MII_TG3_MISC_SHDW_SCR5_DLPTLM |
	      MII_TG3_MISC_SHDW_SCR5_SDTL |
	      MII_TG3_MISC_SHDW_SCR5_C125OE;
	if (tg3_asic_rev(tp) != ASIC_REV_5784 || !enable)
		reg |= MII_TG3_MISC_SHDW_SCR5_DLLAPD;

	tg3_writephy(tp, MII_TG3_MISC_SHDW, reg);


	reg = MII_TG3_MISC_SHDW_WREN |
	      MII_TG3_MISC_SHDW_APD_SEL |
	      MII_TG3_MISC_SHDW_APD_WKTM_84MS;
	if (enable)
		reg |= MII_TG3_MISC_SHDW_APD_ENABLE;

	tg3_writephy(tp, MII_TG3_MISC_SHDW, reg);
}

static void tg3_phy_toggle_automdix(struct tg3 *tp, int enable)
{
	u32 phy;

	if (!tg3_flag(tp, 5705_PLUS) ||
	    (tp->phy_flags & TG3_PHYFLG_ANY_SERDES))
		return;

	if (tp->phy_flags & TG3_PHYFLG_IS_FET) {
		u32 ephy;

		if (!tg3_readphy(tp, MII_TG3_FET_TEST, &ephy)) {
			u32 reg = MII_TG3_FET_SHDW_MISCCTRL;

			tg3_writephy(tp, MII_TG3_FET_TEST,
				     ephy | MII_TG3_FET_SHADOW_EN);
			if (!tg3_readphy(tp, reg, &phy)) {
				if (enable)
					phy |= MII_TG3_FET_SHDW_MISCCTRL_MDIX;
				else
					phy &= ~MII_TG3_FET_SHDW_MISCCTRL_MDIX;
				tg3_writephy(tp, reg, phy);
			}
			tg3_writephy(tp, MII_TG3_FET_TEST, ephy);
		}
	} else {
		int ret;

		ret = tg3_phy_auxctl_read(tp,
					  MII_TG3_AUXCTL_SHDWSEL_MISC, &phy);
		if (!ret) {
			if (enable)
				phy |= MII_TG3_AUXCTL_MISC_FORCE_AMDIX;
			else
				phy &= ~MII_TG3_AUXCTL_MISC_FORCE_AMDIX;
			tg3_phy_auxctl_write(tp,
					     MII_TG3_AUXCTL_SHDWSEL_MISC, phy);
		}
	}
}

static void tg3_phy_set_wirespeed(struct tg3 *tp)
{
	int ret;
	u32 val;

	if (tp->phy_flags & TG3_PHYFLG_NO_ETH_WIRE_SPEED)
		return;

	ret = tg3_phy_auxctl_read(tp, MII_TG3_AUXCTL_SHDWSEL_MISC, &val);
	if (!ret)
		tg3_phy_auxctl_write(tp, MII_TG3_AUXCTL_SHDWSEL_MISC,
				     val | MII_TG3_AUXCTL_MISC_WIRESPD_EN);
}

static void tg3_phy_apply_otp(struct tg3 *tp)
{
	u32 otp, phy;

	if (!tp->phy_otp)
		return;

	otp = tp->phy_otp;

	if (tg3_phy_toggle_auxctl_smdsp(tp, true))
		return;

	phy = ((otp & TG3_OTP_AGCTGT_MASK) >> TG3_OTP_AGCTGT_SHIFT);
	phy |= MII_TG3_DSP_TAP1_AGCTGT_DFLT;
	tg3_phydsp_write(tp, MII_TG3_DSP_TAP1, phy);

	phy = ((otp & TG3_OTP_HPFFLTR_MASK) >> TG3_OTP_HPFFLTR_SHIFT) |
	      ((otp & TG3_OTP_HPFOVER_MASK) >> TG3_OTP_HPFOVER_SHIFT);
	tg3_phydsp_write(tp, MII_TG3_DSP_AADJ1CH0, phy);

	phy = ((otp & TG3_OTP_LPFDIS_MASK) >> TG3_OTP_LPFDIS_SHIFT);
	phy |= MII_TG3_DSP_AADJ1CH3_ADCCKADJ;
	tg3_phydsp_write(tp, MII_TG3_DSP_AADJ1CH3, phy);

	phy = ((otp & TG3_OTP_VDAC_MASK) >> TG3_OTP_VDAC_SHIFT);
	tg3_phydsp_write(tp, MII_TG3_DSP_EXP75, phy);

	phy = ((otp & TG3_OTP_10BTAMP_MASK) >> TG3_OTP_10BTAMP_SHIFT);
	tg3_phydsp_write(tp, MII_TG3_DSP_EXP96, phy);

	phy = ((otp & TG3_OTP_ROFF_MASK) >> TG3_OTP_ROFF_SHIFT) |
	      ((otp & TG3_OTP_RCOFF_MASK) >> TG3_OTP_RCOFF_SHIFT);
	tg3_phydsp_write(tp, MII_TG3_DSP_EXP97, phy);

	tg3_phy_toggle_auxctl_smdsp(tp, false);
}

static void tg3_phy_eee_adjust(struct tg3 *tp, u32 current_link_up)
{
	u32 val;

	if (!(tp->phy_flags & TG3_PHYFLG_EEE_CAP))
		return;

	tp->setlpicnt = 0;

	if (tp->link_config.autoneg == AUTONEG_ENABLE &&
	    current_link_up == 1 &&
	    tp->link_config.active_duplex == DUPLEX_FULL &&
	    (tp->link_config.active_speed == SPEED_100 ||
	     tp->link_config.active_speed == SPEED_1000)) {
		u32 eeectl;

		if (tp->link_config.active_speed == SPEED_1000)
			eeectl = TG3_CPMU_EEE_CTRL_EXIT_16_5_US;
		else
			eeectl = TG3_CPMU_EEE_CTRL_EXIT_36_US;

		tw32(TG3_CPMU_EEE_CTRL, eeectl);

		tg3_phy_cl45_read(tp, MDIO_MMD_AN,
				  TG3_CL45_D7_EEERES_STAT, &val);

		if (val == TG3_CL45_D7_EEERES_STAT_LP_1000T ||
		    val == TG3_CL45_D7_EEERES_STAT_LP_100TX)
			tp->setlpicnt = 2;
	}

	if (!tp->setlpicnt) {
		if (current_link_up == 1 &&
		   !tg3_phy_toggle_auxctl_smdsp(tp, true)) {
			tg3_phydsp_write(tp, MII_TG3_DSP_TAP26, 0x0000);
			tg3_phy_toggle_auxctl_smdsp(tp, false);
		}

		val = tr32(TG3_CPMU_EEE_MODE);
		tw32(TG3_CPMU_EEE_MODE, val & ~TG3_CPMU_EEEMD_LPI_ENABLE);
	}
}

static void tg3_phy_eee_enable(struct tg3 *tp)
{
	u32 val;

	if (tp->link_config.active_speed == SPEED_1000 &&
	    (tg3_asic_rev(tp) == ASIC_REV_5717 ||
	     tg3_asic_rev(tp) == ASIC_REV_5719 ||
	     tg3_flag(tp, 57765_CLASS)) &&
	    !tg3_phy_toggle_auxctl_smdsp(tp, true)) {
		val = MII_TG3_DSP_TAP26_ALNOKO |
		      MII_TG3_DSP_TAP26_RMRXSTO;
		tg3_phydsp_write(tp, MII_TG3_DSP_TAP26, val);
		tg3_phy_toggle_auxctl_smdsp(tp, false);
	}

	val = tr32(TG3_CPMU_EEE_MODE);
	tw32(TG3_CPMU_EEE_MODE, val | TG3_CPMU_EEEMD_LPI_ENABLE);
}

static int tg3_wait_macro_done(struct tg3 *tp)
{
	int limit = 100;

	while (limit--) {
		u32 tmp32;

		if (!tg3_readphy(tp, MII_TG3_DSP_CONTROL, &tmp32)) {
			if ((tmp32 & 0x1000) == 0)
				break;
		}
	}
	if (limit < 0)
		return -EBUSY;

	return 0;
}

static int tg3_phy_write_and_check_testpat(struct tg3 *tp, int *resetp)
{
	static const u32 test_pat[4][6] = {
	{ 0x00005555, 0x00000005, 0x00002aaa, 0x0000000a, 0x00003456, 0x00000003 },
	{ 0x00002aaa, 0x0000000a, 0x00003333, 0x00000003, 0x0000789a, 0x00000005 },
	{ 0x00005a5a, 0x00000005, 0x00002a6a, 0x0000000a, 0x00001bcd, 0x00000003 },
	{ 0x00002a5a, 0x0000000a, 0x000033c3, 0x00000003, 0x00002ef1, 0x00000005 }
	};
	int chan;

	for (chan = 0; chan < 4; chan++) {
		int i;

		tg3_writephy(tp, MII_TG3_DSP_ADDRESS,
			     (chan * 0x2000) | 0x0200);
		tg3_writephy(tp, MII_TG3_DSP_CONTROL, 0x0002);

		for (i = 0; i < 6; i++)
			tg3_writephy(tp, MII_TG3_DSP_RW_PORT,
				     test_pat[chan][i]);

		tg3_writephy(tp, MII_TG3_DSP_CONTROL, 0x0202);
		if (tg3_wait_macro_done(tp)) {
			*resetp = 1;
			return -EBUSY;
		}

		tg3_writephy(tp, MII_TG3_DSP_ADDRESS,
			     (chan * 0x2000) | 0x0200);
		tg3_writephy(tp, MII_TG3_DSP_CONTROL, 0x0082);
		if (tg3_wait_macro_done(tp)) {
			*resetp = 1;
			return -EBUSY;
		}

		tg3_writephy(tp, MII_TG3_DSP_CONTROL, 0x0802);
		if (tg3_wait_macro_done(tp)) {
			*resetp = 1;
			return -EBUSY;
		}

		for (i = 0; i < 6; i += 2) {
			u32 low, high;

			if (tg3_readphy(tp, MII_TG3_DSP_RW_PORT, &low) ||
			    tg3_readphy(tp, MII_TG3_DSP_RW_PORT, &high) ||
			    tg3_wait_macro_done(tp)) {
				*resetp = 1;
				return -EBUSY;
			}
			low &= 0x7fff;
			high &= 0x000f;
			if (low != test_pat[chan][i] ||
			    high != test_pat[chan][i+1]) {
				tg3_writephy(tp, MII_TG3_DSP_ADDRESS, 0x000b);
				tg3_writephy(tp, MII_TG3_DSP_RW_PORT, 0x4001);
				tg3_writephy(tp, MII_TG3_DSP_RW_PORT, 0x4005);

				return -EBUSY;
			}
		}
	}

	return 0;
}

static int tg3_phy_reset_chanpat(struct tg3 *tp)
{
	int chan;

	for (chan = 0; chan < 4; chan++) {
		int i;

		tg3_writephy(tp, MII_TG3_DSP_ADDRESS,
			     (chan * 0x2000) | 0x0200);
		tg3_writephy(tp, MII_TG3_DSP_CONTROL, 0x0002);
		for (i = 0; i < 6; i++)
			tg3_writephy(tp, MII_TG3_DSP_RW_PORT, 0x000);
		tg3_writephy(tp, MII_TG3_DSP_CONTROL, 0x0202);
		if (tg3_wait_macro_done(tp))
			return -EBUSY;
	}

	return 0;
}

static int tg3_phy_reset_5703_4_5(struct tg3 *tp)
{
	u32 reg32, phy9_orig;
	int retries, do_phy_reset, err;

	retries = 10;
	do_phy_reset = 1;
	do {
		if (do_phy_reset) {
			err = tg3_bmcr_reset(tp);
			if (err)
				return err;
			do_phy_reset = 0;
		}

		/* Disable transmitter and interrupt. */
		if (tg3_readphy(tp, MII_TG3_EXT_CTRL, &reg32))
			continue;

		reg32 |= 0x3000;
		tg3_writephy(tp, MII_TG3_EXT_CTRL, reg32);

		/* Set full-duplex, 1000 mbps. */
		tg3_writephy(tp, MII_BMCR,
			     BMCR_FULLDPLX | BMCR_SPEED1000);

		/* Set to master mode. */
		if (tg3_readphy(tp, MII_CTRL1000, &phy9_orig))
			continue;

		tg3_writephy(tp, MII_CTRL1000,
			     CTL1000_AS_MASTER | CTL1000_ENABLE_MASTER);

		err = tg3_phy_toggle_auxctl_smdsp(tp, true);
		if (err)
			return err;

		/* Block the PHY control access. */
		tg3_phydsp_write(tp, 0x8005, 0x0800);

		err = tg3_phy_write_and_check_testpat(tp, &do_phy_reset);
		if (!err)
			break;
	} while (--retries);

	err = tg3_phy_reset_chanpat(tp);
	if (err)
		return err;

	tg3_phydsp_write(tp, 0x8005, 0x0000);

	tg3_writephy(tp, MII_TG3_DSP_ADDRESS, 0x8200);
	tg3_writephy(tp, MII_TG3_DSP_CONTROL, 0x0000);

	tg3_phy_toggle_auxctl_smdsp(tp, false);

	tg3_writephy(tp, MII_CTRL1000, phy9_orig);

	if (!tg3_readphy(tp, MII_TG3_EXT_CTRL, &reg32)) {
		reg32 &= ~0x3000;
		tg3_writephy(tp, MII_TG3_EXT_CTRL, reg32);
	} else if (!err)
		err = -EBUSY;

	return err;
}

static void tg3_carrier_off(struct tg3 *tp)
{
	netif_carrier_off(tp->dev);
	tp->link_up = false;
}

/* This will reset the tigon3 PHY if there is no valid
 * link unless the FORCE argument is non-zero.
 */
static int tg3_phy_reset(struct tg3 *tp)
{
	u32 val, cpmuctrl;
	int err;

	if (tg3_asic_rev(tp) == ASIC_REV_5906) {
		val = tr32(GRC_MISC_CFG);
		tw32_f(GRC_MISC_CFG, val & ~GRC_MISC_CFG_EPHY_IDDQ);
		udelay(40);
	}
	err  = tg3_readphy(tp, MII_BMSR, &val);
	err |= tg3_readphy(tp, MII_BMSR, &val);
	if (err != 0)
		return -EBUSY;

	if (netif_running(tp->dev) && tp->link_up) {
		netif_carrier_off(tp->dev);
		tg3_link_report(tp);
	}

	if (tg3_asic_rev(tp) == ASIC_REV_5703 ||
	    tg3_asic_rev(tp) == ASIC_REV_5704 ||
	    tg3_asic_rev(tp) == ASIC_REV_5705) {
		err = tg3_phy_reset_5703_4_5(tp);
		if (err)
			return err;
		goto out;
	}

	cpmuctrl = 0;
	if (tg3_asic_rev(tp) == ASIC_REV_5784 &&
	    tg3_chip_rev(tp) != CHIPREV_5784_AX) {
		cpmuctrl = tr32(TG3_CPMU_CTRL);
		if (cpmuctrl & CPMU_CTRL_GPHY_10MB_RXONLY)
			tw32(TG3_CPMU_CTRL,
			     cpmuctrl & ~CPMU_CTRL_GPHY_10MB_RXONLY);
	}

	err = tg3_bmcr_reset(tp);
	if (err)
		return err;

	if (cpmuctrl & CPMU_CTRL_GPHY_10MB_RXONLY) {
		val = MII_TG3_DSP_EXP8_AEDW | MII_TG3_DSP_EXP8_REJ2MHz;
		tg3_phydsp_write(tp, MII_TG3_DSP_EXP8, val);

		tw32(TG3_CPMU_CTRL, cpmuctrl);
	}

	if (tg3_chip_rev(tp) == CHIPREV_5784_AX ||
	    tg3_chip_rev(tp) == CHIPREV_5761_AX) {
		val = tr32(TG3_CPMU_LSPD_1000MB_CLK);
		if ((val & CPMU_LSPD_1000MB_MACCLK_MASK) ==
		    CPMU_LSPD_1000MB_MACCLK_12_5) {
			val &= ~CPMU_LSPD_1000MB_MACCLK_MASK;
			udelay(40);
			tw32_f(TG3_CPMU_LSPD_1000MB_CLK, val);
		}
	}

	if (tg3_flag(tp, 5717_PLUS) &&
	    (tp->phy_flags & TG3_PHYFLG_MII_SERDES))
		return 0;

	tg3_phy_apply_otp(tp);

	if (tp->phy_flags & TG3_PHYFLG_ENABLE_APD)
		tg3_phy_toggle_apd(tp, true);
	else
		tg3_phy_toggle_apd(tp, false);

out:
	if ((tp->phy_flags & TG3_PHYFLG_ADC_BUG) &&
	    !tg3_phy_toggle_auxctl_smdsp(tp, true)) {
		tg3_phydsp_write(tp, 0x201f, 0x2aaa);
		tg3_phydsp_write(tp, 0x000a, 0x0323);
		tg3_phy_toggle_auxctl_smdsp(tp, false);
	}

	if (tp->phy_flags & TG3_PHYFLG_5704_A0_BUG) {
		tg3_writephy(tp, MII_TG3_MISC_SHDW, 0x8d68);
		tg3_writephy(tp, MII_TG3_MISC_SHDW, 0x8d68);
	}

	if (tp->phy_flags & TG3_PHYFLG_BER_BUG) {
		if (!tg3_phy_toggle_auxctl_smdsp(tp, true)) {
			tg3_phydsp_write(tp, 0x000a, 0x310b);
			tg3_phydsp_write(tp, 0x201f, 0x9506);
			tg3_phydsp_write(tp, 0x401f, 0x14e2);
			tg3_phy_toggle_auxctl_smdsp(tp, false);
		}
	} else if (tp->phy_flags & TG3_PHYFLG_JITTER_BUG) {
		if (!tg3_phy_toggle_auxctl_smdsp(tp, true)) {
			tg3_writephy(tp, MII_TG3_DSP_ADDRESS, 0x000a);
			if (tp->phy_flags & TG3_PHYFLG_ADJUST_TRIM) {
				tg3_writephy(tp, MII_TG3_DSP_RW_PORT, 0x110b);
				tg3_writephy(tp, MII_TG3_TEST1,
					     MII_TG3_TEST1_TRIM_EN | 0x4);
			} else
				tg3_writephy(tp, MII_TG3_DSP_RW_PORT, 0x010b);

			tg3_phy_toggle_auxctl_smdsp(tp, false);
		}
	}

	/* Set Extended packet length bit (bit 14) on all chips that */
	/* support jumbo frames */
	if ((tp->phy_id & TG3_PHY_ID_MASK) == TG3_PHY_ID_BCM5401) {
		/* Cannot do read-modify-write on 5401 */
		tg3_phy_auxctl_write(tp, MII_TG3_AUXCTL_SHDWSEL_AUXCTL, 0x4c20);
	} else if (tg3_flag(tp, JUMBO_CAPABLE)) {
		/* Set bit 14 with read-modify-write to preserve other bits */
		err = tg3_phy_auxctl_read(tp,
					  MII_TG3_AUXCTL_SHDWSEL_AUXCTL, &val);
		if (!err)
			tg3_phy_auxctl_write(tp, MII_TG3_AUXCTL_SHDWSEL_AUXCTL,
					   val | MII_TG3_AUXCTL_ACTL_EXTPKTLEN);
	}

	/* Set phy register 0x10 bit 0 to high fifo elasticity to support
 * jumbo frames transmission.
 */
	if (tg3_flag(tp, JUMBO_CAPABLE)) {
		if (!tg3_readphy(tp, MII_TG3_EXT_CTRL, &val))
			tg3_writephy(tp, MII_TG3_EXT_CTRL,
				     val | MII_TG3_EXT_CTRL_FIFO_ELASTIC);
	}

	if (tg3_asic_rev(tp) == ASIC_REV_5906) {
		/* adjust output voltage */
		tg3_writephy(tp, MII_TG3_FET_PTEST, 0x12);
	}

	if (tg3_chip_rev_id(tp) == CHIPREV_ID_5762_A0)
		tg3_phydsp_write(tp, 0xffb, 0x4000);

	tg3_phy_toggle_automdix(tp, 1);
	tg3_phy_set_wirespeed(tp);
	return 0;
}

#define TG3_GPIO_MSG_DRVR_PRES 0x00000001
#define TG3_GPIO_MSG_NEED_VAUX 0x00000002
#define TG3_GPIO_MSG_MASK (TG3_GPIO_MSG_DRVR_PRES | \
 TG3_GPIO_MSG_NEED_VAUX)
#define TG3_GPIO_MSG_ALL_DRVR_PRES_MASK \
 ((TG3_GPIO_MSG_DRVR_PRES << 0) | \
 (TG3_GPIO_MSG_DRVR_PRES << 4) | \
 (TG3_GPIO_MSG_DRVR_PRES << 8) | \
 (TG3_GPIO_MSG_DRVR_PRES << 12))

#define TG3_GPIO_MSG_ALL_NEED_VAUX_MASK \
 ((TG3_GPIO_MSG_NEED_VAUX << 0) | \
 (TG3_GPIO_MSG_NEED_VAUX << 4) | \
 (TG3_GPIO_MSG_NEED_VAUX << 8) | \
 (TG3_GPIO_MSG_NEED_VAUX << 12))

static inline u32 tg3_set_function_status(struct tg3 *tp, u32 newstat)
{
	u32 status, shift;

	if (tg3_asic_rev(tp) == ASIC_REV_5717 ||
	    tg3_asic_rev(tp) == ASIC_REV_5719)
		status = tg3_ape_read32(tp, TG3_APE_GPIO_MSG);
	else
		status = tr32(TG3_CPMU_DRV_STATUS);

	shift = TG3_APE_GPIO_MSG_SHIFT + 4 * tp->pci_fn;
	status &= ~(TG3_GPIO_MSG_MASK << shift);
	status |= (newstat << shift);

	if (tg3_asic_rev(tp) == ASIC_REV_5717 ||
	    tg3_asic_rev(tp) == ASIC_REV_5719)
		tg3_ape_write32(tp, TG3_APE_GPIO_MSG, status);
	else
		tw32(TG3_CPMU_DRV_STATUS, status);

	return status >> TG3_APE_GPIO_MSG_SHIFT;
}

static inline int tg3_pwrsrc_switch_to_vmain(struct tg3 *tp)
{
	if (!tg3_flag(tp, IS_NIC))
		return 0;

	if (tg3_asic_rev(tp) == ASIC_REV_5717 ||
	    tg3_asic_rev(tp) == ASIC_REV_5719 ||
	    tg3_asic_rev(tp) == ASIC_REV_5720) {
		if (tg3_ape_lock(tp, TG3_APE_LOCK_GPIO))
			return -EIO;

		tg3_set_function_status(tp, TG3_GPIO_MSG_DRVR_PRES);

		tw32_wait_f(GRC_LOCAL_CTRL, tp->grc_local_ctrl,
			    TG3_GRC_LCLCTL_PWRSW_DELAY);

		tg3_ape_unlock(tp, TG3_APE_LOCK_GPIO);
	} else {
		tw32_wait_f(GRC_LOCAL_CTRL, tp->grc_local_ctrl,
			    TG3_GRC_LCLCTL_PWRSW_DELAY);
	}

	return 0;
}

static void tg3_pwrsrc_die_with_vmain(struct tg3 *tp)
{
	u32 grc_local_ctrl;

	if (!tg3_flag(tp, IS_NIC) ||
	    tg3_asic_rev(tp) == ASIC_REV_5700 ||
	    tg3_asic_rev(tp) == ASIC_REV_5701)
		return;

	grc_local_ctrl = tp->grc_local_ctrl | GRC_LCLCTRL_GPIO_OE1;

	tw32_wait_f(GRC_LOCAL_CTRL,
		    grc_local_ctrl | GRC_LCLCTRL_GPIO_OUTPUT1,
		    TG3_GRC_LCLCTL_PWRSW_DELAY);

	tw32_wait_f(GRC_LOCAL_CTRL,
		    grc_local_ctrl,
		    TG3_GRC_LCLCTL_PWRSW_DELAY);

	tw32_wait_f(GRC_LOCAL_CTRL,
		    grc_local_ctrl | GRC_LCLCTRL_GPIO_OUTPUT1,
		    TG3_GRC_LCLCTL_PWRSW_DELAY);
}

static void tg3_pwrsrc_switch_to_vaux(struct tg3 *tp)
{
	if (!tg3_flag(tp, IS_NIC))
		return;

	if (tg3_asic_rev(tp) == ASIC_REV_5700 ||
	    tg3_asic_rev(tp) == ASIC_REV_5701) {
		tw32_wait_f(GRC_LOCAL_CTRL, tp->grc_local_ctrl |
			    (GRC_LCLCTRL_GPIO_OE0 |
			     GRC_LCLCTRL_GPIO_OE1 |
			     GRC_LCLCTRL_GPIO_OE2 |
			     GRC_LCLCTRL_GPIO_OUTPUT0 |
			     GRC_LCLCTRL_GPIO_OUTPUT1),
			    TG3_GRC_LCLCTL_PWRSW_DELAY);
	} else if (tp->pdev->device == PCI_DEVICE_ID_TIGON3_5761 ||
		   tp->pdev->device == TG3PCI_DEVICE_TIGON3_5761S) {
		/* The 5761 non-e device swaps GPIO 0 and GPIO 2. */
		u32 grc_local_ctrl = GRC_LCLCTRL_GPIO_OE0 |
				     GRC_LCLCTRL_GPIO_OE1 |
				     GRC_LCLCTRL_GPIO_OE2 |
				     GRC_LCLCTRL_GPIO_OUTPUT0 |
				     GRC_LCLCTRL_GPIO_OUTPUT1 |
				     tp->grc_local_ctrl;
		tw32_wait_f(GRC_LOCAL_CTRL, grc_local_ctrl,
			    TG3_GRC_LCLCTL_PWRSW_DELAY);

		grc_local_ctrl |= GRC_LCLCTRL_GPIO_OUTPUT2;
		tw32_wait_f(GRC_LOCAL_CTRL, grc_local_ctrl,
			    TG3_GRC_LCLCTL_PWRSW_DELAY);

		grc_local_ctrl &= ~GRC_LCLCTRL_GPIO_OUTPUT0;
		tw32_wait_f(GRC_LOCAL_CTRL, grc_local_ctrl,
			    TG3_GRC_LCLCTL_PWRSW_DELAY);
	} else {
		u32 no_gpio2;
		u32 grc_local_ctrl = 0;

		/* Workaround to prevent overdrawing Amps. */
		if (tg3_asic_rev(tp) == ASIC_REV_5714) {
			grc_local_ctrl |= GRC_LCLCTRL_GPIO_OE3;
			tw32_wait_f(GRC_LOCAL_CTRL, tp->grc_local_ctrl |
				    grc_local_ctrl,
				    TG3_GRC_LCLCTL_PWRSW_DELAY);
		}

		/* On 5753 and variants, GPIO2 cannot be used. */
		no_gpio2 = tp->nic_sram_data_cfg &
			   NIC_SRAM_DATA_CFG_NO_GPIO2;

		grc_local_ctrl |= GRC_LCLCTRL_GPIO_OE0 |
				  GRC_LCLCTRL_GPIO_OE1 |
				  GRC_LCLCTRL_GPIO_OE2 |
				  GRC_LCLCTRL_GPIO_OUTPUT1 |
				  GRC_LCLCTRL_GPIO_OUTPUT2;
		if (no_gpio2) {
			grc_local_ctrl &= ~(GRC_LCLCTRL_GPIO_OE2 |
					    GRC_LCLCTRL_GPIO_OUTPUT2);
		}
		tw32_wait_f(GRC_LOCAL_CTRL,
			    tp->grc_local_ctrl | grc_local_ctrl,
			    TG3_GRC_LCLCTL_PWRSW_DELAY);

		grc_local_ctrl |= GRC_LCLCTRL_GPIO_OUTPUT0;

		tw32_wait_f(GRC_LOCAL_CTRL,
			    tp->grc_local_ctrl | grc_local_ctrl,
			    TG3_GRC_LCLCTL_PWRSW_DELAY);

		if (!no_gpio2) {
			grc_local_ctrl &= ~GRC_LCLCTRL_GPIO_OUTPUT2;
			tw32_wait_f(GRC_LOCAL_CTRL,
				    tp->grc_local_ctrl | grc_local_ctrl,
				    TG3_GRC_LCLCTL_PWRSW_DELAY);
		}
	}
}

static void tg3_frob_aux_power_5717(struct tg3 *tp, bool wol_enable)
{
	u32 msg = 0;

	/* Serialize power state transitions */
	if (tg3_ape_lock(tp, TG3_APE_LOCK_GPIO))
		return;

	if (tg3_flag(tp, ENABLE_ASF) || tg3_flag(tp, ENABLE_APE) || wol_enable)
		msg = TG3_GPIO_MSG_NEED_VAUX;

	msg = tg3_set_function_status(tp, msg);

	if (msg & TG3_GPIO_MSG_ALL_DRVR_PRES_MASK)
		goto done;

	if (msg & TG3_GPIO_MSG_ALL_NEED_VAUX_MASK)
		tg3_pwrsrc_switch_to_vaux(tp);
	else
		tg3_pwrsrc_die_with_vmain(tp);

done:
	tg3_ape_unlock(tp, TG3_APE_LOCK_GPIO);
}

static void tg3_frob_aux_power(struct tg3 *tp, bool include_wol)
{
	bool need_vaux = false;

	/* The GPIOs do something completely different on 57765. */
	if (!tg3_flag(tp, IS_NIC) || tg3_flag(tp, 57765_CLASS))
		return;

	if (tg3_asic_rev(tp) == ASIC_REV_5717 ||
	    tg3_asic_rev(tp) == ASIC_REV_5719 ||
	    tg3_asic_rev(tp) == ASIC_REV_5720) {
		tg3_frob_aux_power_5717(tp, include_wol ?
					tg3_flag(tp, WOL_ENABLE) != 0 : 0);
		return;
	}

	if (tp->pdev_peer && tp->pdev_peer != tp->pdev) {
		struct net_device *dev_peer;

		dev_peer = pci_get_drvdata(tp->pdev_peer);

		/* remove_one() may have been run on the peer. */
		if (dev_peer) {
			struct tg3 *tp_peer = netdev_priv(dev_peer);

			if (tg3_flag(tp_peer, INIT_COMPLETE))
				return;

			if ((include_wol && tg3_flag(tp_peer, WOL_ENABLE)) ||
			    tg3_flag(tp_peer, ENABLE_ASF))
				need_vaux = true;
		}
	}

	if ((include_wol && tg3_flag(tp, WOL_ENABLE)) ||
	    tg3_flag(tp, ENABLE_ASF))
		need_vaux = true;

	if (need_vaux)
		tg3_pwrsrc_switch_to_vaux(tp);
	else
		tg3_pwrsrc_die_with_vmain(tp);
}

static int tg3_5700_link_polarity(struct tg3 *tp, u32 speed)
{
	if (tp->led_ctrl == LED_CTRL_MODE_PHY_2)
		return 1;
	else if ((tp->phy_id & TG3_PHY_ID_MASK) == TG3_PHY_ID_BCM5411) {
		if (speed != SPEED_10)
			return 1;
	} else if (speed == SPEED_10)
		return 1;

	return 0;
}

static void tg3_power_down_phy(struct tg3 *tp, bool do_low_power)
{
	u32 val;

	if (tp->phy_flags & TG3_PHYFLG_PHY_SERDES) {
		if (tg3_asic_rev(tp) == ASIC_REV_5704) {
			u32 sg_dig_ctrl = tr32(SG_DIG_CTRL);
			u32 serdes_cfg = tr32(MAC_SERDES_CFG);

			sg_dig_ctrl |=
				SG_DIG_USING_HW_AUTONEG | SG_DIG_SOFT_RESET;
			tw32(SG_DIG_CTRL, sg_dig_ctrl);
			tw32(MAC_SERDES_CFG, serdes_cfg | (1 << 15));
		}
		return;
	}

	if (tg3_asic_rev(tp) == ASIC_REV_5906) {
		tg3_bmcr_reset(tp);
		val = tr32(GRC_MISC_CFG);
		tw32_f(GRC_MISC_CFG, val | GRC_MISC_CFG_EPHY_IDDQ);
		udelay(40);
		return;
	} else if (tp->phy_flags & TG3_PHYFLG_IS_FET) {
		u32 phytest;
		if (!tg3_readphy(tp, MII_TG3_FET_TEST, &phytest)) {
			u32 phy;

			tg3_writephy(tp, MII_ADVERTISE, 0);
			tg3_writephy(tp, MII_BMCR,
				     BMCR_ANENABLE | BMCR_ANRESTART);

			tg3_writephy(tp, MII_TG3_FET_TEST,
				     phytest | MII_TG3_FET_SHADOW_EN);
			if (!tg3_readphy(tp, MII_TG3_FET_SHDW_AUXMODE4, &phy)) {
				phy |= MII_TG3_FET_SHDW_AUXMODE4_SBPD;
				tg3_writephy(tp,
					     MII_TG3_FET_SHDW_AUXMODE4,
					     phy);
			}
			tg3_writephy(tp, MII_TG3_FET_TEST, phytest);
		}
		return;
	} else if (do_low_power) {
		tg3_writephy(tp, MII_TG3_EXT_CTRL,
			     MII_TG3_EXT_CTRL_FORCE_LED_OFF);

		val = MII_TG3_AUXCTL_PCTL_100TX_LPWR |
		      MII_TG3_AUXCTL_PCTL_SPR_ISOLATE |
		      MII_TG3_AUXCTL_PCTL_VREG_11V;
		tg3_phy_auxctl_write(tp, MII_TG3_AUXCTL_SHDWSEL_PWRCTL, val);
	}

	/* The PHY should not be powered down on some chips because
 * of bugs.
 */
	if (tg3_asic_rev(tp) == ASIC_REV_5700 ||
	    tg3_asic_rev(tp) == ASIC_REV_5704 ||
	    (tg3_asic_rev(tp) == ASIC_REV_5780 &&
	     (tp->phy_flags & TG3_PHYFLG_MII_SERDES)) ||
	    (tg3_asic_rev(tp) == ASIC_REV_5717 &&
	     !tp->pci_fn))
		return;

	if (tg3_chip_rev(tp) == CHIPREV_5784_AX ||
	    tg3_chip_rev(tp) == CHIPREV_5761_AX) {
		val = tr32(TG3_CPMU_LSPD_1000MB_CLK);
		val &= ~CPMU_LSPD_1000MB_MACCLK_MASK;
		val |= CPMU_LSPD_1000MB_MACCLK_12_5;
		tw32_f(TG3_CPMU_LSPD_1000MB_CLK, val);
	}

	tg3_writephy(tp, MII_BMCR, BMCR_PDOWN);
}

/* tp->lock is held. */
static int tg3_nvram_lock(struct tg3 *tp)
{
	if (tg3_flag(tp, NVRAM)) {
		int i;

		if (tp->nvram_lock_cnt == 0) {
			tw32(NVRAM_SWARB, SWARB_REQ_SET1);
			for (i = 0; i < 8000; i++) {
				if (tr32(NVRAM_SWARB) & SWARB_GNT1)
					break;
				udelay(20);
			}
			if (i == 8000) {
				tw32(NVRAM_SWARB, SWARB_REQ_CLR1);
				return -ENODEV;
			}
		}
		tp->nvram_lock_cnt++;
	}
	return 0;
}

/* tp->lock is held. */
static void tg3_nvram_unlock(struct tg3 *tp)
{
	if (tg3_flag(tp, NVRAM)) {
		if (tp->nvram_lock_cnt > 0)
			tp->nvram_lock_cnt--;
		if (tp->nvram_lock_cnt == 0)
			tw32_f(NVRAM_SWARB, SWARB_REQ_CLR1);
	}
}

/* tp->lock is held. */
static void tg3_enable_nvram_access(struct tg3 *tp)
{
	if (tg3_flag(tp, 5750_PLUS) && !tg3_flag(tp, PROTECTED_NVRAM)) {
		u32 nvaccess = tr32(NVRAM_ACCESS);

		tw32(NVRAM_ACCESS, nvaccess | ACCESS_ENABLE);
	}
}

/* tp->lock is held. */
static void tg3_disable_nvram_access(struct tg3 *tp)
{
	if (tg3_flag(tp, 5750_PLUS) && !tg3_flag(tp, PROTECTED_NVRAM)) {
		u32 nvaccess = tr32(NVRAM_ACCESS);

		tw32(NVRAM_ACCESS, nvaccess & ~ACCESS_ENABLE);
	}
}

static int tg3_nvram_read_using_eeprom(struct tg3 *tp,
					u32 offset, u32 *val)
{
	u32 tmp;
	int i;

	if (offset > EEPROM_ADDR_ADDR_MASK || (offset % 4) != 0)
		return -EINVAL;

	tmp = tr32(GRC_EEPROM_ADDR) & ~(EEPROM_ADDR_ADDR_MASK |
					EEPROM_ADDR_DEVID_MASK |
					EEPROM_ADDR_READ);
	tw32(GRC_EEPROM_ADDR,
	     tmp |
	     (0 << EEPROM_ADDR_DEVID_SHIFT) |
	     ((offset << EEPROM_ADDR_ADDR_SHIFT) &
	      EEPROM_ADDR_ADDR_MASK) |
	     EEPROM_ADDR_READ | EEPROM_ADDR_START);

	for (i = 0; i < 1000; i++) {
		tmp = tr32(GRC_EEPROM_ADDR);

		if (tmp & EEPROM_ADDR_COMPLETE)
			break;
		msleep(1);
	}
	if (!(tmp & EEPROM_ADDR_COMPLETE))
		return -EBUSY;

	tmp = tr32(GRC_EEPROM_DATA);

	/*
 * The data will always be opposite the native endian
 * format. Perform a blind byteswap to compensate.
 */
	*val = swab32(tmp);

	return 0;
}

#define NVRAM_CMD_TIMEOUT 10000

static int tg3_nvram_exec_cmd(struct tg3 *tp, u32 nvram_cmd)
{
	int i;

	tw32(NVRAM_CMD, nvram_cmd);
	for (i = 0; i < NVRAM_CMD_TIMEOUT; i++) {
		udelay(10);
		if (tr32(NVRAM_CMD) & NVRAM_CMD_DONE) {
			udelay(10);
			break;
		}
	}

	if (i == NVRAM_CMD_TIMEOUT)
		return -EBUSY;

	return 0;
}

static u32 tg3_nvram_phys_addr(struct tg3 *tp, u32 addr)
{
	if (tg3_flag(tp, NVRAM) &&
	    tg3_flag(tp, NVRAM_BUFFERED) &&
	    tg3_flag(tp, FLASH) &&
	    !tg3_flag(tp, NO_NVRAM_ADDR_TRANS) &&
	    (tp->nvram_jedecnum == JEDEC_ATMEL))

		addr = ((addr / tp->nvram_pagesize) <<
			ATMEL_AT45DB0X1B_PAGE_POS) +
		       (addr % tp->nvram_pagesize);

	return addr;
}

static u32 tg3_nvram_logical_addr(struct tg3 *tp, u32 addr)
{
	if (tg3_flag(tp, NVRAM) &&
	    tg3_flag(tp, NVRAM_BUFFERED) &&
	    tg3_flag(tp, FLASH) &&
	    !tg3_flag(tp, NO_NVRAM_ADDR_TRANS) &&
	    (tp->nvram_jedecnum == JEDEC_ATMEL))

		addr = ((addr >> ATMEL_AT45DB0X1B_PAGE_POS) *
			tp->nvram_pagesize) +
		       (addr & ((1 << ATMEL_AT45DB0X1B_PAGE_POS) - 1));

	return addr;
}

/* NOTE: Data read in from NVRAM is byteswapped according to
 * the byteswapping settings for all other register accesses.
 * tg3 devices are BE devices, so on a BE machine, the data
 * returned will be exactly as it is seen in NVRAM. On a LE
 * machine, the 32-bit value will be byteswapped.
 */
static int tg3_nvram_read(struct tg3 *tp, u32 offset, u32 *val)
{
	int ret;

	if (!tg3_flag(tp, NVRAM))
		return tg3_nvram_read_using_eeprom(tp, offset, val);

	offset = tg3_nvram_phys_addr(tp, offset);

	if (offset > NVRAM_ADDR_MSK)
		return -EINVAL;

	ret = tg3_nvram_lock(tp);
	if (ret)
		return ret;

	tg3_enable_nvram_access(tp);

	tw32(NVRAM_ADDR, offset);
	ret = tg3_nvram_exec_cmd(tp, NVRAM_CMD_RD | NVRAM_CMD_GO |
		NVRAM_CMD_FIRST | NVRAM_CMD_LAST | NVRAM_CMD_DONE);

	if (ret == 0)
		*val = tr32(NVRAM_RDDATA);

	tg3_disable_nvram_access(tp);

	tg3_nvram_unlock(tp);

	return ret;
}

/* Ensures NVRAM data is in bytestream format. */
static int tg3_nvram_read_be32(struct tg3 *tp, u32 offset, __be32 *val)
{
	u32 v;
	int res = tg3_nvram_read(tp, offset, &v);
	if (!res)
		*val = cpu_to_be32(v);
	return res;
}

static int tg3_nvram_write_block_using_eeprom(struct tg3 *tp,
				    u32 offset, u32 len, u8 *buf)
{
	int i, j, rc = 0;
	u32 val;

	for (i = 0; i < len; i += 4) {
		u32 addr;
		__be32 data;

		addr = offset + i;

		memcpy(&data, buf + i, 4);

		/*
 * The SEEPROM interface expects the data to always be opposite
 * the native endian format. We accomplish this by reversing
 * all the operations that would have been performed on the
 * data from a call to tg3_nvram_read_be32().
 */
		tw32(GRC_EEPROM_DATA, swab32(be32_to_cpu(data)));

		val = tr32(GRC_EEPROM_ADDR);
		tw32(GRC_EEPROM_ADDR, val | EEPROM_ADDR_COMPLETE);

		val &= ~(EEPROM_ADDR_ADDR_MASK | EEPROM_ADDR_DEVID_MASK |
			EEPROM_ADDR_READ);
		tw32(GRC_EEPROM_ADDR, val |
			(0 << EEPROM_ADDR_DEVID_SHIFT) |
			(addr & EEPROM_ADDR_ADDR_MASK) |
			EEPROM_ADDR_START |
			EEPROM_ADDR_WRITE);

		for (j = 0; j < 1000; j++) {
			val = tr32(GRC_EEPROM_ADDR);

			if (val & EEPROM_ADDR_COMPLETE)
				break;
			msleep(1);
		}
		if (!(val & EEPROM_ADDR_COMPLETE)) {
			rc = -EBUSY;
			break;
		}
	}

	return rc;
}

/* offset and length are dword aligned */
static int tg3_nvram_write_block_unbuffered(struct tg3 *tp, u32 offset, u32 len,
		u8 *buf)
{
	int ret = 0;
	u32 pagesize = tp->nvram_pagesize;
	u32 pagemask = pagesize - 1;
	u32 nvram_cmd;
	u8 *tmp;

	tmp = kmalloc(pagesize, GFP_KERNEL);
	if (tmp == NULL)
		return -ENOMEM;

	while (len) {
		int j;
		u32 phy_addr, page_off, size;

		phy_addr = offset & ~pagemask;

		for (j = 0; j < pagesize; j += 4) {
			ret = tg3_nvram_read_be32(tp, phy_addr + j,
						  (__be32 *) (tmp + j));
			if (ret)
				break;
		}
		if (ret)
			break;

		page_off = offset & pagemask;
		size = pagesize;
		if (len < size)
			size = len;

		len -= size;

		memcpy(tmp + page_off, buf, size);

		offset = offset + (pagesize - page_off);

		tg3_enable_nvram_access(tp);

		/*
 * Before we can erase the flash page, we need
 * to issue a special "write enable" command.
 */
		nvram_cmd = NVRAM_CMD_WREN | NVRAM_CMD_GO | NVRAM_CMD_DONE;

		if (tg3_nvram_exec_cmd(tp, nvram_cmd))
			break;

		/* Erase the target page */
		tw32(NVRAM_ADDR, phy_addr);

		nvram_cmd = NVRAM_CMD_GO | NVRAM_CMD_DONE | NVRAM_CMD_WR |
			NVRAM_CMD_FIRST | NVRAM_CMD_LAST | NVRAM_CMD_ERASE;

		if (tg3_nvram_exec_cmd(tp, nvram_cmd))
			break;

		/* Issue another write enable to start the write. */
		nvram_cmd = NVRAM_CMD_WREN | NVRAM_CMD_GO | NVRAM_CMD_DONE;

		if (tg3_nvram_exec_cmd(tp, nvram_cmd))
			break;

		for (j = 0; j < pagesize; j += 4) {
			__be32 data;

			data = *((__be32 *) (tmp + j));

			tw32(NVRAM_WRDATA, be32_to_cpu(data));

			tw32(NVRAM_ADDR, phy_addr + j);

			nvram_cmd = NVRAM_CMD_GO | NVRAM_CMD_DONE |
				NVRAM_CMD_WR;

			if (j == 0)
				nvram_cmd |= NVRAM_CMD_FIRST;
			else if (j == (pagesize - 4))
				nvram_cmd |= NVRAM_CMD_LAST;

			ret = tg3_nvram_exec_cmd(tp, nvram_cmd);
			if (ret)
				break;
		}
		if (ret)
			break;
	}

	nvram_cmd = NVRAM_CMD_WRDI | NVRAM_CMD_GO | NVRAM_CMD_DONE;
	tg3_nvram_exec_cmd(tp, nvram_cmd);

	kfree(tmp);

	return ret;
}

/* offset and length are dword aligned */
static int tg3_nvram_write_block_buffered(struct tg3 *tp, u32 offset, u32 len,
		u8 *buf)
{
	int i, ret = 0;

	for (i = 0; i < len; i += 4, offset += 4) {
		u32 page_off, phy_addr, nvram_cmd;
		__be32 data;

		memcpy(&data, buf + i, 4);
		tw32(NVRAM_WRDATA, be32_to_cpu(data));

		page_off = offset % tp->nvram_pagesize;

		phy_addr = tg3_nvram_phys_addr(tp, offset);

		nvram_cmd = NVRAM_CMD_GO | NVRAM_CMD_DONE | NVRAM_CMD_WR;

		if (page_off == 0 || i == 0)
			nvram_cmd |= NVRAM_CMD_FIRST;
		if (page_off == (tp->nvram_pagesize - 4))
			nvram_cmd |= NVRAM_CMD_LAST;

		if (i == (len - 4))
			nvram_cmd |= NVRAM_CMD_LAST;

		if ((nvram_cmd & NVRAM_CMD_FIRST) ||
		    !tg3_flag(tp, FLASH) ||
		    !tg3_flag(tp, 57765_PLUS))
			tw32(NVRAM_ADDR, phy_addr);

		if (tg3_asic_rev(tp) != ASIC_REV_5752 &&
		    !tg3_flag(tp, 5755_PLUS) &&
		    (tp->nvram_jedecnum == JEDEC_ST) &&
		    (nvram_cmd & NVRAM_CMD_FIRST)) {
			u32 cmd;

			cmd = NVRAM_CMD_WREN | NVRAM_CMD_GO | NVRAM_CMD_DONE;
			ret = tg3_nvram_exec_cmd(tp, cmd);
			if (ret)
				break;
		}
		if (!tg3_flag(tp, FLASH)) {
			/* We always do complete word writes to eeprom. */
			nvram_cmd |= (NVRAM_CMD_FIRST | NVRAM_CMD_LAST);
		}

		ret = tg3_nvram_exec_cmd(tp, nvram_cmd);
		if (ret)
			break;
	}
	return ret;
}

/* offset and length are dword aligned */
static int tg3_nvram_write_block(struct tg3 *tp, u32 offset, u32 len, u8 *buf)
{
	int ret;

	if (tg3_flag(tp, EEPROM_WRITE_PROT)) {
		tw32_f(GRC_LOCAL_CTRL, tp->grc_local_ctrl &
		       ~GRC_LCLCTRL_GPIO_OUTPUT1);
		udelay(40);
	}

	if (!tg3_flag(tp, NVRAM)) {
		ret = tg3_nvram_write_block_using_eeprom(tp, offset, len, buf);
	} else {
		u32 grc_mode;

		ret = tg3_nvram_lock(tp);
		if (ret)
			return ret;

		tg3_enable_nvram_access(tp);
		if (tg3_flag(tp, 5750_PLUS) && !tg3_flag(tp, PROTECTED_NVRAM))
			tw32(NVRAM_WRITE1, 0x406);

		grc_mode = tr32(GRC_MODE);
		tw32(GRC_MODE, grc_mode | GRC_MODE_NVRAM_WR_ENABLE);

		if (tg3_flag(tp, NVRAM_BUFFERED) || !tg3_flag(tp, FLASH)) {
			ret = tg3_nvram_write_block_buffered(tp, offset, len,
				buf);
		} else {
			ret = tg3_nvram_write_block_unbuffered(tp, offset, len,
				buf);
		}

		grc_mode = tr32(GRC_MODE);
		tw32(GRC_MODE, grc_mode & ~GRC_MODE_NVRAM_WR_ENABLE);

		tg3_disable_nvram_access(tp);
		tg3_nvram_unlock(tp);
	}

	if (tg3_flag(tp, EEPROM_WRITE_PROT)) {
		tw32_f(GRC_LOCAL_CTRL, tp->grc_local_ctrl);
		udelay(40);
	}

	return ret;
}

#define RX_CPU_SCRATCH_BASE 0x30000
#define RX_CPU_SCRATCH_SIZE 0x04000
#define TX_CPU_SCRATCH_BASE 0x34000
#define TX_CPU_SCRATCH_SIZE 0x04000

/* tp->lock is held. */
static int tg3_halt_cpu(struct tg3 *tp, u32 offset)
{
	int i;

	BUG_ON(offset == TX_CPU_BASE && tg3_flag(tp, 5705_PLUS));

	if (tg3_asic_rev(tp) == ASIC_REV_5906) {
		u32 val = tr32(GRC_VCPU_EXT_CTRL);

		tw32(GRC_VCPU_EXT_CTRL, val | GRC_VCPU_EXT_CTRL_HALT_CPU);
		return 0;
	}
	if (offset == RX_CPU_BASE) {
		for (i = 0; i < 10000; i++) {
			tw32(offset + CPU_STATE, 0xffffffff);
			tw32(offset + CPU_MODE,  CPU_MODE_HALT);
			if (tr32(offset + CPU_MODE) & CPU_MODE_HALT)
				break;
		}

		tw32(offset + CPU_STATE, 0xffffffff);
		tw32_f(offset + CPU_MODE,  CPU_MODE_HALT);
		udelay(10);
	} else {
		/*
 * There is only an Rx CPU for the 5750 derivative in the
 * BCM4785.
 */
		if (tg3_flag(tp, IS_SSB_CORE))
			return 0;

		for (i = 0; i < 10000; i++) {
			tw32(offset + CPU_STATE, 0xffffffff);
			tw32(offset + CPU_MODE,  CPU_MODE_HALT);
			if (tr32(offset + CPU_MODE) & CPU_MODE_HALT)
				break;
		}
	}

	if (i >= 10000) {
		netdev_err(tp->dev, "%s timed out, %s CPU\n",
			   __func__, offset == RX_CPU_BASE ? "RX" : "TX");
		return -ENODEV;
	}

	/* Clear firmware's nvram arbitration. */
	if (tg3_flag(tp, NVRAM))
		tw32(NVRAM_SWARB, SWARB_REQ_CLR0);
	return 0;
}

struct fw_info {
	unsigned int fw_base;
	unsigned int fw_len;
	const __be32 *fw_data;
};

/* tp->lock is held. */
static int tg3_load_firmware_cpu(struct tg3 *tp, u32 cpu_base,
				 u32 cpu_scratch_base, int cpu_scratch_size,
				 struct fw_info *info)
{
	int err, lock_err, i;
	void (*write_op)(struct tg3 *, u32, u32);

	if (cpu_base == TX_CPU_BASE && tg3_flag(tp, 5705_PLUS)) {
		netdev_err(tp->dev,
			   "%s: Trying to load TX cpu firmware which is 5705\n",
			   __func__);
		return -EINVAL;
	}

	if (tg3_flag(tp, 5705_PLUS))
		write_op = tg3_write_mem;
	else
		write_op = tg3_write_indirect_reg32;

	/* It is possible that bootcode is still loading at this point.
 * Get the nvram lock first before halting the cpu.
 */
	lock_err = tg3_nvram_lock(tp);
	err = tg3_halt_cpu(tp, cpu_base);
	if (!lock_err)
		tg3_nvram_unlock(tp);
	if (err)
		goto out;

	for (i = 0; i < cpu_scratch_size; i += sizeof(u32))
		write_op(tp, cpu_scratch_base + i, 0);
	tw32(cpu_base + CPU_STATE, 0xffffffff);
	tw32(cpu_base + CPU_MODE, tr32(cpu_base+CPU_MODE)|CPU_MODE_HALT);
	for (i = 0; i < (info->fw_len / sizeof(u32)); i++)
		write_op(tp, (cpu_scratch_base +
			      (info->fw_base & 0xffff) +
			      (i * sizeof(u32))),
			      be32_to_cpu(info->fw_data[i]));

	err = 0;

out:
	return err;
}

/* tp->lock is held. */
static int tg3_load_5701_a0_firmware_fix(struct tg3 *tp)
{
	struct fw_info info;
	const __be32 *fw_data;
	int err, i;

	fw_data = (void *)tp->fw->data;

	/* Firmware blob starts with version numbers, followed by
 start address and length. We are setting complete length.
 length = end_address_of_bss - start_address_of_text.
 Remainder is the blob to be loaded contiguously
 from start address. */

	info.fw_base = be32_to_cpu(fw_data[1]);
	info.fw_len = tp->fw->size - 12;
	info.fw_data = &fw_data[3];

	err = tg3_load_firmware_cpu(tp, RX_CPU_BASE,
				    RX_CPU_SCRATCH_BASE, RX_CPU_SCRATCH_SIZE,
				    &info);
	if (err)
		return err;

	err = tg3_load_firmware_cpu(tp, TX_CPU_BASE,
				    TX_CPU_SCRATCH_BASE, TX_CPU_SCRATCH_SIZE,
				    &info);
	if (err)
		return err;

	/* Now startup only the RX cpu. */
	tw32(RX_CPU_BASE + CPU_STATE, 0xffffffff);
	tw32_f(RX_CPU_BASE + CPU_PC, info.fw_base);

	for (i = 0; i < 5; i++) {
		if (tr32(RX_CPU_BASE + CPU_PC) == info.fw_base)
			break;
		tw32(RX_CPU_BASE + CPU_STATE, 0xffffffff);
		tw32(RX_CPU_BASE + CPU_MODE,  CPU_MODE_HALT);
		tw32_f(RX_CPU_BASE + CPU_PC, info.fw_base);
		udelay(1000);
	}
	if (i >= 5) {
		netdev_err(tp->dev, "%s fails to set RX CPU PC, is %08x "
			   "should be %08x\n", __func__,
			   tr32(RX_CPU_BASE + CPU_PC), info.fw_base);
		return -ENODEV;
	}
	tw32(RX_CPU_BASE + CPU_STATE, 0xffffffff);
	tw32_f(RX_CPU_BASE + CPU_MODE,  0x00000000);

	return 0;
}

/* tp->lock is held. */
static int tg3_load_tso_firmware(struct tg3 *tp)
{
	struct fw_info info;
	const __be32 *fw_data;
	unsigned long cpu_base, cpu_scratch_base, cpu_scratch_size;
	int err, i;

	if (tg3_flag(tp, HW_TSO_1) ||
	    tg3_flag(tp, HW_TSO_2) ||
	    tg3_flag(tp, HW_TSO_3))
		return 0;

	fw_data = (void *)tp->fw->data;

	/* Firmware blob starts with version numbers, followed by
 start address and length. We are setting complete length.
 length = end_address_of_bss - start_address_of_text.
 Remainder is the blob to be loaded contiguously
 from start address. */

	info.fw_base = be32_to_cpu(fw_data[1]);
	cpu_scratch_size = tp->fw_len;
	info.fw_len = tp->fw->size - 12;
	info.fw_data = &fw_data[3];

	if (tg3_asic_rev(tp) == ASIC_REV_5705) {
		cpu_base = RX_CPU_BASE;
		cpu_scratch_base = NIC_SRAM_MBUF_POOL_BASE5705;
	} else {
		cpu_base = TX_CPU_BASE;
		cpu_scratch_base = TX_CPU_SCRATCH_BASE;
		cpu_scratch_size = TX_CPU_SCRATCH_SIZE;
	}

	err = tg3_load_firmware_cpu(tp, cpu_base,
				    cpu_scratch_base, cpu_scratch_size,
				    &info);
	if (err)
		return err;

	/* Now startup the cpu. */
	tw32(cpu_base + CPU_STATE, 0xffffffff);
	tw32_f(cpu_base + CPU_PC, info.fw_base);

	for (i = 0; i < 5; i++) {
		if (tr32(cpu_base + CPU_PC) == info.fw_base)
			break;
		tw32(cpu_base + CPU_STATE, 0xffffffff);
		tw32(cpu_base + CPU_MODE,  CPU_MODE_HALT);
		tw32_f(cpu_base + CPU_PC, info.fw_base);
		udelay(1000);
	}
	if (i >= 5) {
		netdev_err(tp->dev,
			   "%s fails to set CPU PC, is %08x should be %08x\n",
			   __func__, tr32(cpu_base + CPU_PC), info.fw_base);
		return -ENODEV;
	}
	tw32(cpu_base + CPU_STATE, 0xffffffff);
	tw32_f(cpu_base + CPU_MODE,  0x00000000);
	return 0;
}


/* tp->lock is held. */
static void __tg3_set_mac_addr(struct tg3 *tp, int skip_mac_1)
{
	u32 addr_high, addr_low;
	int i;

	addr_high = ((tp->dev->dev_addr[0] << 8) |
		     tp->dev->dev_addr[1]);
	addr_low = ((tp->dev->dev_addr[2] << 24) |
		    (tp->dev->dev_addr[3] << 16) |
		    (tp->dev->dev_addr[4] <<  8) |
		    (tp->dev->dev_addr[5] <<  0));
	for (i = 0; i < 4; i++) {
		if (i == 1 && skip_mac_1)
			continue;
		tw32(MAC_ADDR_0_HIGH + (i * 8), addr_high);
		tw32(MAC_ADDR_0_LOW + (i * 8), addr_low);
	}

	if (tg3_asic_rev(tp) == ASIC_REV_5703 ||
	    tg3_asic_rev(tp) == ASIC_REV_5704) {
		for (i = 0; i < 12; i++) {
			tw32(MAC_EXTADDR_0_HIGH + (i * 8), addr_high);
			tw32(MAC_EXTADDR_0_LOW + (i * 8), addr_low);
		}
	}

	addr_high = (tp->dev->dev_addr[0] +
		     tp->dev->dev_addr[1] +
		     tp->dev->dev_addr[2] +
		     tp->dev->dev_addr[3] +
		     tp->dev->dev_addr[4] +
		     tp->dev->dev_addr[5]) &
		TX_BACKOFF_SEED_MASK;
	tw32(MAC_TX_BACKOFF_SEED, addr_high);
}

static void tg3_enable_register_access(struct tg3 *tp)
{
	/*
 * Make sure register accesses (indirect or otherwise) will function
 * correctly.
 */
	pci_write_config_dword(tp->pdev,
			       TG3PCI_MISC_HOST_CTRL, tp->misc_host_ctrl);
}

static int tg3_power_up(struct tg3 *tp)
{
	int err;

	tg3_enable_register_access(tp);

	err = pci_set_power_state(tp->pdev, PCI_D0);
	if (!err) {
		/* Switch out of Vaux if it is a NIC */
		tg3_pwrsrc_switch_to_vmain(tp);
	} else {
		netdev_err(tp->dev, "Transition to D0 failed\n");
	}

	return err;
}

static int tg3_setup_phy(struct tg3 *, int);

static int tg3_power_down_prepare(struct tg3 *tp)
{
	u32 misc_host_ctrl;
	bool device_should_wake, do_low_power;

	tg3_enable_register_access(tp);

	/* Restore the CLKREQ setting. */
	if (tg3_flag(tp, CLKREQ_BUG))
		pcie_capability_set_word(tp->pdev, PCI_EXP_LNKCTL,
					 PCI_EXP_LNKCTL_CLKREQ_EN);

	misc_host_ctrl = tr32(TG3PCI_MISC_HOST_CTRL);
	tw32(TG3PCI_MISC_HOST_CTRL,
	     misc_host_ctrl | MISC_HOST_CTRL_MASK_PCI_INT);

	device_should_wake = device_may_wakeup(&tp->pdev->dev) &&
			     tg3_flag(tp, WOL_ENABLE);

	if (tg3_flag(tp, USE_PHYLIB)) {
		do_low_power = false;
		if ((tp->phy_flags & TG3_PHYFLG_IS_CONNECTED) &&
		    !(tp->phy_flags & TG3_PHYFLG_IS_LOW_POWER)) {
			struct phy_device *phydev;
			u32 phyid, advertising;

			phydev = tp->mdio_bus->phy_map[TG3_PHY_MII_ADDR];

			tp->phy_flags |= TG3_PHYFLG_IS_LOW_POWER;

			tp->link_config.speed = phydev->speed;
			tp->link_config.duplex = phydev->duplex;
			tp->link_config.autoneg = phydev->autoneg;
			tp->link_config.advertising = phydev->advertising;

			advertising = ADVERTISED_TP |
				      ADVERTISED_Pause