

/* niu.c: Neptune ethernet driver.
 *
 * Copyright (C) 2007, 2008 David S. Miller (davem@davemloft.net)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/bitops.h>
#include <linux/mii.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/log2.h>
#include <linux/jiffies.h>
#include <linux/crc32.h>
#include <linux/list.h>
#include <linux/slab.h>

#include <linux/io.h>

#ifdef CONFIG_SPARC64
#include <linux/of_device.h>
#endif

#include "niu.h"

#define DRV_MODULE_NAME		"niu"
#define DRV_MODULE_VERSION	"1.1"
#define DRV_MODULE_RELDATE	"Apr 22, 2010"

static char version[] __devinitdata =
	DRV_MODULE_NAME ".c:v" DRV_MODULE_VERSION " (" DRV_MODULE_RELDATE ")\n";

MODULE_AUTHOR("David S. Miller (davem@davemloft.net)");
MODULE_DESCRIPTION("NIU ethernet driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_MODULE_VERSION);

#ifndef readq
static u64 readq(void __iomem *reg)
{
	return ((u64) readl(reg)) | (((u64) readl(reg + 4UL)) << 32);
}

static void writeq(u64 val, void __iomem *reg)
{
	writel(val & 0xffffffff, reg);
	writel(val >> 32, reg + 0x4UL);
}
#endif

static DEFINE_PCI_DEVICE_TABLE(niu_pci_tbl) = {
	{PCI_DEVICE(PCI_VENDOR_ID_SUN, 0xabcd)},
	{}
};

MODULE_DEVICE_TABLE(pci, niu_pci_tbl);

#define NIU_TX_TIMEOUT (5 * HZ)

#define nr64(reg) readq(np->regs + (reg))
#define nw64(reg, val) writeq((val), np->regs + (reg))

#define nr64_mac(reg) readq(np->mac_regs + (reg))
#define nw64_mac(reg, val) writeq((val), np->mac_regs + (reg))

#define nr64_ipp(reg) readq(np->regs + np->ipp_off + (reg))
#define nw64_ipp(reg, val) writeq((val), np->regs + np->ipp_off + (reg))

#define nr64_pcs(reg) readq(np->regs + np->pcs_off + (reg))
#define nw64_pcs(reg, val) writeq((val), np->regs + np->pcs_off + (reg))

#define nr64_xpcs(reg) readq(np->regs + np->xpcs_off + (reg))
#define nw64_xpcs(reg, val) writeq((val), np->regs + np->xpcs_off + (reg))

#define NIU_MSG_DEFAULT (NETIF_MSG_DRV | NETIF_MSG_PROBE | NETIF_MSG_LINK)

static int niu_debug;
static int debug = -1;
module_param(debug, int, 0);
MODULE_PARM_DESC(debug, "NIU debug level");

#define niu_lock_parent(np, flags) \
 spin_lock_irqsave(&np->parent->lock, flags)
#define niu_unlock_parent(np, flags) \
 spin_unlock_irqrestore(&np->parent->lock, flags)

static int serdes_init_10g_serdes(struct niu *np);

static int __niu_wait_bits_clear_mac(struct niu *np, unsigned long reg,
				     u64 bits, int limit, int delay)
{
	while (--limit >= 0) {
		u64 val = nr64_mac(reg);

		if (!(val & bits))
			break;
		udelay(delay);
	}
	if (limit < 0)
		return -ENODEV;
	return 0;
}

static int __niu_set_and_wait_clear_mac(struct niu *np, unsigned long reg,
					u64 bits, int limit, int delay,
					const char *reg_name)
{
	int err;

	nw64_mac(reg, bits);
	err = __niu_wait_bits_clear_mac(np, reg, bits, limit, delay);
	if (err)
		netdev_err(np->dev, "bits (%llx) of register %s would not clear, val[%llx]\n",
			   (unsigned long long)bits, reg_name,
			   (unsigned long long)nr64_mac(reg));
	return err;
}

#define niu_set_and_wait_clear_mac(NP, REG, BITS, LIMIT, DELAY, REG_NAME) \
({ BUILD_BUG_ON(LIMIT <= 0 || DELAY < 0); \
 __niu_set_and_wait_clear_mac(NP, REG, BITS, LIMIT, DELAY, REG_NAME); \
})

static int __niu_wait_bits_clear_ipp(struct niu *np, unsigned long reg,
				     u64 bits, int limit, int delay)
{
	while (--limit >= 0) {
		u64 val = nr64_ipp(reg);

		if (!(val & bits))
			break;
		udelay(delay);
	}
	if (limit < 0)
		return -ENODEV;
	return 0;
}

static int __niu_set_and_wait_clear_ipp(struct niu *np, unsigned long reg,
					u64 bits, int limit, int delay,
					const char *reg_name)
{
	int err;
	u64 val;

	val = nr64_ipp(reg);
	val |= bits;
	nw64_ipp(reg, val);

	err = __niu_wait_bits_clear_ipp(np, reg, bits, limit, delay);
	if (err)
		netdev_err(np->dev, "bits (%llx) of register %s would not clear, val[%llx]\n",
			   (unsigned long long)bits, reg_name,
			   (unsigned long long)nr64_ipp(reg));
	return err;
}

#define niu_set_and_wait_clear_ipp(NP, REG, BITS, LIMIT, DELAY, REG_NAME) \
({ BUILD_BUG_ON(LIMIT <= 0 || DELAY < 0); \
 __niu_set_and_wait_clear_ipp(NP, REG, BITS, LIMIT, DELAY, REG_NAME); \
})

static int __niu_wait_bits_clear(struct niu *np, unsigned long reg,
				 u64 bits, int limit, int delay)
{
	while (--limit >= 0) {
		u64 val = nr64(reg);

		if (!(val & bits))
			break;
		udelay(delay);
	}
	if (limit < 0)
		return -ENODEV;
	return 0;
}

#define niu_wait_bits_clear(NP, REG, BITS, LIMIT, DELAY) \
({ BUILD_BUG_ON(LIMIT <= 0 || DELAY < 0); \
 __niu_wait_bits_clear(NP, REG, BITS, LIMIT, DELAY); \
})

static int __niu_set_and_wait_clear(struct niu *np, unsigned long reg,
				    u64 bits, int limit, int delay,
				    const char *reg_name)
{
	int err;

	nw64(reg, bits);
	err = __niu_wait_bits_clear(np, reg, bits, limit, delay);
	if (err)
		netdev_err(np->dev, "bits (%llx) of register %s would not clear, val[%llx]\n",
			   (unsigned long long)bits, reg_name,
			   (unsigned long long)nr64(reg));
	return err;
}

#define niu_set_and_wait_clear(NP, REG, BITS, LIMIT, DELAY, REG_NAME) \
({ BUILD_BUG_ON(LIMIT <= 0 || DELAY < 0); \
 __niu_set_and_wait_clear(NP, REG, BITS, LIMIT, DELAY, REG_NAME); \
})

static void niu_ldg_rearm(struct niu *np, struct niu_ldg *lp, int on)
{
	u64 val = (u64) lp->timer;

	if (on)
		val |= LDG_IMGMT_ARM;

	nw64(LDG_IMGMT(lp->ldg_num), val);
}

static int niu_ldn_irq_enable(struct niu *np, int ldn, int on)
{
	unsigned long mask_reg, bits;
	u64 val;

	if (ldn < 0 || ldn > LDN_MAX)
		return -EINVAL;

	if (ldn < 64) {
		mask_reg = LD_IM0(ldn);
		bits = LD_IM0_MASK;
	} else {
		mask_reg = LD_IM1(ldn - 64);
		bits = LD_IM1_MASK;
	}

	val = nr64(mask_reg);
	if (on)
		val &= ~bits;
	else
		val |= bits;
	nw64(mask_reg, val);

	return 0;
}

static int niu_enable_ldn_in_ldg(struct niu *np, struct niu_ldg *lp, int on)
{
	struct niu_parent *parent = np->parent;
	int i;

	for (i = 0; i <= LDN_MAX; i++) {
		int err;

		if (parent->ldg_map[i] != lp->ldg_num)
			continue;

		err = niu_ldn_irq_enable(np, i, on);
		if (err)
			return err;
	}
	return 0;
}

static int niu_enable_interrupts(struct niu *np, int on)
{
	int i;

	for (i = 0; i < np->num_ldg; i++) {
		struct niu_ldg *lp = &np->ldg[i];
		int err;

		err = niu_enable_ldn_in_ldg(np, lp, on);
		if (err)
			return err;
	}
	for (i = 0; i < np->num_ldg; i++)
		niu_ldg_rearm(np, &np->ldg[i], on);

	return 0;
}

static u32 phy_encode(u32 type, int port)
{
	return (type << (port * 2));
}

static u32 phy_decode(u32 val, int port)
{
	return (val >> (port * 2)) & PORT_TYPE_MASK;
}

static int mdio_wait(struct niu *np)
{
	int limit = 1000;
	u64 val;

	while (--limit > 0) {
		val = nr64(MIF_FRAME_OUTPUT);
		if ((val >> MIF_FRAME_OUTPUT_TA_SHIFT) & 0x1)
			return val & MIF_FRAME_OUTPUT_DATA;

		udelay(10);
	}

	return -ENODEV;
}

static int mdio_read(struct niu *np, int port, int dev, int reg)
{
	int err;

	nw64(MIF_FRAME_OUTPUT, MDIO_ADDR_OP(port, dev, reg));
	err = mdio_wait(np);
	if (err < 0)
		return err;

	nw64(MIF_FRAME_OUTPUT, MDIO_READ_OP(port, dev));
	return mdio_wait(np);
}

static int mdio_write(struct niu *np, int port, int dev, int reg, int data)
{
	int err;

	nw64(MIF_FRAME_OUTPUT, MDIO_ADDR_OP(port, dev, reg));
	err = mdio_wait(np);
	if (err < 0)
		return err;

	nw64(MIF_FRAME_OUTPUT, MDIO_WRITE_OP(port, dev, data));
	err = mdio_wait(np);
	if (err < 0)
		return err;

	return 0;
}

static int mii_read(struct niu *np, int port, int reg)
{
	nw64(MIF_FRAME_OUTPUT, MII_READ_OP(port, reg));
	return mdio_wait(np);
}

static int mii_write(struct niu *np, int port, int reg, int data)
{
	int err;

	nw64(MIF_FRAME_OUTPUT, MII_WRITE_OP(port, reg, data));
	err = mdio_wait(np);
	if (err < 0)
		return err;

	return 0;
}

static int esr2_set_tx_cfg(struct niu *np, unsigned long channel, u32 val)
{
	int err;

	err = mdio_write(np, np->port, NIU_ESR2_DEV_ADDR,
			 ESR2_TI_PLL_TX_CFG_L(channel),
			 val & 0xffff);
	if (!err)
		err = mdio_write(np, np->port, NIU_ESR2_DEV_ADDR,
				 ESR2_TI_PLL_TX_CFG_H(channel),
				 val >> 16);
	return err;
}

static int esr2_set_rx_cfg(struct niu *np, unsigned long channel, u32 val)
{
	int err;

	err = mdio_write(np, np->port, NIU_ESR2_DEV_ADDR,
			 ESR2_TI_PLL_RX_CFG_L(channel),
			 val & 0xffff);
	if (!err)
		err = mdio_write(np, np->port, NIU_ESR2_DEV_ADDR,
				 ESR2_TI_PLL_RX_CFG_H(channel),
				 val >> 16);
	return err;
}

/* Mode is always 10G fiber. */
static int serdes_init_niu_10g_fiber(struct niu *np)
{
	struct niu_link_config *lp = &np->link_config;
	u32 tx_cfg, rx_cfg;
	unsigned long i;

	tx_cfg = (PLL_TX_CFG_ENTX | PLL_TX_CFG_SWING_1375MV);
	rx_cfg = (PLL_RX_CFG_ENRX | PLL_RX_CFG_TERM_0P8VDDT |
		  PLL_RX_CFG_ALIGN_ENA | PLL_RX_CFG_LOS_LTHRESH |
		  PLL_RX_CFG_EQ_LP_ADAPTIVE);

	if (lp->loopback_mode == LOOPBACK_PHY) {
		u16 test_cfg = PLL_TEST_CFG_LOOPBACK_CML_DIS;

		mdio_write(np, np->port, NIU_ESR2_DEV_ADDR,
			   ESR2_TI_PLL_TEST_CFG_L, test_cfg);

		tx_cfg |= PLL_TX_CFG_ENTEST;
		rx_cfg |= PLL_RX_CFG_ENTEST;
	}

	/* Initialize all 4 lanes of the SERDES. */
	for (i = 0; i < 4; i++) {
		int err = esr2_set_tx_cfg(np, i, tx_cfg);
		if (err)
			return err;
	}

	for (i = 0; i < 4; i++) {
		int err = esr2_set_rx_cfg(np, i, rx_cfg);
		if (err)
			return err;
	}

	return 0;
}

static int serdes_init_niu_1g_serdes(struct niu *np)
{
	struct niu_link_config *lp = &np->link_config;
	u16 pll_cfg, pll_sts;
	int max_retry = 100;
	u64 uninitialized_var(sig), mask, val;
	u32 tx_cfg, rx_cfg;
	unsigned long i;
	int err;

	tx_cfg = (PLL_TX_CFG_ENTX | PLL_TX_CFG_SWING_1375MV |
		  PLL_TX_CFG_RATE_HALF);
	rx_cfg = (PLL_RX_CFG_ENRX | PLL_RX_CFG_TERM_0P8VDDT |
		  PLL_RX_CFG_ALIGN_ENA | PLL_RX_CFG_LOS_LTHRESH |
		  PLL_RX_CFG_RATE_HALF);

	if (np->port == 0)
		rx_cfg |= PLL_RX_CFG_EQ_LP_ADAPTIVE;

	if (lp->loopback_mode == LOOPBACK_PHY) {
		u16 test_cfg = PLL_TEST_CFG_LOOPBACK_CML_DIS;

		mdio_write(np, np->port, NIU_ESR2_DEV_ADDR,
			   ESR2_TI_PLL_TEST_CFG_L, test_cfg);

		tx_cfg |= PLL_TX_CFG_ENTEST;
		rx_cfg |= PLL_RX_CFG_ENTEST;
	}

	/* Initialize PLL for 1G */
	pll_cfg = (PLL_CFG_ENPLL | PLL_CFG_MPY_8X);

	err = mdio_write(np, np->port, NIU_ESR2_DEV_ADDR,
			 ESR2_TI_PLL_CFG_L, pll_cfg);
	if (err) {
		netdev_err(np->dev, "NIU Port %d %s() mdio write to ESR2_TI_PLL_CFG_L failed\n",
			   np->port, __func__);
		return err;
	}

	pll_sts = PLL_CFG_ENPLL;

	err = mdio_write(np, np->port, NIU_ESR2_DEV_ADDR,
			 ESR2_TI_PLL_STS_L, pll_sts);
	if (err) {
		netdev_err(np->dev, "NIU Port %d %s() mdio write to ESR2_TI_PLL_STS_L failed\n",
			   np->port, __func__);
		return err;
	}

	udelay(200);

	/* Initialize all 4 lanes of the SERDES. */
	for (i = 0; i < 4; i++) {
		err = esr2_set_tx_cfg(np, i, tx_cfg);
		if (err)
			return err;
	}

	for (i = 0; i < 4; i++) {
		err = esr2_set_rx_cfg(np, i, rx_cfg);
		if (err)
			return err;
	}

	switch (np->port) {
	case 0:
		val = (ESR_INT_SRDY0_P0 | ESR_INT_DET0_P0);
		mask = val;
		break;

	case 1:
		val = (ESR_INT_SRDY0_P1 | ESR_INT_DET0_P1);
		mask = val;
		break;

	default:
		return -EINVAL;
	}

	while (max_retry--) {
		sig = nr64(ESR_INT_SIGNALS);
		if ((sig & mask) == val)
			break;

		mdelay(500);
	}

	if ((sig & mask) != val) {
		netdev_err(np->dev, "Port %u signal bits [%08x] are not [%08x]\n",
			   np->port, (int)(sig & mask), (int)val);
		return -ENODEV;
	}

	return 0;
}

static int serdes_init_niu_10g_serdes(struct niu *np)
{
	struct niu_link_config *lp = &np->link_config;
	u32 tx_cfg, rx_cfg, pll_cfg, pll_sts;
	int max_retry = 100;
	u64 uninitialized_var(sig), mask, val;
	unsigned long i;
	int err;

	tx_cfg = (PLL_TX_CFG_ENTX | PLL_TX_CFG_SWING_1375MV);
	rx_cfg = (PLL_RX_CFG_ENRX | PLL_RX_CFG_TERM_0P8VDDT |
		  PLL_RX_CFG_ALIGN_ENA | PLL_RX_CFG_LOS_LTHRESH |
		  PLL_RX_CFG_EQ_LP_ADAPTIVE);

	if (lp->loopback_mode == LOOPBACK_PHY) {
		u16 test_cfg = PLL_TEST_CFG_LOOPBACK_CML_DIS;

		mdio_write(np, np->port, NIU_ESR2_DEV_ADDR,
			   ESR2_TI_PLL_TEST_CFG_L, test_cfg);

		tx_cfg |= PLL_TX_CFG_ENTEST;
		rx_cfg |= PLL_RX_CFG_ENTEST;
	}

	/* Initialize PLL for 10G */
	pll_cfg = (PLL_CFG_ENPLL | PLL_CFG_MPY_10X);

	err = mdio_write(np, np->port, NIU_ESR2_DEV_ADDR,
			 ESR2_TI_PLL_CFG_L, pll_cfg & 0xffff);
	if (err) {
		netdev_err(np->dev, "NIU Port %d %s() mdio write to ESR2_TI_PLL_CFG_L failed\n",
			   np->port, __func__);
		return err;
	}

	pll_sts = PLL_CFG_ENPLL;

	err = mdio_write(np, np->port, NIU_ESR2_DEV_ADDR,
			 ESR2_TI_PLL_STS_L, pll_sts & 0xffff);
	if (err) {
		netdev_err(np->dev, "NIU Port %d %s() mdio write to ESR2_TI_PLL_STS_L failed\n",
			   np->port, __func__);
		return err;
	}

	udelay(200);

	/* Initialize all 4 lanes of the SERDES. */
	for (i = 0; i < 4; i++) {
		err = esr2_set_tx_cfg(np, i, tx_cfg);
		if (err)
			return err;
	}

	for (i = 0; i < 4; i++) {
		err = esr2_set_rx_cfg(np, i, rx_cfg);
		if (err)
			return err;
	}

	/* check if serdes is ready */

	switch (np->port) {
	case 0:
		mask = ESR_INT_SIGNALS_P0_BITS;
		val = (ESR_INT_SRDY0_P0 |
		       ESR_INT_DET0_P0 |
		       ESR_INT_XSRDY_P0 |
		       ESR_INT_XDP_P0_CH3 |
		       ESR_INT_XDP_P0_CH2 |
		       ESR_INT_XDP_P0_CH1 |
		       ESR_INT_XDP_P0_CH0);
		break;

	case 1:
		mask = ESR_INT_SIGNALS_P1_BITS;
		val = (ESR_INT_SRDY0_P1 |
		       ESR_INT_DET0_P1 |
		       ESR_INT_XSRDY_P1 |
		       ESR_INT_XDP_P1_CH3 |
		       ESR_INT_XDP_P1_CH2 |
		       ESR_INT_XDP_P1_CH1 |
		       ESR_INT_XDP_P1_CH0);
		break;

	default:
		return -EINVAL;
	}

	while (max_retry--) {
		sig = nr64(ESR_INT_SIGNALS);
		if ((sig & mask) == val)
			break;

		mdelay(500);
	}

	if ((sig & mask) != val) {
		pr_info("NIU Port %u signal bits [%08x] are not [%08x] for 10G...trying 1G\n",
			np->port, (int)(sig & mask), (int)val);

		/* 10G failed, try initializing at 1G */
		err = serdes_init_niu_1g_serdes(np);
		if (!err) {
			np->flags &= ~NIU_FLAGS_10G;
			np->mac_xcvr = MAC_XCVR_PCS;
		}  else {
			netdev_err(np->dev, "Port %u 10G/1G SERDES Link Failed\n",
				   np->port);
			return -ENODEV;
		}
	}
	return 0;
}

static int esr_read_rxtx_ctrl(struct niu *np, unsigned long chan, u32 *val)
{
	int err;

	err = mdio_read(np, np->port, NIU_ESR_DEV_ADDR, ESR_RXTX_CTRL_L(chan));
	if (err >= 0) {
		*val = (err & 0xffff);
		err = mdio_read(np, np->port, NIU_ESR_DEV_ADDR,
				ESR_RXTX_CTRL_H(chan));
		if (err >= 0)
			*val |= ((err & 0xffff) << 16);
		err = 0;
	}
	return err;
}

static int esr_read_glue0(struct niu *np, unsigned long chan, u32 *val)
{
	int err;

	err = mdio_read(np, np->port, NIU_ESR_DEV_ADDR,
			ESR_GLUE_CTRL0_L(chan));
	if (err >= 0) {
		*val = (err & 0xffff);
		err = mdio_read(np, np->port, NIU_ESR_DEV_ADDR,
				ESR_GLUE_CTRL0_H(chan));
		if (err >= 0) {
			*val |= ((err & 0xffff) << 16);
			err = 0;
		}
	}
	return err;
}

static int esr_read_reset(struct niu *np, u32 *val)
{
	int err;

	err = mdio_read(np, np->port, NIU_ESR_DEV_ADDR,
			ESR_RXTX_RESET_CTRL_L);
	if (err >= 0) {
		*val = (err & 0xffff);
		err = mdio_read(np, np->port, NIU_ESR_DEV_ADDR,
				ESR_RXTX_RESET_CTRL_H);
		if (err >= 0) {
			*val |= ((err & 0xffff) << 16);
			err = 0;
		}
	}
	return err;
}

static int esr_write_rxtx_ctrl(struct niu *np, unsigned long chan, u32 val)
{
	int err;

	err = mdio_write(np, np->port, NIU_ESR_DEV_ADDR,
			 ESR_RXTX_CTRL_L(chan), val & 0xffff);
	if (!err)
		err = mdio_write(np, np->port, NIU_ESR_DEV_ADDR,
				 ESR_RXTX_CTRL_H(chan), (val >> 16));
	return err;
}

static int esr_write_glue0(struct niu *np, unsigned long chan, u32 val)
{
	int err;

	err = mdio_write(np, np->port, NIU_ESR_DEV_ADDR,
			ESR_GLUE_CTRL0_L(chan), val & 0xffff);
	if (!err)
		err = mdio_write(np, np->port, NIU_ESR_DEV_ADDR,
				 ESR_GLUE_CTRL0_H(chan), (val >> 16));
	return err;
}

static int esr_reset(struct niu *np)
{
	u32 uninitialized_var(reset);
	int err;

	err = mdio_write(np, np->port, NIU_ESR_DEV_ADDR,
			 ESR_RXTX_RESET_CTRL_L, 0x0000);
	if (err)
		return err;
	err = mdio_write(np, np->port, NIU_ESR_DEV_ADDR,
			 ESR_RXTX_RESET_CTRL_H, 0xffff);
	if (err)
		return err;
	udelay(200);

	err = mdio_write(np, np->port, NIU_ESR_DEV_ADDR,
			 ESR_RXTX_RESET_CTRL_L, 0xffff);
	if (err)
		return err;
	udelay(200);

	err = mdio_write(np, np->port, NIU_ESR_DEV_ADDR,
			 ESR_RXTX_RESET_CTRL_H, 0x0000);
	if (err)
		return err;
	udelay(200);

	err = esr_read_reset(np, &reset);
	if (err)
		return err;
	if (reset != 0) {
		netdev_err(np->dev, "Port %u ESR_RESET did not clear [%08x]\n",
			   np->port, reset);
		return -ENODEV;
	}

	return 0;
}

static int serdes_init_10g(struct niu *np)
{
	struct niu_link_config *lp = &np->link_config;
	unsigned long ctrl_reg, test_cfg_reg, i;
	u64 ctrl_val, test_cfg_val, sig, mask, val;
	int err;

	switch (np->port) {
	case 0:
		ctrl_reg = ENET_SERDES_0_CTRL_CFG;
		test_cfg_reg = ENET_SERDES_0_TEST_CFG;
		break;
	case 1:
		ctrl_reg = ENET_SERDES_1_CTRL_CFG;
		test_cfg_reg = ENET_SERDES_1_TEST_CFG;
		break;

	default:
		return -EINVAL;
	}
	ctrl_val = (ENET_SERDES_CTRL_SDET_0 |
		    ENET_SERDES_CTRL_SDET_1 |
		    ENET_SERDES_CTRL_SDET_2 |
		    ENET_SERDES_CTRL_SDET_3 |
		    (0x5 << ENET_SERDES_CTRL_EMPH_0_SHIFT) |
		    (0x5 << ENET_SERDES_CTRL_EMPH_1_SHIFT) |
		    (0x5 << ENET_SERDES_CTRL_EMPH_2_SHIFT) |
		    (0x5 << ENET_SERDES_CTRL_EMPH_3_SHIFT) |
		    (0x1 << ENET_SERDES_CTRL_LADJ_0_SHIFT) |
		    (0x1 << ENET_SERDES_CTRL_LADJ_1_SHIFT) |
		    (0x1 << ENET_SERDES_CTRL_LADJ_2_SHIFT) |
		    (0x1 << ENET_SERDES_CTRL_LADJ_3_SHIFT));
	test_cfg_val = 0;

	if (lp->loopback_mode == LOOPBACK_PHY) {
		test_cfg_val |= ((ENET_TEST_MD_PAD_LOOPBACK <<
				  ENET_SERDES_TEST_MD_0_SHIFT) |
				 (ENET_TEST_MD_PAD_LOOPBACK <<
				  ENET_SERDES_TEST_MD_1_SHIFT) |
				 (ENET_TEST_MD_PAD_LOOPBACK <<
				  ENET_SERDES_TEST_MD_2_SHIFT) |
				 (ENET_TEST_MD_PAD_LOOPBACK <<
				  ENET_SERDES_TEST_MD_3_SHIFT));
	}

	nw64(ctrl_reg, ctrl_val);
	nw64(test_cfg_reg, test_cfg_val);

	/* Initialize all 4 lanes of the SERDES. */
	for (i = 0; i < 4; i++) {
		u32 rxtx_ctrl, glue0;

		err = esr_read_rxtx_ctrl(np, i, &rxtx_ctrl);
		if (err)
			return err;
		err = esr_read_glue0(np, i, &glue0);
		if (err)
			return err;

		rxtx_ctrl &= ~(ESR_RXTX_CTRL_VMUXLO);
		rxtx_ctrl |= (ESR_RXTX_CTRL_ENSTRETCH |
			      (2 << ESR_RXTX_CTRL_VMUXLO_SHIFT));

		glue0 &= ~(ESR_GLUE_CTRL0_SRATE |
			   ESR_GLUE_CTRL0_THCNT |
			   ESR_GLUE_CTRL0_BLTIME);
		glue0 |= (ESR_GLUE_CTRL0_RXLOSENAB |
			  (0xf << ESR_GLUE_CTRL0_SRATE_SHIFT) |
			  (0xff << ESR_GLUE_CTRL0_THCNT_SHIFT) |
			  (BLTIME_300_CYCLES <<
			   ESR_GLUE_CTRL0_BLTIME_SHIFT));

		err = esr_write_rxtx_ctrl(np, i, rxtx_ctrl);
		if (err)
			return err;
		err = esr_write_glue0(np, i, glue0);
		if (err)
			return err;
	}

	err = esr_reset(np);
	if (err)
		return err;

	sig = nr64(ESR_INT_SIGNALS);
	switch (np->port) {
	case 0:
		mask = ESR_INT_SIGNALS_P0_BITS;
		val = (ESR_INT_SRDY0_P0 |
		       ESR_INT_DET0_P0 |
		       ESR_INT_XSRDY_P0 |
		       ESR_INT_XDP_P0_CH3 |
		       ESR_INT_XDP_P0_CH2 |
		       ESR_INT_XDP_P0_CH1 |
		       ESR_INT_XDP_P0_CH0);
		break;

	case 1:
		mask = ESR_INT_SIGNALS_P1_BITS;
		val = (ESR_INT_SRDY0_P1 |
		       ESR_INT_DET0_P1 |
		       ESR_INT_XSRDY_P1 |
		       ESR_INT_XDP_P1_CH3 |
		       ESR_INT_XDP_P1_CH2 |
		       ESR_INT_XDP_P1_CH1 |
		       ESR_INT_XDP_P1_CH0);
		break;

	default:
		return -EINVAL;
	}

	if ((sig & mask) != val) {
		if (np->flags & NIU_FLAGS_HOTPLUG_PHY) {
			np->flags &= ~NIU_FLAGS_HOTPLUG_PHY_PRESENT;
			return 0;
		}
		netdev_err(np->dev, "Port %u signal bits [%08x] are not [%08x]\n",
			   np->port, (int)(sig & mask), (int)val);
		return -ENODEV;
	}
	if (np->flags & NIU_FLAGS_HOTPLUG_PHY)
		np->flags |= NIU_FLAGS_HOTPLUG_PHY_PRESENT;
	return 0;
}

static int serdes_init_1g(struct niu *np)
{
	u64 val;

	val = nr64(ENET_SERDES_1_PLL_CFG);
	val &= ~ENET_SERDES_PLL_FBDIV2;
	switch (np->port) {
	case 0:
		val |= ENET_SERDES_PLL_HRATE0;
		break;
	case 1:
		val |= ENET_SERDES_PLL_HRATE1;
		break;
	case 2:
		val |= ENET_SERDES_PLL_HRATE2;
		break;
	case 3:
		val |= ENET_SERDES_PLL_HRATE3;
		break;
	default:
		return -EINVAL;
	}
	nw64(ENET_SERDES_1_PLL_CFG, val);

	return 0;
}

static int serdes_init_1g_serdes(struct niu *np)
{
	struct niu_link_config *lp = &np->link_config;
	unsigned long ctrl_reg, test_cfg_reg, pll_cfg, i;
	u64 ctrl_val, test_cfg_val, sig, mask, val;
	int err;
	u64 reset_val, val_rd;

	val = ENET_SERDES_PLL_HRATE0 | ENET_SERDES_PLL_HRATE1 |
		ENET_SERDES_PLL_HRATE2 | ENET_SERDES_PLL_HRATE3 |
		ENET_SERDES_PLL_FBDIV0;
	switch (np->port) {
	case 0:
		reset_val =  ENET_SERDES_RESET_0;
		ctrl_reg = ENET_SERDES_0_CTRL_CFG;
		test_cfg_reg = ENET_SERDES_0_TEST_CFG;
		pll_cfg = ENET_SERDES_0_PLL_CFG;
		break;
	case 1:
		reset_val =  ENET_SERDES_RESET_1;
		ctrl_reg = ENET_SERDES_1_CTRL_CFG;
		test_cfg_reg = ENET_SERDES_1_TEST_CFG;
		pll_cfg = ENET_SERDES_1_PLL_CFG;
		break;

	default:
		return -EINVAL;
	}
	ctrl_val = (ENET_SERDES_CTRL_SDET_0 |
		    ENET_SERDES_CTRL_SDET_1 |
		    ENET_SERDES_CTRL_SDET_2 |
		    ENET_SERDES_CTRL_SDET_3 |
		    (0x5 << ENET_SERDES_CTRL_EMPH_0_SHIFT) |
		    (0x5 << ENET_SERDES_CTRL_EMPH_1_SHIFT) |
		    (0x5 << ENET_SERDES_CTRL_EMPH_2_SHIFT) |
		    (0x5 << ENET_SERDES_CTRL_EMPH_3_SHIFT) |
		    (0x1 << ENET_SERDES_CTRL_LADJ_0_SHIFT) |
		    (0x1 << ENET_SERDES_CTRL_LADJ_1_SHIFT) |
		    (0x1 << ENET_SERDES_CTRL_LADJ_2_SHIFT) |
		    (0x1 << ENET_SERDES_CTRL_LADJ_3_SHIFT));
	test_cfg_val = 0;

	if (lp->loopback_mode == LOOPBACK_PHY) {
		test_cfg_val |= ((ENET_TEST_MD_PAD_LOOPBACK <<
				  ENET_SERDES_TEST_MD_0_SHIFT) |
				 (ENET_TEST_MD_PAD_LOOPBACK <<
				  ENET_SERDES_TEST_MD_1_SHIFT) |
				 (ENET_TEST_MD_PAD_LOOPBACK <<
				  ENET_SERDES_TEST_MD_2_SHIFT) |
				 (ENET_TEST_MD_PAD_LOOPBACK <<
				  ENET_SERDES_TEST_MD_3_SHIFT));
	}

	nw64(ENET_SERDES_RESET, reset_val);
	mdelay(20);
	val_rd = nr64(ENET_SERDES_RESET);
	val_rd &= ~reset_val;
	nw64(pll_cfg, val);
	nw64(ctrl_reg, ctrl_val);
	nw64(test_cfg_reg, test_cfg_val);
	nw64(ENET_SERDES_RESET, val_rd);
	mdelay(2000);

	/* Initialize all 4 lanes of the SERDES. */
	for (i = 0; i < 4; i++) {
		u32 rxtx_ctrl, glue0;

		err = esr_read_rxtx_ctrl(np, i, &rxtx_ctrl);
		if (err)
			return err;
		err = esr_read_glue0(np, i, &glue0);
		if (err)
			return err;

		rxtx_ctrl &= ~(ESR_RXTX_CTRL_VMUXLO);
		rxtx_ctrl |= (ESR_RXTX_CTRL_ENSTRETCH |
			      (2 << ESR_RXTX_CTRL_VMUXLO_SHIFT));

		glue0 &= ~(ESR_GLUE_CTRL0_SRATE |
			   ESR_GLUE_CTRL0_THCNT |
			   ESR_GLUE_CTRL0_BLTIME);
		glue0 |= (ESR_GLUE_CTRL0_RXLOSENAB |
			  (0xf << ESR_GLUE_CTRL0_SRATE_SHIFT) |
			  (0xff << ESR_GLUE_CTRL0_THCNT_SHIFT) |
			  (BLTIME_300_CYCLES <<
			   ESR_GLUE_CTRL0_BLTIME_SHIFT));

		err = esr_write_rxtx_ctrl(np, i, rxtx_ctrl);
		if (err)
			return err;
		err = esr_write_glue0(np, i, glue0);
		if (err)
			return err;
	}


	sig = nr64(ESR_INT_SIGNALS);
	switch (np->port) {
	case 0:
		val = (ESR_INT_SRDY0_P0 | ESR_INT_DET0_P0);
		mask = val;
		break;

	case 1:
		val = (ESR_INT_SRDY0_P1 | ESR_INT_DET0_P1);
		mask = val;
		break;

	default:
		return -EINVAL;
	}

	if ((sig & mask) != val) {
		netdev_err(np->dev, "Port %u signal bits [%08x] are not [%08x]\n",
			   np->port, (int)(sig & mask), (int)val);
		return -ENODEV;
	}

	return 0;
}

static int link_status_1g_serdes(struct niu *np, int *link_up_p)
{
	struct niu_link_config *lp = &np->link_config;
	int link_up;
	u64 val;
	u16 current_speed;
	unsigned long flags;
	u8 current_duplex;

	link_up = 0;
	current_speed = SPEED_INVALID;
	current_duplex = DUPLEX_INVALID;

	spin_lock_irqsave(&np->lock, flags);

	val = nr64_pcs(PCS_MII_STAT);

	if (val & PCS_MII_STAT_LINK_STATUS) {
		link_up = 1;
		current_speed = SPEED_1000;
		current_duplex = DUPLEX_FULL;
	}

	lp->active_speed = current_speed;
	lp->active_duplex = current_duplex;
	spin_unlock_irqrestore(&np->lock, flags);

	*link_up_p = link_up;
	return 0;
}

static int link_status_10g_serdes(struct niu *np, int *link_up_p)
{
	unsigned long flags;
	struct niu_link_config *lp = &np->link_config;
	int link_up = 0;
	int link_ok = 1;
	u64 val, val2;
	u16 current_speed;
	u8 current_duplex;

	if (!(np->flags & NIU_FLAGS_10G))
		return link_status_1g_serdes(np, link_up_p);

	current_speed = SPEED_INVALID;
	current_duplex = DUPLEX_INVALID;
	spin_lock_irqsave(&np->lock, flags);

	val = nr64_xpcs(XPCS_STATUS(0));
	val2 = nr64_mac(XMAC_INTER2);
	if (val2 & 0x01000000)
		link_ok = 0;

	if ((val & 0x1000ULL) && link_ok) {
		link_up = 1;
		current_speed = SPEED_10000;
		current_duplex = DUPLEX_FULL;
	}
	lp->active_speed = current_speed;
	lp->active_duplex = current_duplex;
	spin_unlock_irqrestore(&np->lock, flags);
	*link_up_p = link_up;
	return 0;
}

static int link_status_mii(struct niu *np, int *link_up_p)
{
	struct niu_link_config *lp = &np->link_config;
	int err;
	int bmsr, advert, ctrl1000, stat1000, lpa, bmcr, estatus;
	int supported, advertising, active_speed, active_duplex;

	err = mii_read(np, np->phy_addr, MII_BMCR);
	if (unlikely(err < 0))
		return err;
	bmcr = err;

	err = mii_read(np, np->phy_addr, MII_BMSR);
	if (unlikely(err < 0))
		return err;
	bmsr = err;

	err = mii_read(np, np->phy_addr, MII_ADVERTISE);
	if (unlikely(err < 0))
		return err;
	advert = err;

	err = mii_read(np, np->phy_addr, MII_LPA);
	if (unlikely(err < 0))
		return err;
	lpa = err;

	if (likely(bmsr & BMSR_ESTATEN)) {
		err = mii_read(np, np->phy_addr, MII_ESTATUS);
		if (unlikely(err < 0))
			return err;
		estatus = err;

		err = mii_read(np, np->phy_addr, MII_CTRL1000);
		if (unlikely(err < 0))
			return err;
		ctrl1000 = err;

		err = mii_read(np, np->phy_addr, MII_STAT1000);
		if (unlikely(err < 0))
			return err;
		stat1000 = err;
	} else
		estatus = ctrl1000 = stat1000 = 0;

	supported = 0;
	if (bmsr & BMSR_ANEGCAPABLE)
		supported |= SUPPORTED_Autoneg;
	if (bmsr & BMSR_10HALF)
		supported |= SUPPORTED_10baseT_Half;
	if (bmsr & BMSR_10FULL)
		supported |= SUPPORTED_10baseT_Full;
	if (bmsr & BMSR_100HALF)
		supported |= SUPPORTED_100baseT_Half;
	if (bmsr & BMSR_100FULL)
		supported |= SUPPORTED_100baseT_Full;
	if (estatus & ESTATUS_1000_THALF)
		supported |= SUPPORTED_1000baseT_Half;
	if (estatus & ESTATUS_1000_TFULL)
		supported |= SUPPORTED_1000baseT_Full;
	lp->supported = supported;

	advertising = 0;
	if (advert & ADVERTISE_10HALF)
		advertising |= ADVERTISED_10baseT_Half;
	if (advert & ADVERTISE_10FULL)
		advertising |= ADVERTISED_10baseT_Full;
	if (advert & ADVERTISE_100HALF)
		advertising |= ADVERTISED_100baseT_Half;
	if (advert & ADVERTISE_100FULL)
		advertising |= ADVERTISED_100baseT_Full;
	if (ctrl1000 & ADVERTISE_1000HALF)
		advertising |= ADVERTISED_1000baseT_Half;
	if (ctrl1000 & ADVERTISE_1000FULL)
		advertising |= ADVERTISED_1000baseT_Full;

	if (bmcr & BMCR_ANENABLE) {
		int neg, neg1000;

		lp->active_autoneg = 1;
		advertising |= ADVERTISED_Autoneg;

		neg = advert & lpa;
		neg1000 = (ctrl1000 << 2) & stat1000;

		if (neg1000 & (LPA_1000FULL | LPA_1000HALF))
			active_speed = SPEED_1000;
		else if (neg & LPA_100)
			active_speed = SPEED_100;
		else if (neg & (LPA_10HALF | LPA_10FULL))
			active_speed = SPEED_10;
		else
			active_speed = SPEED_INVALID;

		if ((neg1000 & LPA_1000FULL) || (neg & LPA_DUPLEX))
			active_duplex = DUPLEX_FULL;
		else if (active_speed != SPEED_INVALID)
			active_duplex = DUPLEX_HALF;
		else
			active_duplex = DUPLEX_INVALID;
	} else {
		lp->active_autoneg = 0;

		if ((bmcr & BMCR_SPEED1000) && !(bmcr & BMCR_SPEED100))
			active_speed = SPEED_1000;
		else if (bmcr & BMCR_SPEED100)
			active_speed = SPEED_100;
		else
			active_speed = SPEED_10;

		if (bmcr & BMCR_FULLDPLX)
			active_duplex = DUPLEX_FULL;
		else
			active_duplex = DUPLEX_HALF;
	}

	lp->active_advertising = advertising;
	lp->active_speed = active_speed;
	lp->active_duplex = active_duplex;
	*link_up_p = !!(bmsr & BMSR_LSTATUS);

	return 0;
}

static int link_status_1g_rgmii(struct niu *np, int *link_up_p)
{
	struct niu_link_config *lp = &np->link_config;
	u16 current_speed, bmsr;
	unsigned long flags;
	u8 current_duplex;
	int err, link_up;

	link_up = 0;
	current_speed = SPEED_INVALID;
	current_duplex = DUPLEX_INVALID;

	spin_lock_irqsave(&np->lock, flags);

	err = -EINVAL;

	err = mii_read(np, np->phy_addr, MII_BMSR);
	if (err < 0)
		goto out;

	bmsr = err;
	if (bmsr & BMSR_LSTATUS) {
		u16 adv, lpa, common, estat;

		err = mii_read(np, np->phy_addr, MII_ADVERTISE);
		if (err < 0)
			goto out;
		adv = err;

		err = mii_read(np, np->phy_addr, MII_LPA);
		if (err < 0)
			goto out;
		lpa = err;

		common = adv & lpa;

		err = mii_read(np, np->phy_addr, MII_ESTATUS);
		if (err < 0)
			goto out;
		estat = err;
		link_up = 1;
		current_speed = SPEED_1000;
		current_duplex = DUPLEX_FULL;

	}
	lp->active_speed = current_speed;
	lp->active_duplex = current_duplex;
	err = 0;

out:
	spin_unlock_irqrestore(&np->lock, flags);

	*link_up_p = link_up;
	return err;
}

static int link_status_1g(struct niu *np, int *link_up_p)
{
	struct niu_link_config *lp = &np->link_config;
	unsigned long flags;
	int err;

	spin_lock_irqsave(&np->lock, flags);

	err = link_status_mii(np, link_up_p);
	lp->supported |= SUPPORTED_TP;
	lp->active_advertising |= ADVERTISED_TP;

	spin_unlock_irqrestore(&np->lock, flags);
	return err;
}

static int bcm8704_reset(struct niu *np)
{
	int err, limit;

	err = mdio_read(np, np->phy_addr,
			BCM8704_PHYXS_DEV_ADDR, MII_BMCR);
	if (err < 0 || err == 0xffff)
		return err;
	err |= BMCR_RESET;
	err = mdio_write(np, np->phy_addr, BCM8704_PHYXS_DEV_ADDR,
			 MII_BMCR, err);
	if (err)
		return err;

	limit = 1000;
	while (--limit >= 0) {
		err = mdio_read(np, np->phy_addr,
				BCM8704_PHYXS_DEV_ADDR, MII_BMCR);
		if (err < 0)
			return err;
		if (!(err & BMCR_RESET))
			break;
	}
	if (limit < 0) {
		netdev_err(np->dev, "Port %u PHY will not reset (bmcr=%04x)\n",
			   np->port, (err & 0xffff));
		return -ENODEV;
	}
	return 0;
}

/* When written, certain PHY registers need to be read back twice
 * in order for the bits to settle properly.
 */
static int bcm8704_user_dev3_readback(struct niu *np, int reg)
{
	int err = mdio_read(np, np->phy_addr, BCM8704_USER_DEV3_ADDR, reg);
	if (err < 0)
		return err;
	err = mdio_read(np, np->phy_addr, BCM8704_USER_DEV3_ADDR, reg);
	if (err < 0)
		return err;
	return 0;
}

static int bcm8706_init_user_dev3(struct niu *np)
{
	int err;


	err = mdio_read(np, np->phy_addr, BCM8704_USER_DEV3_ADDR,
			BCM8704_USER_OPT_DIGITAL_CTRL);
	if (err < 0)
		return err;
	err &= ~USER_ODIG_CTRL_GPIOS;
	err |= (0x3 << USER_ODIG_CTRL_GPIOS_SHIFT);
	err |=  USER_ODIG_CTRL_RESV2;
	err = mdio_write(np, np->phy_addr, BCM8704_USER_DEV3_ADDR,
			 BCM8704_USER_OPT_DIGITAL_CTRL, err);
	if (err)
		return err;

	mdelay(1000);

	return 0;
}

static int bcm8704_init_user_dev3(struct niu *np)
{
	int err;

	err = mdio_write(np, np->phy_addr,
			 BCM8704_USER_DEV3_ADDR, BCM8704_USER_CONTROL,
			 (USER_CONTROL_OPTXRST_LVL |
			  USER_CONTROL_OPBIASFLT_LVL |
			  USER_CONTROL_OBTMPFLT_LVL |
			  USER_CONTROL_OPPRFLT_LVL |
			  USER_CONTROL_OPTXFLT_LVL |
			  USER_CONTROL_OPRXLOS_LVL |
			  USER_CONTROL_OPRXFLT_LVL |
			  USER_CONTROL_OPTXON_LVL |
			  (0x3f << USER_CONTROL_RES1_SHIFT)));
	if (err)
		return err;

	err = mdio_write(np, np->phy_addr,
			 BCM8704_USER_DEV3_ADDR, BCM8704_USER_PMD_TX_CONTROL,
			 (USER_PMD_TX_CTL_XFP_CLKEN |
			  (1 << USER_PMD_TX_CTL_TX_DAC_TXD_SH) |
			  (2 << USER_PMD_TX_CTL_TX_DAC_TXCK_SH) |
			  USER_PMD_TX_CTL_TSCK_LPWREN));
	if (err)
		return err;

	err = bcm8704_user_dev3_readback(np, BCM8704_USER_CONTROL);
	if (err)
		return err;
	err = bcm8704_user_dev3_readback(np, BCM8704_USER_PMD_TX_CONTROL);
	if (err)
		return err;

	err = mdio_read(np, np->phy_addr, BCM8704_USER_DEV3_ADDR,
			BCM8704_USER_OPT_DIGITAL_CTRL);
	if (err < 0)
		return err;
	err &= ~USER_ODIG_CTRL_GPIOS;
	err |= (0x3 << USER_ODIG_CTRL_GPIOS_SHIFT);
	err = mdio_write(np, np->phy_addr, BCM8704_USER_DEV3_ADDR,
			 BCM8704_USER_OPT_DIGITAL_CTRL, err);
	if (err)
		return err;

	mdelay(1000);

	return 0;
}

static int mrvl88x2011_act_led(struct niu *np, int val)
{
	int	err;

	err  = mdio_read(np, np->phy_addr, MRVL88X2011_USER_DEV2_ADDR,
		MRVL88X2011_LED_8_TO_11_CTL);
	if (err < 0)
		return err;

	err &= ~MRVL88X2011_LED(MRVL88X2011_LED_ACT,MRVL88X2011_LED_CTL_MASK);
	err |=  MRVL88X2011_LED(MRVL88X2011_LED_ACT,val);

	return mdio_write(np, np->phy_addr, MRVL88X2011_USER_DEV2_ADDR,
			  MRVL88X2011_LED_8_TO_11_CTL, err);
}

static int mrvl88x2011_led_blink_rate(struct niu *np, int rate)
{
	int	err;

	err = mdio_read(np, np->phy_addr, MRVL88X2011_USER_DEV2_ADDR,
			MRVL88X2011_LED_BLINK_CTL);
	if (err >= 0) {
		err &= ~MRVL88X2011_LED_BLKRATE_MASK;
		err |= (rate << 4);

		err = mdio_write(np, np->phy_addr, MRVL88X2011_USER_DEV2_ADDR,
				 MRVL88X2011_LED_BLINK_CTL, err);
	}

	return err;
}

static int xcvr_init_10g_mrvl88x2011(struct niu *np)
{
	int	err;

	/* Set LED functions */
	err = mrvl88x2011_led_blink_rate(np, MRVL88X2011_LED_BLKRATE_134MS);
	if (err)
		return err;

	/* led activity */
	err = mrvl88x2011_act_led(np, MRVL88X2011_LED_CTL_OFF);
	if (err)
		return err;

	err = mdio_read(np, np->phy_addr, MRVL88X2011_USER_DEV3_ADDR,
			MRVL88X2011_GENERAL_CTL);
	if (err < 0)
		return err;

	err |= MRVL88X2011_ENA_XFPREFCLK;

	err = mdio_write(np, np->phy_addr, MRVL88X2011_USER_DEV3_ADDR,
			 MRVL88X2011_GENERAL_CTL, err);
	if (err < 0)
		return err;

	err = mdio_read(np, np->phy_addr, MRVL88X2011_USER_DEV1_ADDR,
			MRVL88X2011_PMA_PMD_CTL_1);
	if (err < 0)
		return err;

	if (np->link_config.loopback_mode == LOOPBACK_MAC)
		err |= MRVL88X2011_LOOPBACK;
	else
		err &= ~MRVL88X2011_LOOPBACK;

	err = mdio_write(np, np->phy_addr, MRVL88X2011_USER_DEV1_ADDR,
			 MRVL88X2011_PMA_PMD_CTL_1, err);
	if (err < 0)
		return err;

	/* Enable PMD */
	return mdio_write(np, np->phy_addr, MRVL88X2011_USER_DEV1_ADDR,
			  MRVL88X2011_10G_PMD_TX_DIS, MRVL88X2011_ENA_PMDTX);
}


static int xcvr_diag_bcm870x(struct niu *np)
{
	u16 analog_stat0, tx_alarm_status;
	int err = 0;

#if 1
	err = mdio_read(np, np->phy_addr, BCM8704_PMA_PMD_DEV_ADDR,
			MII_STAT1000);
	if (err < 0)
		return err;
	pr_info("Port %u PMA_PMD(MII_STAT1000) [%04x]\n", np->port, err);

	err = mdio_read(np, np->phy_addr, BCM8704_USER_DEV3_ADDR, 0x20);
	if (err < 0)
		return err;
	pr_info("Port %u USER_DEV3(0x20) [%04x]\n", np->port, err);

	err = mdio_read(np, np->phy_addr, BCM8704_PHYXS_DEV_ADDR,
			MII_NWAYTEST);
	if (err < 0)
		return err;
	pr_info("Port %u PHYXS(MII_NWAYTEST) [%04x]\n", np->port, err);
#endif

	/* XXX dig this out it might not be so useful XXX */
	err = mdio_read(np, np->phy_addr, BCM8704_USER_DEV3_ADDR,
			BCM8704_USER_ANALOG_STATUS0);
	if (err < 0)
		return err;
	err = mdio_read(np, np->phy_addr, BCM8704_USER_DEV3_ADDR,
			BCM8704_USER_ANALOG_STATUS0);
	if (err < 0)
		return err;
	analog_stat0 = err;

	err = mdio_read(np, np->phy_addr, BCM8704_USER_DEV3_ADDR,
			BCM8704_USER_TX_ALARM_STATUS);
	if (err < 0)
		return err;
	err = mdio_read(np, np->phy_addr, BCM8704_USER_DEV3_ADDR,
			BCM8704_USER_TX_ALARM_STATUS);
	if (err < 0)
		return err;
	tx_alarm_status = err;

	if (analog_stat0 != 0x03fc) {
		if ((analog_stat0 == 0x43bc) && (tx_alarm_status != 0)) {
			pr_info("Port %u cable not connected or bad cable\n",
				np->port);
		} else if (analog_stat0 == 0x639c) {
			pr_info("Port %u optical module is bad or missing\n",
				np->port);
		}
	}

	return 0;
}

static int xcvr_10g_set_lb_bcm870x(struct niu *np)
{
	struct niu_link_config *lp = &np->link_config;
	int err;

	err = mdio_read(np, np->phy_addr, BCM8704_PCS_DEV_ADDR,
			MII_BMCR);
	if (err < 0)
		return err;

	err &= ~BMCR_LOOPBACK;

	if (lp->loopback_mode == LOOPBACK_MAC)
		err |= BMCR_LOOPBACK;

	err = mdio_write(np, np->phy_addr, BCM8704_PCS_DEV_ADDR,
			 MII_BMCR, err);
	if (err)
		return err;

	return 0;
}

static int xcvr_init_10g_bcm8706(struct niu *np)
{
	int err = 0;
	u64 val;

	if ((np->flags & NIU_FLAGS_HOTPLUG_PHY) &&
	    (np->flags & NIU_FLAGS_HOTPLUG_PHY_PRESENT) == 0)
			return err;

	val = nr64_mac(XMAC_CONFIG);
	val &= ~XMAC_CONFIG_LED_POLARITY;
	val |= XMAC_CONFIG_FORCE_LED_ON;
	nw64_mac(XMAC_CONFIG, val);

	val = nr64(MIF_CONFIG);
	val |= MIF_CONFIG_INDIRECT_MODE;
	nw64(MIF_CONFIG, val);

	err = bcm8704_reset(np);
	if (err)
		return err;

	err = xcvr_10g_set_lb_bcm870x(np);
	if (err)
		return err;

	err = bcm8706_init_user_dev3(np);
	if (err)
		return err;

	err = xcvr_diag_bcm870x(np);
	if (err)
		return err;

	return 0;
}

static int xcvr_init_10g_bcm8704(struct niu *np)
{
	int err;

	err = bcm8704_reset(np);
	if (err)
		return err;

	err = bcm8704_init_user_dev3(np);
	if (err)
		return err;

	err = xcvr_10g_set_lb_bcm870x(np);
	if (err)
		return err;

	err =  xcvr_diag_bcm870x(np);
	if (err)
		return err;

	return 0;
}

static int xcvr_init_10g(struct niu *np)
{
	int phy_id, err;
	u64 val;

	val = nr64_mac(XMAC_CONFIG);
	val &= ~XMAC_CONFIG_LED_POLARITY;
	val |= XMAC_CONFIG_FORCE_LED_ON;
	nw64_mac(XMAC_CONFIG, val);

	/* XXX shared resource, lock parent XXX */
	val = nr64(MIF_CONFIG);
	val |= MIF_CONFIG_INDIRECT_MODE;
	nw64(MIF_CONFIG, val);

	phy_id = phy_decode(np->parent->port_phy, np->port);
	phy_id = np->parent->phy_probe_info.phy_id[phy_id][np->port];

	/* handle different phy types */
	switch (phy_id & NIU_PHY_ID_MASK) {
	case NIU_PHY_ID_MRVL88X2011:
		err = xcvr_init_10g_mrvl88x2011(np);
		break;

	default: /* bcom 8704 */
		err = xcvr_init_10g_bcm8704(np);
		break;
	}

	return 0;
}

static int mii_reset(struct niu *np)
{
	int limit, err;

	err = mii_write(np, np->phy_addr, MII_BMCR, BMCR_RESET);
	if (err)
		return err;

	limit = 1000;
	while (--limit >= 0) {
		udelay(500);
		err = mii_read(np, np->phy_addr, MII_BMCR);
		if (err < 0)
			return err;
		if (!(err & BMCR_RESET))
			break;
	}
	if (limit < 0) {
		netdev_err(np->dev, "Port %u MII would not reset, bmcr[%04x]\n",
			   np->port, err);
		return -ENODEV;
	}

	return 0;
}

static int xcvr_init_1g_rgmii(struct niu *np)
{
	int err;
	u64 val;
	u16 bmcr, bmsr, estat;

	val = nr64(MIF_CONFIG);
	val &= ~MIF_CONFIG_INDIRECT_MODE;
	nw64(MIF_CONFIG, val);

	err = mii_reset(np);
	if (err)
		return err;

	err = mii_read(np, np->phy_addr, MII_BMSR);
	if (err < 0)
		return err;
	bmsr = err;

	estat = 0;
	if (bmsr & BMSR_ESTATEN) {
		err = mii_read(np, np->phy_addr, MII_ESTATUS);
		if (err < 0)
			return err;
		estat = err;
	}

	bmcr = 0;
	err = mii_write(np, np->phy_addr, MII_BMCR, bmcr);
	if (err)
		return err;

	if (bmsr & BMSR_ESTATEN) {
		u16 ctrl1000 = 0;

		if (estat & ESTATUS_1000_TFULL)
			ctrl1000 |= ADVERTISE_1000FULL;
		err = mii_write(np, np->phy_addr, MII_CTRL1000, ctrl1000);
		if (err)
			return err;
	}

	bmcr = (BMCR_SPEED1000 | BMCR_FULLDPLX);

	err = mii_write(np, np->phy_addr, MII_BMCR, bmcr);
	if (err)
		return err;

	err = mii_read(np, np->phy_addr, MII_BMCR);
	if (err < 0)
		return err;
	bmcr = mii_read(np, np->phy_addr, MII_BMCR);

	err = mii_read(np, np->phy_addr, MII_BMSR);
	if (err < 0)
		return err;

	return 0;
}

static int mii_init_common(struct niu *np)
{
	struct niu_link_config *lp = &np->link_config;
	u16 bmcr, bmsr, adv, estat;
	int err;

	err = mii_reset(np);
	if (err)
		return err;

	err = mii_read(np, np->phy_addr, MII_BMSR);
	if (err < 0)
		return err;
	bmsr = err;

	estat = 0;
	if (bmsr & BMSR_ESTATEN) {
		err = mii_read(np, np->phy_addr, MII_ESTATUS);
		if (err < 0)
			return err;
		estat = err;
	}

	bmcr = 0;
	err = mii_write(np, np->phy_addr, MII_BMCR, bmcr);
	if (err)
		return err;

	if (lp->loopback_mode == LOOPBACK_MAC) {
		bmcr |= BMCR_LOOPBACK;
		if (lp->active_speed == SPEED_1000)
			bmcr |= BMCR_SPEED1000;
		if (lp->active_duplex == DUPLEX_FULL)
			bmcr |= BMCR_FULLDPLX;
	}

	if (lp->loopback_mode == LOOPBACK_PHY) {
		u16 aux;

		aux = (BCM5464R_AUX_CTL_EXT_LB |
		       BCM5464R_AUX_CTL_WRITE_1);
		err = mii_write(np, np->phy_addr, BCM5464R_AUX_CTL, aux);
		if (err)
			return err;
	}

	if (lp->autoneg) {
		u16 ctrl1000;

		adv = ADVERTISE_CSMA | ADVERTISE_PAUSE_CAP;
		if ((bmsr & BMSR_10HALF) &&
			(lp->advertising & ADVERTISED_10baseT_Half))
			adv |= ADVERTISE_10HALF;
		if ((bmsr & BMSR_10FULL) &&
			(lp->advertising & ADVERTISED_10baseT_Full))
			adv |= ADVERTISE_10FULL;
		if ((bmsr & BMSR_100HALF) &&
			(lp->advertising & ADVERTISED_100baseT_Half))
			adv |= ADVERTISE_100HALF;
		if ((bmsr & BMSR_100FULL) &&
			(lp->advertising & ADVERTISED_100baseT_Full))
			adv |= ADVERTISE_100FULL;
		err = mii_write(np, np->phy_addr, MII_ADVERTISE, adv);
		if (err)
			return err;

		if (likely(bmsr & BMSR_ESTATEN)) {
			ctrl1000 = 0;
			if ((estat & ESTATUS_1000_THALF) &&
				(lp->advertising & ADVERTISED_1000baseT_Half))
				ctrl1000 |= ADVERTISE_1000HALF;
			if ((estat & ESTATUS_1000_TFULL) &&
				(lp->advertising & ADVERTISED_1000baseT_Full))
				ctrl1000 |= ADVERTISE_1000FULL;
			err = mii_write(np, np->phy_addr,
					MII_CTRL1000, ctrl1000);
			if (err)
				return err;
		}

		bmcr |= (BMCR_ANENABLE | BMCR_ANRESTART);
	} else {
		/* !lp->autoneg */
		int fulldpx;

		if (lp->duplex == DUPLEX_FULL) {
			bmcr |= BMCR_FULLDPLX;
			fulldpx = 1;
		} else if (lp->duplex == DUPLEX_HALF)
			fulldpx = 0;
		else
			return -EINVAL;

		if (lp->speed == SPEED_1000) {
			/* if X-full requested while not supported, or
 X-half requested while not supported... */
			if ((fulldpx && !(estat & ESTATUS_1000_TFULL)) ||
				(!fulldpx && !(estat & ESTATUS_1000_THALF)))
				return -EINVAL;
			bmcr |= BMCR_SPEED1000;
		} else if (lp->speed == SPEED_100) {
			if ((fulldpx && !(bmsr & BMSR_100FULL)) ||
				(!fulldpx && !(bmsr & BMSR_100HALF)))
				return -EINVAL;
			bmcr |= BMCR_SPEED100;
		} else if (lp->speed == SPEED_10) {
			if ((fulldpx && !(bmsr & BMSR_10FULL)) ||
				(!fulldpx && !(bmsr & BMSR_10HALF)))
				return -EINVAL;
		} else
			return -EINVAL;
	}

	err = mii_write(np, np->phy_addr, MII_BMCR, bmcr);
	if (err)
		return err;

#if 0
	err = mii_read(np, np->phy_addr, MII_BMCR);
	if (err < 0)
		return err;
	bmcr = err;

	err = mii_read(np, np->phy_addr, MII_BMSR);
	if (err < 0)
		return err;
	bmsr = err;

	pr_info("Port %u after MII init bmcr[%04x] bmsr[%04x]\n",
		np->port, bmcr, bmsr);
#endif

	return 0;
}

static int xcvr_init_1g(struct niu *np)
{
	u64 val;

	/* XXX shared resource, lock parent XXX */
	val = nr64(MIF_CONFIG);
	val &= ~MIF_CONFIG_INDIRECT_MODE;
	nw64(MIF_CONFIG, val);

	return mii_init_common(np);
}

static int niu_xcvr_init(struct niu *np)
{
	const struct niu_phy_ops *ops = np->phy_ops;
	int err;

	err = 0;
	if (ops->xcvr_init)
		err = ops->xcvr_init(np);

	return err;
}

static int niu_serdes_init(struct niu *np)
{
	const struct niu_phy_ops *ops = np->phy_ops;
	int err;

	err = 0;
	if (ops->serdes_init)
		err = ops->serdes_init(np);

	return err;
}

static void niu_init_xif(struct niu *);
static void niu_handle_led(struct niu *, int status);

static int niu_link_status_common(struct niu *np, int link_up)
{
	struct niu_link_config *lp = &np->link_config;
	struct net_device *dev = np->dev;
	unsigned long flags;

	if (!netif_carrier_ok(dev) && link_up) {
		netif_info(np, link, dev, "Link is up at %s, %s duplex\n",
			   lp->active_speed == SPEED_10000 ? "10Gb/sec" :
			   lp->active_speed == SPEED_1000 ? "1Gb/sec" :
			   lp->active_speed == SPEED_100 ? "100Mbit/sec" :
			   "10Mbit/sec",
			   lp->active_duplex == DUPLEX_FULL ? "full" : "half");

		spin_lock_irqsave(&np->lock, flags);
		niu_init_xif(np);
		niu_handle_led(np, 1);
		spin_unlock_irqrestore(&np->lock, flags);

		netif_carrier_on(dev);
	} else if (netif_carrier_ok(dev) && !link_up) {
		netif_warn(np, link, dev, "Link is down\n");
		spin_lock_irqsave(&np->lock, flags);
		niu_handle_led(np, 0);
		spin_unlock_irqrestore(&np->lock, flags);
		netif_carrier_off(dev);
	}

	return 0;
}

static int link_status_10g_mrvl(struct niu *np, int *link_up_p)
{
	int err, link_up, pma_status, pcs_status;

	link_up = 0;

	err = mdio_read(np, np->phy_addr, MRVL88X2011_USER_DEV1_ADDR,
			MRVL88X2011_10G_PMD_STATUS_2);
	if (err < 0)
		goto out;

	/* Check PMA/PMD Register: 1.0001.2 == 1 */
	err = mdio_read(np, np->phy_addr, MRVL88X2011_USER_DEV1_ADDR,
			MRVL88X2011_PMA_PMD_STATUS_1);
	if (err < 0)
		goto out;

	pma_status = ((err & MRVL88X2011_LNK_STATUS_OK) ? 1 : 0);

        /* Check PMC Register : 3.0001.2 == 1: read twice */
	err = mdio_read(np, np->phy_addr, MRVL88X2011_USER_DEV3_ADDR,
			MRVL88X2011_PMA_PMD_STATUS_1);
	if (err < 0)
		goto out;

	err = mdio_read(np, np->phy_addr, MRVL88X2011_USER_DEV3_ADDR,
			MRVL88X2011_PMA_PMD_STATUS_1);
	if (err < 0)
		goto out;

	pcs_status = ((err & MRVL88X2011_LNK_STATUS_OK) ? 1 : 0);

        /* Check XGXS Register : 4.0018.[0-3,12] */
	err = mdio_read(np, np->phy_addr, MRVL88X2011_USER_DEV4_ADDR,
			MRVL88X2011_10G_XGXS_LANE_STAT);
	if (err < 0)
		goto out;

	if (err == (PHYXS_XGXS_LANE_STAT_ALINGED | PHYXS_XGXS_LANE_STAT_LANE3 |
		    PHYXS_XGXS_LANE_STAT_LANE2 | PHYXS_XGXS_LANE_STAT_LANE1 |
		    PHYXS_XGXS_LANE_STAT_LANE0 | PHYXS_XGXS_LANE_STAT_MAGIC |
		    0x800))
		link_up = (pma_status && pcs_status) ? 1 : 0;

	np->link_config.active_speed = SPEED_10000;
	np->link_config.active_duplex = DUPLEX_FULL;
	err = 0;
out:
	mrvl88x2011_act_led(np, (link_up ?
				 MRVL88X2011_LED_CTL_PCS_ACT :
				 MRVL88X2011_LED_CTL_OFF));

	*link_up_p = link_up;
	return err;
}

static int link_status_10g_bcm8706(struct niu *np, int *link_up_p)
{
	int err, link_up;
	link_up = 0;

	err = mdio_read(np, np->phy_addr, BCM8704_PMA_PMD_DEV_ADDR,
			BCM8704_PMD_RCV_SIGDET);
	if (err < 0 || err == 0xffff)
		goto out;
	if (!(err & PMD_RCV_SIGDET_GLOBAL)) {
		err = 0;
		goto out;
	}

	err = mdio_read(np, np->phy_addr, BCM8704_PCS_DEV_ADDR,
			BCM8704_PCS_10G_R_STATUS);
	if (err < 0)
		goto out;

	if (!(err & PCS_10G_R_STATUS_BLK_LOCK)) {
		err = 0;
		goto out;
	}

	err = mdio_read(np, np->phy_addr, BCM8704_PHYXS_DEV_ADDR,
			BCM8704_PHYXS_XGXS_LANE_STAT);
	if (err < 0)
		goto out;
	if (err != (PHYXS_XGXS_LANE_STAT_ALINGED |
		    PHYXS_XGXS_LANE_STAT_MAGIC |
		    PHYXS_XGXS_LANE_STAT_PATTEST |
		    PHYXS_XGXS_LANE_STAT_LANE3 |
		    PHYXS_XGXS_LANE_STAT_LANE2 |
		    PHYXS_XGXS_LANE_STAT_LANE1 |
		    PHYXS_XGXS_LANE_STAT_LANE0)) {
		err = 0;
		np->link_config.active_speed = SPEED_INVALID;
		np->link_config.active_duplex = DUPLEX_INVALID;
		goto out;
	}

	link_up = 1;
	np->link_config.active_speed = SPEED_10000;
	np->link_config.active_duplex = DUPLEX_FULL;
	err = 0;

out:
	*link_up_p = link_up;
	return err;
}

static int link_status_10g_bcom(struct niu *np, int *link_up_p)
{
	int err, link_up;

	link_up = 0;

	err = mdio_read(np, np->phy_addr, BCM8704_PMA_PMD_DEV_ADDR,
			BCM8704_PMD_RCV_SIGDET);
	if (err < 0)
		goto out;
	if (!(err & PMD_RCV_SIGDET_GLOBAL)) {
		err = 0;
		goto out;
	}

	err = mdio_read(np, np->phy_addr, BCM8704_PCS_DEV_ADDR,
			BCM8704_PCS_10G_R_STATUS);
	if (err < 0)
		goto out;
	if (!(err & PCS_10G_R_STATUS_BLK_LOCK)) {
		err = 0;
		goto out;
	}

	err = mdio_read(np, np->phy_addr, BCM8704_PHYXS_DEV_ADDR,
			BCM8704_PHYXS_XGXS_LANE_STAT);
	if (err < 0)
		goto out;

	if (err != (PHYXS_XGXS_LANE_STAT_ALINGED |
		    PHYXS_XGXS_LANE_STAT_MAGIC |
		    PHYXS_XGXS_LANE_STAT_LANE3 |
		    PHYXS_XGXS_LANE_STAT_LANE2 |
		    PHYXS_XGXS_LANE_STAT_LANE1 |
		    PHYXS_XGXS_LANE_STAT_LANE0)) {
		err = 0;
		goto out;
	}

	link_up = 1;
	np->link_config.active_speed = SPEED_10000;
	np->link_config.active_duplex = DUPLEX_FULL;
	err = 0;

out:
	*link_up_p = link_up;
	return err;
}

static int link_status_10g(struct niu *np, int *link_up_p)
{
	unsigned long flags;
	int err = -EINVAL;

	spin_lock_irqsave(&np->lock, flags);

	if (np->link_config.loopback_mode == LOOPBACK_DISABLED) {
		int phy_id;

		phy_id = phy_decode(np->parent->port_phy, np->port);
		phy_id = np->parent->phy_probe_info.phy_id[phy_id][np->port];

		/* handle different phy types */
		switch (phy_id & NIU_PHY_ID_MASK) {
		case NIU_PHY_ID_MRVL88X2011:
			err = link_status_10g_mrvl(np, link_up_p);
			break;

		default: /* bcom 8704 */
			err = link_status_10g_bcom(np, link_up_p);
			break;
		}
	}

	spin_unlock_irqrestore(&np->lock, flags);

	return err;
}

static int niu_10g_phy_present(struct niu *np)
{
	u64 sig, mask, val;

	sig = nr64(ESR_INT_SIGNALS);
	switch (np->port) {
	case 0:
		mask = ESR_INT_SIGNALS_P0_BITS;
		val = (ESR_INT_SRDY0_P0 |
		       ESR_INT_DET0_P0 |
		       ESR_INT_XSRDY_P0 |
		       ESR_INT_XDP_P0_CH3 |
		       ESR_INT_XDP_P0_CH2 |
		       ESR_INT_XDP_P0_CH1 |
		       ESR_INT_XDP_P0_CH0);
		break;

	case 1:
		mask = ESR_INT_SIGNALS_P1_BITS;
		val = (ESR_INT_SRDY0_P1 |
		       ESR_INT_DET0_P1 |
		       ESR_INT_XSRDY_P1 |
		       ESR_INT_XDP_P1_CH3 |
		       ESR_INT_XDP_P1_CH2 |
		       ESR_INT_XDP_P1_CH1 |
		       ESR_INT_XDP_P1_CH0);
		break;

	default:
		return 0;
	}

	if ((sig & mask) != val)
		return 0;
	return 1;
}

static int link_status_10g_hotplug(struct niu *np, int *link_up_p)
{
	unsigned long flags;
	int err = 0;
	int phy_present;
	int phy_present_prev;

	spin_lock_irqsave(&np->lock, flags);

	if (np->link_config.loopback_mode == LOOPBACK_DISABLED) {
		phy_present_prev = (np->flags & NIU_FLAGS_HOTPLUG_PHY_PRESENT) ?
			1 : 0;
		phy_present = niu_10g_phy_present(np);
		if (phy_present != phy_present_prev) {
			/* state change */
			if (phy_present) {
				/* A NEM was just plugged in */
				np->flags |= NIU_FLAGS_HOTPLUG_PHY_PRESENT;
				if (np->phy_ops->xcvr_init)
					err = np->phy_ops->xcvr_init(np);
				if (err) {
					err = mdio_read(np, np->phy_addr,
						BCM8704_PHYXS_DEV_ADDR, MII_BMCR);
					if (err == 0xffff) {
						/* No mdio, back-to-back XAUI */
						goto out;
					}
					/* debounce */
					np->flags &= ~NIU_FLAGS_HOTPLUG_PHY_PRESENT;
				}
			} else {
				np->flags &= ~NIU_FLAGS_HOTPLUG_PHY_PRESENT;
				*link_up_p = 0;
				netif_warn(np, link, np->dev,
					   "Hotplug PHY Removed\n");
			}
		}
out:
		if (np->flags & NIU_FLAGS_HOTPLUG_PHY_PRESENT) {
			err = link_status_10g_bcm8706(np, link_up_p);
			if (err == 0xffff) {
				/* No mdio, back-to-back XAUI: it is C10NEM */
				*link_up_p = 1;
				np->link_config.active_speed = SPEED_10000;
				np->link_config.active_duplex = DUPLEX_FULL;
			}
		}
	}

	spin_unlock_irqrestore(&np->lock, flags);

	return 0;
}

static int niu_link_status(struct niu *np, int *link_up_p)
{
	const struct niu_phy_ops *ops = np->phy_ops;
	int err;

	err = 0;
	if (ops->link_status)
		err = ops->link_status(np, link_up_p);

	return err;
}

static void niu_timer(unsigned long __opaque)
{
	struct niu *np = (struct niu *) __opaque;
	unsigned long off;
	int err, link_up;

	err = niu_link_status(np, &link_up);
	if (!err)
		niu_link_status_common(np, link_up);

	if (netif_carrier_ok(np->dev))
		off = 5 * HZ;
	else
		off = 1 * HZ;
	np->timer.expires = jiffies + off;

	add_timer(&np->timer);
}

static const struct niu_phy_ops phy_ops_10g_serdes = {
	.serdes_init		= serdes_init_10g_serdes,
	.link_status		= link_status_10g_serdes,
};

static const struct niu_phy_ops phy_ops_10g_serdes_niu = {
	.serdes_init		= serdes_init_niu_10g_serdes,
	.link_status		= link_status_10g_serdes,
};

static const struct niu_phy_ops phy_ops_1g_serdes_niu = {
	.serdes_init		= serdes_init_niu_1g_serdes,
	.link_status		= link_status_1g_serdes,
};

static const struct niu_phy_ops phy_ops_1g_rgmii = {
	.xcvr_init		= xcvr_init_1g_rgmii,
	.link_status		= link_status_1g_rgmii,
};

static const struct niu_phy_ops phy_ops_10g_fiber_niu = {
	.serdes_init		= serdes_init_niu_10g_fiber,
	.xcvr_init		= xcvr_init_10g,
	.link_status		= link_status_10g,
};

static const struct niu_phy_ops phy_ops_10g_fiber = {
	.serdes_init		= serdes_init_10g,
	.xcvr_init		= xcvr_init_10g,
	.link_status		= link_status_10g,
};

static const struct niu_phy_ops phy_ops_10g_fiber_hotplug = {
	.serdes_init		= serdes_init_10g,
	.xcvr_init		= xcvr_init_10g_bcm8706,
	.link_status		= link_status_10g_hotplug,
};

static const struct niu_phy_ops phy_ops_niu_10g_hotplug = {
	.serdes_init		= serdes_init_niu_10g_fiber,
	.xcvr_init		= xcvr_init_10g_bcm8706,
	.link_status		= link_status_10g_hotplug,
};

static const struct niu_phy_ops phy_ops_10g_copper = {
	.serdes_init		= serdes_init_10g,
	.link_status		= link_status_10g, /* XXX */
};

static const struct niu_phy_ops phy_ops_1g_fiber = {
	.serdes_init		= serdes_init_1g,
	.xcvr_init		= xcvr_init_1g,
	.link_status		= link_status_1g,
};

static const struct niu_phy_ops phy_ops_1g_copper = {
	.xcvr_init		= xcvr_init_1g,
	.link_status		= link_status_1g,
};

struct niu_phy_template {
	const struct niu_phy_ops	*ops;
	u32				phy_addr_base;
};

static const struct niu_phy_template phy_template_niu_10g_fiber = {
	.ops		= &phy_ops_10g_fiber_niu,
	.phy_addr_base	= 16,
};

static const struct niu_phy_template phy_template_niu_10g_serdes = {
	.ops		= &phy_ops_10g_serdes_niu,
	.phy_addr_base	= 0,
};

static const struct niu_phy_template phy_template_niu_1g_serdes = {
	.ops		= &phy_ops_1g_serdes_niu,
	.phy_addr_base	= 0,
};

static const struct niu_phy_template phy_template_10g_fiber = {
	.ops		= &phy_ops_10g_fiber,
	.phy_addr_base	= 8,
};

static const struct niu_phy_template phy_template_10g_fiber_hotplug = {
	.ops		= &phy_ops_10g_fiber_hotplug,
	.phy_addr_base	= 8,
};

static const struct niu_phy_template phy_template_niu_10g_hotplug = {
	.ops		= &phy_ops_niu_10g_hotplug,
	.phy_addr_base	= 8,
};

static const struct niu_phy_template phy_template_10g_copper = {
	.ops		= &phy_ops_10g_copper,
	.phy_addr_base	= 10,
};

static const struct niu_phy_template phy_template_1g_fiber = {
	.ops		= &phy_ops_1g_fiber,
	.phy_addr_base	= 0,
};

static const struct niu_phy_template phy_template_1g_copper = {
	.ops		= &phy_ops_1g_copper,
	.phy_addr_base	= 0,
};

static const struct niu_phy_template phy_template_1g_rgmii = {
	.ops		= &phy_ops_1g_rgmii,
	.phy_addr_base	= 0,
};

static const struct niu_phy_template phy_template_10g_serdes = {
	.ops		= &phy_ops_10g_serdes,
	.phy_addr_base	= 0,
};

static int niu_atca_port_num[4] = {
	0, 0,  11, 10
};

static int serdes_init_10g_serdes(struct niu *np)
{
	struct niu_link_config *lp = &np->link_config;
	unsigned long ctrl_reg, test_cfg_reg, pll_cfg, i;
	u64 ctrl_val, test_cfg_val, sig, mask, val;
	u64 reset_val;

	switch (np->port) {
	case 0:
		reset_val =  ENET_SERDES_RESET_0;
		ctrl_reg = ENET_SERDES_0_CTRL_CFG;
		test_cfg_reg = ENET_SERDES_0_TEST_CFG;
		pll_cfg = ENET_SERDES_0_PLL_CFG;
		break;
	case 1:
		reset_val =  ENET_SERDES_RESET_1;
		ctrl_reg = ENET_SERDES_1_CTRL_CFG;
		test_cfg_reg = ENET_SERDES_1_TEST_CFG;
		pll_cfg = ENET_SERDES_1_PLL_CFG;
		break;

	default:
		return -EINVAL;
	}
	ctrl_val = (ENET_SERDES_CTRL_SDET_0 |
		    ENET_SERDES_CTRL_SDET_1 |
		    ENET_SERDES_CTRL_SDET_2 |
		    ENET_SERDES_CTRL_SDET_3 |
		    (0x5 << ENET_SERDES_CTRL_EMPH_0_SHIFT) |
		    (0x5 << ENET_SERDES_CTRL_EMPH_1_SHIFT) |
		    (0x5 << ENET_SERDES_CTRL_EMPH_2_SHIFT) |
		    (0x5 << ENET_SERDES_CTRL_EMPH_3_SHIFT) |
		    (0x1 << ENET_SERDES_CTRL_LADJ_0_SHIFT) |
		    (0x1 << ENET_SERDES_CTRL_LADJ_1_SHIFT) |
		    (0x1 << ENET_SERDES_CTRL_LADJ_2_SHIFT) |
		    (0x1 << ENET_SERDES_CTRL_LADJ_3_SHIFT));
	test_cfg_val = 0;

	if (lp->loopback_mode == LOOPBACK_PHY) {
		test_cfg_val |= ((ENET_TEST_MD_PAD_LOOPBACK <<
				  ENET_SERDES_TEST_MD_0_SHIFT) |
				 (ENET_TEST_MD_PAD_LOOPBACK <<
				  ENET_SERDES_TEST_MD_1_SHIFT) |
				 (ENET_TEST_MD_PAD_LOOPBACK <<
				  ENET_SERDES_TEST_MD_2_SHIFT) |
				 (ENET_TEST_MD_PAD_LOOPBACK <<
				  ENET_SERDES_TEST_MD_3_SHIFT));
	}

	esr_reset(np);
	nw64(pll_cfg, ENET_SERDES_PLL_FBDIV2);
	nw64(ctrl_reg, ctrl_val);
	nw64(test_cfg_reg, test_cfg_val);

	/* Initialize all 4 lanes of the SERDES. */
	for (i = 0; i < 4; i++) {
		u32 rxtx_ctrl, glue0;
		int err;

		err = esr_read_rxtx_ctrl(np, i, &rxtx_ctrl);
		if (err)
			return err;
		err = esr_read_glue0(np, i, &glue0);
		if (err)
			return err;

		rxtx_ctrl &= ~(ESR_RXTX_CTRL_VMUXLO);
		rxtx_ctrl |= (ESR_RXTX_CTRL_ENSTRETCH |
			      (2 << ESR_RXTX_CTRL_VMUXLO_SHIFT));

		glue0 &= ~(ESR_GLUE_CTRL0_SRATE |
			   ESR_GLUE_CTRL0_THCNT |
			   ESR_GLUE_CTRL0_BLTIME);
		glue0 |= (ESR_GLUE_CTRL0_RXLOSENAB |
			  (0xf << ESR_GLUE_CTRL0_SRATE_SHIFT) |
			  (0xff << ESR_GLUE_CTRL0_THCNT_SHIFT) |
			  (BLTIME_300_CYCLES <<
			   ESR_GLUE_CTRL0_BLTIME_SHIFT));

		err = esr_write_rxtx_ctrl(np, i, rxtx_ctrl);
		if (err)
			return err;
		err = esr_write_glue0(np, i, glue0);
		if (err)
			return err;
	}


	sig = nr64(ESR_INT_SIGNALS);
	switch (np->port) {
	case 0:
		mask = ESR_INT_SIGNALS_P0_BITS;
		val = (ESR_INT_SRDY0_P0 |
		       ESR_INT_DET0_P0 |
		       ESR_INT_XSRDY_P0 |
		       ESR_INT_XDP_P0_CH3 |
		       ESR_INT_XDP_P0_CH2 |
		       ESR_INT_XDP_P0_CH1 |
		       ESR_INT_XDP_P0_CH0);
		break;

	case 1:
		mask = ESR_INT_SIGNALS_P1_BITS;
		val = (ESR_INT_SRDY0_P1 |
		       ESR_INT_DET0_P1 |
		       ESR_INT_XSRDY_P1 |
		       ESR_INT_XDP_P1_CH3 |
		       ESR_INT_XDP_P1_CH2 |
		       ESR_INT_XDP_P1_CH1 |
		       ESR_INT_XDP_P1_CH0);
		break;

	default:
		return -EINVAL;
	}

	if ((sig & mask) != val) {
		int err;
		err = serdes_init_1g_serdes(np);
		if (!err) {
			np->flags &= ~NIU_FLAGS_10G;
			np->mac_xcvr = MAC_XCVR_PCS;
		}  else {
			netdev_err(np->dev, "Port %u 10G/1G SERDES Link Failed\n",
				   np->port);
			return -ENODEV;
		}
	}

	return 0;
}

static int niu_determine_phy_disposition(struct niu *np)
{
	struct niu_parent *parent = np->parent;
	u8 plat_type = parent->plat_type;
	const struct niu_phy_template *tp;
	u32 phy_addr_off = 0;

	if (plat_type == PLAT_TYPE_NIU) {
		switch (np->flags &
			(NIU_FLAGS_10G |
			 NIU_FLAGS_FIBER |
			 NIU_FLAGS_XCVR_SERDES)) {
		case NIU_FLAGS_10G | NIU_FLAGS_XCVR_SERDES:
			/* 10G Serdes */
			tp = &phy_template_niu_10g_serdes;
			break;
		case NIU_FLAGS_XCVR_SERDES:
			/* 1G Serdes */
			tp = &phy_template_niu_1g_serdes;
			break;
		case NIU_FLAGS_10G | NIU_FLAGS_FIBER:
			/* 10G Fiber */
		default:
			if (np->flags & NIU_FLAGS_HOTPLUG_PHY) {
				tp = &phy_template_niu_10g_hotplug;
				if (np->port == 0)
					phy_addr_off = 8;
				if (np->port == 1)
					phy_addr_off = 12;
			} else {
				tp = &phy_template_niu_10g_fiber;
				phy_addr_off += np->port;
			}
			break;
		}
	} else {
		switch (np->flags &
			(NIU_FLAGS_10G |
			 NIU_FLAGS_FIBER |
			 NIU_FLAGS_XCVR_SERDES)) {
		case 0:
			/* 1G copper */
			tp = &phy_template_1g_copper;
			if (plat_type == PLAT_TYPE_VF_P0)
				phy_addr_off = 10;
			else if (plat_type == PLAT_TYPE_VF_P1)
				phy_addr_off = 26;

			phy_addr_off += (np->port ^ 0x3);
			break;

		case NIU_FLAGS_10G:
			/* 10G copper */
			tp = &phy_template_10g_copper;
			break;

		case NIU_FLAGS_FIBER:
			/* 1G fiber */
			tp = &phy_template_1g_fiber;
			break;

		case NIU_FLAGS_10G | NIU_FLAGS_FIBER:
			/* 10G fiber */
			tp = &phy_template_10g_fiber;
			if (plat_type == PLAT_TYPE_VF_P0 ||
			    plat_type == PLAT_TYPE_VF_P1)
				phy_addr_off = 8;
			phy_addr_off += np->port;
			if (np->flags & NIU_FLAGS_HOTPLUG_PHY) {
				tp = &phy_template_10g_fiber_hotplug;
				if (np->port == 0)
					phy_addr_off = 8;
				if (np->port == 1)
					phy_addr_off = 12;
			}
			break;

		case NIU_FLAGS_10G | NIU_FLAGS_XCVR_SERDES:
		case NIU_FLAGS_XCVR_SERDES | NIU_FLAGS_FIBER:
		case NIU_FLAGS_XCVR_SERDES:
			switch(np->port) {
			case 0:
			case 1:
				tp = &phy_template_10g_serdes;
				break;
			case 2:
			case 3:
				tp = &phy_template_1g_rgmii;
				break;
			default:
				return -EINVAL;
				break;
			}
			phy_addr_off = niu_atca_port_num[np->port];
			break;

		default:
			return -EINVAL;
		}
	}

	np->phy_ops = tp->ops;
	np->phy_addr = tp->phy_addr_base + phy_addr_off;

	return 0;
}

static int niu_init_link(struct niu *np)
{
	struct niu_parent *parent = np->parent;
	int err, ignore;

	if (parent->plat_type == PLAT_TYPE_NIU) {
		err = niu_xcvr_init(np);
		if (err)
			return err;
		msleep(200);
	}
	err = niu_serdes_init(np);
	if (err && !(np->flags & NIU_FLAGS_HOTPLUG_PHY))
		return err;
	msleep(200);
	err = niu_xcvr_init(np);
	if (!err || (np->flags & NIU_FLAGS_HOTPLUG_PHY))
		niu_link_status(np, &ignore);
	return 0;
}

static void niu_set_primary_mac(struct niu *np, unsigned char *addr)
{
	u16 reg0 = addr[4] << 8 | addr[5];
	u16 reg1 = addr[2] << 8 | addr[3];
	u16 reg2 = addr[0] << 8 | addr[1];

	if (np->flags & NIU_FLAGS_XMAC) {
		nw64_mac(XMAC_ADDR0, reg0);
		nw64_mac(XMAC_ADDR1, reg1);
		nw64_mac(XMAC_ADDR2, reg2);
	} else {
		nw64_mac(BMAC_ADDR0, reg0);
		nw64_mac(BMAC_ADDR1, reg1);
		nw64_mac(BMAC_ADDR2, reg2);
	}
}

static int niu_num_alt_addr(struct niu *np)
{
	if (np->flags & NIU_FLAGS_XMAC)
		return XMAC_NUM_ALT_ADDR;
	else
		return BMAC_NUM_ALT_ADDR;
}

static int niu_set_alt_mac(struct niu *np, int index, unsigned char *addr)
{
	u16 reg0 = addr[4] << 8 | addr[5];
	u16 reg1 = addr[2] << 8 | addr[3];
	u16 reg2 = addr[0] << 8 | addr[1];

	if (index >= niu_num_alt_addr(np))
		return -EINVAL;

	if (np->flags & NIU_FLAGS_XMAC) {
		nw64_mac(XMAC_ALT_ADDR0(index), reg0);
		nw64_mac(XMAC_ALT_ADDR1(index), reg1);
		nw64_mac(XMAC_ALT_ADDR2(index), reg2);
	} else {
		nw64_mac(BMAC_ALT_ADDR0(index), reg0);
		nw64_mac(BMAC_ALT_ADDR1(index), reg1);
		nw64_mac(BMAC_ALT_ADDR2(index), reg2);
	}

	return 0;
}

static int niu_enable_alt_mac(struct niu *np, int index, int on)
{
	unsigned long reg;
	u64 val, mask;

	if (index >= niu_num_alt_addr(np))
		return -EINVAL;

	if (np->flags & NIU_FLAGS_XMAC) {
		reg = XMAC_ADDR_CMPEN;
		mask = 1 << index;
	} else {
		reg = BMAC_ADDR_CMPEN;
		mask = 1 << (index + 1);
	}

	val = nr64_mac(reg);
	if (on)
		val |= mask;
	else
		val &= ~mask;
	nw64_mac(reg, val);

	return 0;
}

static void __set_rdc_table_num_hw(struct niu *np, unsigned long reg,
				   int num, int mac_pref)
{
	u64 val = nr64_mac(reg);
	val &= ~(HOST_INFO_MACRDCTBLN | HOST_INFO_MPR);
	val |= num;
	if (mac_pref)
		val |= HOST_INFO_MPR;
	nw64_mac(reg, val);
}

static int __set_rdc_table_num(struct niu *np,
			       int xmac_index, int bmac_index,
			       int rdc_table_num, int mac_pref)
{
	unsigned long reg;

	if (rdc_table_num & ~HOST_INFO_MACRDCTBLN)
		return -EINVAL;
	if (np->flags & NIU_FLAGS_XMAC)
		reg = XMAC_HOST_INFO(xmac_index);
	else
		reg = BMAC_HOST_INFO(bmac_index);
	__set_rdc_table_num_hw(np, reg, rdc_table_num, mac_pref);
	return 0;
}

static int niu_set_primary_mac_rdc_table(struct niu *np, int table_num,
					 int mac_pref)
{
	return __set_rdc_table_num(np, 17, 0, table_num, mac_pref);
}

static int niu_set_multicast_mac_rdc_table(struct niu *np, int table_num,
					   int mac_pref)
{
	return __set_rdc_table_num(np, 16, 8, table_num, mac_pref);
}

static int niu_set_alt_mac_rdc_table(struct niu *np, int idx,
				     int table_num, int mac_pref)
{
	if (idx >= niu_num_alt_addr(np))
		return -EINVAL;
	return __set_rdc_table_num(np, idx, idx + 1, table_num, mac_pref);
}

static u64 vlan_entry_set_parity(u64 reg_val)
{
	u64 port01_mask;
	u64 port23_mask;

	port01_mask = 0x00ff;
	port23_mask = 0xff00;

	if (hweight64(reg_val & port01_mask) & 1)
		reg_val |= ENET_VLAN_TBL_PARITY0;
	else
		reg_val &= ~ENET_VLAN_TBL_PARITY0;

	if (hweight64(reg_val & port23_mask) & 1)
		reg_val |= ENET_VLAN_TBL_PARITY1;
	else
		reg_val &= ~ENET_VLAN_TBL_PARITY1;

	return reg_val;
}

static void vlan_tbl_write(struct niu *np, unsigned long index,
			   int port, int vpr, int rdc_table)
{
	u64 reg_val = nr64(ENET_VLAN_TBL(index));

	reg_val &= ~((ENET_VLAN_TBL_VPR |
		      ENET_VLAN_TBL_VLANRDCTBLN) <<
		     ENET_VLAN_TBL_SHIFT(port));
	if (vpr)
		reg_val |= (ENET_VLAN_TBL_VPR <<
			    ENET_VLAN_TBL_SHIFT(port));
	reg_val |= (rdc_table << ENET_VLAN_TBL_SHIFT(port));

	reg_val = vlan_entry_set_parity(reg_val);

	nw64(ENET_VLAN_TBL(index), reg_val);
}

static void vlan_tbl_clear(struct niu *np)
{
	int i;

	for (i = 0; i < ENET_VLAN_TBL_NUM_ENTRIES; i++)
		nw64(ENET_VLAN_TBL(i), 0);
}

static int tcam_wait_bit(struct niu *np, u64 bit)
{
	int limit = 1000;

	while (--limit > 0) {
		if (nr64(TCAM_CTL) & bit)
			break;
		udelay(1);
	}
	if (limit <= 0)
		return -ENODEV;

	return 0;
}

static int tcam_flush(struct niu *np, int index)
{
	nw64(TCAM_KEY_0, 0x00);
	nw64(TCAM_KEY_MASK_0, 0xff);
	nw64(TCAM_CTL, (TCAM_CTL_RWC_TCAM_WRITE | index));

	return tcam_wait_bit(np, TCAM_CTL_STAT);
}

#if 0
static int tcam_read(struct niu *np, int index,
		     u64 *key, u64 *mask)
{
	int err;

	nw64(TCAM_CTL, (TCAM_CTL_RWC_TCAM_READ | index));
	err = tcam_wait_bit(np, TCAM_CTL_STAT);
	if (!err) {
		key[0] = nr64(TCAM_KEY_0);
		key[1] = nr64(TCAM_KEY_1);
		key[2] = nr64(TCAM_KEY_2);
		key[3] = nr64(TCAM_KEY_3);
		mask[0] = nr64(TCAM_KEY_MASK_0);
		mask[1] = nr64(TCAM_KEY_MASK_1);
		mask[2] = nr64(TCAM_KEY_MASK_2);
		mask[3] = nr64(TCAM_KEY_MASK_3);
	}
	return err;
}
#endif

static int tcam_write(struct niu *np, int index,
		      u64 *key, u64 *mask)
{
	nw64(TCAM_KEY_0, key[0]);
	nw64(TCAM_KEY_1, key[1]);
	nw64(TCAM_KEY_2, key[2]);
	nw64(TCAM_KEY_3, key[3]);
	nw64(TCAM_KEY_MASK_0, mask[0]);
	nw64(TCAM_KEY_MASK_1, mask[1]);
	nw64(TCAM_KEY_MASK_2, mask[2]);
	nw64(TCAM_KEY_MASK_3, mask[3]);
	nw64(TCAM_CTL, (TCAM_CTL_RWC_TCAM_WRITE | index));

	return tcam_wait_bit(np, TCAM_CTL_STAT);
}

#if 0
static int tcam_assoc_read(struct niu *np, int index, u64 *data)
{
	int err;

	nw64(TCAM_CTL, (TCAM_CTL_RWC_RAM_READ | index));
	err = tcam_wait_bit(np, TCAM_CTL_STAT);
	if (!err)
		*data = nr64(TCAM_KEY_1);

	return err;
}
#endif

static int tcam_assoc_write(struct niu *np, int index, u64 assoc_data)
{
	nw64(TCAM_KEY_1, assoc_data);
	nw64(TCAM_CTL, (TCAM_CTL_RWC_RAM_WRITE | index));

	return tcam_wait_bit(np, TCAM_CTL_STAT);
}

static void tcam_enable(struct niu *np, int on)
{
	u64 val = nr64(FFLP_CFG_1);

	if (on)
		val &= ~FFLP_CFG_1_TCAM_DIS;
	else
		val |= FFLP_CFG_1_TCAM_DIS;
	nw64(FFLP_CFG_1, val);
}

static void tcam_set_lat_and_ratio(struct niu *np, u64 latency, u64 ratio)
{
	u64 val = nr64(FFLP_CFG_1);

	val &= ~(FFLP_CFG_1_FFLPINITDONE |
		 FFLP_CFG_1_CAMLAT |
		 FFLP_CFG_1_CAMRATIO);
	val |= (latency << FFLP_CFG_1_CAMLAT_SHIFT);
	val |= (ratio << FFLP_CFG_1_CAMRATIO_SHIFT);
	nw64(FFLP_CFG_1, val);

	val = nr64(FFLP_CFG_1);
	val |= FFLP_CFG_1_FFLPINITDONE;
	nw64(FFLP_CFG_1, val);
}

static int tcam_user_eth_class_enable(struct niu *np, unsigned long class,
				      int on)
{
	unsigned long reg;
	u64 val;

	if (class < CLASS_CODE_ETHERTYPE1 ||
	    class > CLASS_CODE_ETHERTYPE2)
		return -EINVAL;

	reg = L2_CLS(class - CLASS_CODE_ETHERTYPE1);
	val = nr64(reg);
	if (on)
		val |= L2_CLS_VLD;
	else
		val &= ~L2_CLS_VLD;
	nw64(reg, val);

	return 0;
}

#if 0
static int tcam_user_eth_class_set(struct niu *np, unsigned long class,
				   u64 ether_type)
{
	unsigned long reg;
	u64 val;

	if (class < CLASS_CODE_ETHERTYPE1 ||
	    class > CLASS_CODE_ETHERTYPE2 ||
	    (ether_type & ~(u64)0xffff) != 0)
		return -EINVAL;

	reg = L2_CLS(class - CLASS_CODE_ETHERTYPE1);
	val = nr64(reg);
	val &= ~L2_CLS_ETYPE;
	val |= (ether_type << L2_CLS_ETYPE_SHIFT);
	nw64(reg, val);

	return 0;
}
#endif

static int tcam_user_ip_class_enable(struct niu *np, unsigned long class,
				     int on)
{
	unsigned long reg;
	u64 val;

	if (class < CLASS_CODE_USER_PROG1 ||
	    class > CLASS_CODE_USER_PROG4)
		return -EINVAL;

	reg = L3_CLS(class - CLASS_CODE_USER_PROG1);
	val = nr64(reg);
	if (on)
		val |= L3_CLS_VALID;
	else
		val &= ~L3_CLS_VALID;
	nw64(reg, val);

	return 0;
}

static int tcam_user_ip_class_set(struct niu *np, unsigned long class,
				  int ipv6, u64 protocol_id,
				  u64 tos_mask, u64 tos_val)
{
	unsigned long reg;
	u64 val;

	if (class < CLASS_CODE_USER_PROG1 ||
	    class > CLASS_CODE_USER_PROG4 ||
	    (protocol_id & ~(u64)0xff) != 0 ||
	    (tos_mask & ~(u64)0xff) != 0 ||
	    (tos_val & ~(u64)0xff) != 0)
		return -EINVAL;

	reg = L3_CLS(class - CLASS_CODE_USER_PROG1);
	val = nr64(reg);
	val &= ~(L3_CLS_IPVER | L3_CLS_PID |
		 L3_CLS_TOSMASK | L3_CLS_TOS);
	if (ipv6)
		val |= L3_CLS_IPVER;
	val |= (protocol_id << L3_CLS_PID_SHIFT);
	val |= (tos_mask << L3_CLS_TOSMASK_SHIFT);
	val |= (tos_val << L3_CLS_TOS_SHIFT);
	nw64(reg, val);

	return 0;
}

static int tcam_early_init(struct niu *np)
{
	unsigned long i;
	int err;

	tcam_enable(np, 0);
	tcam_set_lat_and_ratio(np,
			       DEFAULT_TCAM_LATENCY,
			       DEFAULT_TCAM_ACCESS_RATIO);
	for (i = CLASS_CODE_ETHERTYPE1; i <= CLASS_CODE_ETHERTYPE2; i++) {
		err = tcam_user_eth_class_enable(np, i, 0);
		if (err)
			return err;
	}
	for (i = CLASS_CODE_USER_PROG1; i <= CLASS_CODE_USER_PROG4; i++) {
		err = tcam_user_ip_class_enable(np, i, 0);
		if (err)
			return err;
	}

	return 0;
}

static int tcam_flush_all(struct niu *np)
{
	unsigned long i;

	for (i = 0; i < np->parent->tcam_num_entries; i++) {
		int err = tcam_flush(np, i);
		if (err)
			return err;
	}
	return 0;
}

static u64 hash_addr_regval(unsigned long index, unsigned long num_entries)
{
	return ((u64)index | (num_entries == 1 ?
			      HASH_TBL_ADDR_AUTOINC : 0));
}

#if 0
static int hash_read(struct niu *np, unsigned long partition,
		     unsigned long index, unsigned long num_entries,
		     u64 *data)
{
	u64 val = hash_addr_regval(index, num_entries);
	unsigned long i;

	if (partition >= FCRAM_NUM_PARTITIONS ||
	    index + num_entries > FCRAM_SIZE)
		return -EINVAL;

	nw64(HASH_TBL_ADDR(partition), val);
	for (i = 0; i < num_entries; i++)
		data[i] = nr64(HASH_TBL_DATA(partition));

	return 0;
}
#endif

static int hash_write(struct niu *np, unsigned long partition,
		      unsigned long index, unsigned long num_entries,
		      u64 *data)
{
	u64 val = hash_addr_regval(index, num_entries);
	unsigned long i;

	if (partition >= FCRAM_NUM_PARTITIONS ||
	    index + (num_entries * 8) > FCRAM_SIZE)
		return -EINVAL;

	nw64(HASH_TBL_ADDR(partition), val);
	for (i = 0; i < num_entries; i++)
		nw64(HASH_TBL_DATA(partition), data[i]);

	return 0;
}

static void fflp_reset(struct niu *np)
{
	u64 val;

	nw64(FFLP_CFG_1, FFLP_CFG_1_PIO_FIO_RST);
	udelay(10);
	nw64(FFLP_CFG_1, 0);

	val = FFLP_CFG_1_FCRAMOUTDR_NORMAL | FFLP_CFG_1_FFLPINITDONE;
	nw64(FFLP_CFG_1, val);
}

static void fflp_set_timings(struct niu *np)
{
	u64 val = nr64(FFLP_CFG_1);

	val &= ~FFLP_CFG_1_FFLPINITDONE;
	val |= (DEFAULT_FCRAMRATIO << FFLP_CFG_1_FCRAMRATIO_SHIFT);
	nw64(FFLP_CFG_1, val);

	val = nr64(FFLP_CFG_1);
	val |= FFLP_CFG_1_FFLPINITDONE;
	nw64(FFLP_CFG_1, val);

	val = nr64(FCRAM_REF_TMR);
	val &= ~(FCRAM_REF_TMR_MAX | FCRAM_REF_TMR_MIN);
	val |= (DEFAULT_FCRAM_REFRESH_MAX << FCRAM_REF_TMR_MAX_SHIFT);
	val |= (DEFAULT_FCRAM_REFRESH_MIN << FCRAM_REF_TMR_MIN_SHIFT);
	nw64(FCRAM_REF_TMR, val);
}

static int fflp_set_partition(struct niu *np, u64 partition,
			      u64 mask, u64 base, int enable)
{
	unsigned long reg;
	u64 val;

	if (partition >= FCRAM_NUM_PARTITIONS ||
	    (mask & ~(u64)0x1f) != 0 ||
	    (base & ~(u64)0x1f) != 0)
		return -EINVAL;

	reg = FLW_PRT_SEL(partition);

	val = nr64(reg);
	val &= ~(FLW_PRT_SEL_EXT | FLW_PRT_SEL_MASK | FLW_PRT_SEL_BASE);
	val |= (mask << FLW_PRT_SEL_MASK_SHIFT);
	val |= (base << FLW_PRT_SEL_BASE_SHIFT);
	if (enable)
		val |= FLW_PRT_SEL_EXT;
	nw64(reg, val);

	return 0;
}

static int fflp_disable_all_partitions(struct niu *np)
{
	unsigned long i;

	for (i = 0; i < FCRAM_NUM_PARTITIONS; i++) {
		int err = fflp_set_partition(np, 0, 0, 0, 0);
		if (err)
			return err;
	}
	return 0;
}

static void fflp_llcsnap_enable(struct niu *np, int on)
{
	u64 val = nr64(FFLP_CFG_1);

	if (on)
		val |= FFLP_CFG_1_LLCSNAP;
	else
		val &= ~FFLP_CFG_1_LLCSNAP;
	nw64(FFLP_CFG_1, val);
}

static void fflp_errors_enable(struct niu *np, int on)
{
	u64 val = nr64(FFLP_CFG_1);

	if (on)
		val &= ~FFLP_CFG_1_ERRORDIS;
	else
		val |= FFLP_CFG_1_ERRORDIS;
	nw64(FFLP_CFG_1, val);
}

static int fflp_hash_clear(struct niu *np)
{
	struct fcram_hash_ipv4 ent;
	unsigned long i;

	/* IPV4 hash entry with valid bit clear, rest is don't care. */
	memset(&ent, 0, sizeof(ent));
	ent.header = HASH_HEADER_EXT;

	for (i = 0; i < FCRAM_SIZE; i += sizeof(ent)) {
		int err = hash_write(np, 0, i, 1, (u64 *) &ent);
		if (err)
			return err;
	}
	return 0;
}

static int fflp_early_init(struct niu *np)
{
	struct niu_parent *parent;
	unsigned long flags;
	int err;

	niu_lock_parent(np, flags);

	parent = np->parent;
	err = 0;
	if (!(parent->flags & PARENT_FLGS_CLS_HWINIT)) {
		if (np->parent->plat_type != PLAT_TYPE_NIU) {
			fflp_reset(np);
			fflp_set_timings(np);
			err = fflp_disable_all_partitions(np);
			if (err) {
				netif_printk(np, probe, KERN_DEBUG, np->dev,
					     "fflp_disable_all_partitions failed, err=%d\n",
					     err);
				goto out;
			}
		}

		err = tcam_early_init(np);
		if (err) {
			netif_printk(np, probe, KERN_DEBUG, np->dev,
				     "tcam_early_init failed, err=%d\n", err);
			goto out;
		}
		fflp_llcsnap_enable(np, 1);
		fflp_errors_enable(np, 0);
		nw64(H1POLY, 0);
		nw64(H2POLY, 0);

		err = tcam_flush_all(np);
		if (err) {
			netif_printk(np, probe, KERN_DEBUG, np->dev,
				     "tcam_flush_all failed, err=%d\n", err);
			goto out;
		}
		if (np->parent->plat_type != PLAT_TYPE_NIU) {
			err = fflp_hash_clear(np);
			if (err) {
				netif_printk(np, probe, KERN_DEBUG, np->dev,
					     "fflp_hash_clear failed, err=%d\n",
					     err);
				goto out;
			}
		}

		vlan_tbl_clear(np);

		parent->flags |= PARENT_FLGS_CLS_HWINIT;
	}
out:
	niu_unlock_parent(np, flags);
	return err;
}

static int niu_set_flow_key(struct niu *np, unsigned long class_code, u64 key)
{
	if (class_code < CLASS_CODE_USER_PROG1 ||
	    class_code > CLASS_CODE_SCTP_IPV6)
		return -EINVAL;

	nw64(FLOW_KEY(class_code - CLASS_CODE_USER_PROG1), key);
	return 0;
}

static int niu_set_tcam_key(struct niu *np, unsigned long class_code, u64 key)
{
	if (class_code < CLASS_CODE_USER_PROG1 ||
	    class_code > CLASS_CODE_SCTP_IPV6)
		return -EINVAL;

	nw64(TCAM_KEY(class_code - CLASS_CODE_USER_PROG1), key);
	return 0;
}

/* Entries for the ports are interleaved in the TCAM */
static u16 tcam_get_index(struct niu *np, u16 idx)
{
	/* One entry reserved for IP fragment rule */
	if (idx >= (np->clas.tcam_sz - 1))
		idx = 0;
	return (np->clas.tcam_top + ((idx+1) * np->parent->num_ports));
}

static u16 tcam_get_size(struct niu *np)
{
	/* One entry reserved for IP fragment rule */
	return np->clas.tcam_sz - 1;
}

static u16 tcam_get_valid_entry_cnt(struct niu *np)
{
	/* One entry reserved for IP fragment rule */
	return np->clas.tcam_valid_entries - 1;
}

static void niu_rx_skb_append(struct sk_buff *skb, struct page *page,
			      u32 offset, u32 size)
{
	int i = skb_shinfo(skb)->nr_frags;
	skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

	frag->page = page;
	frag->page_offset = offset;
	frag->size = size;

	skb->len += size;
	skb->data_len += size;
	skb->truesize += size;

	skb_shinfo(skb)->nr_frags = i + 1;
}

static unsigned int niu_hash_rxaddr(struct rx_ring_info *rp, u64 a)
{
	a >>= PAGE_SHIFT;
	a ^= (a >> ilog2(MAX_RBR_RING_SIZE));

	return (a & (MAX_RBR_RING_SIZE - 1));
}

static struct page *niu_find_rxpage(struct rx_ring_info *rp, u64 addr,
				    struct page ***link)
{
	unsigned int h = niu_hash_rxaddr(rp, addr);
	struct page *p, **pp;

	addr &= PAGE_MASK;
	pp = &rp->rxhash[h];
	for (; (p = *pp) != NULL; pp = (struct page **) &p->mapping) {
		if (p->index == addr) {
			*link = pp;
			goto found;
		}
	}
	BUG();

found:
	return p;
}

static void niu_hash_page(struct rx_ring_info *rp, struct page *page, u64 base)
{
	unsigned int h = niu_hash_rxaddr(rp, base);

	page->index = base;
	page->mapping = (struct address_space *) rp->rxhash[h];
	rp->rxhash[h] = page;
}

static int niu_rbr_add_page(struct niu *np, struct rx_ring_info *rp,
			    gfp_t mask, int start_index)
{
	struct page *page;
	u64 addr;
	int i;

	page = alloc_page(mask);
	if (!page)
		return -ENOMEM;

	addr = np->ops->map_page(np->device, page, 0,
				 PAGE_SIZE, DMA_FROM_DEVICE);

	niu_hash_page(rp, page, addr);
	if (rp->rbr_blocks_per_page > 1)
		atomic_add(rp->rbr_blocks_per_page - 1,
			   &compound_head(page)->_count);

	for (i = 0; i < rp->rbr_blocks_per_page; i++) {
		__le32 *rbr = &rp->rbr[start_index + i];

		*rbr = cpu_to_le32(addr >> RBR_DESCR_ADDR_SHIFT);
		addr += rp->rbr_block_size;
	}

	return 0;
}

static void niu_rbr_refill(struct niu *np, struct rx_ring_info *rp, gfp_t mask)
{
	int index = rp->rbr_index;

	rp->rbr_pending++;
	if ((rp->rbr_pending % rp->rbr_blocks_per_page) == 0) {
		int err = niu_rbr_add_page(np, rp, mask, index);

		if (unlikely(err)) {
			rp->rbr_pending--;
			return;
		}

		rp->rbr_index += rp->rbr_blocks_per_page;
		BUG_ON(rp->rbr_index > rp->rbr_table_size);
		if (rp->rbr_index == rp->rbr_table_size)
			rp->rbr_index = 0;

		if (rp->rbr_pending >= rp->rbr_kick_thresh) {
			nw64(RBR_KICK(rp->rx_channel), rp->rbr_pending);
			rp->rbr_pending = 0;
		}
	}
}

static int niu_rx_pkt_ignore(struct niu *np, struct rx_ring_info *rp)
{
	unsigned int index = rp->rcr_index;
	int num_rcr = 0;

	rp->rx_dropped++;
	while (1) {
		struct page *page, **link;
		u64 addr, val;
		u32 rcr_size;

		num_rcr++;

		val = le64_to_cpup(&rp->rcr[index]);
		addr = (val & RCR_ENTRY_PKT_BUF_ADDR) <<
			RCR_ENTRY_PKT_BUF_ADDR_SHIFT;
		page = niu_find_rxpage(rp, addr, &link);

		rcr_size = rp->rbr_sizes[(val & RCR_ENTRY_PKTBUFSZ) >>
					 RCR_ENTRY_PKTBUFSZ_SHIFT];
		if ((page->index + PAGE_SIZE) - rcr_size == addr) {
			*link = (struct page *) page->mapping;
			np->ops->unmap_page(np->device, page->index,
					    PAGE_SIZE, DMA_FROM_DEVICE);
			page->index = 0;
			page->mapping = NULL;
			__free_page(page);
			rp->rbr_refill_pending++;
		}

		index = NEXT_RCR(rp, index);
		if (!(val & RCR_ENTRY_MULTI))
			break;

	}
	rp->rcr_index = index;

	return num_rcr;
}

static int niu_process_rx_pkt(struct napi_struct *napi, struct niu *np,
			      struct rx_ring_info *rp)
{
	unsigned int index = rp->rcr_index;
	struct rx_pkt_hdr1 *rh;
	struct sk_buff *skb;
	int len, num_rcr;

	skb = netdev_alloc_skb(np->dev, RX_SKB_ALLOC_SIZE);
	if (unlikely(!skb))
		return niu_rx_pkt_ignore(np, rp);

	num_rcr = 0;
	while (1) {
		struct page *page, **link;
		u32 rcr_size, append_size;
		u64 addr, val, off;

		num_rcr++;

		val = le64_to_cpup(&rp->rcr[index]);

		len = (val & RCR_ENTRY_L2_LEN) >>
			RCR_ENTRY_L2_LEN_SHIFT;
		len -= ETH_FCS_LEN;

		addr = (val & RCR_ENTRY_PKT_BUF_ADDR) <<
			RCR_ENTRY_PKT_BUF_ADDR_SHIFT;
		page = niu_find_rxpage(rp, addr, &link);

		rcr_size = rp->rbr_sizes[(val & RCR_ENTRY_PKTBUFSZ) >>
					 RCR_ENTRY_PKTBUFSZ_SHIFT];

		off = addr & ~PAGE_MASK;
		append_size = rcr_size;
		if (num_rcr == 1) {
			int ptype;

			ptype = (val >> RCR_ENTRY_PKT_TYPE_SHIFT);
			if ((ptype == RCR_PKT_TYPE_TCP ||
			     ptype == RCR_PKT_TYPE_UDP) &&
			    !(val & (RCR_ENTRY_NOPORT |
				     RCR_ENTRY_ERROR)))
				skb->ip_summed = CHECKSUM_UNNECESSARY;
			else
				skb->ip_summed = CHECKSUM_NONE;
		} else if (!(val & RCR_ENTRY_MULTI))
			append_size = len - skb->len;

		niu_rx_skb_append(skb, page, off, append_size);
		if ((page->index + rp->rbr_block_size) - rcr_size == addr) {
			*link = (struct page *) page->mapping;
			np->ops->unmap_page(np->device, page->index,
					    PAGE_SIZE, DMA_FROM_DEVICE);
			page->index = 0;
			page->mapping = NULL;
			rp->rbr_refill_pending++;
		} else
			get_page(page);

		index = NEXT_RCR(rp, index);
		if (!(val & RCR_ENTRY_MULTI))
			break;

	}
	rp->rcr_index = index;

	len += sizeof(*rh);
	len = min_t(int, len, sizeof(*rh) + VLAN_ETH_HLEN);
	__pskb_pull_tail(skb, len);

	rh = (struct rx_pkt_hdr1 *) skb->data;
	if (np->dev->features & NETIF_F_RXHASH)
		skb->rxhash = ((u32)rh->hashval2_0 << 24 |
			       (u32)rh->hashval2_1 << 16 |
			       (u32)rh->hashval1_1 << 8 |
			       (u32)rh->hashval1_2 << 0);
	skb_pull(skb, sizeof(*rh));

	rp->rx_packets++;
	rp->rx_bytes += skb->len;

	skb->protocol = eth_type_trans(skb, np->dev);
	skb_record_rx_queue(skb, rp->rx_channel);
	napi_gro_receive(napi, skb);

	return num_rcr;
}

static int niu_rbr_fill(struct niu *np, struct rx_ring_info *rp, gfp_t mask)
{
	int blocks_per_page = rp->rbr_blocks_per_page;
	int err, index = rp->rbr_index;

	err = 0;
	while (index < (rp->rbr_table_size - blocks_per_page)) {
		err = niu_rbr_add_page(np, rp, mask, index);
		if (err)
			break;

		index += blocks_per_page;
	}

	rp->rbr_index = index;
	return err;
}

static void niu_rbr_free(struct niu *np, struct rx_ring_info *rp)
{
	int i;

	for (i = 0; i < MAX_RBR_RING_SIZE; i++) {
		struct page *page;

		page = rp->rxhash[i];
		while (page) {
			struct page *next = (struct page *) page->mapping;
			u64 base = page->index;

			np->ops->unmap_page(np->device, base, PAGE_SIZE,
					    DMA_FROM_DEVICE);
			page->index = 0;
			page->mapping = NULL;

			__free_page(page);

			page = next;
		}
	}

	for (i = 0; i < rp->rbr_table_size; i++)
		rp->rbr[i] = cpu_to_le32(0);
	rp->rbr_index = 0;
}

static int release_tx_packet(struct niu *np, struct tx_ring_info *rp, int idx)
{
	struct tx_buff_info *tb = &rp->tx_buffs[idx];
	struct sk_buff *skb = tb->skb;
	struct tx_pkt_hdr *tp;
	u64 tx_flags;
	int i, len;

	tp = (struct tx_pkt_hdr *) skb->data;
	tx_flags = le64_to_cpup(&tp->flags);

	rp->tx_packets++;
	rp->tx_bytes += (((tx_flags & TXHDR_LEN) >> TXHDR_LEN_SHIFT) -
			 ((tx_flags & TXHDR_PAD) / 2));

	len = skb_headlen(skb);
	np->ops->unmap_single(np->device, tb->mapping,
			      len, DMA_TO_DEVICE);

	if (le64_to_cpu(rp->descr[idx]) & TX_DESC_MARK)
		rp->mark_pending--;

	tb->skb = NULL;
	do {
		idx = NEXT_TX(rp, idx);
		len -= MAX_TX_DESC_LEN;
	} while (len > 0);

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		tb = &rp->tx_buffs[idx];
		BUG_ON(tb->skb != NULL);
		np->ops->unmap_page(np->device, tb->mapping,
				    skb_shinfo(skb)->frags[i].size,
				    DMA_TO_DEVICE);
		idx = NEXT_TX(rp, idx);
	}

	dev_kfree_skb(skb);

	return idx;
}

#define NIU_TX_WAKEUP_THRESH(rp) ((rp)->pending / 4)

static void niu_tx_work(struct niu *np, struct tx_ring_info *rp)
{
	struct netdev_queue *txq;
	u16 pkt_cnt, tmp;
	int cons, index;
	u64 cs;

	index = (rp - np->tx_rings);
	txq = netdev_get_tx_queue(np->dev, index);

	cs = rp->tx_cs;
	if (unlikely(!(cs & (TX_CS_MK | TX_CS_MMK))))
		goto out;

	tmp = pkt_cnt = (cs & TX_CS_PKT_CNT) >> TX_CS_PKT_CNT_SHIFT;
	pkt_cnt = (pkt_cnt - rp->last_pkt_cnt) &
		(TX_CS_PKT_CNT >> TX_CS_PKT_CNT_SHIFT);

	rp->last_pkt_cnt = tmp;

	cons = rp->cons;

	netif_printk(np, tx_done, KERN_DEBUG, np->dev,
		     "%s() pkt_cnt[%u] cons[%d]\n", __func__, pkt_cnt, cons);

	while (pkt_cnt--)
		cons = release_tx_packet(np, rp, cons);

	rp->cons = cons;
	smp_mb();

out:
	if (unlikely(netif_tx_queue_stopped(txq) &&
		     (niu_tx_avail(rp) > NIU_TX_WAKEUP_THRESH(rp)))) {
		__netif_tx_lock(txq, smp_processor_id());
		if (netif_tx_queue_stopped(txq) &&
		    (niu_tx_avail(rp) > NIU_TX_WAKEUP_THRESH(rp)))
			netif_tx_wake_queue(txq);
		__netif_tx_unlock(txq);
	}
}

static inline void niu_sync_rx_discard_stats(struct niu *np,
					     struct rx_ring_info *rp,
					     const int limit)
{
	/* This elaborate scheme is needed for reading the RX discard
 * counters, as they are only 16-bit and can overflow quickly,
 * and because the overflow indication bit is not usable as
 * the counter value does not wrap, but remains at max value
 * 0xFFFF.
 *
 * In theory and in practice counters can be lost in between
 * reading nr64() and clearing the counter nw64(). For this
 * reason, the number of counter clearings nw64() is
 * limited/reduced though the limit parameter.
 */
	int rx_channel = rp->rx_channel;
	u32 misc, wred;

	/* RXMISC (Receive Miscellaneous Discard Count), covers the
 * following discard events: IPP (Input Port Process),
 * FFLP/TCAM, Full RCR (Receive Completion Ring) RBR (Receive
 * Block Ring) prefetch buffer is empty.
 */
	misc = nr64(RXMISC(rx_channel));
	if (unlikely((misc & RXMISC_COUNT) > limit)) {
		nw64(RXMISC(rx_channel), 0);
		rp->rx_errors += misc & RXMISC_COUNT;

		if (unlikely(misc & RXMISC_OFLOW))
			dev_err(np->device, "rx-%d: Counter overflow RXMISC discard\n",
				rx_channel);

		netif_printk(np, rx_err, KERN_DEBUG, np->dev,
			     "rx-%d: MISC drop=%u over=%u\n",
			     rx_channel, misc, misc-limit);
	}

	/* WRED (Weighted Random Early Discard) by hardware */
	wred = nr64(RED_DIS_CNT(rx_channel));
	if (unlikely((wred & RED_DIS_CNT_COUNT) > limit)) {
		nw64(RED_DIS_CNT(rx_channel), 0);
		rp->rx_dropped += wred & RED_DIS_CNT_COUNT;

		if (unlikely(wred & RED_DIS_CNT_OFLOW))
			dev_err(np->device, "rx-%d: Counter overflow WRED discard\n", rx_channel);

		netif_printk(np, rx_err, KERN_DEBUG, np->dev,
			     "rx-%d: WRED drop=%u over=%u\n",
			     rx_channel, wred, wred-limit);
	}
}

static int niu_rx_work(struct napi_struct *napi, struct niu *np,
		       struct rx_ring_info *rp, int budget)
{
	int qlen, rcr_done = 0, work_done = 0;
	struct rxdma_mailbox *mbox = rp->mbox;
	u64 stat;

#if 1
	stat = nr64(RX_DMA_CTL_STAT(rp->rx_channel));
	qlen = nr64(RCRSTAT_A(rp->rx_channel)) & RCRSTAT_A_QLEN;
#else
	stat = le64_to_cpup(&mbox->rx_dma_ctl_stat);
	qlen = (le64_to_cpup(&mbox->rcrstat_a) & RCRSTAT_A_QLEN);
#endif
	mbox->rx_dma_ctl_stat = 0;
	mbox->rcrstat_a = 0;

	netif_printk(np, rx_status, KERN_DEBUG, np->dev,
		     "%s(chan[%d]), stat[%llx] qlen=%d\n",
		     __func__, rp->rx_channel, (unsigned long long)stat, qlen);

	rcr_done = work_done = 0;
	qlen = min(qlen, budget);
	while (work_done < qlen) {
		rcr_done += niu_process_rx_pkt(napi, np, rp);
		work_done++;
	}

	if (rp->rbr_refill_pending >= rp->rbr_kick_thresh) {
		unsigned int i;

		for (i = 0; i < rp->rbr_refill_pending; i++)
			niu_rbr_refill(np, rp, GFP_ATOMIC);
		rp->rbr_refill_pending = 0;
	}

	stat = (RX_DMA_CTL_STAT_MEX |
		((u64)work_done << RX_DMA_CTL_STAT_PKTREAD_SHIFT) |
		((u64)rcr_done << RX_DMA_CTL_STAT_PTRREAD_SHIFT));

	nw64(RX_DMA_CTL_STAT(rp->rx_channel), stat);

	/* Only sync discards stats when qlen indicate potential for drops */
	if (qlen > 10)
		niu_sync_rx_discard_stats(np, rp, 0x7FFF);

	return work_done;
}

static int niu_poll_core(struct niu *np, struct niu_ldg *lp, int budget)
{
	u64 v0 = lp->v0;
	u32 tx_vec = (v0 >> 32);
	u32 rx_vec = (v0 & 0xffffffff);
	int i, work_done = 0;

	netif_printk(np, intr, KERN_DEBUG, np->dev,
		     "%s() v0[%016llx]\n", __func__, (unsigned long long)v0);

	for (i = 0; i < np->num_tx_rings; i++) {
		struct tx_ring_info *rp = &np->tx_rings[i];
		if (tx_vec & (1 << rp->tx_channel))
			niu_tx_work(np, rp);
		nw64(LD_IM0(LDN_TXDMA(rp->tx_channel)), 0);
	}

	for (i = 0; i < np->num_rx_rings; i++) {
		struct rx_ring_info *rp = &np->rx_rings[i];

		if (rx_vec & (1 << rp->rx_channel)) {
			int this_work_done;

			this_work_done = niu_rx_work(&lp->napi, np, rp,
						     budget);

			budget -= this_work_done;
			work_done += this_work_done;
		}
		nw64(LD_IM0(LDN_RXDMA(rp->rx_channel)), 0);
	}

	return work_done;
}

static int niu_poll(struct napi_struct *napi, int budget)
{
	struct niu_ldg *lp = container_of(napi, struct niu_ldg, napi);
	struct niu *np = lp->np;
	int work_done;

	work_done = niu_poll_core(np, lp, budget);

	if (work_done < budget) {
		napi_complete(napi);
		niu_ldg_rearm(np, lp, 1);
	}
	return work_done;
}

static void niu_log_rxchan_errors(struct niu *np, struct rx_ring_info *rp,
				  u64 stat)
{
	netdev_err(np->dev, "RX channel %u errors ( ", rp->rx_channel);

	if (stat & RX_DMA_CTL_STAT_RBR_TMOUT)
		pr_cont("RBR_TMOUT ");
	if (stat & RX_DMA_CTL_STAT_RSP_CNT_ERR)
		pr_cont("RSP_CNT ");
	if (stat & RX_DMA_CTL_STAT_BYTE_EN_BUS)
		pr_cont("BYTE_EN_BUS ");
	if (stat & RX_DMA_CTL_STAT_RSP_DAT_ERR)
		pr_cont("RSP_DAT ");
	if (stat & RX_DMA_CTL_STAT_RCR_ACK_ERR)
		pr_cont("RCR_ACK ");
	if (stat & RX_DMA_CTL_STAT_RCR_SHA_PAR)
		pr_cont("RCR_SHA_PAR ");
	if (stat & RX_DMA_CTL_STAT_RBR_PRE_PAR)
		pr_cont("RBR_PRE_PAR ");
	if (stat & RX_DMA_CTL_STAT_CONFIG_ERR)
		pr_cont("CONFIG ");
	if (stat & RX_DMA_CTL_STAT_RCRINCON)
		pr_cont("RCRINCON ");
	if (stat & RX_DMA_CTL_STAT_RCRFULL)
		pr_cont("RCRFULL ");
	if (stat & RX_DMA_CTL_STAT_RBRFULL)
		pr_cont("RBRFULL ");
	if (stat & RX_DMA_CTL_STAT_RBRLOGPAGE)
		pr_cont("RBRLOGPAGE ");
	if (stat & RX_DMA_CTL_STAT_CFIGLOGPAGE)
		pr_cont("CFIGLOGPAGE ");
	if (stat & RX_DMA_CTL_STAT_DC_FIFO_ERR)
		pr_cont("DC_FIDO ");

	pr_cont(")\n");
}

static int niu_rx_error(struct niu *np, struct rx_ring_info *rp)
{
	u64 stat = nr64(RX_DMA_CTL_STAT(rp->rx_channel));
	int err = 0;


	if (stat & (RX_DMA_CTL_STAT_CHAN_FATAL |
		    RX_DMA_CTL_STAT_PORT_FATAL))
		err = -EINVAL;

	if (err) {
		netdev_err(np->dev, "RX channel %u error, stat[%llx]\n",
			   rp->rx_channel,
			   (unsigned long long) stat);

		niu_log_rxchan_errors(np, rp, stat);
	}

	nw64(RX_DMA_CTL_STAT(rp->rx_channel),
	     stat & RX_DMA_CTL_WRITE_CLEAR_ERRS);

	return err;
}

static void niu_log_txchan_errors(struct niu *np, struct tx_ring_info *rp,
				  u64 cs)
{
	netdev_err(np->dev, "TX channel %u errors ( ", rp->tx_channel);

	if (cs & TX_CS_MBOX_ERR)
		pr_cont("MBOX ");
	if (cs & TX_CS_PKT_SIZE_ERR)
		pr_cont("PKT_SIZE ");
	if (cs & TX_CS_TX_RING_OFLOW)
		pr_cont("TX_RING_OFLOW ");
	if (cs & TX_CS_PREF_BUF_PAR_ERR)
		pr_cont("PREF_BUF_PAR ");
	if (cs & TX_CS_NACK_PREF)
		pr_cont("NACK_PREF ");
	if (cs & TX_CS_NACK_PKT_RD)
		pr_cont("NACK_PKT_RD ");
	if (cs & TX_CS_CONF_PART_ERR)
		pr_cont("CONF_PART ");
	if (cs & TX_CS_PKT_PRT_ERR)
		pr_cont("PKT_PTR ");

	pr_cont(")\n");
}

static int niu_tx_error(struct niu *np, struct tx_ring_info *rp)
{
	u64 cs, logh, logl;

	cs = nr64(TX_CS(rp->tx_channel));
	logh = nr64(TX_RNG_ERR_LOGH(rp->tx_channel));
	logl = nr64(TX_RNG_ERR_LOGL(rp->tx_channel));

	netdev_err(np->dev, "TX channel %u error, cs[%llx] logh[%llx] logl[%llx]\n",
		   rp->tx_channel,
		   (unsigned long long)cs,
		   (unsigned long long)logh,
		   (unsigned long long)logl);

	niu_log_txchan_errors(np, rp, cs);

	return -ENODEV;
}

static int niu_mif_interrupt(struct niu *np)
{
	u64 mif_status = nr64(MIF_STATUS);
	int phy_mdint = 0;

	if (np->flags & NIU_FLAGS_XMAC) {
		u64 xrxmac_stat = nr64_mac(XRXMAC_STATUS);

		if (xrxmac_stat & XRXMAC_STATUS_PHY_MDINT)
			phy_mdint = 1;
	}

	netdev_err(np->dev, "MIF interrupt, stat[%llx] phy_mdint(%d)\n",
		   (unsigned long long)mif_status, phy_mdint);

	return -ENODEV;
}

static void niu_xmac_interrupt(struct niu *np)
{
	struct niu_xmac_stats *mp = &np->mac_stats.xmac;
	u64 val;

	val = nr64_mac(XTXMAC_STATUS);
	if (val & XTXMAC_STATUS_FRAME_CNT_EXP)
		mp->tx_frames += TXMAC_FRM_CNT_COUNT;
	if (val & XTXMAC_STATUS_BYTE_CNT_EXP)
		mp->tx_bytes += TXMAC_BYTE_CNT_COUNT;
	if (val & XTXMAC_STATUS_TXFIFO_XFR_ERR)
		mp->tx_fifo_errors++;
	if (val & XTXMAC_STATUS_TXMAC_OFLOW)
		mp->tx_overflow_errors++;
	if (val & XTXMAC_STATUS_MAX_PSIZE_ERR)
		mp->tx_max_pkt_size_errors++;
	if (val & XTXMAC_STATUS_TXMAC_UFLOW)
		mp->tx_underflow_errors++;

	val = nr64_mac(XRXMAC_STATUS);
	if (val & XRXMAC_STATUS_LCL_FLT_STATUS)
		mp->rx_local_faults++;
	if (val & XRXMAC_STATUS_RFLT_DET)
		mp->rx_remote_faults++;
	if (val & XRXMAC_STATUS_LFLT_CNT_EXP)
		mp->rx_link_faults += LINK_FAULT_CNT_COUNT;
	if (val & XRXMAC_STATUS_ALIGNERR_CNT_EXP)
		mp->rx_align_errors += RXMAC_ALIGN_ERR_CNT_COUNT;
	if (val & XRXMAC_STATUS_RXFRAG_CNT_EXP)
		mp->rx_frags += RXMAC_FRAG_CNT_COUNT;
	if (val & XRXMAC_STATUS_RXMULTF_CNT_EXP)
		mp->rx_mcasts += RXMAC_MC_FRM_CNT_COUNT;
	if (val & XRXMAC_STATUS_RXBCAST_CNT_EXP)
		mp->rx_bcasts += RXMAC_BC_FRM_CNT_COUNT;
	if (val & XRXMAC_STATUS_RXBCAST_CNT_EXP)
		mp->rx_bcasts += RXMAC_BC_FRM_CNT_COUNT;
	if (val & XRXMAC_STATUS_RXHIST1_CNT_EXP)
		mp->rx_hist_cnt1 += RXMAC_HIST_CNT1_COUNT;
	if (val & XRXMAC_STATUS_RXHIST2_CNT_EXP)
		mp->rx_hist_cnt2 += RXMAC_HIST_CNT2_COUNT;
	if (val & XRXMAC_STATUS_RXHIST3_CNT_EXP)
		mp->rx_hist_cnt3 += RXMAC_HIST_CNT3_COUNT;
	if (val & XRXMAC_STATUS_RXHIST4_CNT_EXP)
		mp->rx_hist_cnt4 += RXMAC_HIST_CNT4_COUNT;
	if (val & XRXMAC_STATUS_RXHIST5_CNT_EXP)
		mp->rx_hist_cnt5 += RXMAC_HIST_CNT5_COUNT;
	if (val & XRXMAC_STATUS_RXHIST6_CNT_EXP)
		mp->rx_hist_cnt6 += RXMAC_HIST_CNT6_COUNT;
	if (val & XRXMAC_STATUS_RXHIST7_CNT_EXP)
		mp->rx_hist_cnt7 += RXMAC_HIST_CNT7_COUNT;
	if (val & XRXMAC_STATUS_RXOCTET_CNT_EXP)
		mp->rx_octets += RXMAC_BT_CNT_COUNT;
	if (val & XRXMAC_STATUS_CVIOLERR_CNT_EXP)
		mp->rx_code_violations += RXMAC_CD_VIO_CNT_COUNT;
	if (val & XRXMAC_STATUS_LENERR_CNT_EXP)
		mp->rx_len_errors += RXMAC_MPSZER_CNT_COUNT;
	if (val & XRXMAC_STATUS_CRCERR_CNT_EXP)
		mp->rx_crc_errors += RXMAC_CRC_ER_CNT_COUNT;
	if (val & XRXMAC_STATUS_RXUFLOW)
		mp->rx_underflows++;
	if (val & XRXMAC_STATUS_RXOFLOW)
		mp->rx_overflows++;

	val = nr64_mac(XMAC_FC_STAT);
	if (val & XMAC_FC_STAT_TX_MAC_NPAUSE)
		mp->pause_off_state++;
	if (val & XMAC_FC_STAT_TX_MAC_PAUSE)
		mp->pause_on_state++;
	if (val & XMAC_FC_STAT_RX_MAC_RPAUSE)
		mp->pause_received++;
}

static void niu_bmac_interrupt(struct niu *np)
{
	struct niu_bmac_stats *mp = &np->mac_stats.bmac;
	u64 val;

	val = nr64_mac(BTXMAC_STATUS);
	if (val & BTXMAC_STATUS_UNDERRUN)
		mp->tx_underflow_errors++;
	if (val & BTXMAC_STATUS_MAX_PKT_ERR)
		mp->tx_max_pkt_size_errors++;
	if (val & BTXMAC_STATUS_BYTE_CNT_EXP)
		mp->tx_bytes += BTXMAC_BYTE_CNT_COUNT;
	if (val & BTXMAC_STATUS_FRAME_CNT_EXP)
		mp->tx_frames += BTXMAC_FRM_CNT_COUNT;

	val = nr64_mac(BRXMAC_STATUS);
	if (val & BRXMAC_STATUS_OVERFLOW)
		mp->rx_overflows++;
	if (val & BRXMAC_STATUS_FRAME_CNT_EXP)
		mp->rx_frames += BRXMAC_FRAME_CNT_COUNT;
	if (val & BRXMAC_STATUS_ALIGN_ERR_EXP)
		mp->rx_align_errors += BRXMAC_ALIGN_ERR_CNT_COUNT;
	if (val & BRXMAC_STATUS_CRC_ERR_EXP)
		mp->rx_crc_errors += BRXMAC_ALIGN_ERR_CNT_COUNT;
	if (val & BRXMAC_STATUS_LEN_ERR_EXP)
		mp->rx_len_errors += BRXMAC_CODE_VIOL_ERR_CNT_COUNT;

	val = nr64_mac(BMAC_CTRL_STATUS);
	if (val & BMAC_CTRL_STATUS_NOPAUSE)
		mp->pause_off_state++;
	if (val & BMAC_CTRL_STATUS_PAUSE)
		mp->pause_on_state++;
	if (val & BMAC_CTRL_STATUS_PAUSE_RECV)
		mp->pause_received++;
}

static int niu_mac_interrupt(struct niu *np)
{
	if (np->flags & NIU_FLAGS_XMAC)
		niu_xmac_interrupt(np);
	else
		niu_bmac_interrupt(np);

	return 0;
}

static void niu_log_device_error(struct niu *np, u64 stat)
{
	netdev_err(np->dev, "Core device errors ( ");

	if (stat & SYS_ERR_MASK_META2)
		pr_cont("META2 ");
	if (stat & SYS_ERR_MASK_META1)
		pr_cont("META1 ");
	if (stat & SYS_ERR_MASK_PEU)
		pr_cont("PEU ");
	if (stat & SYS_ERR_MASK_TXC)
		pr_cont("TXC ");
	if (stat & SYS_ERR_MASK_RDMC)
		pr_cont("RDMC ");
	if (stat & SYS_ERR_MASK_TDMC)
		pr_cont("TDMC ");
	if (stat & SYS_ERR_MASK_ZCP)
		pr_cont("ZCP ");
	if (stat & SYS_ERR_MASK_FFLP)
		pr_cont("FFLP ");
	if (stat & SYS_ERR_MASK_IPP)
		pr_cont("IPP ");
	if (stat & SYS_ERR_MASK_MAC)
		pr_cont("MAC ");
	if (stat & SYS_ERR_MASK_SMX)
		pr_cont("SMX ");

	pr_cont(")\n");
}

static int niu_device_error(struct niu *np)
{
	u64 stat = nr64(SYS_ERR_STAT);

	netdev_err(np->dev, "Core device error, stat[%llx]\n",
		   (unsigned long long)stat);

	niu_log_device_error(np, stat);

	return -ENODEV;
}

static int niu_slowpath_interrupt(struct niu *np, struct niu_ldg *lp,
			      u64 v0, u64 v1, u64 v2)
{

	int i, err = 0;

	lp->v0 = v0;
	lp->v1 = v1;
	lp->v2 = v2;

	if (v1 & 0x00000000ffffffffULL) {
		u32 rx_vec = (v1 & 0xffffffff);

		for (i = 0; i < np->num_rx_rings; i++) {
			struct rx_ring_info *rp = &np->rx_rings[i];

			if (rx_vec & (1 << rp->rx_channel)) {
				int r = niu_rx_error(np, rp);
				if (r) {
					err = r;
				} else {
					if (!v0)
						nw64(RX_DMA_CTL_STAT(rp->rx_channel),
						     RX_DMA_CTL_STAT_MEX);
				}
			}
		}
	}
	if (v1 & 0x7fffffff00000000ULL) {
		u32 tx_vec = (v1 >> 32) & 0x7fffffff;

		for (i = 0; i < np->num_tx_rings; i++) {
			struct tx_ring_info *rp = &np->tx_rings[i];

			if (tx_vec & (1 << rp->tx_channel)) {
				int r = niu_tx_error(np, rp);
				if (r)
					err = r;
			}
		}
	}
	if ((v0 | v1) & 0x8000000000000000ULL) {
		int r = niu_mif_interrupt(np);
		if (r)
			err = r;
	}
	if (v2) {
		if (v2 & 0x01ef) {
			int r = niu_mac_interrupt(np);
			if (r)
				err = r;
		}
		if (v2 & 0x0210) {
			int r = niu_device_error(np);
			if (r)
				err = r;
		}
	}

	if (err)
		niu_enable_interrupts(np, 0);

	return err;
}

static void niu_rxchan_intr(struct niu *np, struct rx_ring_info *rp,
			    int ldn)
{
	struct rxdma_mailbox *mbox = rp->mbox;
	u64 stat_write, stat = le64_to_cpup(&mbox->rx_dma_ctl_stat);

	stat_write = (RX_DMA_CTL_STAT_RCRTHRES |
		      RX_DMA_CTL_STAT_RCRTO);
	nw64(RX_DMA_CTL_STAT(rp->rx_channel), stat_write);

	netif_printk(np, intr, KERN_DEBUG, np->dev,
		     "%s() stat[%llx]\n", __func__, (unsigned long long)stat);
}

static void niu_txchan_intr(struct niu *np, struct tx_ring_info *rp,
			    int ldn)
{
	rp->tx_cs = nr64(TX_CS(rp->tx_channel));

	netif_printk(np, intr, KERN_DEBUG, np->dev,
		     "%s() cs[%llx]\n", __func__, (unsigned long long)rp->tx_cs);
}

static void __niu_fastpath_interrupt(struct niu *np, int ldg, u64 v0)
{
	struct niu_parent *parent = np->parent;
	u32 rx_vec, tx_vec;
	int i;

	tx_vec = (v0 >> 32);
	rx_vec = (v0 & 0xffffffff);

	for (i = 0; i < np->num_rx_rings; i++) {
		struct rx_ring_info *rp = &np->rx_rings[i];
		int ldn = LDN_RXDMA(rp->rx_channel);

		if (parent->ldg_map[ldn] != ldg)
			continue;

		nw64(LD_IM0(ldn), LD_IM0_MASK);
		if (rx_vec & (1 << rp->rx_channel))
			niu_rxchan_intr(np, rp, ldn);
	}

	for (i = 0; i < np->num_tx_rings; i++) {
		struct tx_ring_info *rp = &np->tx_rings[i];
		int ldn = LDN_TXDMA(rp->tx_channel);

		if (parent->ldg_map[ldn] != ldg)
			continue;

		nw64(LD_IM0(ldn), LD_IM0_MASK);
		if (tx_vec & (1 << rp->tx_channel))
			niu_txchan_intr(np, rp, ldn);
	}
}

static void niu_schedule_napi(struct niu *np, struct niu_ldg *lp,
			      u64 v0, u64 v1, u64 v2)
{
	if (likely(napi_schedule_prep(&lp->napi))) {
		lp->v0 = v0;
		lp->v1 = v1;
		lp->v2 = v2;
		__niu_fastpath_interrupt(np, lp->ldg_num, v0);
		__napi_schedule(&lp->napi);
	}
}

static irqreturn_t niu_interrupt(int irq, void *dev_id)
{
	struct niu_ldg *lp = dev_id;
	struct niu *np = lp->np;
	int ldg = lp->ldg_num;
	unsigned long flags;
	u64 v0, v1, v2;

	if (netif_msg_intr(np))
		printk(KERN_DEBUG KBUILD_MODNAME ": " "%s() ldg[%p](%d)",
		       __func__, lp, ldg);

	spin_lock_irqsave(&np->lock, flags);

	v0 = nr64(LDSV0(ldg));
	v1 = nr64(LDSV1(ldg));
	v2 = nr64(LDSV2(ldg));

	if (netif_msg_intr(np))
		pr_cont(" v0[%llx] v1[%llx] v2[%llx]\n",
		       (unsigned long long) v0,
		       (unsigned long long) v1,
		       (unsigned long long) v2);

	if (unlikely(!v0 && !v1 && !v2)) {
		spin_unlock_irqrestore(&np->lock, flags);
		return IRQ_NONE;
	}

	if (unlikely((v0 & ((u64)1 << LDN_MIF)) || v1 || v2)) {
		int err = niu_slowpath_interrupt(np, lp, v0, v1, v2);
		if (err)
			goto out;
	}
	if (likely(v0 & ~((u64)1 << LDN_MIF)))
		niu_schedule_napi(np, lp, v0, v1, v2);
	else
		niu_ldg_rearm(np, lp, 1);
out:
	spin_unlock_irqrestore(&np->lock, flags);

	return IRQ_HANDLED;
}

static void niu_free_rx_ring_info(struct niu *np, struct rx_ring_info *rp)
{
	if (rp->mbox) {
		np->ops->free_coherent(np->device,
				       sizeof(struct rxdma_mailbox),
				       rp->mbox, rp->mbox_dma);
		rp->mbox = NULL;
	}
	if (rp->rcr) {
		np->ops->free_coherent(np->device,
				       MAX_RCR_RING_SIZE * sizeof(__le64),
				       rp->rcr, rp->rcr_dma);
		rp->rcr = NULL;
		rp->rcr_table_size = 0;
		rp->rcr_index = 0;
	}
	if (rp->rbr) {
		niu_rbr_free(np, rp);

		np->ops->free_coherent(np->device,
				       MAX_RBR_RING_SIZE * sizeof(__le32),
				       rp->rbr, rp->rbr_dma);
		rp->rbr = NULL;
		rp->rbr_table_size = 0;
		rp->rbr_index = 0;
	}
	kfree(rp->rxhash);
	rp->rxhash = NULL;
}

static void niu_free_tx_ring_info(struct niu *np, struct tx_ring_info *rp)
{
	if (rp->mbox) {
		np->ops->free_coherent(np->device,
				       sizeof(struct txdma_mailbox),
				       rp->mbox, rp->mbox_dma);
		rp->mbox = NULL;
	}
	if (rp->descr) {
		int i;

		for (i = 0; i < MAX_TX_RING_SIZE; i++) {
			if (rp->tx_buffs[i].skb)
				(void) release_tx_packet(np, rp, i);
		}

		np->ops->free_coherent(np->device,
				       MAX_TX_RING_SIZE * sizeof(__le64),
				       rp->descr, rp->descr_dma);
		rp->descr = NULL;
		rp->pending = 0;
		rp->prod = 0;
		rp->cons = 0;
		rp->wrap_bit = 0;
	}
}

static void niu_free_channels(struct niu *np)
{
	int i;

	if (np->rx_rings) {
		for (i = 0; i < np->num_rx_rings; i++) {
			struct rx_ring_info *rp = &np->rx_rings[i];

			niu_free_rx_ring_info(np, rp);
		}
		kfree(np->rx_rings);
		np->rx_rings = NULL;
		np->num_rx_rings = 0;
	}

	if (np->tx_rings) {
		for (i = 0; i < np->num_tx_rings; i++) {
			struct tx_ring_info *rp = &np->tx_rings[i];

			niu_free_tx_ring_info(np, rp);
		}
		kfree(np->tx_rings);
		np->tx_rings = NULL;
		np->num_tx_rings = 0;
	}
}

static int niu_alloc_rx_ring_info(struct niu *np,
				  struct rx_ring_info *rp)
{
	BUILD_BUG_ON(sizeof(struct rxdma_mailbox) != 64);

	rp->rxhash = kzalloc(MAX_RBR_RING_SIZE * sizeof(struct page *),
			     GFP_KERNEL);
	if (!rp->rxhash)
		return -ENOMEM;

	rp->mbox = np->ops->alloc_coherent(np->device,
					   sizeof(struct rxdma_mailbox),
					   &rp->mbox_dma, GFP_KERNEL);
	if (!rp->mbox)
		return -ENOMEM;
	if ((unsigned long)rp->mbox & (64UL - 1)) {
		netdev_err(np->dev, "Coherent alloc gives misaligned RXDMA mailbox %p\n",
			   rp->mbox);
		return -EINVAL;
	}

	rp->rcr = np->ops->alloc_coherent(np->device,
					  MAX_RCR_RING_SIZE * sizeof(__le64),
					  &rp->rcr_dma, GFP_KERNEL);
	if (!rp->rcr)
		return -ENOMEM;
	if ((unsigned long)rp->rcr & (64UL - 1)) {
		netdev_err(np->dev, "Coherent alloc gives misaligned RXDMA RCR table %p\n",
			   rp->rcr);
		return -EINVAL;
	}
	rp->rcr_table_size = MAX_RCR_RING_SIZE;
	rp->rcr_index = 0;

	rp->rbr = np->ops->alloc_coherent(np->device,
					  MAX_RBR_RING_SIZE * sizeof(__le32),
					  &rp->rbr_dma, GFP_KERNEL);
	if (!rp->rbr)
		return -ENOMEM;
	if ((unsigned long)rp->rbr & (64UL - 1)) {
		netdev_err(np->dev, "Coherent alloc gives misaligned RXDMA RBR table %p\n",
			   rp->rbr);
		return -EINVAL;
	}
	rp->rbr_table_size = MAX_RBR_RING_SIZE;
	rp->rbr_index = 0;
	rp->rbr_pending = 0;

	return 0;
}

static void niu_set_max_burst(struct niu *np, struct tx_ring_info *rp)
{
	int mtu = np->dev->mtu;

	/* These values are recommended by the HW designers for fair
 * utilization of DRR amongst the rings.
 */
	rp->max_burst = mtu + 32;
	if (rp->max_burst > 4096)
		rp->max_burst = 4096;
}

static int niu_alloc_tx_ring_info(struct niu *np,
				  struct tx_ring_info *rp)
{
	BUILD_BUG_ON(sizeof(struct txdma_mailbox) != 64);

	rp->mbox = np->ops->alloc_coherent(np->device,
					   sizeof(struct txdma_mailbox),
					   &rp->mbox_dma, GFP_KERNEL);
	if (!rp->mbox)
		return -ENOMEM;
	if ((unsigned long)rp->mbox & (64UL - 1)) {
		netdev_err(np->dev, "Coherent alloc gives misaligned TXDMA mailbox %p\n",
			   rp->mbox);
		return -EINVAL;
	}

	rp->descr = np->ops->alloc_coherent(np->device,
					    MAX_TX_RING_SIZE * sizeof(__le64),
					    &rp->descr_dma, GFP_KERNEL);
	if (!rp->descr)
		return -ENOMEM;
	if ((unsigned long)rp->descr & (64UL - 1)) {
		netdev_err(np->dev, "Coherent alloc gives misaligned TXDMA descr table %p\n",
			   rp->descr);
		return -EINVAL;
	}

	rp->pending = MAX_TX_RING_SIZE;
	rp->prod = 0;
	rp->cons = 0;
	rp->wrap_bit = 0;

	/* XXX make these configurable... XXX */
	rp->mark_freq = rp->pending / 4;

	niu_set_max_burst(np, rp);

	return 0;
}

static void niu_size_rbr(struct niu *np, struct rx_ring_info *rp)
{
	u16 bss;

	bss = min(PAGE_SHIFT, 15);

	rp->rbr_block_size = 1 << bss;
	rp->rbr_blocks_per_page = 1 << (PAGE_SHIFT-bss);

	rp->rbr_sizes[0] = 256;
	rp->rbr_sizes[1] = 1024;
	if (np->dev->mtu > ETH_DATA_LEN) {
		switch (PAGE_SIZE) {
		case 4 * 1024:
			rp->rbr_sizes[2] = 4096;
			break;

		default:
			rp->rbr_sizes[2] = 8192;
			break;
		}
	} else {
		rp->rbr_sizes[2] = 2048;
	}
	rp->rbr_sizes[3] = rp->rbr_block_size;
}

static int niu_alloc_channels(struct niu *np)
{
	struct niu_parent *parent = np->parent;
	int first_rx_channel, first_tx_channel;
	int i, port, err;

	port = np->port;
	first_rx_channel = first_tx_channel = 0;
	for (i = 0; i < port; i++) {
		first_rx_channel += parent->rxchan_per_port[i];
		first_tx_channel += parent->txchan_per_port[i];
	}

	np->num_rx_rings = parent->rxchan_per_port[port];
	np->num_tx_rings = parent->txchan_per_port[port];

	np->dev->real_num_tx_queues = np->num_tx_rings;

	np->rx_rings = kzalloc(np->num_rx_rings * sizeof(struct rx_ring_info),
			       GFP_KERNEL);
	err = -ENOMEM;
	if (!np->rx_rings)
		goto out_err;

	for (i = 0; i < np->num_rx_rings; i++) {
		struct rx_ring_info *rp = &np->rx_rings[i];

		rp->np = np;
		rp->rx_channel = first_rx_channel + i;

		err = niu_alloc_rx_ring_info(np, rp);
		if (err)
			goto out_err;

		niu_size_rbr(np, rp);

		/* XXX better defaults, configurable, etc... XXX */
		rp->nonsyn_window = 64;
		rp->nonsyn_threshold = rp->rcr_table_size - 64;
		rp->syn_window = 64;
		rp->syn_threshold = rp->rcr_table_size - 64;
		rp->rcr_pkt_threshold = 16;
		rp->rcr_timeout = 8;
		rp->rbr_kick_thresh = RBR_REFILL_MIN;
		if (rp->rbr_kick_thresh < rp->rbr_blocks_per_page)
			rp->rbr_kick_thresh = rp->rbr_blocks_per_page;

		err = niu_rbr_fill(np, rp, GFP_KERNEL);
		if (err)
			return err;
	}

	np->tx_rings = kzalloc(np->num_tx_rings * sizeof(struct tx_ring_info),
			       GFP_KERNEL);
	err = -ENOMEM;
	if (!np->tx_rings)
		goto out_err;

	for (i = 0; i < np->num_tx_rings; i++) {
		struct tx_ring_info *rp = &np->tx_rings[i];

		rp->np = np;
		rp->tx_channel = first_tx_channel + i;

		err = niu_alloc_tx_ring_info(np, rp);
		if (err)
			goto out_err;
	}

	return 0;

out_err:
	niu_free_channels(np);
	return err;
}

static int niu_tx_cs_sng_poll(struct niu *np, int channel)
{
	int limit = 1000;

	while (--limit > 0) {
		u64 val = nr64(TX_CS(channel));
		if (val & TX_CS_SNG_STATE)
			return 0;
	}
	return -ENODEV;
}

static int niu_tx_channel_stop(struct niu *np, int channel)
{
	u64 val = nr64(TX_CS(channel));

	val |= TX_CS_STOP_N_GO;
	nw64(TX_CS(channel), val);

	return niu_tx_cs_sng_poll(np, channel);
}

static int niu_tx_cs_reset_poll(struct niu *np, int channel)
{
	int limit = 1000;

	while (--limit > 0) {
		u64 val = nr64(TX_CS(channel));
		if (!(val & TX_CS_RST))
			return 0;
	}
	return -ENODEV;
}

static int niu_tx_channel_reset(struct niu *np, int channel)
{
	u64 val = nr64(TX_CS(channel));
	int err;

	val |= TX_CS_RST;
	nw64(TX_CS(channel), val);

	err = niu_tx_cs_reset_poll(np, channel);
	if (!err)
		nw64(TX_RING_KICK(channel), 0);

	return err;
}

static int niu_tx_channel_lpage_init(struct niu *np, int channel)
{
	u64 val;

	nw64(TX_LOG_MASK1(channel), 0);
	nw64(TX_LOG_VAL1(channel), 0);
	nw64(TX_LOG_MASK2(channel), 0);
	nw64(TX_LOG_VAL2(channel), 0);
	nw64(TX_LOG_PAGE_RELO1(channel), 0);
	nw64(TX_LOG_PAGE_RELO2(channel), 0);
	nw64(TX_LOG_PAGE_HDL(channel), 0);

	val  = (u64)np->port << TX_LOG_PAGE_VLD_FUNC_SHIFT;
	val |= (TX_LOG_PAGE_VLD_PAGE0 | TX_LOG_PAGE_VLD_PAGE1);
	nw64(TX_LOG_PAGE_VLD(channel), val);

	/* XXX TXDMA 32bit mode? XXX */

	return 0;
}

static void niu_txc_enable_port(struct niu *np, int on)
{
	unsigned long flags;
	u64 val, mask;

	niu_lock_parent(np, flags);
	val = nr64(TXC_CONTROL);
	mask = (u64)1 << np->port;
	if (on) {
		val |= TXC_CONTROL_ENABLE | mask;
	} else {
		val &= ~mask;
		if ((val & ~TXC_CONTROL_ENABLE) == 0)
			val &= ~TXC_CONTROL_ENABLE;
	}
	nw64(TXC_CONTROL, val);
	niu_unlock_parent(np, flags);
}

static void niu_txc_set_imask(struct niu *np, u64 imask)
{
	unsigned long flags;
	u64 val;

	niu_lock_parent(np, flags);
	val = nr64(TXC_INT_MASK);
	val &= ~TXC_INT_MASK_VAL(np->port);
	val |= (imask << TXC_INT_MASK_VAL_SHIFT(np->port));
	niu_unlock_parent(np, flags);
}

static void niu_txc_port_dma_enable(struct niu *np, int on)
{
	u64 val = 0;

	if (on) {
		int i;

		for (i = 0; i < np->num_tx_rings; i++)
			val |= (1 << np->tx_rings[i].tx_channel);
	}
	nw64(TXC_PORT_DMA(np->port), val);
}

static int niu_init_one_tx_channel(struct niu *np, struct tx_ring_info *rp)
{
	int err, channel = rp->tx_channel;
	u64 val, ring_len;

	err = niu_tx_channel_stop(np, channel);
	if (err)
		return err;

	err = niu_tx_channel_reset(np, channel);
	if (err)
		return err;

	err = niu_tx_channel_lpage_init(np, channel);
	if (err)
		return err;

	nw64(TXC_DMA_MAX(channel), rp->max_burst);
	nw64(TX_ENT_MSK(channel), 0);

	if (rp->descr_dma & ~(TX_RNG_CFIG_STADDR_BASE |
			      TX_RNG_CFIG_STADDR)) {
		netdev_err(np->dev, "TX ring channel %d DMA addr (%llx) is not aligned\n",
			   channel, (unsigned long long)rp->descr_dma);
		return -EINVAL;
	}

	/* The length field in TX_RNG_CFIG is measured in 64-byte
 * blocks. rp->pending is the number of TX descriptors in
 * our ring, 8 bytes each, thus we divide by 8 bytes more
 * to get the proper value the chip wants.
 */
	ring_len = (rp->pending / 8);

	val = ((ring_len << TX_RNG_CFIG_LEN_SHIFT) |
	       rp->descr_dma);
	nw64(TX_RNG_CFIG(channel), val);

	if (((rp->mbox_dma >> 32) & ~TXDMA_MBH_MBADDR) ||
	    ((u32)rp->mbox_dma & ~TXDMA_MBL_MBADDR)) {
		netdev_err(np->dev, "TX ring channel %d MBOX addr (%llx) has invalid bits\n",
			    channel, (unsigned long long)rp->mbox_dma);
		return -EINVAL;
	}
	nw64(TXDMA_MBH(channel), rp->mbox_dma >> 32);
	nw64(TXDMA_MBL(channel), rp->mbox_dma & TXDMA_MBL_MBADDR);

	nw64(TX_CS(channel), 0);

	rp->last_pkt_cnt = 0;

	return 0;
}

static void niu_init_rdc_groups(struct niu *np)
{
	struct niu_rdc_tables *tp = &np->parent->rdc_group_cfg[np->port];
	int i, first_table_num = tp->first_table_num;

	for (i = 0; i < tp->num_tables; i++) {
		struct rdc_table *tbl = &tp->tables[i];
		int this_table = first_table_num + i;
		int slot;

		for (slot = 0; slot < NIU_RDC_TABLE_SLOTS; slot++)
			nw64(RDC_TBL(this_table, slot),
			     tbl->rxdma_channel[slot]);
	}

	nw64(DEF_RDC(np->port), np->parent->rdc_default[np->port]);
}

static void niu_init_drr_weight(struct niu *np)
{
	int type = phy_decode(np->parent->port_phy, np->port);
	u64 val;

	switch (type) {
	case PORT_TYPE_10G:
		val = PT_DRR_WEIGHT_DEFAULT_10G;
		break;

	case PORT_TYPE_1G:
	default:
		val = PT_DRR_WEIGHT_DEFAULT_1G;
		break;
	}
	nw64(PT_DRR_WT(np->port), val);
}

static int niu_init_hostinfo(struct niu *np)
{
	struct niu_parent *parent = np->parent;
	struct niu_rdc_tables *tp = &parent->rdc_group_cfg[np->port];
	int i, err, num_alt = niu_num_alt_addr(np);
	int first_rdc_table = tp->first_table_num;

	err = niu_set_primary_mac_rdc_table(np, first_rdc_table, 1);
	if (err)
		return err;

	err = niu_set_multicast_mac_rdc_table(np, first_rdc_table, 1);
	if (err)
		return err;

	for (i = 0; i < num_alt; i++) {
		err = niu_set_alt_mac_rdc_table(np, i, first_rdc_table, 1);
		if (err)
			return err;
	}

	return 0;
}

static int niu_rx_channel_reset(struct niu *np, int channel)
{
	return niu_set_and_wait_clear(np, RXDMA_CFIG1(channel),
				      RXDMA_CFIG1_RST, 1000, 10,
				      "RXDMA_CFIG1");
}

static int niu_rx_channel_lpage_init(struct niu *np, int channel)
{
	u64 val;

	nw64(RX_LOG_MASK1(channel), 0);
	nw64(RX_LOG_VAL1(channel), 0);
	nw64(RX_LOG_MASK2(channel), 0);
	nw64(RX_LOG_VAL2(channel), 0);
	nw64(RX_LOG_PAGE_RELO1(channel), 0);
	nw64(RX_LOG_PAGE_RELO2(channel), 0);
	nw64(RX_LOG_PAGE_HDL(channel), 0);

	val  = (u64)np->port << RX_LOG_PAGE_VLD_FUNC_SHIFT;
	val |= (RX_LOG_PAGE_VLD_PAGE0 | RX_LOG_PAGE_VLD_PAGE1);
	nw64(RX_LOG_PAGE_VLD(channel), val);

	return 0;
}

static void niu_rx_channel_wred_init(struct niu *np, struct rx_ring_info *rp)
{
	u64 val;

	val = (((u64)rp->nonsyn_window << RDC_RED_PARA_WIN_SHIFT) |
	       ((u64)rp->nonsyn_threshold << RDC_RED_PARA_THRE_SHIFT) |
	       ((u64)rp->syn_window << RDC_RED_PARA_WIN_SYN_SHIFT) |
	       ((u64)rp->syn_threshold << RDC_RED_PARA_THRE_SYN_SHIFT));
	nw64(RDC_RED_PARA(rp->rx_channel), val);
}

static int niu_compute_rbr_cfig_b(struct rx_ring_info *rp, u64 *ret)
{
	u64 val = 0;

	*ret = 0;
	switch (rp->rbr_block_size) {
	case 4 * 1024:
		val |= (RBR_BLKSIZE_4K << RBR_CFIG_B_BLKSIZE_SHIFT);
		break;
	case 8 * 1024:
		val |= (RBR_BLKSIZE_8K << RBR_CFIG_B_BLKSIZE_SHIFT);
		break;
	case 16 * 1024:
		val |= (RBR_BLKSIZE_16K << RBR_CFIG_B_BLKSIZE_SHIFT);
		break;
	case 32 * 1024:
		val |= (RBR_BLKSIZE_32K << RBR_CFIG_B_BLKSIZE_SHIFT);
		break;
	default:
		return -EINVAL;
	}
	val |= RBR_CFIG_B_VLD2;
	switch (rp->rbr_sizes[2]) {
	case 2 * 1024:
		val |= (RBR_BUFSZ2_2K << RBR_CFIG_B_BUFSZ2_SHIFT);
		break;
	case 4 * 1024:
		val |= (RBR_BUFSZ2_4K << RBR_CFIG_B_BUFSZ2_SHIFT);
		break;
	case 8 * 1024:
		val |= (RBR_BUFSZ2_8K << RBR_CFIG_B_BUFSZ2_SHIFT);
		break;
	case 16 * 1024:
		val |= (RBR_BUFSZ2_16K << RBR_CFIG_B_BUFSZ2_SHIFT);
		break;

	default:
		return -EINVAL;
	}
	val |= RBR_CFIG_B_VLD1;
	switch (rp->rbr_sizes[1]) {
	case 1 * 1024:
		val |= (RBR_BUFSZ1_1K << RBR_CFIG_B_BUFSZ1_SHIFT);
		break;
	case 2 * 1024:
		val |= (RBR_BUFSZ1_2K << RBR_CFIG_B_BUFSZ1_SHIFT);
		break;
	case 4 * 1024:
		val |= (RBR_BUFSZ1_4K << RBR_CFIG_B_BUFSZ1_SHIFT);
		break;
	case 8 * 1024:
		val |= (RBR_BUFSZ1_8K << RBR_CFIG_B_BUFSZ1_SHIFT);
		break;

	default:
		return -EINVAL;
	}
	val |= RBR_CFIG_B_VLD0;
	switch (rp->rbr_sizes[0]) {
	case 256:
		val |= (RBR_BUFSZ0_256 << RBR_CFIG_B_BUFSZ0_SHIFT);
		break;
	case 512:
		val |= (RBR_BUFSZ0_512 << RBR_CFIG_B_BUFSZ0_SHIFT);
		break;
	case 1 * 1024:
		val |= (RBR_BUFSZ0_1K << RBR_CFIG_B_BUFSZ0_SHIFT);
		break;
	case 2 * 1024:
		val |= (RBR_BUFSZ0_2K << RBR_CFIG_B_BUFSZ0_SHIFT);
		break;

	default:
		return -EINVAL;
	}

	*ret = val;
	return 0;
}

static int niu_enable_rx_channel(struct niu *np, int channel, int on)
{
	u64 val = nr64(RXDMA_CFIG1(channel));
	int limit;

	if (on)
		val |= RXDMA_CFIG1_EN;
	else
		val &= ~RXDMA_CFIG1_EN;
	nw64(RXDMA_CFIG1(channel), val);

	limit = 1000;
	while (--limit > 0) {
		if (nr64(RXDMA_CFIG1(channel)) & RXDMA_CFIG1_QST)
			break;
		udelay(10);
	}
	if (limit <= 0)
		return -ENODEV;
	return 0;
}

static int niu_init_one_rx_channel(struct niu *np, struct rx_ring_info *rp)
{
	int err, channel = rp->rx_channel;
	u64 val;

	err = niu_rx_channel_reset(np, channel);
	if (err)
		return err;

	err = niu_rx_channel_lpage_init(np, channel);
	if (err)
		return err;

	niu_rx_channel_wred_init(np, rp);

	nw64(RX_DMA_ENT_MSK(channel), RX_DMA_ENT_MSK_RBR_EMPTY);
	nw64(RX_DMA_CTL_STAT(channel),
	     (RX_DMA_CTL_STAT_MEX |
	      RX_DMA_CTL_STAT_RCRTHRES |
	      RX_DMA_CTL_STAT_RCRTO |
	      RX_DMA_CTL_STAT_RBR_EMPTY));
	nw64(RXDMA_CFIG1(channel), rp->mbox_dma >> 32);
	nw64(RXDMA_CFIG2(channel),
	     ((rp->mbox_dma & RXDMA_CFIG2_MBADDR_L) |
	      RXDMA_CFIG2_FULL_HDR));
	nw64(RBR_CFIG_A(channel),
	     ((u64)rp->rbr_table_size << RBR_CFIG_A_LEN_SHIFT) |
	     (rp->rbr_dma & (RBR_CFIG_A_STADDR_BASE | RBR_CFIG_A_STADDR)));
	err = niu_compute_rbr_cfig_b(rp, &val);
	if (err)
		return err;
	nw64(RBR_CFIG_B(channel), val);
	nw64(RCRCFIG_A(channel),
	     ((u64)rp->rcr_table_size << RCRCFIG_A_LEN_SHIFT) |
	     (rp->rcr_dma & (RCRCFIG_A_STADDR_BASE | RCRCFIG_A_STADDR)));
	nw64(RCRCFIG_B(channel),
	     ((u64)rp->rcr_pkt_threshold << RCRCFIG_B_PTHRES_SHIFT) |
	     RCRCFIG_B_ENTOUT |
	     ((u64)rp->rcr_timeout << RCRCFIG_B_TIMEOUT_SHIFT));

	err = niu_enable_rx_channel(np, channel, 1);
	if (err)
		return err;

	nw64(RBR_KICK(channel), rp->rbr_index);

	val = nr64(RX_DMA_CTL_STAT(channel));
	val |= RX_DMA_CTL_STAT_RBR_EMPTY;
	nw64(RX_DMA_CTL_STAT(channel), val);

	return 0;
}

static int niu_init_rx_channels(struct niu *np)
{
	unsigned long flags;
	u64 seed = jiffies_64;
	int err, i;

	niu_lock_parent(np, flags);
	nw64(RX_DMA_CK_DIV, np->parent->rxdma_clock_divider);
	nw64(RED_RAN_INIT, RED_RAN_INIT_OPMODE | (seed & RED_RAN_INIT_VAL));
	niu_unlock_parent(np, flags);

	/* XXX RXDMA 32bit mode? XXX */

	niu_init_rdc_groups(np);
	niu_init_drr_weight(np);

	err = niu_init_hostinfo(np);
	if (err)
		return err;

	for (i = 0; i < np->num_rx_rings; i++) {
		struct rx_ring_info *rp = &np->rx_rings[i];

		err = niu_init_one_rx_channel(np, rp);
		if (err)
			return err;
	}

	return 0;
}

static int niu_set_ip_frag_rule(struct niu *np)
{
	struct niu_parent *parent = np->parent;
	struct niu_classifier *cp = &np->clas;
	struct niu_tcam_entry *tp;
	int index, err;

	index = cp->tcam_top;
	tp = &parent->tcam[index];

	/* Note that the noport bit is the same in both ipv4 and
 * ipv6 format TCAM entries.
 */
	memset(tp, 0, sizeof(*tp));
	tp->key[1] = TCAM_V4KEY1_NOPORT;
	tp->key_mask[1] = TCAM_V4KEY1_NOPORT;
	tp->assoc_data = (TCAM_ASSOCDATA_TRES_USE_OFFSET |
			  ((u64)0 << TCAM_ASSOCDATA_OFFSET_SHIFT));
	err = tcam_write(np, index, tp->key, tp->key_mask);
	if (err)
		return err;
	err = tcam_assoc_write(np, index, tp->assoc_data);
	if (err)
		return err;
	tp->valid = 1;
	cp->tcam_valid_entries++;

	return 0;
}

static int niu_init_classifier_hw(struct niu *np)
{
	struct niu_parent *parent = np->parent;
	struct niu_classifier *cp = &np->clas;
	int i, err;

	nw64(H1POLY, cp->h1_init);
	nw64(H2POLY, cp->h2_init);

	err = niu_init_hostinfo(np);
	if (err)
		return err;

	for (i = 0; i < ENET_VLAN_TBL_NUM_ENTRIES; i++) {
		struct niu_vlan_rdc *vp = &cp->vlan_mappings[i];

		vlan_tbl_write(np, i, np->port,
			       vp->vlan_pref, vp->rdc_num);
	}

	for (i = 0; i < cp->num_alt_mac_mappings; i++) {
		struct niu_altmac_rdc *ap = &cp->alt_mac_mappings[i];

		err = niu_set_alt_mac_rdc_table(np, ap->alt_mac_num,
						ap->rdc_num, ap->mac_pref);
		if (err)
			return err;
	}

	for (i = CLASS_CODE_USER_PROG1; i <= CLASS_CODE_SCTP_IPV6; i++) {
		int index = i - CLASS_CODE_USER_PROG1;

		err = niu_set_tcam_key(np, i, parent->tcam_key[index]);
		if (err)
			return err;
		err = niu_set_flow_key(np, i, parent->flow_key[index]);
		if (err)
			return err;
	}

	err = niu_set_ip_frag_rule(np);
	if (err)
		return err;

	tcam_enable(np, 1);

	return 0;
}

static int niu_zcp_write(struct niu *np, int index, u64 *data)
{
	nw64(ZCP_RAM_DATA0, data[0]);
	nw64(ZCP_RAM_DATA1, data[1]);
	nw64(ZCP_RAM_DATA2, data[2]);
	nw64(ZCP_RAM_DATA3, data[3]);
	nw64(ZCP_RAM_DATA4, data[4]);
	nw64(ZCP_RAM_BE, ZCP_RAM_BE_VAL);
	nw64(ZCP_RAM_ACC,
	     (ZCP_RAM_ACC_WRITE |
	      (0 << ZCP_RAM_ACC_ZFCID_SHIFT) |
	      (ZCP_RAM_SEL_CFIFO(np->port) << ZCP_RAM_ACC_RAM_SEL_SHIFT)));

	return niu_wait_bits_clear(np, ZCP_RAM_ACC, ZCP_RAM_ACC_BUSY,
				   1000, 100);
}

static int niu_zcp_read(struct niu *np, int index, u64 *data)
{
	int err;

	err = niu_wait_bits_clear(np, ZCP_RAM_ACC, ZCP_RAM_ACC_BUSY,
				  1000, 100);
	if (err) {
		netdev_err(np->dev, "ZCP read busy won't clear, ZCP_RAM_ACC[%llx]\n",
			   (unsigned long long)nr64(ZCP_RAM_ACC));
		return err;
	}

	nw64(ZCP_RAM_ACC,
	     (ZCP_RAM_ACC_READ |
	      (0 << ZCP_RAM_ACC_ZFCID_SHIFT) |
	      (ZCP_RAM_SEL_CFIFO(np->port) << ZCP_RAM_ACC_RAM_SEL_SHIFT)));

	err = niu_wait_bits_clear(np, ZCP_RAM_ACC, ZCP_RAM_ACC_BUSY,
				  1000, 100);
	if (err) {
		netdev_err(np->dev, "ZCP read busy2 won't clear, ZCP_RAM_ACC[%llx]\n",
			   (unsigned long long)nr64(ZCP_RAM_ACC));
		return err;
	}

	data[0] = nr64(ZCP_RAM_DATA0);
	data[1] = nr64(ZCP_RAM_DATA1);
	data[2] = nr64(ZCP_RAM_DATA2);
	data[3] = nr64(ZCP_RAM_DATA3);
	data[4] = nr64(ZCP_RAM_DATA4);

	return 0;
}

static void niu_zcp_cfifo_reset(struct niu *np)
{
	u64 val = nr64(RESET_CFIFO);

	val |= RESET_CFIFO_RST(np->port);
	nw64(RESET_CFIFO, val);
	udelay(10);

	val &= ~RESET_CFIFO_RST(np->port);
	nw64(RESET_CFIFO, val);
}

static int niu_init_zcp(struct niu *np)
{
	u64 data[5], rbuf[5];
	int i, max, err;

	if (np->parent->plat_type != PLAT_TYPE_NIU) {
		if (np->port == 0 || np->port == 1)
			max = ATLAS_P0_P1_CFIFO_ENTRIES;
		else
			max = ATLAS_P2_P3_CFIFO_ENTRIES;
	} else
		max = NIU_CFIFO_ENTRIES;

	data[0] = 0;
	data[1] = 0;
	data[2] = 0;
	data[3] = 0;
	data[4] = 0;

	for (i = 0; i < max; i++) {
		err = niu_zcp_write(np, i, data);
		if (err)
			return err;
		err = niu_zcp_read(np, i, rbuf);
		if (err)
			return err;
	}

	niu_zcp_cfifo_reset(np);
	nw64(CFIFO_ECC(np->port), 0);
	nw64(ZCP_INT_STAT, ZCP_INT_STAT_ALL);
	(void) nr64(ZCP_INT_STAT);
	nw64(ZCP_INT_MASK, ZCP_INT_MASK_ALL);

	return 0;
}

static void niu_ipp_write(struct niu *np, int index, u64 *data)
{
	u64 val = nr64_ipp(IPP_CFIG);

	nw64_ipp(IPP_CFIG, val | IPP_CFIG_DFIFO_PIO_W);
	nw64_ipp(IPP_DFIFO_WR_PTR, index);
	nw64_ipp(IPP_DFIFO_WR0, data[0]);
	nw64_ipp(IPP_DFIFO_WR1, data[1]);
	nw64_ipp(IPP_DFIFO_WR2, data[2]);
	nw64_ipp(IPP_DFIFO_WR3, data[3]);
	nw64_ipp(IPP_DFIFO_WR4, data[4]);
	nw64_ipp(IPP_CFIG, val & ~IPP_CFIG_DFIFO_PIO_W);
}

static void niu_ipp_read(struct niu *np, int index, u64 *data)
{
	nw64_ipp(IPP_DFIFO_RD_PTR, index);
	data[0] = nr64_ipp(IPP_DFIFO_RD0);
	data[1] = nr64_ipp(IPP_DFIFO_RD1);
	data[2] = nr64_ipp(IPP_DFIFO_RD2);
	data[3] = nr64_ipp(IPP_DFIFO_RD3);
	data[4] = nr64_ipp(IPP_DFIFO_RD4);
}

static int niu_ipp_reset(struct niu *np)
{
	return niu_set_and_wait_clear_ipp(np, IPP_CFIG, IPP_CFIG_SOFT_RST,
					  1000, 100, "IPP_CFIG");
}

static int niu_init_ipp(struct niu *np)
{
	u64 data[5], rbuf[5], val;
	int i, max, err;

	if (np->parent->plat_type != PLAT_TYPE_NIU) {
		if (np->port == 0 || np->port == 1)
			max = ATLAS_P0_P1_DFIFO_ENTRIES;
		else
			max = ATLAS_P2_P3_DFIFO_ENTRIES;
	} else
		max = NIU_DFIFO_ENTRIES;

	data[0] = 0;
	data[1] = 0;
	data[2] = 0;
	data[3] = 0;
	data[4] = 0;

	for (i = 0; i < max; i++) {
		niu_ipp_write(np, i, data);
		niu_ipp_read(np, i, rbuf);
	}

	(void) nr64_ipp(IPP_INT_STAT);
	(void) nr64_ipp(IPP_INT_STAT);

	err = niu_ipp_reset(np);
	if (err)
		return err;

	(void) nr64_ipp(IPP_PKT_DIS);
	(void) nr64_ipp(IPP_BAD_CS_CNT);
	(void) nr64_ipp(IPP_ECC);

	(void) nr64_ipp(IPP_INT_STAT);

	nw64_ipp(IPP_MSK, ~IPP_MSK_ALL);

	val = nr64_ipp(IPP_CFIG);
	val &= ~IPP_CFIG_IP_MAX_PKT;
	val |= (IPP_CFIG_IPP_ENABLE |
		IPP_CFIG_DFIFO_ECC_EN |
		IPP_CFIG_DROP_BAD_CRC |
		IPP_CFIG_CKSUM_EN |
		(0x1ffff << IPP_CFIG_IP_MAX_PKT_SHIFT));
	nw64_ipp(IPP_CFIG, val);

	return 0;
}

static void niu_handle_led(struct niu *np, int status)
{
	u64 val;
	val = nr64_mac(XMAC_CONFIG);

	if ((np->flags & NIU_FLAGS_10G) != 0 &&
	    (np->flags & NIU_FLAGS_FIBER) != 0) {
		if (status) {
			val |= XMAC_CONFIG_LED_POLARITY;
			val &= ~XMAC_CONFIG_FORCE_LED_ON;
		} else {
			val |= XMAC_CONFIG_FORCE_LED_ON;
			val &= ~XMAC_CONFIG_LED_POLARITY;
		}
	}

	nw64_mac(XMAC_CONFIG, val);
}

static void niu_init_xif_xmac(struct niu *np)
{
	struct niu_link_config *lp = &np->link_config;
	u64 val;

	if (np->flags & NIU_FLAGS_XCVR_SERDES) {
		val = nr64(MIF_CONFIG);
		val |= MIF_CONFIG_ATCA_GE;
		nw64(MIF_CONFIG, val);
	}

	val = nr64_mac(XMAC_CONFIG);
	val &= ~XMAC_CONFIG_SEL_POR_CLK_SRC;

	val |= XMAC_CONFIG_TX_OUTPUT_EN;

	if (lp->loopback_mode == LOOPBACK_MAC) {
		val &= ~XMAC_CONFIG_SEL_POR_CLK_SRC;
		val |= XMAC_CONFIG_LOOPBACK;
	} else {
		val &= ~XMAC_CONFIG_LOOPBACK;
	}

	if (np->flags & NIU_FLAGS_10G) {
		val &= ~XMAC_CONFIG_LFS_DISABLE;
	} else {
		val |= XMAC_CONFIG_LFS_DISABLE;
		if (!(np->flags & NIU_FLAGS_FIBER) &&
		    !(np->flags & NIU_FLAGS_XCVR_SERDES))
			val |= XMAC_CONFIG_1G_PCS_BYPASS;
		else
			val &= ~XMAC_CONFIG_1G_PCS_BYPASS;
	}

	val &= ~XMAC_CONFIG_10G_XPCS_BYPASS;

	if (lp->active_speed == SPEED_100)
		val |= XMAC_CONFIG_SEL_CLK_25MHZ;
	else
		val &= ~XMAC_CONFIG_SEL_CLK_25MHZ;

	nw64_mac(XMAC_CONFIG, val);

	val = nr64_mac(XMAC_CONFIG);
	val &= ~XMAC_CONFIG_MODE_MASK;
	if (np->flags & NIU_FLAGS_10G) {
		val |= XMAC_CONFIG_MODE_XGMII;
	} else {
		if (lp->active_speed == SPEED_1000)
			val |= XMAC_CONFIG_MODE_GMII;
		else
			val |= XMAC_CONFIG_MODE_MII;
	}

	nw64_mac(XMAC_CONFIG, val);
}

static void niu_init_xif_bmac(struct niu *np)
{
	struct niu_link_config *lp = &np->link_config;
	u64 val;

	val = BMAC_XIF_CONFIG_TX_OUTPUT_EN;

	if (lp->loopback_mode == LOOPBACK_MAC)
		val |= BMAC_XIF_CONFIG_MII_LOOPBACK;
	else
		val &= ~BMAC_XIF_CONFIG_MII_LOOPBACK;

	if (lp->active_speed == SPEED_1000)
		val |= BMAC_XIF_CONFIG_GMII_MODE;
	else
		val &= ~BMAC_XIF_CONFIG_GMII_MODE;

	val &= ~(BMAC_XIF_CONFIG_LINK_LED |
		 BMAC_XIF_CONFIG_LED_POLARITY);

	if (!(np->flags & NIU_FLAGS_10G) &&
	    !(np->flags & NIU_FLAGS_FIBER) &&
	    lp->active_speed == SPEED_100)
		val |= BMAC_XIF_CONFIG_25MHZ_CLOCK;
	else
		val &= ~BMAC_XIF_CONFIG_25MHZ_CLOCK;

	nw64_mac(BMAC_XIF_CONFIG, val);
}

static void niu_init_xif(struct niu *np)
{
	if (np->flags & NIU_FLAGS_XMAC)
		niu_init_xif_xmac(np);
	else
		niu_init_xif_bmac(np);
}

static void niu_pcs_mii_reset(struct niu *np)
{
	int limit = 1000;
	u64 val = nr64_pcs(PCS_MII_CTL);
	val |= PCS_MII_CTL_RST;
	nw64_pcs(PCS_MII_CTL, val);
	while ((--limit >= 0) && (val & PCS_MII_CTL_RST)) {
		udelay(100);
		val = nr64_pcs(PCS_MII_CTL);
	}
}

static void niu_xpcs_reset(struct niu *np)
{
	int limit = 1000;
	u64 val = nr64_xpcs(XPCS_CONTROL1);
	val |= XPCS_CONTROL1_RESET;
	nw64_xpcs(XPCS_CONTROL1, val);
	while ((--limit >= 0) && (val & XPCS_CONTROL1_RESET)) {
		udelay(100);
		val = nr64_xpcs(XPCS_CONTROL1);
	}
}

static int niu_init_pcs(struct niu *np)
{
	struct niu_link_config *lp = &np->link_config;
	u64 val;

	switch (np->flags & (NIU_FLAGS_10G |
			     NIU_FLAGS_FIBER |
			     NIU_FLAGS_XCVR_SERDES)) {
	case NIU_FLAGS_FIBER:
		/* 1G fiber */
		nw64_pcs(PCS_CONF, PCS_CONF_MASK | PCS_CONF_ENABLE);
		nw64_pcs(PCS_DPATH_MODE, 0);
		niu_pcs_mii_reset(np);
		break;

	case NIU_FLAGS_10G:
	case NIU_FLAGS_10G | NIU_FLAGS_FIBER:
	case NIU_FLAGS_10G | NIU_FLAGS_XCVR_SERDES:
		/* 10G SERDES */
		if (!(np->flags & NIU_FLAGS_XMAC))
			return -EINVAL;

		/* 10G copper or fiber */
		val = nr64_mac(XMAC_CONFIG);
		val &= ~XMAC_CONFIG_10G_XPCS_BYPASS;
		nw64_mac(XMAC_CONFIG, val);

		niu_xpcs_reset(np);

		val = nr64_xpcs(XPCS_CONTROL1);
		if (lp->loopback_mode == LOOPBACK_PHY)
			val |= XPCS_CONTROL1_LOOPBACK;
		else
			val &= ~XPCS_CONTROL1_LOOPBACK;
		nw64_xpcs(XPCS_CONTROL1, val);

		nw64_xpcs(XPCS_DESKEW_ERR_CNT, 0);
		(void) nr64_xpcs(XPCS_SYMERR_CNT01);
		(void) nr64_xpcs(XPCS_SYMERR_CNT23);
		break;


	case NIU_FLAGS_XCVR_SERDES:
		/* 1G SERDES */
		niu_pcs_mii_reset(np);
		nw64_pcs(PCS_CONF, PCS_CONF_MASK | PCS_CONF_ENABLE);
		nw64_pcs(PCS_DPATH_MODE, 0);
		break;

	case 0:
		/* 1G copper */
	case NIU_FLAGS_XCVR_SERDES | NIU_FLAGS_FIBER:
		/* 1G RGMII FIBER */
		nw64_pcs(PCS_DPATH_MODE, PCS_DPATH_MODE_MII);
		niu_pcs_mii_reset(np);
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

static int niu_reset_tx_xmac(struct niu *np)
{
	return niu_set_and_wait_clear_mac(np, XTXMAC_SW_RST,
					  (XTXMAC_SW_RST_REG_RS |
					   XTXMAC_SW_RST_SOFT_RST),
					  1000, 100, "XTXMAC_SW_RST");
}

static int niu_reset_tx_bmac(struct niu *np)
{
	int limit;

	nw64_mac(BTXMAC_SW_RST, BTXMAC_SW_RST_RESET);
	limit = 1000;
	while (--limit >= 0) {
		if (!(nr64_mac(BTXMAC_SW_RST) & BTXMAC_SW_RST_RESET))
			break;
		udelay(100);
	}
	if (limit < 0) {
		dev_err(np->device, "Port %u TX BMAC would not reset, BTXMAC_SW_RST[%llx]\n",
			np->port,
			(unsigned long long) nr64_mac(BTXMAC_SW_RST));
		return -ENODEV;
	}

	return 0;
}

static int niu_reset_tx_mac(struct niu *np)
{
	if (np->flags & NIU_FLAGS_XMAC)
		return niu_reset_tx_xmac(np);
	else
		return niu_reset_tx_bmac(np);
}

static void niu_init_tx_xmac(struct niu *np, u64 min, u64 max)
{
	u64 val;

	val = nr64_mac(XMAC_MIN);
	val &= ~(XMAC_MIN_TX_MIN_PKT_SIZE |
		 XMAC_MIN_RX_MIN_PKT_SIZE);
	val |= (min << XMAC_MIN_RX_MIN_PKT_SIZE_SHFT);
	val |= (min << XMAC_MIN_TX_MIN_PKT_SIZE_SHFT);
	nw64_mac(XMAC_MIN, val);

	nw64_mac(XMAC_MAX, max);

	nw64_mac(XTXMAC_STAT_MSK, ~(u64)0);

	val = nr64_mac(XMAC_IPG);
	if (np->flags & NIU_FLAGS_10G) {
		val &= ~XMAC_IPG_IPG_XGMII;
		val |= (IPG_12_15_XGMII << XMAC_IPG_IPG_XGMII_SHIFT);
	} else {
		val &= ~XMAC_IPG_IPG_MII_GMII;
		val |= (IPG_12_MII_GMII << XMAC_IPG_IPG_MII_GMII_SHIFT);
	}
	nw64_mac(XMAC_IPG, val);

	val = nr64_mac(XMAC_CONFIG);
	val &= ~(XMAC_CONFIG_ALWAYS_NO_CRC |
		 XMAC_CONFIG_STRETCH_MODE |
		 XMAC_CONFIG_VAR_MIN_IPG_EN |
		 XMAC_CONFIG_TX_ENABLE);
	nw64_mac(XMAC_CONFIG, val);

	nw64_mac(TXMAC_FRM_CNT, 0);
	nw64_mac(TXMAC_BYTE_CNT, 0);
}

static void niu_init_tx_bmac(struct niu *np, u64 min, u64 max)
{
	u64 val;

	nw64_mac(BMAC_MIN_FRAME, min);
	nw64_mac(BMAC_MAX_FRAME, max);

	nw64_mac(BTXMAC_STATUS_MASK, ~(u64)0);
	nw64_mac(BMAC_CTRL_TYPE, 0x8808);
	nw64_mac(BMAC_PREAMBLE_SIZE, 7);

	val = nr64_mac(BTXMAC_CONFIG);
	val &= ~(BTXMAC_CONFIG_FCS_DISABLE |
		 BTXMAC_CONFIG_ENABLE);
	nw64_mac(BTXMAC_CONFIG, val);
}

static void niu_init_tx_mac(struct niu *np)
{
	u64 min, max;

	min = 64;
	if (np->dev->mtu > ETH_DATA_LEN)
		max = 9216;
	else
		max = 1522;

	/* The XMAC_MIN register only accepts values for TX min which
 * have the low 3 bits cleared.
 */
	BUG_ON(min & 0x7);

	if (np->flags & NIU_FLAGS_XMAC)
		niu_init_tx_xmac(np, min, max);
	else
		niu_init_tx_bmac(np, min, max);
}

static int niu_reset_rx_xmac(struct niu *np)
{
	int limit;

	nw64_mac(XRXMAC_SW_RST,
		 XRXMAC_SW_RST_REG_RS | XRXMAC_SW_RST_SOFT_RST);
	limit = 1000;
	while (--limit >= 0) {
		if (!(nr64_mac(XRXMAC_SW_RST) & (XRXMAC_SW_RST_REG_RS |
						 XRXMAC_SW_RST_SOFT_RST)))
			break;
		udelay(100);
	}
	if (limit < 0) {
		dev_err(np->device, "Port %u RX XMAC would not reset, XRXMAC_SW_RST[%llx]\n",
			np->port,
			(unsigned long long) nr64_mac(XRXMAC_SW_RST));
		return -ENODEV;
	}

	return 0;
}

static int niu_reset_rx_bmac(struct niu *np)
{
	int limit;

	nw64_mac(BRXMAC_SW_RST, BRXMAC_SW_RST_RESET);
	limit = 1000;
	while (--limit >= 0) {
		if (!(nr64_mac(BRXMAC_SW_RST) & BRXMAC_SW_RST_RESET))
			break;
		udelay(100);
	}
	if (limit < 0) {
		dev_err(np->device, "Port %u RX BMAC would not reset, BRXMAC_SW_RST[%llx]\n",
			np->port,
			(unsigned long long) nr64_mac(BRXMAC_SW_RST));
		return -ENODEV;
	}

	return 0;
}

static int niu_reset_rx_mac(struct niu *np)
{
	if (np->flags & NIU_FLAGS_XMAC)
		return niu_reset_rx_xmac(np);
	else
		return niu_reset_rx_bmac(np);
}

static void niu_init_rx_xmac(struct niu *np)
{
	struct niu_parent *parent = np->parent;
	struct niu_rdc_tables *tp = &parent->rdc_group_cfg[np->port];
	int first_rdc_table = tp->first_table_num;
	unsigned long i;
	u64 val;

	nw64_mac(XMAC_ADD_FILT0, 0);
	nw64_mac(XMAC_ADD_FILT1, 0);
	nw64_mac(XMAC_ADD_FILT2, 0);
	nw64_mac(XMAC_ADD_FILT12_MASK, 0);
	nw64_mac(XMAC_ADD_FILT00_MASK, 0);
	for (i = 0; i < MAC_NUM_HASH; i++)
		nw64_mac(XMAC_HASH_TBL(i), 0);
	nw64_mac(XRXMAC_STAT_MSK, ~(u64)0);
	niu_set_primary_mac_rdc_table(np, first_rdc_table, 1);
	niu_set_multicast_mac_rdc_table(np, first_rdc_table, 1);

	val = nr64_mac(XMAC_CONFIG);
	val &= ~(XMAC_CONFIG_RX_MAC_ENABLE |
		 XMAC_CONFIG_PROMISCUOUS |
		 XMAC_CONFIG_PROMISC_GROUP |
		 XMAC_CONFIG_ERR_CHK_DIS |
		 XMAC_CONFIG_RX_CRC_CHK_DIS |
		 XMAC_CONFIG_RESERVED_MULTICAST |
		 XMAC_CONFIG_RX_CODEV_CHK_DIS |
		 XMAC_CONFIG_ADDR_FILTER_EN |
		 XMAC_CONFIG_RCV_PAUSE_ENABLE |
		 XMAC_CONFIG_STRIP_CRC |
		 XMAC_CONFIG_PASS_FLOW_CTRL |
		 XMAC_CONFIG_MAC2IPP_PKT_CNT_EN);
	val |= (XMAC_CONFIG_HASH_FILTER_EN);
	nw64_mac(XMAC_CONFIG, val);

	nw64_mac(RXMAC_BT_CNT, 0);
	nw64_mac(RXMAC_BC_FRM_CNT, 0);
	nw64_mac(RXMAC_MC_FRM_CNT, 0);
	nw64_mac(RXMAC_FRAG_CNT, 0);
	nw64_mac(RXMAC_HIST_CNT1, 0);
	nw64_mac(RXMAC_HIST_CNT2, 0);
	nw64_mac(RXMAC_HIST_CNT3, 0);
	nw64_mac(RXMAC_HIST_CNT4, 0);
	nw64_mac(RXMAC_HIST_CNT5, 0);
	nw64_mac(RXMAC_HIST_CNT6, 0);
	nw64_mac(RXMAC_HIST_CNT7, 0);
	nw64_mac(RXMAC_MPSZER_CNT, 0);
	nw64_mac(RXMAC_CRC_ER_CNT, 0);
	nw64_mac(RXMAC_CD_VIO_CNT, 0);
	nw64_mac(LINK_FAULT_CNT, 0);
}

static void niu_init_rx_bmac(struct niu *np)
{
	struct niu_parent *parent = np->parent;
	struct niu_rdc_tables *tp = &parent->rdc_group_cfg[np->port];
	int first_rdc_table = tp->first_table_num;
	unsigned long i;
	u64 val;

	nw64_mac(BMAC_ADD_FILT0, 0);
	nw64_mac(BMAC_ADD_FILT1, 0);
	nw64_mac(BMAC_ADD_FILT2, 0);
	nw64_mac(BMAC_ADD_FILT12_MASK, 0);
	nw64_mac(BMAC_ADD_FILT00_MASK, 0);
	for (i = 0; i < MAC_NUM_HASH; i++)
		nw64_mac(BMAC_HASH_TBL(i), 0);
	niu_set_primary_mac_rdc_table(np, first_rdc_table, 1);
	niu_set_multicast_mac_rdc_table(np, first_rdc_table, 1);
	nw64_mac(BRXMAC_STATUS_MASK, ~(u64)0);

	val = nr64_mac(BRXMAC_CONFIG);
	val &= ~(BRXMAC_CONFIG_ENABLE |
		 BRXMAC_CONFIG_STRIP_PAD |
		 BRXMAC_CONFIG_STRIP_FCS |
		 BRXMAC_CONFIG_PROMISC |
		 BRXMAC_CONFIG_PROMISC_GRP |
		 BRXMAC_CONFIG_ADDR_FILT_EN |
		 BRXMAC_CONFIG_DISCARD_DIS);
	val |= (BRXMAC_CONFIG_HASH_FILT_EN);
	nw64_mac(BRXMAC_CONFIG, val);

	val = nr64_mac(BMAC_ADDR_CMPEN);
	val |= BMAC_ADDR_CMPEN_EN0;
	nw64_mac(BMAC_ADDR_CMPEN, val);
}

static void niu_init_rx_mac(struct niu *np)
{
	niu_set_primary_mac(np, np->dev->dev_addr);

	if (np->flags & NIU_FLAGS_XMAC)
		niu_init_rx_xmac(np);
	else
		niu_init_rx_bmac(np);
}

static void niu_enable_tx_xmac(struct niu *np, int on)
{
	u64 val = nr64_mac(XMAC_CONFIG);

	if (on)
		val |= XMAC_CONFIG_TX_ENABLE;
	else
		val &= ~XMAC_CONFIG_TX_ENABLE;
	nw64_mac(XMAC_CONFIG, val);
}

static void niu_enable_tx_bmac(struct niu *np, int on)
{
	u64 val = nr64_mac(BTXMAC_CONFIG);

	if (on)
		val |= BTXMAC_CONFIG_ENABLE;
	else
		val &= ~BTXMAC_CONFIG_ENABLE;
	nw64_mac(BTXMAC_CONFIG, val);
}

static void niu_enable_tx_mac(struct niu *np, int on)
{
	if (np->flags & NIU_FLAGS_XMAC)
		niu_enable_tx_xmac(np, on);
	else
		niu_enable_tx_bmac(np, on);
}

static void niu_enable_rx_xmac(struct niu *np, int on)
{
	u64 val = nr64_mac(XMAC_CONFIG);

	val &= ~(XMAC_CONFIG_HASH_FILTER_EN |
		 XMAC_CONFIG_PROMISCUOUS);

	if (np->flags & NIU_FLAGS_MCAST)
		val |= XMAC_CONFIG_HASH_FILTER_EN;
	if (np->flags & NIU_FLAGS_PROMISC)
		val |= XMAC_CONFIG_PROMISCUOUS;

	if (on)
		val |= XMAC_CONFIG_RX_MAC_ENABLE;
	else
		val &= ~XMAC_CONFIG_RX_MAC_ENABLE;
	nw64_mac(XMAC_CONFIG, val);
}

static void niu_enable_rx_bmac(struct niu *np, int on)
{
	u64 val = nr64_mac(BRXMAC_CONFIG);

	val &= ~(BRXMAC_CONFIG_HASH_FILT_EN |
		 BRXMAC_CONFIG_PROMISC);

	if (np->flags & NIU_FLAGS_MCAST)
		val |= BRXMAC_CONFIG_HASH_FILT_EN;
	if (np->flags & NIU_FLAGS_PROMISC)
		val |= BRXMAC_CONFIG_PROMISC;

	if (on)
		val |= BRXMAC_CONFIG_ENABLE;
	else
		val &= ~BRXMAC_CONFIG_ENABLE;
	nw64_mac(BRXMAC_CONFIG, val);
}

static void niu_enable_rx_mac(struct niu *np, int on)
{
	if (np->flags & NIU_FLAGS_XMAC)
		niu_enable_rx_xmac(np, on);
	else
		niu_enable_rx_bmac(np, on);
}

static int niu_init_mac(struct niu *np)
{
	int err;

	niu_init_xif(np);
	err = niu_init_pcs(np);
	if (err)
		return err;

	err = niu_reset_tx_mac(np);
	if (err)
		return err;
	niu_init_tx_mac(np);
	err = niu_reset_rx_mac(np);
	if (err)
		return err;
	niu_init_rx_mac(np);

	/* This looks hookey but the RX MAC reset we just did will
 * undo some of the state we setup in niu_init_tx_mac() so we
 * have to call it again. In particular, the RX MAC reset will
 * set the XMAC_MAX register back to it's default value.
 */
	niu_init_tx_mac(np);
	niu_enable_tx_mac(np, 1);

	niu_enable_rx_mac(np, 1);

	return 0;
}

static void niu_stop_one_tx_channel(struct niu *np, struct tx_ring_info *rp)
{
	(void) niu_tx_channel_stop(np, rp->tx_channel);
}

static void niu_stop_tx_channels(struct niu *np)
{
	int i;

	for (i = 0; i < np->num_tx_rings; i++) {
		struct tx_ring_info *rp = &np->tx_rings[i];

		niu_stop_one_tx_channel(np, rp);
	}
}

static void niu_reset_one_tx_channel(struct niu *np, struct tx_ring_info *rp)
{
	(void) niu_tx_channel_reset(np, rp->tx_channel);
}

static void niu_reset_tx_channels(struct niu *np)
{
	int i;

	for (i = 0; i < np->num_tx_rings; i++) {
		struct tx_ring_info *rp = &np->tx_rings[i];

		niu_reset_one_tx_channel(np, rp);
	}
}

static void niu_stop_one_rx_channel(struct niu *np, struct rx_ring_info *rp)
{
	(void) niu_enable_rx_channel(np, rp->rx_channel, 0);
}

static void niu_stop_rx_channels(struct niu *np)
{
	int i;

	for (i = 0; i < np->num_rx_rings; i++) {
		struct rx_ring_info *rp = &np->rx_rings[i];

		niu_stop_one_rx_channel(np, rp);
	}
}

static void niu_reset_one_rx_channel(struct niu *np, struct rx_ring_info *rp)
{
	int channel = rp->rx_channel;

	(void) niu_rx_channel_reset(np, channel);
	nw64(RX_DMA_ENT_MSK(channel), RX_DMA_ENT_MSK_ALL);
	nw64(RX_DMA_CTL_STAT(channel), 0);
	(void) niu_enable_rx_channel(np, channel, 0);
}

static void niu_reset_rx_channels(struct niu *np)
{
	int i;

	for (i = 0; i < np->num_rx_rings; i++) {
		struct rx_ring_info *rp = &np->rx_rings[i];

		niu_reset_one_rx_channel(np, rp);
	}
}

static void niu_disable_ipp(struct niu *np)
{
	u64 rd, wr, val;
	int limit;

	rd = nr64_ipp(IPP_DFIFO_RD_PTR);
	wr = nr64_ipp(IPP_DFIFO_WR_PTR);
	limit = 100;
	while (--limit >= 0 && (rd != wr)) {
		rd = nr64_ipp(IPP_DFIFO_RD_PTR);
		wr = nr64_ipp(IPP_DFIFO_WR_PTR);
	}
	if (limit < 0 &&
	    (rd != 0 && wr != 1)) {
		netdev_err(np->dev, "IPP would not quiesce, rd_ptr[%llx] wr_ptr[%llx]\n",
			   (unsigned long long)nr64_ipp(IPP_DFIFO_RD_PTR),
			   (unsigned long long)nr64_ipp(IPP_DFIFO_WR_PTR));
	}

	val = nr64_ipp(IPP_CFIG);
	val &= ~(IPP_CFIG_IPP_ENABLE |
		 IPP_CFIG_DFIFO_ECC_EN |
		 IPP_CFIG_DROP_BAD_CRC |
		 IPP_CFIG_CKSUM_EN);
	nw64_ipp(IPP_CFIG, val);

	(void) niu_ipp_reset(np);
}

static int niu_init_hw(struct niu *np)
{
	int i, err;

	netif_printk(np, ifup, KERN_DEBUG, np->dev, "Initialize TXC\n");
	niu_txc_enable_port(np, 1);
	niu_txc_port_dma_enable(np, 1);
	niu_txc_set_imask(np, 0);

	netif_printk(np, ifup, KERN_DEBUG, np->dev, "Initialize TX channels\n");
	for (i = 0; i < np->num_tx_rings; i++) {
		struct tx_ring_info *rp = &np->tx_rings[i];

		err = niu_init_one_tx_channel(np, rp);
		if (err)
			return err;
	}

	netif_printk(np, ifup, KERN_DEBUG, np->dev, "Initialize RX channels\n");
	err = niu_init_rx_channels(np);
	if (err)
		goto out_uninit_tx_channels;

	netif_printk(np, ifup, KERN_DEBUG, np->dev, "Initialize classifier\n");
	err = niu_init_classifier_hw(np);
	if (err)
		goto out_uninit_rx_channels;

	netif_printk(np, ifup, KERN_DEBUG, np->dev, "Initialize ZCP\n");
	err = niu_init_zcp(np);
	if (err)
		goto out_uninit_rx_channels;

	netif_printk(np, ifup, KERN_DEBUG, np->dev, "Initialize IPP\n");
	err = niu_init_ipp(np);
	if (err)
		goto out_uninit_rx_channels;

	netif_printk(np, ifup, KERN_DEBUG, np->dev, "Initialize MAC\n");
	err = niu_init_mac(np);
	if (err)
		goto out_uninit_ipp;

	return 0;

out_uninit_ipp:
	netif_printk(np, ifup, KERN_DEBUG, np->dev, "Uninit IPP\n");
	niu_disable_ipp(np);

out_uninit_rx_channels:
	netif_printk(np, ifup, KERN_DEBUG, np->dev, "Uninit RX channels\n");
	niu_stop_rx_channels(np);
	niu_reset_rx_channels(np);

out_uninit_tx_channels:
	netif_printk(np, ifup, KERN_DEBUG, np->dev, "Uninit TX channels\n");
	niu_stop_tx_channels(np);
	niu_reset_tx_channels(np);

	return err;
}

static void niu_stop_hw(struct niu *np)
{
	netif_printk(np, ifdown, KERN_DEBUG, np->dev, "Disable interrupts\n");
	niu_enable_interrupts(np, 0);

	netif_printk(np, ifdown, KERN_DEBUG, np->dev, "Disable RX MAC\n");
	niu_enable_rx_mac(np, 0);

	netif_printk(np, ifdown, KERN_DEBUG, np->dev, "Disable IPP\n");
	niu_disable_ipp(np);

	netif_printk(np, ifdown, KERN_DEBUG, np->dev, "Stop TX channels\n");
	niu_stop_tx_channels(np);

	netif_printk(np, ifdown, KERN_DEBUG, np->dev, "Stop RX channels\n");
	niu_stop_rx_channels(np);

	netif_printk(np, ifdown, KERN_DEBUG, np->dev, "Reset TX channels\n");
	niu_reset_tx_channels(np);

	netif_printk(np, ifdown, KERN_DEBUG, np->dev, "Reset RX channels\n");
	niu_reset_rx_channels(np);
}

static void niu_set_irq_name(struct niu *np)
{
	int port = np->port;
	int i, j = 1;

	sprintf(np->irq_name[0], "%s:MAC", np->dev->name);

	if (port == 0) {
		sprintf(np->irq_name[1], "%s:MIF", np->dev->name);
		sprintf(np->irq_name[2], "%s:SYSERR", np->dev->name);
		j = 3;
	}

	for (i = 0; i < np->num_ldg - j; i++) {
		if (i < np->num_rx_rings)
			sprintf(np->irq_name[i+j], "%s-rx-%d",
				np->dev->name, i);
		else if (i < np->num_tx_rings + np->num_rx_rings)
			sprintf(np->irq_name[i+j], "%s-tx-%d", np->dev->name,
				i - np->num_rx_rings);
	}
}

static int niu_request_irq(struct niu *np)
{
	int i, j, err;

	niu_set_irq_name(np);

	err = 0;
	for (i = 0; i < np->num_ldg; i++) {
		struct niu_ldg *lp = &np->ldg[i];

		err = request_irq(lp->irq, niu_interrupt,
				  IRQF_SHARED | IRQF_SAMPLE_RANDOM,
				  np->irq_name[i], lp);
		if (err)
			goto out_free_irqs;

	}

	return 0;

out_free_irqs:
	for (j = 0; j < i; j++) {
		struct niu_ldg *lp = &np->ldg[j];

		free_irq(lp->irq, lp);
	}
	return err;
}

static void niu_free_irq(struct niu *np)
{
	int i;

	for (i = 0; i < np->num_ldg; i++) {
		struct niu_ldg *lp = &np->ldg[i];

		free_irq(lp->irq, lp);
	}
}

static void niu_enable_napi(struct niu *np)
{
	int i;

	for (i = 0; i < np->num_ldg; i++)
		napi_enable(&np->ldg[i].napi);
}

static void niu_disable_napi(struct niu *np)
{
	int i;

	for (i = 0; i < np->num_ldg; i++)
		napi_disable(&np->ldg[i].napi);
}

static int niu_open(struct net_device *dev)
{
	struct niu *np = netdev_priv(dev);
	int err;

	netif_carrier_off(dev);

	err = niu_alloc_channels(np);
	if (err)
		goto out_err;

	err = niu_enable_interrupts(np, 0);
	if (err)
		goto out_free_channels;

	err = niu_request_irq(np);
	if (err)
		goto out_free_channels;

	niu_enable_napi(np);

	spin_lock_irq(&np->lock);

	err = niu_init_hw(np);
	if (!err) {
		init_timer(&np->timer);
		np->timer.expires = jiffies + HZ;
		np->timer.data = (unsigned long) np;
		np->timer.function = niu_timer;

		err = niu_enable_interrupts(np, 1);
		if (err)
			niu_stop_hw(np);
	}

	spin_unlock_irq(&np->lock);

	if (err) {
		niu_disable_napi(np);
		goto out_free_irq;
	}

	netif_tx_start_all_queues(dev);

	if (np->link_config.loopback_mode != LOOPBACK_DISABLED)
		netif_carrier_on(dev);

	add_timer(&np->timer);

	return 0;

out_free_irq:
	niu_free_irq(np);

out_free_channels:
	niu_free_channels(np);

out_err:
	return err;
}

static void niu_full_shutdown(struct niu *np, struct net_device *dev)
{
	cancel_work_sync(&np->reset_task);

	niu_disable_napi(np);
	netif_tx_stop_all_queues(dev);

	del_timer_sync(&np->timer);

	spin_lock_irq(&np->lock);

	niu_stop_hw(np);

	spin_unlock_irq(&np->lock);
}

static int niu_close(struct net_device *dev)
{
	struct niu *np = netdev_priv(dev);

	niu_full_shutdown(np, dev);

	niu_free_irq(np);

	niu_free_channels(np);

	niu_handle_led(np, 0);

	return 0;
}

static void niu_sync_xmac_stats(struct niu *np)
{
	struct niu_xmac_stats *mp = &np->mac_stats.xmac;

	mp->tx_frames += nr64_mac(TXMAC_FRM_CNT);
	mp->tx_bytes += nr64_mac(TXMAC_BYTE_CNT);

	mp->rx_link_faults += nr64_mac(LINK_FAULT_CNT);
	mp->rx_align_errors += nr64_mac(RXMAC_ALIGN_ERR_CNT);
	mp->rx_frags += nr64_mac(RXMAC_FRAG_CNT);
	mp->rx_mcasts += nr64_mac(RXMAC_MC_FRM_CNT);
	mp->rx_bcasts += nr64_mac(RXMAC_BC_FRM_CNT);
	mp->rx_hist_cnt1 += nr64_mac(RXMAC_HIST_CNT1);
	mp->rx_hist_cnt2 += nr64_mac(RXMAC_HIST_CNT2);
	mp->rx_hist_cnt3 += nr64_mac(RXMAC_HIST_CNT3);
	mp->rx_hist_cnt4 += nr64_mac(RXMAC_HIST_CNT4);
	mp->rx_hist_cnt5 += nr64_mac(RXMAC_HIST_CNT5);
	mp->rx_hist_cnt6 += nr64_mac(RXMAC_HIST_CNT6);
	mp->rx_hist_cnt7 += nr64_mac(RXMAC_HIST_CNT7);
	mp->rx_octets += nr64_mac(RXMAC_BT_CNT);
	mp->rx_code_violations += nr64_mac(RXMAC_CD_VIO_CNT);
	mp->rx_len_errors += nr64_mac(RXMAC_MPSZER_CNT);
	mp->rx_crc_errors += nr64_mac(RXMAC_CRC_ER_CNT);
}

static void niu_sync_bmac_stats(struct niu *np)
{
	struct niu_bmac_stats *mp = &np->mac_stats.bmac;

	mp->tx_bytes += nr64_mac(BTXMAC_BYTE_CNT);
	mp->tx_frames += nr64_mac(BTXMAC_FRM_CNT);

	mp->rx_frames += nr64_mac(BRXMAC_FRAME_CNT);
	mp->rx_align_errors += nr64_mac(BRXMAC_ALIGN_ERR_CNT);
	mp->rx_crc_errors += nr64_mac(BRXMAC_ALIGN_ERR_CNT);
	mp->rx_len_errors += nr64_mac(BRXMAC_CODE_VIOL_ERR_CNT);
}

static void niu_sync_mac_stats(struct niu *np)
{
	if (np->flags & NIU_FLAGS_XMAC)
		niu_sync_xmac_stats(np);
	else
		niu_sync_bmac_stats(np);
}

static void niu_get_rx_stats(struct niu *np)
{
	unsigned long pkts, dropped, errors, bytes;
	int i;

	pkts = dropped = errors = bytes = 0;
	for (i = 0; i < np->num_rx_rings; i++) {
		struct rx_ring_info *rp = &np->rx_rings[i];

		niu_sync_rx_discard_stats(np, rp, 0);

		pkts += rp->rx_packets;
		bytes += rp->rx_bytes;
		dropped += rp->rx_dropped;
		errors += rp->rx_errors;
	}
	np->dev->stats.rx_packets = pkts;
	np->dev->stats.rx_bytes = bytes;
	np->dev->stats.rx_dropped = dropped;
	np->dev->stats.rx_errors = errors;
}

static void niu_get_tx_stats(struct niu *np)
{
	unsigned long pkts, errors, bytes;
	int i;

	pkts = errors = bytes = 0;
	for (i = 0; i < np->num_tx_rings; i++) {
		struct tx_ring_info *rp = &np->tx_rings[i];

		pkts += rp->tx_packets;
		bytes += rp->tx_bytes;
		errors += rp->tx_errors;
	}
	np->dev->stats.tx_packets = pkts;
	np->dev->stats.tx_bytes = bytes;
	np->dev->stats.tx_errors = errors;
}

static struct net_device_stats *niu_get_stats(struct net_device *dev)
{
	struct niu *np = netdev_priv(dev);

	niu_get_rx_stats(np);
	niu_get_tx_stats(np);

	return &dev->stats;
}

static void niu_load_hash_xmac(struct niu *np, u16 *hash)
{
	int i;

	for (i = 0; i < 16; i++)
		nw64_mac(XMAC_HASH_TBL(i), hash[i]);
}

static void niu_load_hash_bmac(struct niu *np, u16 *hash)
{
	int i;

	for (i = 0; i < 16; i++)
		nw64_mac(BMAC_HASH_TBL(i), hash[i]);
}

static void niu_load_hash(struct niu *np, u16 *hash)
{
	if (np->flags & NIU_FLAGS_XMAC)
		niu_load_hash_xmac(np, hash);
	else
		niu_load_hash_bmac(np, hash);
}

static void niu_set_rx_mode(struct net_device *dev)
{
	struct niu *np = netdev_priv(dev);
	int i, alt_cnt, err;
	struct netdev_hw_addr *ha;
	unsigned long flags;
	u16 hash[16] = { 0, };

	spin_lock_irqsave(&np->lock, flags);
	niu_enable_rx_mac(np, 0);

	np->flags