/*
 * snull.c --  the Simple Network Utility
 *
 * Copyright (C) 2001 Alessandro Rubini and Jonathan Corbet
 * Copyright (C) 2001 O'Reilly & Associates
 *
 * The source code in this file can be freely used, adapted,
 * and redistributed in source or binary form, so long as an
 * acknowledgment appears in derived source files.  The citation
 * should list that the code comes from the book "Linux Device
 * Drivers" by Alessandro Rubini and Jonathan Corbet, published
 * by O'Reilly & Associates.   No warranty is attached;
 * we cannot take responsibility for errors or fitness for use.
 *
 * $Id: snull.c,v 1.21 2004/11/05 02:36:03 rubini Exp $
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/moduleparam.h>

#include <linux/sched.h>
#include <linux/kernel.h> /* printk() */
#include <linux/slab.h> /* kmalloc() */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> /* mark_bh */

#include <linux/in.h>
#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/ip.h>          /* struct iphdr */
#include <linux/tcp.h>         /* struct tcphdr */
#include <linux/skbuff.h>

#include "snull.h"

#include <linux/in6.h>
#include <asm/checksum.h>

MODULE_AUTHOR("Alessandro Rubini, Jonathan Corbet, Jay Hirata");
MODULE_LICENSE("Dual BSD/GPL");

#define MAC_ADDR    { 0xc4, 0xd4, 0x89, 0xfb, 0xf8, 0xab }

#define MAX_MACS                    20
static int num_mac_addrs = 0;
static char *mac_addrs[MAX_MACS] = { [0 ... (MAX_MACS - 1)] = NULL };
static char converted_mac_addrs[MAX_MACS][ETH_ALEN];

int ascii_char_to_int(char c) {
    int result = -1;

    if (c >= '0' && c <= '9')
        result = c - '0';
    else if (c >= 'a' && c <= 'f')
        result = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F')
        result = c - 'A' + 10;

    return result;
}

unsigned char ascii_to_byte(char *str) {
    unsigned char byte = 0;
    int i;

    i = ascii_char_to_int(str[0]);
    if (i < 0)
        return 0;

    byte = (i << 4) & 0xff;

    i = ascii_char_to_int(str[1]);
    if (i < 0)
        return 0;

    byte |= i & 0xff;

    return byte;
}


void convert_mac_addrs(void) {
    int i, j;

    for (i = 0; i < num_mac_addrs; i++) {
        printk("MAC: %d\n", i);
        for (j = 0; j < ETH_ALEN; j++) {
            printk("  converted: %02x\n", ascii_to_byte(&mac_addrs[i][j * 2]));
            converted_mac_addrs[i][j] = ascii_to_byte(&mac_addrs[i][j * 2]);
        }
    }
}




/*
 * MAC addresses of devices to use.
 */
module_param_array(mac_addrs, charp, &num_mac_addrs, 0);

/*
 * Transmitter lockup simulation, normally disabled.
 */
static int lockup = 0;
module_param(lockup, int, 0);

static int timeout = SNULL_TIMEOUT;
module_param(timeout, int, 0);


/*
 * A structure representing an in-flight packet.
 */
struct snull_packet {
	struct snull_packet *next;
	struct net_device *dev;
	int	datalen;
	u8 data[ETH_DATA_LEN];
};

int pool_size = 8;
module_param(pool_size, int, 0);

/*
 * This structure is private to each device. It is used to pass
 * packets in and out, so there is place for a packet
 */

struct snull_priv {
	struct net_device_stats stats;
	int status;
	struct snull_packet *ppool;
	struct snull_packet *rx_queue;  /* List of incoming packets */
	int rx_int_enabled;
	int tx_packetlen;
	u8 *tx_packetdata;
	struct sk_buff *skb;
	spinlock_t lock;
};

/*
 * Set up a device's packet pool.
 */
void snull_setup_pool(struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);
	int i;
	struct snull_packet *pkt;

	priv->ppool = NULL;
	for (i = 0; i < pool_size; i++) {
		pkt = kmalloc (sizeof (struct snull_packet), GFP_KERNEL);
		if (pkt == NULL) {
			printk (KERN_NOTICE "Ran out of memory allocating packet pool\n");
			return;
		}
		pkt->dev = dev;
		pkt->next = priv->ppool;
		priv->ppool = pkt;
	}
}

void snull_teardown_pool(struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);
	struct snull_packet *pkt;
    
	while ((pkt = priv->ppool)) {
		priv->ppool = pkt->next;
		kfree (pkt);
		/* FIXME - in-flight packets ? */
	}
}    

/*
 * Enable and disable receive interrupts.
 */
static void snull_rx_ints(struct net_device *dev, int enable)
{
	struct snull_priv *priv = netdev_priv(dev);
	priv->rx_int_enabled = enable;
}

    
/*
 * Open and close
 */

int snull_open(struct net_device *dev)
{
    int i;

    /* Find the matching device */
    for (i = 0; i < num_mac_addrs; i++) {
        if (dev == snull_devs[i])
            break;
    }

	memcpy(dev->dev_addr, converted_mac_addrs[i], ETH_ALEN);
	netif_start_queue(dev);
	return 0;
}

int snull_release(struct net_device *dev)
{
    /* release ports, irq and such -- like fops->close */

	netif_stop_queue(dev); /* can't transmit any more */
	return 0;
}

/*
 * This function is called to fill up an eth header, since arp is not
 * available on the interface
 */
int snull_rebuild_header(struct sk_buff *skb)
{
	struct ethhdr *eth = (struct ethhdr *) skb->data;
	struct net_device *dev = skb->dev;
    
	memcpy(eth->h_source, dev->dev_addr, dev->addr_len);
	memcpy(eth->h_dest, dev->dev_addr, dev->addr_len);
	eth->h_dest[ETH_ALEN-1]   ^= 0x01;   /* dest is us xor 1 */
	return 0;
}


int snull_header(struct sk_buff *skb, struct net_device *dev,
                unsigned short type, const void *daddr, const void *saddr,
                unsigned int len)
{
	struct ethhdr *eth = (struct ethhdr *)skb_push(skb,ETH_HLEN);

	eth->h_proto = htons(type);
	memcpy(eth->h_source, saddr ? saddr : dev->dev_addr, dev->addr_len);
	memcpy(eth->h_dest,   daddr ? daddr : dev->dev_addr, dev->addr_len);
	eth->h_dest[ETH_ALEN-1]   ^= 0x01;   /* dest is us xor 1 */
	return (dev->hard_header_len);
}

static const struct net_device_ops snull_netdev_ops = {
    .ndo_open       = snull_open,
    .ndo_stop       = snull_release,
};

static const struct header_ops snull_header_ops = {
    .create     = snull_header,
    .rebuild    = snull_rebuild_header,
};


/*
 * The init function (sometimes called probe).
 * It is invoked by register_netdev()
 */
void snull_init(struct net_device *dev)
{
	struct snull_priv *priv;
#if 0
    	/*
	 * Make the usual checks: check_region(), probe irq, ...  -ENODEV
	 * should be returned if no device found.  No resource should be
	 * grabbed: this is done on open(). 
	 */
#endif

    	/* 
	 * Then, assign other fields in dev, using ether_setup() and some
	 * hand assignments
	 */
	ether_setup(dev); /* assign some of the fields */


    dev->netdev_ops = &snull_netdev_ops;
    dev->header_ops = &snull_header_ops;
	dev->watchdog_timeo = timeout;

	/* keep the default flags, just add NOARP */
	dev->flags           |= IFF_NOARP;

	/*
	 * Then, initialize the priv field. This encloses the statistics
	 * and a few private fields.
	 */
	priv = netdev_priv(dev);
	memset(priv, 0, sizeof(struct snull_priv));
	spin_lock_init(&priv->lock);
	snull_rx_ints(dev, 1);		/* enable receive interrupts */
	snull_setup_pool(dev);
}

/*
 * The devices
 */

struct net_device *snull_devs[MAX_MACS];



/*
 * Finally, the module stuff
 */

void snull_cleanup(void)
{
	int i;
    
	for (i = 0; i < num_mac_addrs;  i++) {
		if (snull_devs[i]) {
			unregister_netdev(snull_devs[i]);
			snull_teardown_pool(snull_devs[i]);
			free_netdev(snull_devs[i]);
		}
	}
	return;
}




int snull_init_module(void)
{
	int result, i, ret = -ENOMEM;
    int j;

    printk("There are %d mac addresses\n", num_mac_addrs);
	ret = -ENODEV;
    for (i = 0; i < num_mac_addrs; i++) {
        if (strlen(mac_addrs[i]) < 12)
            goto out;
    }
    convert_mac_addrs();

    for (i = 0; i < num_mac_addrs; i++) {
        printk(" addr: %s\n", mac_addrs[i]);
        for (j = 0; j < ETH_ALEN; j++)
            printk("   %02x\n", 0xff & converted_mac_addrs[i][j]);

    }

	/* Allocate the devices */
    ret = -ENODEV;
    for (i = 0; i < num_mac_addrs; i++) {
        snull_devs[i] = alloc_netdev(sizeof(struct snull_priv), "eth%d", snull_init);
        if (snull_devs[i] == NULL)
            goto out;

    }

    ret = -ENODEV;
    for (i = 0; i < num_mac_addrs;  i++) {
        if ((result = register_netdev(snull_devs[i])))
            printk("snull: error %i registering device \"%s\"\n", result, snull_devs[i]->name);
        else
            ret = 0;
    }

out:
    if (ret) 
        snull_cleanup();
    return ret;
}


module_init(snull_init_module);
module_exit(snull_cleanup);
