// RUN: set -e
// RUN: %merge %s %kernel_bc %t-merged.bc %kernel-dir
// RUN: %sea kernel --file-operations=dvb_device_fops_unsat %t-merged.bc | OutputCheck %s
// CHECK: ^unsat$

#define pr_fmt(fmt) "dvbdev: " fmt

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/i2c.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/mutex.h>
#include <media/dvbdev.h>

/* Due to enum tuner_pad_index */
#include <media/tuner.h>

static DEFINE_MUTEX(dvbdev_mutex);
static LIST_HEAD(dvbdevfops_list);
static int dvbdev_debug;

module_param(dvbdev_debug, int, 0644);
MODULE_PARM_DESC(dvbdev_debug, "Turn on/off device debugging (default:off).");

#define dprintk(fmt, arg...) do {					\
	if (dvbdev_debug)						\
		printk(KERN_DEBUG pr_fmt("%s: " fmt),			\
		       __func__, ##arg);				\
} while (0)

static LIST_HEAD(dvb_adapter_list);
static DEFINE_MUTEX(dvbdev_register_lock);

static const char * const dnames[] = {
	[DVB_DEVICE_VIDEO] =		"video",
	[DVB_DEVICE_AUDIO] =		"audio",
	[DVB_DEVICE_SEC] =		"sec",
	[DVB_DEVICE_FRONTEND] =		"frontend",
	[DVB_DEVICE_DEMUX] =		"demux",
	[DVB_DEVICE_DVR] =		"dvr",
	[DVB_DEVICE_CA] =		"ca",
	[DVB_DEVICE_NET] =		"net",
	[DVB_DEVICE_OSD] =		"osd"
};

#ifdef CONFIG_DVB_DYNAMIC_MINORS
#define MAX_DVB_MINORS		256
#define DVB_MAX_IDS		MAX_DVB_MINORS
#else
#define DVB_MAX_IDS		4

static const u8 minor_type[] = {
	[DVB_DEVICE_VIDEO]      = 0,
	[DVB_DEVICE_AUDIO]      = 1,
	[DVB_DEVICE_SEC]        = 2,
	[DVB_DEVICE_FRONTEND]   = 3,
	[DVB_DEVICE_DEMUX]      = 4,
	[DVB_DEVICE_DVR]        = 5,
	[DVB_DEVICE_CA]         = 6,
	[DVB_DEVICE_NET]        = 7,
	[DVB_DEVICE_OSD]        = 8,
};

#define nums2minor(num, type, id) \
	(((num) << 6) | ((id) << 4) | minor_type[type])

#define MAX_DVB_MINORS		(DVB_MAX_ADAPTERS * 64)
#endif

struct dvb_device *dvb_minors_unsat[MAX_DVB_MINORS];
static DECLARE_RWSEM(minor_rwsem);

static int dvb_device_open_unsat(struct inode *inode, struct file *file)
{
	struct dvb_device *dvbdev;

	mutex_lock(&dvbdev_mutex);
	down_read(&minor_rwsem);
	dvbdev = dvb_minors_unsat[iminor(inode)];

	if (dvbdev && dvbdev->fops) {
		int err = 0;
		const struct file_operations *new_fops;

		new_fops = fops_get(dvbdev->fops);
		if (!new_fops)
			goto fail;
		file->private_data = dvb_device_get(dvbdev);
		replace_fops(file, new_fops);
		if (file->f_op->open)
			err = file->f_op->open(inode, file);
		up_read(&minor_rwsem);
		mutex_unlock(&dvbdev_mutex);
    if (err)
      dvb_device_put(dvbdev);
		return err;
	}
fail:
	up_read(&minor_rwsem);
	mutex_unlock(&dvbdev_mutex);
	return -ENODEV;
}

const struct file_operations dvb_device_fops_unsat = {
	.owner =	THIS_MODULE,
	.open =		dvb_device_open_unsat,
	.llseek =	noop_llseek,
};
