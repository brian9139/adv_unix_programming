/*
 * cryptomod.c - Kernel module for encrypting and decrypting data
 * using AES ECB mode with support for two I/O modes (BASIC/ADV)
 * and PKCS#7 padding.
 *
 * This module automatically creates /dev/cryptodev and /proc/cryptomod.
 *
 * Author: Your Name
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/crypto.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/ioctl.h>
#include <linux/string.h>
#include <linux/seq_file.h>
#include <linux/vmalloc.h>

/* 引入實驗提供的 header，內含：
 * - struct CryptoSetup
 * - enum CryptoMode { ENC, DEC } 與 enum IOMode { BASIC, ADV }
 * - 常數 CM_KEY_MAX_LEN 與 CM_BLOCK_SIZE
 * - ioctl 命令定義
 */
#include "cryptomod.h"

#define MAX_DATA_SIZE     1024

/* 每個開啟檔案的私有資料 */
struct crypto_priv {
    bool setup_done;
    bool finalized;
    enum CryptoMode c_mode;  /* ENC 或 DEC */
    enum IOMode io_mode;     /* BASIC 或 ADV */
    int key_len;
    u8 key[CM_KEY_MAX_LEN];

    struct crypto_skcipher *tfm;
    struct skcipher_request *req;

    /* BASIC 模式下的緩衝區 */
    u8 *in_buf;
    size_t in_len;

    /* out_buf 用來存放所有輸出資料 */
    u8 *out_buf;
    size_t out_len;
    size_t out_buf_size;  /* 目前 out_buf 的容量 */
    bool use_vmalloc;     /* 若 io_mode==ADV 則採用 vmalloc 分配 out_buf */

    /* ADV 模式下累積未處理的輸入資料（一個 block） */
    u8 adv_in[CM_BLOCK_SIZE];
    size_t adv_in_len;

    /* ADV 模式下解密時，保留上一個完整 block */
    bool withheld;
    u8 withheld_block[CM_BLOCK_SIZE];
};

/* 全域變數區 */
static int major;
static struct cdev cryptodev_cdev;
static struct class *cryptodev_class;

/* 全域統計計數器（必須保護更新） */
static size_t total_bytes_read = 0;
static size_t total_bytes_written = 0;
static unsigned long byte_freq[256];
static DEFINE_MUTEX(counter_mutex);

/* 輔助函數：確保 out_buf 有足夠容量，採用倍數增長策略，
 * 若 use_vmalloc 為 true 則使用 vmalloc 方式重新配置 */
static int ensure_out_buf_capacity(struct crypto_priv *priv, size_t additional)
{
    size_t required = priv->out_len + additional;
    if (required > priv->out_buf_size) {
        size_t new_size = priv->out_buf_size ? priv->out_buf_size * 2 : (MAX_DATA_SIZE + CM_BLOCK_SIZE);
        while (new_size < required)
            new_size *= 2;
        if (priv->use_vmalloc) {
            void *new_buf = vmalloc(new_size);
            if (!new_buf)
                return -ENOMEM;
            memcpy(new_buf, priv->out_buf, priv->out_len);
            vfree(priv->out_buf);
            priv->out_buf = new_buf;
        } else {
            u8 *new_buf = krealloc(priv->out_buf, new_size, GFP_KERNEL);
            if (!new_buf)
                return -ENOMEM;
            priv->out_buf = new_buf;
        }
        priv->out_buf_size = new_size;
    }
    return 0;
}

/* /proc/cryptomod 介面顯示統計資料 */
static int cryptomod_proc_show(struct seq_file *m, void *v)
{
    int i, j;
    mutex_lock(&counter_mutex);
    seq_printf(m, "%zu %zu\n", total_bytes_read, total_bytes_written);
    for (i = 0; i < 16; i++) {
        for (j = 0; j < 16; j++)
            seq_printf(m, "%lu ", byte_freq[i * 16 + j]);
        seq_printf(m, "\n");
    }
    mutex_unlock(&counter_mutex);
    return 0;
}

static int cryptomod_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, cryptomod_proc_show, NULL);
}

static const struct proc_ops cryptomod_proc_ops = {
    .proc_open    = cryptomod_proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* 處理單一區塊的加解密 */
static int aes_crypt_block(struct crypto_skcipher *tfm,
                           struct skcipher_request *req,
                           u8 *src, u8 *dst, bool enc)
{
    struct scatterlist sg_src, sg_dst;
    int ret;
    sg_init_one(&sg_src, src, CM_BLOCK_SIZE);
    sg_init_one(&sg_dst, dst, CM_BLOCK_SIZE);
    skcipher_request_set_crypt(req, &sg_src, &sg_dst, CM_BLOCK_SIZE, NULL);
    if (enc)
        ret = crypto_skcipher_encrypt(req);
    else
        ret = crypto_skcipher_decrypt(req);
    return ret;
}

static void free_crypto_resources(struct crypto_priv *priv)
{
    if (priv->req)
        skcipher_request_free(priv->req);
    if (priv->tfm)
        crypto_free_skcipher(priv->tfm);
    priv->req = NULL;
    priv->tfm = NULL;
}

/* ioctl 處理 */
static long cryptodev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct crypto_priv *priv = file->private_data;
    struct CryptoSetup setup;
    int ret = 0;

    switch (cmd) {
    case CM_IOC_SETUP:
        if (!arg) {
            printk(KERN_ERR "cryptomod: CM_IOC_SETUP: null argument\n");
            return -EINVAL;
        }
        if (copy_from_user(&setup, (struct CryptoSetup __user *)arg, sizeof(setup))) {
            printk(KERN_ERR "cryptomod: CM_IOC_SETUP: copy_from_user failed\n");
            return -EBUSY;
        }
        /* 驗證金鑰長度 */
        if ((setup.key_len != 16) && (setup.key_len != 24) && (setup.key_len != 32)) {
            printk(KERN_ERR "cryptomod: CM_IOC_SETUP: invalid key length %d\n", setup.key_len);
            return -EINVAL;
        }
        /* 驗證 enum 值 */
        if (setup.c_mode != ENC && setup.c_mode != DEC) {
            printk(KERN_ERR "cryptomod: CM_IOC_SETUP: invalid c_mode %d\n", setup.c_mode);
            return -EINVAL;
        }
        if (setup.io_mode != BASIC && setup.io_mode != ADV) {
            printk(KERN_ERR "cryptomod: CM_IOC_SETUP: invalid io_mode %d\n", setup.io_mode);
            return -EINVAL;
        }
        printk(KERN_INFO "cryptomod: CM_IOC_SETUP: c_mode=%d, io_mode=%d, key_len=%d\n",
               setup.c_mode, setup.io_mode, setup.key_len);
        if (priv->setup_done) {
            free_crypto_resources(priv);
            kfree(priv->in_buf);
            kfree(priv->out_buf);
            priv->in_buf = NULL;
            priv->out_buf = NULL;
            priv->in_len = 0;
            priv->out_len = 0;
            priv->adv_in_len = 0;
            priv->withheld = false;
        }
        priv->c_mode = setup.c_mode;
        priv->io_mode = setup.io_mode;
        priv->key_len = setup.key_len;
        memcpy(priv->key, setup.key, setup.key_len);
        priv->tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
        if (IS_ERR(priv->tfm)) {
            printk(KERN_ERR "cryptomod: CM_IOC_SETUP: crypto_alloc_skcipher failed: %ld\n",
                   PTR_ERR(priv->tfm));
            return PTR_ERR(priv->tfm);
        }
        ret = crypto_skcipher_setkey(priv->tfm, priv->key, priv->key_len);
        if (ret) {
            printk(KERN_ERR "cryptomod: CM_IOC_SETUP: setkey failed: %d\n", ret);
            crypto_free_skcipher(priv->tfm);
            return ret;
        }
        priv->req = skcipher_request_alloc(priv->tfm, GFP_KERNEL);
        if (!priv->req) {
            printk(KERN_ERR "cryptomod: CM_IOC_SETUP: skcipher_request_alloc failed\n");
            crypto_free_skcipher(priv->tfm);
            return -ENOMEM;
        }
        if (priv->io_mode == BASIC) {
            priv->in_buf = kmalloc(MAX_DATA_SIZE, GFP_KERNEL);
            if (!priv->in_buf) {
                printk(KERN_ERR "cryptomod: CM_IOC_SETUP: kmalloc in_buf failed\n");
                free_crypto_resources(priv);
                return -ENOMEM;
            }
            priv->out_buf = kmalloc(MAX_DATA_SIZE + CM_BLOCK_SIZE, GFP_KERNEL);
            if (!priv->out_buf) {
                printk(KERN_ERR "cryptomod: CM_IOC_SETUP: kmalloc out_buf failed\n");
                kfree(priv->in_buf);
                free_crypto_resources(priv);
                return -ENOMEM;
            }
            priv->in_len = 0;
            priv->out_len = 0;
            priv->out_buf_size = MAX_DATA_SIZE + CM_BLOCK_SIZE;
            priv->use_vmalloc = false;
        } else { /* ADV 模式：使用 vmalloc 以處理大數量資料 */
            priv->adv_in_len = 0;
            priv->withheld = false;
            priv->out_buf = vmalloc(MAX_DATA_SIZE + CM_BLOCK_SIZE);
            if (!priv->out_buf) {
                printk(KERN_ERR "cryptomod: CM_IOC_SETUP: vmalloc out_buf failed (ADV)\n");
                free_crypto_resources(priv);
                return -ENOMEM;
            }
            priv->out_buf_size = MAX_DATA_SIZE + CM_BLOCK_SIZE;
            priv->out_len = 0;
            priv->use_vmalloc = true;
        }
        priv->setup_done = true;
        printk(KERN_INFO "cryptomod: CM_IOC_SETUP completed\n");
        break;

    case CM_IOC_FINALIZE:
        if (!priv->setup_done) {
            printk(KERN_ERR "cryptomod: CM_IOC_FINALIZE: device not set up\n");
            return -EINVAL;
        }
        if (priv->finalized) {
            printk(KERN_ERR "cryptomod: CM_IOC_FINALIZE: already finalized\n");
            return -EINVAL;
        }
        if (priv->io_mode == BASIC) {
            size_t pad;
            u8 pad_val;
            int i;
            if (priv->c_mode == ENC) {
                pad = CM_BLOCK_SIZE - (priv->in_len % CM_BLOCK_SIZE);
                if (pad == 0)
                    pad = CM_BLOCK_SIZE;
                pad_val = (u8)pad;
                if (priv->in_len + pad > MAX_DATA_SIZE) {
                    printk(KERN_ERR "cryptomod: CM_IOC_FINALIZE: not enough buffer for padding\n");
                    return -EINVAL;
                }
                memset(priv->in_buf + priv->in_len, pad_val, pad);
                priv->in_len += pad;
                for (i = 0; i < priv->in_len; i += CM_BLOCK_SIZE) {
                    ret = aes_crypt_block(priv->tfm, priv->req,
                                          priv->in_buf + i,
                                          priv->out_buf + i, true);
                    if (ret) {
                        printk(KERN_ERR "cryptomod: CM_IOC_FINALIZE: encryption block %d failed\n",
                               i / CM_BLOCK_SIZE);
                        return ret;
                    }
                }
                priv->out_len = priv->in_len;
            } else {
                if (priv->in_len % CM_BLOCK_SIZE != 0) {
                    printk(KERN_ERR "cryptomod: CM_IOC_FINALIZE: input length not multiple of block\n");
                    return -EINVAL;
                }
                for (i = 0; i < priv->in_len; i += CM_BLOCK_SIZE) {
                    ret = aes_crypt_block(priv->tfm, priv->req,
                                          priv->in_buf + i,
                                          priv->out_buf + i, false);
                    if (ret) {
                        printk(KERN_ERR "cryptomod: CM_IOC_FINALIZE: decryption block %d failed\n",
                               i / CM_BLOCK_SIZE);
                        return ret;
                    }
                }
                priv->out_len = priv->in_len;
                if (priv->out_len < 1) {
                    printk(KERN_ERR "cryptomod: CM_IOC_FINALIZE: output length too small\n");
                    return -EINVAL;
                }
                pad_val = priv->out_buf[priv->out_len - 1];
                if (pad_val < 1 || pad_val > CM_BLOCK_SIZE) {
                    printk(KERN_ERR "cryptomod: CM_IOC_FINALIZE: invalid padding value %d\n", pad_val);
                    return -EINVAL;
                }
                for (i = priv->out_len - pad_val; i < (int)priv->out_len; i++) {
                    if (priv->out_buf[i] != pad_val) {
                        printk(KERN_ERR "cryptomod: CM_IOC_FINALIZE: padding mismatch at index %d\n", i);
                        return -EINVAL;
                    }
                }
                priv->out_len -= pad_val;
            }
        } else { /* ADV 模式 */
            if (priv->c_mode == ENC) {
                u8 tmp[CM_BLOCK_SIZE];
                if (priv->adv_in_len > 0) {
                    size_t pad = CM_BLOCK_SIZE - priv->adv_in_len;
                    u8 pad_val = (u8)pad;
                    memcpy(tmp, priv->adv_in, priv->adv_in_len);
                    memset(tmp + priv->adv_in_len, pad_val, pad);
                    ret = ensure_out_buf_capacity(priv, CM_BLOCK_SIZE);
                    if (ret)
                        return ret;
                    ret = aes_crypt_block(priv->tfm, priv->req, tmp,
                                          priv->out_buf + priv->out_len, true);
                    if (ret)
                        return ret;
                    priv->out_len += CM_BLOCK_SIZE;
                    priv->adv_in_len = 0;
                } else {
                    memset(tmp, CM_BLOCK_SIZE, CM_BLOCK_SIZE);
                    ret = ensure_out_buf_capacity(priv, CM_BLOCK_SIZE);
                    if (ret)
                        return ret;
                    ret = aes_crypt_block(priv->tfm, priv->req, tmp,
                                          priv->out_buf + priv->out_len, true);
                    if (ret)
                        return ret;
                    priv->out_len += CM_BLOCK_SIZE;
                }
            } else { /* ADV 模式 + DEC */
                if (!priv->withheld) {
                    printk(KERN_ERR "cryptomod: CM_IOC_FINALIZE: ADV DEC no withheld block\n");
                    return -EINVAL;
                }
                {
                    u8 tmp[CM_BLOCK_SIZE];
                    int i;
                    ret = aes_crypt_block(priv->tfm, priv->req, priv->withheld_block,
                                          tmp, false);
                    if (ret) {
                        printk(KERN_ERR "cryptomod: CM_IOC_FINALIZE: ADV decryption block failed\n");
                        return ret;
                    }
                    {
                        u8 pad_val = tmp[CM_BLOCK_SIZE - 1];
                        if (pad_val < 1 || pad_val > CM_BLOCK_SIZE) {
                            printk(KERN_ERR "cryptomod: CM_IOC_FINALIZE: invalid padding %d\n", pad_val);
                            return -EINVAL;
                        }
                        for (i = CM_BLOCK_SIZE - pad_val; i < CM_BLOCK_SIZE; i++) {
                            if (tmp[i] != pad_val) {
                                printk(KERN_ERR "cryptomod: CM_IOC_FINALIZE: padding mismatch at index %d\n", i);
                                return -EINVAL;
                            }
                        }
                        ret = ensure_out_buf_capacity(priv, CM_BLOCK_SIZE - pad_val);
                        if (ret)
                            return ret;
                        memcpy(priv->out_buf + priv->out_len, tmp, CM_BLOCK_SIZE - pad_val);
                        priv->out_len += (CM_BLOCK_SIZE - pad_val);
                    }
                    priv->withheld = false;
                }
            }
        }
        priv->finalized = true;
        printk(KERN_INFO "cryptomod: CM_IOC_FINALIZE completed\n");
        break;

    case CM_IOC_CLEANUP:
        if (!priv->setup_done) {
            printk(KERN_ERR "cryptomod: CM_IOC_CLEANUP: device not set up\n");
            return -EINVAL;
        }
        priv->in_len = 0;
        priv->out_len = 0;
        priv->adv_in_len = 0;
        priv->withheld = false;
        priv->finalized = false;
        printk(KERN_INFO "cryptomod: CM_IOC_CLEANUP completed\n");
        break;

    case CM_IOC_CNT_RST:
        printk(KERN_INFO "cryptomod: CM_IOC_CNT_RST called, resetting counters\n");
        mutex_lock(&counter_mutex);
        total_bytes_read = 0;
        total_bytes_written = 0;
        memset(byte_freq, 0, sizeof(byte_freq));
        mutex_unlock(&counter_mutex);
        break;

    default:
        printk(KERN_ERR "cryptomod: ioctl: unknown command %u\n", cmd);
        return -EINVAL;
    }
    return 0;
}

/*
 * write():
 *  - BASIC 模式下將 user 資料複製進 in_buf
 *  - ADV 模式下：
 *      * ENC 模式：每當累積滿一個 block 就加密後存入 out_buf
 *      * DEC 模式：採用保留上一個完整 block 機制，
 *          第一次取得完整 block時僅保留；隨後每滿一個 block，
 *          先將先前保留的區塊以 AES 解密後輸出，再以當前 block取代保留區。
 */
static ssize_t cryptodev_write(struct file *file,
                               const char __user *buf, size_t count, loff_t *ppos)
{
    struct crypto_priv *priv = file->private_data;
    ssize_t processed = 0;
    int ret = 0;
    size_t idx = 0;

    if (!priv->setup_done || priv->finalized)
        return -EINVAL;

    if (priv->io_mode == BASIC) {
        size_t space = MAX_DATA_SIZE - priv->in_len;
        size_t to_copy = (count > space) ? space : count;
        if (copy_from_user(priv->in_buf + priv->in_len, buf, to_copy))
            return -EBUSY;
        priv->in_len += to_copy;
        processed = to_copy;
        mutex_lock(&counter_mutex);
        total_bytes_written += to_copy;
        mutex_unlock(&counter_mutex);
    } else {
        /* ADV 模式 */
        while (idx < count) {
            size_t remaining = count - idx;
            size_t needed = CM_BLOCK_SIZE - priv->adv_in_len;
            size_t copy_len = (remaining < needed) ? remaining : needed;
            if (copy_from_user(priv->adv_in + priv->adv_in_len, buf + idx, copy_len))
                return -EBUSY;
            mutex_lock(&counter_mutex);
            total_bytes_written += copy_len;
            mutex_unlock(&counter_mutex);
            priv->adv_in_len += copy_len;
            idx += copy_len;
            if (priv->adv_in_len == CM_BLOCK_SIZE) {
                if (priv->c_mode == DEC) {
                    if (!priv->withheld) {
                        memcpy(priv->withheld_block, priv->adv_in, CM_BLOCK_SIZE);
                        priv->withheld = true;
                        priv->adv_in_len = 0;
                    } else {
                        ret = ensure_out_buf_capacity(priv, CM_BLOCK_SIZE);
                        if (ret)
                            return ret;
                        {
                            u8 decrypted[CM_BLOCK_SIZE];
                            ret = aes_crypt_block(priv->tfm, priv->req,
                                                  priv->withheld_block,
                                                  decrypted, false);
                            if (ret)
                                return ret;
                            memcpy(priv->out_buf + priv->out_len, decrypted, CM_BLOCK_SIZE);
                            priv->out_len += CM_BLOCK_SIZE;
                        }
                        memcpy(priv->withheld_block, priv->adv_in, CM_BLOCK_SIZE);
                        priv->adv_in_len = 0;
                    }
                } else { /* ENC 模式 */
                    ret = ensure_out_buf_capacity(priv, CM_BLOCK_SIZE);
                    if (ret)
                        return ret;
                    ret = aes_crypt_block(priv->tfm, priv->req,
                                          priv->adv_in,
                                          priv->out_buf + priv->out_len, true);
                    if (ret)
                        return ret;
                    priv->out_len += CM_BLOCK_SIZE;
                    priv->adv_in_len = 0;
                }
            }
        }
        processed = idx;
    }
    return processed;
}

/*
 * read():
 *  - 從 out_buf 將資料複製給 user
 *  - 若尚未 finalize 且無資料可讀，回傳 -EAGAIN
 *  - 若 finalize 後資料讀完，回傳 0
 *
 * In ADV mode, after copying data out we check whether a large portion
 * of the output buffer has been consumed. If so, we shift the remaining data
 * to the beginning of out_buf and update the offsets. This helps to avoid
 * unbounded memory growth when processing large files.
 */
static ssize_t cryptodev_read(struct file *file,
                              char __user *buf, size_t count, loff_t *ppos)
{
    struct crypto_priv *priv = file->private_data;
    size_t available;
    ssize_t ret_val;

    if (!priv->setup_done)
        return -EINVAL;
    if (!priv->finalized && priv->out_len == 0)
        return -EAGAIN;
    available = priv->out_len - *ppos;
    if (available == 0)
        return 0;
    if (count > available)
        count = available;
    if (copy_to_user(buf, priv->out_buf + *ppos, count))
        return -EBUSY;
    *ppos += count;
    mutex_lock(&counter_mutex);
    total_bytes_read += count;
    if (priv->c_mode == ENC) {
        size_t i;
        for (i = 0; i < count; i++) {
            byte_freq[ priv->out_buf[*ppos - count + i] ]++;
        }
    }
    mutex_unlock(&counter_mutex);

    /* In ADV mode, shift out the already-read data to free up space */
    if (priv->io_mode == ADV && *ppos > (priv->out_buf_size / 2)) {
        size_t remaining = priv->out_len - *ppos;
        memmove(priv->out_buf, priv->out_buf + *ppos, remaining);
        priv->out_len = remaining;
        *ppos = 0;
    }

    ret_val = count;
    return ret_val;
}

/* open(): 為每個 open 分配 private data */
static int cryptodev_open(struct inode *inode, struct file *file)
{
    struct crypto_priv *priv = kzalloc(sizeof(*priv), GFP_KERNEL);
    if (!priv)
        return -ENOMEM;
    priv->setup_done = false;
    priv->finalized = false;
    priv->adv_in_len = 0;
    priv->withheld = false;
    file->private_data = priv;
    return 0;
}

/* release(): 釋放 private data */
static int cryptodev_release(struct inode *inode, struct file *file)
{
    struct crypto_priv *priv = file->private_data;
    if (priv) {
        kfree(priv->in_buf);
        if (priv->use_vmalloc)
            vfree(priv->out_buf);
        else
            kfree(priv->out_buf);
        free_crypto_resources(priv);
        kfree(priv);
    }
    return 0;
}

static const struct file_operations cryptodev_fops = {
    .owner           = THIS_MODULE,
    .open            = cryptodev_open,
    .release         = cryptodev_release,
    .read            = cryptodev_read,
    .write           = cryptodev_write,
    .unlocked_ioctl  = cryptodev_ioctl,
};

static int __init cryptomod_init(void)
{
    int ret;
    dev_t dev;
    ret = alloc_chrdev_region(&dev, 0, 1, "cryptodev");
    if (ret < 0)
        return ret;
    major = MAJOR(dev);
    cdev_init(&cryptodev_cdev, &cryptodev_fops);
    ret = cdev_add(&cryptodev_cdev, dev, 1);
    if (ret) {
        unregister_chrdev_region(dev, 1);
        return ret;
    }
    cryptodev_class = class_create("cryptodev");
    if (IS_ERR(cryptodev_class)) {
        cdev_del(&cryptodev_cdev);
        unregister_chrdev_region(dev, 1);
        return PTR_ERR(cryptodev_class);
    }
    device_create(cryptodev_class, NULL, dev, NULL, "cryptodev");
    proc_create("cryptomod", 0, NULL, &cryptomod_proc_ops);
    printk(KERN_INFO "cryptomod module loaded\n");
    return 0;
}

static void __exit cryptomod_exit(void)
{
    dev_t dev = MKDEV(major, 0);
    remove_proc_entry("cryptomod", NULL);
    device_destroy(cryptodev_class, dev);
    class_destroy(cryptodev_class);
    cdev_del(&cryptodev_cdev);
    unregister_chrdev_region(dev, 1);
    printk(KERN_INFO "cryptomod module unloaded\n");
}

module_init(cryptomod_init);
module_exit(cryptomod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Cryptomod: Encrypt and Decrypt Data Using a Kernel Module");
