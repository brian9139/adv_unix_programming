

#include <linux/printk.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>

static int test_skcipher(u8* key, size_t key_len)
{
    struct crypto_skcipher *tfm = NULL;
    struct skcipher_request *req = NULL;
    u8 *data = NULL;
    const size_t datasize = 512; /* data size in bytes */
    struct scatterlist sg;
    DECLARE_CRYPTO_WAIT(wait);
    int err;

    /*
     * Allocate a tfm (a transformation object) and set the key.
     *
     * In real-world use, a tfm and key are typically used for many
     * encryption/decryption operations.  But in this example, we'll just do a
     * single encryption operation with it (which is not very efficient).
     */

    tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
    if (IS_ERR(tfm)) {
            pr_err("Error allocating ecb(aes) handle: %ld\n", PTR_ERR(tfm));
            return PTR_ERR(tfm);
    }

    err = crypto_skcipher_setkey(tfm, key, key_len);
    if (err) {
            pr_err("Error setting key: %d\n", err);
            goto out;
    }

    /* Allocate a request object */
    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
            err = -ENOMEM;
            goto out;
    }

    /* Prepare the input data */
    data = kmalloc(datasize, GFP_KERNEL);
    if (!data) {
            err = -ENOMEM;
            goto out;
    }
    get_random_bytes(data, datasize);

    /*
     * Encrypt the data in-place.
     *
     * For simplicity, in this example we wait for the request to complete
     * before proceeding, even if the underlying implementation is asynchronous.
     *
     * To decrypt instead of encrypt, just change crypto_skcipher_encrypt() to
     * crypto_skcipher_decrypt().
     */
    /* you also can init two scatterlists instead of inplace operation */
    sg_init_one(&sg, data, datasize); // You need to make sure that data size is mutiple of block size
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                       CRYPTO_TFM_REQ_MAY_SLEEP,
                                  crypto_req_done, &wait);
    skcipher_request_set_crypt(req, &sg, &sg, datasize, NULL);
    err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
    if (err) {
            pr_err("Error encrypting data: %d\n", err);
            goto out;
    }

    pr_debug("Encryption was successful\n");
out:
    crypto_free_skcipher(tfm);
    skcipher_request_free(req);
    kfree(data);
    return err;
}
