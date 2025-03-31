#ifndef CRYPTOMOD_H
#define CRYPTOMOD_H

#define CM_KEY_MAX_LEN 32
#define CM_BLOCK_SIZE 16

// ENC: encryption, DEC: decryption
enum CryptoMode { ENC, DEC };
// BASIC: basic I/O mode, ADV: advanced I/O mode
enum IOMode { BASIC, ADV };

struct CryptoSetup {
    char key[CM_KEY_MAX_LEN];
    // valid key length are 16, 24, 32
    int key_len;
    enum IOMode io_mode;
    enum CryptoMode c_mode;
};

// ioctl command
#define CM_IOC_MAGIC 'k'
#define CM_IOC_SETUP _IOW(CM_IOC_MAGIC, 1, struct CryptoSetup)
#define CM_IOC_FINALIZE _IO(CM_IOC_MAGIC, 2)
#define CM_IOC_CLEANUP _IO(CM_IOC_MAGIC, 3)
#define CM_IOC_CNT_RST _IO(CM_IOC_MAGIC, 4)

#endif
