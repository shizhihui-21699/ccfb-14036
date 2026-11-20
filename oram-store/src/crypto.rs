//! 加密原语：ChaCha20-Poly1305 AEAD。
//! 每个密文自带随机 nonce，同一明文每次加密结果不同 ——
//! 这样云端连"同一个 bucket 被写了两次"都看不出来。

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

pub struct Cipher {
    key: Key,
}

impl Cipher {
    /// 演示用：从种子派生密钥。真实部署应来自 KMS / 硬件密钥模块。
    pub fn from_seed(seed: u64) -> Self {
        let mut key = [0u8; 32];
        let mut x = seed;
        for chunk in key.chunks_mut(8) {
            // splitmix64
            x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            chunk.copy_from_slice(&z.to_le_bytes());
        }
        Cipher {
            key: *Key::from_slice(&key),
        }
    }

    /// 加密，输出 nonce || ciphertext||tag。aad 作为关联数据参与认证。
    pub fn encrypt(&self, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(&self.key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = cipher
            .encrypt(&nonce, Payload { msg: plaintext, aad })
            .expect("encryption failed");
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    pub fn decrypt(&self, aad: &[u8], blob: &[u8]) -> Option<Vec<u8>> {
        if blob.len() < 12 + 16 {
            return None;
        }
        let (n, ct) = blob.split_at(12);
        let cipher = ChaCha20Poly1305::new(&self.key);
        cipher
            .decrypt(Nonce::from_slice(n), Payload { msg: ct, aad })
            .ok()
    }
}
