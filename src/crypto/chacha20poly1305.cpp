// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/chacha20poly1305.h>

#include <crypto/common.h>
#include <crypto/chacha20.h>
#include <crypto/poly1305.h>
#include <span.h>
#include <support/cleanse.h>

#include <assert.h>
#include <cstdint>
#include <cstddef>
#include <iterator>

AEADChaCha20Poly1305::AEADChaCha20Poly1305(Span<const std::byte> key) noexcept : m_chacha20(UCharCast(key.data()))
{
    assert(key.size() == KEYLEN);
}

void AEADChaCha20Poly1305::SetKey(Span<const std::byte> key) noexcept
{
    assert(key.size() == KEYLEN);
    m_chacha20.SetKey32(UCharCast(key.data()));
}

namespace {

#ifndef HAVE_TIMINGSAFE_BCMP
#define HAVE_TIMINGSAFE_BCMP

int timingsafe_bcmp(const unsigned char* b1, const unsigned char* b2, size_t n) noexcept
{
    const unsigned char *p1 = b1, *p2 = b2;
    int ret = 0;
    for (; n > 0; n--)
        ret |= *p1++ ^ *p2++;
    return (ret != 0);
}

#endif

/** Write all tag data to poly1305 for an AEADChaCha20Poly1305 tag. */
void UpdateTag(Poly1305& poly1305, Span<const std::byte> aad, Span<const std::byte> cipher) noexcept
{
    static const std::byte PADDING[16] = {{}};
    // Process the padded AAD with Poly1305.
    unsigned aad_padding = (16 - (aad.size() % 16)) % 16;
    poly1305.Update(aad).Update(Span{PADDING}.first(aad_padding));
    // Process the padded ciphertext with Poly1305.
    unsigned cipher_padding = (16 - (cipher.size() % 16)) % 16;
    poly1305.Update(cipher).Update(Span{PADDING}.first(cipher_padding));
    // Process the AAD and plaintext length with Poly1305.
    std::byte length_desc[16];
    WriteLE64(UCharCast(length_desc), aad.size());
    WriteLE64(UCharCast(length_desc + 8), cipher.size());
    poly1305.Update(length_desc);
}

} // namespace

void AEADChaCha20Poly1305::Encrypt(Span<const std::byte> plain, Span<const std::byte> aad, Nonce96 nonce, Span<std::byte> cipher) noexcept
{
    assert(cipher.size() == plain.size() + EXPANSION);

    // Encrypt using ChaCha20 (starting at index 1).
    m_chacha20.Seek64(nonce, 1);
    m_chacha20.Crypt(UCharCast(plain.data()), UCharCast(cipher.data()), plain.size());

    // Get first block of keystream.
    std::byte first_block[64];
    m_chacha20.Seek64(nonce, 0);
    m_chacha20.Keystream(UCharCast(first_block), sizeof(first_block));
    // Use the first 32 bytes of the first keystream block as poly1305 key.
    Poly1305 poly1305{Span{first_block}.first(Poly1305::KEYLEN)};
    // Compute tag.
    UpdateTag(poly1305, aad, cipher.first(plain.size()));

    // Write tag to ciphertext.
    poly1305.Finalize(cipher.last(EXPANSION));
}

bool AEADChaCha20Poly1305::Decrypt(Span<const std::byte> cipher, Span<const std::byte> aad, Nonce96 nonce, Span<std::byte> plain) noexcept
{
    assert(cipher.size() == plain.size() + EXPANSION);

    // Get first block of keystream.
    std::byte first_block[64];
    m_chacha20.Seek64(nonce, 0);
    m_chacha20.Keystream(UCharCast(first_block), sizeof(first_block));
    // Use the first 32 bytes of the first keystream block as poly1305 key.
    Poly1305 poly1305{Span{first_block}.first(Poly1305::KEYLEN)};
    // Compute tag.
    UpdateTag(poly1305, aad, cipher.first(plain.size()));

    // Verify tag.
    std::byte expected_tag[EXPANSION];
    poly1305.Finalize(expected_tag);
    if (timingsafe_bcmp(UCharCast(expected_tag), UCharCast(cipher.data() + plain.size()), EXPANSION)) return false;

    // Decrypt.
    m_chacha20.Crypt(UCharCast(cipher.data()), UCharCast(plain.data()), plain.size());
    return true;
}

void AEADChaCha20Poly1305::Keystream(Nonce96 nonce, Span<std::byte> keystream) noexcept
{
    // Skip the first output block, as it's used for generating the poly1305 key.
    m_chacha20.Seek64(nonce, 1);
    m_chacha20.Keystream(UCharCast(keystream.data()), keystream.size());
}

void FSChaCha20Poly1305::NextPacket() noexcept
{
    if (++m_packet_counter == m_rekey_interval) {
        // Generate a full block of keystream, to avoid needing the ChaCha20 buffer, even though
        // we only need KEYLEN (32) bytes.
        std::byte one_block[64];
        m_aead.Keystream({0xFFFFFFFF, m_rekey_counter}, one_block);
        // Switch keys.
        m_aead.SetKey(Span{one_block}.first(KEYLEN));
        // Wipe the generated keystream (a copy remains inside m_aead, which will be cleaned up
        // once it cycles again, or is destroyed).
        memory_cleanse(one_block, sizeof(one_block));
        // Update counters.
        m_packet_counter = 0;
        ++m_rekey_counter;
    }
}

void FSChaCha20Poly1305::Encrypt(Span<const std::byte> plain, Span<const std::byte> aad, Span<std::byte> cipher) noexcept
{
    m_aead.Encrypt(plain, aad, {m_packet_counter, m_rekey_counter}, cipher);
    NextPacket();
}

bool FSChaCha20Poly1305::Decrypt(Span<const std::byte> cipher, Span<const std::byte> aad, Span<std::byte> plain) noexcept
{
    bool ret = m_aead.Decrypt(cipher, aad, {m_packet_counter, m_rekey_counter}, plain);
    NextPacket();
    return ret;
}
