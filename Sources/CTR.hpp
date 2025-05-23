#ifndef CTR_HPP
#define CTR_HPP

#ifndef DONT_USE_TBB
#include <tbb/parallel_for.h>
#include <tbb/blocked_range.h>
#endif

#define SECUREBUFFER_BIG_ENDIAN_COUNTER
#include "Cipher.hpp"

template <size_t BlockSize, size_t KeySize>
void CTREncrypt(
    const Cipher<BlockSize, KeySize> &cipher,
    uint8_t *data, size_t size,
    const uint8_t (&IV)[BlockSize]
) {
    size_t num_of_blocks = size / BlockSize;
    size_t remainder = size % BlockSize;
    SecureBuffer<BlockSize> state(IV);

#ifndef DONT_USE_TBB
    tbb::parallel_for(tbb::blocked_range<size_t>(0, num_of_blocks, 128),
    [&](const tbb::blocked_range<size_t>& r) {
        SecureBuffer<BlockSize> block;
        for (size_t i = r.begin(); i != r.end(); ++i) {
            block = state;
            block.add(i);
            cipher.encrypt(block);
            std::transform(data + i * BlockSize, data + (i+1) * BlockSize, block.begin(), data + i * BlockSize, std::bit_xor<uint8_t>());
        }
    });
    state.add(num_of_blocks);
    data += num_of_blocks * BlockSize;
#else
    SecureBuffer<BlockSize> block;
    for (size_t i = 0; i < num_of_blocks; ++i) {
        state.add(1);
        block = state;
        cipher.encrypt(block);
        std::transform(data, data + BlockSize, block.begin(), data, std::bit_xor<uint8_t>());
        data += BlockSize;
    }
#endif
    if (remainder > 0) {
        state.add(1);
        SecureBuffer<BlockSize> block(state);
        cipher.encrypt(block);
        std::transform(data, data + remainder, block.begin(), data, std::bit_xor<uint8_t>());
    }
}

template <size_t BlockSize, size_t KeySize>
const auto CTRDecrypt = CTREncrypt<BlockSize, KeySize>;

#endif