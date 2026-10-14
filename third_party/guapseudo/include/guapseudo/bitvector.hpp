#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace guapseudo {

// Width-aware integer value used by the IR. All arithmetic wraps to width bits.
class BitVector {
public:
    BitVector();
    BitVector(std::size_t width, std::uint64_t value);

    static BitVector from_signed(std::size_t width, std::int64_t value);

    std::size_t width() const { return width_; }
    bool is_zero() const;
    bool is_negative() const;
    std::uint64_t low64() const;
    std::string to_hex() const;

    BitVector truncate(std::size_t width) const;
    BitVector zero_extend(std::size_t width) const;
    BitVector sign_extend(std::size_t width) const;

    BitVector operator+(const BitVector& rhs) const;
    BitVector operator-(const BitVector& rhs) const;
    BitVector operator&(const BitVector& rhs) const;
    BitVector operator|(const BitVector& rhs) const;
    BitVector operator^(const BitVector& rhs) const;
    BitVector operator~() const;
    BitVector logical_shift_left(std::size_t amount) const;
    BitVector logical_shift_right(std::size_t amount) const;
    BitVector arithmetic_shift_right(std::size_t amount) const;

    int compare_unsigned(const BitVector& rhs) const;
    int compare_signed(const BitVector& rhs) const;

private:
    std::size_t width_;
    std::vector<std::uint64_t> limbs_;

    void mask_unused_bits();
    bool bit(std::size_t index) const;
    void set_bit(std::size_t index, bool value);
    void require_same_width(const BitVector& rhs) const;
};

} // namespace guapseudo

