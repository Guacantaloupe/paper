#include "guapseudo/bitvector.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace guapseudo {

BitVector::BitVector() : width_(1), limbs_(1, 0) {}

BitVector::BitVector(std::size_t width, std::uint64_t value)
    : width_(width == 0 ? 1 : width), limbs_((width_ + 63) / 64, 0) {
    limbs_[0] = value;
    mask_unused_bits();
}

BitVector BitVector::from_signed(std::size_t width, std::int64_t value) {
    BitVector result(width, static_cast<std::uint64_t>(value));
    if (value < 0 && result.width_ > 64) {
        std::fill(result.limbs_.begin() + 1, result.limbs_.end(), ~std::uint64_t(0));
        result.mask_unused_bits();
    }
    return result;
}

void BitVector::mask_unused_bits() {
    const auto remainder = width_ % 64;
    if (remainder != 0) limbs_.back() &= ((std::uint64_t(1) << remainder) - 1);
}

bool BitVector::is_zero() const {
    return std::all_of(limbs_.begin(), limbs_.end(), [](std::uint64_t limb) { return limb == 0; });
}

bool BitVector::is_negative() const {
    return bit(width_ - 1);
}

std::uint64_t BitVector::low64() const {
    return limbs_.empty() ? 0 : limbs_[0];
}

std::string BitVector::to_hex() const {
    std::ostringstream out;
    out << "0x";
    bool emitted = false;
    for (std::size_t i = limbs_.size(); i-- > 0;) {
        if (!emitted) {
            out << std::hex << limbs_[i];
            emitted = true;
        } else {
            out << std::setfill('0') << std::setw(16) << std::hex << limbs_[i];
        }
    }
    return emitted ? out.str() : "0x0";
}

BitVector BitVector::truncate(std::size_t width) const {
    BitVector result(width, 0);
    const auto count = std::min(result.limbs_.size(), limbs_.size());
    std::copy(limbs_.begin(), limbs_.begin() + static_cast<std::ptrdiff_t>(count), result.limbs_.begin());
    result.mask_unused_bits();
    return result;
}

BitVector BitVector::zero_extend(std::size_t width) const {
    if (width < width_) return truncate(width);
    BitVector result(width, 0);
    std::copy(limbs_.begin(), limbs_.end(), result.limbs_.begin());
    return result;
}

BitVector BitVector::sign_extend(std::size_t width) const {
    if (width < width_) return truncate(width);
    BitVector result = zero_extend(width);
    if (is_negative()) {
        for (std::size_t i = width_; i < width; ++i) result.set_bit(i, true);
    }
    return result;
}

bool BitVector::bit(std::size_t index) const {
    if (index >= width_) return false;
    return (limbs_[index / 64] >> (index % 64)) & 1U;
}

void BitVector::set_bit(std::size_t index, bool value) {
    if (index >= width_) return;
    const auto mask = std::uint64_t(1) << (index % 64);
    if (value) limbs_[index / 64] |= mask;
    else limbs_[index / 64] &= ~mask;
}

void BitVector::require_same_width(const BitVector& rhs) const {
    if (width_ != rhs.width_) throw std::invalid_argument("bitvector width mismatch");
}

BitVector BitVector::operator+(const BitVector& rhs) const {
    require_same_width(rhs);
    BitVector result(width_, 0);
    std::uint64_t carry = 0;
    for (std::size_t i = 0; i < limbs_.size(); ++i) {
        const auto old = limbs_[i];
        auto sum = old + rhs.limbs_[i];
        const auto carry_a = sum < old;
        const auto with_carry = sum + carry;
        const auto carry_b = with_carry < sum;
        result.limbs_[i] = with_carry;
        carry = (carry_a || carry_b) ? 1 : 0;
    }
    result.mask_unused_bits();
    return result;
}

BitVector BitVector::operator-(const BitVector& rhs) const {
    require_same_width(rhs);
    BitVector result(width_, 0);
    std::uint64_t borrow = 0;
    for (std::size_t i = 0; i < limbs_.size(); ++i) {
        const auto subtrahend = rhs.limbs_[i] + borrow;
        const auto overflow = subtrahend < rhs.limbs_[i];
        result.limbs_[i] = limbs_[i] - subtrahend;
        borrow = overflow || limbs_[i] < subtrahend;
    }
    result.mask_unused_bits();
    return result;
}

BitVector BitVector::operator&(const BitVector& rhs) const {
    require_same_width(rhs);
    BitVector result(width_, 0);
    for (std::size_t i = 0; i < limbs_.size(); ++i) result.limbs_[i] = limbs_[i] & rhs.limbs_[i];
    return result;
}

BitVector BitVector::operator|(const BitVector& rhs) const {
    require_same_width(rhs);
    BitVector result(width_, 0);
    for (std::size_t i = 0; i < limbs_.size(); ++i) result.limbs_[i] = limbs_[i] | rhs.limbs_[i];
    result.mask_unused_bits();
    return result;
}

BitVector BitVector::operator^(const BitVector& rhs) const {
    require_same_width(rhs);
    BitVector result(width_, 0);
    for (std::size_t i = 0; i < limbs_.size(); ++i) result.limbs_[i] = limbs_[i] ^ rhs.limbs_[i];
    return result;
}

BitVector BitVector::operator~() const {
    BitVector result(width_, 0);
    for (std::size_t i = 0; i < limbs_.size(); ++i) result.limbs_[i] = ~limbs_[i];
    result.mask_unused_bits();
    return result;
}

BitVector BitVector::logical_shift_left(std::size_t amount) const {
    BitVector result(width_, 0);
    if (amount >= width_) return result;
    for (std::size_t i = amount; i < width_; ++i) result.set_bit(i, bit(i - amount));
    return result;
}

BitVector BitVector::logical_shift_right(std::size_t amount) const {
    BitVector result(width_, 0);
    if (amount >= width_) return result;
    for (std::size_t i = 0; i + amount < width_; ++i) result.set_bit(i, bit(i + amount));
    return result;
}

BitVector BitVector::arithmetic_shift_right(std::size_t amount) const {
    if (amount >= width_) return is_negative() ? BitVector(width_, ~std::uint64_t(0)) : BitVector(width_, 0);
    BitVector result = logical_shift_right(amount);
    if (is_negative()) {
        for (std::size_t i = width_ - amount; i < width_; ++i) result.set_bit(i, true);
    }
    return result;
}

int BitVector::compare_unsigned(const BitVector& rhs) const {
    require_same_width(rhs);
    for (std::size_t i = limbs_.size(); i-- > 0;) {
        if (limbs_[i] < rhs.limbs_[i]) return -1;
        if (limbs_[i] > rhs.limbs_[i]) return 1;
    }
    return 0;
}

int BitVector::compare_signed(const BitVector& rhs) const {
    require_same_width(rhs);
    if (is_negative() != rhs.is_negative()) return is_negative() ? -1 : 1;
    const auto unsigned_result = compare_unsigned(rhs);
    return is_negative() ? -unsigned_result : unsigned_result;
}

} // namespace guapseudo

