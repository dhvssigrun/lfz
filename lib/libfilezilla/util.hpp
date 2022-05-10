#ifndef LIBFILEZILLA_UTIL_HEADER
#define LIBFILEZILLA_UTIL_HEADER

#include "libfilezilla.hpp"
#include "time.hpp"

#include <cstdint>

/** \file
 * \brief Various utility functions
 */

namespace fz {

/** \brief Sleep current thread for the specified \ref duration.
 *
 * Alternative to \c std::this_thread::sleep_for which unfortunately isn't implemented on
 * MinGW.
 *
 * \note May wake up early, e.g. due to a signal. You can use \ref monotonic_clock
 * to check elapsed time and sleep again if needed.
 */
void FZ_PUBLIC_SYMBOL sleep(duration const& d);

/** \brief Relinquish control for a brief amount of time.
 *
 * The exact duration is unspecified.
 */
void FZ_PUBLIC_SYMBOL yield();

/** \brief Get a secure random integer uniformly distributed in the closed interval [min, max]
 *
 * If generation of random number fails, the program is aborted.
 */
int64_t FZ_PUBLIC_SYMBOL random_number(int64_t min, int64_t max);

/** \brief Get random uniformly distributed bytes
 *
 * If generation of random bytes fails, the program is aborted.
 */
std::vector<uint8_t> FZ_PUBLIC_SYMBOL random_bytes(size_t size);

void FZ_PUBLIC_SYMBOL random_bytes(size_t size, uint8_t* destination);

/** \brief Returns index of the least-significant set bit
 *
 * For example \c bitscan(12) returns 2
 *
 * Undefined if called with 0
 */
uint64_t FZ_PUBLIC_SYMBOL bitscan(uint64_t v);

/** \brief Returns index of the most-significant set bit
 *
 * For example \c bitscan_reverse(12) returns 3
 *
 * Undefined if called with 0
 */
uint64_t FZ_PUBLIC_SYMBOL bitscan_reverse(uint64_t v);

/** \brief Secure equality test in constant time
 *
 * As long as both inputs are of the same size, comparison is done in constant
 * time to prevent timing attacks.
 */
bool FZ_PUBLIC_SYMBOL equal_consttime(std::basic_string_view<uint8_t> const& lhs, std::basic_string_view<uint8_t> const& rhs);

template <typename First, typename Second,
          std::enable_if_t<sizeof(typename First::value_type) == sizeof(uint8_t) &&
                          sizeof(typename Second::value_type) == sizeof(uint8_t)>* = nullptr>
inline bool equal_consttime(First const& lhs, Second const& rhs)
{
	return equal_consttime(std::basic_string_view<uint8_t>(reinterpret_cast<uint8_t const*>(lhs.data()), lhs.size()),
	                       std::basic_string_view<uint8_t>(reinterpret_cast<uint8_t const*>(rhs.data()), rhs.size()));
}

/**
 * /brief Helper to move-assign guaranteeing same member destruction order as the destructor.
 *
 * The implicity-defined move operator performs a member-wise move
 * (class.copy.assign 15.8.2.12 in the C++17 standard), which can lead to members
 * being destroyed in construction order, e.g. if moving a std::unique_ptr
 *
 * If the members depend on being destroyed in destruction order, by default the
 * reverse default construction order, the implicitly-defined move operator cannot
 * be used.
 *
 * By first explicitly destructing the moved-to instance and then placement
 * move-constructing it from the moved-from instance, correct destruction order is guaranteed.
 */
template<typename T, typename std::enable_if_t<std::is_final_v<T>>* = nullptr>
T& move_assign_through_move_constructor(T* p, T&& op) noexcept
{
	p->~T();
	new (p)T(std::move(op));
	return *p;
}

}

#endif
