#pragma once

#include <string_view>

// GCC before 10 requires a "bool" keyword in concept; this CONCEPT_COMPAT is empty by default, but
// expands to bool if under such a GCC.
#if (!(defined(__clang__)) && defined(__GNUC__) && __GNUC__ < 10)
#define CONCEPT_COMPAT bool
#else
#define CONCEPT_COMPAT
#endif

namespace oxen::quic
{
    // Types can opt-in to being fmt-formattable by ensuring they have a ::to_string() method defined
    template <typename T>
    concept CONCEPT_COMPAT ToStringFormattable = requires(T a) {
        {
            a.to_string()
        } -> std::convertible_to<std::string_view>;
    };

}  // namespace oxen::quic
