// Copyright (c) 2024-2025 Lars-Christian Schulz
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#pragma once

#include <format>


namespace scion {

class NoFlagsType {};
constexpr auto NoFlags = NoFlagsType();

namespace details {

template<typename EnumType>
class FlagProxy;

/// \brief Class template for type-safe flags.
/// The function `FlagSet operator|(EnumType lhs, EnumType rhs)` should be
/// implemented in the containing namespace if needed.
/// \param EnumType Enumeration of the possible flags.
template<typename EnumType>
class FlagSet
{
public:
	using UnderlyingType = std::underlying_type_t<EnumType>;

	FlagSet() : flags(0) { }
	FlagSet(NoFlagsType) : flags(0) { }
	FlagSet(EnumType flags) : flags((UnderlyingType)flags) { }
	explicit FlagSet(UnderlyingType flags) : flags(flags) { }

	explicit operator UnderlyingType() const { return flags; }

	/// \brief Obtain a mutable reference to the underlying integer.
	UnderlyingType& ref() { return flags; }

	bool operator[](EnumType flag) const { return flags & (UnderlyingType)flag; }
	auto operator[](EnumType flag) { return FlagProxy<EnumType>(*this, flag); }

	bool operator==(FlagSet other) const { return flags == other.flags; }
	bool operator!=(FlagSet other) const { return flags != other.flags; }

	FlagSet operator~() const { return FlagSet(~flags); }
	FlagSet operator|(FlagSet other) const { return FlagSet(flags | other.flags); }
	FlagSet operator&(FlagSet other) const { return FlagSet(flags & other.flags); }
	FlagSet operator^(FlagSet other) const { return FlagSet(flags ^ other.flags); }

	FlagSet& operator|=(FlagSet other) { flags |= other.flags; return *this; }
	FlagSet& operator&=(FlagSet other) { flags &= other.flags; return *this; }
	FlagSet& operator^=(FlagSet other) { flags ^= other.flags; return *this; }

	FlagSet operator|(EnumType rhs) const { return FlagSet(flags | (UnderlyingType)rhs); }
	FlagSet operator&(EnumType rhs) const { return FlagSet(flags & (UnderlyingType)rhs); }
	FlagSet operator^(EnumType rhs) const { return FlagSet(flags ^ (UnderlyingType)rhs); }

	FlagSet& operator|=(EnumType rhs) { FlagSet(flags |= (UnderlyingType)rhs); return *this; }
	FlagSet& operator&=(EnumType rhs) { FlagSet(flags &= (UnderlyingType)rhs); return *this; }
	FlagSet& operator^=(EnumType rhs) { FlagSet(flags ^= (UnderlyingType)rhs); return *this; }

	friend FlagSet operator|(EnumType lhs, FlagSet rhs) { return FlagSet((UnderlyingType)lhs | rhs); }
	friend FlagSet operator&(EnumType lhs, FlagSet rhs) { return FlagSet((UnderlyingType)lhs & rhs); }
	friend FlagSet operator^(EnumType lhs, FlagSet rhs) { return FlagSet((UnderlyingType)lhs ^ rhs); }

	friend FlagSet& operator|=(EnumType lhs, FlagSet rhs) { FlagSet((UnderlyingType)lhs |= rhs); return lhs; }
	friend FlagSet& operator&=(EnumType lhs, FlagSet rhs) { FlagSet((UnderlyingType)lhs &= rhs); return lhs; }
	friend FlagSet& operator^=(EnumType lhs, FlagSet rhs) { FlagSet((UnderlyingType)lhs ^= rhs); return lhs; }

private:
	UnderlyingType flags;
	friend class FlagProxy<EnumType>;
};

template<typename EnumType>
class FlagProxy
{
private:
	using UnderlyingType = typename FlagSet<EnumType>::UnderlyingType;
	FlagSet<EnumType>& flagSet;
	UnderlyingType flag;

public:
	FlagProxy(FlagSet<EnumType>& flagSet, EnumType flag)
		: flagSet(flagSet), flag((UnderlyingType)flag)
	{}

	operator bool() const { return (flagSet.flags & flag) != 0; }

	FlagProxy<EnumType> operator=(bool value) { flagSet.flags &= flag; return *this; }
};

} // namespace details
} // namespace scion

template<typename T>
struct std::formatter<scion::details::FlagSet<T>>
{
    constexpr auto parse(auto& ctx)
    {
        return ctx.begin();
    }

    auto format(const scion::details::FlagSet<T>& flags, auto& ctx) const
    {
        return std::format_to(ctx.out(), "{:#x}", (std::underlying_type_t<T>)flags);
    }
};
