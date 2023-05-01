// Copyright 2010 Google Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
// * Neither the name of Google Inc. nor the names of its contributors
//   may be used to endorse or promote products derived from this software
//   without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "utils/format/formatter.hpp"

#include <ostream>

#include <atf-c++.hpp>

#include "utils/format/exceptions.hpp"
#include "utils/format/macros.hpp"

namespace format = utils::format;


namespace {


/// Wraps an integer in a C++ class.
///
/// This custom type exists to ensure that we can feed arbitrary objects that
/// support operator<< to the formatter;
class int_wrapper {
    /// The wrapped integer.
    int _value;

public:
    /// Constructs a new wrapper.
    ///
    /// \param value_ The value to wrap.
    int_wrapper(const int value_) : _value(value_)
    {
    }

    /// Returns the wrapped value.
    ///
    /// \return An integer.
    int
    value(void) const
    {
        return _value;
    }
};


/// Writes a wrapped integer into an output stream.
///
/// \param output The output stream into which to place the integer.
/// \param wrapper The wrapped integer.
///
/// \return The output stream.
std::ostream&
operator<<(std::ostream& output, const int_wrapper& wrapper)
{
    return (output << wrapper.value());
}


}  // anonymous namespace


/// Calls ATF_REQUIRE_EQ on an expected string and a formatter.
///
/// This is pure syntactic sugar to avoid calling the str() method on all the
/// individual tests below, which results in very long lines that require
/// wrapping and clutter readability.
///
/// \param expected The expected string generated by the formatter.
/// \param formatter The formatter to test.
#define EQ(expected, formatter) ATF_REQUIRE_EQ(expected, (formatter).str())


ATF_TEST_CASE_WITHOUT_HEAD(no_fields);
ATF_TEST_CASE_BODY(no_fields)
{
    EQ("Plain string", F("Plain string"));
}


ATF_TEST_CASE_WITHOUT_HEAD(one_field);
ATF_TEST_CASE_BODY(one_field)
{
    EQ("foo", F("%sfoo") % "");
    EQ(" foo", F("%sfoo") % " ");
    EQ("foo ", F("foo %s") % "");
    EQ("foo bar", F("foo %s") % "bar");
    EQ("foo bar baz", F("foo %s baz") % "bar");
    EQ("foo %s %s", F("foo %s %s") % "%s" % "%s");
}


ATF_TEST_CASE_WITHOUT_HEAD(many_fields);
ATF_TEST_CASE_BODY(many_fields)
{
    EQ("", F("%s%s") % "" % "");
    EQ("foo", F("%s%s%s") % "" % "foo" % "");
    EQ("some 5 text", F("%s %s %s") % "some" % 5 % "text");
    EQ("f%s 5 text", F("%s %s %s") % "f%s" % 5 % "text");
}


ATF_TEST_CASE_WITHOUT_HEAD(escape);
ATF_TEST_CASE_BODY(escape)
{
    EQ("%", F("%%"));
    EQ("% %", F("%% %%"));
    EQ("%% %%", F("%%%% %%%%"));

    EQ("foo %", F("foo %%"));
    EQ("foo bar %", F("foo %s %%") % "bar");
    EQ("foo % bar", F("foo %% %s") % "bar");

    EQ("foo %%", F("foo %s") % "%%");
    EQ("foo a%%b", F("foo a%sb") % "%%");
    EQ("foo a%%b", F("foo %s") % "a%%b");

    EQ("foo % bar %%", F("foo %% %s %%%%") % "bar");
}


ATF_TEST_CASE_WITHOUT_HEAD(extra_args_error);
ATF_TEST_CASE_BODY(extra_args_error)
{
    using format::extra_args_error;

    ATF_REQUIRE_THROW(extra_args_error, F("foo") % "bar");
    ATF_REQUIRE_THROW(extra_args_error, F("foo %%") % "bar");
    ATF_REQUIRE_THROW(extra_args_error, F("foo %s") % "bar" % "baz");
    ATF_REQUIRE_THROW(extra_args_error, F("foo %s") % "%s" % "bar");
    ATF_REQUIRE_THROW(extra_args_error, F("%s foo %s") % "bar" % "baz" % "foo");

    try {
        F("foo %s %s") % "bar" % "baz" % "something extra";
        fail("extra_args_error not raised");
    } catch (const extra_args_error& e) {
        ATF_REQUIRE_EQ("foo %s %s", e.format());
        ATF_REQUIRE_EQ("something extra", e.arg());
    }
}


ATF_TEST_CASE_WITHOUT_HEAD(format__class);
ATF_TEST_CASE_BODY(format__class)
{
    EQ("foo bar", F("%s") % std::string("foo bar"));
    EQ("3", F("%s") % int_wrapper(3));
}


ATF_TEST_CASE_WITHOUT_HEAD(format__pointer);
ATF_TEST_CASE_BODY(format__pointer)
{
    EQ("0xcafebabe", F("%s") % reinterpret_cast< void* >(0xcafebabe));
    EQ("foo bar", F("%s") % "foo bar");
}


ATF_TEST_CASE_WITHOUT_HEAD(format__bool);
ATF_TEST_CASE_BODY(format__bool)
{
    EQ("true", F("%s") % true);
    EQ("false", F("%s") % false);
}


ATF_TEST_CASE_WITHOUT_HEAD(format__char);
ATF_TEST_CASE_BODY(format__char)
{
    EQ("Z", F("%s") % 'Z');
}


ATF_TEST_CASE_WITHOUT_HEAD(format__float);
ATF_TEST_CASE_BODY(format__float)
{
    EQ("3", F("%s") % 3.0);
    EQ("3.0", F("%.1s") % 3.0);
    EQ("3.0", F("%0.1s") % 3.0);
    EQ("  15.600", F("%8.3s") % 15.6);
    EQ("01.52", F("%05.2s") % 1.52);
}


ATF_TEST_CASE_WITHOUT_HEAD(format__int);
ATF_TEST_CASE_BODY(format__int)
{
    EQ("3", F("%s") % 3);
    EQ("3", F("%0s") % 3);
    EQ(" -123", F("%5s") % -123);
    EQ("00078", F("%05s") % 78);
}


ATF_TEST_CASE_WITHOUT_HEAD(format__error);
ATF_TEST_CASE_BODY(format__error)
{
    using format::bad_format_error;

    ATF_REQUIRE_THROW_RE(bad_format_error, "Trailing %", F("%"));
    ATF_REQUIRE_THROW_RE(bad_format_error, "Trailing %", F("f%"));
    ATF_REQUIRE_THROW_RE(bad_format_error, "Trailing %", F("f%%%"));
    ATF_REQUIRE_THROW_RE(bad_format_error, "Trailing %", F("ab %s cd%") % "cd");

    ATF_REQUIRE_THROW_RE(bad_format_error, "Invalid width", F("%1bs"));

    ATF_REQUIRE_THROW_RE(bad_format_error, "Invalid precision", F("%.s"));
    ATF_REQUIRE_THROW_RE(bad_format_error, "Invalid precision", F("%0.s"));
    ATF_REQUIRE_THROW_RE(bad_format_error, "Invalid precision", F("%123.s"));
    ATF_REQUIRE_THROW_RE(bad_format_error, "Invalid precision", F("%.12bs"));

    ATF_REQUIRE_THROW_RE(bad_format_error, "Unterminated", F("%c") % 'Z');
    ATF_REQUIRE_THROW_RE(bad_format_error, "Unterminated", F("%d") % 5);
    ATF_REQUIRE_THROW_RE(bad_format_error, "Unterminated", F("%.1f") % 3);
    ATF_REQUIRE_THROW_RE(bad_format_error, "Unterminated", F("%d%s") % 3 % "a");

    try {
        F("foo %s%") % "bar";
        fail("bad_format_error not raised");
    } catch (const bad_format_error& e) {
        ATF_REQUIRE_EQ("foo %s%", e.format());
    }
}


ATF_INIT_TEST_CASES(tcs)
{
    ATF_ADD_TEST_CASE(tcs, no_fields);
    ATF_ADD_TEST_CASE(tcs, one_field);
    ATF_ADD_TEST_CASE(tcs, many_fields);
    ATF_ADD_TEST_CASE(tcs, escape);
    ATF_ADD_TEST_CASE(tcs, extra_args_error);

    ATF_ADD_TEST_CASE(tcs, format__class);
    ATF_ADD_TEST_CASE(tcs, format__pointer);
    ATF_ADD_TEST_CASE(tcs, format__bool);
    ATF_ADD_TEST_CASE(tcs, format__char);
    ATF_ADD_TEST_CASE(tcs, format__float);
    ATF_ADD_TEST_CASE(tcs, format__int);
    ATF_ADD_TEST_CASE(tcs, format__error);
}
