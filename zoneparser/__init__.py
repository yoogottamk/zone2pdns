# -*- encoding: utf8 -*-
# Copyright (C) 2012 Gert Burger <gertburger@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""
Modified version of the original
https://github.com/GertBurger/zoneparser
https://github.com/GertBurger/zoneparser/blob/c2d054a446226efc7b02e13cae647f0622f816bf/zoneparser/__init__.py

Major Changes:
 - python3
 - parse comments with the records
 - tries to parse active / disabled records
 - mostly made ready to be fed into pdns api directly
"""

import re


def debug_gen(g, num=0):
    for i in g:
        print("G[%s]: %r" % (num, i))
        yield i


class Token(object):
    def __repr__(self):
        return type(self).__name__


class DataToken(Token):
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "'%s'" % self.value

    def __str__(self):
        return str(self.value)

    def __eq__(self, other):
        return self.value == other

    def is_special(self):
        if self.value:
            if self.value[0] == "$":
                return True

        return False


class NonDataToken(Token):
    pass


class CommentToken(NonDataToken):
    def __init__(self, value):
        self.value = value


class EOLToken(NonDataToken):
    pass


class OpenParenthesisToken(NonDataToken):
    pass


class CloseParenthesisToken(NonDataToken):
    pass


class SpaceToken(NonDataToken):
    pass


class Tokeniser(object):
    def tokenise(self, zonefile):
        current = []
        tokens = self._tokens_from_file(zonefile)
        reduced_tokens = self._remove_extra_tokens(tokens)

        in_parens = False

        for token in reduced_tokens:
            if type(token) == SpaceToken:
                if not current:
                    current.append(token)
            elif type(token) == OpenParenthesisToken:
                in_parens = True
            elif type(token) == CloseParenthesisToken:
                in_parens = False
            elif type(token) == EOLToken and current:
                if not in_parens:
                    if current and not (
                        len(current) == 1 and type(current[0]) == SpaceToken
                    ):
                        yield current
                        current = []
            else:
                current.append(token)

        if current:
            yield current

    def _tokens_from_file(self, zonefile):
        for line in zonefile:
            current_token = None
            escaped_char = False

            for i, c in enumerate(line):
                # escape char
                if c == "\\":
                    if type(current_token) is DataToken:
                        current_token.value += c + line[i + 1]
                    else:
                        raise ValueError("Illegal char \\")
                    escaped_char = True
                    continue
                if escaped_char:
                    escaped_char = False
                    continue

                c_token = self.char_to_token(c)

                if current_token:
                    if type(c_token) is DataToken:
                        current_token.value = current_token.value + c
                    else:
                        yield current_token
                        current_token = None

                if type(c_token) is DataToken:
                    if not current_token:
                        current_token = c_token
                elif type(c_token) is CommentToken:
                    c_token.value = line[i + 1 :].strip()
                    yield c_token
                    break
                else:
                    yield c_token

            if current_token:
                yield current_token

            yield EOLToken()

    def char_to_token(self, char):
        if char in (" ", "\t"):
            return SpaceToken()
        elif char == ";":
            return CommentToken("")
        elif char in ("\r", "\n"):
            return EOLToken()
        elif char == "(":
            return OpenParenthesisToken()
        elif char == ")":
            return CloseParenthesisToken()
        else:
            return DataToken(char)

    def _remove_extra_tokens(self, tokens):
        """Removed extra spaces/tabs and end-of-lines"""
        prev_token = None
        for token in tokens:
            do_yield = False

            if type(token) == DataToken:
                do_yield = True
            elif type(prev_token) == SpaceToken and type(token) == SpaceToken:
                do_yield = False
            elif type(prev_token) == EOLToken and type(token) == EOLToken:
                do_yield = False
            else:
                if type(token) == EOLToken and prev_token is None:
                    do_yield = False
                else:
                    do_yield = True

            if do_yield:
                yield token

            prev_token = token


class DNSRecord(object):
    def __init__(self, domain, type, value, ttl, record_class="IN", comment=""):
        self.domain = domain
        self.type = type
        self.value = value.replace("\\;", ";")
        self.ttl = ttl
        self.record_class = record_class
        self.comment = comment

    def __repr__(self):
        return "%s [%s] %s (%s)" % (
            self.domain,
            self.type,
            self.value,
            self.comment,
        )


class DNSRecordError(object):
    def __init__(self, group, error):
        self.group = group
        self.error = error

    def __repr__(self):
        return "DNS Parsing error on %r: %s" % (self.group, self.error)


class ZoneAnalyser(object):
    def _is_namespace(self, v):
        return v in ("IN", "CH", "HS")

    def _is_ttl(self, v):
        return re.match(r"^\d+\w?$", v) is not None

    def _is_type(self, v):
        return (
            v
            in "A AAAA AFSDB APL CERT CNAME DHCID DLV DNAME DNSKEY DS HIP IPSECKEY KEY KX LOC MX NAPTR NS NSEC NSEC3 NSEC3PARAM PTR RRSIG RP SIG SOA SPF SRV SSHFP TA TKEY TLSA TSIG TXT".split()
        )

    def analyze(self, token_groups, default_zone):
        """Generator which creates DNSRecord(s) from a tokenized zone file"""

        current_ttl = None
        current_origin = DataToken(default_zone)
        last_domain = None

        for group in token_groups:
            if isinstance(group[-1], CommentToken):
                comment = group.pop().value
            else:
                comment = ""

            group_length = len(group)
            if not group:
                yield DNSRecordError(group, "Empty token group")
                continue

            if group_length < 2:
                yield DNSRecordError(group, "Missing fields")
                continue

            # Check for special entries
            if isinstance(group[0], DataToken) and group[0].is_special():
                if group[0] == "$ORIGIN":
                    if group_length == 2:
                        current_origin = group[1]
                    else:
                        yield DNSRecordError(group, "Invalid ORIGIN entry")
                elif group[0] == "$TTL":
                    if group_length == 2:
                        current_ttl = group[1]
                    else:
                        yield DNSRecordError(group, "Invalid TTL entry")
                elif group[0] == "$INCLUDE":
                    yield DNSRecordError(group, "$INCLUDE is unsupported")
                else:
                    yield DNSRecordError(group, "Invalid special %s" % group[0])

                continue

            # Replace some empty fields so long
            if isinstance(group[0], SpaceToken):
                if last_domain:
                    group[0] = last_domain
                else:
                    yield DNSRecordError(
                        group, "No preceding domain for empty domain field"
                    )
                    continue
            elif group[0] == "@":
                if current_origin:
                    group[0] = current_origin
                    last_domain = current_origin
                else:
                    yield DNSRecordError(group, "No ORIGIN declared for @ usage")
                    continue

            # Dns Record structure: Owner (TTL) (Class) Type rdata
            ttl_pos = 1
            class_pos = 2
            type_pos = 3
            rdata_pos = 4

            entry_owner = group[0].value
            entry_ttl = current_ttl
            entry_class = "IN"
            entry_type = None
            entry_value = None

            if group_length <= ttl_pos:
                yield DNSRecordError(group, "Invalid Record")
                continue

            if self._is_ttl(group[ttl_pos].value):
                entry_ttl = group[ttl_pos].value
            else:
                class_pos -= 1
                type_pos -= 1
                rdata_pos -= 1

            if group_length <= class_pos:
                yield DNSRecordError(group, "Invalid Record")
                continue

            if self._is_namespace(group[class_pos].value):
                entry_class = group[class_pos].value
            else:
                type_pos -= 1
                rdata_pos -= 1

            if group_length <= type_pos:
                yield DNSRecordError(group, "Invalid Record")
                continue

            if self._is_type(group[type_pos].value):
                entry_type = group[type_pos].value
            else:
                yield DNSRecordError(group, "Invalid Type")
                continue

            entry_value = " ".join([x.value for x in group[rdata_pos:]])

            if not entry_ttl:
                yield DNSRecordError(
                    group, "No ttl specified and no default ttl specified"
                )
                continue

            if not entry_owner.endswith("."):
                if current_origin.value.startswith("."):
                    entry_owner += current_origin.value
                else:
                    entry_owner += f".{current_origin.value}"

            if (entry_type == "MX" or entry_type == "CNAME") and entry_value[-1] != ".":
                entry_value += f".{current_origin.value}"

            yield DNSRecord(
                entry_owner, entry_type, entry_value, entry_ttl, entry_class, comment
            )


def parse_zonefile(zonefile, zone):
    token_groups = Tokeniser().tokenise(zonefile)
    records = ZoneAnalyser().analyze(token_groups, zone)

    return records
