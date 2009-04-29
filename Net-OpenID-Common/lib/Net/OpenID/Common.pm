
package Net::OpenID::Common;

$VERSION = 1.01;

=head1 NAME

Net::OpenID::Common - Libraries shared between L<Net::OpenID::Consumer> and L<Net::OpenID::Server>

=head1 DESCRIPTION

The Consumer and Server implementations share a few libraries which live with this module. This module is here largely to hold the version number and this documentation, though it also incorporates some utility functions inherited from previous versions of L<Net::OpenID::Consumer>.

=head1 COPYRIGHT

This package is Copyright (c) 2005 Brad Fitzpatrick, and (c) 2008 Martin Atkins. All rights reserved.

You may distribute under the terms of either the GNU General Public License or the Artistic License, as specified in the Perl README file. If you need more liberal licensing terms, please contact the maintainer.

=head1 MAINTAINER

Maintained by Martin Atkins <mart@degeneration.co.uk>

=cut

# This package should totally be called Net::OpenID::util, but
# it was historically named wrong so we're just leaving it
# like this to avoid confusion.
package OpenID::util;

use constant VERSION_1_NAMESPACE => "http://openid.net/signon/1.1";
use constant VERSION_2_NAMESPACE => "http://specs.openid.net/auth/2.0";

# I guess this is a bit daft since constants are subs anyway,
# but whatever.
sub version_1_namespace {
    return VERSION_1_NAMESPACE;
}
sub version_2_namespace {
    return VERSION_2_NAMESPACE;
}
sub version_1_xrds_service_url {
    return VERSION_1_NAMESPACE;
}
sub version_2_xrds_service_url {
    return "http://specs.openid.net/auth/2.0/signon";
}
sub version_2_xrds_directed_service_url {
    return "http://specs.openid.net/auth/2.0/server";
}
sub version_2_identifier_select_url {
    return "http://specs.openid.net/auth/2.0/identifier_select";
}

# From Digest::HMAC
sub hmac_sha1_hex {
    unpack("H*", &hmac_sha1);
}
sub hmac_sha1 {
    hmac($_[0], $_[1], \&Digest::SHA1::sha1, 64);
}
sub hmac {
    my($data, $key, $hash_func, $block_size) = @_;
    $block_size ||= 64;
    $key = &$hash_func($key) if length($key) > $block_size;

    my $k_ipad = $key ^ (chr(0x36) x $block_size);
    my $k_opad = $key ^ (chr(0x5c) x $block_size);

    &$hash_func($k_opad, &$hash_func($k_ipad, $data));
}

sub parse_keyvalue {
    my $reply = shift;
    my %ret;
    $reply =~ s/\r//g;
    foreach (split /\n/, $reply) {
        next unless /^(\S+?):(.*)/;
        $ret{$1} = $2;
    }
    return %ret;
}

sub ejs
{
    my $a = $_[0];
    $a =~ s/[\"\'\\]/\\$&/g;
    $a =~ s/\r?\n/\\n/gs;
    $a =~ s/\r//;
    return $a;
}

# Data::Dumper for JavaScript
sub js_dumper {
    my $obj = shift;
    if (ref $obj eq "HASH") {
        my $ret = "{";
        foreach my $k (keys %$obj) {
            $ret .= "$k: " . js_dumper($obj->{$k}) . ",";
        }
        chop $ret;
        $ret .= "}";
        return $ret;
    } elsif (ref $obj eq "ARRAY") {
        my $ret = "[" . join(", ", map { js_dumper($_) } @$obj) . "]";
        return $ret;
    } else {
        return $obj if $obj =~ /^\d+$/;
        return "\"" . ejs($obj) . "\"";
    }
}

sub eurl
{
    my $a = $_[0];
    $a =~ s/([^a-zA-Z0-9_\,\-.\/\\\: ])/uc sprintf("%%%02x",ord($1))/eg;
    $a =~ tr/ /+/;
    return $a;
}

sub push_url_arg {
    my $uref = shift;
    $$uref =~ s/[&?]$//;
    my $got_qmark = ($$uref =~ /\?/);

    while (@_) {
        my $key = shift;
        my $value = shift;
        $$uref .= $got_qmark ? "&" : ($got_qmark = 1, "?");
        $$uref .= eurl($key) . "=" . eurl($value);
    }
}

sub push_openid2_url_arg {
    my $uref = shift;
    my %args = @_;
    push_url_arg($uref,
        'openid.ns' => VERSION_2_NAMESPACE,
        map {
            'openid.'.$_ => $args{$_}
        } keys %args,
    );
}

sub time_to_w3c {
    my $time = shift || time();
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = gmtime($time);
    $mon++;
    $year += 1900;

    return sprintf("%04d-%02d-%02dT%02d:%02d:%02dZ",
                   $year, $mon, $mday,
                   $hour, $min, $sec);
}

sub w3c_to_time {
    my $hms = shift;
    return 0 unless
        $hms =~ /^(\d{4,4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)Z$/;

    my $time;
    eval {
        $time = Time::Local::timegm($6, $5, $4, $3, $2 - 1, $1);
    };
    return 0 if $@;
    return $time;
}

sub bi2bytes {
    my $bigint = shift;
    die "Can't deal with negative numbers" if $bigint->is_negative;

    my $bits = $bigint->as_bin;
    die unless $bits =~ s/^0b//;

    # prepend zeros to round to byte boundary, or to unset high bit
    my $prepend = (8 - length($bits) % 8) || ($bits =~ /^1/ ? 8 : 0);
    $bits = ("0" x $prepend) . $bits if $prepend;

    return pack("B*", $bits);
}

sub bi2arg {
    return b64(bi2bytes($_[0]));
}

sub b64 {
    my $val = MIME::Base64::encode_base64($_[0]);
    $val =~ s/\s+//g;
    return $val;
}

sub d64 {
    return MIME::Base64::decode_base64($_[0]);
}

sub bytes2bi {
    return Math::BigInt->new("0b" . unpack("B*", $_[0]));
}

sub arg2bi {
    return undef unless defined $_[0] and $_[0] ne "";
    # don't acccept base-64 encoded numbers over 700 bytes.  which means
    # those over 4200 bits.
    return Math::BigInt->new("0") if length($_[0]) > 700;
    return bytes2bi(MIME::Base64::decode_base64($_[0]));
}


1;
