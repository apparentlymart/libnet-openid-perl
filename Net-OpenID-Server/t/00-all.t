#!/usr/bin/perl

use strict;
use Test::More tests => 1080;
use Net::OpenID::Server;
use Math::BigInt;

for my $num (1..1080) {
    my $bi = Math::BigInt->new("$num");
    my $bytes = Net::OpenID::Server::_bi2bytes($bi);
    my $bi2 = Net::OpenID::Server::_bytes2bi($bytes);
    is($bi,$bi2);
}


