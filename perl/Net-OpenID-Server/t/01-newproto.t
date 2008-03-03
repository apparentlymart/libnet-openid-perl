#!/usr/bin/perl

use strict;
use Test::More 'no_plan';
use Data::Dumper;
use Net::OpenID::Server;
use Crypt::DH;
use Digest::SHA1 qw(sha1 sha1_hex);

for (my $num=1; $num <= 2000; $num += 20) {
    my $bi = Math::BigInt->new("$num");
    my $bytes = Net::OpenID::Server::_bi2bytes($bi);
    my $bi2 = Net::OpenID::Server::_bytes2bi($bytes);
    is($bi,$bi2);
}


my ($query_string, %get, %post, $ctype, $content);
my $parse = sub {
    %get = map { durl($_) } split(/[&=]/, $query_string);
};
my %res;

my $nos = Net::OpenID::Server->new(
                                   get_args => \%get,
                                   post_args => \%post,
                                   server_secret => "o3kjn3nf9832hf32nfo32nfdo32nro32n29332",
                                   setup_url => "http://server.com/setup.app",
                                   endpoint_url => "http://server.com/server.app",
                                   compat => 1,
                                   );
ok($nos);
my ($secret, $ahandle);

assoc_clear();
login_success();

assoc_dh();
login_success();

login_im_fail();
login_setup_fail();
login_setup_fail2();

login_bogus_handle();

login20_success();
login20_select_success();

sub assoc_clear {
    %get = ();
    # regular associate
    %post = (
             "openid.mode" => "associate",
             "openid.assoc_type" => "HMAC-SHA1",
             );
    ($ctype, $content) = $nos->handle_page;
    is($ctype, "text/plain");
    %res = parse_reply($content);
    ok($res{assoc_handle});
    $ahandle = $res{'assoc_handle'};
    ok($ahandle !~ /\bSTLS\./);
    is($res{assoc_type}, "HMAC-SHA1");
    ok(good_date($res{expiry}));
    ok(good_date($res{issued}));
    ok($res{mac_key});
    $secret = $res{'mac_key'};
}

# DH associate
sub assoc_dh {
    my $dh = Crypt::DH->new;
    $dh->p("155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443");
    $dh->g("2");
    $dh->generate_keys;
    %get = ();
    %post = (
             "openid.mode" => "associate",
             "openid.assoc_type" => "HMAC-SHA1",
             "openid.session_type" => "DH-SHA1",
             "openid.dh_consumer_public" => _bi2arg($dh->pub_key),
             );

    ($ctype, $content) = $nos->handle_page;
    is($ctype, "text/plain");
    %res = parse_reply($content);
    ok($res{assoc_handle});
    ok($res{dh_server_public});
    is($res{assoc_type}, "HMAC-SHA1");
    is($res{session_type}, "DH-SHA1");
    ok(good_date($res{expiry}));
    ok(good_date($res{issued}));
    ok($res{enc_mac_key});
    ok(! $res{mac_key});

    my $server_pub = _arg2bi($res{'dh_server_public'});
    my $dh_sec = $dh->compute_secret($server_pub);
    $ahandle = $res{'assoc_handle'};
    ok($ahandle !~ /\bSTLS\./);
    is(length(_d64($res{'enc_mac_key'})), 20);
    is(length(sha1(_bi2bytes($dh_sec))),  20);
    $secret = _d64($res{'enc_mac_key'}) ^ sha1(_bi2bytes($dh_sec));
    is(length($secret), 20);
}

# try to login, with success
sub login_success {
    $nos->is_identity(sub { 1; });
    $nos->is_trusted(sub { 1; });
    $nos->get_user(sub { "brad"; });
    %post = ();
    %get = (
            "openid.mode" => "checkid_immediate",
            "openid.identity" => "http://bradfitz.com/",
            "openid.return_to" => "http://trust.root/return/",
            "openid.trust_root" => "http://trust.root/",
            "openid.assoc_handle" => $ahandle,
            );
    ($ctype, $content) = $nos->handle_page;
    is($ctype, "redirect");
    ok($content =~ s!^http://trust.root/return/\?!!);
    my %rarg = map { durl($_) } split(/[\&\=]/, $content);
    my $token = "";
    foreach my $p (split(/,/, $rarg{'openid.signed'})) {
        $token .= "$p:" . $rarg{"openid.$p"} . "\n";
    }
    my $good_sig = _b64(hmac_sha1($token, $secret));
    ok($rarg{'openid.sig'}, $good_sig);

    # and verify that check_authentication never lets this succeed
    %get = ();
    %post = (
             "openid.mode" => "check_authentication",
             );
    foreach my $p ("assoc_handle", "sig", "signed", "invalidate_handle",
                   split(/,/, $rarg{"openid.signed"}))
    {
        $post{"openid.$p"} ||= $rarg{"openid.$p"};
    }
    ($ctype, $content) = $nos->handle_page;
    is($ctype, "text/plain");
    %rarg = parse_reply($content);
    ok($rarg{"error"} =~ /bad_handle/);
}

# try to login, with success
sub login_bogus_handle {
    $nos->is_identity(sub { 1; });
    $nos->is_trusted(sub { 1; });
    $nos->get_user(sub { "brad"; });
    %post = ();
    %get = (
            "openid.mode" => "checkid_immediate",
            "openid.identity" => "http://bradfitz.com/",
            "openid.return_to" => "http://trust.root/return/",
            "openid.trust_root" => "http://trust.root/",
            "openid.assoc_handle" => "GIBBERISH",
            );
    ($ctype, $content) = $nos->handle_page;
    is($ctype, "redirect");
    ok($content =~ s!^http://trust.root/return/\?!!);
    my %rarg = map { durl($_) } split(/[\&\=]/, $content);
    is($rarg{'openid.invalidate_handle'}, "GIBBERISH");
    ok($rarg{'openid.assoc_handle'} =~ /\bSTLS\./);

    # try to verify it with check_authentication
    %get = ();
    %post = (
             "openid.mode" => "check_authentication",
             );
    foreach my $p ("assoc_handle", "sig", "signed", "invalidate_handle",
                   split(/,/, $rarg{"openid.signed"}))
    {
        $post{"openid.$p"} ||= $rarg{"openid.$p"};
    }
    ($ctype, $content) = $nos->handle_page;
    is($ctype, "text/plain");
    %rarg = parse_reply($content);
    ok($rarg{"lifetime"} > 0);
    is($rarg{"invalidate_handle"}, "GIBBERISH");
}

# try to login, but fail (immediately)
sub login_im_fail {
    $nos->is_identity(sub { 0; });
    $nos->is_trusted(sub { 1; });
    $nos->get_user(sub { "brad"; });
    %post = ();
    %get = (
            "openid.mode" => "checkid_immediate",
            "openid.identity" => "http://bradfitz.com/",
            "openid.return_to" => "http://trust.root/return/",
            "openid.trust_root" => "http://trust.root/",
            "openid.assoc_handle" => $ahandle,
            );
    ($ctype, $content) = $nos->handle_page;
    is($ctype, "redirect");
    ok($content =~ s!^http://trust.root/return/\?!!);
    my %rarg = map { durl($_) } split(/[\&\=]/, $content);

    is($rarg{'openid.mode'}, "id_res");
    ok($rarg{'openid.user_setup_url'} =~ m!setup\.app.+bradfitz!);
}

# try to login, but fail (w/ setup)
sub login_setup_fail {
    $nos->is_identity(sub { 0; });
    $nos->is_trusted(sub { 1; });
    $nos->get_user(sub { "brad"; });
    %post = ();
    %get = (
            "openid.mode" => "checkid_setup",
            "openid.identity" => "http://bradfitz.com/",
            "openid.return_to" => "http://trust.root/return/",
            "openid.trust_root" => "http://trust.root/",
            "openid.assoc_handle" => $ahandle,
            );
    ($ctype, $content) = $nos->handle_page;
    is($ctype, "setup");
    ok(ref $content eq "HASH");
}

# try to login, but fail (w/ setup redirect)
sub login_setup_fail2 {
    $nos->is_identity(sub { 0; });
    $nos->is_trusted(sub { 1; });
    $nos->get_user(sub { "brad"; });
    %post = ();
    %get = (
            "openid.mode" => "checkid_setup",
            "openid.identity" => "http://bradfitz.com/",
            "openid.return_to" => "http://trust.root/return/",
            "openid.trust_root" => "http://trust.root/",
            "openid.assoc_handle" => $ahandle,
            );
    ($ctype, $content) = $nos->handle_page(redirect_for_setup => 1);
    is($ctype, "redirect");
    ok($content =~ m!^http://.+setup\.app\?!);
}

sub login20_success {
    $nos->is_identity(sub { 1; });
    $nos->is_trusted(sub { 1; });
    $nos->get_user(sub { "brad"; });
    %post = ();
    %get = (
            "openid.ns"   => 'http://specs.openid.net/auth/2.0',
            "openid.mode" => "checkid_setup",
            "openid.identity" => "http://bradfitz.com/",
            "openid.return_to" => "http://trust.root/return/",
            "openid.realm" => "http://trust.root/",
            "openid.assoc_handle" => $ahandle,
            );
    ($ctype, $content) = $nos->handle_page();
    is($ctype, "redirect");
}

sub login20_select_success {
    $nos->is_identity(sub { 1; });
    $nos->is_trusted(sub { 1; });
    $nos->get_user(sub { "brad"; });
    $nos->get_identity(sub { "http://bradfitz.com/user/brad"; });
    %post = ();
    %get = (
            "openid.ns"   => 'http://specs.openid.net/auth/2.0',
            "openid.mode" => "checkid_setup",
            "openid.identity" => "http://specs.openid.net/auth/2.0/identifier_select",
            "openid.claimed_id" => "http://specs.openid.net/auth/2.0/identifier_select",
            "openid.return_to" => "http://trust.root/return/",
            "openid.realm" => "http://trust.root/",
            "openid.assoc_handle" => $ahandle,
            );
    ($ctype, $content) = $nos->handle_page();
    is($ctype, "redirect");
    ok($content =~ m!http://bradfitz.com/user/brad! );
}

sub good_date {
    return $_[0] =~ /^(\d{4,4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)Z$/;
}

sub parse_reply {
    my $reply = shift;
    my %ret;
    foreach (split /\n/, $reply) {
        next unless /^(\S+?):(.+)/;
        $ret{$1} = $2;
    }
    return %ret;
}

sub durl
{
    my ($a) = @_;
    $a =~ tr/+/ /;
    $a =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;
    return $a;
}

sub _bi2bytes {
    my $bigint = shift;
    die "Can't deal with negative numbers" if $bigint->is_negative;

    my $bits = $bigint->as_bin;
    die unless $bits =~ s/^0b//;

    # prepend zeros to round to byte boundary, or to unset high bit
    my $prepend = (8 - length($bits) % 8) || ($bits =~ /^1/ ? 8 : 0);
    $bits = ("0" x $prepend) . $bits if $prepend;

    return pack("B*", $bits);
}

sub _bi2arg {
    my $b64 = MIME::Base64::encode_base64(_bi2bytes($_[0]));
    $b64 =~ s/\s+//g;
    return $b64;
}

sub _b64 {
    my $val = MIME::Base64::encode_base64($_[0]);
    $val =~ s/\s+//g;
    return $val;
}

sub _d64 {
    return MIME::Base64::decode_base64($_[0]);
}

sub _bytes2bi {
    return Math::BigInt->new("0b" . unpack("B*", $_[0]));
}

sub _arg2bi {
    return undef unless defined $_[0] and $_[0] ne "";
    # don't acccept base-64 encoded numbers over 700 bytes.  which means
    # those over 4200 bits.
    return Math::BigInt->new("0") if length($_[0]) > 700;
    return _bytes2bi(MIME::Base64::decode_base64($_[0]));
}

# From Digest::HMAC
sub hmac_sha1_hex {
    unpack("H*", &hmac_sha1);
}
sub hmac_sha1 {
    hmac($_[0], $_[1], \&sha1, 64);
}
sub hmac {
    my($data, $key, $hash_func, $block_size) = @_;
    $block_size ||= 64;
    $key = &$hash_func($key) if length($key) > $block_size;

    my $k_ipad = $key ^ (chr(0x36) x $block_size);
    my $k_opad = $key ^ (chr(0x5c) x $block_size);

    &$hash_func($k_opad, &$hash_func($k_ipad, $data));
}
