#!/usr/bin/perl

use strict;
use Test::More 'no_plan';
use Data::Dumper;
use Net::OpenID::Server;
use Crypt::OpenSSL::DSA;

use Math::BigInt;
for my $num (1..1080) {
    my $bi = Math::BigInt->new("$num");
    my $bytes = Net::OpenID::Server::_bi2bytes($bi);
    my $bi2 = Net::OpenID::Server::_bytes2bi($bytes);
    is($bi,$bi2);
    printf "$bi = $bi2\n";
}
exit 0;

my ($query_string, %get_vars, $ctype, $content);
my $parse = sub {
    %get_vars = map { durl($_) } split(/[&=]/, $query_string);
};

my $pub_key_file = "test.openid_public.key";
my $priv_key_file = "test.openid_private.key";


my $nos = Net::OpenID::Server->new(
                                   args => \%get_vars,
                                   public_key => $pub_key_file,
                                   private_key => $priv_key_file,
                                   );
ok($nos);

# generate a key
my $dsa = Crypt::OpenSSL::DSA->generate_parameters( 512 );
$dsa->generate_key;
print "done.\n";
$dsa->write_pub_key($pub_key_file);
$dsa->write_priv_key($priv_key_file);

my $read_pub_key = sub {
    open (F, $pub_key_file);
    my $content = do { local $/; <F>; };
    close F;
    return $content;
};

my $read_priv_key = sub {
    open (F, $priv_key_file);
    my $content = do { local $/; <F>; };
    close F;
    return $content;
};


# see if we get our public key back
$query_string = "openid.mode=getpubkey";
$parse->();
$nos->private_key("BOGUS");
for (1..3) {
    $nos->public_key($pub_key_file)     if $_ == 1;
    $nos->public_key($read_pub_key)     if $_ == 2;
    $nos->public_key($read_pub_key->()) if $_ == 3;

    ($ctype, $content) = $nos->handle_page;
    ok($ctype eq "text/plain");
    ok($content =~ /\-\-\-BEGIN/ && $content =~ /\-\-\-END/);
}

# see if we get a user_setup_url vs. signature
$query_string = "openid.is_identity=http://bradfitz.com/&openid.return_to=http://return.example.com/%3Ffoo%3Dbar";
$parse->();
$nos->get_user(sub { return "brad"; });
$nos->is_identity(sub {
    my ($u, $url) = @_;
    return $u eq "brad" && $url eq "http://bradfitz.com/";
});


# first an untrusted case:
$nos->is_trusted(sub { 0; });
$nos->setup_url("http://setup.example.com/?set1=set2");
($ctype, $content) = $nos->handle_page or die $nos->err;
ok($ctype eq "redirect");
ok($content =~ m!user_setup_url=http://setup\.example\.com!);
ok($content =~ m!return\.example\.com/\?foo=bar\&open!);

# now a trusted case, but with bogus private key:
$nos->is_trusted(sub { 1; });
$nos->private_key("BOGUS");
($ctype, $content) = $nos->handle_page;
ok(! $ctype);

$nos->private_key($priv_key_file);
($ctype, $content) = $nos->handle_page;
ok($ctype eq "redirect");
ok($content =~ m!return\.example\.com/\?foo=bar\&open!);
ok($content =~ m!\&openid\.sig=M!);

$nos->private_key($read_priv_key);
($ctype, $content) = $nos->handle_page;
ok($ctype eq "redirect");
ok($content =~ m!return\.example\.com/\?foo=bar\&open!);
ok($content =~ m!\&openid\.sig=M!);

# checking two types of failure cases
$nos->setup_url("http://setup.example.com/");
$nos->is_trusted(sub { 0; });

# immediate mode:
$query_string = "openid.mode=checkid_immediate&openid.is_identity=http://bradfitz.com/&openid.return_to=http://return.example.com/%3Ffoo%3Dbar";
$parse->();
($ctype, $content) = $nos->handle_page;
ok($ctype eq "redirect");

# setup mode:
$query_string = "openid.mode=checkid_setup&openid.is_identity=http://bradfitz.com/&openid.return_to=http://return.example.com/%3Ffoo%3Dbar";
$parse->();
($ctype, $content) = $nos->handle_page;
ok($ctype eq "setup");
ok($content->{return_to} eq "http://return.example.com/?foo=bar");

sub durl
{
    my ($a) = @_;
    $a =~ tr/+/ /;
    $a =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;
    return $a;
}
