#!/usr/bin/perl

use strict;
use Test::More tests => 24;
use Data::Dumper;
use Net::OpenID::Consumer;

my ($query_string, %get_vars);

my $csr = Net::OpenID::Consumer->new(
                                     args => \%get_vars,
                                     );
my $cache = My::Cache->new;
$csr->cache($cache);

ok($csr);

my $set_lj_key = sub {
    # the public key at the time this test suite was made.
$cache->set("http://www.livejournal.com/misc/openid.bml?ljuser_sha1=9233b6f5388d6867a2a7be14d8b4ba53c86cfde2&openid.mode=getpubkey",
            "-----BEGIN PUBLIC KEY-----
MIIBtjCCASsGByqGSM44BAEwggEeAoGBANuhjw/GIilXNuvnf9q3ygn1XSzzRtql
3BpsWSRVwXA05G/d9pEBIH35ADEQ6F035f88OfuZYRlUZt6Zx5q4ReA4KXWdAIaA
snDem9vNYJM+O2yK5sh6yYC6AnDn+zx0gUyr9npXun2nfQcrrXT4b2/Q1mAzawTX
q51pCAaDVICVAhUA611/IduNCUoRyE4a4DZ5jUUfGlUCgYBtFIHm3xwTszWVyWzr
YpE6I7PGkgO6bHTLyH4ngmFbhLt3zCj5Kzi9ifRb906CStAsCQAH6x5BKGybq6hD
8JqJk0kaQ8CpHaCjXcFLAjaNxH5pHftfYq3F8waUkeAwvtIQpEL4UKaLaMqbTm3N
FxWoTcEZ2khdlgGbyNXTmDxN3gOBhAACgYAT/V4S6EYk8Sz25Lq1THXo20b0HH8B
F8bvrfeWL26j6zL+Xzxw2T2s6Jo1vSbhflyZ6mou9tjSTN5xNBbKWCGm7jljLEE2
l9P4G6t5+IIgzf3TFrnApYPSb75HmSVChWiafDkfETB1Ubu2BBmGr9DWMicSvage
nsxOWTm7SqJt1Q==
-----END PUBLIC KEY-----
");
};


# $csr->nonce_generator(sub { rand(5000); });
# $csr->nonce_checker(sub { return 1; });
# $csr->identity_cache(sub { return 1; });
# $csr->web_cache(sub { return 1; });

my $ident = $csr->claimed_identity(" sdlkj lskdj 3");
ok(! $ident);
ok( $csr->json_err =~ /url_fetch_error/);

# test an internal function
my $full_url;
my $content = $csr->_get_url_contents("http://bradfitz.com/fake-identity", \$full_url, sub { ${$_[0]} = "ALTER"; });
ok($full_url =~ m!fake-identity/$!);
is($content, "ALTER");

$ident = $csr->claimed_identity("bradfitz.com")
    or die $csr->err . ": " . $csr->errtext;

ok($ident->claimed_url eq "http://bradfitz.com/");
ok(($ident->identity_servers)[0] eq "http://www.livejournal.com/misc/openid.bml?ljuser_sha1=9233b6f5388d6867a2a7be14d8b4ba53c86cfde2");

my $check_url = $ident->check_url(
                                  return_to => "http://www.danga.com/sdf/openid/demo/classic-helper.bml",
                                  trust_root => "http://*.danga.com/sdf",
                                  delayed_return => 1,
                                  );


ok($check_url =~ /openid\.bml\?/);
ok($check_url =~ /openid\.mode=checkid_setup/);

$query_string = "openid.mode=id_res&openid.user_setup_url=http://www.livejournal.com/misc/openid-approve.bml%3Ftrust_root%3Dhttp://%252A.danga.com/sdf%26return_to%3Dhttp://www.danga.com/sdf/openid/demo/classic-helper.bml%26post_grant%3Dreturn%26is_identity%3Dhttp://bradfitz.com/";
%get_vars = map { durl($_) } split(/[&=]/, $query_string);

if (my $setup_url = $csr->user_setup_url) {
    ok($setup_url =~ /openid-approve/);
} else {
    die;
}

my $vident;

# bogus identity (bad signature)
$query_string = "openid.mode=id_res&openid.assert_identity=http://bradfitz.com/fake-identity/&openid.sig=MCwCFCi%2BYw3vVwjujVVO%2Bh2KIlFs0hr1AhRhNl%2BQJfu685Cs7BxmDwH050ShNQ%3D%3D&openid.timestamp=2005-05-21T11:22:33Z&openid.return_to=http://www.danga.com/openid/demo/helper.bml";
%get_vars = map { durl($_) } split(/[&=]/, $query_string);
ok(! $csr->user_setup_url);
$vident = $csr->verified_identity;
ok(! $vident);

# good identity (signature verifies)
$set_lj_key->();
$query_string = "openid.mode=id_res&openid.assert_identity=http://bradfitz.com/fake-identity/&openid.sig=MCwCFCi%2BYw3vVwjujVVO%2Bh2KIlFs0hr1AhRhNl%2BQJfu685Cs7BxmDwH050ShNQ%3D%3D&openid.timestamp=2005-05-21T21:32:46Z&openid.return_to=http://www.danga.com/openid/demo/helper.bml";
%get_vars = map { durl($_) } split(/[&=]/, $query_string);
ok(! $csr->user_setup_url);
$vident = $csr->verified_identity;
ok($vident);

# see if it found the profile info
ok(! $vident->foaf);  # wasn't under the root
ok(  $vident->declared_foaf eq "http://brad.livejournal.com/data/foaf");
ok(  $vident->foafmaker    eq "foaf:mbox_sha1sum '4caa1d6f6203d21705a00a7aca86203e82a9cf7a'");

ok($vident->rss  eq "http://bradfitz.com/fake-identity/rss.xml");
ok($vident->atom eq "http://bradfitz.com/fake-identity/dir/atom.xml");

# get a display URL
ok($vident->display eq "http://bradfitz.com/fake-identity/");
ok(Net::OpenID::VerifiedIdentity::DisplayOfURL("http://bradfitz.com/") eq "bradfitz.com");
ok(Net::OpenID::VerifiedIdentity::DisplayOfURL("http://bradfitz.com/users/bob/") eq "bob [bradfitz.com]");
ok(Net::OpenID::VerifiedIdentity::DisplayOfURL("http://www.foo.com/~hacker") eq "hacker [foo.com]");
ok(Net::OpenID::VerifiedIdentity::DisplayOfURL("http://aol.com/members/mary/") eq "mary [aol.com]");

sub durl
{
    my ($a) = @_;
    $a =~ tr/+/ /;
    $a =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;
    return $a;
}

package My::Cache;
use constant DBG => 0;
sub new { bless {}, shift }
sub get { if (DBG) { print "get $_[1]!\n"; } $_[0]->{ $_[1] } }
sub set { if (DBG) { print "set $_[1]!\n"; } $_[0]->{ $_[1] } = $_[2] }
