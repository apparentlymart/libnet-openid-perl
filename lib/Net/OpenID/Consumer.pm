# LICENSE: You're free to distribute this under the same terms as Perl itself.

use strict;
use Carp ();
use LWP::UserAgent;
use URI::Fetch 0.02;

############################################################################
package Net::OpenID::Consumer;

use vars qw($VERSION);
$VERSION = "0.09";

use fields (
            'cache',          # the Cache object sent to URI::Fetch
            'ua',             # LWP::UserAgent instance to use
            'args',           # how to get at your args
            'last_errcode',   # last error code we got
            'last_errtext',   # last error code we got
            'debug',          # debug flag or codeblock
            );

use Net::OpenID::ClaimedIdentity;
use Net::OpenID::VerifiedIdentity;
use Net::OpenID::Association;

use MIME::Base64 ();
use Digest::SHA1 ();
use Crypt::DH 0.05;
use Time::Local qw(timegm);
use HTTP::Request;

sub new {
    my Net::OpenID::Consumer $self = shift;
    $self = fields::new( $self ) unless ref $self;
    my %opts = @_;

    $self->{ua} = delete $opts{ua};
    $self->args  (delete $opts{args}  );
    $self->cache (delete $opts{cache} );

    $self->{debug} = delete $opts{debug};

    Carp::croak("Unknown options: " . join(", ", keys %opts)) if %opts;
    return $self;
}

sub cache {
    my Net::OpenID::Consumer $self = shift;
    $self->{cache} = shift if @_;
    $self->{cache};
}

sub _debug {
    my Net::OpenID::Consumer $self = shift;
    return unless $self->{debug};

    if (ref $self->{debug} eq "CODE") {
        $self->{debug}->($_[0]);
    } else {
        print STDERR "[DEBUG Net::OpenID::Consumer] $_[0]\n";
    }
}

# given something that can have GET arguments, returns a subref to get them:
#   Apache
#   Apache::Request
#   CGI
#   HASH of get args
#   CODE returning get arg, given key

#   ...

sub args {
    my Net::OpenID::Consumer $self = shift;

    if (my $what = shift) {
        Carp::croak("Too many parameters") if @_;
        my $getter;
        if (! ref $what){
            Carp::croak("No args defined") unless $self->{args};
            return $self->{args}->($what);
        } elsif (ref $what eq "HASH") {
            $getter = sub { $what->{$_[0]}; };
        } elsif (ref $what eq "CGI") {
            $getter = sub { scalar $what->param($_[0]); };
        } elsif (ref $what eq "Apache") {
            my %get = $what->args;
            $getter = sub { $get{$_[0]}; };
        } elsif (ref $what eq "Apache::Request") {
            $getter = sub { scalar $what->param($_[0]); };
        } elsif (ref $what eq "CODE") {
            $getter = $what;
        } else {
            Carp::croak("Unknown parameter type ($what)");
        }
        if ($getter) {
            $self->{args} = $getter;
        }
    }
    $self->{args};
}

sub ua {
    my Net::OpenID::Consumer $self = shift;
    $self->{ua} = shift if @_;
    Carp::croak("Too many parameters") if @_;

    # make default one on first access
    unless ($self->{ua}) {
        my $ua = $self->{ua} = LWP::UserAgent->new;
        $ua->timeout(10);
    }

    $self->{ua};
}

sub _fail {
    my Net::OpenID::Consumer $self = shift;
    my ($code, $text) = @_;
    $self->{last_errcode} = $code;
    $self->{last_errtext} = $text;

    $self->_debug("fail($code) $text");
    wantarray ? () : undef;
}

sub json_err {
    my Net::OpenID::Consumer $self = shift;
    return OpenID::util::js_dumper({
        err_code => $self->{last_errcode},
        err_text => $self->{last_errtext},
    });
}

sub err {
    my Net::OpenID::Consumer $self = shift;
    $self->{last_errcode} . ": " . $self->{last_errtext};
}

sub errcode {
    my Net::OpenID::Consumer $self = shift;
    $self->{last_errcode};
}

sub errtext {
    my Net::OpenID::Consumer $self = shift;
    $self->{last_errtext};
}


sub _get_url_contents {
    my Net::OpenID::Consumer $self = shift;
    my  ($url, $final_url_ref, $hook) = @_;
    $final_url_ref ||= do { my $dummy; \$dummy; };

    my $ures = URI::Fetch->fetch($url,
                                 UserAgent        => $self->ua,
                                 Cache            => $self->cache,
                                 ContentAlterHook => $hook,
                                 )
        or return $self->_fail("url_fetch_error", "Error fetching URL: " . URI::Fetch->errstr);

    # who actually uses HTTP gone response status?  uh, nobody.
    if ($ures->status == URI::Fetch::URI_GONE()) {
        return $self->_fail("url_gone", "URL is no longer available");
    }

    my $res = $ures->http_response;
    $$final_url_ref = $res->request->uri->as_string;

    return $ures->content;
}

sub _find_semantic_info {
    my Net::OpenID::Consumer $self = shift;
    my $url = shift;
    my $final_url_ref = shift;

    my $trim_hook = sub {
        my $htmlref = shift;
        # trim everything past the body.  this is in case the user doesn't
        # have a head document and somebody was able to inject their own
        # head.  -- brad choate
        $$htmlref =~ s/<body\b.*//is;
    };

    my $doc = $self->_get_url_contents($url, $final_url_ref, $trim_hook) or
        return;

    # find <head> content of document (notably: the first head, if an attacker
    # has added others somehow)
    return $self->_fail("no_head_tag", "Couldn't find OpenID servers due to no head tag")
        unless $doc =~ m!<head[^>]*>(.*?)</head>!is;
    my $head = $1;

    my $ret = {
        'openid.server' => undef,
        'openid.delegate' => undef,
        'foaf' => undef,
        'foaf.maker' => undef,
        'rss' => undef,
        'atom' => undef,
    };

    # analyze link/meta tags
    while ($head =~ m!<(link|meta)\b([^>]+)>!g) {
        my ($type, $val) = ($1, $2);
        my $temp;

        # OpenID servers / delegated identities
        # <link rel="openid.server" href="http://www.livejournal.com/misc/openid.bml" />
        if ($type eq "link" &&
            $val =~ /\brel=.openid\.(server|delegate)./i && ($temp = $1) &&
            $val =~ m!\bhref=[\"\']([^\"\']+)[\"\']!i) {
            $ret->{"openid.$temp"} = $1;
            next;
        }

        # FOAF documents
        #<link rel="meta" type="application/rdf+xml" title="FOAF" href="http://brad.livejournal.com/data/foaf" />
        if ($type eq "link" &&
            $val =~ m!title=.foaf.!i &&
            $val =~ m!rel=.meta.!i &&
            $val =~ m!type=.application/rdf\+xml.!i &&
            $val =~ m!href=[\"\']([^\"\']+)[\"\']!i) {
            $ret->{"foaf"} = $1;
            next;
        }

        # FOAF maker info
        # <meta name="foaf:maker" content="foaf:mbox_sha1sum '4caa1d6f6203d21705a00a7aca86203e82a9cf7a'" />
        if ($type eq "meta" &&
            $val =~ m!name=.foaf:maker.!i &&
            $val =~ m!content=([\'\"])(.*?)\1!i) {
            $ret->{"foaf.maker"} = $2;
            next;
        }

        if ($type eq "meta" &&
            $val =~ m!name=.foaf:maker.!i &&
            $val =~ m!content=([\'\"])(.*?)\1!i) {
            $ret->{"foaf.maker"} = $2;
            next;
        }

        # RSS
        # <link rel="alternate" type="application/rss+xml" title="RSS" href="http://www.livejournal.com/~brad/data/rss" />
        if ($type eq "link" &&
            $val =~ m!rel=.alternate.!i &&
            $val =~ m!type=.application/rss\+xml.!i &&
            $val =~ m!href=[\"\']([^\"\']+)[\"\']!i) {
            $ret->{"rss"} = $1;
            next;
        }

        # Atom
        # <link rel="alternate" type="application/atom+xml" title="Atom" href="http://www.livejournal.com/~brad/data/rss" />
        if ($type eq "link" &&
            $val =~ m!rel=.alternate.!i &&
            $val =~ m!type=.application/atom\+xml.!i &&
            $val =~ m!href=[\"\']([^\"\']+)[\"\']!i) {
            $ret->{"atom"} = $1;
            next;
        }
    }

    $self->_debug("semantic info ($url) = " . join(", ", %$ret));

    return $ret;
}

sub _find_openid_server {
    my Net::OpenID::Consumer $self = shift;
    my $url = shift;
    my $final_url_ref = shift;

    my $sem_info = $self->_find_semantic_info($url, $final_url_ref) or
        return;

    return $self->_fail("no_identity_servers") unless $sem_info->{"openid.server"};
    $sem_info->{"openid.server"};
}

# returns Net::OpenID::ClaimedIdentity
sub claimed_identity {
    my Net::OpenID::Consumer $self = shift;
    my $url = shift;
    Carp::croak("Too many parameters") if @_;

    # trim whitespace
    $url =~ s/^\s+//;
    $url =~ s/\s+$//;
    return $self->_fail("empty_url", "Empty URL") unless $url;

    # do basic canonicalization
    $url = "http://$url" if $url && $url !~ m!^\w+://!;
    return $self->_fail("bogus_url", "Invalid URL") unless $url =~ m!^http://!i;
    # add a slash, if none exists
    $url .= "/" unless $url =~ m!^http://.+/!i;

    my $final_url;

    my $sem_info = $self->_find_semantic_info($url, \$final_url) or
        return $self->_fail("no_head_info", "No information found in head.");

    my $id_server = $sem_info->{"openid.server"} or
        return $self->_fail("no_identity_servers");

    return Net::OpenID::ClaimedIdentity->new(
                                             identity => $final_url,
                                             server   => $id_server,
                                             consumer => $self,
                                             delegate => $sem_info->{'openid.delegate'},
                                             );
}


sub user_setup_url {
    my Net::OpenID::Consumer $self = shift;
    my %opts = @_;
    my $post_grant = delete $opts{'post_grant'};
    Carp::croak("Unknown options: " . join(", ", keys %opts)) if %opts;
    return $self->_fail("bad_mode") unless $self->args("openid.mode") eq "id_res";

    my $setup_url = $self->args("openid.user_setup_url");

    OpenID::util::push_url_arg(\$setup_url, "openid.post_grant", $post_grant)
        if $setup_url && $post_grant;

    return $setup_url;
}

sub verified_identity {
    my Net::OpenID::Consumer $self = shift;
    Carp::croak("Too many parameters") if @_;

    return $self->_fail("bad_mode") unless $self->args("openid.mode") eq "id_res";

    # the asserted identity (the delegated one, if there is one, since the protocol
    # knows nothing of the original URL)
    my $a_ident  = $self->args("openid.identity")     or return $self->_fail("no_identity");

    my $sig64    = $self->args("openid.sig")          or return $self->_fail("no_sig");
    my $returnto = $self->args("openid.return_to")    or return $self->_fail("no_return_to");
    my $signed   = $self->args("openid.signed");

    my $real_ident = $self->args("oic.identity") || $a_ident;

    my $final_url;
    my $sem_info = $self->_find_semantic_info($real_ident, \$final_url);
    return $self->_fail("unexpected_url_redirect") unless $final_url eq $real_ident;

    my $server = $sem_info->{"openid.server"};
    return $self->_fail("no_identity_server")
        unless $server;

    # if openid.delegate was used, check that it was done correctly
    if ($a_ident ne $real_ident) {
        return $self->_fail("bogus_delegation") unless $sem_info->{"openid.delegate"} eq $a_ident;
    }

    my $assoc_handle = $self->args("openid.assoc_handle");

    $self->_debug("verified_identity: assoc_handle: $assoc_handle");
    my $assoc = Net::OpenID::Association::handle_assoc($self, $server, $assoc_handle);

    if ($assoc) {
        $self->_debug("verified_identity: verifying with found association");
        # verify the token
        my $token = "";
        foreach my $p (split(/,/, $signed)) {
            $token .= "$p:" . $self->args("openid.$p") . "\n";
        }

        my $good_sig = OpenID::util::b64(OpenID::util::hmac_sha1($token, $assoc->secret));
        return $self->_fail("signature_mismatch") unless $sig64 eq $good_sig;

    } else {
        $self->_debug("verified_identity: verifying using HTTP (dumb mode)");
        # didn't find an association.  have to do dumb consumer mode
        # and check it with a POST
        my %post = (
                    "openid.mode"         => "check_authentication",
                    "openid.identity"     => $a_ident,
                    "openid.assoc_handle" => $assoc_handle,
                    "openid.issued"       => $self->args("openid.issued"),
                    "openid.valid_to"     => $self->args("openid.valid_to"),
                    "openid.return_to"    => $returnto,
                    "openid.signed"       => $signed,
                    "openid.sig"          => $sig64,
                    );

        my $req = HTTP::Request->new(POST => $server);
        $req->header("Content-Type" => "application/x-www-form-urlencoded");
        $req->content(join("&", map { "$_=" . OpenID::util::eurl($post{$_}) } keys %post));

        my $ua  = $self->ua;
        my $res = $ua->request($req);

        # uh, some failure, let's go into dumb mode?
        return $self->_fail("naive_verify_failed_network") unless $res && $res->is_success;

        my $content = $res->content;
        my %args = OpenID::util::parse_keyvalue($content);
        return $self->_fail("naive_verify_failed_return") unless $args{'lifetime'};
    }

    # TODO: hook to check return to?

    $self->_debug("verified identity! = $real_ident");

    # verified!
    return Net::OpenID::VerifiedIdentity->new(
                                              identity  => $real_ident,
                                              foaf      => $sem_info->{"foaf"},
                                              foafmaker => $sem_info->{"foaf.maker"},
                                              rss       => $sem_info->{"rss"},
                                              atom      => $sem_info->{"atom"},
                                              consumer  => $self,
                                              );
}

package OpenID::util;

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
        $time = timegm($6, $5, $4, $3, $2 - 1, $1);
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


__END__

=head1 NAME

Net::OpenID::Consumer - library for consumers of OpenID identities

=head1 SYNOPSIS

  use Net::OpenID::Consumer;

  my $csr = Net::OpenID::Consumer->new(
    ua    => LWPx::ParanoidAgent->new,
    cache => Some::Cache->new,
    args  => $cgi,
  );

  # a user entered, say, "bradfitz.com" as their identity.  The first
  # step is to fetch that page, parse it, and get a
  # Net::OpenID::ClaimedIdentity object:

  my $claimed_identity = $csr->claimed_identity("bradfitz.com");

  # now your app has to send them at their identity server's endpoint
  # to get redirected to either a positive assertion that they own
  # that identity, or where they need to go to login/setup trust/etc.

  my $check_url = $claimed_identity->check_url(
    return_to  => "http://example.com/openid-check.app?yourarg=val",
    trust_root => "http://example.com/",
  );

  # so you send the user off there, and then they come back to
  # openid-check.app, then you see what the identity server said;

  if (my $setup_url = $csr->user_setup_url) {
       # redirect/link/popup user to $setup_url
  } elsif (my $vident = $csr->verified_identity) {
       my $verified_url = $vident->url;
       print "You are $verified_url !";
  } else {
       die "Error validating identity: " . $csr->err;
  }


=head1 DESCRIPTION

This is the Perl API for (the consumer half of) OpenID, a distributed
identity system based on proving you own a URL, which is then your
identity.  More information is available at:

  http://www.danga.com/openid/

=head1 CONSTRUCTOR

=over 4

=item C<new>

my $csr = Net::OpenID::Consumer->new([ %opts ]);

You can set the C<ua>, C<cache>, and C<args> in the constructor.  See
the corresponding method descriptions below.

=back

=head1 METHODS

=over 4

=item $csr->B<ua>($user_agent)

=item $csr->B<ua>

Getter/setter for the LWP::UserAgent (or subclass) instance which will
be used when web donwloads are needed.  It's highly recommended that
you use LWPx::ParanoidAgent, or at least read its documentation so
you're aware of why you should care.

=item $csr->B<cache>($cache)

=item $csr->B<cache>

Getter/setter for the optional (but recommended!) cache instance you
want to use for storing fetched parts of pages.  (identity server
public keys, and the E<lt>headE<gt> section of user's HTML pages)

The $cache object can be anything that has a -E<gt>get($key) and
-E<gt>set($key,$value) methods.  See L<URI::Fetch> for more
information.  This cache object is just passed to L<URI::Fetch>
directly.

=item $csr->B<args>($ref)

=item $csr->B<args>($param)

=item $csr->B<args>

Can be used in 1 of 3 ways:

1. Setting the way which the Consumer instances obtains GET parameters:

$csr->args( $reference )

Where $reference is either a HASH ref, CODE ref, Apache $r,
Apache::Request $apreq, or CGI.pm $cgi.  If a CODE ref, the subref
must return the value given one argument (the parameter to retrieve)

2. Get a paramater:

my $foo = $csr->args("foo");

When given an unblessed scalar, it retrieves the value.  It croaks if
you haven't defined a way to get at the parameters.

3. Get the getter:

my $code = $csr->args;

Without arguments, returns a subref that returns the value given a
parameter name.

=item $csr->B<claimed_identity>($url)

Given a user-entered $url (which could be missing http://, or have
extra whitespace, etc), returns either a Net::OpenID::ClaimedIdentity
object, or undef on failure.

Note that this identity is NOT verified yet.  It's only who the user
claims they are, but they could be lying.

=item $csr->B<user_setup_url>( [ %opts ] )

Returns the URL the user must return to in order to login, setup trust,
or do whatever the identity server needs them to do in order to make
the identity assertion which they previously initiated by entering
their claimed identity URL.  Returns undef if this setup URL isn't
required, in which case you should ask for the verified_identity.

The base URL this this function returns can be modified by using the
following options in %opts:

=over

=item C<post_grant>

What you're asking the identity server to do with the user after they
setup trust.  Can be either C<return> or C<close> to return the user
back to the return_to URL, or close the browser window with
JavaScript.  If you don't specify, the behavior is undefined (probably
the user gets a dead-end page with a link back to the return_to URL).
In any case, the identity server can do whatever it wants, so don't
depend on this.

=back

=item $csr->B<verified_identity>

Returns a Net::OpenID::VerifiedIdentity object, or undef.
Verification includes double-checking the reported identity URL
declares the identity server, verifying the signature, etc.

=item $csr->B<err>

Returns the last error, in form "errcode: errtext"

=item $csr->B<errcode>

Returns the last error code.

=item $csr->B<errtext>

Returns the last error text.

=item $csr->B<json_err>

Returns the last error code/text in JSON format.

=back

=head1 COPYRIGHT

This module is Copyright (c) 2005 Brad Fitzpatrick.
All rights reserved.

You may distribute under the terms of either the GNU General Public
License or the Artistic License, as specified in the Perl README file.
If you need more liberal licensing terms, please contact the
maintainer.

=head1 WARRANTY

This is free software. IT COMES WITHOUT WARRANTY OF ANY KIND.

=head1 SEE ALSO

OpenID website:  http://www.danga.com/openid/

L<Net::OpenID::ClaimedIdentity> -- part of this module

L<Net::OpenID::VerifiedIdentity> -- part of this module

L<Net::OpenID::Server> -- another module, for acting like an OpenID server

=head1 AUTHORS

Brad Fitzpatrick <brad@danga.com>
