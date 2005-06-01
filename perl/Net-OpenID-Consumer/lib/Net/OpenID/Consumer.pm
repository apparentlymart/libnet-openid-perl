# LICENSE: You're free to distribute this under the same terms as Perl itself.

use strict;
use Carp ();
use LWP::UserAgent;
use URI::Fetch 0.02;

############################################################################
package Net::OpenID::Consumer;

use vars qw($VERSION $HAS_CRYPT_DSA $HAS_CRYPT_OPENSSL $HAS_OPENSSL);
$VERSION = "0.08";

use fields (
            'cache',          # the Cache object sent to URI::Fetch
            'ua',             # LWP::UserAgent instance to use
            'args',           # how to get at your args
            'server_selector',# optional subref that will pick which identity server to use, if multiple 
            'last_errcode',   # last error code we got
            'last_errtext',   # last error code we got
            'tmpdir',        # temporary directory to write files to
            );

use Net::OpenID::ClaimedIdentity;
use Net::OpenID::VerifiedIdentity;
use MIME::Base64 ();
use Digest::SHA1 ();

BEGIN {
    unless ($HAS_CRYPT_OPENSSL = eval "use Crypt::OpenSSL::DSA 0.12; 1;") {
        unless ($HAS_CRYPT_DSA = eval "use Crypt::DSA 0.13 (); use Convert::PEM 0.07; 1;") {
            unless ($HAS_OPENSSL = `which openssl`) {
                die "Net::OpenID::Consumer failed to load, due to missing dependencies.  You to have ".
                    "Crypt::OpenSSL::DSA (0.12+) -or- ".
                    "Crypt::DSA (0.13+) -or- ".
                    "the binary 'openssl' in your path.";
            }
        }
    }
}

sub new {
    my Net::OpenID::Consumer $self = shift;
    $self = fields::new( $self ) unless ref $self;
    my %opts = @_;

    $self->{ua} = delete $opts{ua};
    $self->args  (delete $opts{args}  );
    $self->cache (delete $opts{cache} );
    $self->tmpdir(delete $opts{tmpdir});

    Carp::croak("Unknown options: " . join(", ", keys %opts)) if %opts;
    return $self;
}

sub cache {
    my Net::OpenID::Consumer $self = shift;
    $self->{cache} = shift if @_;
    $self->{cache};
}

sub tmpdir {
    my Net::OpenID::Consumer $self = shift;
    if (@_ && $_[0]) {
        my $dir = shift;
        Carp::croak("Too many parameters") if @_;
        Carp::croak("Not a directory") unless -d $dir;
        $self->{tmpdir} = $dir;
    }
    $self->{tmpdir};
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

sub server_selector {
    my Net::OpenID::Consumer $self = shift;
    if (@_) {
        my $code = shift;
        Carp::croak("Too many parameters") if @_;
        Carp::croak("Not a CODE ref") unless ref $code eq "CODE";
        $self->{server_selector} = $code;
    }
    $self->{server_selector};
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
    $self->{last_errcode} = shift;
    $self->{last_errtext} = shift;
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

sub _get_publickey {
    my Net::OpenID::Consumer $self = shift;
    my ($key_url, $mode) = @_;

    my $cache = $self->cache;

    if ($mode eq "cache") {
        return undef unless $cache;
        return $cache->get($key_url);
    } elsif ($mode eq "network") {
        my $res = $self->ua->get($key_url);
        if ($res && $res->is_success) {
            my $pem = $res->content;
            $cache->set($key_url, $pem) if $cache && $pem;
            return $pem;
        }
        return undef;
    }
    die;
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

sub _pick_identity_server {
    my Net::OpenID::Consumer $self = shift;
    my $id_server_list = shift;

    if (my $hook = $self->{server_selector}) {
        return $hook->($self, $id_server_list);
    }

    # default just picks first one.
    return $id_server_list->[0];
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
        'openid.server' => [],
        'foaf' => undef,
        'foaf.maker' => undef,
        'rss' => undef,
        'atom' => undef,
    };

    # analyze link/meta tags
    while ($head =~ m!<(link|meta)\b([^>]+)>!g) {
        my ($type, $val) = ($1, $2);

        # OpenID servers
        # <link rel="openid.server" href="http://www.livejournal.com/misc/openid.bml" />
        if ($type eq "link" &&
            $val =~ /rel=.openid\.server./i &&
            $val =~ m!href=[\"\']([^\"\']+)[\"\']!i) {
            push @{ $ret->{"openid.server"} }, $1;
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

    return $ret;
}

sub _find_openid_servers {
    my Net::OpenID::Consumer $self = shift;
    my $url = shift;
    my $final_url_ref = shift;

    my $sem_info = $self->_find_semantic_info($url, $final_url_ref) or
        return;

    return $self->_fail("no_identity_servers") unless @{ $sem_info->{"openid.server"} || [] };
    @{ $sem_info->{"openid.server"} };
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
    return $self->_fail("bogus_url", "Invalid URL") unless $url =~ m!^http://!;
    # add a slash, if none exists
    $url .= "/" unless $url =~ m!^http://.+/!;

    my $final_url;
    my @id_servers = $self->_find_openid_servers($url, \$final_url)
        or return;

    return Net::OpenID::ClaimedIdentity->new(
                                             identity => $final_url,
                                             servers => \@id_servers,
                                             consumer => $self,
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

    my $sig64 = $self->args("openid.sig")             or return $self->_fail("no_sig");
    my $url   = $self->args("openid.assert_identity") or return $self->_fail("no_identity");
    my $retto = $self->args("openid.return_to")       or return $self->_fail("no_return_to");

    # present and valid
    my $ts  = $self->args("openid.timestamp");
    $ts =~ /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/ or return $self->_fail("malformed_timestamp");

    # make the raw string that we're going to check the signature against
    my $msg_plain = join("::",
                         $ts,
                         "assert_identity",
                         $url,
                         $retto);

    # to verify the signature, we need to fetch the public key, which
    # means we need to figure out what identity server to get the public
    # key from.  because there might be multiple, we'd previously
    # passed to ourselves the index that we chose.  so first go
    # re-fetch (possibly from cache) the page, re-find the acceptable
    # identity servers for this user, and get the public key
    my $final_url;
    my $sem_info = $self->_find_semantic_info($url, \$final_url);

    my @id_servers = @{ $sem_info->{"openid.server"} || [] }
        or return undef;

    return $self->_fail("identity_changed_on_fetch")
        if $url ne $final_url;

    my $used_idx = int($self->args("oicsr.idx") || 0);
    return $self->_fail("bad_idx")
        if $used_idx < 0 || $used_idx > 50;

    my $id_server = $id_servers[$used_idx]
        or return $self->_fail("identity_server_idx_empty");

    my $pem_url = $id_server;
    $pem_url .= ($id_server =~ /\?/) ? "&" : "?";
    $pem_url .= "openid.mode=getpubkey";

    my $msg = Digest::SHA1::sha1($msg_plain);
    my $sig = MIME::Base64::decode_base64($sig64);

    # try to check the public key both from our cached key, if
    # present, and then later from the network (which will also end up
    # caching it)
    my $verify_okay = 0;
    foreach my $mode ("cache", "network") {
        my $public_pem = $self->_get_publickey($pem_url, $mode);
        unless ($public_pem) {
            $self->_fail("public_key_fetch_error", "Couldn't get public key from $mode");
            next;
        }
        $verify_okay = $self->_dsa_verify($public_pem, $sig, $msg, $msg_plain);
        last if $verify_okay;
    }
    return undef unless $verify_okay;

    # TODO: nonce callback?

    # verified!
    return Net::OpenID::VerifiedIdentity->new(
                                              identity  => $url,
                                              foaf      => $sem_info->{"foaf"},
                                              foafmaker => $sem_info->{"foaf.maker"},
                                              rss       => $sem_info->{"rss"},
                                              atom      => $sem_info->{"atom"},
                                              consumer  => $self,
                                              );
}

sub _dsa_verify {
    my ($self, $public_pem, $sig, $msg, $msg_plain) = @_;

    if ($HAS_CRYPT_OPENSSL) {
        my $dsa_pub  = Crypt::OpenSSL::DSA->read_pub_key_str($public_pem)
            or $self->_fail("pubkey_parse_error", "Couldn't parse public key");
        my $good = eval { $dsa_pub->verify($msg, $sig) };
        return $self->_fail("verify_failed", "DSA signature verification failed") unless $good;
        return 1;
    }

    if ($HAS_CRYPT_DSA) {
        # Crypt::DSA (as of 0.13) has the odd requirement that it'll only
        # parse ASN.1-encoded objects if they're also base64-encoded
        my $sig64 = MIME::Base64::encode_base64($sig);

        my $sigobj = eval { Crypt::DSA::Signature->new(Content => $sig64) }
            or $self->_fail("sig_parse_error", "Failed to parse DSA signature");

        my $key =  eval {
            Crypt::DSA::Key->new(
                                 Type => "PEM",
                                 Content => $public_pem,
                                 )
            }
        or return $self->_fail("pubkey_parse_error", "Couldn't generate Crypt::DSA::Key from PEM");

        my $cd = Crypt::DSA->new;
        my $good = eval {
            $cd->verify(
                        Digest    => $msg,
                        Signature => $sigobj,
                        Key       => $key,
                        )
            };
        return $self->_fail("verify_failed", "DSA signature verification failed") unless $good;
        return 1;
    }

    if ($HAS_OPENSSL) {
        require File::Temp;
        my $sig_temp = eval { File::Temp->new(DIR => $self->tmpdir, TEMPLATE => "tmp.signatureXXXX") };

        # if temporary file creation failed, and they haven't set a tmpdir, try /tmp/ for them
        if (! $sig_temp) {
            my $likely_tmp = "/tmp";
            if (! $self->tmpdir && -d $likely_tmp) {
                $self->tmpdir($likely_tmp);
                $sig_temp = eval { File::Temp->new(DIR => $self->tmpdir, TEMPLATE => "tmp.signatureXXXX") };
            }
            return $self->_fail("tmpfile_error", "Couldn't create necessary temp files")
                unless $sig_temp;
        }

        my $pub_temp = File::Temp->new(DIR => $self->tmpdir, TEMPLATE => "tmp.pubkeyXXXX") or die;
        my $msg_temp = File::Temp->new(DIR => $self->tmpdir, TEMPLATE => "tmp.msgXXXX") or die;
        syswrite($sig_temp,$sig);
        syswrite($pub_temp,$public_pem);
        syswrite($msg_temp,$msg_plain);

        my $pid = open(my $fh, '-|', "openssl", "dgst", "-dss1", "-verify", "$pub_temp", "-signature", "$sig_temp", "$msg_temp");
        return $self->_fail("no_openssl", "OpenSSL not available") unless defined $pid;
        my $line = <$fh>;
        close($fh);
        my $exit_error = $?;
        return 1 if $line =~ /Verified OK/ && ! $exit_error;
        return $self->_fail("verify_failed", "DSA signature verification failed");

        # More portable form, but spews to stdout:
        #my $rv = system("openssl", "dgst", "-dss1", "-verify", "$pub_temp", "-signature", "$sig_temp", "$msg_temp");
        #return $self->_fail("verify_failed", "DSA signature verification failed") if $rv;
        #return 1;
    }

    return 0;
}

package OpenID::util;

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

You can set the C<ua>, C<cache>, C<args>, and C<tmpdir> in the
constructor.  See the corresponding method descriptions below.

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
declares the identity server, getting the DSA public key, verifying
the signature, etc.

=item $csr->B<server_selector>

Get/set the optional subref that selects which openid server to check
against, if the user has declared multiple.  By default, if no
server_selector is declared, the first is always chosen.

=item $csr->B<err>

Returns the last error, in form "errcode: errtext"

=item $csr->B<errcode>

Returns the last error code.

=item $csr->B<errtext>

Returns the last error text.

=item $csr->B<json_err>

Returns the last error code/text in JSON format.

=item $csr->B<tmpdir>($dir)

Set the temporary directory used if you don't have either Crypt::DSA
or Crypt::OpenSSL::DSA installed and you're using the OpenSSL binaries
to verify signatures.  Defaults to current working directory, and then
/tmp.  You shouldn't need to override this in most cases.

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
