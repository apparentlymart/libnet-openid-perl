# LICENSE: You're free to distribute this under the same terms as Perl itself.

use strict;
use Carp ();

############################################################################
package Net::OpenID::Server;

use vars qw($VERSION $HAS_CRYPT_DSA $HAS_CRYPT_OPENSSL);
$VERSION = "0.03";

use fields (
            'last_errcode',   # last error code we got
            'last_errtext',   # last error code we got

            'private_key',     # filename, scalar, or subref returning PEM contents
            'public_key',      # filename, scalar, or subref returning PEM contents

            'get_user',        # subref returning a defined value representing the logged in user, or undef if no user.
                               # this return value ($u) is passed to the other subrefs

            'is_identity',     # subref given a ($u, $identity_url).  should return true if $u owns the URL
                               # tree given by $identity_url.  not that $u may be undef, if get_user returned undef.
                               # it's up to you if you immediately return 0 on $u or do some work to make the
                               # timing be approximately equal, so you don't reveal if somebody's logged in or not

            'is_trusted',      # subref given a ($u, $trust_root, $is_identity).  should return true if $u wants $trust_root
                               # to know about their identity.  if you don't care about timing attacks, you can
                               # immediately return 0 if ! $is_identity, as the entire case can't succeed
                               # unless both is_identity and is_trusted pass, and is_identity is called first.

            'setup_url',       # setup URL base (optionally with query parameters) where users should go
                               # to login/setup trust/etc.

            'setup_map',       # optional hashref mapping some/all standard keys that would be added to
                               # setup_url to your preferred names.  the standard keys are:
                               # "trust_root", "return_to", "post_grant", and "is_identity"

            'args',            # that magic anything reference (returns a subref)
            );

use URI;
use MIME::Base64 ();
use Digest::SHA1 ();

BEGIN {
    unless ($HAS_CRYPT_OPENSSL = eval "use Crypt::OpenSSL::DSA 0.12; 1;") {
        unless ($HAS_CRYPT_DSA = eval "use Crypt::DSA (); use Convert::PEM; 1;") {
            die "You need Crypt::OpenSSL::DSA version 0.12+ -or- Crypt::DSA (ideally 0.13+)\n";
        }
    }
}

sub new {
    my Net::OpenID::Server $self = shift;
    $self = fields::new( $self ) unless ref $self;
    my %opts = @_;

    $self->{last_errcode} = undef;
    $self->{last_errtext} = undef;

    $self->args(delete $opts{args});

    $self->$_(delete $opts{$_})
        foreach (qw(
                    private_key public_key
                    get_user is_identity is_trusted
                    setup_url setup_map
                    ));

    Carp::croak("Unknown options: " . join(", ", keys %opts)) if %opts;
    return $self;
}

sub get_user    { &_getsetcode; }
sub is_identity { &_getsetcode; }
sub is_trusted  { &_getsetcode; }

sub public_key  { &_getsetkey; }
sub private_key { &_getsetkey; }

sub setup_url   { &_getset; }
sub setup_map   { &_getset; }


# given something that can have GET arguments, returns a subref to get them:
#   Apache
#   Apache::Request
#   CGI
#   HASH of get args
#   CODE returning get arg, given key

#   ...

sub args {
    my Net::OpenID::Server $self = shift;

    if (my $what = shift) {
        Carp::croak("Too many parameters") if @_;
        my $getter;
        if (! ref $what){
            Carp::croak("No args defined") unless $self->{args};
            return $self->{args}->($what) || "";
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

# returns ($content_type, $page), where $content_type can be "redirect"
# in which case a temporary redirect should be done to the URL in $page
# $content_type can also be "setup", in which case the setup_map variables
# are in $page as a hashref, and caller has full control from there.
#
# returns undef on error, in which case caller should generate an error
# page using info in $nos->err.
sub handle_page {
    my Net::OpenID::Server $self = shift;
    Carp::croak("Too many parameters") if @_;
    Carp::croak("handle_page must be called in list context") unless wantarray;

    return $self->_page_pubkey
        if $self->args("openid.mode") eq "getpubkey";

    my $mode = $self->args("openid.mode") || "checkid_immediate";

    return $self->_fail("unknown_mode") unless $mode =~ /^checkid_(?:immediate|setup)/;

    my $return_to = $self->args("openid.return_to");
    return $self->_fail("no_return_to") unless $return_to =~ m!^https?://!;

    my $trust_root = $self->args("openid.trust_root") || $return_to;
    return $self->_fail("invalid_trust_root") unless _url_is_under($trust_root, $return_to);

    my $identity = $self->args("openid.is_identity");

    # chop off the query string, in case our trust_root came from the return_to URL
    $trust_root =~ s/\?.*//;

    my $u = $self->_proxy("get_user");
    my $is_identity = $self->_proxy("is_identity", $u, $identity);
    my $is_trusted  = $self->_proxy("is_trusted",  $u, $trust_root, $is_identity);

    # where we'll be returning the user to:
    my $ret_url = $return_to;
    _push_url_arg(\$ret_url, "openid.mode", "id_res");

    # assertion path:
    if ($is_identity && $is_trusted) {
        my $now = _time_to_w3c();
        my $plain = join("::",
                         $now,
                         "assert_identity",
                         $identity,
                         $return_to);

        my $sig = $self->_dsa_sig($plain)
            or return;

        die "Failed to make signature (has length = " . length($sig) . ")"
            unless length($sig) >= 45 && length($sig) <= 48;

        my $sig64 = MIME::Base64::encode_base64($sig);
        chomp $sig64;  # remove \n

        _push_url_arg(\$ret_url,
                      "openid.assert_identity", $identity,
                      "openid.sig",             $sig64,
                      "openid.timestamp",       $now,
                      "openid.return_to",       $return_to);
        return ("redirect", $ret_url);
    }

    # assertion could not be made, so user requires setup (login/trust.. something)
    # two ways that can happen:  caller might have asked us for an immediate return
    # with a setup URL (the default), or explictly said that we're in control of
    # the user-agent's full window, and we can do whatever we want with them now.
    my %setup_args = (
                      $self->_setup_map("trust_root"),  $trust_root,
                      $self->_setup_map("return_to"),   $return_to,
                      $self->_setup_map("is_identity"), $identity,
                      );
    if ($mode eq "checkid_immediate") {
        # normal case, with setup URL returned
        my $setup_url = $self->{setup_url} or Carp::croak("No setup_url defined.");
        _push_url_arg(\$setup_url, %setup_args);
        _push_url_arg(\$ret_url, "openid.user_setup_url",  $setup_url);
        return ("redirect", $ret_url);
    } else {
        # the "checkid_setup" mode, where we take control of the user-agent
        # and return to their return_to URL later.
        return ("setup", \%setup_args);
    }
}

sub _setup_map {
    my Net::OpenID::Server $self = shift;
    my $key = shift;
    Carp::croak("Too many parameters") if @_;
    return $key unless ref $self->{setup_map} eq "HASH" && $self->{setup_map}{$key};
    return $self->{setup_map}{$key};
}

sub _proxy {
    my Net::OpenID::Server $self = shift;
    my $meth = shift;

    my $getter = $self->{$meth};
    Carp::croak("You haven't defined a subref for '$meth'")
        unless ref $getter eq "CODE";

    return $getter->(@_);
}

sub _page_pubkey {
    my Net::OpenID::Server $self = shift;
    my $pubkey = $self->_get_key_contents("public")
        or return;

    return ("text/plain", $pubkey);
}

sub _get_key_contents {
    my Net::OpenID::Server $self = shift;
    my $key = shift;
    Carp::croak("Too many parameters") if @_;
    Carp::croak("Unknown key type") unless $key =~ /^public|private$/;

    my $mval = $self->{"${key}_key"};
    my $contents;

    if (ref $mval eq "CODE") {
        $contents = $mval->();
    } elsif ($mval !~ /\n/ && -f $mval) {
        local *KF;
        return $self->_fail("key_open_failure", "Couldn't open key file for reading")
            unless open(KF, $mval);
        $contents = do { local $/; <KF>; };
        close KF;
    } else {
        $contents = $mval;
    }

    return $self->_fail("invalid_key", "$key file not in correct format")
        unless $contents =~ /\-\-\-\-BEGIN/ && $contents =~ /\-\-\-\-END/;
    return $contents;
}


sub _getset {
    my Net::OpenID::Server $self = shift;
    my $param = (caller(1))[3];
    $param =~ s/.+:://;

    if (@_) {
        my $val = shift;
        Carp::croak("Too many parameters") if @_;
        $self->{$param} = $val;
    }
    return $self->{$param};
}

sub _getsetcode {
    my Net::OpenID::Server $self = shift;
    my $param = (caller(1))[3];
    $param =~ s/.+:://;

    if (my $code = shift) {
        Carp::croak("Too many parameters") if @_;
        Carp::croak("Expected CODE reference") unless ref $code eq "CODE";
        $self->{$param} = $code;
    }
    return $self->{$param};
}

sub _getsetkey {
    my Net::OpenID::Server $self = shift;
    my $which = (caller(1))[3] =~ /public/ ? "public" : "private";

    if (my $key = shift) {
        Carp::croak("Too many parameters") if @_;
        $self->{"${which}_key"} = $key;
    } else {
        return $self->_get_key_contents($which);
    }
}

sub _fail {
    my Net::OpenID::Server $self = shift;
    $self->{last_errcode} = shift;
    $self->{last_errtext} = shift;
    wantarray ? () : undef;
}

sub err {
    my Net::OpenID::Server $self = shift;
    $self->{last_errcode} . ": " . $self->{last_errtext};
}

sub errcode {
    my Net::OpenID::Server $self = shift;
    $self->{last_errcode};
}

sub errtext {
    my Net::OpenID::Server $self = shift;
    $self->{last_errtext};
}

sub _dsa_sig {
    my ($self, $plain) = @_;
    my $msg = Digest::SHA1::sha1($plain);

    if ($HAS_CRYPT_OPENSSL) {
        my $priv = $self->_get_key_contents("private")
            or return;
        my $dsa_priv  = Crypt::OpenSSL::DSA->read_priv_key_str($priv)
            or $self->_fail("privkey_parse_error", "Couldn't parse private key");
        return $dsa_priv->sign($msg);
    }

    if ($HAS_CRYPT_DSA) {
        my $dsa = Crypt::DSA->new;
        my $key;
        if (-f $self->{private_key}) {
            $key = Crypt::DSA::Key->new(Filename => $self->{private_key},
                                        Type => 'PEM');
        } elsif ($Crypt::DSA::VERSION >= 0.14) {
            my $priv = $self->_get_key_contents("private")
                or return;

            $key = Crypt::DSA::Key->new(Content => $priv,
                                        Type => 'PEM');
        } else {
            my $priv = $self->_get_key_contents("private")
                or return;

            # gross:  diving into the innards of Crypt::DSA::Key so
            # we don't have to write a private key to disk
            $key = Crypt::DSA::Key->new;

            my $class = 'Crypt::DSA::Key::PEM';
            eval "use $class;";
            Carp::croak("Unable to load Crypt::DSA::Key::PEM\n") if $@;
            bless $key, $class;

            # gross, gross, gross...
            $key->{Content} = $priv;
            $key->deserialize(Content => $priv);
        }

        return $self->_fail("privkey_parse_error", "Couldn't parse private key")
            unless $key;

        my $sigobj = $dsa->sign(Digest => $msg, Key => $key);
        return $self->_fail("sign_failure", "Couldn't do Crypt::DSA sign")
            unless $sigobj && $sigobj->r;

        my $asn = Convert::ASN1->new;
        $asn->prepare("SEQUENCE { r INTEGER, s INTEGER }");
        my $sig = $asn->encode( r => $sigobj->r, s => $sigobj->s );
        return $sig;
    }

    # OpenSSL mode, if it's later supported:
    # openssl dgst -dss1 -hex -sign yadis_private.key foobar.txt > sig.txt

}

sub _eurl
{
    my $a = $_[0];
    $a =~ s/([^a-zA-Z0-9_\,\-.\/\\\: ])/uc sprintf("%%%02x",ord($1))/eg;
    $a =~ tr/ /+/;
    return $a;
}

# FIXME: duplicated in Net::OpenID::Consumer's VerifiedIdentity
sub _url_is_under {
    my ($root, $test, $err_ref) = @_;

    my $err = sub {
        $$err_ref = shift if $err_ref;
        return undef;
    };

    my $ru = URI->new($root);
    return $err->("invalid root scheme") unless $ru->scheme =~ /^https?$/;
    my $tu = URI->new($test);
    return $err->("invalid test scheme") unless $tu->scheme =~ /^https?$/;
    return $err->("schemes don't match") unless $ru->scheme eq $tu->scheme;
    return $err->("ports don't match") unless $ru->port == $tu->port;

    # check hostnames
    my $ru_host = $ru->host;
    my $tu_host = $tu->host;
    my $wildcard_host = 0;
    if ($ru_host =~ s!^\*\.!!) {
        $wildcard_host = 1;
    }
    unless ($ru_host eq $tu_host) {
        if ($wildcard_host) {
            return $err->("host names don't match") unless
                $tu_host =~ /\.\Q$ru_host\E$/;
        } else {
            return $err->("host names don't match");
        }
    }

    # check paths
    my $ru_path = $ru->path || "/";
    my $tu_path = $tu->path || "/";
    $ru_path .= "/" unless $ru_path =~ m!/$!;
    $tu_path .= "/" unless $tu_path =~ m!/$!;
    return $err->("path not a subpath") unless $tu_path =~ m!^\Q$ru_path\E!;

    return 1;
}

sub _time_to_w3c {
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = gmtime(time());
    $mon++;
    $year += 1900;

    return sprintf("%04d-%02d-%02dT%02d:%02d:%02dZ",
                   $year, $mon, $mday,
                   $hour, $min, $sec);
}

sub _push_url_arg {
    my $uref = shift;
    $$uref =~ s/[&?]$//;
    my $got_qmark = ($$uref =~ /\?/);

    while (@_) {
        my $key = shift;
        my $value = shift;
        $$uref .= $got_qmark ? "&" : ($got_qmark = 1, "?");
        $$uref .= _eurl($key) . "=" . _eurl($value);
    }
}


__END__

=head1 NAME

Net::OpenID::Server - library for consumers of OpenID identities

=head1 SYNOPSIS

  use Net::OpenID::Server;

  my $nos = Net::OpenID::Server->new(
    args         => $cgi,
    private_key  => \&get_priv_key_from_database,
    public_key   => "public_key.txt",
    get_user     => \&get_user,
    is_identity  => \&is_identity,
    is_trusted   => \&is_trusted
    setup_url    => "http://example.com/pass-identity.bml",
    setup_map    => { "post_grant" => "do_after_grant" },
  );

  # From your OpenID server endpoint:

  my ($type, $data) = $nos->handle_page;
  if ($type eq "redirect") {
      WebApp::redirect_to($data);
  } elsif ($type eq "setup") {
      my %setup_opts = %$data;
      # ... show them setup page(s), with options from setup_map
      # it's then your job to redirect them at the end to "return_to"
      # (or whatever you've named it in setup_map)
  } else {
      WebApp::set_content_type($type);
      WebApp::print($data);
  }

=head1 DESCRIPTION

This is the Perl API for (the server half of) OpenID, a distributed
identity system based on proving you own a URL, which is then your
identity.  More information is available at:

  http://www.danga.com/openid/

=head1 CONSTRUCTOR

=over 4

=item Net::OpenID::Server->B<new>([ %opts ])

You can set anything in the constructor options that there are
getters/setters methods for below.  That includes: args, private_key,
public_key, get_user, is_identity, is_trusted, setup_url, and setup_map.
See below for docs.

=back

=head1 METHODS

=over 4

=item ($type, $data) = $nos->B<handle_page>

Returns a $type and $data, where $type can be:

=over

=item C<redirect>

... in which case you redirect the user (via your web framework's
redirect functionality) to the URL specified in $data.

=item C<setup>

... in which case you should show the user a page (or redirect them to
one of your pages) where they can setup trust for the given
"trust_root" in the hashref in $data, and then redirect them to
"return_to" at the end.  Note that the parameters in the $data hashref
are as you named them with setup_map.

=item Some content type

Otherwise, set the content type to $type and print the page out, the
contents of which are in $data.

=back

=item $nos->B<args>($ref)

=item $nos->B<args>($param)

=item $nos->B<args>

Can be used in 1 of 3 ways:

1. Setting the way which the Server instances obtains GET parameters:

$nos->args( $reference )

Where $reference is either a HASH ref, CODE ref, Apache $r,
Apache::Request $apreq, or CGI.pm $cgi.  If a CODE ref, the subref
must return the value given one argument (the parameter to retrieve)

2. Get a paramater:

my $foo = $nos->args("foo");

When given an unblessed scalar, it retrieves the value.  It croaks if
you haven't defined a way to get at the parameters.

3. Get the getter:

my $code = $nos->args;

Without arguments, returns a subref that returns the value given a
parameter name.

=item $nos->B<public_key>

Returns scalar with PEM-encoded public key.

=item $nos->B<public_key>($key_arg)

Set the public_key.  $key_arg can be a scalar with the PEM-encoded
key, a scalar of the filename holding the public key, or a subref
that returns the public key when requested.

=item $nos->B<private_key>

=item $nos->B<private_key>($key_arg)

Get/set private_key.  Same interface as public_key.

=item $nos->B<get_user>($code)

=item $code = $nos->B<get_user>; $u = $code->();

Get/set the subref returning a defined value representing the logged
in user, or undef if no user.  The return value (let's call it $u) is
not touched.  It's simply given back to your other callbacks
(is_identity and is_trusted).

=item $nos->B<is_identity>($code)

=item $code = $nos->B<is_identity>; $code->($u, $identity_url)

Get/set the subref which is responsible for returning true if the
logged in user $u (which may be undef if user isn't logged in) owns
the URL tree given by $identity_url.  Note that if $u is undef, your
function should always return 0.  The framework doesn't do that for
you so you can do unnecessary work on purpose if you care about
exposing information via timing attacks.

=item $nos->B<is_trusted>($code)

=item $code = $nos->B<is_trusted>; $code->($u, $trust_root, $is_identity)

Get/set the subref which is responsible for returning true if the
logged in user $u (which may be undef if user isn't logged in) trusts
the URL given by $trust_root to know his/her identity.  Note that if
either $u is undef, or $is_identity is false (this is the result of
your previous is_identity callback), you should return 0.  But your
callback is always run so you can avoid timing attacks, if you care.

=item $nos->B<setup_url>($url)

=item $url = $nos->B<setup_url>

Get/set the user setup URL.  This is the URL the user is told to go to
if they're either not logged in, not who they said they were, or trust
hasn't been setup.  You use the same URL in all three cases.  Your
setup URL may contain existing query parameters.

=item $nos->B<setup_map>($hashref)

=item $hashref = $nos->B<setup_map>

When this module gives a consumer site a user_setup_url from your
provided setup_url, it also has to append a number of get parameters
onto your setup_url, so your app based at that setup_url knows what it
has to setup.  Those keys are named, by default, "trust_root",
"return_to", "post_grant", and "is_identity".  If you don't like those
parameter names, this $hashref setup_map lets you change one or more
of them.  The hashref's keys should be the default values, with values
being the parameter names you want.

=item $nos->B<err>

Returns the last error, in form "errcode: errtext";

=item $nos->B<errcode>

Returns the last error code.

=item $nos->B<errtext>

Returns the last error text.

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

=head1 AUTHORS

Brad Fitzpatrick <brad@danga.com>

