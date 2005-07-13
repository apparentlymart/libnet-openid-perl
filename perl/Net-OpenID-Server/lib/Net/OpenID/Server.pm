# LICENSE: You're free to distribute this under the same terms as Perl itself.

use strict;
use Carp ();

############################################################################
package Net::OpenID::Server;

use vars qw($VERSION);
$VERSION = "0.08.90"; # 9-pre

use fields (
            'last_errcode',   # last error code we got
            'last_errtext',   # last error code we got

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
                               # setup_url to your preferred names. 

            'get_args',        # thing to get get args
            'post_args',       # thing to get post args

            'server_secret',    # subref returning secret given $time
            'secret_gen_interval',
            'secret_expire_age',

	    'compat',          # version 1.0 compatibility flag (otherwise only sends 1.1 parameters)
            );

use URI;
use MIME::Base64 ();
use Digest::SHA1 qw(sha1 sha1_hex);
use Crypt::DH 0.05;
use Math::BigInt;
use Time::Local qw(timegm);

sub new {
    my Net::OpenID::Server $self = shift;
    $self = fields::new( $self ) unless ref $self;
    my %opts = @_;

    $self->{last_errcode} = undef;
    $self->{last_errtext} = undef;

    $self->get_args(delete $opts{get_args} || delete $opts{args});
    $self->post_args(delete $opts{post_args});

    $opts{'secret_gen_interval'} ||= 86400;
    $opts{'secret_expire_age'}   ||= 86400 * 14;

    # use compatibility mode until 30 days from July 10, 2005
    unless (defined $opts{'compat'}) {
	$opts{'compat'} = time() < 1121052339 + 86400*30 ? 1 : 0;
    }

    $self->$_(delete $opts{$_})
        foreach (qw(
                    get_user is_identity is_trusted
                    setup_url setup_map server_secret
                    secret_gen_interval secret_expire_age
		    compat
                    ));

    Carp::croak("Unknown options: " . join(", ", keys %opts)) if %opts;
    return $self;
}

sub get_user     { &_getsetcode; }
sub is_identity  { &_getsetcode; }
sub is_trusted   { &_getsetcode; }

sub setup_url   { &_getset; }
sub setup_map   { &_getset; }
sub compat      { &_getset; }

sub server_secret       { &_getset; }
sub secret_gen_interval { &_getset; }
sub secret_expire_age   { &_getset; }


# returns ($content_type, $page), where $content_type can be "redirect"
# in which case a temporary redirect should be done to the URL in $page
# $content_type can also be "setup", in which case the setup_map variables
# are in $page as a hashref, and caller has full control from there.
#
# returns undef on error, in which case caller should generate an error
# page using info in $nos->err.
sub handle_page {
    my Net::OpenID::Server $self = shift;
    my %opts = @_;
    my $redirect_for_setup = delete $opts{'redirect_for_setup'};
    Carp::croak("Unknown options: " . join(", ", keys %opts)) if %opts;
    Carp::croak("handle_page must be called in list context") unless wantarray;

    return $self->_mode_associate
        if $self->pargs("openid.mode") eq "associate";

    return $self->_mode_check_authentication
        if $self->pargs("openid.mode") eq "check_authentication";

    my $mode = $self->args("openid.mode");
    unless ($mode) {
        return ("text/html",
                "<html><head><title>OpenID Endpoint</title></head><body>This is an OpenID server endpoint, not a human-readable resource.  For more information, see <a href='http://openid.net/'>http://openid.net/</a>.</body></html>");
    }

    return $self->_error_page("Unknown mode")
        unless $mode =~ /^checkid_(?:immediate|setup)/;

    return $self->_mode_checkid($mode, $redirect_for_setup);
}


# given something that can have GET arguments, returns a subref to get them:
#   Apache
#   Apache::Request
#   CGI
#   HASH of get args
#   CODE returning get arg, given key

#   ...

# GET args
*args = \&get_args;
sub get_args {
    my Net::OpenID::Server $self = shift;

    if (my $what = shift) {
        Carp::croak("Too many parameters") if @_;
        my $getter;
        if (! ref $what){
            Carp::croak("No get_args defined") unless $self->{get_args};
            return $self->{get_args}->($what) || "";
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
            $self->{get_args} = $getter;
        }
    }
    $self->{get_args};
}

# POST args
*pargs = \&post_args;
sub post_args {
    my Net::OpenID::Server $self = shift;

    if (my $what = shift) {
        Carp::croak("Too many parameters") if @_;
        my $getter;
        if (! ref $what){
            Carp::croak("No pargs defined") unless $self->{post_args};
            return $self->{post_args}->($what) || "";
        } elsif (ref $what eq "HASH") {
            $getter = sub { $what->{$_[0]}; };
        } elsif (ref $what eq "CGI") {
            $getter = sub { scalar $what->param($_[0]); };
        } elsif (ref $what eq "Apache::Request") {
            $getter = sub { scalar $what->param($_[0]); };
        } elsif (ref $what eq "CODE") {
            $getter = $what;
        } else {
            Carp::croak("Unknown parameter type ($what)");
        }
        if ($getter) {
            $self->{post_args} = $getter;
        }
    }
    $self->{post_args};
}

sub cancel_return_url {
    my Net::OpenID::Server $self = shift;

    my %opts = @_;
    my $return_to = delete $opts{'return_to'};
    Carp::croak("Unknown options: " . join(", ", keys %opts)) if %opts;

    my $ret_url = $return_to;
    _push_url_arg(\$ret_url, "openid.mode" => "cancel");
    return $ret_url;
}

sub signed_return_url {
    my Net::OpenID::Server $self = shift;
    my %opts = @_;
    my $identity     = delete $opts{'identity'};
    my $return_to    = delete $opts{'return_to'};
    my $assoc_handle = delete $opts{'assoc_handle'};

    # verify the trust_root, if provided
    if (my $trust_root = delete $opts{'trust_root'}) {
        return undef unless _url_is_under($trust_root, $return_to);
    }
    Carp::croak("Unknown options: " . join(", ", keys %opts)) if %opts;

    my $ret_url = $return_to;

    my $c_sec;
    my $invalid_handle;

    if ($assoc_handle) {
        $c_sec = $self->_secret_of_handle($assoc_handle);

        # tell the consumer that their provided handle is bogus
        # (or we forgot it) and that they should stop using it
        $invalid_handle = $assoc_handle unless $c_sec;
    }

    unless ($c_sec) {
        # dumb consumer mode
        ($assoc_handle, $c_sec, undef) = $self->_generate_association(type => "HMAC-SHA1",
                                                                      dumb => 1);
    }

    my @sign = qw(mode identity return_to);
    my $now = time();
    my %arg = (
               mode         => "id_res",
               identity     => $identity,
               return_to    => $return_to,
               assoc_handle => $assoc_handle,
               );

    # compatibility mode with version 1.0 of the protocol which still
    # had absolute dates
    if ($self->{compat}) {
        $arg{issued}   = _time_to_w3c($now);
        $arg{valid_to} = _time_to_w3c($now + 3600);
        push @sign, "issued", "valid_to";
    }

    # include the list of all fields we'll be signing
    $arg{signed} = join(",", @sign);

    my @arg; # arguments we'll append to the URL
    my $token_contents = "";
    foreach my $f (@sign) {
        $token_contents .= "$f:$arg{$f}\n";
        push @arg, "openid.$f" => $arg{$f};
        delete $arg{$f};
    }

    # include the arguments we didn't sign in the URL
    push @arg, map { ( "openid.$_" => $arg{$_} ) } sort keys %arg;

    # include (unsigned) the handle we're telling the consumer to invalidate
    if ($invalid_handle) {
        push @arg, "openid.invalidate_handle" => $invalid_handle;
    }

    # finally include the signature
    push @arg, "openid.sig" => _b64(hmac_sha1($token_contents, $c_sec));

    _push_url_arg(\$ret_url, @arg);
    return $ret_url;
}

sub _mode_checkid {
    my Net::OpenID::Server $self = shift;
    my ($mode, $redirect_for_setup) = @_;

    my $return_to = $self->args("openid.return_to");
    return $self->_fail("no_return_to") unless $return_to =~ m!^https?://!;

    my $trust_root = $self->args("openid.trust_root") || $return_to;
    return $self->_fail("invalid_trust_root") unless _url_is_under($trust_root, $return_to);

    my $identity = $self->args("openid.identity");

    # chop off the query string, in case our trust_root came from the return_to URL
    $trust_root =~ s/\?.*//;

    my $u = $self->_proxy("get_user");
    my $is_identity = $self->_proxy("is_identity", $u, $identity);
    my $is_trusted  = $self->_proxy("is_trusted",  $u, $trust_root, $is_identity);

    # assertion path:
    if ($is_identity && $is_trusted) {
        my $ret_url = $self->signed_return_url(
                                               identity => $identity,
                                               return_to => $return_to,
                                               assoc_handle => $self->args("openid.assoc_handle"),
                                               );
        return ("redirect", $ret_url);
    }

    # assertion could not be made, so user requires setup (login/trust.. something)
    # two ways that can happen:  caller might have asked us for an immediate return
    # with a setup URL (the default), or explictly said that we're in control of
    # the user-agent's full window, and we can do whatever we want with them now.
    my %setup_args = (
                      $self->_setup_map("trust_root"),   $trust_root,
                      $self->_setup_map("return_to"),    $return_to,
                      $self->_setup_map("identity"),     $identity,
                      $self->_setup_map("assoc_handle"), $self->args("openid.assoc_handle"),
                      );

    my $setup_url = $self->{setup_url} or Carp::croak("No setup_url defined.");
    _push_url_arg(\$setup_url, %setup_args);

    if ($mode eq "checkid_immediate") {
        my $ret_url = $return_to;
        _push_url_arg(\$ret_url, "openid.mode",           "id_res");
        _push_url_arg(\$ret_url, "openid.user_setup_url", $setup_url);
        return ("redirect", $ret_url);
    } else {
        # the "checkid_setup" mode, where we take control of the user-agent
        # and return to their return_to URL later.

        if ($redirect_for_setup) {
            return ("redirect", $setup_url);
        } else {
            return ("setup", \%setup_args);
        }
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

sub _get_server_secret {
    my Net::OpenID::Server $self = shift;
    my $time = shift;

    my $ss;
    if (ref $self->{server_secret} eq "CODE") {
        $ss = $self->{server_secret};
    } elsif ($self->{server_secret}) {
        $ss = sub { return $self->{server_secret}; };
    } else {
        Carp::croak("You haven't defined a server_secret value or subref defined.\n");
    }

    my $sec = $ss->($time);
    Carp::croak("Server secret too long") if length($sec) > 255;
    return $sec;
}

# returns ($assoc_handle, $secret, $expires)
sub _generate_association {
    my Net::OpenID::Server $self = shift;
    my %opts = @_;
    my $type = delete $opts{type};
    my $dumb = delete $opts{dumb} || 0;
    Carp::croak("Unknown options: " . join(", ", keys %opts)) if %opts;
    die unless $type eq "HMAC-SHA1";

    my $now = time();
    my $sec_time = $now - ($now % $self->secret_gen_interval);

    my $s_sec = $self->_get_server_secret($sec_time)
        or Carp::croak("server_secret didn't return a secret given what should've been a valid time ($sec_time)\n");

    my $nonce = _rand_chars(20);
    $nonce = "STLS.$nonce" if $dumb;  # flag nonce as stateless

    my $handle = "$now:$nonce";
    $handle .= ":" . substr(hmac_sha1_hex($handle, $s_sec), 0, 10);

    my $c_sec = $self->_secret_of_handle($handle, dumb => $dumb)
        or return ();

    my $expires = $sec_time + $self->secret_expire_age;
    return ($handle, $c_sec, $expires);
}

sub _secret_of_handle {
    my Net::OpenID::Server $self = shift;
    my ($handle, %opts) = @_;

    my $dumb_mode = delete $opts{'dumb'}      || 0;
    my $no_verify = delete $opts{'no_verify'} || 0;
    Carp::croak("Unknown options: " . join(", ", keys %opts)) if %opts;

    my ($time, $nonce, $nonce_sig80) = split(/:/, $handle);
    return unless $time =~ /^\d+$/ && $nonce && $nonce_sig80;

    # check_authentication mode only verifies signatures made with
    # dumb (stateless == STLS) handles, so if that caller requests it,
    # don't return the secrets here of non-stateless handles
    return if $dumb_mode && $nonce !~ /^STLS\./;

    my $sec_time = $time - ($time % $self->secret_gen_interval);
    my $s_sec = $self->_get_server_secret($sec_time)  or return;

    length($nonce)       == ($dumb_mode ? 25 : 20) or return;
    length($nonce_sig80) == 10                     or return;

    return unless $no_verify || $nonce_sig80 eq substr(hmac_sha1_hex("$time:$nonce", $s_sec), 0, 10);

    return hmac_sha1($handle, $s_sec);
}

sub _mode_associate {
    my Net::OpenID::Server $self = shift;

    my $now = time();
    my %prop;

    my $assoc_type = "HMAC-SHA1";
    # FUTURE: protocol will let people choose their preferred authn scheme,
    # in which case we see if we support any of them, and override the
    # default value of HMAC-SHA1

    my ($assoc_handle, $secret, $expires) =
        $self->_generate_association(type => $assoc_type);

    # make absolute form of expires
    my $exp_abs = $expires > 1000000000 ? $expires : $expires + $now;

    # make relative form of expires
    my $exp_rel = $exp_abs - $now;

    $prop{'assoc_type'}   = $assoc_type;
    $prop{'assoc_handle'} = $assoc_handle;
    $prop{'expires_in'}   = $exp_rel;

    if ($self->{compat}) {
        $prop{'expiry'}   = _time_to_w3c($exp_abs);
        $prop{'issued'}   = _time_to_w3c($now);
    }

    if ($self->pargs("openid.session_type") eq "DH-SHA1") {

        my $dh   = Crypt::DH->new;
        my $p    = _arg2bi($self->pargs("openid.dh_modulus")) || _default_p();
        my $g    = _arg2bi($self->pargs("openid.dh_gen"))     || _default_g();
        my $cpub = _arg2bi($self->pargs("openid.dh_consumer_public"));

        return $self->_error_page("invalid dh params p=$p, g=$g, cpub=$cpub")
            unless $p > 10 && $g > 1 && $cpub;

        $dh->p($p);
        $dh->g($g);
        $dh->generate_keys;

        my $dh_sec = $dh->compute_secret($cpub);

        $prop{'dh_server_public'} = _bi2arg($dh->pub_key);
        $prop{'session_type'}     = "DH-SHA1";
        $prop{'enc_mac_key'}      = _b64($secret ^ sha1(_bi2bytes($dh_sec)));

    } else {
        $prop{'mac_key'} = _b64($secret);
    }

    return $self->_serialized_props(\%prop);
}

sub _mode_check_authentication {
    my Net::OpenID::Server $self = shift;

    my $signed = $self->pargs("openid.signed") || "";
    my $token = "";
    foreach my $param (split(/,/, $signed)) {
        next unless $param =~ /^\w+$/;
        my $val = $param eq "mode" ? "id_res" : $self->pargs("openid.$param");
        next unless defined $val;
        next if $val =~ /\n/;
        $token .= "$param:$val\n";
    }

    my $sig = $self->pargs("openid.sig");
    my $ahandle = $self->pargs("openid.assoc_handle")
        or return $self->_error_page("no_assoc_handle");

    my $c_sec = $self->_secret_of_handle($ahandle, dumb => 1)
        or return $self->_error_page("bad_handle");

    my $good_sig = _b64(hmac_sha1($token, $c_sec));

    my $is_valid = $sig eq $good_sig;

    my $ret = {
        is_valid => $is_valid ? "true" : "false",
    };

    if ($self->{compat}) {
        $ret->{lifetime} = 3600;
        $ret->{WARNING} = 
            "The lifetime parameter is deprecated and will " .
            "soon be removed.  Use is_valid instead.  " .
            "See openid.net/specs.bml.";
    }

    # tell them if a handle they asked about is invalid, too
    if (my $ih = $self->pargs("openid.invalidate_handle")) {
        $c_sec = $self->_secret_of_handle($ih);
        $ret->{"invalidate_handle"} = $ih unless $c_sec;
    }

    return $self->_serialized_props($ret);
}

sub _b64 {
    my $val = MIME::Base64::encode_base64($_[0]);
    $val =~ s/\s+//g;
    return $val;
}

sub _error_page {
    my Net::OpenID::Server $self = shift;
    return $self->_serialized_props({ 'error' => $_[0] });
}

sub _serialized_props {
    my Net::OpenID::Server $self = shift;
    my $props = shift;

    my $body = "";
    foreach (sort keys %$props) {
        $body .= "$_:$props->{$_}\n";
    }

    return ("text/plain", $body);
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
    my $time = shift || time();
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = gmtime($time);
    $mon++;
    $year += 1900;

    return sprintf("%04d-%02d-%02dT%02d:%02d:%02dZ",
                   $year, $mon, $mday,
                   $hour, $min, $sec);
}

sub _w3c_to_time {
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
    return _b64(_bi2bytes($_[0]));
}

sub _bytes2bi {
    return Math::BigInt->new("0b" . unpack("B*", $_[0]));
}

sub _arg2bi {
    return undef unless defined $_[0] && $_[0] ne "";
    # don't acccept base-64 encoded numbers over 700 bytes.  which means
    # those over 4200 bits.
    return Math::BigInt->new("0") if length($_[0]) > 700;
    return _bytes2bi(MIME::Base64::decode_base64($_[0]));
}

sub _default_p {
    return Math::BigInt->new("155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443");
}

sub _default_g {
    return Math::BigInt->new("2");
}

sub _rand_chars
{
    shift if @_ == 2;  # shift off classname/obj, if called as method
    my $length = shift;

    my $chal = "";
    my $digits = "abcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWZYZ0123456789";
    for (1..$length) {
        $chal .= substr($digits, int(rand(62)), 1);
    }
    return $chal;
}

# also a public interface:
*rand_chars = \&_rand_chars;

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

__END__

=head1 NAME

Net::OpenID::Server - library for consumers of OpenID identities

=head1 SYNOPSIS

  use Net::OpenID::Server;

  my $nos = Net::OpenID::Server->new(
    get_args     => $cgi,
    post_args    => $cgi,
    private_key  => \&get_priv_key_from_database,
    public_key   => "public_key.txt",
    get_user     => \&get_user,
    is_identity  => \&is_identity,
    is_trusted   => \&is_trusted
    setup_url    => "http://example.com/pass-identity.bml",
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
getters/setters methods for below.  That includes: get_args,
post_args, private_key, public_key, get_user, is_identity, is_trusted,
setup_url, and setup_map.  See below for docs.

=back

=head1 METHODS

=over 4

=item ($type, $data) = $nos->B<handle_page>([ %opts ])

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

The optional %opts may contain:

=over

=item C<redirect_for_setup>

If set to a true value, signals that you don't want to handle the
C<setup> return type from handle_page, and you'd prefer it just be
converted to a C<redirect> type to your already-defined C<setup_url>,
with the arguments from setup_map already appended.

=back

=item $url = $nos->B<signed_return_url>( %opts )

Generates a positive identity assertion URL that you'd redirect a user
to.  Typically this would be after they've completed your setup_url.
Once trust has been setup, the C<handle_page> method will redirect you
to this signed return automatically.

The URL generated is the consumer site's return_to URL, with a signed
identity included in the GET arguments.  The %opts are:

=over

=item C<identity>

Required.  The identity URL to sign.

=item C<return_to>

Required.  The base of the URL being generated.

=item C<assoc_handle>

The association handle to use for the signature.  If blank, dumb
consumer mode is used, and the library picks the handle.

=item C<trust_root>

Optional.  If present, the C<return_to> URL will be checked to be within
("under") this trust_root.  If not, the URL returned will be undef.

=back

=item $url = $nos->B<cancel_return_url>( %opts )

Generates a cancel notice to the return_to URL, if a user
declines to share their identity.  %opts are:

=over

=item C<return_to>

Required.  The base of the URL being generated.

=back

=item $nos->B<get_args>($ref)

=item $nos->B<get_args>($param)

=item $nos->B<get_args>

=item $nos->B<post_args>($ref)

=item $nos->B<post_args>($param)

=item $nos->B<post_args>

Can be used in 1 of 3 ways:

1. Setting the way which the Server instances obtains GET parameters:

$nos->get_args( $reference )

Where $reference is either a HASH ref, CODE ref, Apache $r (for
get_args only), Apache::Request $apreq, or CGI.pm $cgi.  If a CODE
ref, the subref must return the value given one argument (the
parameter to retrieve)

2. Get a paramater:

my $foo = $nos->get_args("foo");

When given an unblessed scalar, it retrieves the value.  It croaks if
you haven't defined a way to get at the parameters.

3. Get the getter:

my $code = $nos->get_args;

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

=item $nos->B<server_secret>($scalar)

=item $nos->B<server_secret>($code)

=item $code = $nos->B<server_secret>; ($secret) = $code->($time);

The server secret is used to generate and sign lots of per-consumer
secrets, and is never handed out directly.

In the simplest (and least secure) form, you configure a static secret
value with a scalar.  If you use this method and change the scalar
value, all consumers that have cached their per-consumer secrets will
start failing, since their secrets no longer work.

The recommended usage, however, is to supply a subref that returns a
secret based on the provided I<$time>, a unix timestamp.  And if one
doesn't exist for that time, create, store and return it (with
appropriate locking so you never return different secrets for the same
time.)  Your secret can just be random characters, but it's your
responsibility to do the locking and storage.  If you want help
generating random characters, call C<Net::OpenID::Server::rand_chars($len)>.

Your secret may not exceed 255 characters.

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
"return_to", "identity", and "assoc_handle".  If you
don't like those parameter names, this $hashref setup_map lets you
change one or more of them.  The hashref's keys should be the default
values, with values being the parameter names you want.

=item Net::OpenID::Server->rand_chars($len)

Utility function to return a string of $len random characters.  May be
called as package method, object method, or regular function.

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

