
package Net::OpenID::IndirectMessage;

use strict;
use Carp;

sub new {
    my $class = shift;
    my $what = shift;

    my $self = bless {}, $what;

    Carp::croak("Too many parameters") if @_;
    my $getter;
    my $enumer;
    if (ref $what eq "HASH") {
        $getter = sub { $what->{$_[0]}; };
        $enumer = sub { keys(%$what); };
    } elsif (UNIVERSAL::isa($what, "CGI")) {
        $getter = sub { scalar $what->param($_[0]); };
        $enumer = sub { $what->param; };
    } elsif (ref $what eq "Apache") {
        my %get = $what->args;
        $getter = sub { $get{$_[0]}; };
        $enumer = sub { keys(%$get); };
    } elsif (ref $what eq "Apache::Request") {
        $getter = sub { scalar $what->param($_[0]); };
        $enumer = sub { $what->param; };
    } elsif (ref $what eq "CODE") {
        $getter = $what;
        # We can't enumerate with just a coderef.
        # OpenID 2 spec only requires enumeration to support
        # extension namespaces, so we don't care too much.
        $enumer = sub { return (); };
    } else {
        Carp::croak("Unknown parameter type ($what)");
    }
    $self->{getter} = $getter;
    $self->{enumer} = $enumer;

    # Now some quick pre-configuration of a few bits

    # Is this an OpenID message at all?
    # All OpenID messages have an openid.mode value...
    return undef unless $self->get('mode');

    # Is this an OpenID 2.0 message?
    my $ns = $self->get('ns');
    if ($ns eq Net::OpenID::util::version_2_namespace) {
        $self->{protocol_version} = 2;
    }
    elsif (! defined($ns)) {
        # No namespace at all means a 1.1 message
        $self->{protocol_version} = 1;
    }
    else {
        # Unknown version is the same as not being an OpenID message at all
        return undef;
    }

    # This will be populated in on demand
    $self->{extension_prefixes} = undef;

}

sub protocol_version {
    return $_[0]->{protocol_version};
}

sub get {
    my $self = shift;
    my $key = shift or Carp::croak("No argument name supplied to get method");

    # NOTE: There is intentionally no way to get all of the keys in the core
    # namespace because that means we don't need to be able to enumerate
    # to support the core protocol, and there is no requirement to enumerate
    # anyway.

    # Arguments can only contain letters, numbers, underscores and dashes
    Carp::croak("Invalid argument key") unless $key =~ /^[\W\-]+$/;
    Carp::croak("Too many arguments") if scalar(@_);

    return $self->{getter}->("openid.$key");
}

sub get_ext {
    my $self = shift;
    my $namespace = shift or Carp::croak("No namespace URI supplied to get_ext method");
    my $key = shift;

    Carp::croak("Too many arguments") if scalar(@_);

    $self->_compute_extension_prefixes() unless defined($self->{extension_prefixes});

    my $alias = $self->{extension_prefixes}{$namespace};
    return $key ? undef : {} unless $alias;

    if ($key) {
        return $self->{getter}->("openid.$alias.$key");
    }
    else {
        my $prefix = "openid.$alias.";
        my $prefixlen = length($prefix);
        my $ret = {};
        foreach my $key ($self->{enumer}) {
            next unless substr($key, 0, $prefixlen) eq $prefix;
            $ret{substr($key, $prefixlen)} = $self->{getter}->($prefix.$key);
        }
    }
}

sub has_ext {
    my $self = shift;
    my $namespace = shift or Carp::croak("No namespace URI supplied to get_ext method");

    Carp::croak("Too many arguments") if scalar(@_);

    $self->_compute_extension_prefixes() unless defined($self->{extension_prefixes});

    return defined($self->{extension_prefixes}{$namespace}) ? 1 : 0;
}

sub _compute_extension_prefixes {
    my ($self) = @_;

    return unless $self->{enumer};

    $self->{extension_prefixes} = {};
    if ($self->protocol_version != 1) {
        foreach my $key ($self->{enumer}->()) {
            next unless $key =~ /^openid\.ns\.(\w+)$/;
            my $alias = $1;
            my $uri = $self->{getter}->($key);
            $self->{extension_prefixes}{$uri} = $alias;
        }
    }
    else {
        # Synthesize the SREG namespace as it was used in OpenID 1.1
        $self->{extension_prefixes}{"http://openid.net/extensions/sreg/1.1"} = "sreg";
    }
}

=head1 NAME

Net::OpenID::IndirectMessage - Class representing a collection of namespaced arguments

=head1 DESCRIPTION

This class acts as an abstraction layer over a collection of flat URL arguments
which supports namespaces as defined by the OpenID Auth 2.0 specification.

It also recognises when its is given OpenID 1.1 non-namespaced arguments and
acts as if the relevant namespaces were present. In this case, it only
supports the basic OpenID 1.1 arguments and the extension arguments
for Simple Registration.

This class can operate on a normal hashref, a L<CGI> object, an L<Apache>
object, an L<Apache::Request> object or an arbitrary C<CODE> ref that takes
a key name as its first parameter and returns a value. However,
if you use a coderef then extension arguments are not supported.

=head1 SYNOPSIS

    use Net::OpenID::IndirectMessage;
    
    # Pass in something suitable for the underlying flat dictionary.
    # Will return an instance if the request arguments can be understood
    # as a supported OpenID Message format.
    # Will return undef if this doesn't seem to be an OpenID Auth message.
    # Will croak if the $argumenty_thing is not of a suitable type.
    my $args = Net::OpenID::IndirectMessage->new($argumenty_thing);
    
    # Determine which protocol version the message is using.
    # Currently this can be either 1 for 1.1 or 2 for 2.0.
    # Expect larger numbers for other versions in future.
    # Most callers don't really need to care about this.
    my $version = $args->protocol_version();
    
    # Get a core argument value ("openid.mode")
    my $mode = $args->get("mode");
    
    # Get an extension argument value
    my $nickname = $args->get_ext("http://openid.net/extensions/sreg/1.1", "nickname");
    
    # Get hashref of all arguments in a given namespace
    my $sreg = $args->get_ext("http://openid.net/extensions/sreg/1.1");

Most of the time callers won't need to use this class directly, but will instead
access it through a L<Net::OpenID::Consumer> instance.

