package kafkalog

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"
)

// Default connection and delivery settings. Production defaults require three
// configured replicas and at least two in-sync replicas for acknowledged writes.
const (
	DefaultTopic                = "sbo-telemetry"
	DefaultGroupPrefix          = "sbo"
	DefaultMaxMsgBytes    int32 = 32 << 20
	DefaultMaxDeliver           = 10
	DefaultAckWait              = 30 * time.Second
	DefaultConnectTimeout       = 10 * time.Second
	DefaultPublishTimeout       = 10 * time.Second
)

// Options configures an existing Kafka topic; it never provisions or mutates
// topic/broker configuration. TLS=false is allowed only for loopback brokers.
type Options struct {
	Brokers           []string
	Topic             string
	GroupPrefix       string
	ClientID          string
	RequiredReplicas  int
	MinInSyncReplicas int
	MaxMsgBytes       int32
	MaxDeliver        int
	AckWait           time.Duration
	ConnectTimeout    time.Duration
	PublishTimeout    time.Duration
	TLS               bool
	CAFile            string
	CertFile          string
	KeyFile           string
	SASLMechanism     string
	User              string
	Password          string
}

// String avoids exposing credentials through diagnostic formatting.
func (o Options) String() string { return "kafkalog.Options{credentials redacted}" }

// GoString redacts Go-syntax diagnostic formatting too.
func (o Options) GoString() string { return o.String() }

// ValidateOptions checks defaulted structural settings only. It performs no
// filesystem access or network I/O, so configuration loaders can use it safely.
func ValidateOptions(opts Options) error { return opts.defaults().validate() }

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)

func (o Options) defaults() Options {
	o.Brokers = append([]string(nil), o.Brokers...)
	if o.Topic == "" {
		o.Topic = DefaultTopic
	}
	if o.GroupPrefix == "" {
		o.GroupPrefix = DefaultGroupPrefix
	}
	if o.ClientID == "" {
		o.ClientID = "observer-org"
	}
	if o.RequiredReplicas == 0 {
		o.RequiredReplicas = 3
	}
	if o.MinInSyncReplicas == 0 {
		o.MinInSyncReplicas = 2
	}
	if o.MaxMsgBytes == 0 {
		o.MaxMsgBytes = DefaultMaxMsgBytes
	}
	if o.MaxDeliver == 0 {
		o.MaxDeliver = DefaultMaxDeliver
	}
	if o.AckWait == 0 {
		o.AckWait = DefaultAckWait
	}
	if o.ConnectTimeout == 0 {
		o.ConnectTimeout = DefaultConnectTimeout
	}
	if o.PublishTimeout == 0 {
		o.PublishTimeout = DefaultPublishTimeout
	}
	return o
}

func (o Options) validate() error {
	if err := o.validateBrokers(); err != nil {
		return err
	}
	if !identifier.MatchString(o.Topic) || !identifier.MatchString(o.GroupPrefix) {
		return fmt.Errorf("kafkalog: invalid topic or group prefix")
	}
	if o.RequiredReplicas < 1 || o.MinInSyncReplicas < 1 || o.MinInSyncReplicas > o.RequiredReplicas {
		return fmt.Errorf("kafkalog: invalid replication requirements")
	}
	if o.MaxMsgBytes <= 0 || o.MaxMsgBytes > (1<<30) || o.MaxDeliver < 1 || o.AckWait <= 0 || o.ConnectTimeout <= 0 || o.PublishTimeout <= 0 {
		return fmt.Errorf("kafkalog: limits and timeouts must be positive and bounded")
	}
	return o.validateAuth()
}

func (o Options) validateBrokers() error {
	if len(o.Brokers) == 0 {
		return fmt.Errorf("kafkalog: brokers required")
	}
	for _, broker := range o.Brokers {
		host, port, err := net.SplitHostPort(broker)
		if err != nil || host == "" || port == "" || strings.ContainsAny(broker, "/@?#") {
			return fmt.Errorf("kafkalog: brokers must be host:port without credentials")
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return fmt.Errorf("kafkalog: broker port must be between 1 and 65535")
		}
		if !o.TLS && !loopback(host) {
			return fmt.Errorf("kafkalog: TLS is required outside loopback")
		}
	}
	return nil
}

func (o Options) validateAuth() error {
	if (o.CertFile == "") != (o.KeyFile == "") {
		return fmt.Errorf("kafkalog: TLS client cert and key must be supplied together")
	}
	if !o.TLS && (o.CAFile != "" || o.CertFile != "") {
		return fmt.Errorf("kafkalog: TLS files require TLS")
	}
	switch strings.ToUpper(o.SASLMechanism) {
	case "":
		if o.User != "" || o.Password != "" {
			return fmt.Errorf("kafkalog: credentials require a SASL mechanism")
		}
	case "PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512":
		if o.User == "" || o.Password == "" {
			return fmt.Errorf("kafkalog: SASL user and password required")
		}
	default:
		return fmt.Errorf("kafkalog: unsupported SASL mechanism")
	}
	return nil
}

func loopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

func (o Options) clientOptions() ([]kgo.Opt, error) {
	opts := []kgo.Opt{kgo.SeedBrokers(o.Brokers...), kgo.ClientID(o.ClientID), kgo.DialTimeout(o.ConnectTimeout), kgo.RequestTimeoutOverhead(o.PublishTimeout)}
	if o.TLS {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if o.CAFile != "" {
			pem, err := os.ReadFile(o.CAFile)
			if err != nil {
				return nil, fmt.Errorf("kafkalog: cannot read TLS CA")
			}
			cfg.RootCAs = x509.NewCertPool()
			if !cfg.RootCAs.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("kafkalog: invalid TLS CA")
			}
		}
		if o.CertFile != "" {
			cert, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("kafkalog: cannot load TLS client identity")
			}
			cfg.Certificates = []tls.Certificate{cert}
		}
		opts = append(opts, kgo.DialTLSConfig(cfg))
	} else {
		opts = append(opts, kgo.Dialer(func(ctx context.Context, network, address string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(address)
			if err != nil || !loopback(host) {
				return nil, fmt.Errorf("kafkalog: refused non-loopback plaintext broker")
			}
			return (&net.Dialer{Timeout: o.ConnectTimeout}).DialContext(ctx, network, address)
		}))
	}
	switch strings.ToUpper(o.SASLMechanism) {
	case "":
		if o.User != "" || o.Password != "" {
			return nil, fmt.Errorf("kafkalog: credentials require a SASL mechanism")
		}
	case "PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512":
		if o.User == "" || o.Password == "" {
			return nil, fmt.Errorf("kafkalog: SASL user and password required")
		}
		switch strings.ToUpper(o.SASLMechanism) {
		case "PLAIN":
			opts = append(opts, kgo.SASL(plain.Auth{User: o.User, Pass: o.Password}.AsMechanism()))
		case "SCRAM-SHA-256":
			opts = append(opts, kgo.SASL(scram.Auth{User: o.User, Pass: o.Password}.AsSha256Mechanism()))
		case "SCRAM-SHA-512":
			opts = append(opts, kgo.SASL(scram.Auth{User: o.User, Pass: o.Password}.AsSha512Mechanism()))
		}
	default:
		return nil, fmt.Errorf("kafkalog: unsupported SASL mechanism")
	}
	return opts, nil
}
