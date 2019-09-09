package email

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"
)

// Pool is used to maintain SMTP connection pool
type Pool struct {
	logger       zerolog.Logger
	addr         string
	auth         smtp.Auth
	max          int
	created      int
	clients      chan *client
	rebuild      chan struct{}
	mut          *sync.Mutex
	lastBuildErr *timestampedErr
	closing      chan struct{}
	tlsConfig    *tls.Config
}

// client wraps built-in SMTP client and records failtCount while using the connection pool
type client struct {
	*smtp.Client
	failCount int
}

type timestampedErr struct {
	err error
	ts  time.Time
}

const maxFails = 4
const buildConnectionTimeout = 5 * time.Second

var (
	ErrClosed  = errors.New("pool closed")
	ErrTimeout = errors.New("timed out")
)

func NewPool(logger zerolog.Logger, address string, count int, auth smtp.Auth, opt_tlsConfig ...*tls.Config) (pool *Pool, err error) {
	pool = &Pool{
		logger: logger,
		addr:    address,
		auth:    auth,
		max:     count,
		clients: make(chan *client, count),
		rebuild: make(chan struct{}),
		closing: make(chan struct{}),
		mut:     &sync.Mutex{},
	}

	// create clients at the beginning
	for i:=0; i< count; i++ {
		pool.makeOne(buildConnectionTimeout)
	}

	if len(opt_tlsConfig) == 1 {
		pool.tlsConfig = opt_tlsConfig[0]
	} else if host, _, e := net.SplitHostPort(address); e != nil {
		return nil, e
	} else {
		pool.tlsConfig = &tls.Config{ServerName: host}
	}
	return
}

func (c *client) Close() error {
	return c.Text.Close()
}

// get the idle client
func (p *Pool) get(timeout time.Duration) *client {
	p.logger.Debug().Int("created", p.created).Int("max", p.max).Msgf("try to get the idle client")

	// get the client immediately
	select {
	case c := <-p.clients:
		return c
	default:
	}

	// if there is no enough client in the pool, make the new one (spawn the goroutine to make one)
	if p.created < p.max {
		go p.makeOne(buildConnectionTimeout)
	}

	// set up the timeout
	var deadline <-chan time.Time
	if timeout >= 0 {
		deadline = time.After(timeout)
	}

	for {
		select {
		case c := <-p.clients:
			return c
		case <-p.rebuild:
			go p.makeOne(buildConnectionTimeout)
		case <-deadline:
			p.logger.Error().Msgf("failed to get the idle client")
			return nil
		case <-p.closing:
			return nil
		}
	}
}

func shouldReuse(err error) bool {
	// certainly not perfect, but might be close:
	//  - EOF: clearly, the connection went down
	//  - textproto.Errors were valid SMTP over a valid connection,
	//    but resulted from an SMTP error response
	//  - textproto.ProtocolErrors result from connections going down,
	//    invalid SMTP, that sort of thing
	//  - syscall.Errno is probably down connection/bad pipe, but
	//    passed straight through by textproto instead of becoming a
	//    ProtocolError
	//  - if we don't recognize the error, don't reuse the connection
	// A false positive will probably fail on the Reset(), and even if
	// not will eventually hit maxFails.
	// A false negative will knock over (and trigger replacement of) a
	// conn that might have still worked.
	if err == io.EOF {
		return false
	}
	switch err.(type) {
	case *textproto.Error:
		return true
	case *textproto.ProtocolError, textproto.ProtocolError:
		return false
	case syscall.Errno:
		return false
	default:
		return false
	}
}

func (p *Pool) replace(c *client) {
	p.clients <- c
}

func (p *Pool) inc() bool {
	if p.created >= p.max {
		return false
	}

	p.mut.Lock()
	defer p.mut.Unlock()

	if p.created >= p.max {
		return false
	}
	p.created++
	return true
}

func (p *Pool) dec() {
	p.mut.Lock()
	p.created--
	p.mut.Unlock()

	select {
	case p.rebuild <- struct{}{}:
	default:
	}
}

func (p *Pool) makeOne(timeout time.Duration) {
	if p.inc() {
		p.logger.Info().Str("addr", p.addr).Msg("build a new client")

		c, err:= p.build(timeout)
		if err != nil {
			p.logger.Err(err).Msg("failed to build a new client")
			p.lastBuildErr = &timestampedErr{err, time.Now()}
			p.dec()
			return
		}
		p.logger.Info().Int("created", p.created).Int("max", p.max).Msg("create the new client successfully")
		p.clients <- c
	}
}

func startTLS(c *client, t *tls.Config) (bool, error) {
	if ok, _ := c.Extension("STARTTLS"); !ok {
		return false, nil
	}

	if err := c.StartTLS(t); err != nil {
		return false, err
	}

	return true, nil
}

func addAuth(c *client, auth smtp.Auth) (bool, error) {
	if ok, _ := c.Extension("AUTH"); !ok {
		return false, nil
	}

	if err := c.Auth(auth); err != nil {
		return false, err
	}

	return true, nil
}

func (p *Pool) build(timeout time.Duration) (*client, error) {
	conn, err := net.DialTimeout("tcp", p.addr, timeout)
	if err != nil {
		return nil, err
	}

	host := strings.Split(p.addr, ":")[0]
	cl, err := smtp.NewClient(conn, host)
	if err != nil {
		return nil, err
	}
	c := &client{cl, 0}

	if _, err := startTLS(c, p.tlsConfig); err != nil {
		c.Close()
		return nil, err
	}

	if p.auth != nil {
		if _, err := addAuth(c, p.auth); err != nil {
			c.Close()
			return nil, err
		}
	}

	return c, nil
}

func (p *Pool) maybeReplace(err error, c *client) {
	if err == nil {
		c.failCount = 0
		p.replace(c)
		return
	}

	c.failCount++
	if c.failCount >= maxFails {
		goto shutdown
	}

	if !shouldReuse(err) {
		goto shutdown
	}

	if err := c.Reset(); err != nil {
		goto shutdown
	}

	p.replace(c)
	return

shutdown:
	p.dec()
	c.Close()
}

func (p *Pool) failedToGet(startTime time.Time) error {
	select {
	case <-p.closing:
		return ErrClosed
	default:
	}

	if p.lastBuildErr != nil && startTime.Before(p.lastBuildErr.ts) {
		return p.lastBuildErr.err
	}

	return ErrTimeout
}

// Send sends an email via a connection pulled from the Pool. The timeout may
// be <0 to indicate no timeout. Otherwise reaching the timeout will produce
// and error building a connection that occurred while we were waiting, or
// otherwise ErrTimeout.
func (p *Pool) Send(e *Email, timeout time.Duration) error {
	recipients, err := addressLists(e.To, e.Cc, e.Bcc)
	if err != nil {
		return err
	}

	msg, err := e.Bytes()
	if err != nil {
		return err
	}

	from, err := emailOnly(e.From)
	if err != nil {
		return err
	}

	return p.SendRawMsg(from, recipients, msg, timeout)
}

// SendRawMsg sends an email via a connection pulled from the Pool. Given from, recipients, and
// raw SMTP mail payload. Note that the from and recipients should be bare email addresses.
// The timeout may be <0 to indicate no timeout. Otherwise reaching the timeout will
// produce an error building a connection that occurred while we were waiting, or
// otherwise ErrTimeout.
func (p *Pool) SendRawMsg(from string, recipients []string, msg []byte, timeout time.Duration) (err error) {
	start := time.Now()
	c := p.get(timeout)
	if c == nil {
		return p.failedToGet(start)
	}

	defer func() {
		p.maybeReplace(err, c)
	}()

	if err = c.Mail(from); err != nil {
		return err
	}

	for _, recip := range recipients {
		if err = c.Rcpt(recip); err != nil {
			return err
		}
	}

	w, err := c.Data()
	if err != nil {
		return err
	}

	if _, err = w.Write(msg); err != nil {
		return err
	}

	err = w.Close()

	return err
}

func emailOnly(full string) (string, error) {
	addr, err := mail.ParseAddress(full)
	if err != nil {
		return "", err
	}
	return addr.Address, nil
}

func addressLists(lists ...[]string) ([]string, error) {
	length := 0
	for _, lst := range lists {
		length += len(lst)
	}
	combined := make([]string, 0, length)

	for _, lst := range lists {
		for _, full := range lst {
			addr, err := emailOnly(full)
			if err != nil {
				return nil, err
			}
			combined = append(combined, addr)
		}
	}

	return combined, nil
}

// Close immediately changes the pool's state so no new connections will be
// created, then gets and closes the existing ones as they become available.
func (p *Pool) Close() {
	close(p.closing)

	for p.created > 0 {
		c := <-p.clients
		c.Quit()
		p.dec()
	}
}
