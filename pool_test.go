package email

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/stretchr/testify/assert"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type unencryptedAuth struct {
	smtp.Auth
}

func (a unencryptedAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	(*server).TLS = true
	return a.Auth.Start(server)
}

var sendMailServer = `220 hello world
502 EH?
250 mx.google.com at your service
250 Sender ok
250 Receiver ok
354 Go ahead
250 Data ok
221 Goodbye
`

func TestPool_SendMail(t *testing.T) {

	// 1. Create a local smtp server
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	if err != nil {
		t.Fatalf("Unable to create listener: %v", err)
	}
	defer l.Close()

	server := strings.Join(strings.Split(sendMailServer, "\n"), "\r\n")
	var cmdbuf bytes.Buffer
	bcmdbuf := bufio.NewWriter(&cmdbuf)

	// prevent data race on bcmdbuf
	var done = make(chan struct{})
	go func(data []string) {
		defer close(done)

		conn, err := l.Accept()
		if err != nil {
			t.Errorf("Accept error: %v", err)
			return
		}
		defer conn.Close()

		fmt.Println("create the connection")
		tc := textproto.NewConn(conn)
		for i := 0; i < len(data) && data[i] != ""; i++ {
			tc.PrintfLine(data[i])
			for len(data[i]) >= 4 && data[i][3] == '-' {
				i++
				tc.PrintfLine(data[i])
			}
			if data[i] == "221 Goodbye" {
				return
			}
			read := false
			for !read || data[i] == "354 Go ahead" {
				msg, err := tc.ReadLine()
				bcmdbuf.Write([]byte(msg + "\r\n"))
				read = true
				if err != nil {
					t.Errorf("Read error: %v", err)
					return
				}
				if data[i] == "354 Go ahead" && msg == "." {
					break
				}
			}
		}
	}(strings.Split(server, "\r\n"))

	//2. Send mail through mail pool
	auth := unencryptedAuth{
		smtp.PlainAuth("", "", "", "127.0.0.1"),
	}
	p, _ := NewPool(
		zerolog.New(zerolog.NewConsoleWriter()),
		l.Addr().String(),
		4,
		auth,
	)
	timeout := 10 * time.Second
	err = p.SendRawMsg("test@umbocv.com", []string{"test.umbocv.com"}, []byte("Subject: helloworld!"), timeout)
	require.NoError(t, err)
	p.Close()

	<-done
	bcmdbuf.Flush()
	actualcmds := cmdbuf.String()
	expected := `EHLO localhost
HELO localhost
MAIL FROM:<test@umbocv.com>
RCPT TO:<test.umbocv.com>
DATA
Subject: helloworld!
.
QUIT
`
	expectedString := strings.Join(strings.Split(expected, "\n"), "\r\n")
	assert.Equal(t, expectedString, actualcmds)

}

func TestPool_Sureview(t *testing.T) {
	// https://testmydevice.sureviewsystems.com/Alarms?ID=490
	poolSize := 10
	auth := unencryptedAuth{
		smtp.PlainAuth("", "", "", "70.35.203.226"),
	}
	p, _ := NewPool(
		zerolog.New(zerolog.NewConsoleWriter()),
		"70.35.203.226:25",
		poolSize,
		auth,
	)


	timeout := 3 * time.Second
	done := make(chan struct{}, 6)
	go func() {
		err := p.SendRawMsg("kakashi@test.umbocv.com", []string{"S688@TestMyDevice.SureViewSystems.com"}, []byte("Subject: helloworld!"), timeout)
		require.NoError(t, err)
		done <- struct{}{}
	}()
	go func() {
		err := p.SendRawMsg("kakashi@test.umbocv.com", []string{"S688@TestMyDevice.SureViewSystems.com"}, []byte("Subject: helloworld!"), timeout)
		require.NoError(t, err)
		done <- struct{}{}
	}()
	go func() {
		err := p.SendRawMsg("kakashi@test.umbocv.com", []string{"S688@TestMyDevice.SureViewSystems.com"}, []byte("Subject: helloworld!"), timeout)
		require.NoError(t, err)
		done <- struct{}{}
	}()
	go func() {
		err := p.SendRawMsg("kakashi@test.umbocv.com", []string{"S688@TestMyDevice.SureViewSystems.com"}, []byte("Subject: helloworld!"), timeout)
		require.NoError(t, err)
		done <- struct{}{}
	}()
	go func() {
		err := p.SendRawMsg("kakashi@test.umbocv.com", []string{"S688@TestMyDevice.SureViewSystems.com"}, []byte("Subject: helloworld!"), timeout)
		require.NoError(t, err)
		done <- struct{}{}
	}()
	go func() {
		err := p.SendRawMsg("kakashi@test.umbocv.com", []string{"S688@TestMyDevice.SureViewSystems.com"}, []byte("Subject: helloworld!"), timeout)
		require.NoError(t, err)
		done <- struct{}{}
	}()

	<-done
}