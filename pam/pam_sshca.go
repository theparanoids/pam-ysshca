// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package pam

// #cgo CFLAGS: -std=c99 -fPIC
// #cgo LDFLAGS: -lpam
//
// #include <sys/types.h>
// #include <stdlib.h>
// #include <syslog.h>
//
// #define PAM_SM_AUTH
// #include <security/pam_appl.h>
// #include <security/pam_modules.h>
//
// int DisablePtrace();
// uid_t GetCurrentUserUID(pam_handle_t *pamh);
// const char *GetCurrentUserName(pam_handle_t *pamh);
// const char *GetCurrentUserHome(pam_handle_t *pamh);
//
import "C"

import (
	"bytes"
	"fmt"
	"log/syslog"
	"net"
	"os"
	"syscall"

	"github.com/theparanoids/pam-ysshca/conf"
	"github.com/theparanoids/pam-ysshca/msg"
	sshagent "github.com/theparanoids/ysshra/agent/ssh"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const configPath = "/etc/pam_sshca.conf"

func init() {
	// Disable ptrace to improve system security.
	C.DisablePtrace()
}

// authenticator authenticates the credentials stored in user's ssh-agent.
type authenticator struct {
	// user is the name of current user.
	user string
	// home is the home path of current user.
	home      string
	config    *conf.Config
	sysLogger *syslog.Writer
}

func newAuthenticator(user, home string) *authenticator {
	// Initialize config.
	parser := conf.NewParser(user, home)
	config := parser.ParseConfigFile(configPath)

	// Initialize system logger.
	// FIXME(darwin): sysLogger output is lost on macOS due to
	// https://github.com/golang/go/issues/59229
	sysLogger, err := syslog.New(syslog.LOG_AUTHPRIV, "PAM_SSHCA")
	if err != nil {
		msg.Printlf(msg.WARN, "Failed to access syslogd, please fix your system logs.")
		sysLogger = nil
	}

	return &authenticator{
		user:      user,
		home:      home,
		config:    &config,
		sysLogger: sysLogger,
	}
}

func (a *authenticator) authenticate() C.int {
	cmd := getCmdLine()

	// Initialize ssh-agent.
	sshAuthSock, err := sshagent.CheckSSHAuthSock()
	if err != nil {
		authNFn := NonSSHAgentAuthN()
		authNErr := authNFn(a.user, *a.config, a.sysLogger)
		if authNErr != nil {
			msg.Printlf(msg.FATAL, "Cannot find SSH agent: %v", err)
			msg.Printlf(msg.FATAL, "Non-ssh-agent authentication failed: %v", authNErr)
			return C.PAM_AUTH_ERR
		}
		return C.PAM_SUCCESS
	}

	conn, err := net.Dial("unix", sshAuthSock)
	if err != nil {
		msg.Printlf(msg.FATAL, "Cannot connect to SSH agent: %v", err)
		return C.PAM_CRED_UNAVAIL
	}
	defer conn.Close()
	ag := agent.NewClient(conn)

	// Fetch all the identities from ssh-agent.
	identities, err := getIdentitiesFromSSHAgent(ag)
	if err != nil {
		msg.Printlf(msg.FATAL, "Failed to get keys from sshagent: %v", err)
		return C.PAM_CRED_UNAVAIL
	}

	msg.Printlf(msg.DEBUG, "Found %d identities in current SSH agent.", len(identities))

	// Feed identities to the filters.
	if len(a.config.Filters) != 0 {
		for _, filter := range a.config.Filters {
			identities = invokeFilter(identities, filter)
			msg.Printlf(msg.DEBUG, "%d identities left after filter %s", len(identities), filter)
		}
	}

	// Authenticate using static keys.
	if a.config.AllowStaticKeys {
		if key := a.authStaticKey(ag, identities); key != nil {
			a.sysLogInfo(fmt.Sprintf("Grant: USER=%s, STATIC_KEY=%s, CMD=(%s)", a.user, bytes.TrimSpace(ssh.MarshalAuthorizedKey(key)), cmd))
			return C.PAM_SUCCESS
		}
	}

	// Authenticate using certificates.
	if a.config.AllowCertificate {
		if cert := a.authCertificate(ag, identities, a.user); cert != nil {
			a.sysLogInfo(fmt.Sprintf("Grant: USER=%s, KEYID=(%s), CMD=(%s)", a.user, cert.KeyId, cmd))
			return C.PAM_SUCCESS
		}
	}

	a.sysLogWarning(fmt.Sprintf("Deny: USER=%s, CMD=(%s)", a.user, cmd))
	return C.PAM_AUTH_ERR
}

func (a *authenticator) sysLogInfo(m string) {
	if a.sysLogger != nil {
		a.sysLogger.Info(m) //nolint:errcheck
	}
}

func (a *authenticator) sysLogWarning(m string) {
	if a.sysLogger != nil {
		a.sysLogger.Warning(m) //nolint:errcheck
	}
}

// Authenticate is the entry of Go language part.
// It is invoked by pam_sm_authenticate in C language part.
//
//export Authenticate
func Authenticate(pamh *C.pam_handle_t) C.int {
	// Initialize login variables.
	user := C.GoString(C.GetCurrentUserName(pamh))
	home := C.GoString(C.GetCurrentUserHome(pamh)) + "/"

	// Set correct euid before authentication.
	// NOTE: https://hackerone.com/reports/204802
	origEUID := os.Geteuid()
	defer syscall.Setreuid(-1, origEUID) //nolint:errcheck
	uid := C.GetCurrentUserUID(pamh)
	syscall.Setreuid(-1, int(uid)) //nolint:errcheck

	authenticator := newAuthenticator(user, home)
	return authenticator.authenticate()
}
