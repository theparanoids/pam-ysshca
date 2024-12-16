// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package conf

import (
	"os"
	"path"
	"strings"

	"github.com/theparanoids/pam-ysshca/decoder"
	"github.com/theparanoids/pam-ysshca/filter"
	"github.com/theparanoids/pam-ysshca/msg"
)

// Parser is the parser to parse pam_sshca.conf.
type Parser struct {
	userName string
	userHome string
}

// NewParser creates a Parser.
func NewParser(userName, userHome string) *Parser {
	return &Parser{
		userName: userName,
		userHome: userHome,
	}
}

// ParseConfigFile reads the content in a file and parse the directives in it.
func (p *Parser) ParseConfigFile(path string) Config {
	data, err := os.ReadFile(path)
	if err != nil {
		msg.Printlf(msg.WARN, "Cannot access config file %s: %v", path, err)
		return defaultConfig()
	}

	conf := p.parse(data)
	conf = p.populate(conf)
	conf = p.validate(conf)

	msg.Printlf(msg.DEBUG, "Parsed config: %v", conf)

	return conf
}

func (p *Parser) parse(data []byte) Config {
	result := defaultConfig()

	config, err := decoder.Decode(data)
	if err != nil {
		msg.Printlf(msg.WARN, "Failed to parse config file: %v", err)
	}

	debug, _ := config.Get("debug")
	switch strings.ToLower(debug) {
	case "on":
		msg.SetDebugMode(true)
	default:
		msg.SetDebugMode(false)
	}

	filters, err := config.GetAll("filter")
	if len(filters) != 0 && err == nil {
		for _, f := range filters {
			result.Filters = append(result.Filters, p.extendFilePath(f))
		}
	}

	allow, err := config.Get("AllowStaticKeys")
	if allow != "" && err == nil {
		result.AllowStaticKeys, _ = parseBool(allow)
	}

	authorizedKeysFiles, err := config.GetAll("AuthorizedKeysFile")
	if len(authorizedKeysFiles) != 0 && err == nil {
		for _, a := range authorizedKeysFiles {
			result.StaticKeys = append(result.StaticKeys, p.extendFilePath(a))
		}
	}

	allow, err = config.Get("AllowCertificate")
	if allow != "" && err == nil {
		result.AllowCertificate, _ = parseBool(allow)
	}

	result.SupportedCriticalOptions, _ = config.GetAll("SupportedCriticalOption")

	trustedUserCAKeys, err := config.GetAll("TrustedUserCAKeys")
	if len(trustedUserCAKeys) != 0 && err == nil {
		for _, a := range trustedUserCAKeys {
			result.CAKeys = append(result.CAKeys, p.extendFilePath(a))
		}
	}

	result.authorizedPrincipalPrefix, _ = config.GetAll("authorizedPrincipalPrefix")

	authorizedPrincipalsFiles, err := config.GetAll("AuthorizedPrincipalsFile")
	if len(authorizedPrincipalsFiles) != 0 && err == nil {
		for _, a := range authorizedPrincipalsFiles {
			result.authorizedPrincipalFiles = append(result.authorizedPrincipalFiles, p.extendFilePath(a))
		}
	}

	prompts, err := config.GetAll("Prompt")
	if len(prompts) != 0 && err == nil {
		for _, p := range prompts {
			prompter, err := newPrompter(p)
			if err != nil {
				msg.Printlf(msg.WARN, "Config: %s corrupt, err: %v", p, err)
			}
			result.Prompters = append(result.Prompters, prompter)
		}
	}
	return result
}

func (p *Parser) populate(c Config) Config {
	if len(c.StaticKeys) == 0 {
		if _, err := os.Stat(p.extendFilePath(".ssh/authorized_keys")); err == nil {
			msg.Printlf(msg.DEBUG, "Add .ssh/authorized_keys as static keys.")
			c.StaticKeys = append(c.StaticKeys, p.extendFilePath(".ssh/authorized_keys"))
		}
		if _, err := os.Stat(p.extendFilePath(".ssh/authorized_keys2")); err == nil {
			msg.Printlf(msg.DEBUG, "Add .ssh/authorized_keys2 as static keys.")
			c.StaticKeys = append(c.StaticKeys, p.extendFilePath(".ssh/authorized_keys2"))
		}
	}
	return c
}

func (p *Parser) validate(c Config) Config {
	c.StaticKeys = validateFiles(c.StaticKeys, -1, 0000, 0022)
	c.CAKeys = validateFiles(c.CAKeys, 0, 0000, 0022)
	c.authorizedPrincipalFiles = validateFiles(c.authorizedPrincipalFiles, 0, 0000, 0022)
	return c
}

func (p *Parser) extendFilePath(path_ string) string {
	if strings.HasPrefix(path_, filter.EmbeddedPrefix) {
		return path_
	}

	if !strings.HasPrefix(path_, "/") {
		path_ = path.Join(p.userHome, path_)
	}
	return strings.Replace(path_, "%u", p.userName, 1)
}
