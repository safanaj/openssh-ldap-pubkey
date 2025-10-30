package main

import (
	"os"
	"strconv"
	"strings"

	"net/url"
)

const (
	nslcdConf     = "/etc/nslcd.conf"
	defaultFilter = "(&(objectClass=posixAccount)(uid=%s))"
)

func getNslcdConfPath() string {
	conf := os.Getenv("NSLCD_CONF")
	if conf == "" {
		conf = nslcdConf
	}
	return conf
}

func (l *ldapEnv) loadNslcdConf() error {
	conf := getNslcdConfPath()
	b, err := os.ReadFile(conf)
	if err != nil {
		l.host = "localhost"
		l.port = 389
		l.base = "dc=example,dc=org"
		l.filter = defaultFilter
		l.tls = false
		l.skip = false
		l.debug = false
		l.binddn = ""
		l.bindpw = ""
		l.cert = ""
		l.key = ""
		l.cacert = ""
	}
	for s := range strings.SplitSeq(string(b), "\n") {
		v := strings.Split(s, " ")
		switch v[0] {
		case "uri":
			u, err := url.Parse(v[1])
			if err != nil {
				return err
			}
			if u.Scheme == "ldaps" {
				l.tls = true
			} else {
				l.tls = false
			}
			if strings.Contains(u.Host, ":") {
				h := strings.Split(u.Host, ":")
				l.host = h[0]
				p, err := strconv.Atoi(h[1])
				if err != nil {
					return err
				}
				l.port = p
			} else {
				l.host = u.Host
				if l.tls {
					l.port = 636
					if isAddr(l.host) {
						l.skip = true
					}
				} else {
					l.port = 389
				}
			}
		case "base":
			l.base = v[1]
		case "binddn":
			l.binddn = v[1]
		case "bindpw":
			l.bindpw = v[1]
		case "pam_authz_search":
			if strings.Contains(v[1], "$username") {
				l.filter = strings.Replace(v[1], "$username", "%s", 1)
			} else {
				l.filter = v[1]
			}
		case "tls_reqcert":
			if v[1] == "never" || v[1] == "allow" {
				l.skip = true
			}
		case "ssl":
			if v[1] == "start_tls" || v[1] == "on" {
				l.tls = true
			}
		case "tls_cert":
			l.cert = v[1]
		case "tls_key":
			l.key = v[1]
		case "tls_cacert":
			l.cacert = v[1]
		default:
			if l.filter == "" {
				l.filter = defaultFilter
			}
		}
	}
	return nil
}
