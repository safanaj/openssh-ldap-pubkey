package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/go-ldap/ldap/v3"
)

const (
	initialVersion   = "0.3.3"
	sshPublicKeyName = "sshPublicKey"
)

var (
	version    string = initialVersion
	errVersion        = errors.New("show version")

	license = `openssh-ldap-pubkey %s

Copyright (C) 2015-2020 Kouhei Maeda
Copyright (C) 2025 Marco Bardelli
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software, and you are welcome to redistribute it.
There is NO WARRANTY, to the extent permitted by law.
`
)

func (l *ldapEnv) argparse(args []string, ver string) error {
	if len(args) == 0 {
		args = os.Args
	}
	flags := flag.NewFlagSet(args[0], flag.ExitOnError)
	h := flags.String("host", l.host, "LDAP server host")
	p := flags.Int("port", l.port, "LDAP server port")
	b := flags.String("base", l.base, "search base")
	f := flags.String("filter", l.filter, "search filter")
	t := flags.Bool("tls", l.tls, "LDAP connect over TLS")
	s := flags.Bool("skip", l.skip, "Insecure skip verify")
	v := flags.Bool("version", false, "show version")
	d := flags.Bool("debug", false, "debug mode")
	flags.Parse(args[1:])

	if *v {
		fmt.Printf(license, version)
		return errVersion
	}
	if l.host != *h {
		l.host = *h
	}
	if l.port != *p {
		l.port = *p
	}
	if l.base != *b {
		l.base = *b
	}
	if l.filter != *f {
		l.filter = *f
	}
	if l.tls != *t {
		l.tls = *t
	}
	if l.skip != *s {
		l.skip = *s
	}
	if l.debug != *d {
		l.debug = *d
	}

	if len(flags.Args()) != 1 {
		return errors.New("Specify username")
	}
	l.uid = flags.Args()[0]
	return nil
}

func main() {
	l := &ldapEnv{}
	l.loadNslcdConf()
	var err error
	var entries []*ldap.Entry
	if version == "" {
		version = initialVersion
	}
	logging(l.argparse([]string{}, version))
	c := &ldap.Conn{}
	if l.debug {
		var bindpw = ""
		if l.bindpw != "" {
			bindpw = "<bindpw can found in nslcd.conf>"
		}
		log.Printf("[debug] host  : %s\n", l.host)
		log.Printf("[debug] port  : %d\n", l.port)
		log.Printf("[debug] tls	  : %v\n", l.tls)
		log.Printf("[debug] base  : %s\n", l.base)
		log.Printf("[debug] skip  : %v\n", l.skip)
		log.Printf("[debug] filter: %s\n", l.filter)
		log.Printf("[debug] uid	  : %s\n", l.uid)
		log.Printf("[debug] binddn: %s\n", l.binddn)
		log.Printf("[debug] bindpw: %s\n", bindpw)
		log.Printf("[debug] cert: %s\n", l.cert)
		log.Printf("[debug] key: %s\n", l.key)
		log.Printf("[debug] cacert: %s\n", l.cert)
	}
	c, err = l.connect()
	logging(err)
	if l.tls {
		tlsCfg, err := l.getTLSConfig()
		logging(err)
		logging(c.StartTLS(tlsCfg))
	} else {
		c.Start()
	}
	defer c.Close()

	if l.binddn != "" {
		logging(simpleBind(c, l))
	} else {
		logging(c.ExternalBind())
	}
	entries, err = l.search(c)
	logging(err)
	logging(printPubkey(entries))
}
