package snmp

import (
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/soniah/gosnmp"
	"time"
)

type sessionAPI interface {
	Configure(config snmpConfig) error
	Connect() error
	Close() error
	Get(oids []string) (result *gosnmp.SnmpPacket, err error)
	GetBulk(oids []string) (result *gosnmp.SnmpPacket, err error)
}

type snmpSession struct {
	gosnmpInst gosnmp.GoSNMP
}

func (s *snmpSession) Configure(config snmpConfig) error {
	maxOids := gosnmp.MaxOids
	if config.OidBatchSize > gosnmp.MaxOids {
		return fmt.Errorf("config OidBatchSize (%d) cannot higher than gosnmp.MaxOids: %d", config.OidBatchSize, maxOids)
	}
	snmpVersion, err := parseVersion(config.SnmpVersion)
	if err != nil {
		return err
	}
	gosnmpInst := gosnmp.GoSNMP{
		Target:  config.IPAddress,
		Port:    config.Port,
		Version: snmpVersion,
		Timeout: time.Duration(config.Timeout) * time.Second,
		Retries: config.Retries,
		MaxOids: maxOids,
	}
	switch snmpVersion {
	case gosnmp.Version2c, gosnmp.Version1:
		gosnmpInst.Community = config.CommunityString
	case gosnmp.Version3:
		authProtocol, err := getAuthProtocol(config.AuthProtocol)
		if err != nil {
			return err
		}

		privProtocol, err := getPrivProtocol(config.PrivProtocol)
		if err != nil {
			return err
		}

		msgFlags := gosnmp.NoAuthNoPriv
		if privProtocol != gosnmp.NoPriv {
			msgFlags = gosnmp.AuthPriv
		} else if authProtocol != gosnmp.NoAuth {
			msgFlags = gosnmp.AuthNoPriv
		}

		gosnmpInst.MsgFlags = msgFlags
		gosnmpInst.ContextName = config.ContextName
		gosnmpInst.SecurityModel = gosnmp.UserSecurityModel
		gosnmpInst.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 config.User,
			AuthenticationProtocol:   authProtocol,
			AuthenticationPassphrase: config.AuthKey,
			PrivacyProtocol:          privProtocol,
			PrivacyPassphrase:        config.PrivKey,
		}
	}
	s.gosnmpInst = gosnmpInst
	log.Warnf("gosnmp Instance: %#v", s.gosnmpInst) // TODO: Remove me
	return nil
}

func (s *snmpSession) Connect() error {
	return s.gosnmpInst.Connect()
}

func (s *snmpSession) Close() error {
	return s.gosnmpInst.Conn.Close()
}

func (s *snmpSession) Get(oids []string) (result *gosnmp.SnmpPacket, err error) {
	return s.gosnmpInst.Get(oids)
}

func (s *snmpSession) GetBulk(oids []string) (result *gosnmp.SnmpPacket, err error) {
	if len(oids) == 0 { // TODO: test me
		return &gosnmp.SnmpPacket{}, nil
	}
	return s.gosnmpInst.GetBulk(oids, 0, 10)
}