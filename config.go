package gost

import (
	"github.com/BurntSushi/toml"
	"github.com/go-log/log"
)

type Config struct {
	Auth struct {
		DynamicPeriod     int64    `toml:"dynamic_period"`
		IPWhiteList       []string `toml:"ip_whitelist"`
		EmailWhiteList    []string `toml:"email_whitelist"`
		EmailRegWhiteList []string `toml:"email_regex"`
		DynamicSkew       int      `toml:"dynamic_skew"`
		Secret            string   `toml:"secret"`
	} `toml:"auth"`
}

var config Config

func LoadAuthConfig() {

	_, err := toml.DecodeFile("auth.toml", &config)
	if err != nil {
		log.Log("not found auth.toml", err)
	}

	LoadIPWhiteList(config.Auth.IPWhiteList)
	LoadEmailACL(config.Auth.EmailWhiteList, config.Auth.EmailRegWhiteList)
}
