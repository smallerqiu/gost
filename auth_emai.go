package gost

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-log/log"
)

// 25 端口 465 和 587
var mailPorts = []string{"25", "465", "587"}

type EmailACL struct {
	emails  map[string]struct{}
	domains map[string]struct{}
	regex   []*regexp.Regexp
}

var emailACL atomic.Value

func LoadEmailACL(list []string, regexList []string) error {
	acl := &EmailACL{
		emails:  map[string]struct{}{},
		domains: map[string]struct{}{},
	}
	for _, v := range list {
		v = strings.ToLower(strings.TrimSpace(v))
		if strings.HasPrefix(v, "@") {
			domain := strings.TrimPrefix(v, "@")
			acl.domains[domain] = struct{}{}
		} else {
			acl.emails[v] = struct{}{}
		}
	}
	for _, r := range regexList {
		re, err := regexp.Compile(r)
		if err != nil {
			return err
		}
		acl.regex = append(acl.regex, re)
	}
	emailACL.Store(acl)
	return nil
}

func IsEmailAllowed(email string) bool {
	acl := emailACL.Load().(*EmailACL)
	email = strings.ToLower(strings.TrimSpace(email))
	// 白名单为空 → 拒绝所有
	if len(acl.emails) == 0 && len(acl.domains) == 0 && len(acl.regex) == 0 {
		return false
	}
	// 精确匹配
	if _, ok := acl.emails[email]; ok {
		return true
	}
	// domain 匹配
	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		domain := parts[1]
		if _, ok := acl.domains[domain]; ok {
			return true
		}
	}
	// regex
	for _, r := range acl.regex {
		if r.MatchString(email) {
			return true
		}
	}
	return false
}

func CheckMailFrom(email string) error {
	if !IsEmailAllowed(email) {
		log.Logf("smtp blocked email: %s", email)
		return fmt.Errorf("550 sender not allowed")
	}
	return nil
}

type RateLimit struct {
	count    int
	lastTime time.Time
}

var rateLimitMap sync.Map // key: ip/user, value: *RateLimit

func CheckRateLimit(ip net.IP, user string, maxPerMinute int) bool {

	key := ip.String() + ":" + user
	now := time.Now()

	v, _ := rateLimitMap.LoadOrStore(key, &RateLimit{
		count:    0,
		lastTime: now,
	})

	rl := v.(*RateLimit)

	// 超过一分钟窗口 → 重置计数
	if now.Sub(rl.lastTime) > time.Minute {
		rl.count = 0
		rl.lastTime = now
	}

	if rl.count >= maxPerMinute {
		return false
	}

	rl.count++
	return true
}

// if !CheckRateLimit(clientIP, username, 50) {
//     return fmt.Errorf("451 Too many messages, rate limit exceeded")
// }
