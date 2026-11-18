// Package model 是全项目共用的数据模型。
//
// 为什么要单独一个包：engine（产出）、pocgen（生成 PoC）、report（渲染报告）
// 三方必须对同一份结构达成一致，否则报告和 PoC 会各自漂移。这个包就是契约。
//
// JSON 字段名与 Python 版 model.py 的 to_dict() 逐字对齐——两边输出必须可 diff，
// 这是 Go 版正确性的唯一硬证据（Python 版当 oracle）。
package model

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// 等级顺序：报告按这个顺序排序，critical 在前
var Severities = []string{"critical", "high", "medium", "low", "info"}

// SevRank 给排序用，越小越严重
var SevRank = map[string]int{
	"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}

// SevCN 中文名
var SevCN = map[string]string{
	"critical": "严重", "high": "高危", "medium": "中危",
	"low": "低危", "info": "信息",
}

// Levels L1 只是「看得见」，L2 拿到真实数据/凭据，L3 拿到内部权限 —— 交付线是 L2
var Levels = []string{"L1", "L2", "L3"}

// Categories 四大类
var Categories = []string{"web", "host", "network", "iot"}

// NowISO 与 Python 的 time.strftime("%Y-%m-%dT%H:%M:%S%z") 等价。
// 注意：Go 的 Z07:00 在 UTC 时输出 "Z"，Python 输出 "+0000"；
// 本地时区两边都是 "+0800" 形式，对齐时需要显式格式化。
func NowISO() string {
	return time.Now().Format("2006-01-02T15:04:05-0700")
}

// MaskSecret 凭据打码：只留前 keep 位。报告里绝不出现完整口令。
func MaskSecret(v string, keep int) string {
	if v == "" {
		return ""
	}
	if len(v) <= keep {
		return strings.Repeat("*", len(v))
	}
	n := len(v) - keep
	if n < 4 {
		n = 4
	}
	return v[:keep] + strings.Repeat("*", n)
}

var slugRe = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)

// Slug 把任意字符串压成文件名安全的短串
func Slug(s string, maxlen int) string {
	s = strings.Trim(slugRe.ReplaceAllString(s, "-"), "-")
	if len(s) > maxlen {
		s = s[:maxlen]
	}
	if s == "" {
		s = "x"
	}
	return strings.ToLower(s)
}

// DedupeKey 同一目标上的同一类问题只留一条，避免刷量。
func DedupeKey(check, target, extra string) string {
	h := sha1.Sum([]byte(check + "|" + target + "|" + extra))
	return hex.EncodeToString(h[:])[:12]
}

// Cred 一条可用的凭据（用于凭据复用与横向）。
type Cred struct {
	Proto  string `json:"proto"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	User   string `json:"user"`
	Secret string `json:"-"` // 明文只在内存里，序列化走 SecretMasked
	Kind   string `json:"kind"`
	Source string `json:"source"`
	Note   string `json:"note"`
}

// CredJSON 是序列化形状：secret 只出打码版
type CredJSON struct {
	Proto        string `json:"proto"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	User         string `json:"user"`
	SecretMasked string `json:"secret_masked"`
	Kind         string `json:"kind"`
	Source       string `json:"source"`
	Note         string `json:"note"`
}

// NewCred 构造一条凭据
func NewCred(proto, host string, port int, user, secret, kind, source, note string) *Cred {
	if kind == "" {
		kind = "password"
	}
	return &Cred{Proto: proto, Host: host, Port: port, User: user,
		Secret: secret, Kind: kind, Source: source, Note: note}
}

// ToJSON 打码后输出
func (c *Cred) ToJSON() CredJSON {
	return CredJSON{Proto: c.Proto, Host: c.Host, Port: c.Port, User: c.User,
		SecretMasked: MaskSecret(c.Secret, 4), Kind: c.Kind,
		Source: c.Source, Note: c.Note}
}

func (c *Cred) String() string {
	return fmt.Sprintf("<Cred %s %s:%d user=%s>", c.Proto, c.Host, c.Port, c.User)
}

// Target 一个待测目标。可以是 IP、host:port、URL 或 CIDR 展开后的单 IP。
type Target struct {
	Raw    string `json:"raw"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Scheme string `json:"scheme"`
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Note   string `json:"note"`
}

// NewTarget 构造目标
func NewTarget(raw, host string, port int, scheme, path, kind, note string) *Target {
	if host == "" {
		host = raw
	}
	if path == "" {
		path = "/"
	}
	if kind == "" {
		kind = "ip"
	}
	return &Target{Raw: raw, Host: host, Port: port, Scheme: scheme,
		Path: path, Kind: kind, Note: note}
}

// Addr host:port 或裸 host
func (t *Target) Addr() string {
	if t.Port > 0 {
		return fmt.Sprintf("%s:%d", t.Host, t.Port)
	}
	return t.Host
}

func (t *Target) String() string { return "<Target " + t.Addr() + ">" }

// Finding 一条发现。字段设计原则：报告要用的全在里面，报告不再回查别的表。
type Finding struct {
	ID         string                 `json:"id"`
	Check      string                 `json:"check"`
	Name       string                 `json:"name"`
	Severity   string                 `json:"severity"`
	Target     string                 `json:"target"`
	Host       string                 `json:"host"`
	Port       int                    `json:"port"`
	Scheme     string                 `json:"scheme"`
	Category   string                 `json:"category"`
	Level      string                 `json:"level"`
	Confidence string                 `json:"confidence"`
	Time       string                 `json:"time"`
	Evidence   string                 `json:"evidence"`
	Repro      string                 `json:"repro"`
	Impact     string                 `json:"impact"`
	Fix        string                 `json:"fix"`
	CVSS       string                 `json:"cvss"`
	PoC        string                 `json:"poc"`
	RawRef     string                 `json:"raw_ref"`
	Extra      map[string]interface{} `json:"extra"`
	Triage     map[string]interface{} `json:"triage"`
	TitleEN    string                 `json:"title_en"`
	Creds      []Cred                 `json:"-"`
	CredsJSON  []CredJSON             `json:"creds"`
}

// FindingOpts 可选字段，避免构造函数 20 个参数
type FindingOpts struct {
	Host, Scheme, Category, Level, Confidence string
	Port                                      int
	Evidence, Repro, Impact, Fix, CVSS, TitleEN string
	Extra, Triage                             map[string]interface{}
	Creds                                     []Cred
}

// NewFinding 构造一条发现，默认值对齐 Python 版
func NewFinding(check, name, severity, target string, o FindingOpts) *Finding {
	if _, ok := SevRank[severity]; !ok {
		severity = "info"
	}
	level := o.Level
	if level != "L1" && level != "L2" && level != "L3" {
		level = "L1"
	}
	cat := o.Category
	if cat == "" {
		cat = "web"
	}
	conf := o.Confidence
	if conf == "" {
		conf = "confirmed"
	}
	host := o.Host
	if host == "" {
		host = target
	}
	extra := o.Extra
	if extra == nil {
		extra = map[string]interface{}{}
	}
	triage := o.Triage
	if triage == nil {
		triage = map[string]interface{}{}
	}
	creds := o.Creds
	if creds == nil {
		creds = []Cred{}
	}
	return &Finding{
		Check: check, Name: name, Severity: severity, Target: target,
		Host: host, Port: o.Port, Scheme: o.Scheme, Category: cat, Level: level,
		Confidence: conf, Time: NowISO(), Evidence: o.Evidence, Repro: o.Repro,
		Impact: o.Impact, Fix: o.Fix, CVSS: o.CVSS, TitleEN: o.TitleEN,
		Extra: extra, Triage: triage, Creds: creds,
	}
}

// SevRankOf 排序用
func (f *Finding) SevRankOf() int {
	if r, ok := SevRank[f.Severity]; ok {
		return r
	}
	return 99
}

// SevCNOf 中文等级名
func (f *Finding) SevCNOf() string {
	if s, ok := SevCN[f.Severity]; ok {
		return s
	}
	return f.Severity
}

// Key 去重键：check + target + extra["path"]
func (f *Finding) Key() string {
	path := ""
	if p, ok := f.Extra["path"]; ok {
		path = fmt.Sprintf("%v", p)
	}
	return DedupeKey(f.Check, f.Target, path)
}

// AddNote 往 triage.notes 里追加一条
func (f *Finding) AddNote(note string) {
	notes, _ := f.Triage["notes"].([]interface{})
	f.Triage["notes"] = append(notes, note)
}

// SyncCredsJSON 序列化前刷新打码凭据
func (f *Finding) SyncCredsJSON() {
	out := make([]CredJSON, 0, len(f.Creds))
	for i := range f.Creds {
		out = append(out, f.Creds[i].ToJSON())
	}
	f.CredsJSON = out
}

func (f *Finding) String() string {
	return fmt.Sprintf("<Finding %s %s @ %s>", f.Severity, f.Name, f.Target)
}

// Coverage 三态覆盖：测了(ok) / 未测(skip, 带原因) / 不适用(na)。
//
// 铁律：面覆盖 != 类覆盖。任何没测的东西都必须以 skip 出现在这里，
// 绝不允许「没报漏洞」和「没测」在报告里长得一样。
type Coverage struct {
	Target   string `json:"target"`
	Category string `json:"category"`
	Item     string `json:"item"`
	State    string `json:"state"`
	Reason   string `json:"reason"`
	Count    int    `json:"count"`
	Time     string `json:"time"`
}

// NewCoverage 构造一条覆盖记录
func NewCoverage(target, category, item, state, reason string, count int) *Coverage {
	if state == "" {
		state = "ok"
	}
	return &Coverage{Target: target, Category: category, Item: item,
		State: state, Reason: reason, Count: count, Time: NowISO()}
}

func (c *Coverage) String() string {
	return fmt.Sprintf("<Coverage %s %s %s>", c.State, c.Target, c.Item)
}
