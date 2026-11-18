// Package store 是运行状态库。
//
// 与 Python 版最大的差别：**不用 SQLite，用 JSONL**。
//
// 为什么：Go 标准库没有 sqlite 驱动（database/sql 只是接口），
// 引 mattn/go-sqlite3 要 cgo（废掉交叉编译与静态单文件），
// 引 modernc.org/sqlite 要拖几十个包的依赖树（废掉零依赖）。
//
// 而 Python 版用到的 SQL 其实只有三张极简表 + 五种查询，全是 KV 形状。
// 换成 JSONL 之后额外得到三个好处：
//   - 人类可读、可 grep、可 diff（渗透证据链尤其需要）
//   - 没有 CGO，CGO_ENABLED=0 静态单文件成立
//   - 崩溃时最多丢最后一行，SQLite 的 WAL 反而更复杂
//
// 代价：与 Python 版 state.db 不互通（跨版本 --resume 不支持，需同版本续跑）。
package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/Kur1sulab/kara/engine-go/litmus/model"
)

// runRec 一行 run 记录
type runRec struct {
	ID          int             `json:"id"`
	Started     string          `json:"started"`
	Finished    string          `json:"finished,omitempty"`
	Args        json.RawMessage `json:"args"`
	TargetsHash string          `json:"targets_hash"`
}

// hostRec 一行主机记录
type hostRec struct {
	RunID int    `json:"run_id"`
	Host  string `json:"host"`
	State string `json:"state"`
	Ports []int  `json:"ports"`
	TS    string `json:"ts"`
}

// findingRec 一行发现记录
type findingRec struct {
	RunID int             `json:"run_id"`
	Key   string          `json:"key"`
	JSON  json.RawMessage `json:"json"`
}

// Store 状态库。目录布局：
//
//	<dir>/runs.jsonl      每次 run 一行
//	<dir>/hosts.jsonl     每台主机一行（同 run+host 后者覆盖前者）
//	<dir>/findings.jsonl  每条发现一行（同 run+key 后者覆盖前者）
type Store struct {
	dir string
	mu  sync.Mutex

	runs     []runRec
	hosts    map[string]hostRec  // key: runID|host
	findings map[string]findingRec // key: runID|key

	fRuns     *os.File
	fHosts    *os.File
	fFindings *os.File
	wRuns     *bufio.Writer
	wHosts    *bufio.Writer
	wFindings *bufio.Writer
}

// Open 打开（或新建）状态库目录
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{
		dir:      dir,
		hosts:    map[string]hostRec{},
		findings: map[string]findingRec{},
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	var err error
	if s.fRuns, err = os.OpenFile(filepath.Join(dir, "runs.jsonl"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err != nil {
		return nil, err
	}
	if s.fHosts, err = os.OpenFile(filepath.Join(dir, "hosts.jsonl"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err != nil {
		return nil, err
	}
	if s.fFindings, err = os.OpenFile(filepath.Join(dir, "findings.jsonl"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err != nil {
		return nil, err
	}
	s.wRuns = bufio.NewWriter(s.fRuns)
	s.wHosts = bufio.NewWriter(s.fHosts)
	s.wFindings = bufio.NewWriter(s.fFindings)
	return s, nil
}

// load 把已有文件读进内存索引
func (s *Store) load() error {
	if err := eachLine(filepath.Join(s.dir, "runs.jsonl"), func(b []byte) error {
		var r runRec
		if err := json.Unmarshal(b, &r); err != nil {
			return nil // 坏行跳过，不让半行毁掉整个库
		}
		s.runs = append(s.runs, r)
		return nil
	}); err != nil {
		return err
	}
	if err := eachLine(filepath.Join(s.dir, "hosts.jsonl"), func(b []byte) error {
		var h hostRec
		if err := json.Unmarshal(b, &h); err != nil {
			return nil
		}
		s.hosts[fmt.Sprintf("%d|%s", h.RunID, h.Host)] = h
		return nil
	}); err != nil {
		return err
	}
	return eachLine(filepath.Join(s.dir, "findings.jsonl"), func(b []byte) error {
		var f findingRec
		if err := json.Unmarshal(b, &f); err != nil {
			return nil
		}
		s.findings[fmt.Sprintf("%d|%s", f.RunID, f.Key)] = f
		return nil
	})
}

func eachLine(path string, fn func([]byte) error) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		if err := fn(sc.Bytes()); err != nil {
			return err
		}
	}
	return sc.Err()
}

// NewRun 开一轮新 run，返回自增 id
func (s *Store) NewRun(args interface{}, targetsHash string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := 1
	if n := len(s.runs); n > 0 {
		id = s.runs[n-1].ID + 1
	}
	raw, err := json.Marshal(args)
	if err != nil {
		return 0, err
	}
	rec := runRec{ID: id, Started: model.NowISO(), Args: raw, TargetsHash: targetsHash}
	b, err := json.Marshal(rec)
	if err != nil {
		return 0, err
	}
	if _, err := s.wRuns.Write(append(b, '\n')); err != nil {
		return 0, err
	}
	if err := s.wRuns.Flush(); err != nil {
		return 0, err
	}
	s.runs = append(s.runs, rec)
	return id, nil
}

// FinishRun 标记 run 结束
func (s *Store) FinishRun(runID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.runs {
		if s.runs[i].ID == runID {
			s.runs[i].Finished = model.NowISO()
			// 追加一条「完成」记录，读时取最后一条
			b, err := json.Marshal(s.runs[i])
			if err != nil {
				return err
			}
			if _, err := s.wRuns.Write(append(b, '\n')); err != nil {
				return err
			}
			return s.wRuns.Flush()
		}
	}
	return fmt.Errorf("run %d 不存在", runID)
}

// DoneHosts 本轮已跑完的主机
func (s *Store) DoneHosts(runID int) map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]bool{}
	for _, h := range s.hosts {
		if h.RunID == runID && h.State == "done" {
			out[h.Host] = true
		}
	}
	return out
}

// MarkHost 记录一台主机的状态
func (s *Store) MarkHost(runID int, host, state string, ports []int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ports == nil {
		ports = []int{}
	}
	rec := hostRec{RunID: runID, Host: host, State: state, Ports: ports, TS: model.NowISO()}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := s.wHosts.Write(append(b, '\n')); err != nil {
		return err
	}
	if err := s.wHosts.Flush(); err != nil {
		return err
	}
	s.hosts[fmt.Sprintf("%d|%s", runID, host)] = rec
	return nil
}

// SaveFindings 落盘本轮全部发现
func (s *Store) SaveFindings(runID int, findings []*model.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range findings {
		f.SyncCredsJSON()
		raw, err := json.Marshal(f)
		if err != nil {
			return err
		}
		rec := findingRec{RunID: runID, Key: f.Key(), JSON: raw}
		b, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if _, err := s.wFindings.Write(append(b, '\n')); err != nil {
			return err
		}
		s.findings[fmt.Sprintf("%d|%s", runID, rec.Key)] = rec
	}
	return s.wFindings.Flush()
}

// LastRun 最近一次已完成的 run。
//
// onlyWithFindings=true 用于 --diff：空跑（比如 --resume 全跳过的那轮）
// 不能当基准，否则「仍在」永远是 0，差异报告全是假新增。
func (s *Store) LastRun(exclude int, onlyWithFindings bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.runs) - 1; i >= 0; i-- {
		r := s.runs[i]
		if r.Finished == "" || r.ID == exclude {
			continue
		}
		if onlyWithFindings {
			has := false
			for _, f := range s.findings {
				if f.RunID == r.ID {
					has = true
					break
				}
			}
			if !has {
				continue
			}
		}
		return r.ID
	}
	return 0
}

// DoneHostsForHash 同一批目标历史上所有跑完的主机（--resume 的判据）。
func (s *Store) DoneHostsForHash(targetsHash string) map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := map[int]bool{}
	for _, r := range s.runs {
		if r.TargetsHash == targetsHash {
			ids[r.ID] = true
		}
	}
	out := map[string]bool{}
	for _, h := range s.hosts {
		if ids[h.RunID] && h.State == "done" {
			out[h.Host] = true
		}
	}
	return out
}

// FindingsOf 读出某轮的发现
func (s *Store) FindingsOf(runID int) ([]*model.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*model.Finding
	for _, f := range s.findings {
		if f.RunID != runID {
			continue
		}
		var m model.Finding
		if err := json.Unmarshal(f.JSON, &m); err != nil {
			continue
		}
		out = append(out, &m)
	}
	return out, nil
}

// Close 刷盘并关闭
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, w := range []*bufio.Writer{s.wRuns, s.wHosts, s.wFindings} {
		if w != nil {
			if err := w.Flush(); err != nil {
				return err
			}
		}
	}
	for _, f := range []*os.File{s.fRuns, s.fHosts, s.fFindings} {
		if f != nil {
			f.Close()
		}
	}
	return nil
}
