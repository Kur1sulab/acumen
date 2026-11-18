package injection

import "github.com/Kur1sulab/kara/engine-go/litmus/scan"

// 覆盖表上的 12 个检查项。Name 是客户会在报告里逐行看到的东西，
// 所以按「客户能问出的问题」切分，而不是按我的实现函数切分。
var (
	metaSqliError = scan.Meta{
		Name: "injection/sqli-error", Family: family,
		Title: "SQL 注入（报错型）", Severity: "high",
		Owasp: "A03:2021", CWE: "CWE-89",
	}
	metaSqliBoolean = scan.Meta{
		Name: "injection/sqli-boolean", Family: family,
		Title: "SQL 注入（布尔盲注）", Severity: "high",
		Owasp: "A03:2021", CWE: "CWE-89",
	}
	metaSqliTime = scan.Meta{
		Name: "injection/sqli-time", Family: family,
		Title: "SQL 注入（时间盲注）", Severity: "high",
		Owasp: "A03:2021", CWE: "CWE-89",
	}
	metaXSS = scan.Meta{
		Name: "injection/xss-reflect", Family: family,
		Title: "反射型 XSS", Severity: "medium",
		Owasp: "A03:2021", CWE: "CWE-79",
	}
	metaCMDI = scan.Meta{
		Name: "injection/cmdi", Family: family,
		Title: "命令注入", Severity: "critical",
		Owasp: "A03:2021", CWE: "CWE-78",
	}
	metaSSTI = scan.Meta{
		Name: "injection/ssti", Family: family,
		Title: "服务端模板注入", Severity: "high",
		Owasp: "A03:2021", CWE: "CWE-1336",
	}
	metaXXE = scan.Meta{
		Name: "injection/xxe", Family: family,
		Title: "XML 外部实体注入", Severity: "high",
		Owasp: "A05:2021", CWE: "CWE-611",
	}
	metaSSRF = scan.Meta{
		Name: "injection/ssrf", Family: family,
		Title: "服务端请求伪造", Severity: "high",
		Owasp: "A10:2021", CWE: "CWE-918",
	}
	metaLFI = scan.Meta{
		Name: "injection/lfi", Family: family,
		Title: "路径穿越 / 文件包含", Severity: "high",
		Owasp: "A01:2021", CWE: "CWE-22",
	}
	metaNoSQL = scan.Meta{
		Name: "injection/nosqli", Family: family,
		Title: "NoSQL 注入", Severity: "high",
		Owasp: "A03:2021", CWE: "CWE-943",
	}
	metaOpenRedirect = scan.Meta{
		Name: "injection/open-redirect", Family: family,
		Title: "开放重定向", Severity: "medium",
		Owasp: "A01:2021", CWE: "CWE-601",
	}
	metaCRLF = scan.Meta{
		Name: "injection/crlf", Family: family,
		Title: "CRLF 响应头注入", Severity: "medium",
		Owasp: "A03:2021", CWE: "CWE-93",
	}
)

// init 把 12 个检查项注册进全局覆盖表。
//
// 重名会 panic（scan.Register 的规矩）：两个检查项同名会让覆盖表互相覆盖，
// 也就是「测了的」把「没测的」抹掉 —— 这正是覆盖表最不能犯的错。
func init() {
	scan.Register(
		scan.Check{Meta: metaSqliError, Run: runSqliError},
		scan.Check{Meta: metaSqliBoolean, Run: runSqliBoolean},
		scan.Check{Meta: metaSqliTime, Run: runSqliTime},
		scan.Check{Meta: metaXSS, Run: runXSS},
		scan.Check{Meta: metaCMDI, Run: runCMDI},
		scan.Check{Meta: metaSSTI, Run: runSSTI},
		scan.Check{Meta: metaXXE, Run: runXXE},
		scan.Check{Meta: metaSSRF, Run: runSSRF},
		scan.Check{Meta: metaLFI, Run: runLFI},
		scan.Check{Meta: metaNoSQL, Run: runNoSQL},
		scan.Check{Meta: metaOpenRedirect, Run: runOpenRedirect},
		scan.Check{Meta: metaCRLF, Run: runCRLF},
	)
}
