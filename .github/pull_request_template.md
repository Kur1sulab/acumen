## 这个 PR 改了什么

<!-- 一两句话。如果修的是某个解析器不认的格式，把那份产物的形状写出来。 -->

## 为什么

<!-- 触发场景。比如「xray 的 xxx 字段以前被丢了，导致这批报告 0 产出」 -->

## 自检

- [ ] `python -m unittest discover -s tests` 全过
- [ ] `python tools/check_zero_deps.py` 通过（**没有引入任何第三方依赖**）
- [ ] 前端没有引入构建链（无 package.json / node_modules）
- [ ] 新格式解析补了对应的 `tests/fixtures/` 夹具
- [ ] 改了解析行为的话，`CHANGELOG.md` 已更新

## 试过的真实产物

<!-- 拿哪份实际扫描结果验证过？没有就写「无，只有夹具」。 -->

## 顺带说明

<!-- 破坏性改动、数据库结构变化、需要重新全量解析（--scan --force）等，写在这里。 -->
