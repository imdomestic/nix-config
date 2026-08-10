#!/usr/bin/env bash
# 把 agent 的状态挂到它所在的 tmux window 上,dotbar 的窗口列表里就能一眼看到
# 谁在等你:
#
#   nvim • claude ⚠ • build ⋯
#
# Claude Code 的 hook 是从 agent 所在的 pane fork 出来的,所以 $TMUX_PANE 就是
# 那个 pane。标记挂在 **window** 而不是 pane 上,有两个原因:状态栏渲染的是
# window 列表;而且你之后在同一个 window 里开新 pane,标记还在对的地方。
#
# 值自带前导空格,格式串那边就不用写条件判断 —— @agent_state 没设的窗口展开成
# 空串,和没装这套东西时的渲染完全一致。
set -u

# 不在 tmux 里(裸终端、CI、没复用器的 ssh)就安静退出。
[ -n "${TMUX:-}" ] && [ -n "${TMUX_PANE:-}" ] || exit 0

case "${1:-}" in
  working) state=' ⋯' ;;
  blocked) state=' ⚠' ;;
  done) state=' ✓' ;;
  clear)
    # -u 是恢复成继承值,而这个 user option 没有上层值,等价于清掉。
    tmux set-option -uw -t "$TMUX_PANE" @agent_state 2>/dev/null
    exit 0
    ;;
  *) exit 0 ;;
esac

tmux set-option -w -t "$TMUX_PANE" @agent_state "$state" 2>/dev/null

# hook 的退出码对 Claude Code 有语义:2 是阻断当前操作,其它非 0 会当错误回报给
# 模型。状态栏挂了不该影响 agent 干活,所以无条件成功退出。
exit 0
