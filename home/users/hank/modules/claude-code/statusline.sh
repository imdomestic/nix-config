#!/usr/bin/env bash
# Claude Code status line.
#
#   ~/Development/max |  main | claude-opus-5 high | $793.65 5h:34% 7d:80% resets:1h58m
#
# Runs on every render, so it does exactly one jq and one git per call.
# Everything below is appended left to right in call order — nothing here
# reads terminal width, so there is no reason to re-run this any faster
# than Claude Code renders a new status line anyway.

input=$(cat)

# One jq process for everything.  Absent fields come back as -1 / empty
# so the sections below can just not render rather than printing junk.
#
# Joined on US (0x1f), not a tab: tab counts as IFS whitespace, so bash
# collapses a run of them into one separator and an absent field takes
# every later field with it — which showed up as the cost rendering
# where the effort should be.
IFS=$'\x1f' read -r cwd model effort cost r5 r7 reset5 <<<"$(
  jq -r '[
    (.workspace.current_dir // .cwd // ""),
    (.model.display_name // .model.id // "Claude"),
    (.effort.level // ""),
    (.cost.total_cost_usd // -1),
    (.rate_limits.five_hour.used_percentage // -1),
    (.rate_limits.seven_day.used_percentage // -1),
    (.rate_limits.five_hour.resets_at // -1)
  ] | join("")' <<<"$input"
)"

# jq hands back floats; the percentages below want integers.
round() { printf '%.0f' "${1:--1}" 2>/dev/null || printf '%s' -1; }
r5=$(round "$r5")
r7=$(round "$r7")

# Green while there is room, yellow when it is worth noticing, red when
# it is about to matter — a spent rate limit costs the whole session.
lim_color() { if (($1 >= 80)); then echo 31; elif (($1 >= 50)); then echo 33; else echo 32; fi; }

# Path: $HOME as ~, and never more than the last three segments.
short_cwd=${cwd/#$HOME/\~}
short_cwd=$(awk -F/ '{ if (NF <= 4) print $0; else print "…/" $(NF-2) "/" $(NF-1) "/" $NF }' <<<"$short_cwd")

# --no-optional-locks so a concurrent git command can never stall the prompt.
branch=$(git -C "$cwd" --no-optional-locks branch --show-current 2>/dev/null)

# One running string, built left to right in call order.  Groups are
# separated by a dim bar and elements within a group by a space, so the
# line reads as four things — where, which branch, which model, what it
# is costing — rather than one run of seven.
#
# The bar is written with $'...' rather than a printf substitution: this
# is on the render path, and a fork per divider is a fork for nothing.
sep=$' \033[2m|\033[0m '
lc=''
add_group() { [ -n "$lc" ] && lc+=$sep; lc+=$1; }

add_group "$(printf '\033[34m%s\033[0m' "$short_cwd")"

# U+E0A0, the Powerline branch glyph, written as explicit UTF-8 bytes:
# it is invisible in most editors and got silently dropped once already
# when this file was rewritten.
[ -n "$branch" ] &&
  add_group "$(printf '\033[32m\xee\x82\xa0 %s\033[0m' "$branch")"

# Effort shares the model's group: it modifies the model rather than
# standing on its own, so it sits one space away and dim instead of
# behind a divider of its own.
if [ -n "$effort" ]; then
  add_group "$(printf '\033[36m%s\033[0m \033[2m%s\033[0m' "$model" "$effort")"
else
  add_group "$(printf '\033[36m%s\033[0m' "$model")"
fi

# Spend, the two rate-limit windows and the countdown are all one answer
# to "how much of this session is left", so they share a group.  Any of
# the three can be absent, hence collecting them here first: the divider
# then lands once, in front of whichever showed up, and not at all when
# none did.
usage=''
add_usage() { [ -n "$usage" ] && usage+=' '; usage+=$1; }

# Session spend so far.
if [ "$cost" != "-1" ] && [ -n "$cost" ]; then
  add_usage "$(printf '\033[2m$\033[0m%.2f' "$cost")"
fi

# Both windows or neither: one number without the other invites reading
# whichever showed up as "the" limit.
if ((r5 >= 0 && r7 >= 0)); then
  add_usage \
    "$(printf '\033[2m5h:\033[0m\033[%sm%d%%\033[0m \033[2m7d:\033[0m\033[%sm%d%%\033[0m' \
      "$(lim_color "$r5")" "$r5" "$(lim_color "$r7")" "$r7")"
fi

# resets_at is a wall-clock epoch; what is worth reading off the bar is
# how far off that is.  Only the five-hour window gets a countdown — it
# is the one that gates a session, where the seven-day reset is usually
# days out and would be a number that never visibly moves.
#
# EPOCHSECONDS is a bash 5.0 builtin so "now" costs no fork, and printf's
# %(...)T fallback is a builtin too: this stays one jq and one git.
if ((reset5 > 0)); then
  left=$((reset5 - ${EPOCHSECONDS:-$(printf '%(%s)T' -1)}))
  ((left < 0)) && left=0
  if ((left >= 3600)); then
    eta=$(printf '%dh%02dm' $((left / 3600)) $((left % 3600 / 60)))
  else
    eta=$(printf '%dm' $((left / 60)))
  fi
  add_usage "$(printf '\033[2mresets:\033[0m%s' "$eta")"
fi

[ -n "$usage" ] && add_group "$usage"

printf '%s\n' "$lc"
