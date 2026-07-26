#!/usr/bin/env bash
# Claude Code status line.
#
#   ~/Development/max   main claude-opus-5 high    $793.65 5h:34% 7d:80% resets:1h58m
#
# Runs on every render, so it does exactly one jq and one git per call.

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

# Two lockstep strings per side: the coloured one that gets printed, and
# a plain one that gets measured.  Measuring means stripping escapes, and
# building the plain form as we go is exact where a strip-the-escapes
# regex is a second thing to keep correct.
lc='' lp='' rc='' rp=''
#
# Elements are separated by one space.  add_left takes an optional third
# argument to widen that separator, which only the branch uses: it leads
# with the Powerline glyph, and one space leaves the glyph sitting on top
# of the path rather than beside it.
add_left() { [ -n "$lp" ] && { lc+=${3:- } lp+=${3:- }; }; lc+=$1 lp+=$2; }
add_right() { [ -n "$rp" ] && { rc+=' ' rp+=' '; }; rc+=$1 rp+=$2; }

add_left "$(printf '\033[34m%s\033[0m' "$short_cwd")" "$short_cwd"

# U+E0A0, the Powerline branch glyph, written as explicit UTF-8 bytes:
# it is invisible in most editors and got silently dropped once already
# when this file was rewritten.
[ -n "$branch" ] &&
  add_left "$(printf '\033[32m\xee\x82\xa0 %s\033[0m' "$branch")" "$(printf '\xee\x82\xa0 %s' "$branch")" '  '

# Every element is separated by the same single space, so effort is set
# apart from the model by being dim alone — it modifies the model rather
# than standing on its own.
if [ -n "$effort" ]; then
  add_left "$(printf '\033[36m%s\033[0m \033[2m%s\033[0m' "$model" "$effort")" "$model $effort"
else
  add_left "$(printf '\033[36m%s\033[0m' "$model")" "$model"
fi

# Session spend so far.
if [ "$cost" != "-1" ] && [ -n "$cost" ]; then
  add_right "$(printf '\033[2m$\033[0m%.2f' "$cost")" "$(printf '$%.2f' "$cost")"
fi

# Both windows or neither: one number without the other invites reading
# whichever showed up as "the" limit.
if ((r5 >= 0 && r7 >= 0)); then
  add_right \
    "$(printf '\033[2m5h:\033[0m\033[%sm%d%%\033[0m \033[2m7d:\033[0m\033[%sm%d%%\033[0m' \
      "$(lim_color "$r5")" "$r5" "$(lim_color "$r7")" "$r7")" \
    "$(printf '5h:%d%% 7d:%d%%' "$r5" "$r7")"
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
  add_right "$(printf '\033[2mresets:\033[0m%s' "$eta")" "resets:$eta"
fi

if [ -z "$rp" ]; then
  printf '%s\n' "$lc"
  exit 0
fi

# COLUMNS is exported into the status line's environment and tracks
# resizes; tput is the fallback for a host that doesn't.  With neither,
# gap stays at the single space everything else is separated by, so the
# line degrades to plain left-to-right rather than guessing a width.
# COLUMNS is set to the *current* terminal size before each run, so it
# is right whenever we are run at all — but a resize is not one of the
# events that runs us, hence refreshInterval in settings.json.
#
# No tput fallback: Claude Code captures our output rather than wiring
# it to the terminal, so tput has no tty to measure and quietly answers
# with terminfo's 80.  A wrong width is worse than none, because none
# just falls through to the plain two-space layout below.
width=${COLUMNS:-0}
[ "$width" -gt 0 ] 2>/dev/null || width=0

# COLUMNS is the terminal's width, not the width Claude Code will draw
# into — it keeps some for itself, and a line that uses all of COLUMNS
# comes back truncated with an ellipsis, eating the right-hand end.
#
# Measured by rendering a column ruler as the status line: at
# COLUMNS=165 the ellipsis sat in column 162, so 3 columns are spoken
# for.  8 is what actually looks right, which says the reserve is not
# only the truncation limit; tune it here rather than editing the
# arithmetic:
#
#   CLAUDE_STATUSLINE_RESERVE=12 claude
#
reserve=${CLAUDE_STATUSLINE_RESERVE:-8}
((width > reserve)) && width=$((width - reserve))

gap=$((width - ${#lp} - ${#rp}))
((gap < 1)) && gap=1

printf '%s%*s%s\n' "$lc" "$gap" '' "$rc"
