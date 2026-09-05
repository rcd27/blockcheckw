#!/usr/bin/env bash
# PreToolUse hook: block gh commands that would post comments/reviews to GitHub.
# The user writes GitHub comments himself — Claude must never post them.

cmd=$(jq -r '.tool_input.command // empty')
[ -z "$cmd" ] && exit 0

deny() {
  jq -n --arg r "$1" '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'
  exit 0
}

# gh pr comment / gh issue comment (any form, incl. --edit-last)
if echo "$cmd" | grep -qE '\bgh[[:space:]]+(pr|issue)[[:space:]]+comment\b'; then
  deny "GitHub-комменты запрещены: пользователь пишет их сам. Апрув/мердж без текста — можно."
fi

# gh pr review with any text payload (--body/-b/--body-file/--comment)
if echo "$cmd" | grep -qE '\bgh[[:space:]]+pr[[:space:]]+review\b' \
   && echo "$cmd" | grep -qE '(--body(-file)?([= ]|$)|[[:space:]]-b[[:space:]=]|--comment)'; then
  deny "Ревью с текстом запрещено: пользователь пишет комменты сам. Разрешён только голый --approve без --body."
fi

# gh api writing to comment/review endpoints
if echo "$cmd" | grep -qE '\bgh[[:space:]]+api\b' \
   && echo "$cmd" | grep -qE '(comments|reviews)' \
   && echo "$cmd" | grep -qiE '(-X[[:space:]=]*(POST|PATCH|PUT)|--method[[:space:]=]+["'"'"']?(POST|PATCH|PUT)|(-f|-F|--field|--raw-field|--input)[= ])'; then
  deny "Запись в comments/reviews через gh api запрещена: пользователь пишет комменты сам."
fi

exit 0
