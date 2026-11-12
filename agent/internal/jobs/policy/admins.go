package policy

import (
	"sort"
	"strings"

	"github.com/dranzo/dranzormm/agent/internal/posture"
)

// Reasons an unexpected administrator is left in the group.
const (
	keepSelf      = "the account the agent runs as"
	keepPrimary   = "administrator through its primary group or uid 0, which a group-membership edit cannot change"
	keepBadName   = "unusual account name; remove it manually"
	keepLastAdmin = "last remaining administrator"
)

// keptAdmin is an unexpected administrator that will not be removed.
type keptAdmin struct {
	Name   string
	Reason string
}

// adminPlan is the decision for localadmins.allowed.
type adminPlan struct {
	// Extra are the administrators that are neither allowed nor built in.
	Extra []posture.AdminAccount
	// Remove are the members of Extra that may be removed from the group.
	Remove []posture.AdminAccount
	// Kept are the members of Extra that must stay, with the reason.
	Kept []keptAdmin
}

// planAdmins decides which administrators are unexpected and which of those
// may be removed from the administrators group. It is a pure function.
//
// Rules:
//   - The built-in administrator (Windows RID 500, root) is always allowed:
//     it cannot be taken out of the group, so it is never "extra".
//   - Never remove the account the agent runs as.
//   - Never remove an account that is an administrator through its primary
//     group or uid 0 (a group edit would not change that), or one with a name
//     that fails ValidAccountName.
//   - Never remove the last remaining administrator: built-in accounts do
//     not count as remaining (the built-in Administrator is usually disabled
//     and root often has no password), so if every other administrator is
//     unexpected, the last one in name order stays.
func planAdmins(current []posture.AdminAccount, allowed []string, self string, key func(string) string) adminPlan {
	if key == nil {
		key = func(s string) string { return s }
	}
	allowedSet := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		allowedSet[key(a)] = true
	}
	selfKey := ""
	if self != "" {
		selfKey = key(self)
	}

	accounts := append([]posture.AdminAccount(nil), current...)
	sort.SliceStable(accounts, func(i, j int) bool { return key(accounts[i].Name) < key(accounts[j].Name) })

	var plan adminPlan
	nonBuiltin := 0
	seen := map[string]bool{}
	for _, a := range accounts {
		k := key(a.Name)
		if a.Name == "" || seen[k] {
			continue
		}
		seen[k] = true
		if a.Builtin {
			continue
		}
		nonBuiltin++
		if allowedSet[k] {
			continue
		}
		plan.Extra = append(plan.Extra, a)
		switch {
		case selfKey != "" && k == selfKey:
			plan.Kept = append(plan.Kept, keptAdmin{a.Name, keepSelf})
		case a.Primary:
			plan.Kept = append(plan.Kept, keptAdmin{a.Name, keepPrimary})
		case !ValidAccountName(a.Name):
			plan.Kept = append(plan.Kept, keptAdmin{a.Name, keepBadName})
		default:
			plan.Remove = append(plan.Remove, a)
		}
	}
	if len(plan.Remove) > 0 && nonBuiltin-len(plan.Remove) == 0 {
		last := plan.Remove[len(plan.Remove)-1]
		plan.Remove = plan.Remove[:len(plan.Remove)-1]
		plan.Kept = append(plan.Kept, keptAdmin{last.Name, keepLastAdmin})
	}
	return plan
}

func accountNames(accounts []posture.AdminAccount) string {
	names := make([]string, 0, len(accounts))
	for _, a := range accounts {
		names = append(names, displayName(a.Name))
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

// displayName makes an account name read from the system safe to print.
func displayName(name string) string { return posture.OneLine(name, 128) }

func keptList(kept []keptAdmin) string {
	parts := make([]string, 0, len(kept))
	for _, k := range kept {
		parts = append(parts, displayName(k.Name)+" ("+k.Reason+")")
	}
	return strings.Join(parts, ", ")
}
