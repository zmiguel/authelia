package authorization

import (
	"strings"

	"github.com/authelia/authelia/internal/utils"
)

func isSubjectMatching(subject Subject, subjectRule, domain string, domains []string) bool {
	// If no subject is provided in the rule, we match any user.
	if subjectRule == "" {
		return true
	}

	if strings.HasPrefix(subjectRule, userPrefix) {
		user := strings.Trim(subjectRule[len(userPrefix):], " ")
		if user == subject.Username {
			return true
		}
	}

	if strings.HasPrefix(subjectRule, groupPrefix) {
		group := strings.Trim(subjectRule[len(groupPrefix):], " ")
		if utils.IsStringInSlice(group, subject.Groups) {
			return true
		}
	}

	for _, domainRule := range domains {
		if strings.HasPrefix(domainRule, "@.") && strings.HasSuffix(domain, domainRule[1:]) {
			suffix := strings.Trim(domainRule[1:], " ")
			group := strings.Trim(strings.Replace(domain, suffix, "", 1), " ")

			if !strings.Contains(group, ".") && utils.IsStringInSlice(group, subject.Groups) {
				return true
			}
		}
	}

	return false
}
