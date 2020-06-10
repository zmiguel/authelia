package authorization

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShouldMatchSubjectWithMatchingUser(t *testing.T) {
	assert.True(t, isSubjectMatching(Subject{Username: "bob"}, "user:bob", "example.com", []string{"example.com"}))
	assert.True(t, isSubjectMatching(Subject{Username: "fred"}, "user:fred", "example.com", []string{"example.com"}))
}

func TestShouldMatchSubjectWithMatchingGroup(t *testing.T) {
	assert.True(t, isSubjectMatching(Subject{Username: "bob", Groups: []string{"abc", "admin", "user"}}, "group:admin", "example.com", []string{"example.com"}))
	assert.True(t, isSubjectMatching(Subject{Username: "bob", Groups: []string{"abc"}}, "group:abc", "example.com", []string{"example.com"}))
}

func TestShouldNotMatchSubjectWithNonMatchingElements(t *testing.T) {
	assert.False(t, isSubjectMatching(Subject{Username: "bob", Groups: []string{"abc", "admin", "user"}}, "user:fred", "example.com", []string{"example.com"}))
	assert.False(t, isSubjectMatching(Subject{Username: "bob", Groups: []string{"abc", "admin", "user"}}, "group:superadmins", "example.com", []string{"example.com"}))
}

func TestShouldMatchSubjectWithDynamicGroup(t *testing.T) {
	assert.True(t, isSubjectMatching(Subject{Username: "bob", Groups: []string{"abc", "somedomain", "admin"}}, "user:superadmins", "somedomain.example.com", []string{"@.example.com"}))
}
