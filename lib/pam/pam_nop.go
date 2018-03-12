// +build !pam,cgo

package pam

import (
	"fmt"
)

func New(config *Config) (*PAM, error) {
	return &nopContext{}, nil
}

// HasPAM returns if the binary was build with support for PAM compiled in or not.
func HasPAM() bool {
	return false
}
