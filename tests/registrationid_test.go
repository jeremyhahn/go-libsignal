package tests

import (
	"fmt"
	"github.com/jeremyhahn/go-libsignal/pkg/util/keyhelper"
	"testing"
)

func TestRegistrationID(t *testing.T) {
	regID := keyhelper.GenerateRegistrationID()
	fmt.Println(regID)
}
