// Test Box filesystem interface
package vfm_test

import (
	"testing"

	"github.com/rclone/rclone/backend/vfm"
	"github.com/rclone/rclone/fstest/fstests"
)

// TestIntegration runs integration tests against the remote
func TestIntegration(t *testing.T) {
	fstests.Run(t, &fstests.Opt{
		RemoteName: "TestVfm:",
		NilObject:  (*vfm.Object)(nil),
	})
}
