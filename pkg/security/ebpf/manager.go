// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

// +build linux_bpf

package ebpf

import (
	"os"

	"github.com/DataDog/ebpf"
	"github.com/DataDog/ebpf/manager"

	"github.com/DataDog/datadog-agent/pkg/security/ebpf/probes"
)

var (
	// verifierLogSize is the size of the log buffer given to the verifier (2 * 1024 * 1024)
	verifierLogSize = 2097152

	// defaultPerfRingBufferSize is the default buffer size of the perf buffers
	defaultPerfRingBufferSize = 128 * os.Getpagesize()
)

// NewDefaultOptions returns a new instance of the default runtime security manager options
func NewDefaultOptions() manager.Options {
	return manager.Options{
		DefaultPerfRingBufferSize: defaultPerfRingBufferSize,
		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize: verifierLogSize,
			},
		},
	}
}

// NewRuntimeSecurityManager returns a new instance of the runtime security module manager
func NewRuntimeSecurityManager() *manager.Manager {
	return &manager.Manager{

		Probes: probes.AllProbes(),

		Maps: []*manager.Map{
			// Dentry resolver table
			{Name: "pathnames"},
			// Snapshot table
			{Name: "inode_numlower"},
			// Open tables
			{Name: "open_policy"},
			{Name: "open_basename_approvers"},
			{Name: "open_flags_approvers"},
			{Name: "open_flags_discarders"},
			{Name: "open_process_inode_approvers"},
			{Name: "open_path_inode_discarders"},
			// Exec tables
			{Name: "proc_cache"},
			{Name: "pid_cookie"},
			// Unlink tables
			{Name: "unlink_path_inode_discarders"},
			// Mount tables
			{Name: "mount_id_offset"},
			// Syscall monitor tables
			{Name: "noisy_processes_buffer"},
			{Name: "noisy_processes_fb"},
			{Name: "noisy_processes_bb"},
		},

		PerfMaps: []*manager.PerfMap{
			{
				Map: manager.Map{Name: "events"},
			},
			{
				Map: manager.Map{Name: "mountpoints_events"},
			},
		},
	}
}
