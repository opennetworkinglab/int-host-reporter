// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package loader

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/opennetworkinglab/int-host-reporter/pkg/common"
	log "github.com/sirupsen/logrus"
	"io"
	"os/exec"
)

const (
	compiler = "clang-10"
	linker   = "llc-10"
)

var (
	standardCFlags = []string{"-O2", "-target", "bpf",
		fmt.Sprintf("-D__NR_CPUS__=%d", common.GetNumPossibleCPUs()),
	}

	standardLDFlags = []string{"-march=bpf", "-filetype=obj"}
)

type CompileOptions struct {
	Debug bool
}

func prepareCmdPipes(cmd *exec.Cmd) (io.ReadCloser, io.ReadCloser, error) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to get stdout pipe: %s", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		stdout.Close()
		return nil, nil, fmt.Errorf("Failed to get stderr pipe: %s", err)
	}

	return stdout, stderr, nil
}

func CompileDatapath(options CompileOptions) error {
	compilerArgs := make([]string, 0, 16)

	versionCmd := exec.Command(compiler, "--version")
	compilerVersion, err := versionCmd.CombinedOutput()
	if err != nil {
		return err
	}
	versionCmd = exec.Command(linker, "--version")
	linkerVersion, err := versionCmd.CombinedOutput()
	if err != nil {
		return err
	}

	log.WithFields(log.Fields{
		compiler: string(compilerVersion),
		linker:   string(linkerVersion),
	}).Debug("Compiling datapath")

	if options.Debug {
		compilerArgs = append(compilerArgs, "-DDEBUG")
	}
	compilerArgs = append(compilerArgs, "-emit-llvm")
	compilerArgs = append(compilerArgs, "-g")
	compilerArgs = append(compilerArgs, standardCFlags...)
	compilerArgs = append(compilerArgs, "-c", "bpf/int-datapath.c")
	compilerArgs = append(compilerArgs, "-o", "-")

	// Compilation is split between two exec calls. First clang generates
	// LLVM bitcode and then later llc compiles it to byte-code.
	log.WithFields(log.Fields{
		"target": compiler,
		"args":   compilerArgs,
	}).Debug("Launching compiler")

	compilerCmd := exec.Command(compiler, compilerArgs...)
	compilerStdout, compilerStderr, err := prepareCmdPipes(compilerCmd)
	if err != nil {
		return err
	}

	linkArgs := make([]string, 0, 8)
	linkArgs = append(linkArgs, standardLDFlags...)
	linkArgs = append(linkArgs, "-o", "/opt/out.o")

	log.WithFields(log.Fields{
		"target": linker,
		"args":   linkArgs,
	}).Debug("Launching linker")
	linkerCmd := exec.Command(linker, linkArgs...)
	linkerCmd.Stdin = compilerStdout
	if err := compilerCmd.Start(); err != nil {
		return fmt.Errorf("failed to start command %s: %s", compilerCmd.Args, err)
	}

	var compileOut []byte
	_, err = linkerCmd.CombinedOutput()
	if err == nil {
		compileOut, _ = io.ReadAll(compilerStderr)
		err = compilerCmd.Wait()
	}

	if err != nil {
		err = fmt.Errorf("failed to compile: %s", err)
		if compileOut != nil {
			scanner := bufio.NewScanner(bytes.NewReader(compileOut))
			for scanner.Scan() {
				log.Debug(scanner.Text())
			}
		}
		return err
	}

	log.Debug("Datapath compiled successfully")
	return nil
}
