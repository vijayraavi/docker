package dockerfile // import "github.com/docker/docker/builder/dockerfile"

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/backend"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/builder"
	"github.com/docker/docker/image"
	"github.com/docker/docker/pkg/system"

	//	"github.com/docker/go-connections/nat"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"

	//	"github.com/moby/buildkit/frontend/dockerfile/shell"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func newBuilderWithMockBackend() *Builder {
	mockBackend := &MockBackend{}
	opts := &types.ImageBuildOptions{}
	ctx := context.Background()
	b := &Builder{
		options:       opts,
		docker:        mockBackend,
		Stdout:        new(bytes.Buffer),
		clientCtx:     ctx,
		disableCommit: true,
		imageSources: newImageSources(ctx, builderOptions{
			Options: opts,
			Backend: mockBackend,
		}),
		imageProber:      newImageProber(mockBackend, nil, false),
		containerManager: newContainerManager(mockBackend),
	}
	return b
}

func TestRunWithBuildArgs(t *testing.T) {
	b := newBuilderWithMockBackend()
	args := NewBuildArgs(make(map[string]*string))
	args.argsFromOptions["HTTP_PROXY"] = strPtr("FOO")
	b.disableCommit = false
	sb := newDispatchRequest(b, '`', nil, args, newStagesBuildResults())

	runConfig := &container.Config{}
	origCmd := strslice.StrSlice([]string{"cmd", "in", "from", "image"})

	var cmdWithShell strslice.StrSlice
	if runtime.GOOS == "windows" {
		cmdWithShell = strslice.StrSlice(append(getShell(runConfig, runtime.GOOS), []string{"echo", "foo"}...))
	} else {
		cmdWithShell = strslice.StrSlice(append(getShell(runConfig, runtime.GOOS), "echo foo"))
	}

	//cmdWithShell := strslice.StrSlice(append(getShell(runConfig, runtime.GOOS), system.EscapeArgs([]string{"echo foo"})...))
	for i, v := range cmdWithShell {
		fmt.Printf("cmdWithShell %d: %s\n", i, v)
	}
	envVars := []string{"|1", "one=two"}
	cachedCmd := strslice.StrSlice(append(envVars, system.EscapeArgs(cmdWithShell)...))

	fmt.Println("JJH: cachedCmd", cachedCmd)
	for i, v := range cachedCmd {
		fmt.Printf("xxx cachedCmd %d: %s\n", i, v)
	}

	//panic("What's up here?")

	imageCache := &mockImageCache{
		getCacheFunc: func(parentID string, cfg *container.Config) (string, error) {
			// Check the runConfig.Cmd sent to probeCache()

			for i, v := range cachedCmd {
				fmt.Printf("cachedCmd %d: %s\n", i, v)
			}
			for i, v := range cfg.Cmd {
				fmt.Printf("cfg.Cmd %d: %s\n", i, v)
			}

			assert.Check(t, is.DeepEqual(cachedCmd, cfg.Cmd)) // JJH FAILS HERE
			assert.Check(t, is.DeepEqual(strslice.StrSlice(nil), cfg.Entrypoint))
			return "", nil
		},
	}

	mockBackend := b.docker.(*MockBackend)
	mockBackend.makeImageCacheFunc = func(_ []string) builder.ImageCache {
		return imageCache
	}
	b.imageProber = newImageProber(mockBackend, nil, false)
	mockBackend.getImageFunc = func(_ string) (builder.Image, builder.ROLayer, error) {
		return &mockImage{
			id:     "abcdef",
			config: &container.Config{Cmd: origCmd},
		}, nil, nil
	}
	mockBackend.containerCreateFunc = func(config types.ContainerCreateConfig) (container.ContainerCreateCreatedBody, error) {
		// Check the runConfig.Cmd sent to create()
		// JJH HACK TEMPORARY assert.Check(t, is.DeepEqual(cmdWithShell, config.Config.Cmd)) // JJH FAILS HERE
		assert.Check(t, is.Contains(config.Config.Env, "one=two"))
		assert.Check(t, is.DeepEqual(strslice.StrSlice{""}, config.Config.Entrypoint))
		return container.ContainerCreateCreatedBody{ID: "12345"}, nil
	}
	mockBackend.commitFunc = func(cfg backend.CommitConfig) (image.ID, error) {
		// Check the runConfig.Cmd sent to commit()
		assert.Check(t, is.DeepEqual(origCmd, cfg.Config.Cmd))
		assert.Check(t, is.DeepEqual(cachedCmd, cfg.ContainerConfig.Cmd))
		assert.Check(t, is.DeepEqual(strslice.StrSlice(nil), cfg.Config.Entrypoint))
		return "", nil
	}
	from := &instructions.Stage{BaseName: "abcdef"}
	err := initializeStage(sb, from)
	assert.NilError(t, err)
	sb.state.buildArgs.AddArg("one", strPtr("two"))

	// This is hugely annoying. On the Windows side, it relies on the
	// RunCommand being able to emit String() and Name() (as implemented by
	// withNameAndCode). Unfortunately, that is internal, and no way to directly
	// set. However, we can fortunately use ParseInstruction in the instructions
	// package to parse a fake node which can be used as our instructions.RunCommand
	// instead.
	node := &parser.Node{
		Original: `RUN echo foo`,
		Value:    "run",
	}
	runint, err := instructions.ParseInstruction(node)
	assert.NilError(t, err)
	runinst := runint.(*instructions.RunCommand)
	runinst.CmdLine = strslice.StrSlice{"echo foo"}
	//runinst.CmdLine = strslice.StrSlice(system.EscapeArgs([]string{"echo foo"}))
	runinst.PrependShell = true

	//
	// run := &instructions.RunCommand{
	// 	ShellDependantCmdLine: instructions.ShellDependantCmdLine{
	// 		CmdLine:      strslice.StrSlice{"echo foo"},
	// 		PrependShell: true,
	// 	},
	// }

	assert.NilError(t, dispatch(sb, runinst))

	// Check that runConfig.Cmd has not been modified by run
	assert.Check(t, is.DeepEqual(origCmd, sb.state.runConfig.Cmd))
}
