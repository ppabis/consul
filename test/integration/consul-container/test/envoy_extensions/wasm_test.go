package envoy_extensions

import (
	"context"
	sha2562 "crypto/sha256"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/hashicorp/consul/api"
	libassert "github.com/hashicorp/consul/test/integration/consul-container/libs/assert"
	libcluster "github.com/hashicorp/consul/test/integration/consul-container/libs/cluster"
	libservice "github.com/hashicorp/consul/test/integration/consul-container/libs/service"
	"github.com/hashicorp/consul/test/integration/consul-container/libs/topology"
)

// TestWASMRemote Summary
// This test ensures that a WASM extension can be loaded from a remote file server then executed.
// It uses the same basic WASM extension as the TestWASMLocal test which adds the header
// "x-test:true" to the response.
func TestWASMRemote(t *testing.T) {
	t.Parallel()

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	hostWASMDir := fmt.Sprintf("%s/testdata/wasm_test_files", cwd)

	buildWASM(t, hostWASMDir)

	cluster, _, _ := topology.NewCluster(t, &topology.ClusterConfig{
		NumServers:                1,
		NumClients:                1,
		ApplyDefaultProxySettings: true,
		BuildOpts: &libcluster.BuildOptions{
			Datacenter:             "dc1",
			InjectAutoEncryption:   true,
			InjectGossipEncryption: true,
		},
	})

	clientService := createServices(t, cluster)
	_, port := clientService.GetAddr()
	_, adminPort := clientService.GetAdminAddr()

	libassert.AssertUpstreamEndpointStatus(t, adminPort, "static-server.default", "HEALTHY", 1)
	libassert.GetEnvoyListenerTCPFilters(t, adminPort)

	libassert.AssertContainerState(t, clientService, "running")
	libassert.AssertFortioName(t, fmt.Sprintf("http://localhost:%d", port), "static-server", "")

	// Check header not present
	c1 := cleanhttp.DefaultClient()
	res, err := c1.Get(fmt.Sprintf("http://localhost:%d", port))
	if err != nil {
		t.Fatal(err)
	}

	// check that header DOES NOT exist before wasm applied
	if _, ok := res.Header["x-test"]; ok {
		t.Fatal("unexpected test header present before WASM applied")
	}

	// Create Nginx file server
	uri := buildNginxFileServer(t,
		// conf file
		testcontainers.ContainerFile{
			HostFilePath:      fmt.Sprintf("%s/nginx.conf", hostWASMDir),
			ContainerFilePath: "/etc/nginx/conf.d/wasm.conf",
			FileMode:          777,
		},
		// extra files loaded after startup
		testcontainers.ContainerFile{
			HostFilePath:      fmt.Sprintf("%s/wasm_add_header.go.wasm", hostWASMDir),
			ContainerFilePath: "/usr/share/nginx/html/wasm_add_header.wasm",
			FileMode:          777,
		})

	// wire up the wasm filter
	consul := cluster.APIClient(0)
	defaults := api.ServiceConfigEntry{
		Kind:     api.ServiceDefaults,
		Name:     "static-server",
		Protocol: "http",
		EnvoyExtensions: []api.EnvoyExtension{{
			Name: "builtin/wasm",
			Arguments: map[string]any{
				"Protocol":     "http",
				"ListenerType": "inbound",
				"PluginConfig": map[string]any{
					"VmConfig": map[string]any{
						"Code": map[string]any{
							"Remote": map[string]any{
								"HttpURI": map[string]any{
									"Service": map[string]any{
										"Name": "nginx-fileserver",
									},
									"URI": fmt.Sprintf("%s/wasm_add_header.wasm", uri),
								},
								"SHA256": sha256(t, fmt.Sprintf("%s/wasm_add_header.go.wasm", hostWASMDir)),
							},
						},
						"Configuration": "plugin configuration",
					},
				},
			},
		}},
	}

	_, _, err = consul.ConfigEntries().Set(&defaults, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Check that header is present after wasm applied
	c2 := cleanhttp.DefaultClient()

	fail := true
	for i := range [3]int{} {
		res2, err := c2.Get(fmt.Sprintf("http://localhost:%d", port))
		if err != nil {
			t.Fatal(err)
		}

		if key := res2.Header.Get("x-test"); key != "" {
			fmt.Printf("attempt %d: test header missing after WASM applied/n", i)
		} else {
			fail = false
			break
		}

		time.Sleep(time.Second)
	}

	if fail {
		t.Fatal(":(")
	}

}

// TestWASMLocal Summary
// This test ensures that a WASM extension with basic functionality is executed correctly.
// The extension takes an incoming request and adds the header "x-test:true"
func TestWASMLocal(t *testing.T) {
	t.Parallel()

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	hostWASMDir := fmt.Sprintf("%s/testdata/wasm_test_files", cwd)

	buildWASM(t, hostWASMDir)

	cluster, _, _ := topology.NewCluster(t, &topology.ClusterConfig{
		NumServers:                1,
		NumClients:                1,
		ApplyDefaultProxySettings: true,
		BuildOpts: &libcluster.BuildOptions{
			Datacenter:             "dc1",
			InjectAutoEncryption:   true,
			InjectGossipEncryption: true,
		},
	})

	clientService := createServices(t, cluster)
	_, port := clientService.GetAddr()
	_, adminPort := clientService.GetAdminAddr()

	libassert.AssertUpstreamEndpointStatus(t, adminPort, "static-server.default", "HEALTHY", 1)
	libassert.GetEnvoyListenerTCPFilters(t, adminPort)

	libassert.AssertContainerState(t, clientService, "running")
	libassert.AssertFortioName(t, fmt.Sprintf("http://localhost:%d", port), "static-server", "")

	// Check header not present
	c1 := cleanhttp.DefaultClient()
	res, err := c1.Get(fmt.Sprintf("http://localhost:%d", port))
	if err != nil {
		t.Fatal(err)
	}

	// check that header DOES NOT exist before wasm applied
	if _, ok := res.Header["x-test"]; ok {
		t.Fatal("unexpected test header present before WASM applied")
	}

	// wire up the wasm filter
	consul := cluster.APIClient(0)
	defaults := api.ServiceConfigEntry{
		Kind:     api.ServiceDefaults,
		Name:     "static-server",
		Protocol: "http",
		EnvoyExtensions: []api.EnvoyExtension{{
			Name: "builtin/wasm",
			Arguments: map[string]any{
				"Protocol":     "http",
				"ListenerType": "inbound",
				"PluginConfig": map[string]any{
					"VmConfig": map[string]any{
						"Code": map[string]any{
							"Local": map[string]any{
								"Filename": "/wasm_add_header.wasm",
							},
						},
						"Configuration": "plugin configuration",
					},
				},
			},
		}},
	}

	_, _, err = consul.ConfigEntries().Set(&defaults, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Check that header is present after wasm applied
	c2 := cleanhttp.DefaultClient()

	// The wasm plugin is not always applied on the first call. Retry and see if it is loaded.
	fail := true
	for i := range [5]int{} {
		res2, err := c2.Get(fmt.Sprintf("http://localhost:%d", port))
		if err != nil {
			t.Fatal(err)
		}

		if key := res2.Header.Get("x-test"); key != "" {
			fmt.Printf("attempt %d: test header missing after WASM applied/n", i)
		} else {
			fail = false
			break
		}

		time.Sleep(time.Second)
	}

	if fail {
		t.Fatal("test header not present")
	}

}

func createServices(t *testing.T, cluster *libcluster.Cluster) libservice.Service {
	node := cluster.Agents[0]
	client := node.GetClient()
	// Create a service and proxy instance
	serviceOpts := &libservice.ServiceOpts{
		Name:     libservice.StaticServerServiceName,
		ID:       "static-server",
		HTTPPort: 8080,
		GRPCPort: 8079,
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	hostWASMDir := fmt.Sprintf("%s/testdata/wasm_test_files", cwd)

	wasmFile := testcontainers.ContainerFile{
		HostFilePath:      fmt.Sprintf("%s/wasm_add_header.go.wasm", hostWASMDir),
		ContainerFilePath: "/wasm_add_header.wasm",
		FileMode:          777,
	}

	customFn := chain(
		copyFilesToContainer([]testcontainers.ContainerFile{wasmFile}),
		chownFiles([]testcontainers.ContainerFile{wasmFile}, "envoy", true),
	)

	// Create a service and proxy instance
	_, _, err = libservice.CreateAndRegisterStaticServerAndSidecar(node, serviceOpts, customFn)
	require.NoError(t, err)

	libassert.CatalogServiceExists(t, client, "static-server-sidecar-proxy", nil)
	libassert.CatalogServiceExists(t, client, libservice.StaticServerServiceName, nil)

	// Create a client proxy instance with the server as an upstream

	clientConnectProxy, err := libservice.CreateAndRegisterStaticClientSidecar(node, "", false, false, nil)
	require.NoError(t, err)

	libassert.CatalogServiceExists(t, client, "static-client-sidecar-proxy", nil)

	return clientConnectProxy
}

func buildWASM(t *testing.T, hostWASMDir string) {
	// check for matching lock file (hash of current wasm file)
	// if lock matches no need to rebuild, file up to date
	// if not, rebuild wasm file

	containerDir := "/home/tinygo"
	containerWASMFile := fmt.Sprintf("%s/wasm_add_header.go.wasm", containerDir)

	req := testcontainers.ContainerRequest{
		Image: "tinygo/tinygo:sha-598cb1e4ddce53d85600a1b7724ed39eea80e119",
		Name:  "wasm-build",
		// Keep container running after start
		Entrypoint: []string{
			"tail",
			"-f",
			"/dev/null",
		},
		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      fmt.Sprintf("%s/wasm_add_header.go", hostWASMDir),
				ContainerFilePath: fmt.Sprintf("%s/wasm_add_header.go", containerDir),
				FileMode:          777,
			},
			{
				HostFilePath:      fmt.Sprintf("%s/go.mod", hostWASMDir),
				ContainerFilePath: fmt.Sprintf("%s/go.mod", containerDir),
				FileMode:          777,
			},
			{
				HostFilePath:      fmt.Sprintf("%s/go.sum", hostWASMDir),
				ContainerFilePath: fmt.Sprintf("%s/go.sum", containerDir),
				FileMode:          777,
			},
		},
	}

	ctx := context.Background()

	buildC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          false,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = buildC.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// The testcontainers.ContainerFile does not honor the filemode set on the files for some reason
	// so we can just chown them to the default user on the image
	_, _, err = buildC.Exec(ctx, []string{
		"sudo",
		"chown",
		"tinygo",
		fmt.Sprintf("%s/wasm_add_header.go", containerDir),
		fmt.Sprintf("%s/go.mod", containerDir),
		fmt.Sprintf("%s/go.sum", containerDir),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = buildC.Exec(ctx, []string{
		"tinygo",
		"build",
		"-o",
		containerWASMFile,
		"-scheduler=none",
		"-target=wasi",
		fmt.Sprintf("%s/wasm_add_header.go", containerDir),
	})
	if err != nil {
		t.Fatal(err)
	}

	r, err := buildC.CopyFileFromContainer(ctx, containerWASMFile)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	f, err := os.Create(fmt.Sprintf("%s/wasm_add_header.go.wasm", hostWASMDir))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	_, err = io.Copy(f, r)
	if err != nil {
		t.Fatal(err)
	}

	defer buildC.Terminate(ctx)
}

func buildNginxFileServer(t *testing.T, conf testcontainers.ContainerFile, files ...testcontainers.ContainerFile) string {
	req := testcontainers.ContainerRequest{
		// nginx:stable
		Image:        "nginx@sha256:b07a5ab5292bd90c4271a55a44761899cc1b14814172cf7f186e3afb8bdbec28",
		Name:         "nginx-fileserver",
		ExposedPorts: []string{"80/tcp"},
		WaitingFor:   wait.ForHTTP("/"),
		LifecycleHooks: []testcontainers.ContainerLifecycleHooks{
			{
				PostStarts: []testcontainers.ContainerHook{
					func(ctx context.Context, c testcontainers.Container) error {
						_, _, err := c.Exec(ctx, []string{"mkdir", "-p", "/www/downloads"})
						if err != nil {
							return err
						}

						for _, f := range files {
							fBytes, err := os.ReadFile(f.HostFilePath)
							if err != nil {
								return err
							}
							err = c.CopyToContainer(ctx, fBytes, f.ContainerFilePath, f.FileMode)
							if err != nil {
								return err
							}

							_, _, err = c.Exec(ctx, []string{"chmod", "+r", f.ContainerFilePath})
							if err != nil {
								return err
							}
						}

						return err
					},
				},
			},
		},
		Files: []testcontainers.ContainerFile{conf},
	}

	ctx := context.Background()

	nginxC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          false,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = nginxC.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}

	ip, err := nginxC.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}

	mappedPort, err := nginxC.MappedPort(ctx, "80")
	if err != nil {
		t.Fatal(err)
	}

	return fmt.Sprintf("http://%s:%s", ip, mappedPort.Port())
}

func chain(fns ...func(testcontainers.ContainerRequest) testcontainers.ContainerRequest) func(testcontainers.ContainerRequest) testcontainers.ContainerRequest {
	return func(req testcontainers.ContainerRequest) testcontainers.ContainerRequest {
		for _, fn := range fns {
			req = fn(req)
		}

		return req
	}
}

func copyFilesToContainer(files []testcontainers.ContainerFile) func(testcontainers.ContainerRequest) testcontainers.ContainerRequest {
	return func(req testcontainers.ContainerRequest) testcontainers.ContainerRequest {
		req.Files = files
		return req
	}
}

func chownFiles(files []testcontainers.ContainerFile, user string, sudo bool) func(request testcontainers.ContainerRequest) testcontainers.ContainerRequest {
	return func(req testcontainers.ContainerRequest) testcontainers.ContainerRequest {
		req.LifecycleHooks = append(req.LifecycleHooks, testcontainers.ContainerLifecycleHooks{
			PostStarts: []testcontainers.ContainerHook{
				func(ctx context.Context, c testcontainers.Container) error {
					cmd := []string{}
					if sudo {
						cmd = append(cmd, "sudo")
					}

					cmd = append(cmd, "chown", user)

					for _, f := range files {
						cmd = append(cmd, f.ContainerFilePath)
					}

					_, _, err := c.Exec(ctx, cmd)
					return err
				},
			},
		})

		return req
	}
}

func sha256(t *testing.T, filepath string) string {
	f, err := os.Open(filepath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	h := sha2562.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}
