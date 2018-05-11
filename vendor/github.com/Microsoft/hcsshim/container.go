package hcsshim

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	// defaultTimeoutSeconds is the default time to wait for various operations.
	// - Waiting for async notifications from HCS
	// - Waiting for processes to launch through
	// - Waiting to copy data to/from a launched processes stdio pipes.
	// This can be overridden through HCS_TIMEOUT_SECONDS
	defaultTimeoutSeconds = time.Second * 60 * 4

	// logDataByteCount is for an advanced debugging technique to allow
	// data read/written to a processes stdio channels hex-dumped to the
	// log when running at debug level or higher. It is controlled through
	// the environment variable HCSSHIM_LOG_DATA_BYTE_COUNT
	logDataByteCount int64

	// createContainerAdditionalJSON is read from the environment at initialisation
	// time. It allows an environment variable to define additional JSON which
	// is merged in the CreateContainer call to HCS. It is controlled through
	// HCSSHIM_CREATECONTAINER_ADDITIONALJSON
	createContainerAdditionalJSON string
)

const (
	statisticsQuery        = `{ "PropertyTypes" : ["Statistics"]}`
	processListQuery       = `{ "PropertyTypes" : ["ProcessList"]}`
	mappedVirtualDiskQuery = `{ "PropertyTypes" : ["MappedVirtualDisk"]}`
)

type vsmbShare struct {
	refCount uint32
	guid     string
}

type container struct {
	handleLock     sync.RWMutex
	handle         hcsSystem
	id             string
	callbackNumber uintptr
	schemaVersion  SchemaVersion
	vsmbShares     struct {
		sync.Mutex
		shares map[string]vsmbShare
	}
	scsiLocations struct {
		sync.Mutex
		hostPath [4][64]string // Hyper-V supports 4 controllers, 64 slots per controller
	}
}

func init() {
	createContainerAdditionalJSON = os.Getenv("HCSSHIM_CREATECONTAINER_ADDITIONALJSON")

	bytes := os.Getenv("HCSSHIM_LOG_DATA_BYTE_COUNT")
	if len(bytes) > 0 {
		u, err := strconv.ParseUint(bytes, 10, 32)
		if err == nil {
			logDataByteCount = int64(u)
		}
	}

	envTimeout := os.Getenv("HCSSHIM_TIMEOUT_SECONDS")
	if len(envTimeout) > 0 {
		e, err := strconv.Atoi(envTimeout)
		if err == nil && e > 0 {
			defaultTimeoutSeconds = time.Second * time.Duration(e)
		}
	}
}

// TODO This was in libcontainerd. Update this comment.

// Create is the entrypoint to create a container from a spec.
// Table below shows the fields required for HCS JSON calling parameters,
// where if not populated, is omitted.
// +-----------------+--------------------------------------------+---------------------------------------------------+
// |                 | Isolation=Process                          | Isolation=Hyper-V                                 |
// +-----------------+--------------------------------------------+---------------------------------------------------+
// | VolumePath      | \\?\\Volume{GUIDa}                         |                                                   |
// | LayerFolderPath | %root%\windowsfilter\containerID           |                                                   |
// | Layers[]        | ID=GUIDb;Path=%root%\windowsfilter\layerID | ID=GUIDb;Path=%root%\windowsfilter\layerID        |
// | HvRuntime       |                                            | ImagePath=%root%\BaseLayerID\UtilityVM            |
// +-----------------+--------------------------------------------+---------------------------------------------------+
//
// Isolation=Process example:
//
// {
//	"SystemType": "Container",
//	"Name": "5e0055c814a6005b8e57ac59f9a522066e0af12b48b3c26a9416e23907698776",
//	"Owner": "docker",
//	"VolumePath": "\\\\\\\\?\\\\Volume{66d1ef4c-7a00-11e6-8948-00155ddbef9d}",
//	"IgnoreFlushesDuringBoot": true,
//	"LayerFolderPath": "C:\\\\control\\\\windowsfilter\\\\5e0055c814a6005b8e57ac59f9a522066e0af12b48b3c26a9416e23907698776",
//	"Layers": [{
//		"ID": "18955d65-d45a-557b-bf1c-49d6dfefc526",
//		"Path": "C:\\\\control\\\\windowsfilter\\\\65bf96e5760a09edf1790cb229e2dfb2dbd0fcdc0bf7451bae099106bfbfea0c"
//	}],
//	"HostName": "5e0055c814a6",
//	"MappedDirectories": [],
//	"HvPartition": false,
//	"EndpointList": ["eef2649d-bb17-4d53-9937-295a8efe6f2c"],
//}
//
// Isolation=Hyper-V example:
//
//{
//	"SystemType": "Container",
//	"Name": "475c2c58933b72687a88a441e7e0ca4bd72d76413c5f9d5031fee83b98f6045d",
//	"Owner": "docker",
//	"IgnoreFlushesDuringBoot": true,
//	"Layers": [{
//		"ID": "18955d65-d45a-557b-bf1c-49d6dfefc526",
//		"Path": "C:\\\\control\\\\windowsfilter\\\\65bf96e5760a09edf1790cb229e2dfb2dbd0fcdc0bf7451bae099106bfbfea0c"
//	}],
//	"HostName": "475c2c58933b",
//	"MappedDirectories": [],
//	"HvPartition": true,
//	"EndpointList": ["e1bb1e61-d56f-405e-b75d-fd520cefa0cb"],
//	"DNSSearchList": "a.com,b.com,c.com",
//	"HvRuntime": {
//		"ImagePath": "C:\\\\control\\\\windowsfilter\\\\65bf96e5760a09edf1790cb229e2dfb2dbd0fcdc0bf7451bae099106bfbfea0c\\\\UtilityVM"
//	},
//}

// CreateContainer creates a new container with the given configuration but does not start it.
// This is a 'legacy' API used in RS1..RS4 for the v1 Schema
func CreateContainer(id string, c *ContainerConfig) (Container, error) {
	configurationb, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return createContainer(id, string(configurationb), SchemaV10())
}

func createContainer(id string, configurationJSON string, schemaVersion *SchemaVersion) (Container, error) {
	operation := "CreateContainer"
	title := "hcsshim::" + operation

	container := &container{
		id:            id,
		schemaVersion: *schemaVersion,
	}
	logrus.Debugf(title+" id=%s config=%s", id, configurationJSON)

	// Merge any additional JSON.
	if createContainerAdditionalJSON != "" {
		configurationMap := map[string]interface{}{}
		if err := json.Unmarshal([]byte(configurationJSON), &configurationMap); err != nil {
			return nil, fmt.Errorf("failed to unmarshal %s: %s", configurationJSON, err)
		}

		additionalMap := map[string]interface{}{}
		if err := json.Unmarshal([]byte(createContainerAdditionalJSON), &additionalMap); err != nil {
			return nil, fmt.Errorf("failed to unmarshal %s: %s", createContainerAdditionalJSON, err)
		}

		mergedMap := mergeMaps(additionalMap, configurationMap)
		mergedJSON, err := json.Marshal(mergedMap)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal merged configuration map %+v: %s", mergedMap, err)
		}

		configurationJSON = string(mergedJSON)
		logrus.Debugf(title+" id=%s merged config=%s", id, configurationJSON)
	}

	var (
		resultp  *uint16
		identity syscall.Handle
	)
	createError := hcsCreateComputeSystem(id, configurationJSON, identity, &container.handle, &resultp)

	if createError == nil || IsPending(createError) {
		if err := container.registerCallback(); err != nil {
			// Terminate the container if it still exists. We're okay to ignore a failure here.
			container.Terminate()
			return nil, makeContainerError(container, operation, nil, "", err)
		}
	}

	err := processAsyncHcsResult(createError, resultp, container.callbackNumber, hcsNotificationSystemCreateCompleted, &defaultTimeoutSeconds)
	if err != nil {
		if err == ErrTimeout {
			// Terminate the container if it still exists. We're okay to ignore a failure here.
			container.Terminate()
		}
		return nil, makeContainerError(container, operation, nil, configurationJSON, err)
	}

	logrus.Debugf(title+" succeeded id=%s handle=%d", id, container.handle)
	return container, nil
}

// mergeMaps recursively merges map `fromMap` into map `ToMap`. Any pre-existing values
// in ToMap are overwritten. Values in fromMap are added to ToMap.
// From http://stackoverflow.com/questions/40491438/merging-two-json-strings-in-golang
func mergeMaps(fromMap, ToMap interface{}) interface{} {
	switch fromMap := fromMap.(type) {
	case map[string]interface{}:
		ToMap, ok := ToMap.(map[string]interface{})
		if !ok {
			return fromMap
		}
		for keyToMap, valueToMap := range ToMap {
			if valueFromMap, ok := fromMap[keyToMap]; ok {
				fromMap[keyToMap] = mergeMaps(valueFromMap, valueToMap)
			} else {
				fromMap[keyToMap] = valueToMap
			}
		}
	case nil:
		// merge(nil, map[string]interface{...}) -> map[string]interface{...}
		ToMap, ok := ToMap.(map[string]interface{})
		if ok {
			return ToMap
		}
	}
	return fromMap
}

// OpenContainer opens an existing container by ID.
func OpenContainer(id string) (Container, error) {
	operation := "OpenContainer"
	title := "hcsshim::" + operation
	logrus.Debugf(title+" id=%s", id)

	container := &container{
		id: id,
	}

	var (
		handle  hcsSystem
		resultp *uint16
	)
	err := hcsOpenComputeSystem(id, &handle, &resultp)
	re := processHcsResult(resultp)
	if err != nil {
		return nil, makeContainerError(container, operation, re, "", err)
	}

	container.handle = handle

	if err := container.registerCallback(); err != nil {
		return nil, makeContainerError(container, operation, nil, "", err)
	}

	logrus.Debugf(title+" succeeded id=%s handle=%d", id, handle)
	return container, nil
}

// GetContainers gets a list of the containers on the system that match the query
func GetContainers(q ComputeSystemQuery) ([]ContainerProperties, error) {
	operation := "GetContainers"
	title := "hcsshim::" + operation

	queryb, err := json.Marshal(q)
	if err != nil {
		return nil, err
	}

	query := string(queryb)
	logrus.Debugf(title+" query=%s", query)

	var (
		resultp         *uint16
		computeSystemsp *uint16
	)
	err = hcsEnumerateComputeSystems(query, &computeSystemsp, &resultp)
	//re := processHcsResult(resultp)
	if err != nil {
		// TODO: makeContainerError. At least do something with the extended result
		return nil, err
	}

	if computeSystemsp == nil {
		return nil, ErrUnexpectedValue
	}
	computeSystemsRaw := convertAndFreeCoTaskMemBytes(computeSystemsp)
	computeSystems := []ContainerProperties{}
	if err := json.Unmarshal(computeSystemsRaw, &computeSystems); err != nil {
		return nil, err
	}

	logrus.Debugf(title + " succeeded")
	return computeSystems, nil
}

// Start synchronously starts the container.
func (container *container) Start() error {
	container.handleLock.RLock()
	defer container.handleLock.RUnlock()
	operation := "Start"
	title := "hcsshim::Container::" + operation
	logrus.Debugf(title+" id=%s", container.id)

	if container.handle == 0 {
		return makeContainerError(container, operation, nil, "", ErrAlreadyClosed)
	}

	var resultp *uint16
	err := hcsStartComputeSystem(container.handle, "", &resultp)
	err = processAsyncHcsResult(err, resultp, container.callbackNumber, hcsNotificationSystemStartCompleted, &defaultTimeoutSeconds)
	if err != nil {
		return makeContainerError(container, operation, nil, "", err)
	}

	logrus.Debugf(title+" succeeded id=%s", container.id)
	return nil
}

// Shutdown requests a container shutdown, if IsPending() on the error returned is true,
// it may not actually be shut down until Wait() succeeds.
func (container *container) Shutdown() error {
	container.handleLock.RLock()
	defer container.handleLock.RUnlock()
	operation := "Shutdown"
	title := "hcsshim::Container::" + operation
	logrus.Debugf(title+" id=%s", container.id)

	if container.handle == 0 {
		return makeContainerError(container, operation, nil, "", ErrAlreadyClosed)
	}

	var resultp *uint16
	err := hcsShutdownComputeSystem(container.handle, "", &resultp)
	re := processHcsResult(resultp)
	if err != nil {
		return makeContainerError(container, operation, re, "", err)
	}

	logrus.Debugf(title+" succeeded id=%s", container.id)
	return nil
}

// Terminate requests a container terminate, if IsPending() on the error returned is true,
// it may not actually be shut down until Wait() succeeds.
func (container *container) Terminate() error {
	container.handleLock.RLock()
	defer container.handleLock.RUnlock()
	operation := "Terminate"
	title := "hcsshim::Container::" + operation
	logrus.Debugf(title+" id=%s", container.id)

	if container.handle == 0 {
		return makeContainerError(container, operation, nil, "", ErrAlreadyClosed)
	}

	var resultp *uint16
	err := hcsTerminateComputeSystem(container.handle, "", &resultp)
	re := processHcsResult(resultp)
	if err != nil {
		return makeContainerError(container, operation, re, "", err)
	}

	logrus.Debugf(title+" succeeded id=%s", container.id)
	return nil
}

// Wait synchronously waits for the container to shutdown or terminate.
func (container *container) Wait() error {
	operation := "Wait"
	title := "hcsshim::Container::" + operation
	logrus.Debugf(title+" id=%s", container.id)

	err := waitForNotification(container.callbackNumber, hcsNotificationSystemExited, nil)
	if err != nil {
		return makeContainerError(container, operation, nil, "", err)
	}

	logrus.Debugf(title+" succeeded id=%s", container.id)
	return nil
}

// WaitTimeout synchronously waits for the container to terminate or the duration to elapse.
// If the timeout expires, IsTimeout(err) == true
func (container *container) WaitTimeout(timeout time.Duration) error {
	operation := "WaitTimeout"
	title := "hcsshim::Container::" + operation
	logrus.Debugf(title+" id=%s", container.id)

	err := waitForNotification(container.callbackNumber, hcsNotificationSystemExited, &timeout)
	if err != nil {
		return makeContainerError(container, operation, nil, "", err)
	}

	logrus.Debugf(title+" succeeded id=%s", container.id)
	return nil
}

func (container *container) properties(query string) (*ContainerProperties, error) {
	var (
		resultp     *uint16
		propertiesp *uint16
	)
	err := hcsGetComputeSystemProperties(container.handle, query, &propertiesp, &resultp)
	//re := processHcsResult(resultp)
	if err != nil {
		// TODO: Do something with the extended result
		return nil, err
	}

	if propertiesp == nil {
		return nil, ErrUnexpectedValue
	}
	propertiesRaw := convertAndFreeCoTaskMemBytes(propertiesp)
	properties := &ContainerProperties{}
	if err := json.Unmarshal(propertiesRaw, properties); err != nil {
		return nil, err
	}
	return properties, nil
}

// HasPendingUpdates is a legacy API and a no-op. It never worked, and has
// since been removed from Windows. It should not be called.
func (container *container) HasPendingUpdates() (bool, error) {
	logrus.Warnf("hcsshim::HasPendingUpdates is a no-op")
	return false, nil
}

// Statistics returns statistics for the container
func (container *container) Statistics() (Statistics, error) {
	container.handleLock.RLock()
	defer container.handleLock.RUnlock()
	operation := "Statistics"
	title := "hcsshim::Container::" + operation
	logrus.Debugf(title+" id=%s", container.id)

	if container.handle == 0 {
		return Statistics{}, makeContainerError(container, operation, nil, "", ErrAlreadyClosed)
	}

	properties, err := container.properties(statisticsQuery)
	if err != nil {
		return Statistics{}, makeContainerError(container, operation, nil, "", err)
	}

	logrus.Debugf(title+" succeeded id=%s", container.id)
	return properties.Statistics, nil
}

// ProcessList returns an array of ProcessListItems for the container
func (container *container) ProcessList() ([]ProcessListItem, error) {
	container.handleLock.RLock()
	defer container.handleLock.RUnlock()
	operation := "ProcessList"
	title := "hcsshim::Container::" + operation
	logrus.Debugf(title+" id=%s", container.id)

	if container.handle == 0 {
		return nil, makeContainerError(container, operation, nil, "", ErrAlreadyClosed)
	}

	properties, err := container.properties(processListQuery)
	if err != nil {
		return nil, makeContainerError(container, operation, nil, "", err)
	}

	logrus.Debugf(title+" succeeded id=%s", container.id)
	return properties.ProcessList, nil
}

// MappedVirtualDisks returns a map of the controllers and the disks mapped
// to a container.
//
// Example of JSON returned by the query.
//{
//   "Id":"1126e8d7d279c707a666972a15976371d365eaf622c02cea2c442b84f6f550a3_svm",
//   "SystemType":"Container",
//   "RuntimeOsType":"Linux",
//   "RuntimeId":"00000000-0000-0000-0000-000000000000",
//   "State":"Running",
//   "MappedVirtualDiskControllers":{
//      "0":{
//         "MappedVirtualDisks":{
//            "2":{
//               "HostPath":"C:\\lcow\\lcow\\scratch\\1126e8d7d279c707a666972a15976371d365eaf622c02cea2c442b84f6f550a3.vhdx",
//               "ContainerPath":"/mnt/gcs/LinuxServiceVM/scratch",
//               "Lun":2,
//               "CreateInUtilityVM":true
//            },
//            "3":{
//               "HostPath":"C:\\lcow\\lcow\\1126e8d7d279c707a666972a15976371d365eaf622c02cea2c442b84f6f550a3\\sandbox.vhdx",
//               "Lun":3,
//               "CreateInUtilityVM":true,
//               "AttachOnly":true
//            }
//         }
//      }
//   }
//}
func (container *container) MappedVirtualDisks() (map[int]MappedVirtualDiskController, error) {
	container.handleLock.RLock()
	defer container.handleLock.RUnlock()
	operation := "MappedVirtualDiskList"
	title := "hcsshim::Container::" + operation
	logrus.Debugf(title+" id=%s", container.id)

	if container.handle == 0 {
		return nil, makeContainerError(container, operation, nil, "", ErrAlreadyClosed)
	}

	properties, err := container.properties(mappedVirtualDiskQuery)
	if err != nil {
		return nil, makeContainerError(container, operation, nil, "", err)
	}

	logrus.Debugf(title+" succeeded id=%s", container.id)
	logrus.Debugf("%+v", properties.MappedVirtualDiskControllers) // TODO Hack hack temporary debugging LCOW v1
	return properties.MappedVirtualDiskControllers, nil
}

// Pause pauses the execution of the container. This feature is not enabled in TP5.
func (container *container) Pause() error {
	container.handleLock.RLock()
	defer container.handleLock.RUnlock()
	operation := "Pause"
	title := "hcsshim::Container::" + operation
	logrus.Debugf(title+" id=%s", container.id)

	if container.handle == 0 {
		return makeContainerError(container, operation, nil, "", ErrAlreadyClosed)
	}

	var resultp *uint16
	err := hcsPauseComputeSystem(container.handle, "", &resultp)
	err = processAsyncHcsResult(err, resultp, container.callbackNumber, hcsNotificationSystemPauseCompleted, &defaultTimeoutSeconds)
	if err != nil {
		return makeContainerError(container, operation, nil, "", err)
	}

	logrus.Debugf(title+" succeeded id=%s", container.id)
	return nil
}

// Resume resumes the execution of the container. This feature is not enabled in TP5.
func (container *container) Resume() error {
	container.handleLock.RLock()
	defer container.handleLock.RUnlock()
	operation := "Resume"
	title := "hcsshim::Container::" + operation
	logrus.Debugf(title+" id=%s", container.id)

	if container.handle == 0 {
		return makeContainerError(container, operation, nil, "", ErrAlreadyClosed)
	}

	var resultp *uint16
	err := hcsResumeComputeSystem(container.handle, "", &resultp)
	err = processAsyncHcsResult(err, resultp, container.callbackNumber, hcsNotificationSystemResumeCompleted, &defaultTimeoutSeconds)
	if err != nil {
		return makeContainerError(container, operation, nil, "", err)
	}

	logrus.Debugf(title+" succeeded id=%s", container.id)
	return nil
}

// CreateProcess launches a new process. It can launch both in a container,
// and inside a utility VM. It is the responsibility of the caller to call
// Close() on the process returned.
func (container *container) CreateProcess(c *ProcessConfig) (Process, error) {
	container.handleLock.RLock()
	defer container.handleLock.RUnlock()
	operation := "CreateProcess"
	title := "hcsshim::Container::" + operation
	var (
		processInfo   hcsProcessInformation
		processHandle hcsProcess
		resultp       *uint16
	)

	if container.handle == 0 {
		return nil, makeContainerError(container, operation, nil, "", ErrAlreadyClosed)
	}

	// If we are not emulating a console, ignore any console size passed to us
	if !c.EmulateConsole {
		c.ConsoleSize[0] = 0
		c.ConsoleSize[1] = 0
	}

	configurationb, err := json.Marshal(c)
	if err != nil {
		return nil, makeContainerError(container, operation, nil, "", err)
	}

	configuration := string(configurationb)
	logrus.Debugf(title+" id=%s config=%s", container.id, configuration)

	err = hcsCreateProcess(container.handle, configuration, &processInfo, &processHandle, &resultp)
	re := processHcsResult(resultp)
	if err != nil {
		return nil, makeContainerError(container, operation, re, configuration, err)
	}

	process := &process{
		handle:    processHandle,
		processID: int(processInfo.ProcessId),
		container: container,
		cachedPipes: &cachedPipes{
			stdIn:  processInfo.StdInput,
			stdOut: processInfo.StdOutput,
			stdErr: processInfo.StdError,
		},
	}

	if err := process.registerCallback(); err != nil {
		return nil, makeContainerError(container, operation, nil, "", err)
	}

	logrus.Debugf(title+" succeeded id=%s processid=%d", container.id, process.processID)
	return process, nil
}

// OpenProcess gets an interface to an existing process within the container.
func (container *container) OpenProcess(pid int) (Process, error) {
	container.handleLock.RLock()
	defer container.handleLock.RUnlock()
	operation := "OpenProcess"
	title := "hcsshim::Container::" + operation
	logrus.Debugf(title+" id=%s, processid=%d", container.id, pid)
	var (
		processHandle hcsProcess
		resultp       *uint16
	)

	if container.handle == 0 {
		return nil, makeContainerError(container, operation, nil, "", ErrAlreadyClosed)
	}

	err := hcsOpenProcess(container.handle, uint32(pid), &processHandle, &resultp)
	re := processHcsResult(resultp)
	if err != nil {
		return nil, makeContainerError(container, operation, re, "", err)
	}

	process := &process{
		handle:    processHandle,
		processID: pid,
		container: container,
	}

	if err := process.registerCallback(); err != nil {
		return nil, makeContainerError(container, operation, nil, "", err)
	}

	logrus.Debugf(title+" succeeded id=%s processid=%s", container.id, process.processID)
	return process, nil
}

// Close cleans up any state associated with the container but does not terminate or wait for it.
func (container *container) Close() error {
	container.handleLock.Lock()
	defer container.handleLock.Unlock()
	operation := "Close"
	title := "hcsshim::Container::" + operation
	logrus.Debugf(title+" id=%s", container.id)

	// Don't double free this
	if container.handle == 0 {
		return nil
	}

	if err := container.unregisterCallback(); err != nil {
		return makeContainerError(container, operation, nil, "", err)
	}

	if err := hcsCloseComputeSystem(container.handle); err != nil {
		return makeContainerError(container, operation, nil, "", err)
	}

	container.handle = 0

	logrus.Debugf(title+" succeeded id=%s", container.id)
	return nil
}

func (container *container) registerCallback() error {
	context := &notifcationWatcherContext{
		channels: newChannels(),
	}

	callbackMapLock.Lock()
	callbackNumber := nextCallback
	nextCallback++
	callbackMap[callbackNumber] = context
	callbackMapLock.Unlock()

	var callbackHandle hcsCallback
	err := hcsRegisterComputeSystemCallback(container.handle, notificationWatcherCallback, callbackNumber, &callbackHandle)
	if err != nil {
		return err
	}
	context.handle = callbackHandle
	container.callbackNumber = callbackNumber

	return nil
}

func (container *container) unregisterCallback() error {
	callbackNumber := container.callbackNumber

	callbackMapLock.RLock()
	context := callbackMap[callbackNumber]
	callbackMapLock.RUnlock()

	if context == nil {
		return nil
	}

	handle := context.handle

	if handle == 0 {
		return nil
	}

	// hcsUnregisterComputeSystemCallback has its own syncronization
	// to wait for all callbacks to complete. We must NOT hold the callbackMapLock.
	err := hcsUnregisterComputeSystemCallback(handle)
	if err != nil {
		return err
	}

	closeChannels(context.channels)

	callbackMapLock.Lock()
	callbackMap[callbackNumber] = nil
	callbackMapLock.Unlock()

	handle = 0

	return nil
}

// Modifies the System by sending a request to HCS
func (container *container) Modify(config interface{}) error {
	container.handleLock.RLock()
	defer container.handleLock.RUnlock()
	operation := "Modify"
	title := "hcsshim::Container::" + operation

	if container.handle == 0 {
		return makeContainerError(container, operation, nil, "", ErrAlreadyClosed)
	}

	requestJSON, err := json.Marshal(config)
	if err != nil {
		return err
	}

	requestString := string(requestJSON)
	logrus.Debugf(title+" id=%s request=%s", container.id, requestString)

	var resultp *uint16
	err = hcsModifyComputeSystem(container.handle, requestString, &resultp)
	re := processHcsResult(resultp)
	if err != nil {
		err = makeContainerError(container, operation, re, requestString, err)
		return err
	}
	logrus.Debugf(title+" succeeded id=%s", container.id)
	return nil
}

// ID returns the ID of a container
func (container *container) ID() string {
	return container.id
}

// SchemaVersion returns the schema version for a container
func (container *container) SchemaVersion() *SchemaVersion {
	return &container.schemaVersion
}
