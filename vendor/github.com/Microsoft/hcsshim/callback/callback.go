// +build windows

package callback

import (
	"sync"
	"syscall"
)

var (
	nextCallback    uintptr
	callbackMap     = map[uintptr]*notifcationWatcherContext{}
	callbackMapLock = sync.RWMutex{}

	notificationWatcherCallback = syscall.NewCallback(notificationWatcher)
)

type notificationChannel chan error

type NotifcationWatcherContext struct {
	channels notificationChannels
	handle   hcsCallback
}

type notificationChannels map[hcsNotification]notificationChannel

func newChannels() notificationChannels {
	channels := make(notificationChannels)

	channels[hcsNotificationSystemExited] = make(notificationChannel, 1)
	channels[hcsNotificationSystemCreateCompleted] = make(notificationChannel, 1)
	channels[hcsNotificationSystemStartCompleted] = make(notificationChannel, 1)
	channels[hcsNotificationSystemPauseCompleted] = make(notificationChannel, 1)
	channels[hcsNotificationSystemResumeCompleted] = make(notificationChannel, 1)
	channels[hcsNotificationProcessExited] = make(notificationChannel, 1)
	channels[hcsNotificationServiceDisconnect] = make(notificationChannel, 1)
	return channels
}
func closeChannels(channels notificationChannels) {
	close(channels[hcsNotificationSystemExited])
	close(channels[hcsNotificationSystemCreateCompleted])
	close(channels[hcsNotificationSystemStartCompleted])
	close(channels[hcsNotificationSystemPauseCompleted])
	close(channels[hcsNotificationSystemResumeCompleted])
	close(channels[hcsNotificationProcessExited])
	close(channels[hcsNotificationServiceDisconnect])
}

func notificationWatcher(notificationType hcsNotification, callbackNumber uintptr, notificationStatus uintptr, notificationData *uint16) uintptr {
	var result error
	if int32(notificationStatus) < 0 {
		result = syscall.Errno(win32FromHresult(notificationStatus))
	}

	callbackMapLock.RLock()
	context := callbackMap[callbackNumber]
	callbackMapLock.RUnlock()

	if context == nil {
		return 0
	}

	context.channels[notificationType] <- result

	return 0
}

func registerCallback() (uintptr, error) {
	context := &notifcationWatcherContext{
		channels: newChannels(),
	}
	callbackMapLock.Lock()
	callbackNumber := nextCallback
	nextCallback++
	callbackMap[callbackNumber] = context
	callbackMapLock.Unlock()

	var callbackHandle hcsCallback
	err := hcsRegisterComputeSystemCallback(uvm.hcsHandle, notificationWatcherCallback, callbackNumber, &callbackHandle)
	if err != nil {
		return err
	}
	context.handle = callbackHandle

	return callbackNumber, nil
}

func unregisterCallback(uintptr callbackNumber) error {
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
