/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package azure

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/Azure/azure-sdk-for-go/arm/compute"
	"github.com/Azure/azure-sdk-for-go/arm/disk"
	"github.com/Azure/azure-sdk-for-go/arm/resources/resources"
	"github.com/Azure/azure-sdk-for-go/arm/storage"
	"github.com/Azure/go-autorest/autorest"
	"github.com/stretchr/testify/mock"
)

// VirtualMachinesClientMock mocks for VirtualMachinesClient.
type VirtualMachinesClientMock struct {
	mock.Mock

	mutex     sync.Mutex
	FakeStore map[string]map[string]compute.VirtualMachine
}

// Get gets the VirtualMachine by VMName.
func (m *VirtualMachinesClientMock) Get(ctx context.Context, resourceGroupName string, VMName string, expand compute.InstanceViewTypes) (result compute.VirtualMachine, err error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if _, ok := m.FakeStore[resourceGroupName]; ok {
		if entity, ok := m.FakeStore[resourceGroupName][VMName]; ok {
			return entity, nil
		}
	}
	return result, autorest.DetailedError{
		StatusCode: http.StatusNotFound,
		Message:    "Not such VM",
	}
}

// List gets a lit of VirtualMachine inside the resource group.
func (m *VirtualMachinesClientMock) List(ctx context.Context, resourceGroupName string) (result []compute.VirtualMachine, err error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, ok := m.FakeStore[resourceGroupName]; ok {
		for _, v := range m.FakeStore[resourceGroupName] {
			result = append(result, v)
		}
	}

	return result, nil
}

// Delete deletes the VirtualMachine by VMName.
func (m *VirtualMachinesClientMock) Delete(ctx context.Context, resourceGroupName string, VMName string) (resp *http.Response, err error) {
	args := m.Called(resourceGroupName, VMName)
	return nil, args.Error(1)
}

// InterfacesClientMock mocks for InterfacesClient.
type InterfacesClientMock struct {
	mock.Mock
}

// Delete deletes the interface by networkInterfaceName.
func (m *InterfacesClientMock) Delete(resourceGroupName string, networkInterfaceName string, cancel <-chan struct{}) (<-chan autorest.Response, <-chan error) {
	args := m.Called(resourceGroupName, networkInterfaceName, cancel)
	errChan := make(chan error)
	go func() {
		errChan <- args.Error(1)
	}()
	return nil, errChan
}

// DisksClientMock mocks for DisksClient.
type DisksClientMock struct {
	mock.Mock
}

// Delete deletes the disk by diskName.
func (m *DisksClientMock) Delete(resourceGroupName string, diskName string, cancel <-chan struct{}) (<-chan disk.OperationStatusResponse, <-chan error) {
	args := m.Called(resourceGroupName, diskName, cancel)
	errChan := make(chan error)
	go func() {
		errChan <- args.Error(1)
	}()
	return nil, errChan
}

// AccountsClientMock mocks for AccountsClient.
type AccountsClientMock struct {
	mock.Mock
}

// ListKeys get a list of keys by accountName.
func (m *AccountsClientMock) ListKeys(resourceGroupName string, accountName string) (result storage.AccountListKeysResult, err error) {
	args := m.Called(resourceGroupName, accountName)
	return storage.AccountListKeysResult{}, args.Error(1)
}

// DeploymentsClientMock mocks for DeploymentsClient.
type DeploymentsClientMock struct {
	mock.Mock

	mutex     sync.Mutex
	FakeStore map[string]resources.DeploymentExtended
}

// Get gets the DeploymentExtended by deploymentName.
func (m *DeploymentsClientMock) Get(resourceGroupName string, deploymentName string) (result resources.DeploymentExtended, err error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	deploy, ok := m.FakeStore[deploymentName]
	if !ok {
		return result, fmt.Errorf("deployment not found")
	}

	return deploy, nil
}

// ExportTemplate exports the deployment's template.
func (m *DeploymentsClientMock) ExportTemplate(resourceGroupName string, deploymentName string) (result resources.DeploymentExportResult, err error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	deploy, ok := m.FakeStore[deploymentName]
	if !ok {
		return result, fmt.Errorf("deployment not found")
	}

	return resources.DeploymentExportResult{
		Template: deploy.Properties.Template,
	}, nil
}

// CreateOrUpdate creates or updates the Deployment.
func (m *DeploymentsClientMock) CreateOrUpdate(resourceGroupName string, deploymentName string, parameters resources.Deployment, cancel <-chan struct{}) (<-chan resources.DeploymentExtended, <-chan error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	errChan := make(chan error)
	go func() {
		errChan <- nil
	}()

	deploy, ok := m.FakeStore[deploymentName]
	if !ok {
		deploy = resources.DeploymentExtended{
			Properties: &resources.DeploymentPropertiesExtended{},
		}
		m.FakeStore[deploymentName] = deploy
	}

	deploy.Properties.Parameters = parameters.Properties.Parameters
	deploy.Properties.Template = parameters.Properties.Template
	return nil, errChan
}
