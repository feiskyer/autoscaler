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
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/arm/compute"
	"github.com/Azure/azure-sdk-for-go/arm/disk"
	"github.com/Azure/azure-sdk-for-go/arm/network"
	"github.com/Azure/azure-sdk-for-go/arm/resources/resources"
	"github.com/Azure/azure-sdk-for-go/arm/storage"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/golang/glog"

	"gopkg.in/gcfg.v1"
	"k8s.io/autoscaler/cluster-autoscaler/cloudprovider"
	"k8s.io/autoscaler/cluster-autoscaler/config/dynamic"
)

const (
	vmTypeVMSS     = "vmss"
	vmTypeStandard = "standard"

	scaleToZeroSupported = false
	refreshInterval      = 1 * time.Minute
)

// VirtualMachineScaleSetsClient defines needed functions for azure compute.VirtualMachineScaleSetsClient.
type VirtualMachineScaleSetsClient interface {
	Get(resourceGroupName string, vmScaleSetName string) (result compute.VirtualMachineScaleSet, err error)
	CreateOrUpdate(resourceGroupName string, name string, parameters compute.VirtualMachineScaleSet, cancel <-chan struct{}) (<-chan compute.VirtualMachineScaleSet, <-chan error)
	DeleteInstances(resourceGroupName string, vmScaleSetName string, vmInstanceIDs compute.VirtualMachineScaleSetVMInstanceRequiredIDs, cancel <-chan struct{}) (<-chan compute.OperationStatusResponse, <-chan error)
	List(resourceGroupName string) (result compute.VirtualMachineScaleSetListResult, err error)
	ListNextResults(lastResults compute.VirtualMachineScaleSetListResult) (result compute.VirtualMachineScaleSetListResult, err error)
}

// VirtualMachineScaleSetVMsClient defines needed functions for azure compute.VirtualMachineScaleSetVMsClient.
type VirtualMachineScaleSetVMsClient interface {
	List(resourceGroupName string, virtualMachineScaleSetName string, filter string, selectParameter string, expand string) (result compute.VirtualMachineScaleSetVMListResult, err error)
	ListNextResults(lastResults compute.VirtualMachineScaleSetVMListResult) (result compute.VirtualMachineScaleSetVMListResult, err error)
}

// VirtualMachinesClient defines needed functions for azure compute.VirtualMachinesClient.
type VirtualMachinesClient interface {
	Get(resourceGroupName string, VMName string, expand compute.InstanceViewTypes) (result compute.VirtualMachine, err error)
	Delete(resourceGroupName string, VMName string, cancel <-chan struct{}) (<-chan compute.OperationStatusResponse, <-chan error)
	List(resourceGroupName string) (result compute.VirtualMachineListResult, err error)
	ListNextResults(lastResults compute.VirtualMachineListResult) (result compute.VirtualMachineListResult, err error)
}

// InterfacesClient defines needed functions for azure network.InterfacesClient.
type InterfacesClient interface {
	Delete(resourceGroupName string, networkInterfaceName string, cancel <-chan struct{}) (<-chan autorest.Response, <-chan error)
}

// DeploymentsClient defines needed functions for azure network.DeploymentsClient.
type DeploymentsClient interface {
	Get(resourceGroupName string, deploymentName string) (result resources.DeploymentExtended, err error)
	ExportTemplate(resourceGroupName string, deploymentName string) (result resources.DeploymentExportResult, err error)
	CreateOrUpdate(resourceGroupName string, deploymentName string, parameters resources.Deployment, cancel <-chan struct{}) (<-chan resources.DeploymentExtended, <-chan error)
}

// DisksClient defines needed functions for azure disk.DisksClient.
type DisksClient interface {
	Delete(resourceGroupName string, diskName string, cancel <-chan struct{}) (<-chan disk.OperationStatusResponse, <-chan error)
}

// AccountsClient defines needed functions for azure storage.AccountsClient.
type AccountsClient interface {
	ListKeys(resourceGroupName string, accountName string) (result storage.AccountListKeysResult, err error)
}

// AzureManager handles Azure communication and data caching.
type AzureManager struct {
	config *Config
	env    azure.Environment

	virtualMachineScaleSetsClient   VirtualMachineScaleSetsClient
	virtualMachineScaleSetVMsClient VirtualMachineScaleSetVMsClient
	virtualMachinesClient           VirtualMachinesClient
	deploymentsClient               DeploymentsClient
	interfacesClient                InterfacesClient
	disksClient                     DisksClient
	storageAccountsClient           AccountsClient

	asgCache              *asgCache
	lastRefresh           time.Time
	asgAutoDiscoverySpecs []cloudprovider.LabelAutoDiscoveryConfig
	explicitlyConfigured  map[azureRef]bool
}

// Config holds the configuration parsed from the --cloud-config flag
type Config struct {
	Cloud          string `json:"cloud" yaml:"cloud"`
	TenantID       string `json:"tenantId" yaml:"tenantId"`
	SubscriptionID string `json:"subscriptionId" yaml:"subscriptionId"`
	ResourceGroup  string `json:"resourceGroup" yaml:"resourceGroup"`
	VMType         string `json:"vmType" yaml:"vmType"`

	AADClientID                 string `json:"aadClientId" yaml:"aadClientId"`
	AADClientSecret             string `json:"aadClientSecret" yaml:"aadClientSecret"`
	AADClientCertPath           string `json:"aadClientCertPath" yaml:"aadClientCertPath"`
	AADClientCertPassword       string `json:"aadClientCertPassword" yaml:"aadClientCertPassword"`
	UseManagedIdentityExtension bool   `json:"useManagedIdentityExtension" yaml:"useManagedIdentityExtension"`

	// Configs only for standard vmType (agent pools).
	Deployment           string `json:"deployment" yaml:"deployment"`
	APIServerPrivateKey  string `json:"apiServerPrivateKey" yaml:"apiServerPrivateKey"`
	CAPrivateKey         string `json:"caPrivateKey" yaml:"caPrivateKey"`
	ClientPrivateKey     string `json:"clientPrivateKey" yaml:"clientPrivateKey"`
	KubeConfigPrivateKey string `json:"kubeConfigPrivateKey" yaml:"kubeConfigPrivateKey"`
	WindowsAdminPassword string `json:"windowsAdminPassword" yaml:"windowsAdminPassword"`
	EtcdClientPrivateKey string `json:"etcdClientPrivateKey" yaml:"etcdClientPrivateKey"`
	EtcdServerPrivateKey string `json:"etcdServerPrivateKey" yaml:"etcdServerPrivateKey"`
}

// TrimSpace removes all leading and trailing white spaces.
func (c *Config) TrimSpace() {
	c.Cloud = strings.TrimSpace(c.Cloud)
	c.TenantID = strings.TrimSpace(c.TenantID)
	c.SubscriptionID = strings.TrimSpace(c.SubscriptionID)
	c.ResourceGroup = strings.TrimSpace(c.ResourceGroup)
	c.VMType = strings.TrimSpace(c.VMType)
	c.AADClientID = strings.TrimSpace(c.AADClientID)
	c.AADClientSecret = strings.TrimSpace(c.AADClientSecret)
	c.AADClientCertPath = strings.TrimSpace(c.AADClientCertPath)
	c.AADClientCertPassword = strings.TrimSpace(c.AADClientCertPassword)
	c.Deployment = strings.TrimSpace(c.Deployment)
	c.APIServerPrivateKey = strings.TrimSpace(c.APIServerPrivateKey)
	c.CAPrivateKey = strings.TrimSpace(c.CAPrivateKey)
	c.ClientPrivateKey = strings.TrimSpace(c.ClientPrivateKey)
	c.KubeConfigPrivateKey = strings.TrimSpace(c.KubeConfigPrivateKey)
	c.WindowsAdminPassword = strings.TrimSpace(c.WindowsAdminPassword)
	c.EtcdClientPrivateKey = strings.TrimSpace(c.EtcdClientPrivateKey)
	c.EtcdServerPrivateKey = strings.TrimSpace(c.EtcdServerPrivateKey)
}

// CreateAzureManager creates Azure Manager object to work with Azure.
func CreateAzureManager(configReader io.Reader, discoveryOpts cloudprovider.NodeGroupDiscoveryOptions) (*AzureManager, error) {
	var err error
	var cfg Config

	if configReader != nil {
		if err := gcfg.ReadInto(&cfg, configReader); err != nil {
			glog.Errorf("Couldn't read config: %v", err)
			return nil, err
		}
	} else {
		cfg.Cloud = os.Getenv("ARM_CLOUD")
		cfg.SubscriptionID = os.Getenv("ARM_SUBSCRIPTION_ID")
		cfg.ResourceGroup = os.Getenv("ARM_RESOURCE_GROUP")
		cfg.TenantID = os.Getenv("ARM_TENANT_ID")
		cfg.AADClientID = os.Getenv("ARM_CLIENT_ID")
		cfg.AADClientSecret = os.Getenv("ARM_CLIENT_SECRET")
		cfg.VMType = strings.ToLower(os.Getenv("ARM_VM_TYPE"))
		cfg.AADClientCertPath = os.Getenv("ARM_CLIENT_CERT_PATH")
		cfg.AADClientCertPassword = os.Getenv("ARM_CLIENT_CERT_PASSWORD")
		cfg.Deployment = os.Getenv("ARM_DEPLOYMENT")
		cfg.APIServerPrivateKey = os.Getenv("ARM_APISEVER_PRIVATE_KEY")
		cfg.CAPrivateKey = os.Getenv("ARM_CA_PRIVATE_KEY")
		cfg.ClientPrivateKey = os.Getenv("ARM_CLIENT_PRIVATE_KEY")
		cfg.KubeConfigPrivateKey = os.Getenv("ARM_KUBECONFIG_PRIVATE_KEY")
		cfg.WindowsAdminPassword = os.Getenv("ARM_WINDOWS_ADMIN_PASSWORD")
		cfg.EtcdClientPrivateKey = os.Getenv("ARM_ETCD_CLIENT_RPIVATE_KEY")
		cfg.EtcdServerPrivateKey = os.Getenv("ARM_ETCD_SERVER_PRIVATE_KEY")

		useManagedIdentityExtensionFromEnv := os.Getenv("ARM_USE_MANAGED_IDENTITY_EXTENSION")
		if len(useManagedIdentityExtensionFromEnv) > 0 {
			cfg.UseManagedIdentityExtension, err = strconv.ParseBool(useManagedIdentityExtensionFromEnv)
			if err != nil {
				return nil, err
			}
		}
	}
	cfg.TrimSpace()

	// Defaulting vmType to vmss.
	if cfg.VMType == "" {
		cfg.VMType = vmTypeVMSS
	}

	env := azure.PublicCloud
	if cfg.Cloud != "" {
		env, err = azure.EnvironmentFromName(cfg.Cloud)
		if err != nil {
			return nil, err
		}
	}

	if cfg.ResourceGroup == "" {
		return nil, fmt.Errorf("resource group not set")
	}

	if cfg.SubscriptionID == "" {
		return nil, fmt.Errorf("subscription ID not set")
	}

	if cfg.TenantID == "" {
		return nil, fmt.Errorf("tenant ID not set")
	}

	if cfg.AADClientID == "" {
		return nil, fmt.Errorf("ARM Client ID not set")
	}

	if cfg.VMType == vmTypeStandard {
		if cfg.Deployment == "" {
			return nil, fmt.Errorf("deployment not set")
		}

		if cfg.APIServerPrivateKey == "" {
			return nil, fmt.Errorf("apiServerPrivateKey not set")
		}

		if cfg.CAPrivateKey == "" {
			return nil, fmt.Errorf("caPrivateKey not set")
		}

		if cfg.ClientPrivateKey == "" {
			return nil, fmt.Errorf("clientPrivateKey not set")
		}

		if cfg.KubeConfigPrivateKey == "" {
			return nil, fmt.Errorf("kubeConfigPrivateKey not set")
		}
	}

	glog.Infof("Starting azure manager with subscription ID %q", cfg.SubscriptionID)

	spt, err := NewServicePrincipalTokenFromCredentials(&cfg, &env)
	if err != nil {
		return nil, err
	}

	scaleSetsClient := compute.NewVirtualMachineScaleSetsClient(cfg.SubscriptionID)
	scaleSetsClient.BaseURI = env.ResourceManagerEndpoint
	scaleSetsClient.Authorizer = autorest.NewBearerAuthorizer(spt)
	scaleSetsClient.PollingDelay = 5 * time.Second
	configureUserAgent(&scaleSetsClient.Client)
	glog.V(5).Infof("Created scale set client with authorizer: %v", scaleSetsClient)

	scaleSetVMsClient := compute.NewVirtualMachineScaleSetVMsClient(cfg.SubscriptionID)
	scaleSetVMsClient.BaseURI = env.ResourceManagerEndpoint
	scaleSetVMsClient.Authorizer = autorest.NewBearerAuthorizer(spt)
	scaleSetVMsClient.PollingDelay = 5 * time.Second
	configureUserAgent(&scaleSetVMsClient.Client)
	glog.V(5).Infof("Created scale set vm client with authorizer: %v", scaleSetVMsClient)

	virtualMachinesClient := compute.NewVirtualMachinesClient(cfg.SubscriptionID)
	virtualMachinesClient.BaseURI = env.ResourceManagerEndpoint
	virtualMachinesClient.Authorizer = autorest.NewBearerAuthorizer(spt)
	virtualMachinesClient.PollingDelay = 5 * time.Second
	configureUserAgent(&virtualMachinesClient.Client)
	glog.V(5).Infof("Created vm client with authorizer: %v", virtualMachinesClient)

	deploymentsClient := resources.NewDeploymentsClient(cfg.SubscriptionID)
	deploymentsClient.BaseURI = env.ResourceManagerEndpoint
	deploymentsClient.Authorizer = autorest.NewBearerAuthorizer(spt)
	deploymentsClient.PollingDelay = 5 * time.Second
	configureUserAgent(&deploymentsClient.Client)
	glog.V(5).Infof("Created deployments client with authorizer: %v", deploymentsClient)

	interfacesClient := network.NewInterfacesClient(cfg.SubscriptionID)
	interfacesClient.BaseURI = env.ResourceManagerEndpoint
	interfacesClient.Authorizer = autorest.NewBearerAuthorizer(spt)
	interfacesClient.PollingDelay = 5 * time.Second
	glog.V(5).Infof("Created interfaces client with authorizer: %v", interfacesClient)

	storageAccountsClient := storage.NewAccountsClient(cfg.SubscriptionID)
	storageAccountsClient.BaseURI = env.ResourceManagerEndpoint
	storageAccountsClient.Authorizer = autorest.NewBearerAuthorizer(spt)
	storageAccountsClient.PollingDelay = 5 * time.Second
	glog.V(5).Infof("Created storage accounts client with authorizer: %v", storageAccountsClient)

	disksClient := disk.NewDisksClient(cfg.SubscriptionID)
	disksClient.BaseURI = env.ResourceManagerEndpoint
	disksClient.Authorizer = autorest.NewBearerAuthorizer(spt)
	disksClient.PollingDelay = 5 * time.Second
	glog.V(5).Infof("Created disks client with authorizer: %v", disksClient)

	// Create azure manager.
	manager := &AzureManager{
		config:                          &cfg,
		env:                             env,
		disksClient:                     disksClient,
		interfacesClient:                interfacesClient,
		virtualMachineScaleSetsClient:   scaleSetsClient,
		virtualMachineScaleSetVMsClient: scaleSetVMsClient,
		deploymentsClient:               deploymentsClient,
		virtualMachinesClient:           virtualMachinesClient,
		storageAccountsClient:           storageAccountsClient,
		explicitlyConfigured:            make(map[azureRef]bool),
	}

	cache, err := newAsgCache(manager)
	if err != nil {
		return nil, err
	}
	manager.asgCache = cache

	specs, err := discoveryOpts.ParseLabelAutoDiscoverySpecs()
	if err != nil {
		return nil, err
	}
	manager.asgAutoDiscoverySpecs = specs

	if err := manager.fetchExplicitAsgs(discoveryOpts.NodeGroupSpecs); err != nil {
		return nil, err
	}

	if err := manager.forceRefresh(); err != nil {
		return nil, err
	}

	return manager, nil
}

// NewServicePrincipalTokenFromCredentials creates a new ServicePrincipalToken using values of the
// passed credentials map.
func NewServicePrincipalTokenFromCredentials(config *Config, env *azure.Environment) (*adal.ServicePrincipalToken, error) {
	oauthConfig, err := adal.NewOAuthConfig(env.ActiveDirectoryEndpoint, config.TenantID)
	if err != nil {
		return nil, fmt.Errorf("creating the OAuth config: %v", err)
	}

	if config.UseManagedIdentityExtension {
		glog.V(2).Infoln("azure: using managed identity extension to retrieve access token")
		msiEndpoint, err := adal.GetMSIVMEndpoint()
		if err != nil {
			return nil, fmt.Errorf("Getting the managed service identity endpoint: %v", err)
		}
		return adal.NewServicePrincipalTokenFromMSI(
			msiEndpoint,
			env.ServiceManagementEndpoint)
	}

	if len(config.AADClientSecret) > 0 {
		glog.V(2).Infoln("azure: using client_id+client_secret to retrieve access token")
		return adal.NewServicePrincipalToken(
			*oauthConfig,
			config.AADClientID,
			config.AADClientSecret,
			env.ServiceManagementEndpoint)
	}

	if len(config.AADClientCertPath) > 0 && len(config.AADClientCertPassword) > 0 {
		glog.V(2).Infoln("azure: using jwt client_assertion (client_cert+client_private_key) to retrieve access token")
		certData, err := ioutil.ReadFile(config.AADClientCertPath)
		if err != nil {
			return nil, fmt.Errorf("reading the client certificate from file %s: %v", config.AADClientCertPath, err)
		}
		certificate, privateKey, err := decodePkcs12(certData, config.AADClientCertPassword)
		if err != nil {
			return nil, fmt.Errorf("decoding the client certificate: %v", err)
		}
		return adal.NewServicePrincipalTokenFromCertificate(
			*oauthConfig,
			config.AADClientID,
			certificate,
			privateKey,
			env.ServiceManagementEndpoint)
	}

	return nil, fmt.Errorf("No credentials provided for AAD application %s", config.AADClientID)
}

func (m *AzureManager) fetchExplicitAsgs(specs []string) error {
	changed := false
	for _, spec := range specs {
		asg, err := m.buildAsgFromSpec(spec)
		if err != nil {
			return fmt.Errorf("failed to parse node group spec: %v", err)
		}
		if m.RegisterAsg(asg) {
			changed = true
		}
		m.explicitlyConfigured[asg.getAzureRef()] = true
	}

	if changed {
		if err := m.regenerateCache(); err != nil {
			return err
		}
	}
	return nil
}

func (m *AzureManager) buildAsgFromSpec(spec string) (Asg, error) {
	s, err := dynamic.SpecFromString(spec, scaleToZeroSupported)
	if err != nil {
		return nil, fmt.Errorf("failed to parse node group spec: %v", err)
	}

	switch m.config.VMType {
	case vmTypeStandard:
		return NewAgentPool(s, m)
	case vmTypeVMSS:
		return NewScaleSet(s, m)
	default:
		return nil, fmt.Errorf("vmtype %s not supported", m.config.VMType)
	}
}

// Refresh is called before every main loop and can be used to dynamically update cloud provider state.
// In particular the list of node groups returned by NodeGroups can change as a result of CloudProvider.Refresh().
func (m *AzureManager) Refresh() error {
	if m.lastRefresh.Add(refreshInterval).After(time.Now()) {
		return nil
	}
	return m.forceRefresh()
}

func (m *AzureManager) forceRefresh() error {
	if err := m.fetchAutoAsgs(); err != nil {
		glog.Errorf("Failed to fetch ASGs: %v", err)
		return err
	}
	m.lastRefresh = time.Now()
	glog.V(2).Infof("Refreshed ASG list, next refresh after %v", m.lastRefresh.Add(refreshInterval))
	return nil
}

// Fetch automatically discovered ASGs. These ASGs should be unregistered if
// they no longer exist in Azure.
func (m *AzureManager) fetchAutoAsgs() error {
	groups, err := m.getFilteredAutoscalingGroups(m.asgAutoDiscoverySpecs)
	if err != nil {
		return fmt.Errorf("cannot autodiscover ASGs: %s", err)
	}

	changed := false
	exists := make(map[azureRef]bool)
	for _, asg := range groups {
		azRef := asg.getAzureRef()
		exists[azRef] = true
		if m.explicitlyConfigured[azRef] {
			// This ASG was explicitly configured, but would also be
			// autodiscovered. We want the explicitly configured min and max
			// nodes to take precedence.
			glog.V(3).Infof("Ignoring explicitly configured ASG %s for autodiscovery.", asg.Id())
			continue
		}
		if m.RegisterAsg(asg) {
			glog.V(3).Infof("Autodiscovered ASG %s using tags %v", asg.Id(), m.asgAutoDiscoverySpecs)
			changed = true
		}
	}

	for _, asg := range m.getAsgs() {
		azRef := asg.getAzureRef()
		if !exists[azRef] && !m.explicitlyConfigured[azRef] {
			m.UnregisterAsg(asg)
			changed = true
		}
	}

	if changed {
		if err := m.regenerateCache(); err != nil {
			return err
		}
	}

	return nil
}

func (m *AzureManager) getAsgs() []Asg {
	return m.asgCache.get()
}

func (m *AzureManager) getInstanceIDs(instances []*azureRef) []string {
	return m.asgCache.getInstanceIDs(instances)
}

// RegisterAsg registers an ASG.
func (m *AzureManager) RegisterAsg(asg Asg) bool {
	return m.asgCache.Register(asg)
}

// UnregisterAsg unregisters an ASG.
func (m *AzureManager) UnregisterAsg(asg Asg) bool {
	return m.asgCache.Unregister(asg)
}

// GetAsgForInstance returns AsgConfig of the given Instance
func (m *AzureManager) GetAsgForInstance(instance *azureRef) (Asg, error) {
	return m.asgCache.FindForInstance(instance)
}

func (m *AzureManager) regenerateCache() error {
	m.asgCache.mutex.Lock()
	defer m.asgCache.mutex.Unlock()
	return m.asgCache.regenerate()
}

// Cleanup the ASG cache.
func (m *AzureManager) Cleanup() {
	m.asgCache.Cleanup()
}

func (m *AzureManager) getFilteredAutoscalingGroups(filter []cloudprovider.LabelAutoDiscoveryConfig) (asgs []Asg, err error) {
	switch m.config.VMType {
	case vmTypeVMSS:
		asgs, err = m.listScaleSets(filter)
	case vmTypeStandard:
		asgs, err = m.listAgentPools(filter)
	default:
		err = fmt.Errorf("vmType %q not supported", m.config.VMType)
	}
	if err != nil {
		return nil, err
	}

	return asgs, nil
}

// listScaleSets gets a list of scale sets and instanceIDs.
func (m *AzureManager) listScaleSets(filter []cloudprovider.LabelAutoDiscoveryConfig) (asgs []Asg, err error) {
	result, err := m.virtualMachineScaleSetsClient.List(m.config.ResourceGroup)
	if err != nil {
		glog.Errorf("VirtualMachineScaleSetsClient.List for %v failed: %v", m.config.ResourceGroup, err)
		return nil, err
	}

	moreResults := (result.Value != nil && len(*result.Value) > 0)
	for moreResults {
		for _, scaleSet := range *result.Value {
			if len(filter) > 0 {
				if scaleSet.Tags == nil || len(*scaleSet.Tags) == 0 {
					continue
				}

				if !matchDiscoveryConfig(*scaleSet.Tags, filter) {
					continue
				}
			}

			spec := &dynamic.NodeGroupSpec{
				Name:               *scaleSet.Name,
				MinSize:            1,
				MaxSize:            -1,
				SupportScaleToZero: scaleToZeroSupported,
			}
			asg, _ := NewScaleSet(spec, m)
			asgs = append(asgs, asg)
		}
		moreResults = false

		if result.NextLink != nil {
			result, err = m.virtualMachineScaleSetsClient.ListNextResults(result)
			if err != nil {
				glog.Errorf("VirtualMachineScaleSetsClient.ListNextResults for %v failed: %v", m.config.ResourceGroup, err)
				return nil, err
			}

			moreResults = (result.Value != nil && len(*result.Value) > 0)
		}

	}

	return asgs, nil
}

// listAgentPools gets a list of agent pools and instanceIDs.
// Note: filter won't take effect for agent pools.
func (m *AzureManager) listAgentPools(filter []cloudprovider.LabelAutoDiscoveryConfig) (asgs []Asg, err error) {
	deploy, err := m.deploymentsClient.Get(m.config.ResourceGroup, m.config.Deployment)
	if err != nil {
		glog.Errorf("deploymentsClient.Get(%s, %s) failed: %v", m.config.ResourceGroup, m.config.Deployment, err)
		return nil, err
	}

	for k := range *deploy.Properties.Parameters {
		if k == "masterVMSize" || !strings.HasSuffix(k, "VMSize") {
			continue
		}

		poolName := strings.TrimRight(k, "VMSize")
		spec := &dynamic.NodeGroupSpec{
			Name:               poolName,
			MinSize:            1,
			MaxSize:            -1,
			SupportScaleToZero: scaleToZeroSupported,
		}
		asg, _ := NewAgentPool(spec, m)
		asgs = append(asgs, asg)
	}

	return asgs, nil
}
