/*
Copyright 2018 The Kubernetes Authors.

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
	"github.com/Azure/azure-sdk-for-go/arm/compute"
)

var (
	instanceFamily = map[string]string{
		"Basic_A0":               "basicAFamily",
		"Basic_A1":               "basicAFamily",
		"Basic_A2":               "basicAFamily",
		"Basic_A3":               "basicAFamily",
		"Basic_A4":               "basicAFamily",
		"Standard_A0":            "standardA0_A7Family",
		"Standard_A1_v2":         "standardAv2Family",
		"Standard_A1":            "standardA0_A7Family",
		"Standard_A10":           "standardA8_A11Family",
		"Standard_A11":           "standardA8_A11Family",
		"Standard_A2_v2":         "standardAv2Family",
		"Standard_A2":            "standardA0_A7Family",
		"Standard_A2m_v2":        "standardAv2Family",
		"Standard_A3":            "standardA0_A7Family",
		"Standard_A4_v2":         "standardAv2Family",
		"Standard_A4":            "standardA0_A7Family",
		"Standard_A4m_v2":        "standardAv2Family",
		"Standard_A5":            "standardA0_A7Family",
		"Standard_A6":            "standardA0_A7Family",
		"Standard_A7":            "standardA0_A7Family",
		"Standard_A8_v2":         "standardAv2Family",
		"Standard_A8":            "standardA8_A11Family",
		"Standard_A8m_v2":        "standardAv2Family",
		"Standard_A9":            "standardA8_A11Family",
		"Standard_B1s":           "standardBFamily",
		"Standard_B2ms":          "standardBFamily",
		"Standard_B2s":           "standardBFamily",
		"Standard_B4ms":          "standardBFamily",
		"Standard_B8ms":          "standardBFamily",
		"Standard_D1_v2":         "standardDv2Family",
		"Standard_D1":            "standardDFamily",
		"Standard_D11_v2_Promo":  "standardDv2PromoFamily",
		"Standard_D11_v2":        "standardDv2Family",
		"Standard_D11":           "standardDFamily",
		"Standard_D12_v2_Promo":  "standardDv2PromoFamily",
		"Standard_D12_v2":        "standardDv2Family",
		"Standard_D12":           "standardDFamily",
		"Standard_D13_v2_Promo":  "standardDv2PromoFamily",
		"Standard_D13_v2":        "standardDv2Family",
		"Standard_D13":           "standardDFamily",
		"Standard_D14_v2_Promo":  "standardDv2PromoFamily",
		"Standard_D14_v2":        "standardDv2Family",
		"Standard_D14":           "standardDFamily",
		"Standard_D15_v2":        "standardDv2Family",
		"Standard_D16_v3":        "standardDv3Family",
		"Standard_D16s_v3":       "standardDSv3Family",
		"Standard_D2_v2_Promo":   "standardDv2PromoFamily",
		"Standard_D2_v2":         "standardDv2Family",
		"Standard_D2_v3":         "standardDv3Family",
		"Standard_D2":            "standardDFamily",
		"Standard_D2s_v3":        "standardDSv3Family",
		"Standard_D3_v2_Promo":   "standardDv2PromoFamily",
		"Standard_D3_v2":         "standardDv2Family",
		"Standard_D3":            "standardDFamily",
		"Standard_D32_v3":        "standardDv3Family",
		"Standard_D32s_v3":       "standardDSv3Family",
		"Standard_D4_v2_Promo":   "standardDv2PromoFamily",
		"Standard_D4_v2":         "standardDv2Family",
		"Standard_D4_v3":         "standardDv3Family",
		"Standard_D4":            "standardDFamily",
		"Standard_D4s_v3":        "standardDSv3Family",
		"Standard_D5_v2_Promo":   "standardDv2PromoFamily",
		"Standard_D5_v2":         "standardDv2Family",
		"Standard_D64_v3":        "standardDv3Family",
		"Standard_D64s_v3":       "standardDSv3Family",
		"Standard_D8_v3":         "standardDv3Family",
		"Standard_D8s_v3":        "standardDSv3Family",
		"Standard_DS1_v2":        "standardDSv2Family",
		"Standard_DS1":           "standardDSFamily",
		"Standard_DS11_v2_Promo": "standardDSv2PromoFamily",
		"Standard_DS11_v2":       "standardDSv2Family",
		"Standard_DS11":          "standardDSFamily",
		"Standard_DS12_v2_Promo": "standardDSv2PromoFamily",
		"Standard_DS12_v2":       "standardDSv2Family",
		"Standard_DS12":          "standardDSFamily",
		"Standard_DS13_v2_Promo": "standardDSv2PromoFamily",
		"Standard_DS13_v2":       "standardDSv2Family",
		"Standard_DS13-2_v2":     "standardDSv2Family",
		"Standard_DS13-4_v2":     "standardDSv2Family",
		"Standard_DS13":          "standardDSFamily",
		"Standard_DS14_v2_Promo": "standardDSv2PromoFamily",
		"Standard_DS14_v2":       "standardDSv2Family",
		"Standard_DS14-4_v2":     "standardDSv2Family",
		"Standard_DS14-8_v2":     "standardDSv2Family",
		"Standard_DS14":          "standardDSFamily",
		"Standard_DS15_v2":       "standardDSv2Family",
		"Standard_DS2_v2_Promo":  "standardDSv2PromoFamily",
		"Standard_DS2_v2":        "standardDSv2Family",
		"Standard_DS2":           "standardDSFamily",
		"Standard_DS3_v2_Promo":  "standardDSv2PromoFamily",
		"Standard_DS3_v2":        "standardDSv2Family",
		"Standard_DS3":           "standardDSFamily",
		"Standard_DS4_v2_Promo":  "standardDSv2PromoFamily",
		"Standard_DS4_v2":        "standardDSv2Family",
		"Standard_DS4":           "standardDSFamily",
		"Standard_DS5_v2_Promo":  "standardDSv2PromoFamily",
		"Standard_DS5_v2":        "standardDSv2Family",
		"Standard_E16_v3":        "standardEv3Family",
		"Standard_E16s_v3":       "standardESv3Family",
		"Standard_E2_v3":         "standardEv3Family",
		"Standard_E2s_v3":        "standardESv3Family",
		"Standard_E32_v3":        "standardEv3Family",
		"Standard_E32-16s_v3":    "standardESv3Family",
		"Standard_E32-8s_v3":     "standardESv3Family",
		"Standard_E32s_v3":       "standardESv3Family",
		"Standard_E4_v3":         "standardEv3Family",
		"Standard_E4s_v3":        "standardESv3Family",
		"Standard_E64_v3":        "standardEv3Family",
		"Standard_E64-16s_v3":    "standardESv3Family",
		"Standard_E64-32s_v3":    "standardESv3Family",
		"Standard_E64s_v3":       "standardESv3Family",
		"Standard_E8_v3":         "standardEv3Family",
		"Standard_E8s_v3":        "standardESv3Family",
		"Standard_F1":            "standardFFamily",
		"Standard_F16":           "standardFFamily",
		"Standard_F16s_v2":       "standardESv3Family",
		"Standard_F16s":          "",
		"Standard_F1s":           "standardFSFamily",
		"Standard_F2":            "standardFFamily",
		"Standard_F2s_v2":        "",
		"Standard_F2s":           "standardFSFamily",
		"Standard_F32s_v2":       "",
		"Standard_F4":            "standardFFamily",
		"Standard_F4s_v2":        "",
		"Standard_F4s":           "",
		"Standard_F64s_v2":       "",
		"Standard_F72s_v2":       "",
		"Standard_F8":            "standardFFamily",
		"Standard_F8s_v2":        "",
		"Standard_F8s":           "",
		"Standard_H16":           "",
		"Standard_H16m":          "",
		"Standard_H16mr":         "",
		"Standard_H16r":          "",
		"Standard_H8":            "",
		"Standard_H8m":           "",
		"Standard_NC12":          "",
		"Standard_NC12s_v2":      "",
		"Standard_NC12s_v3":      "",
		"Standard_NC24":          "",
		"Standard_NC24r":         "",
		"Standard_NC24rs_v2":     "",
		"Standard_NC24rs_v3":     "",
		"Standard_NC24s_v2":      "",
		"Standard_NC24s_v3":      "",
		"Standard_NC6":           "",
		"Standard_NC6s_v2":       "",
		"Standard_NC6s_v3":       "",
		"Standard_ND12s":         "",
		"Standard_ND24rs":        "",
		"Standard_ND24s":         "",
		"Standard_ND6s":          "",
		"Standard_NV12":          "",
		"Standard_NV24":          "",
		"Standard_NV6":           "",
		"Standard_B1ms":          "",
	}
)

// standardFSFamily
// standardFSv2Family
// standardGFamily
// standardGSFamily
// standardHFamily
// standardLSFamily
// standardLSv2Family
// standardMSFamily
// standardNCFamily
// standardNCv2Family
// standardNCv3Family
// standardNDFamily
// standardNVFamily

func (m *AzureManager) listAvailableSizes() error {
	azSizes := make(map[string]*compute.VirtualMachineSize)
	sizes, err := m.azClient.virtualMachineSizesClient.List(m.config.Location)
	if err != nil {
		return err
	}

	for idx := range *sizes.Value {
		vmSize := (*sizes.Value)[idx]
		azSizes[*vmSize.Name] = &vmSize
	}

	usageList, err := m.azClient.usageClient.List(m.config.Location)
	if err != nil {
		return err
	}
	moreResults := (usageList.Value != nil && len(*usageList.Value) > 0)
	for moreResults {
		for _, usage := range *usageList.Value {

		}
		moreResults = false

		if usageList.NextLink != nil {
			usageList, err = m.azClient.usageClient.ListNextResults(usageList)
			if err != nil {
				return err
			}

			moreResults = (usageList.Value != nil && len(*usageList.Value) > 0)
		}

	}
}
