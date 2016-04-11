package types

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/noironetworks/cilium-net/common"
)

const (
	// LPCfgFileVersion represents the version of a Label Prefix Configuration File
	LPCfgFileVersion = 1
)

// LabelPrefixCfg is the label prefix configuration to filter labels of started
// containers.
type LabelPrefixCfg struct {
	Version       int      `json:"version"`
	LabelPrefixes []*Label `json:"labels"`
}

// DefaultLabelPrefixCfg returns a default LabelPrefixCfg using the latest
// LPCfgFileVersion and the following label prefixes: Key: common.GlobalLabelPrefix,
// Source: common.CiliumLabelSource and Key: common.GlobalLabelPrefix, Source:
// common.K8sLabelSource.
func DefaultLabelPrefixCfg() *LabelPrefixCfg {
	return &LabelPrefixCfg{
		Version: LPCfgFileVersion,
		LabelPrefixes: []*Label{
			&Label{
				Key:    common.GlobalLabelPrefix,
				Source: common.CiliumLabelSource,
			},
			&Label{
				Key:    common.GlobalLabelPrefix,
				Source: common.K8sLabelSource,
			},
		},
	}
}

// ReadLabelPrefixCfgFrom reads a label prefix configuration file from fileName. If the
// version is not supported by us it returns an error.
func ReadLabelPrefixCfgFrom(fileName string) (*LabelPrefixCfg, error) {
	f, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	lpc := LabelPrefixCfg{}
	err = json.NewDecoder(f).Decode(&lpc)
	if err != nil {
		return nil, err
	}
	if lpc.Version != LPCfgFileVersion {
		return nil, fmt.Errorf("unsupported version %d", lpc.Version)
	}
	return &lpc, nil
}

// FilterLabels returns Labels from the given labels that have the same source and the
// same prefix as one of lpc valid prefixes.
func (lpc *LabelPrefixCfg) FilterLabels(labels Labels) Labels {
	filteredLabels := Labels{}
	for k, v := range labels {
		for _, lpcValue := range lpc.LabelPrefixes {
			if lpcValue.Source == v.Source &&
				strings.HasPrefix(v.Key, lpcValue.Key) {
				// Just want to make sure we don't have labels deleted in
				// on side and disappearing in the other side...
				cpy := Label(*v)
				filteredLabels[k] = &cpy
			}
		}
	}
	return filteredLabels
}