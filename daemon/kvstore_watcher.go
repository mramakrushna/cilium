// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/policy"

	log "github.com/Sirupsen/logrus"
)

// EnableKVStoreWatcher watches for kvstore changes in the common.LastFreeIDKeyPath key.
// Triggers policy updates every time the value of that key is changed.
func (d *Daemon) EnableKVStoreWatcher(maxSeconds time.Duration) {
	// The service kvstore watcher is only required in direct-server-return
	// mode. Otherwise, the reply always flows back synchroneously
	if directServerReturn {
		startServiceWatch()
	}

	if maxID, err := GetMaxLabelID(); err == nil {
		d.setCachedMaxLabelID(maxID)
	}
	ch := kvstore.Client.GetWatcher(common.LastFreeLabelIDKeyPath, maxSeconds)
	go func() {
		for {
			select {
			case updates, updateOk := <-ch:
				if !updateOk {
					log.Debugf("Watcher for %s closed, reacquiring it", common.LastFreeLabelIDKeyPath)
					ch = kvstore.Client.GetWatcher(common.LastFreeLabelIDKeyPath, maxSeconds)
				}
				if len(updates) != 0 {
					d.setCachedMaxLabelID(updates[0])
				}
				d.TriggerPolicyUpdates(updates)
			}
		}
	}()
}

// GetCachedMaxLabelID returns the cached max label ID from the last event
// received from the KVStore.
func (d *Daemon) GetCachedMaxLabelID() (policy.NumericIdentity, error) {
	d.maxCachedLabelIDMU.RLock()
	id := d.maxCachedLabelID
	d.maxCachedLabelIDMU.RUnlock()
	if id == 0 {
		// FIXME: KVStore might not set up the watcher at this point
		// If that's the case, we should ask directly the KVStore
		// What's the maxLabelID value.
		return policy.MinimalNumericIdentity, nil
	}
	return id, nil
}

func (d *Daemon) setCachedMaxLabelID(id policy.NumericIdentity) {
	d.maxCachedLabelIDMU.Lock()
	d.maxCachedLabelID = id
	d.maxCachedLabelIDMU.Unlock()
}

func extractID(path string) uint64 {
	key := strings.TrimPrefix(path, common.ServiceIDKeyPath+"/")
	if strings.Contains(key, ".lock") {
		return 0
	}
	id, err := strconv.ParseUint(key, 10, 64)
	if err != nil {
		log.Warningf("kvstore: invalid service id encountered '%s': %s", key, err)
		return 0
	}

	return id
}

func addRevNAT(id uint64, value []byte) {
	if len(value) <= 0 {
		log.Warningf("kvstore: invalid value for service %s: %#v", id, value)
		return
	}

	val := types.L3n4AddrID{}
	if err := json.Unmarshal(value, &val); err != nil {
		log.Warningf("kvstore: cannot unmarshal service %s %#v: %s", id, value, err)
		return
	}

	log.Debugf("Adding reverse NAT %d => %v", id, val.L3n4Addr)

	err := lbmap.UpdateRevNat(lbmap.L3n4Addr2RevNatKeynValue(types.ServiceID(id), val.L3n4Addr))
	if err != nil {
		log.Warningf("kvstore: Unable to synchronize kvstore service %d %v with BPF map: %s",
			id, val.L3n4Addr, err)
	}
}

func startServiceWatch() {
	go func() {
		prefix := common.ServiceIDKeyPath
		watcher := kvstore.StartWatch(prefix, prefix, 512)
		for {
			select {
			case event := <-watcher.Events:
				log.Debugf("Received kvstore service event %+v", event)
				id := extractID(event.Key)
				if id == 0 {
					continue
				}

				switch event.Typ {
				case kvstore.EventTypeCreate, kvstore.EventTypeModify:
					addRevNAT(id, event.Value)

				case kvstore.EventTypeDelete:
					log.Debugf("Removing reverse NAT %d", id)
					if err := lbmap.DeleteRevNat(lbmap.NewRevNat4Key(uint16(id))); err != nil {
						log.Warningf("kvstore: Unable to synchronize kvstore service %d with BPF map, delete failed: %s",
							id, err)
					}
				}
			}
		}
	}()

	ids, err := kvstore.ListPrefix(common.ServiceIDKeyPath)
	if err != nil {
		return
	}

	for k, v := range ids {
		if id := extractID(k); id != 0 {
			addRevNAT(id, v)
		}
	}

}
