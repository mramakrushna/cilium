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
	"fmt"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/service"
	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/apierror"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/lbmap"

	log "github.com/Sirupsen/logrus"
	"github.com/go-openapi/runtime/middleware"
)

// addSVC2BPFMap adds the given bpf service to the bpf maps. If addRevNAT is set, adds the
// RevNAT value (feCilium.L3n4Addr) to the lb's RevNAT map for the given feCilium.ID.
func (d *Daemon) addSVC2BPFMap(feCilium types.L3n4AddrID, feBPF lbmap.ServiceKey,
	besBPF []lbmap.ServiceValue, addRevNAT bool) error {
	log.Debugf("addSVC2BPFMap: adding service %s to LBMap", feBPF)

	_, err := lbmap.AddSVC2BPFMap(feBPF, besBPF, addRevNAT, int(feCilium.ID))
	if err != nil {
		if addRevNAT {
			delete(d.loadBalancer.RevNATMap, feCilium.ID)
		}
		return err
	}

	if addRevNAT {
		d.loadBalancer.RevNATMap[feCilium.ID] = *feCilium.L3n4Addr.DeepCopy()
	}
	return nil
}

// SVCAdd is the public method to add services. We assume the ID provided is not in
// synced with the KVStore. If that's the case the service won't be used and an error is
// returned to the caller.
//
// Returns true if service was created
func (d *Daemon) SVCAdd(feL3n4Addr types.L3n4AddrID, be []types.LBBackEnd, addRevNAT bool) (bool, error) {
	log.Debugf("SVCAdd: adding service with ID %s", feL3n4Addr.L3n4Addr)
	if feL3n4Addr.ID == 0 {
		return false, fmt.Errorf("invalid service ID 0")
	}
	// Check if the service is already registered with this ID.
	feAddr, err := GetL3n4AddrID(uint32(feL3n4Addr.ID))
	if err != nil {
		return false, fmt.Errorf("unable to get the service with ID %d: %s", feL3n4Addr.ID, err)
	}
	if feAddr == nil {
		feAddr, err = PutL3n4Addr(feL3n4Addr.L3n4Addr, uint32(feL3n4Addr.ID))
		if err != nil {
			return false, fmt.Errorf("unable to put the service %s: %s", feL3n4Addr.L3n4Addr.String(), err)
		}
		// This won't be atomic so we need to check if the baseID, feL3n4Addr.ID was given to the service
		if feAddr.ID != feL3n4Addr.ID {
			return false, fmt.Errorf("the service provided %s is already registered with ID %d, please select that ID instead of %d", feL3n4Addr.L3n4Addr.String(), feAddr.ID, feL3n4Addr.ID)
		}
	}

	feAddr256Sum := feAddr.L3n4Addr.SHA256Sum()
	feL3n4Addr256Sum := feL3n4Addr.L3n4Addr.SHA256Sum()

	if feAddr256Sum != feL3n4Addr256Sum {
		return false, fmt.Errorf("service ID %d is already registered to service %s, please choose a different ID", feL3n4Addr.ID, feAddr.String())
	}

	return d.svcAdd(feL3n4Addr, be, addRevNAT)
}

// svcAdd adds a service from the given feL3n4Addr (frontend) and LBBackEnd (backends).
// If addRevNAT is set, the RevNAT entry is also created for this particular service.
// If any of the backend addresses set in bes have a different L3 address type than the
// one set in fe, it returns an error without modifying the bpf LB map. If any backend
// entry fails while updating the LB map, the frontend won't be inserted in the LB map
// therefore there won't be any traffic going to the given backends.
// All of the backends added will be DeepCopied to the internal load balancer map.
func (d *Daemon) svcAdd(feL3n4Addr types.L3n4AddrID, bes []types.LBBackEnd, addRevNAT bool) (bool, error) {
	log.Debugf("daemon.svcAdd: adding svc with ID %s", feL3n4Addr.L3n4Addr)
	for _, v := range bes {
		log.Debugf("daemon.svcAdd: ID %s has backend %s", feL3n4Addr, v)
	}
	// Move the slice to the loadbalancer map which has a mutex. If we don't
	// copy the slice we might risk changing memory that should be locked.
	beCpy := []types.LBBackEnd{}
	for _, v := range bes {
		beCpy = append(beCpy, v)
	}

	svc := types.LBSVC{
		FE:     feL3n4Addr,
		BES:    beCpy,
		Sha256: feL3n4Addr.L3n4Addr.SHA256Sum(),
	}

	fe, besValues, err := lbmap.LBSVC2ServiceKeynValue(svc)
	if err != nil {
		return false, err
	}

	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	err = d.addSVC2BPFMap(feL3n4Addr, fe, besValues, addRevNAT)
	if err != nil {
		return false, err
	}

	return d.loadBalancer.AddService(svc), nil
}

type putServiceID struct {
	d *Daemon
}

func NewPutServiceIDHandler(d *Daemon) PutServiceIDHandler {
	return &putServiceID{d: d}
}

func (h *putServiceID) Handle(params PutServiceIDParams) middleware.Responder {
	log.Debugf("PUT /service/{id} request: %+v", params)

	f, err := types.NewL3n4AddrFromModel(params.Config.FrontendAddress)
	if err != nil {
		return apierror.Error(PutServiceIDInvalidFrontendCode, err)
	}

	frontend := types.L3n4AddrID{
		L3n4Addr: *f,
		ID:       types.ServiceID(params.Config.ID),
	}

	backends := []types.LBBackEnd{}
	for _, v := range params.Config.BackendAddresses {
		b, err := types.NewLBBackEndFromBackendModel(v)
		if err != nil {
			return apierror.Error(PutServiceIDInvalidBackendCode, err)
		}
		backends = append(backends, *b)
	}

	revnat := false
	if params.Config.Flags != nil {
		revnat = params.Config.Flags.DirectServerReturn
	}

	// FIXME
	// Add flag to indicate whether service should be registered in
	// global key value store

	if created, err := h.d.SVCAdd(frontend, backends, revnat); err != nil {
		return apierror.Error(PutServiceIDFailureCode, err)
	} else if created {
		return NewPutServiceIDCreated()
	} else {
		return NewPutServiceIDOK()
	}
}

type deleteServiceID struct {
	d *Daemon
}

func NewDeleteServiceIDHandler(d *Daemon) DeleteServiceIDHandler {
	return &deleteServiceID{d: d}
}

func (h *deleteServiceID) Handle(params DeleteServiceIDParams) middleware.Responder {
	log.Debugf("DELETE /service/{id} request: %+v", params)

	d := h.d
	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	log.Debugf("DELETE service: trying to delete service with ID %d from d.loadBalancer.SVCMapID", types.ServiceID(params.ID))

	log.Debugf("DELETE service: contents of SVCMapID")
	for k, v := range d.loadBalancer.SVCMapID {
		log.Debugf("DELETE service: d.loadBalancer.SVCMapID k --> v: %s --> %v", k, v)
	}
	log.Debugf("DELETE service: done dumping contents of SVCMapID")
	svc, ok1 := d.loadBalancer.SVCMapID[types.ServiceID(params.ID)]

	if !ok1 {
		return NewDeleteServiceIDNotFound()
	}

	// FIXME: How to handle error?
	err := DeleteL3n4AddrIDByUUID(uint32(params.ID))

	if err != nil {
		log.Warningf("error, DeleteL3n4AddrIDByUUID failed: %s", err)
	}

	if err := h.d.svcDelete(svc); err != nil {
		log.Warningf("Handle DELETE /service: error deleting svc %v:%s", svc, err)
		return apierror.Error(DeleteServiceIDFailureCode, err)
	}

	return NewDeleteServiceIDOK()
}

// Deletes a service by the frontend address
func (d *Daemon) svcDeleteByFrontend(frontend *types.L3n4Addr) error {
	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	svc, ok := d.loadBalancer.SVCMap[frontend.SHA256Sum()]
	if !ok {
		return fmt.Errorf("Service frontend not found %+v", frontend)
	}
	return d.svcDelete(&svc)
}

func (d *Daemon) svcDelete(svc *types.LBSVC) error {
	var svcKey lbmap.ServiceKey
	if !svc.FE.IsIPv6() {
		svcKey = lbmap.NewService4Key(svc.FE.IP, svc.FE.Port, 0)
	} else {
		svcKey = lbmap.NewService6Key(svc.FE.IP, svc.FE.Port, 0)
	}

	svcKey.SetBackend(0)

	// Get count of backends from master.
	val, err := svcKey.Map().Lookup(svcKey.ToNetwork())
	if err != nil {
		return fmt.Errorf("key %s is not in lbmap", svcKey.ToNetwork())
	}

	var numBackends uint16

	switch val.(type) {
	case lbmap.ServiceValue:
		vval := val.(lbmap.ServiceValue)
		numBackends = uint16(vval.GetCount())
	default:
		return fmt.Errorf("ServiceKey %s did not map to ServiceValue", svcKey.ToNetwork())
	}

	log.Debugf("svcDelete: numBackends = %d for frontend %s", numBackends, svcKey)

	// ServiceKeys are unique by their slave number, which corresponds to the number of backends. Delete each of these.
	for i := numBackends ; i > 0 ; i-- {
		var slaveKey lbmap.ServiceKey
		if !svc.FE.IsIPv6() {
			slaveKey = lbmap.NewService4Key(svc.FE.IP, svc.FE.Port, i)
		} else {
			slaveKey = lbmap.NewService6Key(svc.FE.IP, svc.FE.Port, i)
		}
		log.Debugf("svcDelete: deleting backend # %d for svcKey: %s", i, slaveKey)
		if err := lbmap.DeleteService(slaveKey) ; err != nil {
			return fmt.Errorf("svcDelete: lbMap.DeleteService failed for %s: %s", slaveKey.String(), err)

		}
	}

	log.Debugf("done deleting slaves, now deleting master key")
	if err := lbmap.DeleteService(svcKey); err != nil {
		log.Debugf("svcDelete: lbMap.DeleteService failed for %s", svcKey.String())
		return err
	}

	d.loadBalancer.DeleteService(svc)

	return nil
}

type getServiceID struct {
	daemon *Daemon
}

func NewGetServiceIDHandler(d *Daemon) GetServiceIDHandler {
	return &getServiceID{daemon: d}
}

func (h *getServiceID) Handle(params GetServiceIDParams) middleware.Responder {
	log.Debugf("GET /service/{id} request: %+v", params)

	d := h.daemon

	d.loadBalancer.BPFMapMU.RLock()
	defer d.loadBalancer.BPFMapMU.RUnlock()

	if svc, ok := d.loadBalancer.SVCMapID[types.ServiceID(params.ID)]; ok {
		return NewGetServiceIDOK().WithPayload(svc.GetModel())
	}
	return NewGetServiceIDNotFound()
}

// SVCGetBySHA256Sum returns a DeepCopied frontend with its backends.
func (d *Daemon) svcGetBySHA256Sum(feL3n4SHA256Sum string) *types.LBSVC {
	d.loadBalancer.BPFMapMU.RLock()
	defer d.loadBalancer.BPFMapMU.RUnlock()

	v, ok := d.loadBalancer.SVCMap[feL3n4SHA256Sum]
	if !ok {
		return nil
	}
	// We will move the slice from the loadbalancer map which have a mutex. If
	// we don't copy the slice we might risk changing memory that should be
	// locked.
	beCpy := []types.LBBackEnd{}
	for _, v := range v.BES {
		beCpy = append(beCpy, v)
	}
	return &types.LBSVC{
		FE:  *v.FE.DeepCopy(),
		BES: beCpy,
	}
}

type getService struct {
	d *Daemon
}

func NewGetServiceHandler(d *Daemon) GetServiceHandler {
	return &getService{d: d}
}

func (h *getService) Handle(params GetServiceParams) middleware.Responder {
	log.Debugf("GET /service request: %+v", params)

	list := []*models.Service{}

	h.d.loadBalancer.BPFMapMU.RLock()
	defer h.d.loadBalancer.BPFMapMU.RUnlock()

	for _, v := range h.d.loadBalancer.SVCMap {
		list = append(list, v.GetModel())
	}

	return NewGetServiceOK().WithPayload(list)
}

// RevNATAdd deep copies the given revNAT address to the cilium lbmap with the given id.
func (d *Daemon) RevNATAdd(id types.ServiceID, revNAT types.L3n4Addr) error {
	revNATK, revNATV := lbmap.L3n4Addr2RevNatKeynValue(id, revNAT)

	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	err := lbmap.UpdateRevNat(revNATK, revNATV)
	if err != nil {
		return err
	}

	d.loadBalancer.RevNATMap[id] = *revNAT.DeepCopy()
	return nil
}

// RevNATDelete deletes the revNatKey from the local bpf map.
func (d *Daemon) RevNATDelete(id types.ServiceID) error {
	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	revNAT, ok := d.loadBalancer.RevNATMap[id]
	if !ok {
		return nil
	}

	var revNATK lbmap.RevNatKey
	if !revNAT.IsIPv6() {
		revNATK = lbmap.NewRevNat4Key(uint16(id))
	} else {
		revNATK = lbmap.NewRevNat6Key(uint16(id))
	}

	err := lbmap.DeleteRevNat(revNATK)
	// TODO should we delete even if err is != nil?
	if err == nil {
		delete(d.loadBalancer.RevNATMap, id)
	}
	return err
}

// RevNATDeleteAll deletes all RevNAT4, if IPv4 is enabled on daemon, and all RevNAT6
// stored on the daemon and on the bpf maps.
func (d *Daemon) RevNATDeleteAll() error {
	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	if !d.conf.IPv4Disabled {
		if err := lbmap.RevNat4Map.DeleteAll(); err != nil {
			return err
		}
	}
	if err := lbmap.RevNat6Map.DeleteAll(); err != nil {
		return err
	}
	// TODO should we delete even if err is != nil?

	d.loadBalancer.RevNATMap = map[types.ServiceID]types.L3n4Addr{}
	return nil
}

// RevNATGet returns a DeepCopy of the revNAT found with the given ID or nil if not found.
func (d *Daemon) RevNATGet(id types.ServiceID) (*types.L3n4Addr, error) {
	d.loadBalancer.BPFMapMU.RLock()
	defer d.loadBalancer.BPFMapMU.RUnlock()

	revNAT, ok := d.loadBalancer.RevNATMap[id]
	if !ok {
		return nil, nil
	}
	return revNAT.DeepCopy(), nil
}

// RevNATDump dumps a DeepCopy of the cilium's loadbalancer.
func (d *Daemon) RevNATDump() ([]types.L3n4AddrID, error) {
	dump := []types.L3n4AddrID{}

	d.loadBalancer.BPFMapMU.RLock()
	defer d.loadBalancer.BPFMapMU.RUnlock()

	for k, v := range d.loadBalancer.RevNATMap {
		dump = append(dump, types.L3n4AddrID{
			ID:       k,
			L3n4Addr: *v.DeepCopy(),
		})
	}

	return dump, nil
}

// SyncLBMap syncs the bpf lbmap with the daemon's lb map. All bpf entries will overwrite
// the daemon's LB map. If the bpf lbmap entry has a different service ID than the
// KVStore's ID, that entry will be updated on the bpf map accordingly with the new ID
// retrieved from the KVStore.
func (d *Daemon) SyncLBMap() error {
	log.Debugf("SyncLBMap: syncing BPF LBMap with daemon's LB map")
	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	newSVCMap := types.SVCMap{}
	newSVCMapID := types.SVCMapID{}
	newRevNATMap := types.RevNATMap{}
	failedSyncSVC := []types.LBSVC{}
	failedSyncRevNAT := map[types.ServiceID]types.L3n4Addr{}

	parseSVCEntries := func(key bpf.MapKey, value bpf.MapValue) {
		svcKey := key.(lbmap.ServiceKey)
		//It's the frontend service so we don't add this one
		if svcKey.GetBackend() == 0 {
			return
		}
		svcValue := value.(lbmap.ServiceValue)
		log.Debugf("SyncLBMap: parseSVCEntries: %s --> %s", svcKey.String(), svcValue.String())
		fe, be, err := lbmap.ServiceKeynValue2FEnBE(svcKey, svcValue)
		log.Debugf("SyncLBMap: parseSVCEntries created frontend: %s from svckey / value: %s --> %s ", fe.String(), svcKey.String(), svcValue.String())
		log.Debugf("SyncLBMap: parseSVCEntires created backend: %s from svckey / value: %s --> %s ", be.String(), svcKey.String, svcValue.String())
		if err != nil {
			log.Errorf("SyncLBMap: %s", err)
			return
		}

		log.Debugf("SyncLBMap: adding fe %s to newSVCMap", fe)
		newSVCMap.AddFEnBE(fe, be, svcKey.GetBackend())
	}

	parseRevNATEntries := func(key bpf.MapKey, value bpf.MapValue) {
		revNatK := key.(lbmap.RevNatKey)
		revNatV := value.(lbmap.RevNatValue)
		log.Debugf("parseRevNatEntries: %s --> %s", revNatK.String(), revNatV.String())
		fe, err := lbmap.RevNatValue2L3n4AddrID(revNatK, revNatV)
		if err != nil {
			log.Errorf("%s", err)
			return
		}
		newRevNATMap[fe.ID] = fe.L3n4Addr
	}

	addSVC2BPFMap := func(oldID types.ServiceID, svc types.LBSVC) error {
		log.Debugf("addSVC2BPFMap: adding service ID %d / load balancer service %s", oldID, svc.Sha256)
		// check if the ID for revNat is present in the bpf map, update the
		// reverse nat key, delete the old one.
		revNAT, ok := newRevNATMap[oldID]
		if ok {
			log.Debugf("addSVC2BPFMap: %d is present in BPF map, updating revnat key", oldID)
			revNATK, revNATV := lbmap.L3n4Addr2RevNatKeynValue(svc.FE.ID, revNAT)
			err := lbmap.UpdateRevNat(revNATK, revNATV)
			if err != nil {
				return fmt.Errorf("Unable to add revNAT: %s: %s."+
					" This entry will be removed from the bpf's LB map.", revNAT.String(), err)
			}

			// Remove the old entry from the bpf map.
			revNATK, _ = lbmap.L3n4Addr2RevNatKeynValue(oldID, revNAT)
			if err := lbmap.DeleteRevNat(revNATK); err != nil {
				log.Warningf("Unable to remove old rev NAT entry with ID %d: %s", oldID, err)
			}

			log.Debugf("addSVC2BPFMap: deleting oldID %d from newRevNATMap", oldID )
			delete(newRevNATMap, oldID)
			log.Debugf("addSVC2BPFMap: adding svc.FE.ID: %d --> revNAT: %s to newRevNATMap", svc.FE.ID, revNAT.String())
			newRevNATMap[svc.FE.ID] = revNAT
		}

		fe, besValues, err := lbmap.LBSVC2ServiceKeynValue(svc)
		if err != nil {
			return fmt.Errorf("Unable to create a BPF key and values for service FE: %s and backends: %+v. Error: %s."+
				" This entry will be removed from the bpf's LB map.", svc.FE.String(), svc.BES, err)
		}

		err = d.addSVC2BPFMap(svc.FE, fe, besValues, false)
		if err != nil {
			return fmt.Errorf("Unable to add service FE: %s: %s."+
				" This entry will be removed from the bpf's LB map.", svc.FE.String(), err)
		}
		return nil
	}

	if !d.conf.IPv4Disabled {
		// lbmap.RRSeq4Map is updated as part of Service4Map and does
		// not need separate dump.
		err := lbmap.Service4Map.Dump(lbmap.Service4DumpParser, parseSVCEntries)
		if err != nil {
			log.Warningf("error dumping Service4Map: %s", err)
		}
		err = lbmap.RevNat4Map.Dump(lbmap.RevNat4DumpParser, parseRevNATEntries)
		if err != nil {
			log.Warningf("error dumping RevNat4Map: %s", err)
		}
	}

	// lbmap.RRSeq6Map is updated as part of Service6Map and does not need
	// separate dump.
	err := lbmap.Service6Map.Dump(lbmap.Service6DumpParser, parseSVCEntries)
	if err != nil {
		log.Warningf("error dumping Service6Map: %s", err)
	}
	lbmap.RevNat6Map.Dump(lbmap.RevNat6DumpParser, parseRevNATEntries)
	if err != nil {
		log.Warningf("error dumping RevNat6Map: %s", err)
	}

	// Let's check if the services read from the lbmap have the same ID set in the
	// KVStore.
	for k, svc := range newSVCMap {
		log.Debugf("SyncLBMap: iterating over services read from LB Map and seeing if they have the same ID set in the KV store")
		kvL3n4AddrID, err := PutL3n4Addr(svc.FE.L3n4Addr, 0)
		if err != nil {
			log.Errorf("Unable to retrieve service ID of: %s from KVStore: %s."+
				" This entry will be removed from the bpf's LB map.", svc.FE.L3n4Addr.String(), err)
			failedSyncSVC = append(failedSyncSVC, svc)
			delete(newSVCMap, k)
			continue
		}

		if svc.FE.ID != kvL3n4AddrID.ID {
			log.Infof("Service ID %d was out of sync, got new ID %d", svc.FE.ID, kvL3n4AddrID.ID)
			oldID := svc.FE.ID
			svc.FE.ID = kvL3n4AddrID.ID
			if err := addSVC2BPFMap(oldID, svc); err != nil {
				log.Errorf("%s", err)

				failedSyncSVC = append(failedSyncSVC, svc)
				delete(newSVCMap, k)

				revNAT, ok := newRevNATMap[svc.FE.ID]
				if ok {
					// Revert the old revNAT
					newRevNATMap[oldID] = revNAT
					failedSyncRevNAT[svc.FE.ID] = revNAT
					delete(newRevNATMap, svc.FE.ID)
				}
				continue
			}
			log.Debugf("SyncLBMap: adding %s to newSVCMap", k)
			newSVCMap[k] = svc
			log.Debugf("SyncLBMap: adding %s to newSVCMapID", svc.FE.ID)
			newSVCMapID[svc.FE.ID] = &svc
			log.Debugf("SyncLBMap: done adding %s to newSVCMapID", svc.FE.ID)
		} else {
			log.Debugf("svc.FE.ID == kvL3n4AddrID.ID: %d == %d", svc.FE.ID, kvL3n4AddrID.ID)
			log.Debugf("svc.FE.ID == kvL3n4AddrID.ID, so we're not updating newSVCMapID")
		}
	}

	// Clean services and rev nats that failed while restoring
	for _, svc := range failedSyncSVC {
		log.Debugf("Removing service: %s", svc.FE)
		feL3n4 := svc.FE
		var svcKey lbmap.ServiceKey
		if !feL3n4.IsIPv6() {
			svcKey = lbmap.NewService4Key(feL3n4.IP, feL3n4.Port, 0)
		} else {
			svcKey = lbmap.NewService6Key(feL3n4.IP, feL3n4.Port, 0)
		}

		svcKey.SetBackend(0)

		if err := lbmap.DeleteService(svcKey); err != nil {
			log.Warningf("Unable to clean service %s from BPF map: %s", svc.FE, err)
		}
	}

	for id, revNAT := range failedSyncRevNAT {
		log.Debugf("Removing revNAT: %s", revNAT)
		var revNATK lbmap.RevNatKey
		if !revNAT.IsIPv6() {
			revNATK = lbmap.NewRevNat4Key(uint16(id))
		} else {
			revNATK = lbmap.NewRevNat6Key(uint16(id))
		}

		if err := lbmap.DeleteRevNat(revNATK); err != nil {
			log.Warningf("Unable to clean rev NAT %s from BPF map: %s", revNAT, err)
		}
	}

	log.Debugf("SyncLBMap: updating daemon's loadbalancer maps")
	for k, v := range newSVCMap {
		log.Debugf("SyncLBMap: daemon SVCMap will have %s --> %v", k, v)
	}
	for k, v := range  newSVCMapID {
		log.Debugf("SyncLBMap: daemon SVCMapID will have %s --> %v", k, v)
	}
	for k, v := range newRevNATMap {
		log.Debugf("SyncLBMap: daemon RevNATMap will have %v --> %v", k, v)
	}
	d.loadBalancer.SVCMap = newSVCMap
	d.loadBalancer.SVCMapID = newSVCMapID
	d.loadBalancer.RevNATMap = newRevNATMap

	return nil
}
