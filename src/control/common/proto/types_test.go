//
// (C) Copyright 2020-2021 Intel Corporation.
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
//

package proto

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/daos-stack/daos/src/control/common"
	ctlpb "github.com/daos-stack/daos/src/control/common/proto/ctl"
	"github.com/daos-stack/daos/src/control/server/storage"
)

func TestProto_ConvertNvmeHealth(t *testing.T) {
	pb := MockNvmeHealth(1)
	native, err := (*NvmeHealth)(pb).ToNative()
	if err != nil {
		t.Fatal(err)
	}
	expNative := storage.MockNvmeHealth(1)

	if diff := cmp.Diff(expNative, native, common.DefaultCmpOpts()...); diff != "" {
		t.Fatalf("unexpected result (-want, +got):\n%s\n", diff)
	}
}

func TestProto_ConvertNvmeNamespace(t *testing.T) {
	pb := MockNvmeNamespace()
	native, err := (*NvmeNamespace)(pb).ToNative()
	if err != nil {
		t.Fatal(err)
	}
	expNative := storage.MockNvmeNamespace()

	if diff := cmp.Diff(expNative, native, common.DefaultCmpOpts()...); diff != "" {
		t.Fatalf("unexpected result (-want, +got):\n%s\n", diff)
	}
}

func TestProto_ConvertNvmeController(t *testing.T) {
	pb := MockNvmeController()
	native, err := (*NvmeController)(pb).ToNative()
	if err != nil {
		t.Fatal(err)
	}
	expNative := storage.MockNvmeController()

	cmpOpts := append(common.DefaultCmpOpts(),
		cmpopts.IgnoreFields(storage.NvmeController{}, "HealthStats", "Serial"),
	)
	if diff := cmp.Diff(expNative, native, cmpOpts...); diff != "" {
		t.Fatalf("unexpected result (-want, +got):\n%s\n", diff)
	}
}

func TestProto_ConvertNvmeControllers(t *testing.T) {
	pbs := []*ctlpb.NvmeController{
		MockNvmeController(1),
		MockNvmeController(2),
		MockNvmeController(3),
	}
	natives, err := (*NvmeControllers)(&pbs).ToNative()
	if err != nil {
		t.Fatal(err)
	}

	var convertedNatives NvmeControllers
	if err := convertedNatives.FromNative(natives); err != nil {
		t.Fatal(err)
	}

	opts := common.DefaultCmpOpts()
	if diff := cmp.Diff(pbs,
		([]*ctlpb.NvmeController)(convertedNatives), opts...); diff != "" {

		t.Fatalf("unexpected result (-want, +got):\n%s\n", diff)
	}
}

func TestProto_ConvertScmModule(t *testing.T) {
	pb := MockScmModule()
	native, err := (*ScmModule)(pb).ToNative()
	if err != nil {
		t.Fatal(err)
	}
	expNative := storage.MockScmModule()

	if diff := cmp.Diff(expNative, native); diff != "" {
		t.Fatalf("unexpected result (-want, +got):\n%s\n", diff)
	}
}

func TestProto_ConvertScmModules(t *testing.T) {
	pbs := []*ctlpb.ScmModule{
		MockScmModule(1),
		MockScmModule(2),
		MockScmModule(3),
	}
	natives, err := (*ScmModules)(&pbs).ToNative()
	if err != nil {
		t.Fatal(err)
	}

	var convertedNatives ScmModules
	if err := convertedNatives.FromNative(natives); err != nil {
		t.Fatal(err)
	}

	opts := common.DefaultCmpOpts()
	if diff := cmp.Diff(pbs,
		([]*ctlpb.ScmModule)(convertedNatives), opts...); diff != "" {

		t.Fatalf("unexpected result (-want, +got):\n%s\n", diff)
	}
}

func TestProto_ConvertScmMountPoint(t *testing.T) {
	a := storage.MockScmMountPoint()
	resA, _ := json.Marshal(a)

	var b storage.ScmMountPoint
	if err := json.Unmarshal(resA, &b); err != nil {
		t.Fatal(err)
	}

	opts := common.DefaultCmpOpts()
	if diff := cmp.Diff(a, &b, opts...); diff != "" {
		t.Fatalf("unexpected result (-want, +got):\n%s\n", diff)
	}

	pb := MockScmMountPoint()
	native, err := (*ScmMountPoint)(pb).ToNative()
	if err != nil {
		t.Fatal(err)
	}
	expNative := storage.MockScmMountPoint()

	if diff := cmp.Diff(expNative, native, opts...); diff != "" {
		t.Fatalf("unexpected result (-want, +got):\n%s\n", diff)
	}
}

func TestProto_ConvertScmNamespace(t *testing.T) {
	pb := MockScmNamespace()
	pb.Mount = MockScmMountPoint()
	native, err := (*ScmNamespace)(pb).ToNative()
	if err != nil {
		t.Fatal(err)
	}
	expNative := storage.MockScmNamespace()
	expNative.Mount = storage.MockScmMountPoint()

	opts := common.DefaultCmpOpts()
	if diff := cmp.Diff(expNative, native, opts...); diff != "" {
		t.Fatalf("unexpected result (-want, +got):\n%s\n", diff)
	}
}

func TestProto_ConvertScmNamespaces(t *testing.T) {
	pbs := []*ctlpb.ScmNamespace{
		MockScmNamespace(1),
		MockScmNamespace(2),
		MockScmNamespace(3),
	}
	natives, err := (*ScmNamespaces)(&pbs).ToNative()
	if err != nil {
		t.Fatal(err)
	}

	var convertedNatives ScmNamespaces
	if err := convertedNatives.FromNative(natives); err != nil {
		t.Fatal(err)
	}
	opts := common.DefaultCmpOpts()
	if diff := cmp.Diff(pbs,
		([]*ctlpb.ScmNamespace)(convertedNatives), opts...); diff != "" {

		t.Fatalf("unexpected result (-want, +got):\n%s\n", diff)
	}
}
