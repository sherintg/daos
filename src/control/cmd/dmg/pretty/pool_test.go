//
// (C) Copyright 2020-2021 Intel Corporation.
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
//

package pretty

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/dustin/go-humanize"
	"github.com/google/go-cmp/cmp"

	"github.com/daos-stack/daos/src/control/common"
	"github.com/daos-stack/daos/src/control/lib/control"
	"github.com/daos-stack/daos/src/control/system"
)

func TestPretty_PrintPoolQueryResp(t *testing.T) {
	for name, tc := range map[string]struct {
		pqr         *control.PoolQueryResp
		expPrintStr string
	}{
		"empty response": {
			pqr: &control.PoolQueryResp{},
			expPrintStr: `
Pool , ntarget=0, disabled=0, leader=0, version=0
Pool space info:
- Target(VOS) count:0
`,
		},
		"normal response": {
			pqr: &control.PoolQueryResp{
				UUID: common.MockUUID(),
				PoolInfo: control.PoolInfo{
					TotalTargets:    2,
					DisabledTargets: 1,
					ActiveTargets:   1,
					Leader:          42,
					Version:         100,
					Rebuild: &control.PoolRebuildStatus{
						State:   control.PoolRebuildStateBusy,
						Objects: 42,
						Records: 21,
					},
					TierStats: []*control.StorageUsageStats{
						{
							Total: 2,
							Free:  1,
						},
						{
							Total: 2,
							Free:  1,
						},
					},
				},
			},
			expPrintStr: fmt.Sprintf(`
Pool %s, ntarget=2, disabled=1, leader=42, version=100
Pool space info:
- Target(VOS) count:1
- Storage tier 0 (SCM):
  Total size: 2 B
  Free: 1 B, min:0 B, max:0 B, mean:0 B
- Storage tier 1 (NVMe):
  Total size: 2 B
  Free: 1 B, min:0 B, max:0 B, mean:0 B
Rebuild busy, 42 objs, 21 recs
`, common.MockUUID()),
		},
		"rebuild failed": {
			pqr: &control.PoolQueryResp{
				UUID: common.MockUUID(),
				PoolInfo: control.PoolInfo{
					TotalTargets:    2,
					DisabledTargets: 1,
					ActiveTargets:   1,
					Leader:          42,
					Version:         100,
					Rebuild: &control.PoolRebuildStatus{
						Status:  2,
						State:   control.PoolRebuildStateBusy,
						Objects: 42,
						Records: 21,
					},
					TierStats: []*control.StorageUsageStats{
						{
							Total: 2,
							Free:  1,
						},
						{
							Total: 2,
							Free:  1,
						},
					},
				},
			},
			expPrintStr: fmt.Sprintf(`
Pool %s, ntarget=2, disabled=1, leader=42, version=100
Pool space info:
- Target(VOS) count:1
- Storage tier 0 (SCM):
  Total size: 2 B
  Free: 1 B, min:0 B, max:0 B, mean:0 B
- Storage tier 1 (NVMe):
  Total size: 2 B
  Free: 1 B, min:0 B, max:0 B, mean:0 B
Rebuild failed, rc=0, status=2
`, common.MockUUID()),
		},
	} {
		t.Run(name, func(t *testing.T) {
			var bld strings.Builder
			if err := PrintPoolQueryResponse(tc.pqr, &bld); err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(strings.TrimLeft(tc.expPrintStr, "\n"), bld.String()); diff != "" {
				t.Fatalf("unexpected format string (-want, +got):\n%s\n", diff)
			}
		})
	}
}

func mockRanks(ranks ...uint32) []uint32 {
	return ranks
}

func TestPretty_PrintPoolCreateResp(t *testing.T) {
	for name, tc := range map[string]struct {
		pcr         *control.PoolCreateResp
		expPrintStr string
		expErr      error
	}{
		"nil response": {
			expErr: errors.New("nil response"),
		},
		"empty response": {
			pcr:    &control.PoolCreateResp{},
			expErr: errors.New("0 storage tiers"),
		},
		"basic": {
			pcr: &control.PoolCreateResp{
				UUID:     common.MockUUID(),
				SvcReps:  mockRanks(0, 1, 2),
				TgtRanks: mockRanks(0, 1, 2, 3),
				TierBytes: []uint64{
					600 * humanize.MByte,
					10 * humanize.GByte,
				},
			},
			expPrintStr: fmt.Sprintf(`
Pool created with 5.66%%%%,94.34%%%% storage tier ratio
---------------------------------------------------
  UUID                 : %s
  Service Ranks        : [0-2]                               
  Storage Ranks        : [0-3]                               
  Total Size           : 42 GB                               
  Storage tier 0 (SCM) : 2.4 GB (600 MB / rank)              
  Storage tier 1 (NVMe): 40 GB (10 GB / rank)                

`, common.MockUUID()),
		},
		"no nvme": {
			pcr: &control.PoolCreateResp{
				UUID:     common.MockUUID(),
				SvcReps:  mockRanks(0, 1, 2),
				TgtRanks: mockRanks(0, 1, 2, 3),
				TierBytes: []uint64{
					600 * humanize.MByte,
				},
			},
			expPrintStr: fmt.Sprintf(`
Pool created with 100.00%%%% storage tier ratio
---------------------------------------------
  UUID                 : %s
  Service Ranks        : [0-2]                               
  Storage Ranks        : [0-3]                               
  Total Size           : 2.4 GB                              
  Storage tier 0 (SCM) : 2.4 GB (600 MB / rank)              

`, common.MockUUID()),
		},
	} {
		t.Run(name, func(t *testing.T) {
			var bld strings.Builder
			gotErr := PrintPoolCreateResponse(tc.pcr, &bld)
			common.CmpErr(t, tc.expErr, gotErr)
			if tc.expErr != nil {
				return
			}

			if diff := cmp.Diff(strings.TrimLeft(tc.expPrintStr, "\n"), bld.String()); diff != "" {
				t.Fatalf("unexpected format string (-want, +got):\n%s\n", diff)
			}
		})
	}
}

func TestPretty_PrintListPoolsResponse(t *testing.T) {
	exampleUsage := []*control.PoolTierUsage{
		{
			TierName:  "SCM",
			Size:      100 * humanize.GByte,
			Free:      20 * humanize.GByte,
			Imbalance: 12,
		},
		{
			TierName:  "NVME",
			Size:      6 * humanize.TByte,
			Free:      1 * humanize.TByte,
			Imbalance: 1,
		},
	}

	for name, tc := range map[string]struct {
		resp        *control.ListPoolsResp
		verbose     bool
		expErr      error
		expPrintStr string
	}{
		"empty response": {
			resp: &control.ListPoolsResp{},
			expPrintStr: `
no pools in system
`,
		},
		"one pool; no usage": {
			resp: &control.ListPoolsResp{
				Pools: []*control.Pool{
					{
						UUID:            common.MockUUID(1),
						ServiceReplicas: []system.Rank{0, 1, 2},
					},
				},
			},
			expPrintStr: `
Pool     Size Used Imbalance Disabled 
----     ---- ---- --------- -------- 
00000001 0 B  0%   0%        0/0      

`,
		},
		"one pool; no uuid": {
			resp: &control.ListPoolsResp{
				Pools: []*control.Pool{
					{
						ServiceReplicas: []system.Rank{0, 1, 2},
						Usage:           exampleUsage,
					},
				},
			},
			expErr: errors.New("no uuid"),
		},
		"two pools; diff num tiers": {
			resp: &control.ListPoolsResp{
				Pools: []*control.Pool{
					{
						UUID:            common.MockUUID(1),
						ServiceReplicas: []system.Rank{0, 1, 2},
						Usage:           exampleUsage,
						TargetsTotal:    16,
						TargetsDisabled: 0,
					},
					{
						UUID:            common.MockUUID(2),
						Label:           "one",
						ServiceReplicas: []system.Rank{3, 4, 5},
						Usage:           exampleUsage[1:],
						TargetsTotal:    64,
						TargetsDisabled: 8,
					},
				},
			},
			expErr: errors.New("has 1 storage tiers, want 2"),
		},
		"two pools; only one labeled": {
			resp: &control.ListPoolsResp{
				Pools: []*control.Pool{
					{
						UUID:            common.MockUUID(1),
						ServiceReplicas: []system.Rank{0, 1, 2},
						Usage:           exampleUsage,
						TargetsTotal:    16,
						TargetsDisabled: 0,
					},
					{
						Label:           "two",
						UUID:            common.MockUUID(2),
						ServiceReplicas: []system.Rank{3, 4, 5},
						Usage:           exampleUsage,
						TargetsTotal:    64,
						TargetsDisabled: 8,
					},
				},
			},
			expPrintStr: `
Pool     Size   Used Imbalance Disabled 
----     ----   ---- --------- -------- 
00000001 6.0 TB 83%  12%       0/16     
two      6.0 TB 83%  12%       8/64     

`,
		},
		"two pools; one SCM only": {
			resp: &control.ListPoolsResp{
				Pools: []*control.Pool{
					{
						Label:           "one",
						UUID:            common.MockUUID(1),
						ServiceReplicas: []system.Rank{0, 1, 2},
						Usage:           exampleUsage,
						TargetsTotal:    16,
						TargetsDisabled: 0,
					},
					{
						Label:           "two",
						UUID:            common.MockUUID(2),
						ServiceReplicas: []system.Rank{3, 4, 5},
						Usage: []*control.PoolTierUsage{
							exampleUsage[0],
							&control.PoolTierUsage{TierName: "NVME"},
						},
						TargetsTotal:    64,
						TargetsDisabled: 8,
					},
				},
			},
			expPrintStr: `
Pool Size   Used Imbalance Disabled 
---- ----   ---- --------- -------- 
one  6.0 TB 83%  12%       0/16     
two  100 GB 80%  12%       8/64     

`,
		},
		"two pools; one failed query": {
			resp: &control.ListPoolsResp{
				Pools: []*control.Pool{
					{
						Label:           "one",
						UUID:            common.MockUUID(1),
						ServiceReplicas: []system.Rank{0, 1, 2},
						Usage:           exampleUsage,
						TargetsTotal:    16,
						TargetsDisabled: 0,
					},
					{
						Label:           "two",
						UUID:            common.MockUUID(2),
						ServiceReplicas: []system.Rank{3, 4, 5},
						QueryErrorMsg:   "stats unavailable",
					},
				},
			},
			expPrintStr: `
Query on pool "two" unsuccessful, error: "stats unavailable"

Pool Size   Used Imbalance Disabled 
---- ----   ---- --------- -------- 
one  6.0 TB 83%  12%       0/16     

`,
		},
		"three pools; one failed query; one query bad status": {
			resp: &control.ListPoolsResp{
				Pools: []*control.Pool{
					{
						Label:           "one",
						UUID:            common.MockUUID(1),
						ServiceReplicas: []system.Rank{0, 1, 2},
						Usage:           exampleUsage,
						TargetsTotal:    16,
						TargetsDisabled: 0,
					},
					{
						UUID:            common.MockUUID(2),
						ServiceReplicas: []system.Rank{3, 4, 5},
						QueryErrorMsg:   "stats unavailable",
					},
					{
						Label:           "three",
						UUID:            common.MockUUID(3),
						ServiceReplicas: []system.Rank{3, 4, 5},
						QueryStatusMsg:  "DER_UNINIT",
					},
				},
			},
			expPrintStr: `
Query on pool "00000002" unsuccessful, error: "stats unavailable"
Query on pool "three" unsuccessful, status: "DER_UNINIT"

Pool Size   Used Imbalance Disabled 
---- ----   ---- --------- -------- 
one  6.0 TB 83%  12%       0/16     

`,
		},
		"verbose, empty response": {
			resp:    &control.ListPoolsResp{},
			verbose: true,
			expPrintStr: `
no pools in system
`,
		},
		"verbose; zero svc replicas": {
			resp: &control.ListPoolsResp{
				Pools: []*control.Pool{
					{
						UUID:            common.MockUUID(1),
						Usage:           exampleUsage,
						TargetsTotal:    16,
						TargetsDisabled: 0,
					},
				},
			},
			verbose: true,
			expPrintStr: `
Label UUID                                 SvcReps SCM Size SCM Used SCM Imbalance NVME Size NVME Used NVME Imbalance Disabled 
----- ----                                 ------- -------- -------- ------------- --------- --------- -------------- -------- 
-     00000001-0001-0001-0001-000000000001 N/A     100 GB   80 GB    12%           6.0 TB    5.0 TB    1%             0/16     

`,
		},
		"verbose; two pools": {
			resp: &control.ListPoolsResp{
				Pools: []*control.Pool{
					{
						Label:           "one",
						UUID:            common.MockUUID(1),
						ServiceReplicas: []system.Rank{0, 1, 2},
						Usage:           exampleUsage,
						TargetsTotal:    16,
						TargetsDisabled: 0,
					},
					{
						Label:           "two",
						UUID:            common.MockUUID(2),
						ServiceReplicas: []system.Rank{3, 4, 5},
						Usage:           exampleUsage,
						TargetsTotal:    64,
						TargetsDisabled: 8,
					},
				},
			},
			verbose: true,
			expPrintStr: `
Label UUID                                 SvcReps SCM Size SCM Used SCM Imbalance NVME Size NVME Used NVME Imbalance Disabled 
----- ----                                 ------- -------- -------- ------------- --------- --------- -------------- -------- 
one   00000001-0001-0001-0001-000000000001 [0-2]   100 GB   80 GB    12%           6.0 TB    5.0 TB    1%             0/16     
two   00000002-0002-0002-0002-000000000002 [3-5]   100 GB   80 GB    12%           6.0 TB    5.0 TB    1%             8/64     

`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			var bld strings.Builder

			// pass the same io writer to standard and error stream
			// parameters to mimic combined output seen on terminal
			err := PrintListPoolsResponse(&bld, &bld, tc.resp, tc.verbose)
			common.CmpErr(t, tc.expErr, err)
			if tc.expErr != nil {
				return
			}

			if diff := cmp.Diff(strings.TrimLeft(tc.expPrintStr, "\n"), bld.String()); diff != "" {
				t.Fatalf("unexpected format string (-want, +got):\n%s\n", diff)
			}
		})
	}
}
