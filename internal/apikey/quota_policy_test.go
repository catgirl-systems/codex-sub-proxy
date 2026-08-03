package apikey

import (
	"context"
	"testing"
	"time"
)

func TestCreateRejectsInvalidQuotaPolicyCombinations(t *testing.T) {
	db := testAPIKeyDatabase(t)
	cases := []Policy{
		{
			Name:                 "rolling-window-without-count",
			Owner:                "owner",
			AllowedEndpoints:     []string{"/v1/responses"},
			RollingRequestWindow: time.Minute,
		},
		{
			Name:             "period-limit-without-duration",
			Owner:            "owner",
			AllowedEndpoints: []string{"/v1/responses"},
			PeriodTokenLimit: 1,
		},
		{
			Name:                    "reservation-default-over-ceiling",
			Owner:                   "owner",
			AllowedEndpoints:        []string{"/v1/responses"},
			TokenReservationDefault: 2,
			TokenReservationCeiling: 1,
		},
	}
	for _, policy := range cases {
		t.Run(policy.Name, func(t *testing.T) {
			if _, _, err := Create(context.Background(), db, []byte("hmac"), policy); err == nil {
				t.Fatal("invalid quota policy was accepted")
			}
		})
	}
}

func TestPolicyPreservesDisabledQuotaZeros(t *testing.T) {
	db := testAPIKeyDatabase(t)
	_, record, err := Create(context.Background(), db, []byte("hmac"), Policy{
		Name:             "disabled",
		Owner:            "owner",
		AllowedEndpoints: []string{"/v1/responses"},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := record.Policy()
	if err != nil {
		t.Fatal(err)
	}
	if policy.MaxConcurrentRequests != 0 || policy.RollingRequestCount != 0 || policy.RollingRequestWindow != 0 ||
		policy.PeriodRequestLimit != 0 || policy.PeriodTokenLimit != 0 || policy.PeriodImageLimit != 0 ||
		policy.PeriodCostMicrounitLimit != 0 || policy.PeriodDuration != 0 || policy.TokenReservationDefault != 0 ||
		policy.TokenReservationCeiling != 0 || policy.ImageReservationDefault != 0 || policy.ImageReservationCeiling != 0 ||
		policy.CostMicrounitReservationDefault != 0 || policy.CostMicrounitReservationCeiling != 0 {
		t.Fatalf("policy quota values = %#v", policy)
	}
}
