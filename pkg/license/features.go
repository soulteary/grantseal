package license

import "sort"

// defaultEditionFeatures maps each edition to the features it implicitly grants.
// A license's explicit Features list is unioned with these defaults, so an
// issuer can grant extra features on top of the edition baseline.
var defaultEditionFeatures = map[Edition][]string{
	EditionTrial:        {"core"},
	EditionBasic:        {"core", "reports"},
	EditionProfessional: {"core", "reports", "api", "sso"},
	EditionEnterprise:   {"core", "reports", "api", "sso", "audit", "priority_support"},
}

// EffectiveFeatures returns the sorted, de-duplicated union of the edition's
// default features and the license's explicit features.
func EffectiveFeatures(p *Payload) []string {
	set := make(map[string]struct{})
	for _, f := range defaultEditionFeatures[p.Edition] {
		set[f] = struct{}{}
	}
	for _, f := range p.Features {
		if f != "" {
			set[f] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// featureSet builds a lookup set of effective features.
func featureSet(p *Payload) map[string]struct{} {
	out := make(map[string]struct{})
	for _, f := range EffectiveFeatures(p) {
		out[f] = struct{}{}
	}
	return out
}
