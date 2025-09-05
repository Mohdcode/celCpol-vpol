package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	// "github.com/kyverno/kyverno/pkg/config"
	// policyvalidation "github.com/kyverno/kyverno/pkg/validation/policy"

	yaml "sigs.k8s.io/kustomize/kyaml/yaml"
	// "gopkg.in/yaml.v3"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes/scheme"
)

type ClusterPolicy struct {
	APIVersion string                 `yaml:"apiVersion"`
	Kind       string                 `yaml:"kind"`
	Metadata   map[string]interface{} `yaml:"metadata"`
	Spec       struct {
		WebhookConfiguration struct {
			TimeoutSecond int8   `yaml:"timeoutSeconds"`
			FailurePolicy string `yaml:"failurePolicy"`
		} `yaml:"webhookConfiguration"`
		ValidationFailureAction string `yaml:"validationFailureAction"`
		Admission               bool   `yaml:"admission"`
		Background              bool   `yaml:"background"`
		Rules                   []Rule `yaml:"rules"`
	} `yaml:"spec"`
}

type Rule struct {
	Name             string                   `yaml:"name"`
	Match            map[string]interface{}   `yaml:"match"`
	CelPreconditions []map[string]interface{} `yaml:"celPreconditions"`
	Validate         struct {
		Cel struct {
			ParamKind   map[string]interface{}   `yaml:"paramKind"`
			ParamRef    map[string]interface{}   `yaml:"paramRef"`
			Variables   []map[string]interface{} `yaml:"variables"`
			Expressions []map[string]interface{} `yaml:"expressions"`
		} `yaml:"cel"`
	} `yaml:"validate"`
}

type ValidatingPolicy struct {
	APIVersion string                 `yaml:"apiVersion"`
	Kind       string                 `yaml:"kind"`
	Metadata   map[string]interface{} `yaml:"metadata"`
	Spec       map[string]interface{} `yaml:"spec"`
}

// getGVRFromKind resolves GroupVersionResource for a given Kind using the Kubernetes scheme
func getResourceFromKind(kind string) (string, error) {
	// Build a RESTMapper only from the known types registered in scheme.Scheme
	restMapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{})

	for gvk := range scheme.Scheme.AllKnownTypes() {
		// scope could be Namespace or Cluster, but for static mapping
		// we can just pick Namespace by default
		restMapper.Add(gvk, meta.RESTScopeNamespace)
	}

	mapping, err := restMapper.RESTMapping(schema.GroupKind{Kind: kind})
	if err != nil {
		log.Print("didn't excute")
		log.Printf("this is the err %s,", err)
		// fallback for irregular plurals
		switch kind {
		case "Ingress":
			return "ingresses", nil
		case "Policy":
			return "policies", nil
		case "NetworkPolicy":
			return "networkpolicies", nil
		}
		// generic fallback: just lowercase + "s"
		return strings.ToLower(kind) + "s", nil
	}

	return mapping.Resource.Resource, nil
}

func toStringSlice(raw interface{}) []string {
	if raw == nil {
		return nil
	}
	switch t := raw.(type) {
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, v := range t {
			out = append(out, fmt.Sprintf("%v", v))
		}
		return out
	case []string:
		return t
	default:
		return []string{fmt.Sprintf("%v", raw)}
	}
}

func convert(cp ClusterPolicy) (ValidatingPolicy, error) {
	if !strings.HasPrefix(cp.APIVersion, "kyverno.io/v") {
		fmt.Println("Input is not a Kyverno ClusterPolicy. Skipping conversion.")
		os.Exit(0)
	}

	var controllers []string
	if anns, ok := cp.Metadata["annotations"].(map[string]interface{}); ok {
		if val, ok := anns["pod-policies.kyverno.io/autogen-controllers"].(string); ok {
			if strings.ToLower(val) != "none" {
				for _, c := range strings.Split(val, ",") {
					controllers = append(controllers, strings.ToLower(strings.TrimSpace(c))+"s")
				}
			}
		}
		delete(anns, "pod-policies.kyverno.io/autogen-controllers")
	}

	// Copy metadata to avoid mutating input
	metaCopy := map[string]interface{}{}
	for k, v := range cp.Metadata {
		metaCopy[k] = v
	}
	if anns, ok := metaCopy["annotations"].(map[string]interface{}); ok && len(anns) == 0 {
		delete(metaCopy, "annotations")
	}

	vp := ValidatingPolicy{
		APIVersion: "policies.kyverno.io/v1alpha1",
		Kind:       "ValidatingPolicy",
		Metadata:   metaCopy,
		Spec:       map[string]interface{}{},
	}

	if cp.Spec.ValidationFailureAction != "" {
		if cp.Spec.ValidationFailureAction == "Enforce" {
			vp.Spec["validatingActions"] = []string{"Deny"}
		} else {
			vp.Spec["validationActions"] = []string{cp.Spec.ValidationFailureAction}
		}

	}
	vp.Spec["failurePolicy"] = cp.Spec.WebhookConfiguration.FailurePolicy
	vp.Spec["WebhookConfiguration"] = map[string]interface{}{
		"timeoutSeconds": cp.Spec.WebhookConfiguration.TimeoutSecond,
	}

	vp.Spec["evaluation"] = map[string]interface{}{
		"background": map[string]bool{"enabled": cp.Spec.Background},
		"admission":  map[string]bool{"enabled": cp.Spec.Admission},
	}

	var resourceRules []map[string]interface{}
	var matchConditions []map[string]interface{}
	var variables []map[string]interface{}
	var validations []map[string]interface{}

	for _, rule := range cp.Spec.Rules {
		if matchAny, ok := rule.Match["any"].([]interface{}); ok {
			for _, m := range matchAny {
				rm, ok := m.(map[string]interface{})
				if !ok {
					continue
				}
				resourcesObj, ok := rm["resources"].(map[string]interface{})
				if !ok {
					continue
				}

				ops := toStringSlice(resourcesObj["operations"])
				if len(ops) == 0 {
					ops = []string{"CREATE", "UPDATE"}
				}

				kindsRaw, _ := resourcesObj["kinds"].([]interface{})
				resourceSet := sets.NewString()

				for _, k := range kindsRaw {
					kindStr := fmt.Sprintf("%v", k)
					gvr, err := getResourceFromKind(kindStr)
					if err != nil {
						// fallback (should rarely happen)
						return ValidatingPolicy{}, fmt.Errorf("failed to get gvr, %s", err)
					}
					resourceSet.Insert(gvr)
				}

				resourceRules = append(resourceRules, map[string]interface{}{
					"operations": ops,
					"resources":  resourceSet.List(),
				})
			}
		}

		if len(rule.CelPreconditions) > 0 {
			matchConditions = append(matchConditions, rule.CelPreconditions...)
		}
		if len(rule.Validate.Cel.Variables) > 0 {
			variables = append(variables, rule.Validate.Cel.Variables...)
		}
		if len(rule.Validate.Cel.Expressions) > 0 {
			for _, expr := range rule.Validate.Cel.Expressions {
				val := map[string]interface{}{}
				if exp, ok := expr["expression"].(string); ok {
					val["expression"] = exp

				}
				log.Print(val)

				if msg, ok := expr["message"].(string); ok {
					val["message"] = msg
				}
				if msg, ok := expr["messageExpression"].(string); ok {
					val["messageExpression"] = msg
				}

				validations = append(validations, val)
			}
		}
	}

	if len(resourceRules) > 0 {
		vp.Spec["matchConstraints"] = map[string]interface{}{
			"resourceRules": resourceRules,
		}
	}
	if len(matchConditions) > 0 {
		vp.Spec["matchConditions"] = matchConditions
	}
	if len(variables) > 0 {
		vp.Spec["variables"] = variables
	}
	if len(validations) > 0 {
		vp.Spec["validations"] = validations
	}
	if len(controllers) > 0 {
		vp.Spec["autogen"] = map[string]interface{}{
			"podControllers": map[string]interface{}{
				"controllers": controllers,
			},
		}
	}

	return vp, nil
}

func main() {
	in := flag.String("in", "", "Input ClusterPolicy YAML file")
	out := flag.String("out", "", "Output ValidatingPolicy YAML file")
	flag.Parse()

	if *in == "" || *out == "" {
		fmt.Println("Usage: -in <input.yaml> -out <output.yaml>")
		os.Exit(1)
	}

	data, err := os.ReadFile(*in)
	if err != nil {
		panic(err)
	}
	// sa := config.KyvernoUserName(config.KyvernoServiceAccountName())
	// _, err = policyvalidation.Validate(data, nil, nil, true, sa, sa)
	// if err != nil {
	// 	fmt.Errorf("Error is %s", err)
	// }

	var cp ClusterPolicy
	if err := yaml.Unmarshal(data, &cp); err != nil {
		panic(err)
	}

	vp, err := convert(cp)
	if err != nil {
		panic(err)
	}
	outData, err := yaml.Marshal(vp)
	log.Print(string(outData))
	if err != nil {
		panic(err)
	}

	if err := os.WriteFile(*out, outData, 0644); err != nil {
		panic(err)
	}
}
