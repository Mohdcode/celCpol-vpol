

# Policy Converter

This tool helps migrate from **ClusterPolicy** with `validate.cel` rules to **ValidatingPolicy** format.

## Build

```bash
go build
```

## Usage

```bash
./policy-converter -in clusterpolicy.yaml -out validatingpolicy.yaml
```

## Notes

* Currently supports converting a single `ClusterPolicy` with `validate.cel` rules.
* Work in progress to:

  * Support multiple constraints.
  * Validate the structure of the policy before conversion.
  * Handle multiple `validate.cel` rules.
  * Dynamic fetching of apiGroup and Version from kind.

## Example Conversion

### Clusterpolicy with validate.cel rule

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: advanced-restrict-image-registries
  annotations:
    policies.kyverno.io/title: Advanced Restrict Image Registries in CEL expressions
    policies.kyverno.io/category: Other in CEL 
    policies.kyverno.io/severity: medium
    kyverno.io/kyverno-version: 1.11.0
    policies.kyverno.io/minversion: 1.11.0
    kyverno.io/kubernetes-version: "1.26-1.27"
    policies.kyverno.io/subject: Pod
    policies.kyverno.io/description: >-
      In instances where a ClusterPolicy defines all the approved image registries
      is insufficient, more granular control may be needed to set permitted registries,
      especially in multi-tenant use cases where some registries may be based on
      the Namespace. This policy shows an advanced version of the Restrict Image Registries
      policy which gets a global approved registry from a ConfigMap and, based upon an
      annotation at the Namespace level, gets the registry approved for that Namespace.
spec:
  validationFailureAction: Audit
  background: true
  webhookConfiguration:
      failurePolicy: Ignore
      timeoutSeconds: 30
  rules:
    - name: validate-corp-registries
      match:
        any:
        - resources:
            kinds:
            - Pod
            operations:
            - CREATE
            - UPDATE
      validate:
        cel:
          paramKind: 
            apiVersion: v1
            kind: ConfigMap
          paramRef: 
            name: clusterregistries
            namespace: default
            parameterNotFoundAction: Deny
          variables:
            - name: allContainers
              expression: "object.spec.containers + object.spec.?initContainers.orValue([]) + object.spec.?ephemeralContainers.orValue([])"
            - name: nsregistries
              expression: >-
                namespaceObject.metadata.?annotations[?'corp.com/allowed-registries'].orValue(' ')
            - name: clusterregistries
              expression: "params.data[?'registries'].orValue(' ')"
          expressions:
            - expression: "variables.allContainers.all(container, container.image.startsWith(variables.nsregistries) || container.image.startsWith(variables.clusterregistries))"
              message: This Pod names an image that is not from an approved registry.


```
To

```yaml
apiVersion: policies.kyverno.io/v1alpha1
kind: ValidatingPolicy
metadata:
    annotations:
        kyverno.io/kubernetes-version: 1.26-1.27
        kyverno.io/kyverno-version: 1.11.0
        policies.kyverno.io/category: Other in CEL
        policies.kyverno.io/description: In instances where a ClusterPolicy defines all the approved image registries is insufficient, more granular control may be needed to set permitted registries, especially in multi-tenant use cases where some registries may be based on the Namespace. This policy shows an advanced version of the Restrict Image Registries policy which gets a global approved registry from a ConfigMap and, based upon an annotation at the Namespace level, gets the registry approved for that Namespace.
        policies.kyverno.io/minversion: 1.11.0
        policies.kyverno.io/severity: medium
        policies.kyverno.io/subject: Pod
        policies.kyverno.io/title: Advanced Restrict Image Registries in CEL expressions
    name: advanced-restrict-image-registries
spec:
    WebhookConfiguration:
        failurePolicy: Ignore
        timeoutSeconds: 30
    evaluation:
        admission:
            enabled: false
        background:
            enabled: true
    failurePolicy: Ignore
    matchConstraints:
        resourceRules:
            - apiGroups:
                - ""
              apiVersions:
                - v1
              operations:
                - CREATE
                - UPDATE
              resources:
                - pods
    validationActions:
        - Audit
    validations:
        - expression: variables.allContainers.all(container, container.image.startsWith(variables.nsregistries) || container.image.startsWith(variables.clusterregistries))
          message: This Pod names an image that is not from an approved registry.
    variables:
        - expression: object.spec.containers + object.spec.?initContainers.orValue([]) + object.spec.?ephemeralContainers.orValue([])
          name: allContainers
        - expression: namespaceObject.metadata.?annotations[?'corp.com/allowed-registries'].orValue(' ')
          name: nsregistries
        - expression: params.data[?'registries'].orValue(' ')
          name: clusterregistries

```
