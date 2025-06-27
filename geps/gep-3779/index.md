# GEP-3779: Identity Based Authz for East-West Traffic

* Issue: [#3779](https://github.com/kubernetes-sigs/gateway-api/issues/3779)
* Status: Provisional

(See [status definitions](../overview.md#gep-states).)


## TLDR

Provide a method for configuring Gateway API Mesh implementations to enforce east-west identity-based Authorization controls. At the time of writing this we leave Authentication for specific implementation and outside of this proposal scope.


## Goals

(Using the [Gateway API Personas](../../concepts/roles-and-personas.md))

* A way for Ana the Application Developer to configure a Gateway API for Mesh implementation to enforce authorization policy that **allows** or **denies** identity or multiple identities to talk with some set of the workloads she controls.

* A way for Chihiro, the Cluster Admin, to configure a Gateway API for Mesh implementation to enforce non-overridable cluster-wide, authorization policies that **allows** or **denies** identity or multiple identities to talk with some set of the workloads in the cluster.

* A way for both Ana and Chihiro to restrict the scope of the policies they deploy to specific ports.

## Stretch Goals

* A way for Chihiro, the Cluster Admin, to configure a Gateway API for Mesh implementation to enforce default, overridable, cluster-wide, authorization policies that **allows** or **denies** identity or multiple identities to talk with some set of the workloads in the cluster.

## Non-Goals

* Support identity based authorization for north-south traffic or define the composition with this API.

## Deferred Goals

* (Potentially) Support enforcement on attributes beyond identities and ports.

## Introduction

Authorization is positioned as one of core mesh values. Every mesh supports some kind of east/west authorization between the workloads it controls.

Kubernetes core provides NetworkPolicies as one way to do it. Network Policies however falls short in many ways including:

* Network policies leverage labels as identities.
  * Labels are mutable at runtime. This opens a path for escalating privileges
  * Most implementations of network policies translate labels to IPs, this involves an eventual consistency nature which can and has lea to over permissiveness in the past.

* Scale. Network Policies are enforced using IPs (different selectors in the APIs get translated to IPs). This does not scale well with large clusters or beyond a single cluster

An identity-based authorization API is essential because it provides a structured way to control authorization between identities within the cluster.

### State of the World

Every mesh vendor has their own API of such authorization. Below we describe the UX for different implementations:

<TODO>

#### Istio
Link: [Istio authorization policy docs](https://istio.io/latest/docs/reference/config/security/authorization-policy/)

Authorization policies can be expressed in the form of _ENTITY_ can (or cannot) do _SOMETHING_ (usually something is sending traffic) to 

##### Enforcement Modes

* ALLOW - Allow a request only if it matches the rules. This is the default type.
* DENY - Deny a request if it matches any of the rules.
* CUSTOM - This mode allows an extension to handle the request. A common usecase is [External Authorization](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/ext_authz/v3/ext_authz.proto) 
* AUDIT - Just audit the request


#### Linkerd


#### Cilium



| Aspect | Istio | Linkerd | Cilium |
| ----- | ----- | ----- | ----- |
| **Policy CRDs** | `AuthorizationPolicy` (APIs `security.istio.io/v1`) | `AuthorizationPolicy` (CRD `policy.linkerd.io/v1alpha1`), plus supporting CRDs (`Server`, `HTTPRoute`, `MeshTLSAuthentication`) | `CiliumNetworkPolicy` and `CiliumClusterwideNetworkPolicy`(`cilium.io/v2`) (superset of K8s NetworkPolicy) |
| **Identity model** | Identities derived from mTLS peer certificates (bound to SA): SPIFFE-like principal `<trust-domain>/ns/<namespace>/sa/<serviceaccount>`.  ServiceAccount name Namespaces identity within JWT derived from `request.auth.principal`. IPBlocks and x-forwarded-for ipBlocks | Identities derived from mTLS peer certificates (bound to SA trust domain `identity.linkerd.cluster.local`. Policies reference service accounts or explicit mesh identities (e.g. `webapp.identity.linkerd.cluster.local`). Policies use `requiredAuthenticationRefs` to reference the entities who get authorization. This is a list of targetRefs and it can include ServiceAccounts `MeshTLSAuthentication` \- which represents a set of mesh identities either with a mesh identities strings or reference to serviceAccounts `NetworkAuthentication` \- represents sets of IPs or subnets.  | Pods are assigned security identities derived from their Kubernetes labels (namespace, app labels, etc.). Cilium’s policy matches based on these label-derived identities. (Optional SPIFFE identities are supported via Cilium Service Mesh.) |
| **Enforcement** | For Istio with sidecars \- a proxy on each pod. For ambient, ztunnel node agent enforces mTLS based L4 authorization, L7 authorization is being enforced in waypoints if any.  | Linkerd data-plane proxy (injected into each pod). The proxy enforces policies via mTLS identity checks. | eBPF-based datapath in the Linux kernel (Cilium agent). No sidecar proxy is needed for L3/4. (Cilium’s minimal Envoy is used only for advanced L7 features.) |
| **Request Match criteria** | Fine-grained L7 and L4 matching: HTTP/gRPC methods, paths, headers, ports, SNI, etc., plus source identity (namespace, service account). Policies use logical OR over rules. All match criterias are inline in the policy. See [https://istio.io/latest/docs/reference/config/security/authorization-policy/\#Rule-To](https://istio.io/latest/docs/reference/config/security/authorization-policy/#Rule-To) and [https://istio.io/latest/docs/reference/config/security/authorization-policy/\#Rule-when](https://istio.io/latest/docs/reference/config/security/authorization-policy/#Rule-when)  | Policies can target: A `Server` which describes a set of pods (using fancy label match expressions), and a single port on those pods.  A user can optionally restrict the authorization to a smaller subset of the traffic by targeting an HTTPRoute. (TODO: any plans to support sectionNames?) A namespace \- this indicates that the policy applies to all traffic to all Servers and HTTPRoutes defined in the namespace. Note: We leave `ServerAuthorization` outside the scope as it planned to be deprecated (per linkerd website)  | Primarily identity-based L3/L4 policy: select pods by labels (`endpointSelector`), then allow/deny traffic from other pods or CIDRs. Cilium supports L7 via built-in HTTP parsing: rules can match HTTP methods, paths, Kafka, etc. For example, a CiliumNetworkPolicy can allow only specific HTTP methods/paths on a port. It also supports TLS-aware rules (by integrating with certificates). |
| **Default policies and admin policies** | If **no** ALLOW policy matches, traffic is **allowed** by default. You can deploy an overridable \- default deny by default by deploying an **allow-nothing** policy in either the namespace or istio-system AuthorizationPolicies in the `istio-system` namespace apply to the whole mesh and take precedence. These are not overridable by namespace-level policies.  | Default inbound policy can be set at install time using `proxy.defaultInboundPolicy`. Supported values are: `all-unauthenticated:` allow all traffic. This is the default. `all-authenticated:` allow traffic from meshed clients in the same or from a different cluster (with multi-cluster). `cluster-authenticated:` allow traffic from meshed clients in the same cluster. `cluster-unauthenticated:` allow traffic from both meshed and non-meshed clients in the same cluster. `deny:` all traffic are denied. `audit:` Same as all-unauthenticated but requests get flagged in logs and metrics. Users can override the default policies for namespaces/pods or by setting the [config.linkerd.io/default-inbound-policy](http://config.linkerd.io/default-inbound-policy) annotation There is no support for admin, non overridable policies. | Follows Kubernetes NetworkPolicy semantics by default: if no CiliumNetworkPolicy allows the traffic, it is **allowed** (no implicit deny). Operators must apply explicit deny rules or “default-deny” policies to block traffic. |
| **YAML Configuration** | Istio `AuthorizationPolicy` CRD. E.g., to **allow** a namespace or service-account to call a service: |  |  |

## API

This GEP introduces a new policy resource, `AuthorizationPolicy`, for **identity-based** authorization. The policy defines a target, a single action (`ALLOW` or `DENY`), and a set of rules that include sources (the “who”) and an optional port attribute.

### **Policy Rules**

Each `AuthorizationPolicy` resource contains a list of rules. A request matches the policy if it matches **any** rule in the list (logical OR). Each rule defines multiple matching criteria; a request matches a rule only if it matches **all** criteria within that rule (logical AND).

A rule may specify:

* **Sources:** The source identities to which the rule applies. A request’s identity must match one of the listed sources. Supported source kinds are:  
  * **SPIFFE ID** (e.g., `spiffe://trust.domain/ns/namespace/sa/service-account`)  
  * **Kubernetes ServiceAccount**  
  * **Kubernetes Namespace**  
* **Attributes:** Conditions on the target workload, at the time of writing this, only port is supported. If no attributes are specified, the rule applies to all traffic toward the target.

### **ALLOW Policies**

* An **ALLOW** policy is permissive.  
* A request is allowed if:  
  * It matches at least one rule in any ALLOW policy targeting the workload **and**  
  * It is not explicitly denied by any DENY policy.  
* If no ALLOW policy exists for a workload, traffic is permitted by default, unless any DENY policy applies.

### **DENY Policies**

* A **DENY** policy is restrictive and takes precedence over ALLOW.  
* If a request matches any rule in a DENY policy, it is immediately rejected, regardless of matching ALLOW rules elsewhere.  
* DENY policies enable to define global blocks or exceptions (for example: “block all traffic from Namespace X”).

### **ALLOW vs. DENY Semantics**

* **DENY always wins.** If both an ALLOW and a DENY policy match a request, the DENY policy blocks it.  
* The presence of any authorization policy causes the system to default to **deny-by-default** for matching workloads.
* Another bullet to re-clarify the one above - the default behavior when no policies select a target workload is to allow all traffic. However, **as soon as at least one `AuthorizationPolicy` targets a workload, the model becomes implicitly deny-if-not-allowed**.

### **Target of Authorization**

The `targetRef` of the policy specifies the workload(s) to which the policy applies. Two options are available for `targetRef`:

#### **Option 1: Targeting a Service**

The `targetRef` can point to a Kubernetes `Service`.

**Benefits:**

* **No API Extension Required:** Works with the current PolicyAttachment model in Gateway API without modification.  
* **Simplicity:** Intuitive for users familiar with Kubernetes networking concepts.

**Downsides and Open Questions:**

However, targeting a `Service` introduces several challenges:

1. Authorization cannot be enforced on workloads not exposed via a `Service` - excluding use cases of pods/jobs without a Service.  
2. If a Pod belongs to multiple Services targeted by different authorization policies, precedence rules, may become unclear, leading to unpredictable or insecure outcomes. Even if such rules are explicitly defined, UX could potentially be confusing for users.
3. UX and implementation challenges - are implementations expected to enforce the policy only if the traffic arrived through the specific Service? Or just to take the service selectors and enforce the policy regardless of how the traffic got to the destination?

#### **Option 2: Targeting Pods via Label Selectors**

Alternatively, the `targetRef` can specify a set of pods using a `LabelSelector` for a more flexible and direct approach.

**Benefits:**

* Aligns with established practices. Mesh implementations (Istio, Linkerd, Cilium) already use label selectors as the primary mechanism for targeting workloads in their native authorization policies, creating a consistent user experience.  
* Directly applies policy to pods, avoiding ambiguity present when targeting services. Ensures policies are enforced exactly where intended, regardless of how many services a pod might belong to.  
* Policies can apply to any workload, including pods not exposed via a `Service`, providing a comprehensive authorization solution.

**Downsides and Open Questions:**

The main downside of `LabelSelector` is the huge increase to the complexity of policy discoverability. See below for more info.

**Requirement: Enhancing Policy Attachment:**

This option depends on enhancements to Gateway API’s policy attachment model to support `LabelSelector` as a valid `targetRef`. This capability was discussed and received consensus at KubeCon North America 2024 and was originally in scope for GEP-713 but deferred for a future PR to keep GEP-713 focused on stabilizing what we already have (See [https://github.com/kubernetes-sigs/gateway-api/pull/3609#discussion_r2053376938](https://github.com/kubernetes-sigs/gateway-api/pull/3609#discussion_r2053376938)).

##### **Experimental Pattern**

To mitigate some of the concerns, `LabelSelector` support in policy attachment is designated as an **experimental pattern**.

* **Gateway API Community First:** Allows experimentation within Gateway API policies (like the one in this GEP).  
* Implementations **should not** adopt `LabelSelector` targeting in their own custom policies attached to Gateway API resources until the pattern is sufficiently battle-tested and promoted to a standard feature. This staged approach mitigates risks of ecosystem fragmentation.

Here is how it is going to look like:

```go

// PolicyTargetReferenceWithLabelSelectors specifies a reference to a set of Kubernetes
// objects by Group and Kind, with an optional label selector to narrow down the matching
// objects.
//
// Currently, we only support label selectors when targeting Pods.
// This restriction is intentional to limit the complexity and potential
// ambiguity of supporting label selectors for arbitrary Kubernetes kinds.
// Unless there is a very strong justification in the future, we plan to keep this
// functionality limited to selecting Pods only.
//
// This is currently experimental in the Gateway API and should only be used
// for policies implemented within Gateway API. It is currently not intended for general-purpose
// use outside of Gateway API resources.
// +kubebuilder:validation:CEL=expression="!(has(selector)) || (kind == 'Pod' && (group == 'core' || group == ''))",message="Selector can only be set when kind is Pod and group is \"core\" or empty."
type PolicyTargetReferenceWithLabelSelectors struct {
  // Group is the group of the target object.
  Group Group `json:"group"`

  // Kind is the kind of the target object.
  Kind Kind `json:"kind"`

  // Selector is the label selector of target objects of the specified kind.
  Selector *metav1.LabelSelector `json:"selector"`
}

```

##### **Enhanced Discoverability with `gwctl`**

A key challenge with `LabelSelector` is the loss of discoverability. It’s easier to see which policies target a `Service` but difficult to determine which policies might affect a specific pod.

To address this, **investment in tooling is required.** Specifically, the `gwctl` CLI tool should be enhanced to provide insights such as:

```sh
TODO: complete gwctl commands
```

Without dedicated tooling, the `LabelSelector` approach could significantly degrade the user experience and observability.

### API Design

```go

type AuthorizationPolicy struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`

    // Spec defines the desired state of AuthorizationPolicy.
    Spec AuthorizationPolicySpec `json:"spec,omitempty"`

    // Status defines the current state of AuthorizationPolicy.
    Status PolicyStatus `json:"status,omitempty"`
}

// AuthorizationPolicyAction specifies the action to take.
// +kubebuilder:validation:Enum=ALLOW;DENY
type AuthorizationPolicyAction string

const (
    // ActionAllow allows requests that match the policy rules.
    ActionAllow AuthorizationPolicyAction = "ALLOW"
    // ActionDeny denies requests that match the policy rules.
    ActionDeny AuthorizationPolicyAction = "DENY"
)

// AuthorizationPolicySpec defines the desired state of AuthorizationPolicy.
type AuthorizationPolicySpec struct {
    // TargetRef identifies the resource this policy is attached to.
    // +kubebuilder:validation:Required
    TargetRef gatewayv1.PolicyTargetReference `json:"targetRef"`

    // Action specifies the action to take when a request matches the rules.
    // +kubebuilder:validation:Required
    Action AuthorizationPolicyAction `json:"action"`

    // TCPRules defines the list of matching criteria. A request is considered to
    // match the policy if it matches any of the rules.
    // +optional
    TCPRules []AuthorizationTCPRule `json:"tcpRules,omitempty"`
}

// AuthorizationTCPRule defines a set of criteria for matching a TCP request.
// A request must match all specified criteria.
type AuthorizationTCPRule struct {
    // Sources specifies a list of identities that are matched by this rule.
    // If this field is empty, this rule matches all sources.
    // A request matches if its identity is present in this list.
    // +optional
    Sources []AuthorizationSource `json:"sources,omitempty"`

    // Attributes specifies a list of properties that are matched by this rule.
    // If this field is empty, this rule matches all attributes.
    // A request matches if its attributes are present in this list.
    //
    // +optional
    Attributes []AuthorizationTCPAttributes `json:"attributes,omitempty"`
}


// AuthorizationSource specifies the source of a request.
// Only one of its fields may be set.
// TODO(liorlieberman): Add CEL validation that only one field is set
type AuthorizationSource struct {

    // Identities specifies a list of identities in SPIFFE format (e.g.,
    // "spiffe://trust.domain/ns/namespace/sa/service-account") that are
    // matched by this rule. A request's identity must be present in this list
    // to match the rule.

    // Identities for authorization can be derived in various ways by the underlying
    // implementation. Common methods include:
    // - From peer mTLS certificates: The identity is extracted from the client's
    //   mTLS certificate presented during connection establishment.
    // - From IP-to-identity mappings: The implementation might maintain a dynamic
    //   mapping between source IP addresses (pod IPs) and their associated
    //   identities (e.g., Service Account, SPIFFE IDs).
    // - From JWTs or other request-level authentication tokens. 
    // 
    // Note for reviewers: While this GEP primarily focuses on identity-based 
    // authorization where identity is often established at the transport layer,
    // some implementations might derive identity from authenticated tokens
    // within the request itself.
    //
    // +optional
    Identities []string `json:"identities,omitempty"`

    // ServiceAccounts specifies a list of Kubernetes Service Accounts that are
    // matched by this rule. Each service account must be specified in the format
    // "<namespace>/<service-account-name>". A request originating from a pod
    // associated with one of these service accounts will match the rule.
    // +optional
    ServiceAccounts []string `json:"serviceAccounts,omitempty"`

    // Namespaces specifies a list of Kubernetes Namespaces that are matched
    // by this rule. A request originating from any pod within one of these
    // namespaces will match the rule, regardless of its specific Service Account.
    // This provides a broader scope for authorization.
    // +optional
    Namespaces []string `json:"namespaces,omitempty"`
}

// AuthorizationAttribute defines L4 properties of a request destination.
type AuthorizationTCPAttributes struct {
    // Ports specifies a list of destination ports to match on.
    // Traffic is matched if it is going to any of these ports.
    // If not specified, the rule applies to all ports.
    // +optional
    Ports []gatewayv1.PortNumber `json:"ports,omitempty"`
}

```

## Conformance Details


#### Feature Names


### Conformance tests 


## Alternatives


## References