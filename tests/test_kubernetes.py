"""Kubernetes rules: what the manifest gives away of the container boundary."""

import base64
import unittest

from bluerayscan.findings import Severity
from bluerayscan.scanners import kubernetes


def rule_ids(findings):
    return {finding.rule_id for finding in findings}


def scan(text, path="deploy/app.yaml"):
    return kubernetes.scan_manifest(path, text)


def pod(container_body="", spec_body=""):
    return (
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\nspec:\n"
        + spec_body
        + "  containers:\n    - name: app\n      image: nginx:1.25\n"
        "      resources:\n        limits:\n          memory: 64Mi\n"
        + container_body
    )


class TestRecognition(unittest.TestCase):
    def test_a_document_is_a_manifest_when_it_says_so(self):
        self.assertTrue(rule_ids(scan(pod())) == set())
        self.assertEqual(scan("jobs:\n  build:\n    steps: []\n"), [])

    def test_a_workflow_in_a_manifest_directory_is_not_a_workload(self):
        # Recognition is by content, so a path pattern cannot be fooled.
        text = "on:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        self.assertEqual(scan(text, "k8s/ci.yaml"), [])


class TestSchemaDocuments(unittest.TestCase):
    """A schema for a resource is not a resource."""

    CRD = (
        "apiVersion: apiextensions.k8s.io/v1\n"
        "kind: CustomResourceDefinition\n"
        "metadata:\n  name: grafanas.example.com\n"
        "spec:\n"
        "  versions:\n"
        "    - schema:\n"
        "        openAPIV3Schema:\n"
        "          properties:\n"
        "            containers:\n"
        "              items:\n"
        "                properties:\n"
        "                  securityContext:\n"
        "                    properties:\n"
        "                      privileged:\n"
        "                        type: boolean\n"
        "            volumes:\n"
        "              properties:\n"
        "                hostPath:\n"
        "                  type: object\n"
    )

    def test_a_crd_is_not_a_workload(self):
        # Every field these rules look for appears in a schema by name, which
        # is how a CRD comes to look like the worst workload ever written.
        self.assertEqual(scan(self.CRD), [])

    def test_a_resource_of_that_kind_is_still_read(self):
        text = pod("      securityContext:\n        privileged: true\n")
        self.assertIn("K8S001", rule_ids(scan(text)))


class TestPrivilege(unittest.TestCase):
    def test_privileged_container(self):
        findings = scan(pod("      securityContext:\n        privileged: true\n"))
        self.assertEqual(findings[0].rule_id, "K8S001")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_privileged_elsewhere_in_the_document_is_not_a_container(self):
        # "privileged: true" under annotations means nothing; a line-based
        # scanner cannot tell the difference and this one must.
        text = pod(spec_body="  nodeSelector:\n    privileged: true\n")
        self.assertNotIn("K8S001", rule_ids(scan(text)))

    def test_allowed_privilege_escalation(self):
        findings = scan(pod("      securityContext:\n        allowPrivilegeEscalation: true\n"))
        self.assertIn("K8S006", rule_ids(findings))

    def test_dangerous_capability(self):
        findings = scan(
            pod("      securityContext:\n        capabilities:\n          add:\n            - SYS_ADMIN\n")
        )
        self.assertIn("K8S006", rule_ids(findings))
        self.assertIn("SYS_ADMIN", findings[0].title)

    def test_an_ordinary_capability_is_not_a_finding(self):
        findings = scan(
            pod("      securityContext:\n        capabilities:\n          add:\n            - CHOWN\n")
        )
        self.assertEqual(findings, [])

    def test_inline_capability_lists_are_read_too(self):
        findings = scan(pod('      securityContext:\n        capabilities:\n          add: ["NET_ADMIN"]\n'))
        self.assertIn("K8S006", rule_ids(findings))


class TestHostAccess(unittest.TestCase):
    def test_host_namespaces(self):
        for key in ("hostNetwork", "hostPID", "hostIPC"):
            with self.subTest(key=key):
                findings = scan(pod(spec_body=f"  {key}: true\n"))
                self.assertIn("K8S003", rule_ids(findings))

    def test_host_namespace_set_to_false_is_fine(self):
        self.assertEqual(scan(pod(spec_body="  hostNetwork: false\n")), [])

    def test_the_container_runtime_socket_is_critical(self):
        text = pod(
            spec_body="  volumes:\n    - name: sock\n      hostPath:\n        path: /var/run/docker.sock\n"
        )
        finding = next(f for f in scan(text) if f.rule_id == "K8S002")
        self.assertEqual(finding.severity, Severity.CRITICAL)

    def test_an_ordinary_host_path_is_high(self):
        text = pod(spec_body="  volumes:\n    - name: data\n      hostPath:\n        path: /srv/data\n")
        finding = next(f for f in scan(text) if f.rule_id == "K8S002")
        self.assertEqual(finding.severity, Severity.HIGH)


class TestConfinement(unittest.TestCase):
    """K8S012: a syscall or AppArmor profile switched off by name."""

    def test_a_container_without_a_seccomp_profile(self):
        text = pod(
            "      securityContext:\n        seccompProfile:\n          type: Unconfined\n"
        )
        findings = [f for f in scan(text) if f.rule_id == "K8S012"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertIn("'app'", findings[0].title)

    def test_the_runtime_default_profile_is_the_fix_and_is_not_reported(self):
        text = pod(
            "      securityContext:\n        seccompProfile:\n          type: RuntimeDefault\n"
        )
        self.assertNotIn("K8S012", rule_ids(scan(text)))

    def test_a_pod_level_profile_is_reported_once_as_the_pods(self):
        text = pod(
            spec_body="  securityContext:\n    seccompProfile:\n      type: Unconfined\n"
        )
        findings = [f for f in scan(text) if f.rule_id == "K8S012"]
        self.assertEqual(len(findings), 1)
        self.assertIn("Pod", findings[0].title)

    def test_a_container_profile_is_not_also_reported_as_the_pods(self):
        text = pod(
            "      securityContext:\n        seccompProfile:\n          type: Unconfined\n"
        )
        findings = [f for f in scan(text) if f.rule_id == "K8S012"]
        self.assertEqual(len(findings), 1)
        self.assertIn("Container", findings[0].title)

    def test_the_apparmor_annotation(self):
        text = (
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\n  annotations:\n"
            "    container.apparmor.security.beta.kubernetes.io/app: unconfined\n"
            "spec:\n  containers:\n    - name: app\n      image: nginx:1.25\n"
            "      resources:\n        limits:\n          memory: 64Mi\n"
        )
        findings = [f for f in scan(text) if f.rule_id == "K8S012"]
        self.assertEqual(len(findings), 1)
        self.assertIn("'app'", findings[0].title)

    def test_an_apparmor_profile_by_name_is_not_reported(self):
        text = (
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\n  annotations:\n"
            "    container.apparmor.security.beta.kubernetes.io/app: runtime/default\n"
            "spec:\n  containers:\n    - name: app\n      image: nginx:1.25\n"
            "      resources:\n        limits:\n          memory: 64Mi\n"
        )
        self.assertNotIn("K8S012", rule_ids(scan(text)))


class TestHostPathTitles(unittest.TestCase):
    def test_a_named_path_is_named(self):
        text = pod(spec_body="  volumes:\n    - hostPath:\n        path: /var/lib\n")
        finding = next(f for f in scan(text) if f.rule_id == "K8S002")
        self.assertIn("/var/lib", finding.title)

    def test_a_path_the_reader_could_not_see_reads_as_a_sentence(self):
        # "mounts host path unnamed" is not a sentence anybody wrote.
        text = pod(spec_body="  volumes:\n    - hostPath:\n        type: Directory\n")
        finding = next(f for f in scan(text) if f.rule_id == "K8S002")
        self.assertIn("mounts a path from the node", finding.title)


class TestUsersAndLimits(unittest.TestCase):
    def test_explicit_root(self):
        self.assertIn("K8S005", rule_ids(scan(pod("      securityContext:\n        runAsUser: 0\n"))))

    def test_run_as_non_root_disabled(self):
        self.assertIn(
            "K8S005", rule_ids(scan(pod("      securityContext:\n        runAsNonRoot: false\n")))
        )

    def test_a_non_root_uid_is_fine(self):
        self.assertEqual(scan(pod("      securityContext:\n        runAsUser: 1000\n")), [])

    def test_missing_limits(self):
        text = (
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\nspec:\n"
            "  containers:\n    - name: app\n      image: nginx:1.25\n"
        )
        findings = scan(text)
        self.assertIn("K8S004", rule_ids(findings))
        self.assertEqual(next(f for f in findings if f.rule_id == "K8S004").severity, Severity.LOW)

    def test_limits_present_is_not_a_finding(self):
        self.assertNotIn("K8S004", rule_ids(scan(pod())))


class TestImages(unittest.TestCase):
    def test_latest_and_untagged_float(self):
        for reference in ("nginx", "nginx:latest"):
            with self.subTest(reference=reference):
                text = (
                    "apiVersion: v1\nkind: Pod\nmetadata:\n  name: w\nspec:\n"
                    f"  containers:\n    - name: app\n      image: {reference}\n"
                    "      resources:\n        limits:\n          cpu: 1\n"
                )
                self.assertIn("K8S008", rule_ids(scan(text)))

    def test_a_version_tag_or_digest_is_accepted(self):
        for reference in ("nginx:1.25.3", "nginx@sha256:" + "a" * 64):
            with self.subTest(reference=reference):
                text = (
                    "apiVersion: v1\nkind: Pod\nmetadata:\n  name: w\nspec:\n"
                    f"  containers:\n    - name: app\n      image: {reference}\n"
                    "      resources:\n        limits:\n          cpu: 1\n"
                )
                self.assertNotIn("K8S008", rule_ids(scan(text)))


class TestSecretManifests(unittest.TestCase):
    def manifest(self, field, key, value):
        return (
            f"apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\n{field}:\n  {key}: {value}\n"
        )

    def encoded(self, value):
        return base64.b64encode(value.encode()).decode()

    def test_a_recognised_credential_is_decoded_and_named(self):
        raw = "AKIA" + "ZZ7Q4TWFN2XKLM3D"
        findings = scan(self.manifest("data", "aws", self.encoded(raw)))
        self.assertEqual(findings[0].rule_id, "K8S007")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertIn("aws access key id", findings[0].title)
        self.assertNotIn(raw, findings[0].evidence)

    def test_an_unrecognised_but_generated_value_is_still_reported(self):
        findings = scan(self.manifest("data", "password", self.encoded("Tv8nRw1YXk92mQp7Lz4T")))
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_string_data_is_read_without_decoding(self):
        findings = scan(self.manifest("stringData", "password", "Tv8nRw1YXk92mQp7Lz4T"))
        self.assertIn("K8S007", rule_ids(findings))

    def test_short_and_placeholder_values_are_not_reported(self):
        for value in (self.encoded("hi"), self.encoded("changeme"), self.encoded("${PASSWORD}")):
            with self.subTest(value=value):
                self.assertEqual(scan(self.manifest("data", "password", value)), [])

    def test_a_value_that_is_not_base64_is_not_a_crash(self):
        self.assertEqual(scan(self.manifest("data", "password", "not!base64!")), [])


class TestHostPorts(unittest.TestCase):
    def manifest(self, ports):
        return (
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: w\nspec:\n"
            "  containers:\n    - name: app\n      image: nginx:1.25\n"
            "      resources:\n        limits:\n          cpu: 1\n"
            "      ports:\n" + ports
        )

    def test_a_host_port_is_reported(self):
        findings = scan(self.manifest("        - containerPort: 8080\n          hostPort: 8080\n"))
        self.assertEqual(findings[0].rule_id, "K8S011")
        self.assertEqual(findings[0].severity, Severity.MEDIUM)

    def test_a_privileged_or_well_known_port_is_worse(self):
        for port in (22, 80):
            with self.subTest(port=port):
                findings = scan(
                    self.manifest(f"        - containerPort: {port}\n          hostPort: {port}\n")
                )
                self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_a_container_port_alone_is_not_a_host_port(self):
        # containerPort is documentation; hostPort is a binding on the node.
        self.assertEqual(scan(self.manifest("        - containerPort: 8080\n")), [])


class TestRbac(unittest.TestCase):
    """Who may do what, which is where a cluster is usually given away."""

    def role(self, kind, verbs, resources):
        return (
            f"apiVersion: rbac.authorization.k8s.io/v1\nkind: {kind}\n"
            f"metadata:\n  name: r\nrules:\n  - apiGroups: [\"*\"]\n"
            f"    resources: {resources}\n    verbs: {verbs}\n"
        )

    def binding(self, name, kind="ClusterRoleBinding"):
        return (
            f"apiVersion: rbac.authorization.k8s.io/v1\nkind: {kind}\n"
            "metadata:\n  name: b\nroleRef:\n  kind: ClusterRole\n  name: cluster-admin\n"
            f"subjects:\n  - kind: Group\n    name: {name}\n"
        )

    def test_a_wildcard_cluster_role_is_critical(self):
        findings = scan(self.role("ClusterRole", '["*"]', '["*"]'))
        self.assertEqual(findings[0].rule_id, "K8S009")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_a_namespaced_role_is_high_rather_than_critical(self):
        findings = scan(self.role("Role", '["*"]', '["*"]'))
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_scoped_verbs_are_not_a_finding(self):
        self.assertEqual(scan(self.role("ClusterRole", '["get", "list"]', '["pods"]')), [])
        self.assertEqual(scan(self.role("ClusterRole", '["*"]', '["pods"]')), [])

    def test_block_style_lists_are_read_too(self):
        text = (
            "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\n"
            "metadata:\n  name: r\nrules:\n  - resources:\n      - '*'\n"
            "    verbs:\n      - '*'\n"
        )
        self.assertIn("K8S009", rule_ids(scan(text)))

    def test_binding_to_everybody(self):
        for name in ("system:anonymous", "system:unauthenticated", "system:authenticated"):
            with self.subTest(name=name):
                findings = scan(self.binding(name))
                self.assertEqual(findings[0].rule_id, "K8S010")
                self.assertIn("cluster-admin", findings[0].title)

    def test_binding_to_a_service_account_is_ordinary(self):
        self.assertEqual(scan(self.binding("app-service-account")), [])

    def test_a_namespaced_binding_counts_as_well(self):
        self.assertIn("K8S010", rule_ids(scan(self.binding("system:anonymous", "RoleBinding"))))


class TestWorkloadKinds(unittest.TestCase):
    def test_containers_are_found_at_any_depth(self):
        text = (
            "apiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: nightly\nspec:\n"
            "  jobTemplate:\n    spec:\n      template:\n        spec:\n"
            "          containers:\n            - name: job\n              image: tool:1.0\n"
            "              securityContext:\n                privileged: true\n"
        )
        findings = scan(text)
        self.assertIn("K8S001", rule_ids(findings))
        self.assertIn("CronJob 'nightly'", findings[0].title)

    def test_init_containers_count(self):
        text = (
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: w\nspec:\n"
            "  initContainers:\n    - name: setup\n      image: busybox:1.36\n"
            "      resources:\n        limits:\n          cpu: 1\n"
            "      securityContext:\n        privileged: true\n"
        )
        self.assertIn("K8S001", rule_ids(scan(text)))


class TestJsonManifests(unittest.TestCase):
    def test_the_rules_read_json_manifests_too(self):
        # "kubectl get -o json" and anything that generates manifests.
        manifest = (
            '{"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "w"},'
            ' "spec": {"containers": [{"name": "app", "image": "nginx:1.25",'
            ' "resources": {"limits": {"cpu": "1"}},'
            ' "securityContext": {"privileged": true}}]}}'
        )
        findings = scan(manifest, "deploy/pod.json")
        self.assertEqual(rule_ids(findings), {"K8S001"})

    def test_a_malformed_json_manifest_reports_nothing(self):
        self.assertEqual(scan('{"apiVersion": "v1",', "deploy/pod.json"), [])

    def test_json_that_is_not_a_manifest_is_left_alone(self):
        self.assertEqual(scan('{"name": "app", "private": true}', "package.json"), [])


class TestChartValues(unittest.TestCase):
    """A chart's values are where most Kubernetes settings actually live."""

    CHART = ("charts/web/Chart.yaml", "apiVersion: v2\nname: web\nversion: 0.1.0\n")

    def scan_values(self, body, path="charts/web/values.yaml"):
        return kubernetes.scan_files([self.CHART, (path, body)])

    def test_a_privileged_security_context(self):
        findings = self.scan_values("securityContext:\n  privileged: true\n")
        finding = next(f for f in findings if f.rule_id == "K8S001")
        self.assertEqual(finding.severity, Severity.CRITICAL)
        # The chart should pass it through, and this reader has not read the
        # template that does.
        self.assertEqual(finding.confidence.value, "medium")

    def test_the_host_namespace_flags(self):
        for key in ("hostNetwork", "hostPID", "hostIPC"):
            with self.subTest(key=key):
                findings = self.scan_values(f"{key}: true\n")
                self.assertIn("K8S003", rule_ids(findings))

    def test_a_flag_left_off_is_not_a_finding(self):
        self.assertEqual(self.scan_values("hostNetwork: false\n"), [])

    def test_capabilities_written_as_a_flow_list(self):
        body = 'securityContext:\n  capabilities:\n    add: ["SYS_ADMIN"]\n'
        findings = [f for f in self.scan_values(body) if f.rule_id == "K8S006"]
        self.assertEqual(len(findings), 1)
        self.assertIn("SYS_ADMIN", findings[0].title)

    def test_privilege_escalation_and_seccomp_in_values(self):
        body = (
            "securityContext:\n"
            "  allowPrivilegeEscalation: true\n"
            "  seccompProfile:\n    type: Unconfined\n"
        )
        found = rule_ids(self.scan_values(body))
        self.assertIn("K8S006", found)
        self.assertIn("K8S012", found)

    def test_a_security_context_that_hardens_is_not_a_finding(self):
        body = (
            "securityContext:\n"
            "  privileged: false\n"
            "  allowPrivilegeEscalation: false\n"
            "  seccompProfile:\n    type: RuntimeDefault\n"
            "  capabilities:\n    drop: [ALL]\n"
        )
        self.assertEqual(self.scan_values(body), [])

    def test_capabilities_written_as_a_block_list(self):
        body = "securityContext:\n  capabilities:\n    add:\n      - NET_ADMIN\n"
        self.assertIn("K8S006", rule_ids(self.scan_values(body)))

    def test_a_host_path_volume_needs_a_path_to_be_one(self):
        # Charts name sections after the feature they configure: Dagger has a
        # hostPath block whose keys are dataVolume and runVolume.
        option = "hostPath:\n  dataVolume:\n    enabled: true\n"
        self.assertEqual(self.scan_values(option), [])
        volume = "extraVolumes:\n  - hostPath:\n      path: /var/run/docker.sock\n"
        self.assertIn("K8S002", rule_ids(self.scan_values(volume)))

    def test_a_values_file_with_no_chart_beside_it_is_not_a_chart(self):
        # Every application repository has a values.yaml somewhere.
        findings = kubernetes.scan_files([("deploy/values.yaml", "hostNetwork: true\n")])
        self.assertEqual(findings, [])

    def test_an_environment_override_is_read_as_well(self):
        findings = self.scan_files_override("charts/web/values-production.yaml")
        self.assertIn("K8S003", rule_ids(findings))

    def scan_files_override(self, path):
        return kubernetes.scan_files([self.CHART, (path, "hostNetwork: true\n")])

    def test_a_marker_silences_the_line(self):
        body = "hostNetwork: true  # bluerayscan: ignore[K8S003]\n"
        self.assertEqual(self.scan_values(body), [])

    def test_a_templated_values_file_is_still_read(self):
        body = "hostNetwork: {{ .Values.host }}\nsecurityContext:\n  privileged: true\n"
        self.assertIn("K8S001", rule_ids(self.scan_values(body)))


class TestKustomizations(unittest.TestCase):
    """An overlay is where the exception for production goes."""

    OVERLAY = (
        "apiVersion: kustomize.config.k8s.io/v1beta1\n"
        "kind: Kustomization\n"
        "resources:\n  - deployment.yaml\n"
        "patches:\n"
        "  - target:\n      kind: Deployment\n      name: web\n"
        "    patch: |\n"
        "      apiVersion: apps/v1\n"
        "      kind: Deployment\n"
        "      metadata:\n        name: web\n"
        "      spec:\n        template:\n          spec:\n"
        "            hostNetwork: true\n"
        "            containers:\n              - name: app\n"
        "                image: nginx:1.25\n"
        "                resources:\n                  limits:\n                    memory: 64Mi\n"
        "                securityContext:\n                  privileged: true\n"
    )

    def scan_overlay(self, text=None, path="overlays/prod/kustomization.yaml"):
        return kubernetes.scan_files([(path, text if text is not None else self.OVERLAY)])

    def test_a_patched_security_context_is_read(self):
        found = rule_ids(self.scan_overlay())
        self.assertIn("K8S001", found)
        self.assertIn("K8S003", found)

    def test_the_finding_points_at_the_patch(self):
        finding = next(f for f in self.scan_overlay() if f.rule_id == "K8S001")
        line = self.OVERLAY.splitlines()[finding.line - 1]
        self.assertIn("privileged: true", line)

    def test_a_kustomization_with_no_inline_patch_says_nothing(self):
        text = (
            "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
            "resources:\n  - deployment.yaml\n"
        )
        self.assertEqual(self.scan_overlay(text), [])

    def test_a_patch_block_with_nothing_in_it(self):
        # "patch: |" at the end of a file, or with nothing indented under it.
        text = (
            "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
            "patches:\n  - patch: |\n"
        )
        self.assertEqual(self.scan_overlay(text), [])

    def test_a_file_that_is_not_a_kustomization_is_not_read_as_one(self):
        self.assertFalse(kubernetes.is_kustomization_path("deploy/app.yaml"))
        self.assertTrue(kubernetes.is_kustomization_path("overlays/prod/kustomization.yml"))

    def test_a_marker_still_silences_the_file(self):
        text = "# bluerayscan: ignore-file\n" + self.OVERLAY
        self.assertEqual(self.scan_overlay(text), [])


class TestSuppression(unittest.TestCase):
    def test_line_marker_silences_a_finding(self):
        text = pod("      securityContext:\n        privileged: true  # bluerayscan: ignore\n")
        self.assertNotIn("K8S001", rule_ids(scan(text)))


class TestHelmTemplates(unittest.TestCase):
    """Charts are where most real manifests live, and a chart is not YAML."""

    CHART = (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n"
        '  name: {{ include "chart.fullname" . }}\n'
        "spec:\n  template:\n    spec:\n"
        "      {{- if .Values.hostNetwork }}\n"
        "      hostNetwork: true\n"
        "      {{- end }}\n"
        "      containers:\n        - name: app\n"
        '          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"\n'
        "          securityContext:\n            privileged: true\n"
        "          resources:\n"
        "            {{- toYaml .Values.resources | nindent 12 }}\n"
    )

    def test_a_value_written_in_the_chart_is_still_found(self):
        findings = scan(self.CHART, "charts/app/templates/deployment.yaml")
        self.assertIn("K8S001", rule_ids(findings))
        self.assertIn("K8S003", rule_ids(findings))

    def test_line_numbers_survive_the_stripping(self):
        finding = next(f for f in scan(self.CHART) if f.rule_id == "K8S001")
        self.assertEqual(finding.line, 15)

    def test_absence_based_rules_do_not_run_on_a_template(self):
        # The values file supplies the limits and the image tag. Neither is in
        # front of us, so concluding anything from their absence is a guess.
        findings = rule_ids(scan(self.CHART))
        self.assertNotIn("K8S004", findings)
        self.assertNotIn("K8S008", findings)

    def test_the_same_document_without_templating_is_judged_completely(self):
        plain = (
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\nspec:\n"
            "  containers:\n    - name: app\n      image: nginx\n"
        )
        findings = rule_ids(scan(plain))
        self.assertIn("K8S004", findings)
        self.assertIn("K8S008", findings)

    def test_a_templated_name_is_not_quoted_back_at_the_reader(self):
        finding = next(f for f in scan(self.CHART) if f.rule_id == "K8S001")
        self.assertNotIn("__TEMPLATED__", finding.title)

    def test_an_interpolated_image_is_not_judged_on_its_shape(self):
        plain = (
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\nspec:\n"
            "  containers:\n    - name: app\n      image: ${IMAGE}\n"
            "      resources:\n        limits:\n          cpu: 1\n"
        )
        self.assertNotIn("K8S008", rule_ids(scan(plain)))


if __name__ == "__main__":
    unittest.main()
