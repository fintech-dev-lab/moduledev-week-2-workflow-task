from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "public_check.py"
SPEC = importlib.util.spec_from_file_location("week2_public_check", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Cannot load public_check.py")
public_check = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = public_check
SPEC.loader.exec_module(public_check)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


class FixtureTests(unittest.TestCase):
    def test_published_fixture_digest_is_valid(self) -> None:
        fixture = public_check.load_fixture(FIXTURES)
        self.assertEqual(
            fixture["digest"], public_check.canonical_fixture_digest(FIXTURES)
        )
        self.assertTrue(fixture["files"]["invalidMaps"]["schema"])
        self.assertTrue(fixture["files"]["invalidMaps"]["semantic"])

    def test_fixture_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / "fixtures"
            shutil.copytree(FIXTURES, copied)
            signal = copied / "data" / "signal.json"
            signal.write_text(
                signal.read_text(encoding="utf-8") + " ", encoding="utf-8"
            )
            with self.assertRaises(public_check.FixtureError):
                public_check.load_fixture(copied)

    def test_recomputed_digest_cannot_replace_published_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / "fixtures"
            shutil.copytree(FIXTURES, copied)
            signal = copied / "data" / "signal.json"
            signal.write_text('{"changed":true}\n', encoding="utf-8")
            metadata_path = copied / "fixture.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["digest"] = public_check.canonical_fixture_digest(copied)
            metadata_path.write_text(
                json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(public_check.FixtureError):
                public_check.load_fixture(copied)


class ParsingTests(unittest.TestCase):
    def test_image_id_uses_compose_reference_before_containers_exist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness = public_check.ComposeHarness(
                repo=root,
                fixtures=root,
                compose_file=root / "compose.yaml",
                compose_wrapper=root / "safe_compose.sh",
                override_file=root / "override.yaml",
                project="public-check-unit",
                gateway_port=8080,
                sensitive=(),
            )
            config = public_check.CommandResult(
                ("compose", "config"),
                0,
                json.dumps({"services": {"api": {"build": {"context": "."}}}}),
                "",
            )
            digest = "a" * 64
            inspected = public_check.CommandResult(
                ("docker", "image", "inspect"), 0, f"sha256:{digest}\n", ""
            )
            with (
                mock.patch.object(harness, "compose", return_value=config),
                mock.patch.object(harness, "run", return_value=inspected) as run,
            ):
                self.assertEqual(harness.image_id("api"), f"sha256:{digest}")
        self.assertEqual(run.call_args.args[0][-1], "public-check-unit-api")

    def test_structured_failpoint_parsing(self) -> None:
        logs = "\n".join(
            (
                "worker-a | not json",
                'worker-a | {"event":"other","name":"after_job_claim","instanceId":"worker-a"}',
                'worker-a | {"event":"failpoint.reached","name":"after_job_claim","instanceId":"worker-a"}',
                'worker-a | {"event":"failpoint.reached","name":"different","instanceId":"worker-a"}',
            )
        )
        self.assertEqual(
            public_check.parse_failpoint_acks(logs, "after_job_claim"),
            [
                {
                    "event": "failpoint.reached",
                    "name": "after_job_claim",
                    "instanceId": "worker-a",
                }
            ],
        )

    def test_cli_json_requires_one_exact_object(self) -> None:
        self.assertEqual(
            public_check.extract_cli_json('  {"status":"ok"}\n'), {"status": "ok"}
        )
        self.assertIsNone(public_check.extract_cli_json('log\n{"status":"ok"}'))
        self.assertIsNone(public_check.extract_cli_json("[]"))
        self.assertIsNone(public_check.extract_cli_json(""))

    def test_duplicate_failpoint_acknowledgement_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness = public_check.ComposeHarness(
                repo=root,
                fixtures=root,
                compose_file=root / "compose.yaml",
                compose_wrapper=root / "wrapper.sh",
                override_file=root / "override.yaml",
                project="project",
                gateway_port=8080,
                sensitive=(),
            )
            line = (
                '{"event":"failpoint.reached","name":"after_job_claim",'
                '"instanceId":"worker-a"}\n'
            )
            duplicate = public_check.CommandResult(
                ("docker", "compose", "logs"), 0, line + line, ""
            )
            with mock.patch.object(harness, "compose", return_value=duplicate):
                with self.assertRaises(public_check.ContractError):
                    harness.wait_failpoint("worker-a", "after_job_claim")
                with self.assertRaises(public_check.ContractError):
                    harness.wait_single_winner(
                        ("worker-a", "worker-b"), "after_job_claim"
                    )

    def test_worker_addresses_are_read_from_docker_inspect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness = public_check.ComposeHarness(
                repo=root,
                fixtures=root,
                compose_file=root / "compose.yaml",
                compose_wrapper=root / "wrapper.sh",
                override_file=root / "override.yaml",
                project="project",
                gateway_port=8080,
                sensitive=(),
            )
            container = public_check.CommandResult(
                ("docker", "compose", "ps"), 0, "a" * 64 + "\n", ""
            )
            inspected = public_check.CommandResult(
                ("docker", "inspect"), 0, "172.20.0.3\n\n", ""
            )
            with (
                mock.patch.object(harness, "compose", return_value=container),
                mock.patch.object(harness, "run", return_value=inspected) as run,
            ):
                succeeded, addresses = harness._service_addresses("worker-a")
            self.assertTrue(succeeded)
            self.assertEqual(addresses, {"172.20.0.3"})
            self.assertEqual(
                run.call_args.args[0][:3], ["docker", "inspect", "--format"]
            )


class QueryTests(unittest.TestCase):
    def test_stable_view_and_fixture_queries_are_allowed(self) -> None:
        public_check.validate_read_only_query(
            "SELECT a.attempt_id FROM autocheck.attempts a "
            "JOIN autocheck.jobs j ON j.job_id = a.job_id"
        )
        public_check.validate_read_only_query(
            "SELECT execution_id FROM probe_test.effect_test",
            ("probe_test", "effect_test"),
        )
        public_check.validate_read_only_query(
            "SELECT has_table_privilege(r.oid, c.oid, 'INSERT') AS has_insert "
            "FROM pg_catalog.pg_class c JOIN pg_catalog.pg_roles r ON true"
        )

    def test_mutating_or_unpublished_queries_are_rejected(self) -> None:
        invalid = (
            "UPDATE autocheck.jobs SET state = 'READY'",
            "SELECT * FROM workflow.jobs",
            "SELECT * FROM autocheck.jobs; SELECT 1",
            "SELECT * FROM autocheck.jobs -- comment",
        )
        for query in invalid:
            with self.subTest(query=query):
                with self.assertRaises(ValueError):
                    public_check.validate_read_only_query(query)


class ReportTests(unittest.TestCase):
    def test_report_shape_and_redaction(self) -> None:
        secret = "synthetic-sensitive-value"
        checks = [
            {
                "name": "sample",
                "phase": "admission",
                "status": "passed",
                "expected": "safe",
                "actual": public_check._redact(
                    {
                        "signingKey": secret,
                        "message": f"prefix {secret} suffix",
                    },
                    (secret,),
                ),
            }
        ]
        report = public_check.build_report(
            started_at="2026-08-29T00:00:00+00:00",
            finished_at="2026-08-29T00:00:01+00:00",
            status="passed",
            checks=checks,
            commands=[
                {"command": ["docker", "compose"], "exitCode": 0, "timedOut": False}
            ],
        )
        self.assertEqual(
            set(report),
            {
                "manifestVersion",
                "toolVersion",
                "timestamps",
                "status",
                "checks",
                "failedChecks",
                "commands",
            },
        )
        self.assertFalse(public_check.report_has_forbidden_keys(report))
        self.assertTrue(public_check.report_has_forbidden_keys({"Sc" + "ore": 1}))
        self.assertNotIn(secret, json.dumps(report))
        self.assertEqual(report["failedChecks"], [])

    def test_failed_check_is_named_in_summary(self) -> None:
        report = public_check.build_report(
            started_at="start",
            finished_at="finish",
            status="failed",
            checks=[
                {
                    "name": "broken-contract",
                    "phase": "execution",
                    "status": "failed",
                    "expected": True,
                    "actual": False,
                }
            ],
            commands=[],
        )
        self.assertEqual(report["failedChecks"], ["broken-contract"])

    def test_report_write_replaces_hard_link_without_truncating_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.txt"
            target.write_text("sentinel\n", encoding="utf-8")
            report_path = root / "report.json"
            report_path.hardlink_to(target)
            public_check._write_report(report_path, {"status": "passed"})
            self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")
            self.assertEqual(
                json.loads(report_path.read_text(encoding="utf-8")),
                {"status": "passed"},
            )


class ExitCodeTests(unittest.TestCase):
    def test_missing_candidate_compose_is_contract_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "report.json"
            with contextlib.redirect_stdout(io.StringIO()):
                code = public_check.main(
                    [
                        "--repo",
                        str(root),
                        "--fixtures",
                        str(FIXTURES),
                        "--output",
                        str(output),
                        "--compose-wrapper",
                        str(MODULE_PATH.with_name("safe_compose.sh")),
                    ]
                )
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(code, 1)
            self.assertEqual(report["status"], "failed")

    def test_missing_trusted_wrapper_is_initialization_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
            output = root / "report.json"
            with contextlib.redirect_stdout(io.StringIO()):
                code = public_check.main(
                    [
                        "--repo",
                        str(root),
                        "--fixtures",
                        str(FIXTURES),
                        "--output",
                        str(output),
                        "--compose-wrapper",
                        str(root / "missing-safe-compose.sh"),
                    ]
                )
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(code, 2)
            self.assertEqual(report["status"], "error")

    def test_report_symlink_is_rejected_without_overwriting_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.txt"
            target.write_text("sentinel\n", encoding="utf-8")
            output = root / "report.json"
            output.symlink_to(target)
            with (
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                code = public_check.main(
                    [
                        "--repo",
                        str(root),
                        "--fixtures",
                        str(FIXTURES),
                        "--output",
                        str(output),
                        "--compose-wrapper",
                        str(MODULE_PATH.with_name("safe_compose.sh")),
                    ]
                )
            self.assertEqual(code, 2)
            self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")


class AdmissionSafetyTests(unittest.TestCase):
    def test_safe_compose_model_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            config = {
                "services": {
                    "api": {
                        "build": {"context": str(repo)},
                    }
                },
                "volumes": {"data": {"name": "project_data"}},
            }
            self.assertEqual(public_check._unsafe_compose_findings(config, repo), [])

    def test_readme_sections_do_not_require_one_heading_hierarchy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            sections = "\n".join(
                f"## {name.title()}\ncontent" for name in public_check.SOLUTION_HEADINGS
            )
            (repo / "README.md").write_text(
                f"# Solution\n{sections}\ndocker compose up -d --build\n./check.sh\n",
                encoding="utf-8",
            )
            checker = object.__new__(public_check.PublicChecker)
            checker.repo = repo
            with mock.patch.object(
                checker, "_tracked_paths", return_value=["README.md", ".gitignore"]
            ):
                self.assertEqual(checker._admission_text_findings(), [])

    def test_host_escape_compose_options_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            config = {
                "services": {
                    "api": {
                        "container_name": "global-api",
                        "network_mode": "host",
                        "device_cgroup_rules": ["b 8:* rmw"],
                        "use_api_socket": True,
                        "volumes_from": ["container:external"],
                        "provider": {"type": "external"},
                        "external_links": ["other:alias"],
                        "logging": {"driver": "syslog"},
                        "security_opt": ["seccomp=unconfined"],
                        "build": {
                            "context": "../outside",
                            "ssh": ["default"],
                            "tags": ["global:latest"],
                        },
                    }
                },
                "volumes": {"data": {"external": True, "name": "global-data"}},
                "networks": {
                    "host-lan": {"driver": "macvlan"},
                    "custom": {"driver": "bridge", "ipam": {"config": []}},
                },
            }
            findings = public_check._unsafe_compose_findings(config, repo)
            rendered = "\n".join(findings)
            for expected in (
                "unsafe network_mode",
                "elevated device",
                "Docker API socket",
                "volumes_from",
                "external service provider",
                "external_links",
                "external logging driver",
                "unconfined",
                "external build context",
                "unsafe build privilege",
                "unsafe build exporter/tag",
                "external resource",
                "unsafe network driver",
                "unsafe network options",
            ):
                with self.subTest(expected=expected):
                    self.assertIn(expected, rendered)

    def test_repository_bind_mount_is_rejected_even_when_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            source = repo / "config"
            source.mkdir()
            config = {
                "services": {
                    "api": {
                        "volumes": [
                            {
                                "type": "bind",
                                "source": str(source),
                                "read_only": True,
                            }
                        ]
                    }
                }
            }
            findings = public_check._unsafe_compose_findings(config, repo)
            self.assertIn("api: repository bind mount", findings)

    def test_repository_config_and_secret_files_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            config = {
                "services": {},
                "configs": {"settings": {"file": str(repo / "settings.json")}},
                "secrets": {"key": {"file": str(repo / "key.txt")}},
            }
            findings = public_check._unsafe_compose_findings(config, repo)
            self.assertIn("configs.settings: repository file mount", findings)
            self.assertIn("secrets.key: repository file mount", findings)

    def test_volume_driver_options_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            config = {
                "services": {"postgres": {"volumes": ["data:/var/lib/postgresql"]}},
                "volumes": {
                    "data": {
                        "driver": "local",
                        "driver_opts": {
                            "type": "none",
                            "o": "bind",
                            "device": "/etc",
                        },
                    }
                },
            }
            findings = public_check._unsafe_compose_findings(config, repo)
            self.assertIn("volumes.data: unsafe volume driver/options", findings)

    def test_compose_include_and_extends_are_rejected_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            compose_file = Path(temporary) / "compose.yaml"
            compose_file.write_text(
                "include:\n  - ../external.yaml\nservices:\n  api:\n    extends:\n      file: ../base.yaml\n",
                encoding="utf-8",
            )
            findings = public_check._raw_compose_findings(compose_file)
            self.assertEqual(len(findings), 2)
            self.assertTrue(any("include" in item for item in findings))
            self.assertTrue(any("extends" in item for item in findings))
            compose_file.write_text(
                "{include: [../external.yaml], services: {api: {extends: {file: ../base.yaml}}}}\n",
                encoding="utf-8",
            )
            self.assertEqual(len(public_check._raw_compose_findings(compose_file)), 2)

    def test_candidate_config_does_not_use_trusted_override(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compose_file = root / "compose.yaml"
            override = root / "override.yaml"
            wrapper = root / "safe_compose.sh"
            for path in (compose_file, override, wrapper):
                path.write_text("", encoding="utf-8")
            harness = public_check.ComposeHarness(
                repo=root,
                fixtures=root,
                compose_file=compose_file,
                compose_wrapper=wrapper,
                override_file=override,
                project="project",
                gateway_port=8080,
                sensitive=(),
            )
            result = public_check.CommandResult(("docker",), 0, "{}", "")
            with mock.patch.object(harness, "run", return_value=result) as run:
                harness.compose_candidate(["config", "--format", "json"])
            command = run.call_args.args[0]
            self.assertIn(str(compose_file), command)
            self.assertNotIn(str(override), command)

    def test_dotnet_detection_requires_final_stage_lineage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / "Api.csproj").write_text("<Project />\n", encoding="utf-8")
            dockerfile = repo / "Dockerfile"
            service = {"build": {"context": ".", "dockerfile": "Dockerfile"}}
            dockerfile.write_text(
                "FROM mcr.microsoft.com/dotnet/sdk:8.0 AS unused\n"
                "FROM python:3.13\n"
                'ENTRYPOINT ["python", "app.py"]\n',
                encoding="utf-8",
            )
            self.assertFalse(public_check._dotnet_build_declared(service, repo))
            dockerfile.write_text(
                "FROM python:3.13 AS selected\n"
                'ENTRYPOINT ["python", "app.py"]\n'
                "FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final\n"
                'ENTRYPOINT ["dotnet", "Api.dll"]\n',
                encoding="utf-8",
            )
            targeted_service = {
                "build": {
                    "context": ".",
                    "dockerfile": "Dockerfile",
                    "target": "selected",
                }
            }
            self.assertFalse(
                public_check._dotnet_build_declared(targeted_service, repo)
            )
            dockerfile.write_text(
                "FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build\n"
                "FROM debian:bookworm-slim\n"
                "COPY --from=build /app /app\n"
                'ENTRYPOINT ["/app/Api"]\n',
                encoding="utf-8",
            )
            self.assertTrue(public_check._dotnet_build_declared(service, repo))
            dockerfile.write_text(
                "FROM mcr.microsoft.com/dotnet/sdk:8.0 AS marker\n"
                "FROM busybox:1.36 AS busybox\n"
                "FROM debian:bookworm-slim\n"
                "COPY --from=marker /tmp/marker /tmp/marker\n"
                "COPY --from=busybox /bin/busybox /app/Api\n"
                'ENTRYPOINT ["/app/Api", "httpd"]\n',
                encoding="utf-8",
            )
            self.assertFalse(public_check._dotnet_build_declared(service, repo))

    def test_override_resets_global_names_and_scopes_resources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checker = object.__new__(public_check.PublicChecker)
            checker.project = "isolated-project"
            checker.secret = "synthetic-secret"
            checker.override = root / "override.yaml"
            checker._write_override(
                {
                    "services": {
                        "api": {
                            "container_name": "global-api",
                            "image": "candidate/api:latest",
                            "build": {"context": "."},
                        },
                        "cli": {"image": "candidate/api:latest"},
                        "worker-a": {},
                        "worker-b": {},
                        "gateway": {},
                    },
                    "volumes": {"data": {"name": "global-data"}},
                    "networks": {"default": {"name": "global-network"}},
                }
            )
            contents = checker.override.read_text(encoding="utf-8")
            self.assertIn("container_name: !reset null", contents)
            self.assertIn("isolated-project-volumes-1", contents)
            self.assertIn("isolated-project-networks-1", contents)
            self.assertNotIn("global-data", contents)
            self.assertNotIn("global-network", contents)

    @unittest.skipUnless(shutil.which("docker"), "Docker CLI is unavailable")
    def test_generated_override_is_accepted_by_docker_compose(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compose_file = root / "compose.yaml"
            compose_file.write_text(
                """services:
  api:
    image: candidate/api:latest
    build: .
    container_name: global-api
  cli:
    image: candidate/api:latest
  gateway:
    image: nginx:alpine
    ports:
      - "8080:8080"
  postgres:
    image: postgres:16
    volumes:
      - data:/var/lib/postgresql/data
  worker-a:
    image: candidate/worker:latest
    build: .
  worker-b:
    image: candidate/worker:latest
volumes:
  data:
    name: global-data
""",
                encoding="utf-8",
            )
            checker = object.__new__(public_check.PublicChecker)
            checker.project = "isolated-project"
            checker.secret = "synthetic-secret"
            checker.override = root / "override.yaml"
            config = {
                "services": {
                    "api": {
                        "container_name": "global-api",
                        "image": "candidate/api:latest",
                        "build": {"context": str(root)},
                    },
                    "cli": {"image": "candidate/api:latest"},
                    "gateway": {"image": "nginx:alpine"},
                    "postgres": {"image": "postgres:16"},
                    "worker-a": {
                        "image": "candidate/worker:latest",
                        "build": {"context": str(root)},
                    },
                    "worker-b": {"image": "candidate/worker:latest"},
                },
                "volumes": {"data": {"name": "global-data"}},
            }
            checker._write_override(config)
            result = subprocess.run(
                [
                    "docker",
                    "compose",
                    "--project-name",
                    checker.project,
                    "-f",
                    str(compose_file),
                    "-f",
                    str(checker.override),
                    "config",
                    "--format",
                    "json",
                ],
                cwd=root,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            rendered = json.loads(result.stdout)
            self.assertNotIn("container_name", rendered["services"]["api"])
            self.assertEqual(
                rendered["volumes"]["data"]["name"],
                "isolated-project-volumes-1",
            )

    def test_shell_wrapper_rejects_trusted_argument_override(self) -> None:
        result = subprocess.run(
            [str(MODULE_PATH.parent / "check.sh"), "--repo", "/tmp/other"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("reserved", result.stderr)

    def test_cleanup_is_not_run_before_scoped_override(self) -> None:
        checker = object.__new__(public_check.PublicChecker)
        checker.args = argparse.Namespace(keep_stack=False)
        checker.cleanup_armed = False
        checker.harness = mock.Mock()
        self.assertIsNone(checker.cleanup())
        checker.harness.compose.assert_not_called()

    def test_docker_permission_and_capability_errors_are_environment_failures(
        self,
    ) -> None:
        failures = (
            "permission denied while trying to connect to the Docker daemon socket",
            "unknown flag: --no-env-resolution",
            "docker: 'compose' is not a docker command",
            "unsupported tag !reset",
        )
        for message in failures:
            with self.subTest(message=message):
                result = public_check.CommandResult(("docker",), 1, "", message)
                self.assertTrue(public_check.ComposeHarness._environment_error(result))


class StatePredicateTests(unittest.TestCase):
    def test_successful_job_attempt_projection(self) -> None:
        job = {
            "job_id": "job-1",
            "execution_id": "execution-1",
            "state": "SUCCEEDED",
            "attempt_count": 2,
            "lease_version": 2,
        }
        attempts = [
            {
                "attempt_id": "attempt-1",
                "job_id": "job-1",
                "execution_id": "execution-1",
                "lease_version": 1,
                "attempt_number": 1,
                "status": "FAILED",
                "outcome": None,
                "error_code": "fixture.retry",
                "started_at": "2026-08-29T00:00:00+00:00",
                "finished_at": "2026-08-29T00:00:01+00:00",
            },
            {
                "attempt_id": "attempt-2",
                "job_id": "job-1",
                "execution_id": "execution-1",
                "lease_version": 2,
                "attempt_number": 2,
                "status": "SUCCEEDED",
                "outcome": "ROUTED",
                "error_code": None,
                "started_at": "2026-08-29T00:00:02+00:00",
                "finished_at": "2026-08-29T00:00:03+00:00",
            },
        ]
        self.assertTrue(public_check.job_attempts_consistent(job, attempts, "ROUTED"))
        attempts[1]["lease_version"] = 1
        self.assertFalse(public_check.job_attempts_consistent(job, attempts, "ROUTED"))

    def test_terminal_failure_and_process_state(self) -> None:
        process = {"state": "FAILED", "current_step_key": "invoke"}
        jobs = [
            {
                "job_id": "job-1",
                "execution_id": "execution-1",
                "state": "DEAD",
                "attempt_count": 1,
                "lease_version": 1,
            }
        ]
        attempts = [
            {
                "attempt_id": "attempt-1",
                "attempt_number": 1,
                "job_id": "job-1",
                "execution_id": "execution-1",
                "lease_version": 1,
                "status": "FAILED",
                "outcome": None,
                "error_code": "fixture.error",
                "started_at": "2026-08-29T00:00:00+00:00",
                "finished_at": "2026-08-29T00:00:01+00:00",
            }
        ]
        self.assertTrue(
            public_check.terminal_failure_consistent(
                process,
                jobs,
                attempts,
                [],
                expected_attempts=1,
                expected_error="fixture.error",
            )
        )
        self.assertTrue(public_check.process_state_matches(process, "FAILED", "invoke"))
        self.assertFalse(public_check.process_state_matches(process, "COMPLETED"))

    def test_mixed_timezone_attempt_timestamps_are_candidate_failure(self) -> None:
        job = {
            "job_id": "job-1",
            "execution_id": "execution-1",
            "state": "SUCCEEDED",
            "attempt_count": 1,
            "lease_version": 1,
        }
        attempts = [
            {
                "attempt_id": "attempt-1",
                "job_id": "job-1",
                "execution_id": "execution-1",
                "lease_version": 1,
                "attempt_number": 1,
                "status": "SUCCEEDED",
                "outcome": "ROUTED",
                "error_code": None,
                "started_at": "2026-08-29T00:00:00",
                "finished_at": "2026-08-29T00:00:01+00:00",
            }
        ]
        self.assertFalse(public_check.job_attempts_consistent(job, attempts, "ROUTED"))

    def test_exact_active_version(self) -> None:
        rows = [
            {"flow_version": 1, "status": "PUBLISHED", "is_active": False},
            {"flow_version": 2, "status": "PUBLISHED", "is_active": True},
        ]
        self.assertTrue(public_check.exact_active_version(rows, 2))
        rows[0]["is_active"] = True
        self.assertFalse(public_check.exact_active_version(rows, 2))

    def test_required_stable_view_schemas_allow_order_and_extra_columns(self) -> None:
        rows = [
            {
                "view_name": view,
                "relation_kind": "v",
                "ordinal": ordinal,
                "column_name": column,
                "data_type": data_type,
            }
            for view, columns in public_check.AUTOCHECK_VIEW_SCHEMAS.items()
            for ordinal, (column, data_type) in enumerate(columns, start=1)
        ]
        self.assertTrue(public_check.stable_view_schemas_match(rows))
        rows.reverse()
        rows.append(
            {
                "view_name": "workflow_events",
                "relation_kind": "v",
                "ordinal": 99,
                "column_name": "diagnostic_code",
                "data_type": "text",
            }
        )
        self.assertTrue(public_check.stable_view_schemas_match(rows))
        required = next(row for row in rows if row["column_name"] == "event_id")
        required["data_type"] = "text"
        self.assertFalse(public_check.stable_view_schemas_match(rows))
        required["data_type"] = "uuid"
        rows = [row for row in rows if row["column_name"] != "event_id"]
        self.assertFalse(public_check.stable_view_schemas_match(rows))

    def test_action_dispatch_requires_trusted_principal_and_result(self) -> None:
        row = {
            "request_id": "execution-1",
            "module": "probe",
            "action": "execute",
            "version": 1,
            "principal": "workflow-worker",
            "status": "OK",
            "outcome": "ROUTED",
        }
        self.assertTrue(
            public_check.action_dispatch_matches(
                row,
                execution_id="execution-1",
                module="probe",
                action="execute",
                outcome="ROUTED",
            )
        )
        row["principal"] = "postgres"
        self.assertFalse(
            public_check.action_dispatch_matches(
                row,
                execution_id="execution-1",
                module="probe",
                action="execute",
                outcome="ROUTED",
            )
        )


if __name__ == "__main__":
    unittest.main()
