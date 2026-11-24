import json

import pytest

from collectors.hdparm import collector as hdparm
from collectors.openseachest import collector as openseachest
from collectors.smartctl import collector as smartctl


COLLECTORS = [
    pytest.param(openseachest, id="openseachest"),
    pytest.param(smartctl, id="smartctl"),
    pytest.param(hdparm, id="hdparm"),
]


@pytest.mark.parametrize("collector", COLLECTORS)
def test_manifest_finalization_publishes_complete_json(
    collector, monkeypatch, tmp_path
):
    monkeypatch.setattr(
        collector, "validate_manifest", lambda evidence: []
    )
    monkeypatch.setattr(
        collector, "validate_output_artifacts",
        lambda output_dir, artifacts: None,
    )

    evidence = {"schema_version": "2.0", "artifacts": [], "test": "complete"}

    collector.write_manifest(tmp_path, evidence)

    manifest_path = tmp_path / "collection.json"
    assert manifest_path.is_file()
    assert json.loads(manifest_path.read_text()) == evidence
    assert list(tmp_path.glob(".collection.json.*.tmp")) == []


@pytest.mark.parametrize("collector", COLLECTORS)
def test_schema_validation_failure_creates_no_manifest(
    collector, monkeypatch, tmp_path
):
    monkeypatch.setattr(
        collector,
        "validate_manifest",
        lambda evidence: ["simulated schema failure"],
    )

    with pytest.raises(ValueError, match="simulated schema failure"):
        collector.write_manifest(tmp_path, {})

    assert not (tmp_path / "collection.json").exists()
    assert list(tmp_path.glob(".collection.json.*.tmp")) == []


@pytest.mark.parametrize("collector", COLLECTORS)
def test_artifact_validation_failure_creates_no_manifest(
    collector, monkeypatch, tmp_path
):
    monkeypatch.setattr(
        collector, "validate_manifest", lambda evidence: []
    )

    def fail_validation(output_dir, artifacts):
        raise ValueError("simulated artifact validation failure")

    monkeypatch.setattr(
        collector, "validate_output_artifacts", fail_validation
    )

    with pytest.raises(
        ValueError, match="simulated artifact validation failure"
    ):
        collector.write_manifest(tmp_path, {"artifacts": []})

    assert not (tmp_path / "collection.json").exists()
    assert list(tmp_path.glob(".collection.json.*.tmp")) == []


@pytest.mark.parametrize("collector", COLLECTORS)
def test_atomic_replace_failure_cleans_temporary_manifest(
    collector, monkeypatch, tmp_path
):
    monkeypatch.setattr(
        collector, "validate_manifest", lambda evidence: []
    )
    monkeypatch.setattr(
        collector, "validate_output_artifacts",
        lambda output_dir, artifacts: None,
    )

    def fail_replace(source, destination):
        raise OSError("simulated atomic replacement failure")

    monkeypatch.setattr(collector.os, "replace", fail_replace)

    with pytest.raises(
        OSError, match="simulated atomic replacement failure"
    ):
        collector.write_manifest(
            tmp_path,
            {"schema_version": "2.0", "artifacts": []},
        )

    assert not (tmp_path / "collection.json").exists()
    assert list(tmp_path.glob(".collection.json.*.tmp")) == []
